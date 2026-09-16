#!/usr/bin/env python3
"""Dynamic probes against a running relay listener.

Unlike the unit tests, every probe here talks to a real TLS socket as an
unauthenticated network client, exercising the protocol the way an attacker
would. The relay is booted in-process against a mock provider and Discord
bridge so the whole thing runs unattended in CI.

Run directly for a human-readable report, with --summary <file> to append
GitHub-flavoured Markdown, and/or --sarif <file> to emit SARIF for code scanning.
Exits non-zero if any probe fails.
"""

import argparse
import asyncio
import datetime
import hashlib
import ipaddress
import json
from pathlib import Path
import secrets
import ssl
import sys
import tempfile
import time
from unittest.mock import AsyncMock, Mock

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from config import load_config
from oidc import Identity
from relay import LinkStore, RelayServer, MAX_LINE

LINKED_USER = 101
PROBES = []


def probe(name, description):
    def register(function):
        PROBES.append((name, description, function))
        return function
    return register


class Harness:
    """A relay on a real TLS port, with a linked account and a live session."""

    async def __aenter__(self):
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1))
                .not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName(
                    [x509.DNSName("localhost"),
                     x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
                .sign(key, hashes.SHA256()))
        self.cert_file = root / "cert.pem"
        self.cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_file = root / "key.pem"
        key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                               serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))

        repository = Path(__file__).resolve().parents[2]
        self.config = load_config(repository / "config.json.example", {})
        self.config["oidc"]["allow_refresh"] = True
        self.store = LinkStore(str(root / "relay.sqlite3"), Fernet(Fernet.generate_key()))
        self.identity = Identity("https://identity.example", "alice",
                                 time.time() + 3600, refresh_token="stored-refresh-token")
        self.store.add(self.identity, LINKED_USER)
        self.store.set_refresh_token(self.identity, "stored-refresh-token")

        self.provider = Mock()
        self.provider.refresh = AsyncMock(return_value=self.identity)
        self.relay = RelayServer(self.config, self.provider, self.store)
        self.relay.bridge = Mock()
        self.relay.bridge.is_ready = Mock(return_value=True)

        server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_tls.minimum_version = ssl.TLSVersion.TLSv1_3
        server_tls.load_cert_chain(self.cert_file, key_file)
        self.client_tls = ssl.create_default_context(cafile=str(self.cert_file))
        self.server = await asyncio.start_server(
            self.relay.handle_client, "127.0.0.1", 0, ssl=server_tls, limit=MAX_LINE)
        self.port = self.server.sockets[0].getsockname()[1]

        # A genuine session, so probes can test tokens that really were issued.
        self.session_token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(self.session_token.encode()).digest()
        self.store.add_session(digest, self.identity, LINKED_USER, time.time() + 3600)
        return self

    async def __aexit__(self, *exc):
        self.server.close()
        await self.server.wait_closed()
        await self.relay.close()
        self.store.close()
        self.directory.cleanup()

    async def connect(self):
        return await asyncio.open_connection("127.0.0.1", self.port, ssl=self.client_tls,
                                             server_hostname="localhost")


async def exchange(harness, *requests, timeout=5):
    """Open a connection, send frames, and collect every reply until close.

    The relay caps connections per IP per minute. That limiter is production
    behaviour worth keeping, but it is not what these probes are testing, so the
    per-IP budget is cleared before each connection.
    """
    harness.relay.connection_attempts.clear()
    reader, writer = await harness.connect()
    replies = []
    try:
        hello = await asyncio.wait_for(reader.readline(), timeout)
        if hello:
            replies.append(json.loads(hello))
        for request in requests:
            raw = request if isinstance(request, bytes) else (json.dumps(request) + "\n").encode()
            writer.write(raw)
            await writer.drain()
            try:
                line = await asyncio.wait_for(reader.readline(), timeout)
            except asyncio.TimeoutError:
                break
            if not line:
                break
            replies.append(json.loads(line))
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout)
        except (asyncio.TimeoutError, ConnectionError, OSError, ssl.SSLError):
            pass
    return replies


def authenticated(replies):
    return [reply for reply in replies if reply.get("type") == "authenticated"]


@probe("resume-forged-token",
       "A token the relay never issued must not authenticate, with or without a claimed Discord ID")
async def probe_forged_token(harness):
    for extra in ({}, {"discord_id": str(LINKED_USER)}):
        replies = await exchange(harness, {"op": "resume", "id": "a",
                                           "token": "A" * 43, **extra})
        if authenticated(replies):
            return False, f"forged token accepted with {extra!r}"
    return True, "rejected in both forms"


@probe("resume-public-identity",
       "Knowing a linked account's public Discord ID must not by itself yield a session")
async def probe_public_identity(harness):
    attempts = [
        {"op": "resume", "id": "b", "discord_id": str(LINKED_USER)},
        {"op": "resume", "id": "b", "token": "", "discord_id": str(LINKED_USER)},
        {"op": "resume", "id": "b", "token": None, "discord_id": str(LINKED_USER)},
        {"op": "resume", "id": "b", "token": secrets.token_urlsafe(32),
         "discord_id": str(LINKED_USER)},
    ]
    for attempt in attempts:
        if authenticated(await exchange(harness, attempt)):
            return False, f"session issued for {attempt!r}"
    return True, "no session issued from public identity alone"


@probe("resume-token-not-replayable",
       "A session token must be single-use: replaying a consumed token must fail")
async def probe_token_replay(harness):
    first = await exchange(harness, {"op": "resume", "id": "c", "token": harness.session_token})
    if not authenticated(first):
        return False, "a legitimately issued token failed to resume"
    rotated = authenticated(first)[0]["token"]
    replay = await exchange(harness, {"op": "resume", "id": "c", "token": harness.session_token})
    if authenticated(replay):
        return False, "consumed token was accepted a second time"
    # The rotated token is the live one and must still work exactly once.
    if not authenticated(await exchange(harness, {"op": "resume", "id": "c", "token": rotated})):
        return False, "rotated token did not resume"
    return True, "old token rejected, rotated token honoured"


@probe("unauthenticated-operations",
       "Privileged operations must be refused before a session exists")
async def probe_unauthenticated_operations(harness):
    operations = [
        {"op": "guilds", "id": "d"},
        {"op": "channels", "id": "d"},
        {"op": "select_guild", "id": "d", "guild_id": "1"},
        {"op": "select_channel", "id": "d", "channel_id": "11"},
        {"op": "send", "id": "d", "text": "injected"},
        {"op": "history", "id": "d"},
    ]
    for operation in operations:
        replies = await exchange(harness, operation)
        errors = [r for r in replies if r.get("type") == "error"]
        if not errors:
            return False, f"{operation['op']} was not refused"
        if errors[0].get("code") not in {"authentication_required", "session_expired"}:
            return False, f"{operation['op']} gave unexpected code {errors[0].get('code')!r}"
    return True, "all six refused with an authentication error"


@probe("malformed-frames",
       "Malformed, oversized, and non-JSON frames must not crash the listener")
async def probe_malformed_frames(harness):
    frames = [
        b"AUTH alice 1234\n",
        b"{}\n",
        b"[]\n",
        b"null\n",
        b"\xff\xfe\n",
        b'{"op":"ping"}\n',
        b'{"id":"1"}\n',
        b'{"op":"ping","id":"' + b"x" * 200 + b'"}\n',
        b"x" * (MAX_LINE + 500) + b"\n",
        b'{"op":"resume","id":"1","token":' + b"[" * 400 + b"]" * 400 + b"}\n",
    ]
    for frame in frames:
        # Hanging up on a bad frame is a correct response, so the probe only asserts
        # that the listener still serves a *new* connection afterwards.
        try:
            await exchange(harness, frame)
        except (ConnectionError, OSError, ssl.SSLError, json.JSONDecodeError):
            pass
        replies = await exchange(harness, {"op": "ping", "id": "alive"})
        if not any(r.get("type") == "pong" for r in replies):
            return False, f"listener stopped answering after frame {frame[:40]!r}"
    return True, f"{len(frames)} malformed frames survived; listener still healthy"


@probe("snowflake-validation",
       "Snowflakes that are out of range or non-numeric must be rejected, not coerced")
async def probe_snowflake_validation(harness):
    values = ["0", "-1", "1e9", "١٢٣", "0x10", " 101", "101 ", "9" * 40, "null", "",
              "18446744073709551616", "1_0_1"]
    # Resume first so the connection holds a session, then probe an operation that
    # actually parses a snowflake. Resume rotates the token, so carry it forward.
    token = harness.session_token
    for value in values:
        replies = await exchange(harness,
                                 {"op": "resume", "id": "f", "token": token},
                                 {"op": "select_guild", "id": "g", "guild_id": value})
        issued = authenticated(replies)
        if not issued:
            return False, f"could not establish a session while probing {value!r}"
        token = issued[0]["token"]
        if any(r.get("type") == "selected_guild" for r in replies):
            return False, f"accepted guild_id {value!r}"
        if not any(r.get("type") == "error" and r.get("id") == "g" for r in replies):
            return False, f"guild_id {value!r} produced neither selection nor error"
    harness.session_token = token
    return True, f"{len(values)} malformed identifiers rejected"


@probe("tls-floor",
       "The listener must refuse anything below TLS 1.3")
async def probe_tls_floor(harness):
    context = ssl.create_default_context(cafile=str(harness.cert_file))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    try:
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", harness.port, ssl=context, server_hostname="localhost")
    except (ssl.SSLError, ConnectionError, OSError):
        return True, "TLS 1.2 handshake refused"
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionError, OSError, ssl.SSLError):
        pass
    return False, "TLS 1.2 handshake succeeded"


def write_sarif(results, path):
    """Emit SARIF 2.1.0 so failures surface as code scanning alerts.

    Probes exercise the protocol rather than a source line, so every result is
    anchored to relay.py: the listener is what was actually under test.
    """
    rules, findings = [], []
    for name, description, passed, detail in results:
        rules.append({
            "id": name,
            "name": name.replace("-", " ").title().replace(" ", ""),
            "shortDescription": {"text": description},
            "fullDescription": {"text": description},
            "defaultConfiguration": {"level": "error"},
            "properties": {"tags": ["security", "dast"]},
        })
        if passed:
            continue
        findings.append({
            "ruleId": name,
            "level": "error",
            "message": {"text": f"DAST probe '{name}' failed: {detail}. Expected: {description}."},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "relay.py"},
                "region": {"startLine": 1},
            }}],
        })

    report = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "relay-dast",
                "informationUri": "https://github.com/cagscalclabs/discord-ce-server",
                "rules": rules,
            }},
            "results": findings,
        }],
    }
    Path(path).write_text(json.dumps(report, indent=2), encoding="utf-8")


async def run(summary_path=None, sarif_path=None):
    results = []
    for name, description, function in PROBES:
        async with Harness() as harness:
            try:
                passed, detail = await function(harness)
            except Exception as error:                      # a crashing probe is a failure
                passed, detail = False, f"probe raised {type(error).__name__}: {error}"
        results.append((name, description, passed, detail))
        print(f"[{'PASS' if passed else 'FAIL'}] {name}: {detail}")

    failures = [r for r in results if not r[2]]
    print(f"\n{len(results) - len(failures)}/{len(results)} probes passed")

    if summary_path:
        lines = ["# DAST report", "",
                 f"**{len(results) - len(failures)}/{len(results)} probes passed**", "",
                 "| Probe | Result | Detail |", "| --- | --- | --- |"]
        for name, description, passed, detail in results:
            lines.append(f"| `{name}`<br><sub>{description}</sub> | "
                         f"{'✅ pass' if passed else '❌ **fail**'} | {detail} |")
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")

    if sarif_path:
        write_sarif(results, sarif_path)

    return 1 if failures else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", help="append a Markdown report to this file")
    parser.add_argument("--sarif", help="write a SARIF report to this file")
    arguments = parser.parse_args()
    sys.exit(asyncio.run(run(arguments.summary, arguments.sarif)))
