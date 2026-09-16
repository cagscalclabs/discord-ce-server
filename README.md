# Discord-CE relay

[![Tests](https://github.com/cagscalclabs/discord-ce-server/actions/workflows/tests.yml/badge.svg)](https://github.com/cagscalclabs/discord-ce-server/actions/workflows/tests.yml)
[![SAST](https://github.com/cagscalclabs/discord-ce-server/actions/workflows/sast.yml/badge.svg)](https://github.com/cagscalclabs/discord-ce-server/actions/workflows/sast.yml)
[![DAST](https://github.com/cagscalclabs/discord-ce-server/actions/workflows/dast.yml/badge.svg)](https://github.com/cagscalclabs/discord-ce-server/actions/workflows/dast.yml)

The server half of Discord-CE: it lets a TI-84+ CE calculator read and post to Discord text channels using the Discord Bot API.

## How the Bot Works

NOTE: This is NOT a self-bot. It does not touch user tokens. The server credentials users via an OIDC session and whatever discord_id the Discord Gateway provides in response to the `/relay_link` slash command.

The bot has two components:

1. A TLS listener that communicates with calculators for authorization.
2. A Discord bot that holds a single Bot Gateway connection and does all the Discord related work.

The connection process works like this:

1. The calculator opens a TLS connection to the server running the bot.
2. The server sends a request to the OIDC endpoint.
3. The calculator displays a code that you must enter consistently with how the provider requires you enter an OTP.
4. The OIDC provider returns a signed ID token, plus a refresh token if `offline_access` is enabled. The relay validates the ID token's signature, issuer, audience, and expiry; the identity it proves is an issuer + subject pair, not a Discord account.
5. A longer code is displayed on the calculator, with the instruction to type `/relay_link <code>` in a Discord server containing the bot. The calculator then shows which Discord account the command came from, and you must confirm it before the link is saved — so entering someone else's code cannot silently bind you to their account.
6. A single SQLite database with three tables persists state. `links` permanently pairs the OIDC identity (issuer + subject) to your discord_id — this is what lets later logins skip the linking step. `sessions` is keyed by SHA-256(session_token) and holds the OIDC identity, discord_id, and expiry; sessions have a TTL of 1 hour. `refresh_tokens` holds Fernet_Encrypt(refresh_token), keyed by that same OIDC identity. CEagle keeps refresh tokens live for 30 days.
7. The relay issues the session token and the calculator is live: messages flow from the calculator to the selected channel and from Discord back to the calculator. Every read and send is checked against current Discord permissions for both you and the bot, so losing access mid-session stops delivery immediately.
8. On subsequent reconnect, the transmitted session token must match the SHA-256 that is stored. If not, the connection fails. If it does, the client is logged back in cleanly. If it does but the session is expired, the refresh token is used cleanly. From the calculator side, both successful login modes are indistinguishable.

## Necessary TLS Configuration (Bot Server)

Your bot server must expose TLS 1.3, as well as ensure the following:

- X25519 curve is provided. Some TLS libraries do not expose this curve by default in favor of secp256r1 or newer.
- The leaf certificate is rsa_pss_rsae_sha256, and the key is 2048 bits. The certificate's CN or SAN matches the hostname the calculator connects to.

*These are temporary constraints while lwIP-CE algorithm support remains work-in-progress.*

*Security Note: lwIP-CE at present will WARN on a Certificate chain that it lacks the algorithm support to fully verify but will complete the connection anyway. In the short term/testing era of this project, that's fine, but please bear this in mind when connecting to relays you do not personally trust (ex: outside of the community connected with lwIP-CE directly). lwIP-CE will announce when algorithm support is complete.*

## Setup

Use Python 3.10 or newer and a dedicated Discord application. From the repository root:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r relay/requirements.txt
cp relay/config.json.example relay/config.json
chmod 600 relay/config.json
```

Edit the config with your bot token and registered OIDC client ID, or supply them as environment variables instead — `DISCORD_TOKEN`, `OIDC_CLIENT_ID`, and `OIDC_CLIENT_SECRET` all override the JSON file, so a Docker deployment can set them in `compose.yaml` and skip `config.json` entirely. Select the OIDC authentication method assigned to that registration and supply a client secret if required. The registration must support the device-code grant with the `openid` scope and return an RS256-signed ID token with a `kid` header.


Install the bot in each participating server with `bot` and
`applications.commands` scopes. Grant View Channels, Send Messages, and Read Message History in participating channels. Enable **Server Members** and **Message Content** privileged intents in the Discord Developer Portal (and obtain approval where applicable). The member intent maintains the membership and role cache used for authorization. See [discord.py's intent guide](https://discordpy.readthedocs.io/en/stable/intents.html).

```sh
.venv/bin/python relay/relay.py
```

Startup validates configuration, loads TLS, opens the link database, discovers
OIDC endpoints, and registers `/relay_link` and `/relay_unlink` as global Discord
commands. Global command propagation can take time. Command synchronization
owns the application's global command set, so use a dedicated application.
The relay won't serve Discord data before the bot's cache is ready.

## Configuration

| Setting | Purpose |
| --- | --- |
| `DISCORD_TOKEN` | Bot token without a `Bot ` prefix. Required. |
| `PERMISSIONS` | Permission bitmask requested by the installation URL logged at startup. Default `68608` requests View Channels, Send Messages, and Read Message History. This does not grant permissions by itself. Environment override: `PERMISSIONS`. |
| `RELAY_HOST`, `RELAY_PORT` | Bind address and TCP port; defaults `0.0.0.0:8443`. Configure your firewall/DNS separately. |
| `RELAY_CERT`, `RELAY_KEY` | PEM certificate chain and private key paths. |
| `DATABASE_FILE` | SQLite database of verified account links, session records, and encrypted refresh tokens. Default `relay.sqlite3`. Parent directory must exist and be writable. |
| `RELAY_TOKEN_KEY` | Fernet key encrypting stored refresh tokens. Required when `oidc.allow_refresh` is enabled. Generate with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. Rotating it invalidates every stored refresh token. |
| `DISCORD_DISPLAY_FMT` | Outgoing attribution; must contain `{user}` and `{text}`. Default `[{user}] {text}`. |
| `SESSION_TTL` | Maximum relay session lifetime in seconds, default 3600, also capped by the ID token's expiry. |
| `LOGIN_TIMEOUT` | Total time to finish device login and first-time linking, default 600 seconds. |
| `MAX_CLIENTS`, `MAX_CLIENTS_PER_IP` | Concurrent connection limits; defaults 64 and 4. |
| `MAX_SESSIONS` | Maximum concurrent live sessions, default 1024. |
| `SEND_INTERVAL` | Minimum seconds between a user's sends across connections, default 2. Channel slowmode also applies unless the member is exempt. |
| `oidc.issuer` | Trusted OIDC issuer, default `https://account.ceagle.cc`. Endpoints are discovered at startup. |
| `oidc.client_id` | Required provider registration ID. This is not the Discord application ID. |
| `oidc.client_secret` | Provider client secret, if assigned. |
| `oidc.token_endpoint_auth_method` | `none`, `client_secret_basic`, or `client_secret_post`, matching the registration. |
| `oidc.allow_refresh` | `true` or `false` (default `false`). When true, requests `offline_access` and keeps encrypted refresh tokens so expired sessions renew silently. Requires `RELAY_TOKEN_KEY` and a registration permitting `offline_access`. |

Environment variables override JSON, which overrides defaults. Top-level fields
use matching environment names; OIDC overrides are `OIDC_ISSUER`,
`OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_TOKEN_ENDPOINT_AUTH_METHOD`, and
`OIDC_ALLOW_REFRESH`.
The default file is `config.json` beside `relay.py`, independent of launch directory.
Select a different host config with:

```sh
RELAY_CONFIG=/etc/discord-ce/config.json .venv/bin/python relay/relay.py
```

An explicitly selected file must exist. A missing default file permits
environment-only configuration. JSON/default relative file paths resolve from
the configuration directory; environment-supplied paths remain relative to the
working directory. Unknown settings are rejected. Remove the obsolete
`DISCORD_CHANNEL_ID` and `USERS_FILE` fields from older configurations.
`users.json` is no longer read; there is no PIN login fallback.

The local config, PEM files, and SQLite files under `relay/` are Git-ignored.
Keep custom paths private too. The database contains identity links, session
records, and — when `oidc.allow_refresh` is enabled — encrypted provider refresh
tokens. Back it up to preserve account links, and protect it accordingly: with
refresh enabled, the database plus `RELAY_TOKEN_KEY` together are sufficient to
re-authenticate linked accounts until their refresh tokens expire. Run one relay
process per deployment/database; connection ownership is in memory and is not
coordinated across replicas.

## Login and account linking

1. The calculator requests login and displays the provider's URL and user code.
2. The user approves in a browser on another device. The relay polls according
   to the provider's interval and handles pending, slow-down, denial, and expiry.
3. The relay validates the ID-token signature, issuer, audience, authorized party,
   required claims, and expiry against the discovered JWKS. It never retains access
   tokens. It requests only `openid` unless `oidc.allow_refresh` is enabled, in which
   case it also requests `offline_access` and stores the returned refresh token
   encrypted (see below).
4. On first login, the calculator displays a separate link code. The user runs
   `/relay_link code:...` in a server where the bot is installed. The code is
   single-use and expires with the pending login.
5. The calculator displays the Discord account from that interaction. The user
   confirms its Discord ID with `link_confirm` before the association is saved.
   Do not approve a different account or enter a link code supplied by someone else.
6. The relay issues a random session token. Later logins use the saved verified
   link. The calculator can resume with that token; resume rotates the token
   without extending its lifetime.

Each Discord account can link to one OIDC identity in this deployment. A new
login/resume replaces the user's previous connection and resets server selection.
`logout` revokes relay credentials; `/relay_unlink` also removes the account link,
its stored refresh token, and closes that user's active connection. Relay logout
does not log the user out of the identity provider. Provider-side logout/revocation
is not pushed to the relay; a validated local session lasts until its bounded expiry
unless locally revoked.

Session records are stored in the database as SHA-256 digests of the bearer token —
never the token itself — so sessions survive a relay restart. Presenting the token is
the sole authentication for `resume`; the relay never trusts a client's claim about
its own identity.

### Refresh tokens

With `oidc.allow_refresh` enabled, the relay requests `offline_access` and stores the
provider's refresh token, encrypted with `RELAY_TOKEN_KEY` (a Fernet key). When a
calculator resumes with a session token whose lifetime has passed, the relay redeems
that refresh token and silently issues a new session — no browser round-trip, for as
long as the provider honours the refresh token (30 days on the default issuer).
Expired session rows are retained for that same window so they remain redeemable, then
purged. Disabling the option leaves the original behaviour: an expired session
requires a fresh device login.

## Access and message behavior

The user selects a mutual server, then a text channel visible to both their
Discord member and the bot. History additionally requires Read Message History
for both; sending requires Send Messages and no timeout. Read-only channels
remain selectable. Membership, roles, and channel overwrites come from the
Discord gateway cache. Cache updates recheck selections, and a disconnected
gateway clears selections and stops data delivery until ready again.

Switching servers resets the active channel. The client must erase the previous
view on selection/reset events and discard messages for other IDs. No private
DMs, threads, voice, reactions, webhook impersonation, or attachment downloads
are implemented. Text is bounded for the calculator; attachment counts and text
truncation flags are supplied. Edits trigger a refresh notification; deletes
identify the message to remove.

Sends use the authenticated Discord display name, suppress all mentions, and
acknowledge success only after Discord accepts the message. The gateway supplies
the message echo. A connection failure after Discord accepts a send can leave
its outcome unknown; request IDs correlate responses but are not idempotency
keys. Do not automatically retry an uncertain send.

## Verification

```sh
.venv/bin/python -m unittest discover -s relay -p 'test_*.py'
```

Tests use generated signing keys, fake provider responses, mocked Discord
objects, and local socket connections. They do not send messages to Discord or
exercise a live provider registration. Deployment still needs a real device
login, permission-revocation checks in a test server, and a TLS handshake from
the calculator.

Protocol references: [device grant](https://www.rfc-editor.org/rfc/rfc8628),
[OIDC validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation),
and [PyJWT usage](https://pyjwt.readthedocs.io/en/stable/usage.html).
