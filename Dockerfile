FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY config.py oidc.py relay.py ./

# Pinned uid so host-side ownership is stable across rebuilds: the host sees this
# number (not the name) on any bind-mounted file the relay reads or writes.
#
# The data directory is created and handed to that user before any volume exists,
# because Docker seeds a new named volume from the image's directory, ownership
# included — letting the relay write its database without ever running as root.
RUN useradd -r -u 10001 -s /sbin/nologin app \
    && mkdir -p /app/data \
    && chown -R app:app /app/data

USER app

ENTRYPOINT ["python3", "relay.py"]
