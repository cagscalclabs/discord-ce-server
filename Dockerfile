FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends su-exec && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY config.py oidc.py relay.py ./

RUN useradd -r -s /sbin/nologin relay

ENTRYPOINT ["python3", "relay.py"]
