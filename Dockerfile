FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY config.py oidc.py relay.py ./

RUN useradd -r -s /sbin/nologin relay

ENTRYPOINT ["python3", "relay.py"]
