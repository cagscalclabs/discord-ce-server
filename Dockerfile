FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY config.py oidc.py relay.py ./

RUN useradd -r -s /sbin/nologin relay && mkdir -p /app/data && chown relay:relay /app/data
USER relay

CMD ["python", "relay.py"]
