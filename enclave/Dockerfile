FROM python:3.11-slim

WORKDIR /app

COPY server.py .
COPY protocol.py .
COPY risk_engine.py .
COPY crypto.py .
COPY attestation_bridge .

COPY requirements.txt .

RUN chmod +x /app/attestation_bridge
RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT ["/usr/local/bin/python3", "/app/server.py"]
