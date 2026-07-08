FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    openssl \
    mosquitto-clients \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Syft + Grype (SBOM + vuln scan) — official install scripts, pinned versions
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin v1.14.0
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin v0.82.0

WORKDIR /work
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

CMD ["sleep", "infinity"]
