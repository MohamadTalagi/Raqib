FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    openssl \
    mosquitto-clients \
    curl \
    ca-certificates \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Syft + Grype (SBOM + vuln scan) — official install scripts, pinned versions
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin v1.14.0
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin v0.82.0

WORKDIR /work
# Build context is ../auditor (see docker-compose.yml), so worker/ and api/
# paths below are siblings within it.
COPY worker/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# device_validation.py is the scan-target security boundary shared with
# auditor-api. It is COPYed into the image (single source of truth still
# lives at auditor/api/device_validation.py) rather than bind-mounted, so
# this image is self-contained and importable outside of this specific
# compose file - a single-file bind mount would leave the worker image
# without the module it depends on, and can break on Docker Desktop when
# the host file is replaced rather than edited in place.
COPY api/device_validation.py .

# job_runner.py (bind-mounted in at runtime, same as the rest of lab/auditor/worker)
# runs in the background so this container is still exec-able for manual
# Day-2-style assessment work, while also polling for dashboard-triggered scans.
CMD ["sh", "-c", "python /work/lab/auditor/worker/job_runner.py & exec sleep infinity"]
