# =============================================================================
# Image for the ML scorer (agentwall_scorer.py).
# Build context = REPO ROOT:  docker build -f deploy/Dockerfile -t agentwall-scorer .
# (docker-compose.yml sets context: .. for the same reason — see .dockerignore
# at the repo root, which is the one Docker actually reads for this context.)
#
# The image runs the scorer in DRY-RUN unless the compose/systemd command adds
# --enforce. This image only installs the pinned deps and the two scorer files.
# =============================================================================
FROM python:3.12-slim

# Unbuffered logs (journalctl/docker logs see lines immediately) and no .pyc
# writes (the container runs with a read-only root filesystem).
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install deps first for layer caching. Same pins as requirements.txt
# (river~=0.21.0, redis~=5.0) — keep this in sync with scorer/requirements.txt.
COPY scorer/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Scorer code (only what the image needs; see .dockerignore).
COPY scorer/agentwall_scorer_v1.py       /app/
COPY scorer/agentwall_scorer.py /app/

# Run as non-root (uid 10001, no login). The scorer writes ONLY under /state
# (a named volume in compose); /var/log/nginx is mounted read-only and the
# container root filesystem is read-only.
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin agentwall \
    && mkdir -p /state \
    && chown agentwall:agentwall /state
USER agentwall

# Metrics endpoint: OPTIONAL. It is only started when --metrics-port is passed
# (compose passes 9101, published on loopback only). /metrics and /healthz are
# served there; do not expose the port publicly.
# ENTRYPOINT + compose command => final argv is the compose `command` list.
ENTRYPOINT ["python3", "agentwall_scorer.py"]
CMD ["--log", "/logs/agentwall_access.log", "--use-xff", "--log-level", "INFO"]
