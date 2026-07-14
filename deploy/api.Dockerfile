# Control-plane API image. Bundles both Python packages so the API can invoke the orchestrator
# in-process for Phase 1. The Docker CLI is not needed here — the SDK talks to the mounted socket.
FROM python:3.12-slim

WORKDIR /app

# The Snyk CLI is no longer installed here. The SAST slot runs via the *pooled* Snyk MCP server, which
# lives in its own hardened image (deploy/mcp-snyk.Dockerfile) launched as a `docker run -i` sibling by
# the connection pool. Moving the tool out of the api process is the isolation win.
#
# That sibling is launched over stdio, so the api needs the Docker *CLI* (the disposable-sandbox path
# uses the docker-py SDK over the socket; the pooled MCP path shells out to `docker run -i`). Install
# just the static CLI binary to keep the image small.
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-27.3.1.tgz -o /tmp/d.tgz \
    && tar -xzf /tmp/d.tgz -C /tmp docker/docker \
    && mv /tmp/docker/docker /usr/local/bin/docker \
    && rm -rf /tmp/d.tgz /tmp/docker \
    && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# Install the control plane and the agent runtime (runtime depends on control-plane).
COPY control-plane /app/control-plane
COPY agent-runtime /app/agent-runtime
COPY graph /app/graph

RUN pip install --no-cache-dir ./control-plane ./agent-runtime

EXPOSE 9000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9000"]
