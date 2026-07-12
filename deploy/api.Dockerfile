# Control-plane API image. Bundles both Python packages so the API can invoke the orchestrator
# in-process for Phase 1. The Docker CLI is not needed here — the SDK talks to the mounted socket.
FROM python:3.12-slim

WORKDIR /app

# Install the control plane and the agent runtime (runtime depends on control-plane).
COPY control-plane /app/control-plane
COPY agent-runtime /app/agent-runtime
COPY graph /app/graph

RUN pip install --no-cache-dir ./control-plane ./agent-runtime

EXPOSE 9000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9000"]
