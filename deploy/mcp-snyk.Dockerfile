# Isolated Snyk MCP server image. Runs `snyk mcp` over stdio; the harness's connection pool launches
# it as a warm, locked-down `docker run -i` sibling (cap-drop-all, read-only rootfs, no socket) and
# reuses it across calls. Keeping snyk here (not in the api image) is the api-slimming win.
FROM debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -Lo /usr/local/bin/snyk https://downloads.snyk.io/cli/stable/snyk-linux \
    && chmod +x /usr/local/bin/snyk \
    && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# Auth comes from SNYK_TOKEN at runtime (forwarded by name from the launcher). --disable-trust stops
# the server blocking on the interactive folder-trust prompt.
ENTRYPOINT ["snyk"]
CMD ["mcp", "-t", "stdio", "--experimental", "--disable-trust"]
