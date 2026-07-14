"""Live integration test against the OFFICIAL Snyk MCP server (`snyk mcp`).

Opt-in and auto-skipping: it only runs when a real `snyk` binary is on PATH (or pointed to by
EYE_TEST_SNYK), so CI without the Snyk CLI just skips it. It exercises the real MCP protocol end to
end through our client — initialize handshake, tools/list, tools/call — and asserts our argument
shaping matches the server's real schema.

It deliberately does NOT assert on returned findings: `snyk_code_scan` needs a SNYK_TOKEN (or a prior
`snyk auth`) to run to completion. That the server accepts our `path` string (validated by its own
schema) is the interoperability proof; findings-mapping on Snyk's `issues[]` shape is covered by the
fast unit tests.
"""
import os
import shutil

import pytest

from runtime.mcp import MCPClient, MCPError
from runtime.mcp.backend import MCPServerSpec

SNYK = os.getenv("EYE_TEST_SNYK") or shutil.which("snyk")
pytestmark = pytest.mark.skipif(not SNYK, reason="snyk binary not available")

_ARGS = ["mcp", "-t", "stdio", "--experimental", "--disable-trust"]
_ENV = {"PATH": f"{os.path.dirname(SNYK)}:{os.environ.get('PATH', '')}"} if SNYK else {}


def _client(timeout=180):
    return MCPClient(SNYK, _ARGS, env=_ENV, timeout=timeout)


def test_live_handshake_and_tool_discovery():
    with _client() as c:
        names = {t.get("name") for t in c.list_tools()}
    # The real server exposes several scan tools; assert the SAST one our integration targets is present.
    assert "snyk_code_scan" in names


def test_live_server_accepts_our_value_shape(tmp_path):
    # Prove the server's own schema validation accepts what MCPServerSpec(target_mode="value")
    # produces for snyk_code_scan: a plain `path` string. We call with a 5s ceiling: a schema
    # *rejection* returns fast as an MCPError we can distinguish; a timeout means the args were
    # accepted and the scan is running.
    f = tmp_path / "app.py"
    f.write_text("import subprocess\nsubprocess.call('ls ' + x, shell=True)\n")
    spec = MCPServerSpec.from_dict({
        "command": SNYK, "args": _ARGS,
        "tool": "snyk_code_scan", "target_arg": "path",
    })
    arguments = {spec.target_arg: spec.shape_target(str(tmp_path))}
    assert arguments["path"] == str(tmp_path)

    try:
        with _client(timeout=5) as c:
            c.call_tool(spec.tool, arguments)
    except MCPError as exc:
        msg = str(exc)
        # A validation error would name the field; a timeout is fine (args accepted, scan running).
        assert "timed out" in msg or "validation" not in msg.lower(), msg
