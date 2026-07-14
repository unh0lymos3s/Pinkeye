"""Configure which registered tools execute via an MCP server, and wrap them.

Opt-in per tool: a tool keeps its sandboxed execution path unless the operator names an MCP server
for it. Two knobs (env var, re-read at startup like the LLM config):

    EYE_MCP_SERVERS   inline JSON: {tool_name: {command, args, tool, target_arg, ...}, ...}
    EYE_MCP_CONFIG    path to a JSON file with the same shape (inline overrides the file)

Example (Snyk Code + trivy via their official MCP servers, nmap via a community one)::

    {
      "semgrep": {"command": "snyk",
                  "args": ["mcp", "-t", "stdio", "--experimental", "--disable-trust"],
                  "tool": "snyk_code_scan", "target_arg": "path"},
      "trivy":   {"command": "trivy",   "args": ["mcp", "-t", "stdio"], "tool": "scan_filesystem", "target_arg": "path"},
      "nmap":    {"command": "npx", "args": ["-y", "nmap-mcp-server"], "tool": "run_nmap_scan", "target_arg": "target"}
    }

Only tools that actually have a public MCP server are worth wiring; `MCP_CAPABLE` documents the ones
found during research (name -> upstream), and `wrap_tools_with_mcp` logs a note if you point one at a
tool with no known server (it still wraps it — your config is authoritative).
"""
from __future__ import annotations

import json
import os

from .backend import MCPBackedTool, MCPServerSpec

# Native tool name -> a known public MCP server for it (from research, July 2026). Reference only;
# the operator still supplies the exact command/args in EYE_MCP_SERVERS. Tools whose backends are our
# own (cve_lookup, tls_cert) have no external MCP and are absent by design.
MCP_CAPABLE: dict[str, str] = {
    "nmap": "community: PhialsBasement/nmap-mcp-server, cyproxio/mcp-for-security",
    "nuclei": "community: addcontent/nuclei-mcp, intelligent-ears/pd-tools-mcp",
    "ffuf": "community: cyproxio/mcp-for-security (FFUF)",
    "nikto": "community: FuzzingLabs/mcp-security-hub, chfle/Pentest-MCP-Server",
    "zap": "official: zaproxy ZAP MCP server; community: dtkmn/mcp-zap-server",
    "semgrep": "official: Snyk Code (`snyk mcp` -> snyk_code_scan); also semgrep (`semgrep mcp`)",
    "trivy": "official: aquasecurity/trivy-mcp (`trivy mcp`)",
    "gitleaks": "community: security-tool suites (FuzzingLabs, pentest-ai)",
    "virustotal": "community: BurtTheCoder/mcp-virustotal, alephnan/MCP-VirusTotal",
    "exploit": "official: Rapid7 msfmcpd; community: GH05TCREW/MetasploitMCP",
    "post_exploit": "official: Rapid7 msfmcpd; community: GH05TCREW/MetasploitMCP",
    "credential_attack": "community: broad pentest suites (0xSteph/pentest-ai)",
}


def mcp_capable_tools() -> dict[str, str]:
    """Tools with a known public MCP server (name -> upstream). For docs/UX, not authorization."""
    return dict(MCP_CAPABLE)


def _load_raw() -> dict:
    """Merge EYE_MCP_CONFIG (file) then EYE_MCP_SERVERS (inline, wins). Bad/missing config is ignored
    so a typo can never crash startup — the harness just runs every tool in the sandbox as before."""
    merged: dict = {}
    path = os.getenv("EYE_MCP_CONFIG")
    if path:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                merged.update(data)
        except (OSError, ValueError):
            pass
    inline = os.getenv("EYE_MCP_SERVERS")
    if inline:
        try:
            data = json.loads(inline)
            if isinstance(data, dict):
                merged.update(data)
        except ValueError:
            pass
    return merged


def load_mcp_config() -> dict[str, MCPServerSpec]:
    """Parse configured MCP backends into {tool_name: MCPServerSpec}. Entries that don't parse are
    skipped individually so one bad spec doesn't disable the others."""
    specs: dict[str, MCPServerSpec] = {}
    for name, raw in _load_raw().items():
        try:
            specs[str(name)] = MCPServerSpec.from_dict(raw)
        except (ValueError, TypeError):
            continue
    return specs


def wrap_tools_with_mcp(tools: list, specs: dict[str, MCPServerSpec] | None = None) -> list:
    """Return `tools` with any tool named in the MCP config replaced by an MCP-backed variant.

    The wrapper preserves name/description/surface/requires_flag, so the scope guard, offensive-flag
    gate, and audit are unchanged and still run first. Tools with no MCP config are returned as-is,
    so the default all-sandbox behavior is preserved unless an operator opts a tool in.
    """
    specs = load_mcp_config() if specs is None else specs
    if not specs:
        return tools
    wrapped: list = []
    for tool in tools:
        spec = specs.get(getattr(tool, "name", None))
        wrapped.append(MCPBackedTool(tool, spec) if spec is not None else tool)
    return wrapped
