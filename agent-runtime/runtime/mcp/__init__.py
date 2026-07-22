"""Model Context Protocol (MCP) integration.

Lets the harness use external MCP servers (semgrep, trivy, nmap, ZAP, nuclei, VirusTotal,
Metasploit, ...) as an *alternative execution backend* for the tools it already exposes to the
agent — without ever handing the LLM raw MCP access.

Safety model (deliberate): an MCP-capable tool is *wrapped*, keeping its name/description/surface/
requires_flag, so `execute_tool_step` runs the scope guard, the offensive-flag gate, and the audit
log FIRST — exactly as for a sandboxed tool. Only an already-authorized target is ever forwarded to
the MCP server. The model still only sees the fixed {target, intensity} registry; it cannot call an
arbitrary MCP tool and cannot widen scope. See `backend.MCPBackedTool` and `config.wrap_tools_with_mcp`.
"""
from __future__ import annotations

from .backend import MCPBackedTool, MCPServerSpec
from .client import MCPClient, MCPError
from .config import load_mcp_config, mcp_capable_tools, wrap_tools_with_mcp
from .pool import MCPConnectionPool, get_pool, shutdown_pool

__all__ = [
    "MCPBackedTool",
    "MCPServerSpec",
    "MCPClient",
    "MCPError",
    "MCPConnectionPool",
    "get_pool",
    "shutdown_pool",
    "load_mcp_config",
    "mcp_capable_tools",
    "wrap_tools_with_mcp",
]
