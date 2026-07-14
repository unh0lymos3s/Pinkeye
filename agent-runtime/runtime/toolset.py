"""Central assembly of every tool the harness can run, grouped by phase.

`all_tools()` is what the API and the agent registry use, so adding a tool in one place makes it
available to both the deterministic path and the LLM planner.
"""
from __future__ import annotations

from .exploit import exploitation_tools
from .mcp import wrap_tools_with_mcp
from .tools.credential import credential_tools
from .tools.dast import dast_tools
from .tools.intel import CveLookupTool
from .tools.nmap import NmapTool
from .tools.reputation import reputation_tools
from .tools.sast import sast_tools


def recon_tools() -> list:
    return [NmapTool()]


def knowledge_tools(db=None) -> list:
    # Tools that need database/secret access are only added when a db handle is available.
    tools: list = []
    if db is not None:
        from app.cve_db import CveRepo

        tools.append(CveLookupTool(CveRepo(db)))
    return tools


def all_tools(db=None) -> list:
    # Offensive tools are always registered but refuse to run unless the scope grants the matching
    # flag (allow_exploit / allow_credential_attacks).
    tools = [*recon_tools(), *dast_tools(), *sast_tools(), *reputation_tools(),
             *exploitation_tools(), *credential_tools(), *knowledge_tools(db)]
    # Opt-in: any tool the operator wired to an MCP server (EYE_MCP_SERVERS/EYE_MCP_CONFIG) is
    # replaced by an MCP-backed variant that still runs behind the scope guard, flag gate, and audit.
    # No config -> the list is returned unchanged (every tool stays on its sandbox path).
    return wrap_tools_with_mcp(tools)
