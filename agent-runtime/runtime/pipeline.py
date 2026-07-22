"""Canonical assessment pipeline: an ordered list of stages and a tool -> stage map.

This is **presentation metadata only**. It lets the chat UI show which phase of an assessment a run
is in and highlight the in-progress stage; it never gates execution. What a tool is *allowed* to do
is decided entirely by the scope guard and the signed-scope flags in `execute_tool_step` — the stage
a tool belongs to has no bearing on authorization.
"""
from __future__ import annotations

# Ordered phases of an assessment, coarsest first. "report" is a terminal presentation stage with no
# tool of its own — it lights up once the run finishes.
STAGES: list[str] = [
    "recon",
    "dynamic scan",
    "static scan",
    "threat intel",
    "exploitation",
    "credentials",
    "report",
]

# Which stage each of the 14 tools belongs to. Kept exhaustive so a newly added tool that isn't
# mapped surfaces as "recon" (see stage_of) rather than silently breaking the rail.
_TOOL_STAGE: dict[str, str] = {
    # recon
    "nmap": "recon",
    # dynamic (DAST)
    "nuclei": "dynamic scan",
    "ffuf": "dynamic scan",
    "nikto": "dynamic scan",
    "zap": "dynamic scan",
    # static (SAST)
    "semgrep": "static scan",
    "gitleaks": "static scan",
    "trivy": "static scan",
    # threat intel / knowledge
    "cve_lookup": "threat intel",
    "virustotal": "threat intel",
    "tls_cert": "threat intel",
    # exploitation (gated)
    "exploit": "exploitation",
    "post_exploit": "exploitation",
    # credentials (gated)
    "credential_attack": "credentials",
}


def stage_of(tool_name: str) -> str:
    """Return the pipeline stage a tool belongs to, defaulting to the first stage for unknown tools
    so the UI never renders an empty stage for a tool we forgot to map."""
    return _TOOL_STAGE.get(tool_name, STAGES[0])


def tools_for_stage(stage: str) -> list[str]:
    """Return the tool names mapped to a pipeline stage — the reverse of `_TOOL_STAGE`.

    This is the single source of truth for a specialist sub-agent's tool subset: a specialist owns
    a stage, and its tools are exactly the tools that render under that stage in the pipeline rail.
    A stage with no tool of its own (e.g. "report") returns an empty list.
    """
    return [name for name, mapped in _TOOL_STAGE.items() if mapped == stage]
