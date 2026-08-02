"""Typed tool contract.

Every security tool the harness can run is a Tool: it declares its container image, builds a
command from a target + intensity, and parses raw output into topology + findings. Because commands
are built here (not by the model) and the target is scope-checked before execution, a hallucinated
or malformed request fails validation instead of running arbitrary shell.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from app.models import Finding, Intensity


@dataclass
class ServiceObservation:
    """A discovered IP:port/service, used to build the graph topology."""

    address: str
    port: int
    proto: str
    service: str = ""
    product: str = ""


@dataclass
class ToolOutput:
    services: list[ServiceObservation] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    # Free-text result for knowledge tools (CVE/reputation lookups) that inform the agent without
    # producing a persisted finding. Surfaced back to the model in its next step.
    note: str = ""


class Tool(Protocol):
    name: str
    description: str
    image: str

    # Round 6 — WS A: optional per-tool sandbox needs. Every one of these defaults to absent, and
    # `execute_tool_step` reads them with `getattr(tool, "...", None)` rather than relying on this
    # Protocol to guarantee their presence — a tool class that doesn't set them (still most of them)
    # is untouched. They exist here, spelled out with defaults, so a new tool class can see the whole
    # contract in one place instead of having to go read the orchestrator to discover what it's
    # allowed to declare.
    tmpfs: list[str] = []             # container paths to mount writable, e.g. ["/tmp", "/zap/wrk"]
    artifact_path: str | None = None  # read this file out of the container instead of parsing stdout
    mem_limit: str | None = None      # per-tool override of the sandbox's default memory ceiling
    timeout_seconds: int | None = None  # per-tool override of the sandbox's default wall-clock timeout

    def build_command(self, target: str, intensity: Intensity) -> list[str]:
        """Return the argv to run in the sandbox. Never includes untrusted free-form input."""
        ...

    def parse(self, raw: bytes, *, engagement_id: str, run_id: str, target: str) -> ToolOutput:
        """Turn raw tool output into normalized topology + findings."""
        ...
