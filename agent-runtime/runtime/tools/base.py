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

    def build_command(self, target: str, intensity: Intensity) -> list[str]:
        """Return the argv to run in the sandbox. Never includes untrusted free-form input."""
        ...

    def parse(self, raw: bytes, *, engagement_id: str, run_id: str, target: str) -> ToolOutput:
        """Turn raw tool output into normalized topology + findings."""
        ...
