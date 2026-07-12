"""Replay a run from the append-only audit log.

Because every step records the tool, target, scope decision, and a SHA-256 of the raw tool output,
a run can be reconstructed as an ordered timeline and its integrity checked: re-running a tool and
hashing the output must match what was recorded, or the evidence has drifted/been tampered with.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .audit import AuditEvent, EventType, hash_output


@dataclass
class ReplayStep:
    tool: str | None
    target: str | None
    allowed: bool | None = None
    output_sha256: str | None = None
    findings: list[str] = field(default_factory=list)


def reconstruct(events: list[AuditEvent], run_id: str) -> list[ReplayStep]:
    """Fold the audit events for one run into an ordered list of steps."""
    steps: list[ReplayStep] = []
    current: ReplayStep | None = None
    for e in sorted((e for e in events if e.run_id == run_id), key=lambda e: e.at):
        if e.type == EventType.scope_decision:
            current = ReplayStep(tool=e.tool, target=e.target, allowed=e.allowed)
            steps.append(current)
        elif e.type == EventType.tool_finished and current is not None:
            current.output_sha256 = e.output_sha256
        elif e.type == EventType.finding_recorded and current is not None:
            current.findings.append(e.detail)
    return steps


def verify_output(events: list[AuditEvent], run_id: str, tool: str, produced: bytes | str) -> bool:
    """True if re-running `tool` produced output matching the hash recorded in the audit log."""
    want = hash_output(produced)
    for step in reconstruct(events, run_id):
        if step.tool == tool and step.output_sha256 == want:
            return True
    return False
