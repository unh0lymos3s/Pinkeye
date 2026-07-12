"""Domain models: engagements, signed scopes, runs, and normalized findings.

These are the shapes that flow through the whole harness. The Scope is the security-critical one:
the scope guard uses it to decide whether a tool is allowed to touch a given target.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class FindingState(str, Enum):
    # A finding starts as "suspected" and is only promoted once a validation step confirms it.
    suspected = "suspected"
    confirmed = "confirmed"
    false_positive = "false_positive"


class Intensity(str, Enum):
    # Caps how aggressive a tool may be; the sandbox and tool adapters translate this to flags.
    passive = "passive"
    light = "light"
    normal = "normal"
    aggressive = "aggressive"


class Scope(BaseModel):
    """The authorization boundary for an engagement.

    A run may only touch targets that fall inside allowed_cidrs or allowed_domains, within the
    time window, and at or below max_intensity. `signature` is an HMAC over the canonical scope so
    the guard can detect tampering before trusting it.
    """

    allowed_cidrs: list[str] = Field(default_factory=list)
    allowed_domains: list[str] = Field(default_factory=list)
    # Source paths / repo URLs the harness may statically analyze (SAST). Prefix-matched.
    allowed_artifacts: list[str] = Field(default_factory=list)
    not_before: datetime
    not_after: datetime
    max_intensity: Intensity = Intensity.normal
    # Intrusive capabilities are OFF unless explicitly authorized in the signed scope. Because they
    # are part of canonical(), flipping them on without re-signing invalidates the scope and the
    # guard rejects it — the model cannot enable exploitation or credential attacks on its own.
    allow_exploit: bool = False
    allow_credential_attacks: bool = False
    signature: Optional[str] = None

    def canonical(self) -> str:
        # Stable string used both for signing and verification. Order and formatting must be fixed.
        cidrs = ",".join(sorted(self.allowed_cidrs))
        domains = ",".join(sorted(d.lower() for d in self.allowed_domains))
        artifacts = ",".join(sorted(self.allowed_artifacts))
        return "|".join(
            [
                cidrs,
                domains,
                artifacts,
                self.not_before.astimezone(timezone.utc).isoformat(),
                self.not_after.astimezone(timezone.utc).isoformat(),
                self.max_intensity.value,
                f"exploit={int(self.allow_exploit)}",
                f"creds={int(self.allow_credential_attacks)}",
            ]
        )


class Engagement(BaseModel):
    id: str
    name: str
    scope: Scope
    created_at: datetime = Field(default_factory=_now)


class RunStatus(str, Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    rejected = "rejected"  # blocked by the scope guard before any tool ran


class Run(BaseModel):
    id: str
    engagement_id: str
    target: str  # the seed target this run was launched against
    status: RunStatus = RunStatus.queued
    created_at: datetime = Field(default_factory=_now)


class Finding(BaseModel):
    """Normalized output of any tool, tool-agnostic so the graph shows one node per real issue."""

    id: str
    engagement_id: str
    run_id: str
    title: str
    category: str  # e.g. "open-port", "outdated-service", "sql-injection"
    severity: Severity = Severity.info
    state: FindingState = FindingState.suspected
    confidence: float = 0.5  # 0..1, drives suspected -> confirmed promotion
    target: str  # host/ip/url the finding is about
    cwe: Optional[str] = None
    cve: Optional[str] = None
    cvss_score: float = 0.0
    cvss_vector: Optional[str] = None
    attack_technique: Optional[str] = None       # MITRE ATT&CK technique id, e.g. "T1190"
    attack_technique_name: Optional[str] = None
    evidence: str = ""  # short snippet from raw tool output
    source_tool: str = ""
    created_at: datetime = Field(default_factory=_now)

    def dedup_key(self) -> str:
        # Two tools reporting the same issue on the same target collapse to one graph node.
        return "|".join([self.engagement_id, self.category, _norm_target(self.target), self.cve or ""])


class AttackChain(BaseModel):
    """An ordered set of related findings that together describe a plausible attack path.

    Built by the correlation step across the graph; rendered as a highlighted path in the UI and a
    section in the report. `steps` are finding dedup_keys in escalation order.
    """

    id: str
    engagement_id: str
    title: str
    risk: Severity
    steps: list[str] = Field(default_factory=list)
    rationale: str = ""


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _norm_target(target: str) -> str:
    """Normalize a target for deduplication: drop a trailing slash and lowercase a URL's host so
    'https://APP.example.com/' and 'https://app.example.com' don't become two findings."""
    t = target.rstrip("/")
    if t.startswith("http://") or t.startswith("https://"):
        scheme, _, rest = t.partition("://")
        host, sep, path = rest.partition("/")
        return f"{scheme.lower()}://{host.lower()}{sep}{path}"
    return t
