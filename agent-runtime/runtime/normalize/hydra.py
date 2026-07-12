"""Parse hydra output. Each success line is a discovered valid credential (a high-severity finding)."""
from __future__ import annotations

import re

from app.models import Severity

from ..tools.base import ToolOutput
from .common import make_finding

# e.g. "[22][ssh] host: 10.0.0.5   login: admin   password: admin123"
_LINE = re.compile(r"host:\s*(?P<host>\S+).*login:\s*(?P<login>\S+).*password:\s*(?P<password>\S+)")


def parse_hydra_output(raw: bytes | str, *, engagement_id: str, run_id: str, target: str) -> ToolOutput:
    if isinstance(raw, bytes):
        raw = raw.decode(errors="replace")
    out = ToolOutput()
    for line in raw.splitlines():
        m = _LINE.search(line)
        if not m:
            continue
        host, login = m.group("host"), m.group("login")
        out.findings.append(
            make_finding(
                engagement_id=engagement_id, run_id=run_id,
                title=f"Weak/guessable credential for {login}@{host}",
                category="credential-attack", target=host, severity=Severity.high,
                confidence=0.95, source_tool="hydra", cwe="CWE-1391",
                # The password itself is not stored in the finding evidence.
                evidence=f"valid login discovered: {login}",
            )
        )
    return out
