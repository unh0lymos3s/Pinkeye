"""Parse gitleaks JSON reports into secret-leak findings.

Split out of the old combined `sast.py` normalizer (round 6) because gitleaks needed its own set of
sandbox fixes (see `../tools/sast.py`) and its own real-output verification — semgrep and trivy have
nothing to do with either. This module only cares about the bytes it is handed, not how they got
here: whether they came from stdout or (gitleaks' case) an artifact pulled out of the sandbox after
the container exited is `../tools/sast.py`'s concern, not this one's.

Verified against genuine `gitleaks detect --no-git --report-format json` output (v8.30.1) from a real,
locked-down container run against a fixture with a planted GitHub PAT and an AWS secret — see the
round-6 report. The real report's top-level shape is a bare JSON array of leak objects; there is no
"findings" wrapper in the wild, but the fallback below is kept because it's a one-line safety net
against a future gitleaks version nesting the array under a key, and costs nothing.
"""
from __future__ import annotations

import json

from app.models import Severity

from ..tools.base import ToolOutput
from .common import make_finding


def parse_gitleaks_json(raw: bytes | str, *, engagement_id: str, run_id: str, target: str) -> ToolOutput:
    data = _load(raw)
    # gitleaks emits a top-level JSON array of leaks; a `[]` array (no leaks, still valid JSON) and a
    # `{}` fallback (empty/unparseable payload) both correctly produce zero findings via .get below.
    leaks = data if isinstance(data, list) else data.get("findings", [])
    out = ToolOutput()
    for leak in leaks:
        # Real output nests the secret's location as `File`/`StartLine` at the top level of each leak
        # (not under a "location" object the way some SARIF-style tools do), and `File` is the
        # in-container absolute path (e.g. "/src/config.py") since gitleaks was pointed at /src — kept
        # as-is rather than stripped, matching how semgrep's `path` is used verbatim elsewhere in this
        # package, so a finding's `target` is always resolvable back to the mounted source tree.
        out.findings.append(
            make_finding(
                engagement_id=engagement_id, run_id=run_id,
                title=f"Secret leaked: {leak.get('RuleID', 'unknown rule')}",
                category="sast:secret",
                target=_loc(leak.get("File", target), leak.get("StartLine")),
                severity=Severity.high,  # a committed secret is high by default
                confidence=0.85, source_tool="gitleaks", cwe="CWE-798",
                evidence=(leak.get("Description") or leak.get("Match", ""))[:200],
            )
        )
    return out


def _loc(path: str, start_line) -> str:
    return f"{path}:{start_line}" if start_line else path


def _load(raw: bytes | str):
    if isinstance(raw, bytes):
        raw = raw.decode(errors="replace")
    try:
        return json.loads(raw or "{}")
    except json.JSONDecodeError:
        return {}
