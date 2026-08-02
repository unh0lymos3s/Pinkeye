"""Parser for semgrep, the one SAST tool whose sandbox path never needed fixing (it runs through MCP,
not the Docker sandbox — see ../tools/sast.py). All emit JSON.

SAST findings target a source location (file:line) rather than a host, and carry CWE where the tool
provides it so they can later be correlated with runtime (DAST) findings on the same weakness class.

gitleaks and trivy used to be parsed here too. Round 6 split them into their own `gitleaks.py`/
`trivy.py` modules — each tool needed its own independent sandbox fix and its own real-output
verification, so keeping them in one file no longer matched how the code changes together. They are
re-exported below unchanged so existing callers/imports of `normalize.sast` keep working.
"""
from __future__ import annotations

import json

from ..tools.base import ToolOutput
from .common import make_finding, to_severity
from .gitleaks import parse_gitleaks_json  # noqa: F401 - re-exported for back-compat callers
from .trivy import parse_trivy_json  # noqa: F401 - re-exported for back-compat callers


def _loc(path: str, start_line) -> str:
    return f"{path}:{start_line}" if start_line else path


def parse_semgrep_json(raw: bytes | str, *, engagement_id: str, run_id: str, target: str) -> ToolOutput:
    data = _load(raw)
    out = ToolOutput()
    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        cwe = _first_cwe(meta.get("cwe"))
        out.findings.append(
            make_finding(
                engagement_id=engagement_id, run_id=run_id,
                title=r.get("check_id", "semgrep finding").split(".")[-1],
                category="sast:semgrep",
                target=_loc(r.get("path", target), r.get("start", {}).get("line")),
                severity=to_severity(extra.get("severity") or meta.get("impact")),
                confidence=0.7, source_tool="semgrep", cwe=cwe,
                evidence=(extra.get("message") or "")[:300],
            )
        )
    return out


def _load(raw: bytes | str):
    if isinstance(raw, bytes):
        raw = raw.decode(errors="replace")
    try:
        return json.loads(raw or "{}")
    except json.JSONDecodeError:
        return {}


def _first_cwe(cwe) -> str | None:
    # semgrep metadata.cwe is often a string or list like "CWE-79: Cross-site Scripting".
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else None
    if isinstance(cwe, str) and cwe.upper().startswith("CWE"):
        return cwe.split(":")[0].strip().upper()
    return None
