"""Markdown report generation, straight from the graph/DB facts. Pure and testable."""
from __future__ import annotations

from datetime import datetime, timezone

from .models import AttackChain, Finding, Severity

_SEV_ORDER = [Severity.critical, Severity.high, Severity.medium, Severity.low, Severity.info]


def generate_report(
    engagement_name: str, metrics: dict, findings: list[Finding], chains: list[AttackChain]
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    by_sev: dict[str, list[Finding]] = {s.value: [] for s in _SEV_ORDER}
    for f in findings:
        by_sev[f.severity.value].append(f)

    lines: list[str] = []
    lines.append(f"# Assessment Report — {engagement_name}")
    lines.append(f"_Generated {now}_\n")

    lines.append("## Summary")
    lines.append(
        f"- CVEs identified: **{metrics.get('cves_identified', 0)}**\n"
        f"- Exposed endpoints: **{metrics.get('exposed_endpoints', 0)}**\n"
        f"- Hosts discovered: **{metrics.get('hosts', 0)}**\n"
        f"- Open issues: **{metrics.get('open_issues', 0)}**\n"
        f"- Runs executed: **{metrics.get('runs', 0)}**\n"
    )

    lines.append("## Attack chains")
    if chains:
        for c in chains:
            lines.append(f"### {c.title}  ·  risk: {c.risk.value}")
            lines.append(c.rationale)
            for i, key in enumerate(c.steps, 1):
                lines.append(f"{i}. `{key}`")
            lines.append("")
    else:
        lines.append("_No multi-step chains correlated._\n")

    lines.append("## Findings by severity")
    for sev in _SEV_ORDER:
        group = by_sev[sev.value]
        if not group:
            continue
        lines.append(f"### {sev.value.title()} ({len(group)})")
        for f in group:
            ref = f" · {f.cve}" if f.cve else (f" · {f.cwe}" if f.cwe else "")
            cvss = f" · CVSS {f.cvss_score:.1f}" if f.cvss_score else ""
            attack = f" · ATT&CK {f.attack_technique} ({f.attack_technique_name})" if f.attack_technique else ""
            lines.append(
                f"- **{f.title}** — {f.target}{ref}{cvss}{attack}  "
                f"_(seen via {f.source_tool}, {f.state.value})_"
            )
        lines.append("")

    return "\n".join(lines)
