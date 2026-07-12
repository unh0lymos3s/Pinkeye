"""Enrich a finding with a CVSS score and MITRE ATT&CK technique before it's persisted.

Called once per finding on the write path so the score and technique are stored on the node/row and
available to the dashboard, query API, and report without recomputation.
"""
from __future__ import annotations

from .attack import technique_for
from .cvss import score_for_finding
from .models import Finding


def enrich_finding(f: Finding) -> Finding:
    f.cvss_score = score_for_finding(f.cvss_vector, f.severity)
    technique = technique_for(f.cwe, f.category)
    if technique:
        f.attack_technique, f.attack_technique_name = technique
    return f
