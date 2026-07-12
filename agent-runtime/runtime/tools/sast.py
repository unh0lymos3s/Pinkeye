"""SAST tools: static analyzers that read source mounted read-only at /src in the sandbox.

They set surface="artifact", so the scope guard authorizes the target against the engagement's
allowed_artifacts (not its network CIDRs). The `target` passed in is the host path to mount.
"""
from __future__ import annotations

from app.models import Intensity

from ..normalize.sast import parse_gitleaks_json, parse_semgrep_json, parse_trivy_json
from .base import ToolOutput


class SemgrepTool:
    name = "semgrep"
    description = "Static code analysis for vulnerabilities. Target is a source path."
    image = "semgrep/semgrep:latest"
    surface = "artifact"

    def build_command(self, target: str, intensity: Intensity) -> list[str]:
        return ["semgrep", "scan", "--config", "auto", "--json", "--quiet", "/src"]

    def parse(self, raw: bytes, *, engagement_id: str, run_id: str, target: str) -> ToolOutput:
        return parse_semgrep_json(raw, engagement_id=engagement_id, run_id=run_id, target=target)


class GitleaksTool:
    name = "gitleaks"
    description = "Detects hardcoded secrets in source. Target is a source path."
    image = "zricethezav/gitleaks:latest"
    surface = "artifact"

    def build_command(self, target: str, intensity: Intensity) -> list[str]:
        return ["detect", "--source", "/src", "--report-format", "json", "--report-path", "/dev/stdout", "--no-banner"]

    def parse(self, raw: bytes, *, engagement_id: str, run_id: str, target: str) -> ToolOutput:
        return parse_gitleaks_json(raw, engagement_id=engagement_id, run_id=run_id, target=target)


class TrivyTool:
    name = "trivy"
    description = "Scans dependencies and containers for known CVEs. Target is a source path."
    image = "aquasec/trivy:latest"
    surface = "artifact"

    def build_command(self, target: str, intensity: Intensity) -> list[str]:
        return ["fs", "--format", "json", "--quiet", "/src"]

    def parse(self, raw: bytes, *, engagement_id: str, run_id: str, target: str) -> ToolOutput:
        return parse_trivy_json(raw, engagement_id=engagement_id, run_id=run_id, target=target)


def sast_tools() -> list:
    return [SemgrepTool(), GitleaksTool(), TrivyTool()]
