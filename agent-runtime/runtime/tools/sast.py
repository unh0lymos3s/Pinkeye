"""SAST tools: static analyzers that read source mounted read-only at /src in the sandbox.

They set surface="artifact", so the scope guard authorizes the target against the engagement's
allowed_artifacts (not its network CIDRs). The `target` passed in is the host path to mount.

Round 6: gitleaks and trivy both reported "0 findings" without having scanned anything — see the
round-6 contract and the round-6 report for the reproduction and the real-Docker verification of the
fixes below. semgrep is unaffected: it runs through the MCP path (see ../mcp), not this sandbox, so it
never hit either bug.
"""
from __future__ import annotations

from app.models import Intensity

from ..normalize.gitleaks import parse_gitleaks_json
from ..normalize.sast import parse_semgrep_json
from ..normalize.trivy import parse_trivy_json
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
    # Round 6 — two independent bugs, both reproduced empirically against v8.30.1 (see the round-6
    # contract), and fixing only one of them still yields zero findings:
    #   1. `detect` defaults to scanning *git history*. The harness hands gitleaks an extracted
    #      upload, not a checkout, so `/src` has no `.git` — without `--no-git`, gitleaks logs
    #      "fatal: not a git repository", reports "0 commits scanned", and exits 0 having opened
    #      nothing. `--no-git` makes it walk the working tree instead.
    #   2. `--report-path /dev/stdout` writes nothing at all, even when leaks are found (reproduced
    #      with AND without `--read-only`, so this is gitleaks refusing to write its report to a
    #      pipe, not a sandbox artifact). The report has to land on a real file, which under
    #      `read_only=True` means a tmpfs — so this tool declares one and reads the report back as an
    #      artifact instead of from stdout. Note gitleaks exits 1 when it *finds* secrets — that is
    #      success, not failure, and `execute_tool_step` only records the exit code, it never gates on
    #      it, so a nonzero exit here must not be treated as an error anywhere downstream.
    tmpfs = ["/tmp"]
    artifact_path = "/tmp/gitleaks-report.json"

    def build_command(self, target: str, intensity: Intensity) -> list[str]:
        return [
            "detect", "--source", "/src", "--no-git",
            "--report-format", "json", "--report-path", self.artifact_path,
            "--no-banner",
        ]

    def parse(self, raw: bytes, *, engagement_id: str, run_id: str, target: str) -> ToolOutput:
        return parse_gitleaks_json(raw, engagement_id=engagement_id, run_id=run_id, target=target)


class TrivyTool:
    name = "trivy"
    description = "Scans dependencies and containers for known CVEs. Target is a source path."
    image = "aquasec/trivy:latest"
    surface = "artifact"
    # Round 6: trivy's vulnerability-DB download needs somewhere writable to unpack to, and under
    # `read_only=True` there is nowhere at all — it failed with "mkdir /tmp/trivy-...: read-only file
    # system" before even looking at /src (see the round-6 contract). `--cache-dir` is pinned inside
    # the declared tmpfs rather than left at its default (~/.cache/trivy, i.e. /root/.cache under this
    # image's user) so the DB lands somewhere we know is writable regardless of which user the image
    # runs as, instead of depending on /root also happening to be covered by the mount.
    tmpfs = ["/tmp"]

    def build_command(self, target: str, intensity: Intensity) -> list[str]:
        return ["fs", "--format", "json", "--quiet", "--cache-dir", "/tmp/trivy-cache", "/src"]

    def parse(self, raw: bytes, *, engagement_id: str, run_id: str, target: str) -> ToolOutput:
        return parse_trivy_json(raw, engagement_id=engagement_id, run_id=run_id, target=target)


def sast_tools() -> list:
    return [SemgrepTool(), GitleaksTool(), TrivyTool()]
