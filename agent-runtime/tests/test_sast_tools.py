"""Round 6 — WS C: gitleaks and trivy stopped reporting "0 findings" on nothing scanned.

Both tools' sandbox commands are covered here (the flags that make the scan actually happen), and
both normalizers are covered against **genuine** captured output — not hand-written approximations —
from real, locked-down `docker run` invocations using the exact sandbox flags from the round-6
contract (`--read-only --cap-drop ALL --security-opt no-new-privileges:true -m 512m --pids-limit 256`)
plus the tmpfs each tool now declares. See the round-6 report for the full transcripts, including the
two independently-reproduced gitleaks bugs (git-history mode on a non-git checkout; `--report-path
/dev/stdout` silently writing nothing) and trivy's read-only-rootfs failure downloading its DB.

Fixture provenance for the gitleaks JSON below: a fixture directory with a planted GitHub
fine-grained PAT (token.txt) and a fake AWS secret access key (config.py) was scanned with
`gitleaks detect --source /src --no-git --report-format json --report-path /out/report.json
--no-banner` under the sandbox flags above (report routed to a bind-mounted /out for this capture
only — the tool itself uses the tmpfs+artifact_path path exercised by build_command below). The
"no leaks" fixture is gitleaks' real empty-report shape: a bare `[]`, not a `{"findings": []}`
wrapper — confirmed by scanning a clean file the same way.
"""
from __future__ import annotations

import json

from app.models import Intensity

from runtime.normalize.gitleaks import parse_gitleaks_json
from runtime.normalize.trivy import parse_trivy_json
from runtime.tools.sast import GitleaksTool, TrivyTool

# Captured verbatim from a real `zricethezav/gitleaks:latest` (v8.30.1) run against a fixture with a
# planted GitHub fine-grained PAT in token.txt and a fake AWS secret in config.py, under the exact
# sandbox flags plus --no-git.
GITLEAKS_REAL_OUTPUT = json.dumps([
    {
        "RuleID": "github-fine-grained-pat",
        "Description": "Found a GitHub Fine-Grained Personal Access Token, risking unauthorized "
                        "repository access and code manipulation.",
        "StartLine": 1, "EndLine": 1, "StartColumn": 1, "EndColumn": 93,
        "Match": "github_pat_ObroUQ4fAbnFbmOInLYaYRvj8vfg1MYTH9xI0M2KScosfogrOwxnq7OMkTkx_OJR1Woctqn7"
                 "3tPy5CqpJq",
        "Secret": "github_pat_ObroUQ4fAbnFbmOInLYaYRvj8vfg1MYTH9xI0M2KScosfogrOwxnq7OMkTkx_OJR1Woctqn"
                  "73tPy5CqpJq",
        "File": "/src/token.txt", "SymlinkFile": "", "Commit": "", "Entropy": 5.419385,
        "Author": "", "Email": "", "Date": "", "Message": "", "Tags": [],
        "Fingerprint": "/src/token.txt:github-fine-grained-pat:1",
    },
    {
        "RuleID": "generic-api-key",
        "Description": "Detected a Generic API Key, potentially exposing access to various services "
                        "and sensitive operations.",
        "StartLine": 3, "EndLine": 3, "StartColumn": 2, "EndColumn": 67,
        "Match": 'AWS_SECRET_ACCESS_KEY = "L5zo+GfdhOYBey+H/3aURIrPhBD94qGl63tOMjWI"',
        "Secret": "L5zo+GfdhOYBey+H/3aURIrPhBD94qGl63tOMjWI",
        "File": "/src/config.py", "SymlinkFile": "", "Commit": "", "Entropy": 4.971928,
        "Author": "", "Email": "", "Date": "", "Message": "", "Tags": [],
        "Fingerprint": "/src/config.py:generic-api-key:3",
    },
])

# Real "no leaks" shape: gitleaks writes a bare empty array, not {"findings": []}.
GITLEAKS_NO_LEAKS = "[]"

# Captured (field-for-field, trimmed to what the parser reads) from a real `aquasec/trivy:latest`
# `fs --format json` run against a requirements.txt pinning a vulnerable `requests`.
TRIVY_REAL_OUTPUT = json.dumps({
    "SchemaVersion": 2,
    "ArtifactName": "/src",
    "Results": [
        {
            "Target": "requirements.txt",
            "Class": "lang-pkgs",
            "Type": "pip",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-32681",
                    "PkgName": "requests",
                    "InstalledVersion": "2.6.0",
                    "FixedVersion": "2.31.0",
                    "Severity": "MEDIUM",
                    "Title": "requests: Proxy-Authorization header leak",
                    "Description": "Requests is a HTTP library. Prior to 2.31.0, Requests...",
                },
            ],
        },
    ],
})


# ==== gitleaks tool: the sandbox command itself ======================================================

def test_gitleaks_command_disables_git_history_mode():
    # Without --no-git, `detect` scans commits, not files — an extracted upload has no .git, so this
    # is the difference between scanning ~0 bytes and scanning the real source tree.
    cmd = GitleaksTool().build_command("/whatever", Intensity.normal)
    assert "--no-git" in cmd


def test_gitleaks_command_routes_report_to_the_declared_artifact_path():
    tool = GitleaksTool()
    cmd = tool.build_command("/whatever", Intensity.normal)
    # /dev/stdout silently produced nothing even when gitleaks found leaks (reproduced with and
    # without --read-only); the report must go to a real file that build_command and artifact_path
    # agree on, not to stdout.
    assert "--report-path" in cmd
    report_path = cmd[cmd.index("--report-path") + 1]
    assert report_path == tool.artifact_path
    assert report_path != "/dev/stdout"
    assert "--report-format" in cmd and cmd[cmd.index("--report-format") + 1] == "json"


def test_gitleaks_declares_a_writable_tmpfs_for_its_report():
    tool = GitleaksTool()
    assert tool.tmpfs == ["/tmp"]
    # The declared artifact path must actually live under a declared tmpfs mount, or the sandbox has
    # nowhere writable to put it and the whole fix is a no-op.
    assert any(tool.artifact_path.startswith(path.rstrip("/") + "/") for path in tool.tmpfs)


# ==== trivy tool: the sandbox command itself =========================================================

def test_trivy_command_pins_cache_dir_under_its_own_tmpfs():
    tool = TrivyTool()
    cmd = tool.build_command("/whatever", Intensity.normal)
    assert "--cache-dir" in cmd
    cache_dir = cmd[cmd.index("--cache-dir") + 1]
    # The default cache dir (~/.cache/trivy) sits outside any mount this tool declares, so under
    # read_only=True it would fail exactly like the unpatched /tmp did. Pinning it under the declared
    # tmpfs is what actually fixes the "read-only file system" error, not just adding a tmpfs.
    assert any(cache_dir.startswith(path.rstrip("/") + "/") for path in tool.tmpfs)


def test_trivy_declares_a_writable_tmpfs():
    # Confirmed empirically: trivy's DB download fails with "mkdir /tmp/trivy-...: read-only file
    # system" before it ever looks at /src, on a rootfs with no writable /tmp at all.
    assert TrivyTool().tmpfs == ["/tmp"]


# ==== gitleaks normalizer, against genuine output ====================================================

def test_gitleaks_parses_real_output_into_two_findings():
    out = parse_gitleaks_json(GITLEAKS_REAL_OUTPUT, engagement_id="e1", run_id="r1", target="/src")
    assert len(out.findings) == 2


def test_gitleaks_finding_fields_match_the_real_pat_leak():
    out = parse_gitleaks_json(GITLEAKS_REAL_OUTPUT, engagement_id="e1", run_id="r1", target="/src")
    pat = next(f for f in out.findings if "github-fine-grained-pat" in f.title)
    assert pat.category == "sast:secret"
    assert pat.severity.value == "high"
    assert pat.cwe == "CWE-798"
    assert pat.target == "/src/token.txt:1"  # File:StartLine, exactly what the graph keys findings on
    assert pat.source_tool == "gitleaks"
    assert "Fine-Grained Personal Access Token" in pat.evidence


def test_gitleaks_finding_fields_match_the_real_generic_key_leak():
    out = parse_gitleaks_json(GITLEAKS_REAL_OUTPUT, engagement_id="e1", run_id="r1", target="/src")
    key = next(f for f in out.findings if "generic-api-key" in f.title)
    assert key.target == "/src/config.py:3"
    assert key.severity.value == "high"


def test_gitleaks_findings_carry_the_fields_dedup_relies_on():
    # Finding.dedup_key() joins engagement_id, category, normalized target, and cve — every finding
    # here needs a non-empty category and a target that actually varies per-leak (file:line), or two
    # unrelated secrets would collapse into one graph node.
    out = parse_gitleaks_json(GITLEAKS_REAL_OUTPUT, engagement_id="e1", run_id="r1", target="/src")
    keys = {f.dedup_key() for f in out.findings}
    assert len(keys) == 2  # both leaks are distinct issues and must not collide


def test_gitleaks_no_leaks_is_zero_findings_not_an_error():
    # Real "clean scan" shape: a bare `[]`. Must not be confused with the artifact never having been
    # written at all (that distinction is artifact_missing, handled by the sandbox layer, not here).
    out = parse_gitleaks_json(GITLEAKS_NO_LEAKS, engagement_id="e1", run_id="r1", target="/src")
    assert out.findings == []


def test_gitleaks_tolerates_garbage_input_without_raising():
    # An empty payload (artifact requested but the tool crashed before writing anything coherent)
    # must degrade to zero findings, not blow up execute_tool_step's parse step.
    out = parse_gitleaks_json(b"", engagement_id="e1", run_id="r1", target="/src")
    assert out.findings == []


# ==== trivy normalizer, against genuine output =======================================================

def test_trivy_parses_real_output_into_a_finding():
    out = parse_trivy_json(TRIVY_REAL_OUTPUT, engagement_id="e1", run_id="r1", target="/src")
    assert len(out.findings) == 1


def test_trivy_finding_fields_match_the_real_cve():
    out = parse_trivy_json(TRIVY_REAL_OUTPUT, engagement_id="e1", run_id="r1", target="/src")
    f = out.findings[0]
    assert f.cve == "CVE-2023-32681"
    assert f.category == "sast:dependency"
    assert f.severity.value == "medium"
    assert f.target == "requirements.txt:requests"
    assert f.source_tool == "trivy"
    assert "requests" in f.title and "CVE-2023-32681" in f.title


def test_trivy_no_vulnerabilities_is_zero_findings():
    clean = json.dumps({"Results": [{"Target": "requirements.txt", "Vulnerabilities": None}]})
    out = parse_trivy_json(clean, engagement_id="e1", run_id="r1", target="/src")
    assert out.findings == []


def test_trivy_tolerates_garbage_input_without_raising():
    out = parse_trivy_json(b"not json", engagement_id="e1", run_id="r1", target="/src")
    assert out.findings == []
