"""Credential attack: hydra parsing, capped command, and scope gating."""
from datetime import datetime, timedelta, timezone

from app.audit import MemoryAuditSink
from app.models import Engagement, Intensity, Run, Scope
from app.scope import sign_scope
from runtime.normalize.hydra import parse_hydra_output
from runtime.orchestrator import execute_tool_step
from runtime.tools.credential import CredentialAttackTool

from tests.test_orchestrator import FakeGraph, FakeSandbox

HYDRA_OUT = (
    "[DATA] attacking ssh://10.0.0.5:22\n"
    "[22][ssh] host: 10.0.0.5   login: admin   password: admin123\n"
    "[STATUS] done\n"
)


def _engagement(allow_creds: bool) -> Engagement:
    now = datetime.now(timezone.utc)
    scope = Scope(allowed_cidrs=["10.0.0.0/24"], not_before=now - timedelta(hours=1),
                  not_after=now + timedelta(hours=1), max_intensity=Intensity.aggressive,
                  allow_credential_attacks=allow_creds)
    scope.signature = sign_scope(scope)
    return Engagement(id="e1", name="t", scope=scope)


def test_hydra_parse_does_not_leak_password():
    out = parse_hydra_output(HYDRA_OUT, engagement_id="e1", run_id="r1", target="10.0.0.5")
    assert len(out.findings) == 1
    f = out.findings[0]
    assert f.category == "credential-attack" and f.target == "10.0.0.5"
    assert "admin" in f.evidence and "admin123" not in f.evidence  # password not stored


def test_command_caps_threads_even_when_aggressive():
    cmd = CredentialAttackTool().build_command("10.0.0.5:22", Intensity.aggressive, {"service": "ssh"})
    t_index = cmd.index("-t")
    assert int(cmd[t_index + 1]) <= 4  # hard thread cap prevents lockout/DoS
    assert "-f" in cmd  # stop on first valid credential (spray, not exhaustive brute force)
    assert cmd[-1] == "ssh" and "10.0.0.5" in cmd


def test_credential_attack_denied_without_flag():
    eng = _engagement(allow_creds=False)
    run = Run(id="r1", engagement_id="e1", target="10.0.0.5")
    step = execute_tool_step(eng, run, CredentialAttackTool(), "10.0.0.5", Intensity.normal,
                             FakeSandbox(HYDRA_OUT.encode()), FakeGraph(), MemoryAuditSink(),
                             context={"service": "ssh"})
    assert not step.allowed and "allow_credential_attacks" in step.reason


def test_credential_attack_runs_when_authorized():
    eng = _engagement(allow_creds=True)
    run = Run(id="r2", engagement_id="e1", target="10.0.0.5")
    graph = FakeGraph()
    step = execute_tool_step(eng, run, CredentialAttackTool(), "10.0.0.5", Intensity.normal,
                             FakeSandbox(HYDRA_OUT.encode()), graph, MemoryAuditSink(),
                             context={"service": "ssh"})
    assert step.allowed and len(graph.findings) == 1
