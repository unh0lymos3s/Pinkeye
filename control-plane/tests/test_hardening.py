"""Phase 6 tests: replay integrity and dedup normalization (control-plane side)."""
from app.audit import AuditEvent, EventType, hash_output
from app.models import Finding
from app.replay import reconstruct, verify_output


def _events():
    out = b"<nmaprun/>"
    return [
        AuditEvent(engagement_id="e1", run_id="r1", type=EventType.scope_decision,
                   tool="nmap", target="10.0.0.5", allowed=True),
        AuditEvent(engagement_id="e1", run_id="r1", type=EventType.tool_finished,
                   tool="nmap", target="10.0.0.5", output_sha256=hash_output(out)),
        AuditEvent(engagement_id="e1", run_id="r1", type=EventType.finding_recorded,
                   tool="nmap", target="10.0.0.5", detail="low: Open port 22/tcp"),
    ], out


def test_reconstruct_builds_ordered_steps():
    events, _ = _events()
    steps = reconstruct(events, "r1")
    assert len(steps) == 1
    assert steps[0].tool == "nmap" and steps[0].allowed is True
    assert steps[0].findings == ["low: Open port 22/tcp"]


def test_verify_output_detects_matching_and_tampered():
    events, out = _events()
    assert verify_output(events, "r1", "nmap", out)          # same bytes -> hash matches
    assert not verify_output(events, "r1", "nmap", b"changed")  # drift -> mismatch


def test_dedup_normalizes_url_target():
    a = Finding(id="1", engagement_id="e1", run_id="r1", title="x", category="nuclei:xss",
                target="https://APP.example.com/path/")
    b = Finding(id="2", engagement_id="e1", run_id="r1", title="x", category="nuclei:xss",
                target="https://app.example.com/path")
    assert a.dedup_key() == b.dedup_key()  # host case + trailing slash collapse
