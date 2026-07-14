"""Cross-run network-memory tests. NetworkMemory runs as a pure in-memory differ here (no graph, no
db), so classification, gone-detection, exploitable transitions, and clustering are all exercised
without a live backend."""
from types import SimpleNamespace

from app.memory import NetworkMemory
from app.models import Finding, FindingState, Severity


def svc(address, port, proto="tcp", service="", product=""):
    # Duck-typed stand-in for runtime.tools.base.ServiceObservation.
    return SimpleNamespace(address=address, port=port, proto=proto, service=service, product=product)


def finding(target, category="sql-injection", severity=Severity.critical, state=FindingState.confirmed):
    return Finding(id="f", engagement_id="e1", run_id="r", title="t", category=category,
                   severity=severity, state=state, target=target)


def test_classifies_new_changed_and_unchanged():
    m = NetworkMemory()
    d1 = m.observe("e1", "run1", [svc("10.0.0.5", 22, service="ssh", product="OpenSSH 8.0")], [])
    assert any(e["kind"] == "device" for e in d1.added)
    assert any(e["kind"] == "service" for e in d1.added)

    # Re-observing the identical service produces no delta.
    d2 = m.observe("e1", "run2", [svc("10.0.0.5", 22, service="ssh", product="OpenSSH 8.0")], [])
    assert d2.is_empty()

    # A version change is classified as changed, with before/after.
    d3 = m.observe("e1", "run3", [svc("10.0.0.5", 22, service="ssh", product="OpenSSH 9.6")], [])
    assert d3.changed and any("9.6" in e["label"] for e in d3.changed)
    assert d3.changed[0]["before"]["product"] == "OpenSSH 8.0"


def test_newly_exploitable_endpoint_and_target_device():
    m = NetworkMemory()
    # A confirmed critical web finding flags the endpoint exploitable.
    d = m.observe("e1", "run1", [], [finding("https://app.example.com/login")])
    assert any(e["kind"] == "endpoint" for e in d.newly_exploitable)

    # An exploitation-category host finding flags the device as a target.
    d2 = m.observe("e1", "run1", [], [finding("10.0.0.5", category="exploitation",
                                              severity=Severity.high)])
    assert any(e["kind"] == "device" and e["key"] == "10.0.0.5" for e in d2.newly_exploitable)

    # A low, unconfirmed finding does not make anything exploitable.
    d3 = m.observe("e1", "run1", [], [finding("10.0.0.9", category="info", severity=Severity.low,
                                             state=FindingState.suspected)])
    assert d3.is_empty()


def test_closed_port_marked_gone_only_on_reobserved_host():
    m = NetworkMemory()
    m.observe("e1", "run1", [svc("10.0.0.5", 22), svc("10.0.0.5", 80)], [])
    # Second run re-scans the host but 80 is now closed.
    d = m.observe("e1", "run2", [svc("10.0.0.5", 22)], [])
    assert any(e["key"] == "10.0.0.5:80/tcp" for e in d.removed)
    # A findings-only step (no services) must never false-flag the host's ports as gone.
    d2 = m.observe("e1", "run3", [], [finding("10.0.0.5", category="info", severity=Severity.info,
                                             state=FindingState.suspected)])
    assert not d2.removed


def test_snapshot_clusters_services_under_devices():
    m = NetworkMemory()
    m.observe("e1", "run1", [svc("10.0.0.5", 22, service="ssh"),
                             svc("10.0.0.5", 80, service="http")], [])
    m.observe("e1", "run1", [], [finding("https://10.0.0.5/admin")])
    snap = m.snapshot("e1")
    assert len(snap["devices"]) == 1
    dev = snap["devices"][0]
    assert dev["address"] == "10.0.0.5"
    assert len(dev["services"]) == 2
    assert [s["port"] for s in dev["services"]] == [22, 80]  # clustered + sorted


def test_deltas_for_run_aggregates_across_steps():
    m = NetworkMemory()
    m.observe("e1", "run1", [svc("10.0.0.5", 22)], [])
    m.observe("e1", "run1", [svc("10.0.0.6", 443)], [])
    agg = m.deltas_for_run("run1")
    keys = {e["key"] for e in agg.added}
    assert "10.0.0.5" in keys and "10.0.0.6" in keys
