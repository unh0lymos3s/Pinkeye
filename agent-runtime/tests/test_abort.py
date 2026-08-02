"""Round 5 — WS A: cooperative run cancellation.

Two layers under test:

1. `run_agent`'s cooperative checks (agent.py) — a scripted FakeProvider + a small cancellation stub
   that flips "cancelled" after a chosen number of polls, so a test can pin exactly which check in the
   loop is the one that notices the abort: top of the provider-call loop, mid tool-call batch, or
   right after `ask_user` returns. Also covers that a nested specialist (run_specialist) stops rather
   than burning through its own carved-off budget once cancelled.
2. `DockerSandbox.abort()` (sandbox.py) — a fake docker container/client so the kill path can be
   exercised without a real daemon: abort() must make an in-flight `container.wait()` return promptly,
   and a sandbox already told to stop must refuse to start a new container at all.
"""
import threading
import time

import pytest

from app.audit import MemoryAuditSink
from app.events import MemoryRunEventSink, RunEventKind, RunInbox
from app.models import Run

from runtime.agent import Budget, run_agent
from runtime.llm.base import ProviderResponse, ToolCall
from runtime.llm.fake import FakeProvider
from runtime.registry import ToolRegistry
from runtime.sandbox import DockerSandbox, SandboxAborted
from runtime.tools.nmap import NmapTool

from tests.test_nmap_normalize import SAMPLE_XML
from tests.test_orchestrator import FakeGraph, FakeSandbox, make_engagement
from tests.test_subagents import _dispatch, _sandbox


class _CancelAfter:
    """A `RunCancels`-shaped stub: looks cancelled only once `is_cancelled` has been polled more than
    `after` times, so a test can pin exactly which cooperative check in `run_agent`'s loop is the one
    that first observes the abort (top-of-loop, pre-dispatch, or post-ask_user)."""

    def __init__(self, after: int):
        self.after = after
        self.calls = 0

    def is_cancelled(self, run_id) -> bool:
        self.calls += 1
        return self.calls > self.after


class _AlwaysCancelled:
    def is_cancelled(self, run_id) -> bool:
        return True


def _registry():
    return ToolRegistry([NmapTool()])


def _nmap_batch(*targets, cid_prefix="c") -> ProviderResponse:
    return ProviderResponse(tool_calls=[
        ToolCall(id=f"{cid_prefix}{i}", name="nmap", arguments={"target": t, "intensity": "light"})
        for i, t in enumerate(targets)
    ])


# ---- top-of-loop: an abort requested before the run ever calls the model ---------------------------

def test_cancelled_before_first_call_never_reaches_the_provider():
    eng = make_engagement()
    run = Run(id="r1", engagement_id="e1", target="10.0.0.5")
    graph, audit, sink = FakeGraph(), MemoryAuditSink(), MemoryRunEventSink()
    provider = FakeProvider([ProviderResponse(text="should never be reached")])

    result = run_agent(eng, run, provider, _registry(), FakeSandbox(SAMPLE_XML.encode()),
                       graph, audit, budget=Budget(), events=sink, cancels=_AlwaysCancelled())

    assert provider.calls == []  # the loop aborted before ever calling complete()
    assert result.stop_reason == "aborted by operator"
    assert run.status.value == "aborted"
    warnings = [e for e in sink.events if e.kind == RunEventKind.warning]
    assert warnings and warnings[0].data.get("scope") == "abort"
    assert sink.events[-1].kind == RunEventKind.status
    assert sink.events[-1].data["status"] == "aborted"


def test_no_cancels_registry_behaves_exactly_as_before():
    # cancels defaults to None: existing callers (and every other test in this suite) must be
    # unaffected by this feature existing.
    eng = make_engagement()
    run = Run(id="r0", engagement_id="e1", target="10.0.0.5")
    provider = FakeProvider([ProviderResponse(text="done")])

    result = run_agent(eng, run, provider, _registry(), FakeSandbox(SAMPLE_XML.encode()),
                       FakeGraph(), MemoryAuditSink(), budget=Budget())

    assert result.stop_reason == "agent finished"
    assert run.status.value == "completed"


# ---- mid-batch: a parallel batch is cut short, remaining calls never dispatch ----------------------

def test_cancelled_mid_batch_skips_remaining_calls_and_stops_the_run():
    eng = make_engagement()  # allows 10.0.0.0/24
    run = Run(id="r2", engagement_id="e1", target="10.0.0.5")
    graph, audit, sink = FakeGraph(), MemoryAuditSink(), MemoryRunEventSink()
    # Two tool calls in one batch; the cancellation flag flips true between the first and second
    # pre-dispatch check (see _CancelAfter — after=2 lets the top-of-loop check and the first tc's
    # check both pass, then trips on the second tc's check).
    provider = FakeProvider([_nmap_batch("10.0.0.5", "10.0.0.6")])
    cancels = _CancelAfter(after=2)

    result = run_agent(eng, run, provider, _registry(), FakeSandbox(SAMPLE_XML.encode()),
                       graph, audit, budget=Budget(), events=sink, cancels=cancels)

    # Only the first call actually ran the tool (one nmap worth of findings from SAMPLE_XML).
    assert result.tool_calls_used == 1
    assert len(graph.findings) == 2
    assert result.stop_reason == "aborted by operator"
    assert run.status.value == "aborted"
    # Note: the skipped call's "role=tool" message (matching the budget-exhausted branch's discipline
    # so the history never goes structurally invalid) is appended to `messages` in the same iteration
    # the loop then breaks out of, so there is no further `provider.complete()` call for it to show up
    # in `provider.calls` — this run terminates precisely because it must not make one. That padding
    # is exercised for real by test_budget_caps_tool_calls's identical shape in test_agent.py.
    assert any(e.kind == RunEventKind.warning and e.data.get("scope") == "abort" for e in sink.events)


def test_cancellation_does_not_fire_when_never_requested():
    # A batch of two calls with no cancels wired in at all must run both — sanity check that the new
    # mid-batch branch can't accidentally trip on its own.
    eng = make_engagement()
    run = Run(id="r2b", engagement_id="e1", target="10.0.0.5")
    graph, audit = FakeGraph(), MemoryAuditSink()
    provider = FakeProvider([_nmap_batch("10.0.0.5", "10.0.0.6"), ProviderResponse(text="done")])

    result = run_agent(eng, run, provider, _registry(), FakeSandbox(SAMPLE_XML.encode()),
                       graph, audit, budget=Budget())

    assert result.tool_calls_used == 2
    assert len(graph.findings) == 4
    assert result.stop_reason == "agent finished"


# ---- after ask_user returns: a wake (not a real reply) must still be caught promptly ---------------

def test_abort_wakes_ask_user_and_is_caught_right_after():
    eng = make_engagement()
    run = Run(id="r3", engagement_id="e1", target="10.0.0.5")
    sink = MemoryRunEventSink()
    inbox = RunInbox()
    inbox.wake(run.id)  # simulates POST /runs/{id}/abort calling inbox.wake() while parked in ask_user
    ask = ProviderResponse(tool_calls=[ToolCall(
        id="a1", name="ask_user", arguments={"question": "proceed?", "kind": "question"})])
    provider = FakeProvider([ask, ProviderResponse(text="should never be reached")])
    # False for the top-of-loop check and this call's own pre-dispatch check; true from the very next
    # poll on — which is the check run_agent does immediately after _ask_user returns.
    cancels = _CancelAfter(after=2)

    result = run_agent(eng, run, provider, _registry(), FakeSandbox(SAMPLE_XML.encode()),
                       FakeGraph(), MemoryAuditSink(), budget=Budget(), events=sink, inbox=inbox,
                       cancels=cancels)

    assert len(provider.calls) == 1  # never looped back for a second model call
    assert result.stop_reason == "aborted by operator"
    assert run.status.value == "aborted"
    # The wake was NOT a real reply — ask_user treated it like a timeout (auto=True).
    replies = [e for e in sink.events if e.kind == RunEventKind.user_reply]
    assert replies and replies[0].data.get("auto") is True


# ---- nested specialist: cancellation propagates into the child instead of it finishing its budget --

def test_nested_specialist_stops_on_cancellation_instead_of_finishing_its_budget():
    eng = make_engagement()
    run = Run(id="r4", engagement_id="e1", target="10.0.0.5")
    graph, audit, sink = FakeGraph(), MemoryAuditSink(), MemoryRunEventSink()
    provider = FakeProvider([
        _dispatch("scout", "10.0.0.5"),                 # orchestrator delegates to Scout
        _nmap_batch("10.0.0.5", "10.0.0.6", cid_prefix="child"),  # child gets a 2-call batch
    ])
    # after=4: orchestrator top-of-loop(1) + orchestrator's dispatch-tc check(2) + child's
    # top-of-loop(3) + child's first tc check(4) all pass; child's second tc check(5) trips.
    cancels = _CancelAfter(after=4)

    result = run_agent(eng, run, provider, ToolRegistry([]), _sandbox(), graph, audit,
                       budget=Budget(), events=sink, specialist_pool=[NmapTool()], cancels=cancels)

    # The child only ran its first nmap call, not the second — it did not exhaust its carved-off
    # budget, it was cut short by the shared cancellation flag.
    assert len(graph.findings) == 2
    # The parent (top-level, non-nested) run is the one whose status/lifecycle actually changed.
    assert run.status.value == "aborted"
    assert result.stop_reason == "aborted by operator"
    # Both the child and the parent noticed and emitted their own abort warning.
    abort_warnings = [e for e in sink.events
                      if e.kind == RunEventKind.warning and e.data.get("scope") == "abort"]
    assert len(abort_warnings) == 2
    assert any(e.data.get("subagent") == "scout" for e in abort_warnings)


# ==== DockerSandbox.abort(): kill the in-flight container from another thread =======================

class _FakeContainer:
    """Stands in for a docker container: `wait()` blocks until either the fake duration elapses or
    `kill()` is called, polling in small slices so a kill() that lands mid-wait is noticed quickly —
    exactly the property a real container's wait() has once it's actually been killed."""

    def __init__(self, run_seconds: float = 0.0):
        self._run_seconds = run_seconds
        self._killed = threading.Event()
        self.kill_calls = 0
        self.removed = False

    def wait(self, timeout=None):
        deadline = time.monotonic() + self._run_seconds
        while time.monotonic() < deadline:
            if self._killed.wait(0.02):
                break
        return {"StatusCode": 137 if self._killed.is_set() else 0}

    def logs(self, stdout=True, stderr=True, stream=False):
        return iter([b"ok\n"]) if stream else b"ok\n"

    def kill(self):
        self.kill_calls += 1
        self._killed.set()

    def remove(self, force=True):
        self.removed = True


class _FakeContainers:
    def __init__(self, container, calls):
        self._container = container
        self._calls = calls

    def run(self, *args, **kwargs):
        self._calls.append((args, kwargs))
        return self._container


class _FakeDockerClient:
    def __init__(self, container):
        self.run_calls: list = []
        self.containers = _FakeContainers(container, self.run_calls)


def _sandbox_with(container, monkeypatch) -> DockerSandbox:
    import docker
    monkeypatch.setattr(docker, "from_env", lambda: _FakeDockerClient(container))
    return DockerSandbox(timeout_seconds=30)


def test_abort_kills_an_in_flight_container(monkeypatch):
    container = _FakeContainer(run_seconds=5.0)
    sandbox = _sandbox_with(container, monkeypatch)

    outcome = {}

    def _go():
        outcome["result"] = sandbox.run("image", ["cmd"])

    t = threading.Thread(target=_go)
    t.start()
    time.sleep(0.1)  # let the "container" get into container.wait()
    sandbox.abort()
    t.join(timeout=2)

    assert not t.is_alive(), "abort() did not unblock container.wait() promptly"
    assert container.kill_calls >= 1
    assert container.removed is True
    assert outcome["result"].exit_code == 137


def test_run_after_abort_raises_without_starting_a_container(monkeypatch):
    container = _FakeContainer(run_seconds=0.0)
    sandbox = _sandbox_with(container, monkeypatch)
    sandbox.abort()  # nothing in flight yet, but sticky for any future run() on this instance

    with pytest.raises(SandboxAborted):
        sandbox.run("image", ["cmd"])
    assert sandbox._client.run_calls == []  # never even tried to start a container


def test_abort_with_nothing_in_flight_is_a_safe_no_op(monkeypatch):
    container = _FakeContainer(run_seconds=0.0)
    sandbox = _sandbox_with(container, monkeypatch)

    sandbox.abort()  # must not raise

    assert container.kill_calls == 0


def test_run_completes_normally_without_any_abort(monkeypatch):
    container = _FakeContainer(run_seconds=0.0)
    sandbox = _sandbox_with(container, monkeypatch)

    result = sandbox.run("image", ["cmd"])

    assert result.exit_code == 0
    assert container.removed is True
    assert container.kill_calls == 0
