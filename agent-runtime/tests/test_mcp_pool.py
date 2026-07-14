"""Connection pool: warm reuse, reconnect-once, idle eviction, and the isolated docker-run argv.

These use a fake session (no real subprocess), so they're fast and hermetic. The point is the pool
*policy* — that a hosted server is connected once and reused, revived on death, and evicted when idle —
plus that the isolated launch command carries the hardening flags.
"""
import pytest

from runtime.mcp import MCPError
from runtime.mcp.backend import MCPServerSpec
from runtime.mcp.pool import MCPConnectionPool


class FakeSession:
    """Stand-in for MCPSession: records calls, can be made to fail, tracks close()."""

    def __init__(self, spec, fail_times=0):
        self.spec = spec
        self.calls: list = []
        self._fail_times = fail_times
        self.closed = False

    def call_tool(self, name, arguments):
        if self._fail_times > 0:
            self._fail_times -= 1
            raise MCPError("boom")
        self.calls.append((name, dict(arguments)))
        return {"content": [{"type": "text", "text": "ok"}], "isError": False}

    def close(self):
        self.closed = True


def _spec(**kw) -> MCPServerSpec:
    base = {"tool": "scan", "image": "eye-mcp-x:latest", "pooled": True, "target_arg": "path"}
    base.update(kw)
    return MCPServerSpec.from_dict(base)


def _pool(factory, idle_ttl=300.0) -> MCPConnectionPool:
    return MCPConnectionPool(session_factory=factory, idle_ttl=idle_ttl)


def test_warm_reuse_connects_once_for_many_calls():
    created = []
    pool = _pool(lambda spec: created.append(FakeSession(spec)) or created[-1])
    spec = _spec()
    for _ in range(5):
        pool.call(spec, spec.tool, {"path": "/samples"})
    assert pool.connect_count == 1            # one connect...
    assert len(created[0].calls) == 5         # ...served all five calls (warm reuse)


def test_reconnects_once_after_a_dead_session():
    created = []

    def factory(spec):
        # First session fails its first call (simulating a died server), second session is healthy.
        s = FakeSession(spec, fail_times=1 if not created else 0)
        created.append(s)
        return s

    pool = _pool(factory)
    spec = _spec()
    out = pool.call(spec, spec.tool, {"path": "/x"})   # first call fails -> drop -> reconnect -> ok
    assert out["isError"] is False
    assert pool.connect_count == 2
    assert created[0].closed is True                   # the dead one was closed


def test_persistent_failure_raises_after_one_retry():
    created = []

    def factory(spec):
        s = FakeSession(spec, fail_times=99)  # always fails
        created.append(s)
        return s

    pool = _pool(factory)
    spec = _spec()
    with pytest.raises(MCPError):
        pool.call(spec, spec.tool, {"path": "/x"})
    assert pool.connect_count == 2  # original + exactly one reconnect, then give up


def test_idle_eviction_closes_stale_sessions():
    created = []
    clock = {"t": 1000.0}
    pool = MCPConnectionPool(
        session_factory=lambda spec: created.append(FakeSession(spec)) or created[-1],
        idle_ttl=100.0, clock=lambda: clock["t"],
    )
    spec = _spec()
    pool.call(spec, spec.tool, {"path": "/x"})   # last_used = 1000
    clock["t"] = 1050.0
    assert pool.reap_idle() == 0                  # 50s idle < 100s ttl -> kept
    clock["t"] = 1200.0
    assert pool.reap_idle() == 1                  # 200s idle >= ttl -> evicted
    assert created[0].closed is True


def test_shutdown_closes_all_sessions():
    created = []
    pool = _pool(lambda spec: created.append(FakeSession(spec)) or created[-1])
    pool.call(_spec(tool="a"), "a", {"path": "/1"})
    pool.call(_spec(image="eye-mcp-y:latest", tool="b"), "b", {"path": "/2"})
    assert pool.connect_count == 2  # different servers -> two sessions
    pool.shutdown()
    assert all(s.closed for s in created)


def test_same_server_different_tools_share_one_session():
    created = []
    pool = _pool(lambda spec: created.append(FakeSession(spec)) or created[-1])
    # Same image/env/mounts -> same pool_key -> one warm session, even for different tool names.
    pool.call(_spec(tool="tool_a"), "tool_a", {"path": "/1"})
    pool.call(_spec(tool="tool_b"), "tool_b", {"path": "/2"})
    assert pool.connect_count == 1


def test_isolated_launch_argv_has_hardening_and_hides_secrets():
    spec = _spec(env={"SNYK_TOKEN": "s3cret"}, mounts=["/host/src:/samples:ro"])
    command, args, env = spec.launch_argv()
    assert command == "docker"
    joined = " ".join(args)
    for flag in ("--rm", "--cap-drop ALL", "--security-opt no-new-privileges:true",
                 "--read-only", "--pids-limit", "-v /host/src:/samples:ro", "eye-mcp-x:latest"):
        assert flag in joined, flag
    assert "no-new-privileges:true" in joined
    # Secret is forwarded by name only; its value must never appear on the container argv.
    assert "-e SNYK_TOKEN" in joined
    assert "s3cret" not in joined
    assert env["SNYK_TOKEN"] == "s3cret"  # ...but is present in the launcher env for docker to read


def test_non_image_spec_launches_command_directly():
    spec = MCPServerSpec.from_dict({"command": "snyk", "args": ["mcp"], "tool": "t"})
    command, args, _ = spec.launch_argv()
    assert command == "snyk" and args == ["mcp"]
