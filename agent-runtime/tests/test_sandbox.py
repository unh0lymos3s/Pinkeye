"""Round 6 — WS A: `DockerSandbox.run()` gains three capabilities, all against a fake docker client
(the fakes follow the same shape `test_abort.py` established — a `_FakeContainer`/`_FakeContainers`/
`_FakeDockerClient` trio patched in for `docker.from_env`). Real-Docker verification of tmpfs
writability and artifact extraction is done separately against the actual daemon; see the round-6
report for that transcript — a fake client can prove the plumbing calls docker-py correctly, but it
can't prove docker-py's tmpfs/get_archive semantics are what we assume they are.

1. tmpfs: a tool's declared writable paths become size-capped, noexec/nosuid/nodev tmpfs mounts, and
   nothing else about the container config changes for tools that don't ask.
2. artifact extraction: `artifact_path` is read back via the container's tar-stream endpoint after it
   exits and before it's removed, capped at EYE_TOOL_MAX_OUTPUT_BYTES the same as stdout.
3. per-tool mem_limit/timeout_seconds overrides, defaulting to the sandbox's own configured values.
"""
from __future__ import annotations

import io
import tarfile

from runtime.sandbox import DEFAULT_TMPFS_SIZE_MB, DockerSandbox, _build_tmpfs, _tmpfs_size_mb


def _tar_bytes(name: str, content: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(name=name)
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


class _FakeContainer:
    """Stands in for a docker container across run()/wait()/logs()/get_archive()/remove(). `archive`
    maps a requested path to the tar bytes `get_archive` should hand back — an absent key means the
    tool never wrote that path, which is exactly the "artifact missing" case under test."""

    def __init__(self, exit_code: int = 0, logs: bytes = b"", archive: dict[str, bytes] | None = None):
        self.exit_code = exit_code
        self._logs = logs
        self._archive = archive or {}
        self.removed = False
        self.remove_order: list[str] = []

    def wait(self, timeout=None):
        return {"StatusCode": self.exit_code}

    def logs(self, stdout=True, stderr=True, stream=False):
        return iter([self._logs]) if stream else self._logs

    def get_archive(self, path, chunk_size=None):
        import docker.errors

        self.remove_order.append("get_archive")
        if path not in self._archive:
            raise docker.errors.NotFound(f"no such file or directory: {path}")
        return iter([self._archive[path]]), {"name": path}

    def kill(self):
        pass

    def remove(self, force=True):
        self.removed = True
        self.remove_order.append("remove")


class _FakeContainers:
    def __init__(self, container):
        self._container = container
        self.run_calls: list[tuple] = []

    def run(self, *args, **kwargs):
        self.run_calls.append((args, kwargs))
        return self._container


class _FakeDockerClient:
    def __init__(self, container):
        self.containers = _FakeContainers(container)


def _sandbox_with(container, monkeypatch, **kwargs) -> DockerSandbox:
    import docker

    monkeypatch.setattr(docker, "from_env", lambda: _FakeDockerClient(container))
    return DockerSandbox(**kwargs)


# ==== tmpfs: the only writable surface a container gets, and it's size-capped =======================

def test_tmpfs_paths_become_capped_rw_mounts(monkeypatch):
    container = _FakeContainer()
    sandbox = _sandbox_with(container, monkeypatch)

    sandbox.run("image", ["cmd"], tmpfs=["/tmp", "/zap/wrk"])

    _, kwargs = sandbox._client.containers.run_calls[0]
    expected_opts = f"rw,noexec,nosuid,nodev,size={_tmpfs_size_mb()}m"
    assert kwargs["tmpfs"] == {"/tmp": expected_opts, "/zap/wrk": expected_opts}
    # tmpfs is the *only* concession — the root filesystem stays read-only regardless.
    assert kwargs["read_only"] is True
    assert kwargs["cap_drop"] == ["ALL"]
    assert kwargs["security_opt"] == ["no-new-privileges:true"]


def test_no_tmpfs_declared_leaves_the_container_config_untouched(monkeypatch):
    # The overwhelming majority of tools (nmap, semgrep, nuclei's normal path, ...) don't declare
    # tmpfs at all; they must see exactly today's container config, i.e. no tmpfs kwarg turned on.
    container = _FakeContainer()
    sandbox = _sandbox_with(container, monkeypatch)

    sandbox.run("image", ["cmd"])

    _, kwargs = sandbox._client.containers.run_calls[0]
    assert kwargs["tmpfs"] is None


def test_tmpfs_size_is_env_tunable(monkeypatch):
    monkeypatch.setenv("EYE_TOOL_TMPFS_SIZE", "16")
    assert _build_tmpfs(["/tmp"]) == {"/tmp": "rw,noexec,nosuid,nodev,size=16m"}


def test_tmpfs_size_falls_back_to_default_on_unusable_env(monkeypatch):
    # A garbage or missing EYE_TOOL_TMPFS_SIZE must never leave the mount uncapped — that would trade
    # a false negative for a host-level DoS, which is exactly the failure mode this cap exists to
    # prevent. Falling back to a sane default (not "unlimited") is the only safe behavior.
    monkeypatch.setenv("EYE_TOOL_TMPFS_SIZE", "not-a-number")
    assert _build_tmpfs(["/tmp"]) == {"/tmp": f"rw,noexec,nosuid,nodev,size={DEFAULT_TMPFS_SIZE_MB}m"}


def test_tmpfs_size_rejects_zero_and_negative(monkeypatch):
    # env_int's `minimum` guard: a "0m" or negative tmpfs would either mean unlimited or be nonsense
    # to the docker API, so garbage-in falls back to the default rather than being taken literally.
    monkeypatch.setenv("EYE_TOOL_TMPFS_SIZE", "0")
    assert _tmpfs_size_mb() == DEFAULT_TMPFS_SIZE_MB


# ==== artifact extraction: the only way some tools can hand back a report at all ====================

def test_artifact_path_is_read_back_after_the_container_exits(monkeypatch):
    payload = b'{"leaks": [{"foo": "bar"}]}'
    # gitleaks-shaped: exit 1 because leaks were found, report only readable as a file.
    container = _FakeContainer(exit_code=1, archive={"/report.json": _tar_bytes("report.json", payload)})
    sandbox = _sandbox_with(container, monkeypatch)

    result = sandbox.run("image", ["cmd"], artifact_path="/report.json")

    assert result.artifact == payload
    assert result.artifact_missing is False
    assert result.artifact_truncated is False
    assert result.exit_code == 1  # a nonzero exit doesn't stop the artifact from being valid


def test_artifact_not_requested_leaves_it_none_not_missing(monkeypatch):
    # "didn't ask" and "asked and got nothing" are different things; only the latter is a signal.
    container = _FakeContainer()
    sandbox = _sandbox_with(container, monkeypatch)

    result = sandbox.run("image", ["cmd"])

    assert result.artifact is None
    assert result.artifact_missing is False


def test_artifact_missing_when_the_tool_never_wrote_it(monkeypatch):
    container = _FakeContainer(archive={})  # nothing at the requested path
    sandbox = _sandbox_with(container, monkeypatch)

    result = sandbox.run("image", ["cmd"], artifact_path="/report.json")

    assert result.artifact is None
    assert result.artifact_missing is True


def test_artifact_is_capped_at_max_output_bytes(monkeypatch):
    monkeypatch.setenv("EYE_TOOL_MAX_OUTPUT_BYTES", "8")
    payload = b"0123456789ABCDEF"  # 16 bytes; cap is 8
    container = _FakeContainer(archive={"/report.json": _tar_bytes("report.json", payload)})
    sandbox = _sandbox_with(container, monkeypatch)

    result = sandbox.run("image", ["cmd"], artifact_path="/report.json")

    assert result.artifact == payload[:8]
    assert result.artifact_truncated is True


def test_artifact_extraction_happens_before_container_removal(monkeypatch):
    # Ordering matters: get_archive only works while the container still exists. Prove the sequence
    # rather than just the outcome, since a reordering bug (extract-after-remove) would silently
    # start returning "missing" for every artifact tool instead of failing loudly.
    container = _FakeContainer(archive={"/r": _tar_bytes("r", b"data")})
    sandbox = _sandbox_with(container, monkeypatch)

    sandbox.run("image", ["cmd"], artifact_path="/r")

    assert container.remove_order == ["get_archive", "remove"]


# ==== per-tool resource overrides: ZAP needs more than the general-purpose default ===================

def test_mem_limit_override_is_passed_to_the_container(monkeypatch):
    container = _FakeContainer()
    sandbox = _sandbox_with(container, monkeypatch, mem_limit="512m")

    sandbox.run("image", ["cmd"], mem_limit="2g")

    _, kwargs = sandbox._client.containers.run_calls[0]
    assert kwargs["mem_limit"] == "2g"


def test_no_mem_limit_override_keeps_the_sandbox_default(monkeypatch):
    container = _FakeContainer()
    sandbox = _sandbox_with(container, monkeypatch, mem_limit="512m")

    sandbox.run("image", ["cmd"])

    _, kwargs = sandbox._client.containers.run_calls[0]
    assert kwargs["mem_limit"] == "512m"


def test_timeout_override_is_used_for_container_wait(monkeypatch):
    calls = []
    container = _FakeContainer()
    real_wait = container.wait
    container.wait = lambda timeout=None: (calls.append(timeout), real_wait(timeout=timeout))[1]
    sandbox = _sandbox_with(container, monkeypatch, timeout_seconds=300)

    sandbox.run("image", ["cmd"], timeout_seconds=900)

    assert calls == [900]


def test_no_timeout_override_keeps_the_sandbox_default(monkeypatch):
    calls = []
    container = _FakeContainer()
    real_wait = container.wait
    container.wait = lambda timeout=None: (calls.append(timeout), real_wait(timeout=timeout))[1]
    sandbox = _sandbox_with(container, monkeypatch, timeout_seconds=300)

    sandbox.run("image", ["cmd"])

    assert calls == [300]


# ==== plain run() is unaffected: no tmpfs, no artifact, no overrides =================================

def test_plain_run_is_unaffected_by_any_of_the_new_kwargs(monkeypatch):
    container = _FakeContainer(exit_code=0, logs=b"ok")
    sandbox = _sandbox_with(container, monkeypatch)

    result = sandbox.run("image", ["cmd"])

    assert result.exit_code == 0
    assert result.stdout == b"ok"
    assert result.artifact is None
    assert result.artifact_missing is False
    assert result.artifact_truncated is False
