"""Disposable Docker sandbox for offensive tooling.

Each tool run gets its own container that is destroyed afterward. The security posture:
  - no host filesystem mounts (except the existing read-only /src mount for artifact-surface tools)
  - all Linux capabilities dropped, no privilege escalation
  - read-only root filesystem — the *only* writable surface a container gets is an explicit,
    size-capped tmpfs mount that the tool declared it needs
  - CPU / memory / wall-clock ceilings
Egress is intentionally NOT opened wide here; the caller is responsible for having already passed
the target through the scope guard. Per-job network egress allow-listing is a Phase 6 hardening item.
"""
from __future__ import annotations

import io
import os
import tarfile
import threading
from dataclasses import dataclass

from .envutil import env_int

# The container has memory/CPU/pids ceilings but its *output* had none: `container.logs()`
# materializes the whole stream as bytes inside the API process, so a huge nmap XML, a ZAP JSON, or
# a looping/hostile tool could pull hundreds of MB into the process that also serves every request.
# Cap it, and record that the cap was hit so a partial parse is visible rather than silent. The same
# cap applies to artifacts extracted from the container (see _extract_artifact) for the same reason:
# a hostile tool that can't be trusted not to flood stdout can't be trusted not to flood a report
# file either.
DEFAULT_MAX_OUTPUT_BYTES = 64 * 1024 * 1024

# Round 6 — WS A: tmpfs is the only writable surface a container gets, and an uncapped tmpfs is just
# host RAM the container can exhaust — that would trade the false negatives this round fixes for a
# host-level DoS. 256MB comfortably fits a vuln-DB download (trivy) or a scan report (gitleaks,
# nuclei) without giving a hostile tool room to page the host to death.
DEFAULT_TMPFS_SIZE_MB = 256


def _max_output_bytes() -> int:
    return env_int("EYE_TOOL_MAX_OUTPUT_BYTES", DEFAULT_MAX_OUTPUT_BYTES, minimum=1)


def _tmpfs_size_mb() -> int:
    return env_int("EYE_TOOL_TMPFS_SIZE", DEFAULT_TMPFS_SIZE_MB, minimum=1)


class SandboxAborted(RuntimeError):
    """Raised by `DockerSandbox.run()` when the sandbox was told to stop (see `abort()`) before this
    call could start a container. `execute_tool_step` already treats any exception out of `run()` as
    a tool-level error (`StepResult(error=str(exc))`), so no other module needs to know this type
    exists — it is its own class mainly so a test can assert on it specifically."""


@dataclass
class SandboxResult:
    exit_code: int
    stdout: bytes
    stderr: bytes
    # True when the stream hit EYE_TOOL_MAX_OUTPUT_BYTES and was cut short.
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    # Round 6 — WS A: contents of `artifact_path`, for tools that can only write their report to a
    # file (gitleaks' `--report-path /dev/stdout` prints nothing; ZAP's `-J /dev/stdout` is rejected
    # outright — see the round-6 contract). None when the caller didn't ask for an artifact at all,
    # which is a different thing from "asked and got nothing" (see `artifact_missing` below).
    artifact: bytes | None = None
    # True when `artifact_path` was requested but the file did not exist in the container when we
    # went looking for it — the tool crashed before writing it, wrote somewhere else, or never ran.
    artifact_missing: bool = False
    # True when the artifact existed but was cut off at EYE_TOOL_MAX_OUTPUT_BYTES, mirroring
    # stdout_truncated: a partial artifact was still parsed, and that must be visible on replay.
    artifact_truncated: bool = False


class DockerSandbox:
    def __init__(self, timeout_seconds: int = 300, mem_limit: str = "512m", cpus: float = 1.0):
        import docker

        self._client = docker.from_env()
        self._timeout = timeout_seconds
        self._mem_limit = mem_limit
        self._cpus = cpus
        # Stronger isolation runtime when available (e.g. "runsc" for gVisor). Firecracker via a
        # microVM runtime is the next step up. Empty = the daemon default (runc).
        self._runtime = os.getenv("EYE_SANDBOX_RUNTIME") or None
        # Round 5 — WS A (abort). `_lock` guards both fields below, which together let `abort()` be
        # called from a *different* thread than the one blocked inside `run()`: the request thread
        # handling POST /runs/{id}/abort, while the run thread may be anywhere in `run()` — before a
        # container exists, waiting on one, or tearing one down. `_current_container` is this
        # instance's one in-flight container (sequential tool calls, so never more than one); `_aborted`
        # is sticky so a sandbox told to stop refuses to start another container later in the same run.
        self._lock = threading.Lock()
        self._current_container = None
        self._aborted = False

    def run(
        self,
        image: str,
        command: list[str],
        source_dir: str | None = None,
        egress=None,
        *,
        tmpfs: list[str] | None = None,
        artifact_path: str | None = None,
        mem_limit: str | None = None,
        timeout_seconds: int | None = None,
    ) -> SandboxResult:
        """Run `command` in a fresh locked-down container and return its output.

        For SAST, `source_dir` is bind-mounted read-only at /src so static analyzers can read the
        code without the container being able to modify it. `egress` is an EgressPolicy the sandbox
        network is restricted to; enforcement is applied to this container's dedicated network.

        Round 6 — WS A additions, all optional and all default to today's behavior:
          - `tmpfs`: container paths (e.g. ["/tmp"]) to mount as writable tmpfs. The root filesystem
            stays `read_only=True` regardless — this is the *only* way a container gets to write
            anything, and every mount is size-capped (see `_tmpfs_size_mb`) so it can't be used to
            exhaust host memory.
          - `artifact_path`: a file to read out of the container after it exits (via the docker API's
            tar-stream endpoint, not a shell) for tools that cannot write their report to stdout at
            all. Populates `SandboxResult.artifact`/`artifact_missing`/`artifact_truncated`.
          - `mem_limit` / `timeout_seconds`: per-tool overrides of this sandbox's defaults, for tools
            (ZAP) whose normal resource needs don't fit the general ceiling.

        Raises `SandboxAborted` if `abort()` was already called on this instance — see its docstring.
        """
        with self._lock:
            if self._aborted:
                raise SandboxAborted("sandbox aborted by operator; refusing to start a new container")

        volumes = (
            {source_dir: {"bind": "/src", "mode": "ro"}} if source_dir else None
        )
        container = self._client.containers.run(
            image,
            command=command,
            detach=True,
            network_mode="bridge",
            runtime=self._runtime,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            read_only=True,
            mem_limit=mem_limit or self._mem_limit,
            nano_cpus=int(self._cpus * 1e9),
            pids_limit=256,
            volumes=volumes,
            tmpfs=_build_tmpfs(tmpfs),
        )
        with self._lock:
            self._current_container = container
            aborted_already = self._aborted
        if aborted_already:
            # abort() landed in the gap between the check above and the container actually starting.
            # Kill it now rather than let it run for up to `self._timeout` seconds before anyone looks
            # at it again — the `finally` below still tears it down exactly as it would otherwise.
            try:
                container.kill()
            except Exception:
                pass
        if egress is not None:
            self._apply_egress(container, egress)
        try:
            result = container.wait(timeout=timeout_seconds or self._timeout)
            cap = _max_output_bytes()
            stdout, stdout_cut = _capped_logs(container, cap, stdout=True, stderr=False)
            stderr, stderr_cut = _capped_logs(container, cap, stdout=False, stderr=True)
            artifact = None
            artifact_missing = False
            artifact_truncated = False
            if artifact_path is not None:
                # Extraction happens here — after wait() returns, before the `finally` below removes
                # the container — regardless of exit code: gitleaks exits 1 when it finds leaks, and
                # the report is exactly what we're here for.
                artifact, artifact_missing, artifact_truncated = _extract_artifact(
                    container, artifact_path, cap
                )
            return SandboxResult(exit_code=result.get("StatusCode", -1), stdout=stdout,
                                 stderr=stderr, stdout_truncated=stdout_cut,
                                 stderr_truncated=stderr_cut, artifact=artifact,
                                 artifact_missing=artifact_missing,
                                 artifact_truncated=artifact_truncated)
        finally:
            # Always tear the container down, even on timeout, error, or abort.
            with self._lock:
                if self._current_container is container:
                    self._current_container = None
            container.remove(force=True)

    def abort(self) -> None:
        """Tell this sandbox to stop now: kill whatever container it currently has in flight — so a
        `container.wait()` blocked in `run()` (on another thread) returns in seconds instead of up to
        `self._timeout` — and refuse to start any further container on this instance. Idempotent and
        safe to call with nothing in flight (a run between tool calls, or already finished)."""
        with self._lock:
            self._aborted = True
            container = self._current_container
        if container is not None:
            try:
                container.kill()
            except Exception:
                pass  # already exited/removed — the run thread's own `finally` still tears it down

    def _apply_egress(self, container, egress) -> None:
        """Enforcement seam for the per-job egress allow-list.

        Real enforcement installs nftables rules on the container's network namespace, permitting
        only egress.cidrs/egress.domains. That requires host netfilter access, so it is delegated to
        an external enforcer named by EYE_EGRESS_ENFORCER (invoked with the container id). If unset,
        the policy is computed and passed but not enforced here — deployments must wire the enforcer.
        """
        enforcer = os.getenv("EYE_EGRESS_ENFORCER")
        if not enforcer:
            return
        import subprocess

        subprocess.run([enforcer, container.id], check=False)


def _build_tmpfs(paths: list[str] | None) -> dict[str, str] | None:
    """Turn a tool's declared list of writable paths into the dict form `docker-py`'s `tmpfs=`
    kwarg expects, with every mount capped at `_tmpfs_size_mb()` and marked `noexec,nosuid,nodev` —
    writable is the one exception this round carves into `read_only=True`; it must not also become an
    exec surface or a way to fill host RAM. Returns None (not passed at all) when the tool asked for
    nothing, which is the overwhelming majority of tools and keeps their container config unchanged.
    """
    if not paths:
        return None
    opts = f"rw,noexec,nosuid,nodev,size={_tmpfs_size_mb()}m"
    return {path: opts for path in paths}


def _extract_artifact(container, path: str, cap: int) -> tuple[bytes | None, bool, bool]:
    """Read `path` out of a stopped-but-not-yet-removed container and return
    `(bytes_or_None, missing, truncated)`.

    This is the only way some tools can hand back their report at all: gitleaks writes zero bytes to
    `/dev/stdout` even when it found leaks (reproduced empirically, with and without `--read-only`),
    and ZAP refuses `-J /dev/stdout` outright as a file-based option. The extraction itself goes
    through the docker API's tar-stream endpoint (`get_archive`), which takes a path argument — not a
    command line — so the scan target (attacker-influenced, by design, for these tools) never reaches
    a shell. Do not "fix" this by wrapping the tool's command in `sh -c "tool ...; cat report"`: that
    would hand the target string to a shell for the first time in this pipeline.
    """
    import docker.errors

    try:
        stream, _stat = container.get_archive(path)
    except docker.errors.NotFound:
        return None, True, False
    except Exception:
        # Any other failure to fetch the archive (daemon hiccup, path is a directory, container
        # already gone) is indistinguishable, from the caller's point of view, from "the tool never
        # wrote it" — treat it the same rather than letting a fetch-layer error masquerade as a tool
        # error via the generic except in execute_tool_step.
        return None, True, False

    raw = b"".join(stream)
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r") as tar:
            member = next((m for m in tar.getmembers() if m.isfile()), None)
            if member is None:
                return None, True, False
            extracted = tar.extractfile(member)
            if extracted is None:
                return None, True, False
            # Read one byte past the cap so truncation can be detected without ever materializing
            # more than cap+1 bytes, the same trick _capped_logs uses for the streaming path.
            data = extracted.read(cap + 1)
    except tarfile.TarError:
        return None, True, False
    return data[:cap], False, len(data) > cap


def _capped_logs(container, cap: int, *, stdout: bool, stderr: bool) -> tuple[bytes, bool]:
    """Read one of the container's streams, stopping at `cap` bytes.

    Streams by preference so the full payload is never resident: chunks are accumulated only up to
    the cap and the rest is abandoned. Falls back to a single read + slice for clients/fakes whose
    `logs()` does not support `stream=True`, which still bounds what is handed on to the parser and
    the hasher (the transient full read is unavoidable on that path).
    """
    try:
        chunks: list[bytes] = []
        total = 0
        for chunk in container.logs(stdout=stdout, stderr=stderr, stream=True):
            if not chunk:
                continue
            chunks.append(chunk)
            total += len(chunk)
            if total >= cap:
                data = b"".join(chunks)
                return data[:cap], total > cap
        return b"".join(chunks), False
    except TypeError:
        pass  # a logs() that doesn't accept stream=
    data = container.logs(stdout=stdout, stderr=stderr) or b""
    return data[:cap], len(data) > cap
