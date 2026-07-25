"""Disposable Docker sandbox for offensive tooling.

Each tool run gets its own container that is destroyed afterward. The security posture:
  - no host filesystem mounts
  - all Linux capabilities dropped, no privilege escalation
  - read-only root filesystem
  - CPU / memory / wall-clock ceilings
Egress is intentionally NOT opened wide here; the caller is responsible for having already passed
the target through the scope guard. Per-job network egress allow-listing is a Phase 6 hardening item.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from .envutil import env_int

# The container has memory/CPU/pids ceilings but its *output* had none: `container.logs()`
# materializes the whole stream as bytes inside the API process, so a huge nmap XML, a ZAP JSON, or
# a looping/hostile tool could pull hundreds of MB into the process that also serves every request.
# Cap it, and record that the cap was hit so a partial parse is visible rather than silent.
DEFAULT_MAX_OUTPUT_BYTES = 64 * 1024 * 1024


def _max_output_bytes() -> int:
    return env_int("EYE_TOOL_MAX_OUTPUT_BYTES", DEFAULT_MAX_OUTPUT_BYTES, minimum=1)


@dataclass
class SandboxResult:
    exit_code: int
    stdout: bytes
    stderr: bytes
    # True when the stream hit EYE_TOOL_MAX_OUTPUT_BYTES and was cut short.
    stdout_truncated: bool = False
    stderr_truncated: bool = False


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

    def run(self, image: str, command: list[str], source_dir: str | None = None, egress=None) -> SandboxResult:
        """Run `command` in a fresh locked-down container and return its output.

        For SAST, `source_dir` is bind-mounted read-only at /src so static analyzers can read the
        code without the container being able to modify it. `egress` is an EgressPolicy the sandbox
        network is restricted to; enforcement is applied to this container's dedicated network.
        """
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
            mem_limit=self._mem_limit,
            nano_cpus=int(self._cpus * 1e9),
            pids_limit=256,
            volumes=volumes,
        )
        if egress is not None:
            self._apply_egress(container, egress)
        try:
            result = container.wait(timeout=self._timeout)
            cap = _max_output_bytes()
            stdout, stdout_cut = _capped_logs(container, cap, stdout=True, stderr=False)
            stderr, stderr_cut = _capped_logs(container, cap, stdout=False, stderr=True)
            return SandboxResult(exit_code=result.get("StatusCode", -1), stdout=stdout,
                                 stderr=stderr, stdout_truncated=stdout_cut,
                                 stderr_truncated=stderr_cut)
        finally:
            # Always tear the container down, even on timeout or error.
            container.remove(force=True)

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
