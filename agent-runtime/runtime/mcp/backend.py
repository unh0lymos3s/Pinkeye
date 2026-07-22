"""Wrap a native Tool so it executes via an external MCP server instead of the local sandbox.

An `MCPBackedTool` copies the wrapped tool's identity (name, description, surface, image,
requires_flag, wants_context) so the harness treats it exactly like the original everywhere that
matters for safety — the scope guard, the offensive-flag gate, and the audit log all key off those
attributes and run in `execute_tool_step` BEFORE `run_mcp` is ever called. The only thing that
changes is *how* the already-authorized target is executed: a JSON-RPC `tools/call` to the MCP
server rather than a sandboxed container.

Result mapping is intentionally conservative: MCP servers don't share a finding schema, so we make a
best effort to pull severity/title/cve out of structured JSON and otherwise record the server's
response as a single informational finding plus a `note` the agent sees verbatim (like a knowledge
tool). Nothing is fabricated; unrecognized output is surfaced, not dropped.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

from app.models import Intensity

from ..normalize.common import make_finding, to_severity
from ..tools.base import ToolOutput
from .client import MCPClient, MCPError, _content_text

_MAX_FINDINGS = 200  # bound a chatty server so one call can't flood the graph


@dataclass
class MCPServerSpec:
    """How to reach one MCP server and drive one of its tools for a given native tool.

    command/args/env launch the stdio server. `tool` is the MCP tool to call; `target_arg` names the
    argument that receives the (already scope-checked) target. `intensity_arg`, if set, forwards the
    run intensity. `extra_args` are static arguments merged into every call.
    """

    command: str = ""
    tool: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    # Pooled/isolated hosting: when `pooled` is set the server runs in a warm, locked-down container
    # (via `docker run -i <image>`) that the connection pool keeps alive across calls, instead of a
    # subprocess spawned per call inside the api container. `image` is the server image; `mounts` are
    # docker `-v host:container:ro` strings (e.g. a read-only source root for SAST); the resource caps
    # mirror sandbox.py's hardening. Only meaningful for read-only analyzers (static egress).
    pooled: bool = False
    image: str | None = None
    mounts: list[str] = field(default_factory=list)
    mem_limit: str = "512m"
    cpus: float = 1.0
    pids_limit: int = 256
    target_arg: str = "target"
    # How the (already scope-checked) target is shaped into the target argument:
    #   "value"        -> the raw target string (default; nmap host, ZAP url, ...).
    #   "path_list"    -> a list of {path_key: <abs path>}, expanding a directory to its files. Suits
    #                     path-based code servers like semgrep's `semgrep_scan` (`[{"path": ...}]`).
    #   "file_content" -> like path_list but each entry also carries {content_key: <file text>}, for
    #                     inline-content servers like semgrep's `semgrep_scan_with_custom_rule`.
    target_mode: str = "value"
    path_key: str = "path"
    content_key: str = "content"
    intensity_arg: str | None = None
    extra_args: dict = field(default_factory=dict)
    timeout: float = 120.0
    max_files: int = 200  # bound for directory expansion
    max_bytes: int = 200_000  # per-file read cap for file_content mode

    @classmethod
    def from_dict(cls, data: dict) -> "MCPServerSpec":
        # A spec needs a `tool` plus a way to launch the server: a `command` (subprocess) or, for
        # pooled hosting, an `image` (run in a container). Deny-by-default: reject if neither is present.
        if not isinstance(data, dict) or not data.get("tool") or not (data.get("command") or data.get("image")):
            raise ValueError("MCP server spec needs 'tool' plus 'command' or 'image'")
        return cls(
            command=str(data.get("command", "")),
            tool=str(data["tool"]),
            args=[str(a) for a in data.get("args", [])],
            env={str(k): str(v) for k, v in (data.get("env") or {}).items()},
            pooled=bool(data.get("pooled", False)),
            image=(str(data["image"]) if data.get("image") else None),
            mounts=[str(m) for m in data.get("mounts", [])],
            mem_limit=str(data.get("mem_limit", "512m")),
            cpus=float(data.get("cpus", 1.0)),
            pids_limit=int(data.get("pids_limit", 256)),
            target_arg=str(data.get("target_arg", "target")),
            target_mode=str(data.get("target_mode", "value")),
            path_key=str(data.get("path_key", "path")),
            content_key=str(data.get("content_key", "content")),
            intensity_arg=(str(data["intensity_arg"]) if data.get("intensity_arg") else None),
            extra_args=dict(data.get("extra_args") or {}),
            timeout=float(data.get("timeout", 120.0)),
            max_files=int(data.get("max_files", 200)),
            max_bytes=int(data.get("max_bytes", 200_000)),
        )

    def shape_target(self, target: str):
        """Turn the scope-checked target into the value placed at `target_arg`, per `target_mode`."""
        if self.target_mode == "path_list":
            return _path_objects(target, self.path_key, self.max_files)
        if self.target_mode == "file_content":
            return _path_objects(target, self.path_key, self.max_files,
                                 content_key=self.content_key, max_bytes=self.max_bytes)
        return target

    def launch_argv(self) -> tuple[str, list[str], dict]:
        """Return (command, args, env) that starts the server process.

        Without `image`: the command/args are launched directly (subprocess). With `image`: they are
        wrapped in `docker run --rm -i` under the same hardening `DockerSandbox` uses (cap-drop-all,
        read-only rootfs, no-new-privileges, mem/cpu/pids caps, no Docker socket). Secrets are forwarded
        by name (`-e KEY`, value taken from the launcher env) so they never appear in the container argv.
        """
        env = {**os.environ, **self.env}
        if not self.image:
            return (self.command, list(self.args), env)
        hardening = [
            "run", "--rm", "-i",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true",
            "--read-only",
            "--memory", self.mem_limit,
            "--cpus", str(self.cpus),
            "--pids-limit", str(self.pids_limit),
            "--network", "bridge",
        ]
        mount_flags: list[str] = []
        for m in self.mounts:
            mount_flags += ["-v", m]
        env_flags: list[str] = []
        for key in self.env:
            env_flags += ["-e", key]  # forward by name -> value stays off the argv
        argv = [*hardening, *mount_flags, *env_flags, self.image, *self.args]
        return ("docker", argv, env)

    def pool_key(self) -> str:
        """Identity of the *server* (not the tool) so multiple tools can share one warm session."""
        return "|".join([
            self.image or self.command,
            repr(list(self.args)),
            repr(sorted(self.env.keys())),
            repr(sorted(self.mounts)),
        ])


class MCPBackedTool:
    """A Tool that runs through an MCP server. Mirrors the wrapped tool's safety-relevant attributes.

    A `client_factory` seam lets tests inject a fake client; in production it defaults to spawning the
    real stdio `MCPClient` from the spec.
    """

    def __init__(self, tool, spec: MCPServerSpec, client_factory=None, pool=None):
        self._tool = tool
        self.spec = spec
        self._client_factory = client_factory or self._default_client
        self._pool = pool  # injectable for tests; production uses the process-wide pool lazily
        # Mirror identity + safety attributes so the guard/gate/audit behave identically.
        self.name = tool.name
        self.description = getattr(tool, "description", "")
        self.image = getattr(tool, "image", "")
        self.surface = getattr(tool, "surface", "network")
        self.wants_context = getattr(tool, "wants_context", False)
        requires_flag = getattr(tool, "requires_flag", None)
        if requires_flag is not None:
            self.requires_flag = requires_flag
        # Marker the orchestrator branches on. Never `local` — MCP execution is out-of-process to a
        # server we don't sandbox, which is a distinct trust boundary from an in-process lookup.
        self.mcp = spec

    def _default_client(self) -> MCPClient:
        return MCPClient(self.spec.command, self.spec.args, self.spec.env, self.spec.timeout)

    def run_mcp(
        self, *, target: str, intensity: Intensity, context: dict,
        engagement_id: str, run_id: str,
    ) -> ToolOutput:
        """Called by execute_tool_step AFTER authorization. Builds the MCP arguments, calls the
        server, and maps the response to a ToolOutput. MCPError propagates as a normal tool error."""
        arguments = dict(self.spec.extra_args)
        arguments[self.spec.target_arg] = self.spec.shape_target(target)
        if self.spec.intensity_arg:
            arguments[self.spec.intensity_arg] = intensity.value
        if self.spec.pooled:
            # Warm, isolated, reused session (server runs in its own locked-down container).
            result = self._get_pool().call(self.spec, self.spec.tool, arguments)
        else:
            # Spawn-per-call path (subprocess), unchanged. Tests inject a fake client here.
            client = self._client_factory()
            if hasattr(client, "__enter__"):
                with client as c:
                    result = c.call_tool(self.spec.tool, arguments)
            else:  # a bare fake client without context-manager support
                client.start()
                try:
                    result = client.call_tool(self.spec.tool, arguments)
                finally:
                    client.close()
        return self._to_output(result, engagement_id=engagement_id, run_id=run_id, target=target)

    def _get_pool(self):
        if self._pool is not None:
            return self._pool
        from .pool import get_pool
        return get_pool()

    def _to_output(self, result: dict, *, engagement_id: str, run_id: str, target: str) -> ToolOutput:
        text = _content_text(result) if isinstance(result, dict) else str(result)
        out = ToolOutput(note=text[:4000])
        payload = _try_json(text)
        items = _finding_items(payload)
        if items:
            for item in items[:_MAX_FINDINGS]:
                out.findings.append(
                    self._finding_from_item(item, engagement_id, run_id, target)
                )
        elif text.strip():
            # Unstructured (or free-text) result: keep it visible as one informational finding so the
            # graph/report reflect that the MCP tool ran, with the raw answer preserved as evidence.
            out.findings.append(make_finding(
                engagement_id=engagement_id, run_id=run_id,
                title=f"{self.name} (MCP) result for {target}",
                category=f"mcp:{self.name}", target=target,
                severity=to_severity(None), confidence=0.4,
                source_tool=self.name, evidence=text[:500],
            ))
        return out

    def _finding_from_item(self, item: dict, engagement_id: str, run_id: str, target: str):
        # `extra` is where several tools (notably semgrep) nest severity/message/metadata, so merge a
        # shallow view of it for key lookups without losing the top-level fields.
        extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
        meta = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        # `cves`/`cwes` (plural, list) are Snyk's shape; the singular variants cover semgrep/nuclei.
        cve = _first(item, "cve", "cve-id", "cve_id", "cves") or _first(meta, "cve")
        cwe = _first(item, "cwe", "cwe-id", "cwe_id", "cwes") or _first(meta, "cwe")
        return make_finding(
            engagement_id=engagement_id, run_id=run_id,
            title=str(_first(item, "title", "name", "template-id", "id", "rule", "check", "check_id")
                      or f"{self.name} finding"),
            category=f"mcp:{self.name}",
            target=str(_first(item, "matched-at", "url", "host", "location", "path", "filePath")
                       or target),
            severity=to_severity(_first_str(item, "severity", "risk", "level")
                                 or _first_str(extra, "severity")),
            confidence=0.6,
            source_tool=self.name,
            cve=(str(cve[0]) if isinstance(cve, list) and cve else (str(cve) if cve else None)),
            cwe=(str(_norm_cwe(cwe)) if cwe else None),
            evidence=str(_first(item, "description", "matcher-name", "detail")
                         or _first(extra, "message") or _first(item, "message") or "")[:500],
        )


def _path_objects(target: str, path_key: str, max_files: int,
                  content_key: str | None = None, max_bytes: int = 200_000) -> list[dict]:
    """Build [{path_key: <abs path>}] for a file, or one entry per file under a directory (bounded).
    When `content_key` is set, each entry also carries the file's text under that key (for
    inline-content MCP tools). The target is already scope-authorized (surface='artifact' ->
    allowed_artifacts) before we get here."""

    def entry(abs_path: str) -> dict:
        item = {path_key: abs_path}
        if content_key is not None:
            try:
                with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
                    item[content_key] = fh.read(max_bytes)
            except OSError:
                item[content_key] = ""
        return item

    if os.path.isdir(target):
        items: list[dict] = []
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if not d.startswith(".")]  # skip .git and friends
            for fn in files:
                items.append(entry(os.path.abspath(os.path.join(root, fn))))
                if len(items) >= max_files:
                    return items
        return items
    return [entry(os.path.abspath(target))]


def _norm_cwe(cwe) -> str:
    """Normalize a CWE value that may be a list, a bare number, or a 'CWE-79: ...' string, down to
    the canonical `CWE-<n>` token."""
    value = cwe[0] if isinstance(cwe, list) and cwe else cwe
    text = str(value).strip().upper()
    match = re.search(r"CWE[-_ ]?(\d+)", text)
    if match:
        return f"CWE-{match.group(1)}"
    return f"CWE-{text}" if text.isdigit() else text


def _try_json(text: str):
    text = text.strip()
    if not text or text[0] not in "[{":
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _finding_items(payload) -> list:
    """Extract a list of finding-like dicts from a parsed MCP payload, or [] if there isn't one."""
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if isinstance(payload, dict):
        for key in ("findings", "results", "vulnerabilities", "alerts", "matches", "issues"):
            value = payload.get(key)
            if isinstance(value, list):
                return [x for x in value if isinstance(x, dict)]
    return []


def _first(item: dict, *keys):
    for key in keys:
        if key in item and item[key] not in (None, ""):
            return item[key]
    return None


def _first_str(item: dict, *keys) -> str | None:
    value = _first(item, *keys)
    return None if value is None else str(value)
