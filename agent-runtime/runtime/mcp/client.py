"""A minimal, dependency-free MCP client (stdio transport).

Speaks JSON-RPC 2.0 over a subprocess's stdin/stdout, which is the lowest-common-denominator MCP
transport every server supports. Deliberately small: it does the `initialize` handshake, then
`tools/list` and `tools/call`. No external `mcp` SDK is required, so the harness picks up no new
runtime dependency and the client is trivially testable against a fake stdio server.

Not implemented here: HTTP/SSE transport (some hosted servers offer it) and server-initiated
sampling. Both are additive and out of scope for the execution-backend use case — the harness only
ever *calls* a tool, it never lets a server call back into the model.
"""
from __future__ import annotations

import collections
import json
import os
import select
import subprocess
import threading
from typing import Any

PROTOCOL_VERSION = "2025-06-18"
_CLIENT_INFO = {"name": "pinkeye", "version": "0.1.0"}
# How many stderr lines to keep for diagnostics. The pipe must be drained continuously (see
# `_start_stderr_pump`); this bounds what we hold on to while doing it.
_STDERR_TAIL_LINES = 200


class MCPError(RuntimeError):
    """Any failure talking to an MCP server: spawn error, timeout, JSON-RPC error, or a tool that
    reported isError. Callers treat it like any other tool failure (surfaced as a step error)."""


class MCPClient:
    """One connection to one stdio MCP server. Not thread-safe; construct per use (or per tool call).

    Usage:
        with MCPClient(command="npx", args=["-y", "some-mcp"]) as c:
            result = c.call_tool("scan", {"target": "..."})
    """

    def __init__(
        self,
        command: str,
        args: list[str] | None = None,
        env: dict[str, str] | None = None,
        timeout: float = 120.0,
    ):
        self._command = command
        self._args = list(args or [])
        # Inherit the harness env so the server can read its own API keys, but let the caller add/override.
        self._env = {**os.environ, **(env or {})}
        self._timeout = timeout
        self._proc: subprocess.Popen | None = None
        self._next_id = 0
        self._lock = threading.Lock()
        # Bounded tail of the server's stderr, filled by a reader thread. `deque.append` is atomic,
        # so no lock is needed between the pump and the request thread that reads it.
        self._stderr_tail: collections.deque[str] = collections.deque(maxlen=_STDERR_TAIL_LINES)
        self._stderr_thread: threading.Thread | None = None

    # -- lifecycle -------------------------------------------------------------------------------
    def __enter__(self) -> "MCPClient":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def start(self) -> None:
        try:
            self._proc = subprocess.Popen(
                [self._command, *self._args],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self._env,
                text=True,
                bufsize=1,  # line-buffered; MCP stdio frames one JSON message per line
            )
        except (OSError, ValueError) as exc:
            raise MCPError(f"failed to launch MCP server '{self._command}': {exc}") from exc
        self._start_stderr_pump()
        self._handshake()

    def _start_stderr_pump(self) -> None:
        """Drain the server's stderr continuously into a bounded tail.

        Without this, nothing reads the pipe during normal operation: a server that logs verbosely
        fills the 64 KiB pipe buffer, blocks on write, stops answering on stdout, and the client
        hangs until its select() ceiling — surfacing to the operator as a misleading "MCP server
        timed out". Draining into a deque (rather than DEVNULL) keeps the last lines available, so
        the timeout/closed errors can say what the server was actually complaining about.
        """
        proc = self._proc
        if proc is None or proc.stderr is None:
            return
        stream = proc.stderr

        def pump() -> None:
            try:
                for line in stream:
                    self._stderr_tail.append(line.rstrip("\n"))
            except Exception:
                pass  # stream closed under us during close(): nothing left to drain

        self._stderr_thread = threading.Thread(target=pump, name="mcp-stderr", daemon=True)
        self._stderr_thread.start()

    def _stderr_text(self) -> str:
        return "\n".join(self._stderr_tail)

    def close(self) -> None:
        proc, self._proc = self._proc, None
        if proc is None:
            return
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            try:
                if stream:
                    stream.close()
            except Exception:
                pass
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    # -- protocol --------------------------------------------------------------------------------
    def _handshake(self) -> None:
        self._request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": _CLIENT_INFO,
            },
        )
        self._notify("notifications/initialized")

    def list_tools(self) -> list[dict]:
        result = self._request("tools/list", {})
        tools = result.get("tools") if isinstance(result, dict) else None
        return tools or []

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict:
        """Invoke a tool and return its raw result object ({content: [...], isError: bool}).
        Raises MCPError if the server reports isError, so a failed scan surfaces as a step error."""
        result = self._request("tools/call", {"name": name, "arguments": arguments})
        if isinstance(result, dict) and result.get("isError"):
            raise MCPError(f"MCP tool '{name}' reported an error: {_content_text(result)[:500]}")
        return result if isinstance(result, dict) else {}

    # -- JSON-RPC transport ----------------------------------------------------------------------
    def _request(self, method: str, params: dict) -> dict:
        if self._proc is None:
            raise MCPError("MCP client is not started")
        with self._lock:
            self._next_id += 1
            req_id = self._next_id
        self._send({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})
        return self._await_response(req_id)

    def _notify(self, method: str, params: dict | None = None) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def _send(self, message: dict) -> None:
        proc = self._proc
        if proc is None or proc.stdin is None:
            raise MCPError("MCP server stdin is closed")
        try:
            proc.stdin.write(json.dumps(message) + "\n")
            proc.stdin.flush()
        except (BrokenPipeError, ValueError) as exc:
            raise MCPError(f"failed to write to MCP server: {exc}") from exc

    def _await_response(self, req_id: int) -> dict:
        """Read messages until the response with our id arrives. Server-initiated notifications and
        requests (no matching id) are ignored — this client never acts as a sampling backend."""
        while True:
            line = self._read_line()
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue  # skip non-JSON noise (some servers log to stdout despite the spec)
            if not isinstance(message, dict) or message.get("id") != req_id:
                continue
            if "error" in message:
                err = message["error"]
                raise MCPError(f"MCP error {err.get('code')}: {err.get('message')}")
            return message.get("result") or {}

    def _read_line(self) -> str:
        proc = self._proc
        if proc is None or proc.stdout is None:
            raise MCPError("MCP server stdout is closed")
        # select() gives us a hard wall-clock ceiling so a hung/silent server can't block a run.
        ready, _, _ = select.select([proc.stdout], [], [], self._timeout)
        if not ready:
            raise MCPError(f"MCP server timed out after {self._timeout}s."
                           f" stderr tail: {self._stderr_text()[-500:]}")
        line = proc.stdout.readline()
        if line == "":
            # stderr is already drained by the pump thread; read the tail it collected rather than
            # racing it for the pipe.
            raise MCPError(f"MCP server closed the connection. stderr: {self._stderr_text()[-500:]}")
        return line


def _content_text(result: dict) -> str:
    """Flatten an MCP result's `content` blocks into a single text string. Text blocks are joined;
    non-text blocks are summarized by type so nothing is silently dropped."""
    parts: list[str] = []
    for block in (result.get("content") or []):
        if not isinstance(block, dict):
            continue
        if block.get("type") == "text":
            parts.append(str(block.get("text", "")))
        else:
            parts.append(f"[{block.get('type', 'unknown')} content]")
    return "\n".join(p for p in parts if p)
