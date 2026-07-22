"""A warm, reusable MCP session over stdio, built on the official `mcp` SDK.

Why this exists: the plain `MCPClient` (client.py) spawns a server subprocess per call. To make a
hosted server *warm* (pooled), we keep one `ClientSession` open across many `tools/call`s. The SDK is
async (anyio-based), but the harness is synchronous/threaded, so each `MCPSession` owns a dedicated
thread running an asyncio loop that holds the session open for its whole lifetime, and exposes a
blocking facade (`call_tool` / `list_tools` / `close`).

The async context managers (`stdio_client`, `ClientSession`) must be entered and exited on the *same*
task (anyio cancel-scope rule), so the whole lifecycle lives inside one `_serve` coroutine that pulls
work off a queue until asked to stop. Callers submit work with `run_coroutine_threadsafe`.

Result objects are mapped back to the same `{content: [...], isError: bool}` dict shape the rest of the
MCP code already consumes (`_to_output` / `_content_text` in backend.py), so nothing downstream changes.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import threading
from datetime import timedelta
from typing import Any, Callable

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from .client import MCPError  # reuse the one error type callers already handle

_STOP = object()  # sentinel queued to shut the serve loop down


class MCPSession:
    """One warm stdio session to one MCP server. Thread-safe: calls are serialized on the pipe."""

    def __init__(self, command: str, args: list[str] | None = None,
                 env: dict[str, str] | None = None, timeout: float = 120.0):
        self._params = StdioServerParameters(command=command, args=list(args or []), env=env or None)
        self._timeout = timeout
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._queue: asyncio.Queue | None = None
        self._connected: concurrent.futures.Future = concurrent.futures.Future()
        self._call_lock = threading.Lock()  # one outstanding call per stdio pipe
        self._closed = False

    # -- lifecycle -------------------------------------------------------------------------------
    def start(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, name="mcp-session", daemon=True)
        self._thread.start()
        # Block until the handshake finishes; re-raise a connect failure as MCPError.
        self._connected.result(timeout=self._timeout + 10)

    def _run(self) -> None:
        assert self._loop is not None
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._serve())
        finally:
            self._loop.close()

    async def _serve(self) -> None:
        self._queue = asyncio.Queue()
        try:
            async with stdio_client(self._params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    self._connected.set_result(True)
                    while True:
                        item = await self._queue.get()
                        if item is _STOP:
                            return
                        make_coro, fut = item
                        try:
                            fut.set_result(await make_coro(session))
                        except Exception as exc:  # noqa: BLE001 - relay to the waiting caller
                            fut.set_exception(exc)
        except Exception as exc:  # noqa: BLE001 - connect/transport died
            if not self._connected.done():
                self._connected.set_exception(
                    MCPError(f"failed to start MCP session '{self._params.command}': {exc}")
                )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        loop, queue = self._loop, self._queue
        if loop is not None and queue is not None and loop.is_running():
            try:
                asyncio.run_coroutine_threadsafe(queue.put(_STOP), loop).result(timeout=5)
            except Exception:
                pass
        if self._thread is not None:
            self._thread.join(timeout=10)

    @property
    def closed(self) -> bool:
        # A crashed serve loop leaves the thread dead; treat that as closed so the pool reconnects.
        return self._closed or (self._thread is not None and not self._thread.is_alive())

    # -- calls -----------------------------------------------------------------------------------
    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict:
        result = self._run_on_loop(
            lambda s: s.call_tool(name, arguments,
                                  read_timeout_seconds=timedelta(seconds=self._timeout))
        )
        if getattr(result, "isError", False):
            raise MCPError(f"MCP tool '{name}' reported an error: {_result_text(result)[:500]}")
        return _to_result_dict(result)

    def list_tools(self) -> list[dict]:
        result = self._run_on_loop(lambda s: s.list_tools())
        return [{"name": t.name} for t in getattr(result, "tools", [])]

    def _run_on_loop(self, make_coro: Callable[[ClientSession], Any]):
        if self.closed or self._loop is None:
            raise MCPError("MCP session is closed")
        with self._call_lock:
            cf = asyncio.run_coroutine_threadsafe(self._request(make_coro), self._loop)
            try:
                return cf.result(timeout=self._timeout + 10)
            except concurrent.futures.TimeoutError as exc:
                raise MCPError(f"MCP call timed out after {self._timeout}s") from exc
            except MCPError:
                raise
            except Exception as exc:  # noqa: BLE001 - normalize SDK/transport errors
                raise MCPError(f"MCP call failed: {exc}") from exc

    async def _request(self, make_coro):
        assert self._loop is not None and self._queue is not None
        fut = self._loop.create_future()
        await self._queue.put((make_coro, fut))
        return await fut


def _to_result_dict(result) -> dict:
    """Map an SDK CallToolResult to the {content:[{type,text}], isError} dict shape used elsewhere."""
    content: list[dict] = []
    for block in (getattr(result, "content", None) or []):
        btype = getattr(block, "type", "unknown")
        entry = {"type": btype}
        if btype == "text":
            entry["text"] = getattr(block, "text", "")
        content.append(entry)
    return {"content": content, "isError": bool(getattr(result, "isError", False))}


def _result_text(result) -> str:
    return "\n".join(
        getattr(b, "text", "") for b in (getattr(result, "content", None) or [])
        if getattr(b, "type", None) == "text"
    )
