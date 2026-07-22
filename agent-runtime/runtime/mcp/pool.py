"""Process-wide pool of warm MCP sessions.

Keeps one open `MCPSession` per configured server so a hosted server stays *warm* across tool calls
instead of being spawned per call. Responsibilities:
  - lazy connect, keyed by server identity (image/command + args + env);
  - serialize is handled inside each `MCPSession`; the pool just hands the session out;
  - reconnect once if a session has died (server crashed/restarted);
  - evict sessions idle longer than `EYE_MCP_IDLE_TTL` so an unused warm container doesn't sit resident
    (warmth while active, zero footprint when idle);
  - `shutdown()` closes everything (wired to FastAPI shutdown + atexit) so no sibling container leaks.

Safety note: the pool is only ever reached from `MCPBackedTool.run_mcp`, which `execute_tool_step`
calls *after* the scope guard / flag gate / audit. The pool changes only how an already-authorized call
is transported.
"""
from __future__ import annotations

import atexit
import os
import threading
import time

from .client import MCPError
from .session import MCPSession


def _default_session_factory(spec) -> MCPSession:
    command, args, env = spec.launch_argv()
    session = MCPSession(command=command, args=args, env=env, timeout=spec.timeout)
    session.start()
    return session


class _Entry:
    __slots__ = ("session", "last_used")

    def __init__(self, session: MCPSession, now: float):
        self.session = session
        self.last_used = now


class MCPConnectionPool:
    def __init__(self, session_factory=None, idle_ttl: float | None = None, clock=None):
        self._factory = session_factory or _default_session_factory
        self._idle_ttl = idle_ttl if idle_ttl is not None else float(os.getenv("EYE_MCP_IDLE_TTL", "300"))
        self._clock = clock or time.monotonic  # injectable so idle eviction is testable
        self._sessions: dict[str, _Entry] = {}
        self._lock = threading.RLock()
        self._reaper: threading.Thread | None = None
        self._stop = threading.Event()
        self.connect_count = 0  # visible for tests / warm-reuse assertions

    def call(self, spec, tool: str, arguments: dict) -> dict:
        """Run one tool call on the pooled session, reconnecting once if the session has died."""
        key = spec.pool_key()
        last_exc: Exception | None = None
        for attempt in range(2):
            session = self._acquire(spec, key)
            try:
                return session.call_tool(tool, arguments)
            except MCPError as exc:
                last_exc = exc
                self._drop(key)  # stale/dead session -> reconnect on the next attempt
        assert last_exc is not None
        raise last_exc

    def _acquire(self, spec, key: str) -> MCPSession:
        with self._lock:
            entry = self._sessions.get(key)
            if entry is None or entry.session.closed:
                if entry is not None:
                    self._safe_close(entry.session)
                session = self._factory(spec)  # connect + handshake (may raise MCPError)
                self.connect_count += 1
                entry = _Entry(session, self._clock())
                self._sessions[key] = entry
                self._ensure_reaper()
            entry.last_used = self._clock()
            return entry.session

    def _drop(self, key: str) -> None:
        with self._lock:
            entry = self._sessions.pop(key, None)
        if entry is not None:
            self._safe_close(entry.session)

    def reap_idle(self, now: float | None = None) -> int:
        """Close sessions idle beyond the TTL. Returns how many were evicted (also used by tests)."""
        now = now if now is not None else self._clock()
        evicted = 0
        with self._lock:
            for key in [k for k, e in self._sessions.items()
                        if now - e.last_used >= self._idle_ttl or e.session.closed]:
                self._safe_close(self._sessions.pop(key).session)
                evicted += 1
        return evicted

    def shutdown(self) -> None:
        self._stop.set()
        with self._lock:
            entries, self._sessions = list(self._sessions.values()), {}
        for e in entries:
            self._safe_close(e.session)

    # -- internals -------------------------------------------------------------------------------
    def _ensure_reaper(self) -> None:
        if self._idle_ttl <= 0:
            return  # eviction disabled
        if self._reaper is not None and self._reaper.is_alive():
            return
        self._stop.clear()
        self._reaper = threading.Thread(target=self._reap_loop, name="mcp-pool-reaper", daemon=True)
        self._reaper.start()

    def _reap_loop(self) -> None:
        interval = max(1.0, min(self._idle_ttl / 2.0, 30.0))
        while not self._stop.wait(interval):
            self.reap_idle()
            with self._lock:
                if not self._sessions:
                    return  # nothing left to watch; a new acquire will restart the reaper

    @staticmethod
    def _safe_close(session: MCPSession) -> None:
        try:
            session.close()
        except Exception:
            pass


_POOL: MCPConnectionPool | None = None
_POOL_LOCK = threading.Lock()


def get_pool() -> MCPConnectionPool:
    global _POOL
    with _POOL_LOCK:
        if _POOL is None:
            _POOL = MCPConnectionPool()
            atexit.register(_POOL.shutdown)
        return _POOL


def shutdown_pool() -> None:
    """Close all warm sessions. Wired to the API's shutdown event so containers never leak."""
    global _POOL
    with _POOL_LOCK:
        if _POOL is not None:
            _POOL.shutdown()
            _POOL = None
