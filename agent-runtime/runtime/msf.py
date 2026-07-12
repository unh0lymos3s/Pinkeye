"""Thin Metasploit RPC client seam.

Talks to a running msfrpcd. Kept minimal and injectable so the exploitation logic is testable
without Metasploit present; production wires this to pymetasploit3 (or the msgpack RPC directly).
Connection details come from secrets, never from run input.
"""
from __future__ import annotations

from app.secrets import load_secret


class MetasploitRpc:
    def __init__(self, host: str, port: int, password: str, ssl: bool = True):
        self._host, self._port, self._password, self._ssl = host, port, password, ssl
        self._client = None

    @classmethod
    def from_env(cls) -> "MetasploitRpc":
        password = load_secret("MSF_RPC_PASSWORD")
        if not password:
            raise RuntimeError("MSF_RPC_PASSWORD not configured")
        return cls(
            host=load_secret("MSF_RPC_HOST", "127.0.0.1"),
            port=int(load_secret("MSF_RPC_PORT", "55553")),
            password=password,
        )

    def _get_client(self):
        if self._client is None:
            from pymetasploit3.msfrpc import MsfRpcClient

            self._client = MsfRpcClient(self._password, server=self._host, port=self._port, ssl=self._ssl)
        return self._client

    def check(self, module: str, target: str) -> dict:
        """Run a module's non-destructive check. Returns {'vulnerable': bool}."""
        client = self._get_client()
        mtype, mname = module.split("/", 1)
        mod = client.modules.use(mtype, mname)
        mod["RHOSTS"] = target
        result = mod.check()
        return {"vulnerable": str(result.get("code", "")).lower() in ("vulnerable", "appears")}

    def exploit(self, module: str, target: str) -> dict:
        """Execute a module and return the opened session id, if any."""
        client = self._get_client()
        mtype, mname = module.split("/", 1)
        mod = client.modules.use(mtype, mname)
        mod["RHOSTS"] = target
        before = set(client.sessions.list.keys())
        client.modules.execute(mtype, mname, mod.runoptions)
        after = set(client.sessions.list.keys())
        opened = after - before
        return {"session_id": next(iter(opened), None)}

    def session_run(self, session_id: str, command: str) -> str:
        """Run a single read-only enumeration command in an existing session."""
        client = self._get_client()
        session = client.sessions.session(session_id)
        session.write(command)
        return session.read()
