"""Cross-run network memory — the persistent, differential map of the target network (the "brain").

It models **devices** (IP nodes) with their **service clusters**, flags **exploitable endpoints and
target devices**, and records **what changed between runs** so each run builds on prior knowledge
instead of rediscovering everything. The durable substrate is Neo4j (topology) plus a Postgres diff
log (`network_observations`); this class holds the in-process working state, diffs each observation
against it, and best-effort mirrors the derived device/exploitable state onto the graph.

Security boundary: memory is **guidance and record-keeping only**. `snapshot()` is injected into the
agent as a compact summary (never raw output) and every tool call the agent then makes is still run
through the scope guard — a remembered host that has fallen out of scope can never be re-authorized
by its presence here. Nothing in this module calls `authorize` or touches the signed scope.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import FindingState, Severity


@dataclass
class MemoryDelta:
    """What one observation (or a whole run) changed in the map. Each list holds change entries:
    dicts of {kind, key, label, before, after} that the chat surfaces and the API returns."""

    added: list[dict] = field(default_factory=list)
    changed: list[dict] = field(default_factory=list)
    removed: list[dict] = field(default_factory=list)
    newly_exploitable: list[dict] = field(default_factory=list)

    def extend(self, other: "MemoryDelta") -> None:
        self.added.extend(other.added)
        self.changed.extend(other.changed)
        self.removed.extend(other.removed)
        self.newly_exploitable.extend(other.newly_exploitable)

    def is_empty(self) -> bool:
        return not (self.added or self.changed or self.removed or self.newly_exploitable)

    def to_dict(self) -> dict:
        return {
            "added": self.added,
            "changed": self.changed,
            "removed": self.removed,
            "newly_exploitable": self.newly_exploitable,
        }


def _svc_key(address: str, port: int, proto: str) -> str:
    return f"{address}:{port}/{proto or 'tcp'}"


def _entry(kind: str, key: str, label: str, before=None, after=None) -> dict:
    return {"kind": kind, "key": key, "label": label, "before": before, "after": after}


class NetworkMemory:
    """`observe` on the write path; `snapshot` for agent context + UI; `deltas_for_run` for the
    "changes since last run" view. Backends are optional — with neither graph nor db it is a pure
    in-memory differ, which is exactly what the tests exercise."""

    def __init__(self, graph=None, db=None) -> None:
        self._graph = graph
        self._db = db
        # engagement_id -> {"devices": {address: device}, "endpoints": {url: {...}}}
        self._state: dict[str, dict] = {}
        self._loaded: set[str] = set()
        # run_id -> aggregated MemoryDelta across every step of that run
        self._run_deltas: dict[str, MemoryDelta] = {}

    # ---- write path ----

    def observe(self, engagement_id: str, run_id: str, services, findings) -> MemoryDelta:
        """Classify each incoming service/finding as new / changed / unchanged / newly-exploitable
        against the remembered map, detect closed ports on re-observed hosts, and record the diff.
        Returns this step's delta; the per-run aggregate is available via `deltas_for_run`."""
        st = self._ensure_loaded(engagement_id)
        delta = MemoryDelta()
        observed_hosts: set[str] = set()
        changed_hosts: set[str] = set()

        # --- topology: devices + service clusters ---
        for svc in services or []:
            addr = getattr(svc, "address", None)
            if not addr:
                continue
            observed_hosts.add(addr)
            dev = st["devices"].get(addr)
            if dev is None:
                dev = self._new_device(addr)
                st["devices"][addr] = dev
                dev["status"] = "new"
                delta.added.append(_entry("device", addr, f"new device {addr}"))
                self._record(engagement_id, run_id, "device", addr, "added", None, {"address": addr})

            port = int(getattr(svc, "port", 0) or 0)
            proto = getattr(svc, "proto", "tcp") or "tcp"
            key = _svc_key(addr, port, proto)
            incoming = {
                "port": port, "proto": proto,
                "service": getattr(svc, "service", "") or "",
                "product": getattr(svc, "product", "") or "",
            }
            existing = dev["services"].get((port, proto))
            if existing is None:
                dev["services"][(port, proto)] = {**incoming, "exploitable": False, "last_run_id": run_id}
                delta.added.append(_entry("service", key, f"new service {key} {incoming['service']}".strip(),
                                          None, incoming))
                self._record(engagement_id, run_id, "service", key, "added", None, incoming)
                if dev["status"] != "new":
                    changed_hosts.add(addr)
            elif existing.get("service") != incoming["service"] or existing.get("product") != incoming["product"]:
                before = {"service": existing.get("service"), "product": existing.get("product")}
                existing.update(incoming)
                existing["last_run_id"] = run_id
                delta.changed.append(_entry("service", key, f"changed {key}: "
                                            f"{before.get('product') or before.get('service')} -> "
                                            f"{incoming['product'] or incoming['service']}", before, incoming))
                self._record(engagement_id, run_id, "service", key, "changed", before, incoming)
                changed_hosts.add(addr)
            else:
                existing["last_run_id"] = run_id  # re-observed, unchanged; keep it fresh
            dev["last_run_id"] = run_id

        # --- closed ports / gone services: only for a host actually re-observed this run, and only
        #     for ports last seen in a *prior* run (never intra-run, so a findings-only step that
        #     reports no services can't false-flag a host's ports as gone) ---
        for addr in observed_hosts:
            dev = st["devices"][addr]
            incoming_keys = {
                (int(getattr(s, "port", 0) or 0), getattr(s, "proto", "tcp") or "tcp")
                for s in (services or []) if getattr(s, "address", None) == addr
            }
            for skey, sstate in list(dev["services"].items()):
                last = sstate.get("last_run_id")
                if skey not in incoming_keys and last not in (None, run_id):
                    key = _svc_key(addr, skey[0], skey[1])
                    delta.removed.append(_entry("service", key, f"closed {key}", sstate, None))
                    self._record(engagement_id, run_id, "service", key, "removed", sstate, None)
                    del dev["services"][skey]
                    changed_hosts.add(addr)

        # --- exploitable transitions from findings ---
        for f in findings or []:
            if not self._is_exploitable_finding(f):
                continue
            target = getattr(f, "target", "") or ""
            dedup = f.dedup_key() if hasattr(f, "dedup_key") else None
            if target.startswith("http://") or target.startswith("https://"):
                ep = st["endpoints"].get(target)
                if not (ep and ep.get("exploitable")):
                    st["endpoints"][target] = {"exploitable": True, "last_run_id": run_id}
                    delta.newly_exploitable.append(
                        _entry("endpoint", target, f"exploitable endpoint {target}"))
                    self._record(engagement_id, run_id, "endpoint", target, "newly_exploitable",
                                 None, {"exploitable": True})
                    self._graph_flag_exploitable(engagement_id, dedup, url=target)
            else:
                dev = st["devices"].get(target)
                if dev is None:
                    dev = self._new_device(target)
                    st["devices"][target] = dev
                    dev["status"] = "new"
                    delta.added.append(_entry("device", target, f"new device {target}"))
                    self._record(engagement_id, run_id, "device", target, "added", None, {"address": target})
                if not dev.get("is_target"):
                    dev["is_target"] = True
                    delta.newly_exploitable.append(_entry("device", target, f"target device {target}"))
                    self._record(engagement_id, run_id, "device", target, "newly_exploitable",
                                 None, {"is_target": True})
                    self._graph_set_device(engagement_id, target, is_target=True)

        # --- derive + roll up device status onto the graph ---
        for addr in observed_hosts:
            dev = st["devices"][addr]
            if dev["status"] != "new":
                dev["status"] = "changed" if addr in changed_hosts else "active"
            self._graph_set_device(engagement_id, addr, status=dev["status"], is_target=dev.get("is_target"))

        self._run_deltas.setdefault(run_id, MemoryDelta()).extend(delta)
        return delta

    def deltas_for_run(self, run_id: str) -> MemoryDelta:
        """The changes recorded during a run (aggregated across all its steps)."""
        return self._run_deltas.get(run_id, MemoryDelta())

    # ---- read path ----

    def snapshot(self, engagement_id: str) -> dict:
        """Compact device -> service-cluster -> exploitable summary for agent context and the UI."""
        st = self._ensure_loaded(engagement_id)
        devices = []
        for addr, dev in st["devices"].items():
            services = [
                {"port": s["port"], "proto": s["proto"], "service": s.get("service", ""),
                 "product": s.get("product", ""), "exploitable": bool(s.get("exploitable"))}
                for s in dev["services"].values()
            ]
            services.sort(key=lambda s: (s["port"], s["proto"]))
            devices.append({
                "address": addr,
                "hostname": dev.get("hostname"),
                "os": dev.get("os"),
                "device_type": dev.get("device_type"),
                "status": dev.get("status", "active"),
                "is_target": bool(dev.get("is_target")),
                "services": services,
                "exploitable_count": sum(1 for s in services if s["exploitable"]),
            })
        devices.sort(key=lambda d: d["address"])
        return {"devices": devices, "endpoints": list(st["endpoints"].keys())}

    # ---- internals ----

    @staticmethod
    def _new_device(address: str) -> dict:
        return {"address": address, "hostname": None, "os": None, "device_type": None,
                "status": "active", "is_target": False, "services": {}, "last_run_id": None}

    @staticmethod
    def _is_exploitable_finding(f) -> bool:
        """A finding makes its target exploitable if it's from the exploitation category or is a
        confirmed critical/high — matching how the report/correlation treat 'proven' issues."""
        category = (getattr(f, "category", "") or "").lower()
        if "exploit" in category:
            return True
        severity = getattr(f, "severity", None)
        sev_value = getattr(severity, "value", severity)
        state = getattr(f, "state", None)
        state_value = getattr(state, "value", state)
        return state_value == FindingState.confirmed.value and sev_value in (
            Severity.high.value, Severity.critical.value)

    def _ensure_loaded(self, engagement_id: str) -> dict:
        st = self._state.get(engagement_id)
        if st is not None:
            return st
        st = self._state[engagement_id] = {"devices": {}, "endpoints": {}}
        if engagement_id not in self._loaded:
            self._loaded.add(engagement_id)
            self._warm_from_graph(engagement_id, st)
        return st

    def _warm_from_graph(self, engagement_id: str, st: dict) -> None:
        """Best-effort rehydrate the working state from the durable graph so cross-run memory survives
        an API restart. A missing method / down graph just leaves the state empty (first run again)."""
        if self._graph is None or not hasattr(self._graph, "load_devices"):
            return
        try:
            devices = self._graph.load_devices(engagement_id)
        except Exception:
            return
        for dev in devices or []:
            addr = dev.get("address")
            if not addr:
                continue
            d = self._new_device(addr)
            d["status"] = dev.get("status", "active")
            d["is_target"] = bool(dev.get("is_target"))
            d["hostname"], d["os"], d["device_type"] = (
                dev.get("hostname"), dev.get("os"), dev.get("device_type"))
            for s in dev.get("services", []):
                port = int(s.get("port", 0) or 0)
                proto = s.get("proto", "tcp") or "tcp"
                d["services"][(port, proto)] = {
                    "port": port, "proto": proto, "service": s.get("service", "") or "",
                    "product": s.get("product", "") or "", "exploitable": bool(s.get("exploitable")),
                    "last_run_id": s.get("last_run_id"),
                }
            st["devices"][addr] = d

    def _record(self, engagement_id, run_id, kind, key, change, before, after) -> None:
        if self._db is None:
            return
        import json
        try:
            with self._db.connection() as conn:
                conn.execute(
                    "INSERT INTO network_observations "
                    "(engagement_id, run_id, kind, key, change, before, after) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (engagement_id, run_id, kind, key, change,
                     json.dumps(before) if before is not None else None,
                     json.dumps(after) if after is not None else None),
                )
        except Exception:
            pass

    def _graph_set_device(self, engagement_id, address, **kwargs) -> None:
        if self._graph is None or not hasattr(self._graph, "set_device"):
            return
        try:
            self._graph.set_device(engagement_id, address, **kwargs)
        except Exception:
            pass

    def _graph_flag_exploitable(self, engagement_id, dedup, **kwargs) -> None:
        if self._graph is None or not hasattr(self._graph, "flag_exploitable") or dedup is None:
            return
        try:
            self._graph.flag_exploitable(engagement_id, dedup, **kwargs)
        except Exception:
            pass
