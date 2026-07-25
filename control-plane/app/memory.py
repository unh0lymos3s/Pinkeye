"""Cross-run network memory — the persistent, differential map of the target network (the "brain").

It models **devices** (IP nodes) with their **service clusters**, flags **exploitable endpoints and
target devices**, and records **what changed between runs** so each run builds on prior knowledge
instead of rediscovering everything. The durable substrate is Neo4j (topology) plus a Postgres diff
log (`network_observations`); this class holds the in-process working state, diffs each observation
against it, and best-effort mirrors the derived device/exploitable state onto the graph.

Security boundary: memory is **guidance and record-keeping only**. `snapshot()` is injected into the
agent as a compact summary (never raw output) and every tool call the agent then makes is still run
through the scope guard — a remembered host that has fallen out of scope can never be re-authorized
by its presence here. Nothing in this module calls `authorize` or touches the signed scope. That also
makes the retention below safe in the only direction that matters: forgetting can leave the agent
*less* informed, never more authorized.

Retention (§4): the working state is a cache in front of durable stores, not the record of truth, so
neither of its two dicts may grow for the lifetime of a weeks-long process. Both are retired on an
idle TTL, and each retirement is gated on the durable copy it would be reconstructed from actually
being wired: `_run_deltas` needs Postgres (`network_observations`, read back by `_load_deltas`) and
`_state` needs the graph (`load_devices`, replayed by `_warm_from_graph`) plus the diff log for the
exploitable-endpoint set the graph cannot replay (`_warm_endpoints_from_db`). With neither backend —
the pure in-memory mode the tests exercise — nothing is ever evicted.
"""
from __future__ import annotations

import json
import threading
import time
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field

from .envknobs import env_float
from .models import FindingState, Severity


# §4 — how long a finished run's aggregated delta stays in memory. Shares the event store's knob so
# one setting governs "how long is a run still cheap to look at", which is what the operator means.
RUN_RETENTION_SECONDS = env_float("EYE_RUN_RETENTION_SECONDS", 3600.0)
# §4 — how long an untouched engagement keeps its device/service map. Longer than a run's retention:
# rebuilding it costs a Neo4j round trip, and it is the thing that makes memory *cross*-run.
STATE_TTL_SECONDS = env_float("EYE_MEMORY_STATE_TTL_SECONDS", 6 * 3600.0)


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


def _dumps(value):
    """Serialize a diff side for the JSONB column. Done eagerly at record time so a buffered row
    can never be affected by later mutation of the dict it came from."""
    return json.dumps(value) if value is not None else None


def _entry(kind: str, key: str, label: str, before=None, after=None) -> dict:
    return {"kind": kind, "key": key, "label": label, "before": before, "after": after}


def _label_for(kind: str, key: str, change: str, before, after) -> str:
    """Reconstruct the human label for a change row replayed out of `network_observations`.

    The table stores the structured diff, not the prose, so this mirrors the phrasing `observe`
    uses when it builds the same entry live.
    """
    before, after = before or {}, after or {}
    if change == "added":
        if kind == "device":
            return f"new device {key}"
        return f"new service {key} {after.get('service', '') or ''}".strip()
    if change == "changed":
        return (f"changed {key}: {before.get('product') or before.get('service')} -> "
                f"{after.get('product') or after.get('service')}")
    if change == "removed":
        return f"closed {key}"
    if change == "newly_exploitable":
        return f"exploitable endpoint {key}" if kind == "endpoint" else f"target device {key}"
    return f"{change} {kind} {key}"


class NetworkMemory:
    """`observe` on the write path; `snapshot` for agent context + UI; `deltas_for_run` for the
    "changes since last run" view. Backends are optional — with neither graph nor db it is a pure
    in-memory differ, which is exactly what the tests exercise."""

    def __init__(self, graph=None, db=None, retention_seconds: float | None = None,
                 state_ttl_seconds: float | None = None) -> None:
        self._graph = graph
        self._db = db
        # engagement_id -> {"devices": {address: device}, "endpoints": {url: {...}}}
        self._state: dict[str, dict] = {}
        self._loaded: set[str] = set()
        # run_id -> aggregated MemoryDelta across every step of that run
        self._run_deltas: dict[str, MemoryDelta] = {}
        # Guards every mutation of the maps above, so a run thread and a request thread can share
        # this object. Held only for dict work — never across the Neo4j/Postgres I/O below.
        self._lock = threading.Lock()
        # engagement_id -> lock serializing *that* engagement's warm-up. Per-key rather than global:
        # `_warm_from_graph` does network I/O, and one engagement's cold start must not block a run
        # thread that wants a different (possibly already-warm) engagement.
        self._warm_locks: dict[str, threading.Lock] = {}
        # --- §4 retention: touch-ordered idle clocks, so a sweep stops at the first live entry ---
        self._delta_seen: "OrderedDict[str, float]" = OrderedDict()
        self._state_seen: "OrderedDict[str, float]" = OrderedDict()
        self._retention = RUN_RETENTION_SECONDS if retention_seconds is None else retention_seconds
        self._state_ttl = STATE_TTL_SECONDS if state_ttl_seconds is None else state_ttl_seconds

    # ---- write path ----

    def observe(self, engagement_id: str, run_id: str, services, findings) -> MemoryDelta:
        """Classify each incoming service/finding as new / changed / unchanged / newly-exploitable
        against the remembered map, detect closed ports on re-observed hosts, and record the diff.
        Returns this step's delta; the per-run aggregate is available via `deltas_for_run`."""
        # `_ensure_loaded` also marks this engagement as used, which is what keeps the retention sweep
        # at the end of this method from ever evicting the map this call is still mutating: the
        # engagement being observed is by construction the freshest entry in the idle clock.
        st = self._ensure_loaded(engagement_id)
        delta = MemoryDelta()
        observed_hosts: set[str] = set()
        changed_hosts: set[str] = set()

        # Buffer the durable diff rows and write them in one batch at the end of the step. Writing
        # them one at a time borrowed a pooled connection per change entry, which a large scan turns
        # into thousands of round trips.
        pending: list[tuple] = []

        def _rec(kind, key, change, before, after) -> None:
            if self._db is None:
                return
            pending.append((engagement_id, run_id, kind, key, change,
                            _dumps(before), _dumps(after)))

        # Index the incoming services by host once. The closed-port pass below needs the per-host
        # port set; rescanning the whole `services` list inside that loop is O(hosts x services).
        incoming_by_host: dict[str, set[tuple[int, str]]] = defaultdict(set)
        for s in services or []:
            s_addr = getattr(s, "address", None)
            if s_addr:
                incoming_by_host[s_addr].add(
                    (int(getattr(s, "port", 0) or 0), getattr(s, "proto", "tcp") or "tcp"))

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
                _rec("device", addr, "added", None, {"address": addr})

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
                _rec("service", key, "added", None, incoming)
                if dev["status"] != "new":
                    changed_hosts.add(addr)
            elif existing.get("service") != incoming["service"] or existing.get("product") != incoming["product"]:
                before = {"service": existing.get("service"), "product": existing.get("product")}
                existing.update(incoming)
                existing["last_run_id"] = run_id
                delta.changed.append(_entry("service", key, f"changed {key}: "
                                            f"{before.get('product') or before.get('service')} -> "
                                            f"{incoming['product'] or incoming['service']}", before, incoming))
                _rec("service", key, "changed", before, incoming)
                changed_hosts.add(addr)
            else:
                existing["last_run_id"] = run_id  # re-observed, unchanged; keep it fresh
            dev["last_run_id"] = run_id

        # --- closed ports / gone services: only for a host actually re-observed this run, and only
        #     for ports last seen in a *prior* run (never intra-run, so a findings-only step that
        #     reports no services can't false-flag a host's ports as gone) ---
        for addr in observed_hosts:
            dev = st["devices"][addr]
            incoming_keys = incoming_by_host[addr]
            for skey, sstate in list(dev["services"].items()):
                last = sstate.get("last_run_id")
                if skey not in incoming_keys and last not in (None, run_id):
                    key = _svc_key(addr, skey[0], skey[1])
                    delta.removed.append(_entry("service", key, f"closed {key}", sstate, None))
                    _rec("service", key, "removed", sstate, None)
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
                    _rec("endpoint", target, "newly_exploitable", None,
                         {"exploitable": True})
                    self._graph_flag_exploitable(engagement_id, dedup, url=target)
            else:
                dev = st["devices"].get(target)
                if dev is None:
                    dev = self._new_device(target)
                    st["devices"][target] = dev
                    dev["status"] = "new"
                    delta.added.append(_entry("device", target, f"new device {target}"))
                    _rec("device", target, "added", None, {"address": target})
                if not dev.get("is_target"):
                    dev["is_target"] = True
                    delta.newly_exploitable.append(_entry("device", target, f"target device {target}"))
                    _rec("device", target, "newly_exploitable", None,
                         {"is_target": True})
                    self._graph_set_device(engagement_id, target, is_target=True)

        # --- derive + roll up device status onto the graph ---
        for addr in observed_hosts:
            dev = st["devices"][addr]
            if dev["status"] != "new":
                dev["status"] = "changed" if addr in changed_hosts else "active"
            self._graph_set_device(engagement_id, addr, status=dev["status"], is_target=dev.get("is_target"))

        self._flush_records(pending)
        now = time.monotonic()
        with self._lock:
            self._run_deltas.setdefault(run_id, MemoryDelta()).extend(delta)
            # Re-touch both clocks with the *same* `now` the sweeps below use. That is what makes the
            # "never evict what this call just wrote" guarantee structural rather than a matter of how
            # long the step took: the two entries this call owns are the newest, so the sweeps stop at
            # them (see the `<=` in each).
            self._touch(self._delta_seen, run_id, now)
            self._touch(self._state_seen, engagement_id, now)
            # Opportunistic sweep on the write path: no timer thread to shut down, and `observe` is
            # the only call that can grow either map.
            self._sweep_run_deltas(now)
            self._sweep_state(now)
        return delta

    def deltas_for_run(self, run_id: str) -> MemoryDelta:
        """The changes recorded during a run (aggregated across all its steps).

        Falls back to the durable `network_observations` log when this process has no in-memory
        copy — i.e. after an API restart, when the run executed in another process, or once the
        in-process aggregate has been retired (§4)."""
        now = time.monotonic()
        with self._lock:
            delta = self._run_deltas.get(run_id)
            if delta is not None:
                # Being looked at counts as use, so a run the operator is watching is not retired
                # out from under the view it is feeding.
                self._touch(self._delta_seen, run_id, now)
                return delta
        return self._load_deltas(run_id)

    def retire_run(self, run_id: str) -> None:
        """Forget a finished run's aggregated delta. Safe to call for an unknown run.

        Intended for `RunEventStore.on_retire`, so run state expires off the run's terminal status
        rather than on a clock. A no-op without Postgres: `_load_deltas` is what makes this free, and
        it needs `network_observations` (C7) to answer.
        """
        if self._db is None:
            return
        with self._lock:
            self._run_deltas.pop(run_id, None)
            self._delta_seen.pop(run_id, None)

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

    # ---- retention (§4) ----

    @staticmethod
    def _touch(clock: "OrderedDict[str, float]", key: str, now: float) -> None:
        """Record `key` as used now, keeping the map in touch order. Caller holds `self._lock`."""
        clock[key] = now
        clock.move_to_end(key)

    def _sweep_run_deltas(self, now: float) -> None:
        """Drop aggregates for runs untouched for the retention window. Caller holds `self._lock`.

        Gated on Postgres: `deltas_for_run` reconstructs an evicted aggregate from
        `network_observations`, which every entry here was already written to by `_flush_records`.
        Without a db there is no durable copy, so nothing is evicted.
        """
        if self._db is None:
            return
        while self._delta_seen:
            run_id, seen = next(iter(self._delta_seen.items()))
            if now - seen <= self._retention:
                # Touch-ordered: everything behind this entry is younger. `<=` so the run that just
                # called `observe` is never evicted by its own sweep.
                break
            self._delta_seen.pop(run_id, None)
            self._run_deltas.pop(run_id, None)

    def _sweep_state(self, now: float) -> None:
        """Drop engagement maps untouched for the state TTL. Caller holds `self._lock`.

        Gated on a graph that can actually replay devices — `_ensure_loaded` re-warms from
        `load_devices` (topology) and `_warm_endpoints_from_db` (exploitable endpoints), so an evicted
        engagement is rebuilt on its next observation. `_loaded` is cleared with it, otherwise the
        once-per-process warm guard would hand back a permanently empty map.
        """
        if self._graph is None or not hasattr(self._graph, "load_devices"):
            return
        while self._state_seen:
            engagement_id, seen = next(iter(self._state_seen.items()))
            if now - seen <= self._state_ttl:
                # `<=` is load-bearing here: `observe` touches its engagement before mutating the map
                # and sweeps at the end of the same call, so this is what guarantees the sweep can
                # never drop the map that call is still writing to.
                break
            self._state_seen.pop(engagement_id, None)
            self._state.pop(engagement_id, None)
            self._loaded.discard(engagement_id)
            # Dropping the warm lock is safe even in the (impossible-by-TTL) case that a thread holds
            # it: publication is re-checked under `self._lock`, so a duplicate warm is wasteful, not
            # incorrect.
            self._warm_locks.pop(engagement_id, None)

    def _ensure_loaded(self, engagement_id: str) -> dict:
        """The engagement's working map, warmed from the durable stores on first use (or after §4
        retention dropped it). Thread-safe: two run threads on the same engagement would otherwise
        both miss the state check and each warm from the graph."""
        now = time.monotonic()
        with self._lock:
            st = self._state.get(engagement_id)
            if st is not None:
                self._touch(self._state_seen, engagement_id, now)
                return st
            warm_lock = self._warm_locks.get(engagement_id)
            if warm_lock is None:
                warm_lock = self._warm_locks[engagement_id] = threading.Lock()
        with warm_lock:
            # Double-checked: another thread may have finished warming while we queued on the lock.
            with self._lock:
                st = self._state.get(engagement_id)
                if st is not None:
                    self._touch(self._state_seen, engagement_id, now)
                    return st
                already_warmed = engagement_id in self._loaded
            st = {"devices": {}, "endpoints": {}}
            if not already_warmed:
                # Deliberately outside `self._lock`: both warm steps do network I/O (Neo4j, then
                # Postgres) and holding the shared lock across them would stall every other
                # engagement's `observe`. `warm_lock` still serializes same-engagement warms, and the
                # map being built is thread-local until it is published below — so no other thread can
                # observe a half-populated state dict.
                self._warm_from_graph(engagement_id, st)
                self._warm_endpoints_from_db(engagement_id, st)
            with self._lock:
                # Publish only once warm-up is done. Re-check in case the lock was dropped by a sweep
                # and a second thread published first; the winner is authoritative either way.
                published = self._state.get(engagement_id)
                if published is not None:
                    self._touch(self._state_seen, engagement_id, now)
                    return published
                self._state[engagement_id] = st
                self._loaded.add(engagement_id)
                self._touch(self._state_seen, engagement_id, now)
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

    def _warm_endpoints_from_db(self, engagement_id: str, st: dict) -> None:
        """Rehydrate the exploitable-endpoint set from the durable diff log.

        `load_devices` replays topology but the graph has no equivalent read for endpoints, so without
        this a cold map would re-report an already-known endpoint as `newly_exploitable` on the next
        observation — a duplicate row in the `/changes` view. The diff log is the durable copy that
        makes state retention lossless, so it is also what closes that gap. Best-effort like every
        other memory backend call: an unreachable db just means a first-run-again map.
        """
        if self._db is None:
            return
        try:
            with self._db.connection() as conn:
                rows = conn.execute(
                    "SELECT DISTINCT key FROM network_observations "
                    "WHERE engagement_id = %s AND kind = 'endpoint' "
                    "AND change = 'newly_exploitable'",
                    (engagement_id,),
                ).fetchall()
        except Exception:
            return
        for row in rows or []:
            url = row[0]
            if url:
                # `last_run_id` is unknown from the diff log and is only used for freshness, never for
                # a decision; None reads the same as "not seen this run".
                st["endpoints"][url] = {"exploitable": True, "last_run_id": None}

    _INSERT_OBSERVATION = (
        "INSERT INTO network_observations "
        "(engagement_id, run_id, kind, key, change, before, after) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s)"
    )

    def _flush_records(self, rows: list[tuple]) -> None:
        """Write one step's buffered change rows in a single round trip. Best-effort, exactly like
        the per-row write it replaces: the diff log must never fail a run."""
        if self._db is None or not rows:
            return
        try:
            with self._db.connection() as conn:
                with conn.cursor() as cur:
                    cur.executemany(self._INSERT_OBSERVATION, rows)
        except Exception:
            pass

    def _load_deltas(self, run_id: str) -> MemoryDelta:
        """Rebuild a run's aggregated delta from the durable diff log."""
        delta = MemoryDelta()
        if self._db is None:
            return delta
        buckets = {"added": delta.added, "changed": delta.changed, "removed": delta.removed,
                   "newly_exploitable": delta.newly_exploitable}
        try:
            with self._db.connection() as conn:
                rows = conn.execute(
                    "SELECT kind, key, change, before, after FROM network_observations "
                    "WHERE run_id = %s ORDER BY id",
                    (run_id,),
                ).fetchall()
        except Exception:
            return delta
        for kind, key, change, before, after in rows or []:
            bucket = buckets.get(change)
            if bucket is None:  # 'unchanged' and anything future: not part of the delta view
                continue
            bucket.append(_entry(kind, key, _label_for(kind, key, change, before, after),
                                 before, after))
        return delta

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
