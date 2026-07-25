# Pinkeye Backend — Optimization Plan

Scope of this review: `control-plane/app/**` and `agent-runtime/runtime/**` (plus `graph/schema.cypher`,
`deploy/docker-compose.yml`, `deploy/api.Dockerfile`). The web frontend is out of scope.

Findings are grouped as **Bottlenecks (B)**, **Correctness caveats (C)**, **Security caveats (S)**, and
**Redundancy (R)**. Each entry gives the observed behaviour, the root cause, and a concrete fix.

---

## 0. Scorecard

| # | Issue | Area | Severity | Effort |
|---|---|---|---|---|
| B1 | Agent runs occupy FastAPI's shared threadpool | Concurrency | **Critical** | M |
| B2 | N+1 write amplification per tool step (Neo4j + PG + audit + memory) | Data layer | **Critical** | M |
| B3 | Postgres pool sized 8, with a lazy-init data race | Data layer | **High** | S |
| C1 | `findings` upsert demotes `confirmed` → `suspected` | Correctness | **High** | S |
| C2 | `GET /chains` mutates the graph and leaks a new node per call | Correctness | **High** | S |
| S1 | All read endpoints, `/reply`, `/graph/query`, `/validate` are unauthenticated | Security | **Critical** | S |
| S2 | Unauthenticated `/reply` can approve intrusive exploitation | Security | **Critical** | S |
| C3 | `graph/query` ignores `engagement_id` — cross-engagement read | Correctness/Security | **High** | S |
| B4 | SSE polls every 400 ms and rescans the ring buffer per client | Concurrency | **High** | M |
| B5 | `get_graph` does an unlabelled property match (AllNodesScan) | Graph | **High** | S |
| B6 | No `Service` uniqueness constraint → label scan on every MERGE | Graph | **High** | XS |
| B7 | LLM message history grows unbounded (quadratic token cost) | Cost | **High** | M |
| R1 | `JobQueue.enqueue` has zero callers; the `worker` service is dead | Redundancy | **High** | M |
| B9 | MCP stdio client never drains stderr → pipe-full deadlock | Runtime | **Medium** | XS |
| B8 | MCP pool holds a global lock across container spawn | Runtime | **Medium** | S |
| B10 | `NetworkMemory.observe` closed-port detection is O(hosts × services) | Memory | **Medium** | S |
| C4–C15 | Assorted correctness caveats (see §3) | Mixed | Medium/Low | S each |
| R2–R10 | Redundancy and dead code (see §5) | Mixed | Low | S each |

---

## 1. Bottlenecks

### B1 — Agent runs are executed on FastAPI's shared anyio threadpool  *(Critical)*

**Observed.** `control-plane/app/main.py:362` declares `create_run` as a sync `def` endpoint and hands
the run to `background.add_task(_launch)` (`main.py:438`). `_launch` is a synchronous function, so
Starlette dispatches it to `anyio.to_thread.run_sync` — the *same* default-capacity-40 threadpool that
every other sync `def` endpoint in this module (`/map`, `/findings`, `/metrics`, `/report`, `/health`, …)
runs on. `deploy/api.Dockerfile:29` starts a single uvicorn worker, so there is exactly one such pool
per deployment.

**Root cause.** A `_launch` task is not a "background task" in the cheap sense — it is the entire
assessment: an LLM planning loop bounded by `Budget.max_tool_calls = 40` (`agent.py:92`), each step
spawning a Docker container with a 300 s ceiling (`sandbox.py:25`), plus `ask_user` blocking on
`RunInbox.wait` for up to `EYE_AGENT_ASK_TIMEOUT` = **600 s** by default (`agent.py:86`, `agent.py:340`).
A single interactive run can hold a worker thread for hours. Forty concurrent runs — well within what the
rate limiter permits at `burst=10, rate_per_min=30` per tenant (`ratelimit.py:20-21`) — saturate the pool
and the API stops answering *every* request, including `/health`.

The orchestrator profile makes this strictly worse: `_dispatch_specialist` (`agent.py:353`) runs the
child `run_agent` **synchronously inside the parent's thread**, so a specialist tree is still one thread
but with a much longer occupancy.

**Fix.**

1. Move run execution off the request path entirely onto a dedicated, explicitly-sized executor:

```python
# control-plane/app/main.py
from concurrent.futures import ThreadPoolExecutor

_RUN_POOL = ThreadPoolExecutor(
    max_workers=int(os.getenv("EYE_MAX_CONCURRENT_RUNS", "8")),
    thread_name_prefix="eye-run",
)

# in create_run, replace: background.add_task(_launch)
_RUN_POOL.submit(_launch)
```

   This makes run concurrency an explicit, tunable capacity rather than an accidental consequence of
   Starlette's threadpool size, and it stops runs from competing with request handling. Drop the
   now-unused `BackgroundTasks` parameter.

2. Raise the request threadpool independently so read endpoints keep flowing:

```python
@app.on_event("startup")
def _size_threadpool():
    import anyio.to_thread
    anyio.to_thread.current_default_thread_limiter().total_tokens = int(
        os.getenv("EYE_API_THREADS", "60")
    )
```

3. Reject new runs when the executor is saturated instead of queueing invisibly — return `503` with a
   `Retry-After`, so an operator sees back-pressure rather than a run stuck in `queued` forever.

4. Longer term, this is exactly what the (currently dead — see **R1**) job queue exists for. Routing
   `create_run` through `JobQueue.enqueue` and letting `app.worker` execute makes run capacity a
   horizontal scaling knob (`docker compose up --scale worker=N`) and survives an API restart.

---

### B2 — N+1 write amplification on every tool step  *(Critical)*

**Observed.** `runtime/orchestrator.py:112-133` persists results with one round trip **per row**, into
four stores:

```python
for svc in out.services:
    graph.upsert_service(...)          # new Neo4j session + write tx
    db.upsert_service(...)             # borrow PG connection, 1 INSERT
for finding in out.findings:
    enrich_finding(finding)
    graph.record_finding(finding)      # new Neo4j session + write tx
    db.record_finding(finding)         # borrow PG connection, 1 INSERT
    _audit(audit, ...)                 # borrow PG connection, 1 INSERT
...
memory.observe(...)                    # 1 INSERT per detected change (memory.py:272)
```

Every `GraphClient` method opens its own `self._driver.session()` (`graph.py:87`, `:137`, `:155`, `:212`,
`:294`) — one session, one implicit transaction, one network round trip per node.

**Root cause.** The write path was written row-at-a-time for clarity and never revisited for the volume
real tools produce. A single `nmap -p-` at `Intensity.aggressive` (`tools/nmap.py:14`) against one host
can yield thousands of open ports; `parse_nmap_xml` emits **one service *and* one finding per open port**
(`normalize/nmap.py:37-56`). For 1 000 open ports that is:

- 1 000 Neo4j sessions for services + 1 000 for findings,
- 1 000 PG connections for services + 1 000 for findings + 1 000 for audit events,
- up to 1 000 more PG connections from `NetworkMemory._record`,

≈ **6 000 round trips inside one tool step**, all serialized on one thread, all contending for a pool of
8 connections (**B3**). The MCP path has the same shape with `_MAX_FINDINGS = 200` per call
(`mcp/backend.py:28`).

**Fix.**

1. **Batch the Neo4j writes.** Add bulk methods that take the whole list and use `UNWIND`, keeping the
   identical MERGE keys so nothing duplicates:

```python
# control-plane/app/graph.py
def upsert_services(self, engagement_id, services, run_id=None) -> None:
    if not services:
        return
    rows = [{"addr": s.address, "port": s.port, "proto": s.proto,
             "service": s.service, "product": s.product} for s in services]
    with self._driver.session() as session:
        session.run("""
            UNWIND $rows AS row
            MERGE (e:Engagement {id: $eid}) SET e.engagement_id = $eid
            MERGE (i:IP {engagement_id: $eid, address: row.addr})
              ON CREATE SET i.first_seen = $now, i.first_run_id = $rid, i.status = 'new'
              ON MATCH  SET i.last_run_id = $rid
              SET i.last_seen = $now
            MERGE (e)-[:DISCOVERED]->(i)
            MERGE (i)-[:EXPOSES]->(p:Port {engagement_id: $eid, address: row.addr, number: row.port})
              ON CREATE SET p.first_seen = $now, p.first_run_id = $rid
              ON MATCH  SET p.last_run_id = $rid
              SET p.proto = row.proto, p.last_seen = $now
            MERGE (p)-[:RUNS]->(s:Service {engagement_id: $eid, address: row.addr, port: row.port})
              ON CREATE SET s.first_seen = $now, s.first_run_id = $rid
              ON MATCH  SET s.last_run_id = $rid
              SET s.name = row.service, s.product = row.product, s.last_seen = $now
        """, rows=rows, eid=engagement_id, rid=run_id, now=_now_iso())
```

   Do the same for `record_findings(list)` and for `write_attack_chain`'s per-step loop
   (`graph.py:301-306`, currently one query per chain step).

2. **Batch the Postgres writes** with `executemany` / `COPY`, borrowing **one** connection per step:

```python
# control-plane/app/repositories.py
class ServiceRepo:
    def upsert_many(self, engagement_id, rows) -> None:
        if not rows:
            return
        with self._db.connection() as conn:
            conn.cursor().executemany(_UPSERT_SERVICE_SQL,
                [(engagement_id, *r) for r in rows])
```

   Give `PersistenceSink` matching `record_findings` / `upsert_services` plural methods and call those
   from `execute_tool_step`.

3. **Batch the audit log.** `PostgresAuditSink.append` (`audit.py:69`) borrows a connection per event.
   Add `append_many` and buffer per step. The append-only guarantee is unaffected — the events are still
   never updated or deleted, they are just written in one transaction.

4. **Batch `NetworkMemory._record`.** `memory.py:272` opens a connection per change entry. Accumulate the
   step's rows and flush once at the end of `observe`.

Expected effect: the 6 000-round-trip step above collapses to roughly **4 round trips**.

---

### B3 — Postgres pool is undersized and its lazy init has a data race  *(High)*

**Observed.** `control-plane/app/db/database.py:20-28`:

```python
def _get_pool(self):
    if self._pool is None:                       # <-- checked without a lock
        from psycopg_pool import ConnectionPool
        pool = ConnectionPool(self._dsn, min_size=1, max_size=8, open=False)
        pool.open(wait=True, timeout=5)
        self._pool = pool
    return self._pool
```

**Root cause (two).**

1. **Sizing.** `max_size=8` was chosen when writes were rare. Given **B2**, one `nmap` step alone will
   queue thousands of connection acquisitions behind 8 slots, and the SSE `_persist` path
   (`events.py:164`) competes for the same 8 while the run is emitting. Everything else — dashboards,
   findings queries, the audit sink — starves behind it.

2. **Race.** `_get_pool` is called from many threads (run threads via `PersistenceSink`, the
   request threadpool via the repos, the MCP reaper indirectly). Two threads can both observe
   `self._pool is None` and each build a pool. One is orphaned but never closed, permanently leaking up
   to 8 connections and 1 background worker thread — and, because `pool.open(wait=True, timeout=5)`
   blocks, the second thread stalls 5 s in the failure case.

**Fix.**

```python
import threading

class Database:
    def __init__(self, dsn: str):
        self._dsn = dsn
        self._pool = None
        self._lock = threading.Lock()

    def _get_pool(self):
        pool = self._pool
        if pool is not None:
            return pool
        with self._lock:
            if self._pool is None:              # double-checked under the lock
                from psycopg_pool import ConnectionPool
                p = ConnectionPool(
                    self._dsn,
                    min_size=int(os.getenv("EYE_PG_POOL_MIN", "2")),
                    max_size=int(os.getenv("EYE_PG_POOL_MAX", "32")),
                    open=False,
                )
                p.open(wait=True, timeout=5)
                self._pool = p
            return self._pool
```

Size `EYE_PG_POOL_MAX` to at least `EYE_MAX_CONCURRENT_RUNS + EYE_API_THREADS/4`, and keep it below the
Postgres `max_connections` budget shared with the `worker` replicas.

---

### B4 — SSE tailing polls every 400 ms and rescans the buffer per client  *(High)*

**Observed.** `main.py:491-507` loops on a fixed `poll_interval = 0.4`, and each tick calls
`run_events.events_after(run_id, last)` which takes the store-wide lock and *linearly scans the whole
ring buffer*:

```python
# control-plane/app/events.py:145
def events_after(self, run_id: str, after: int) -> list[RunEvent]:
    with self._lock:
        buf = self._buffers.get(run_id)
        ...
        return [e for e in buf if e.seq > after]     # O(buffer_size) = up to 4000
```

**Root cause.** The store exposes only a polling primitive, so latency is traded against CPU. With
`buffer_size = 4000` (`events.py:123`) and N watching clients, the cost is `N × 2.5 scans/s × 4000
comparisons`, every one of them serialized on `self._lock` — the *same* lock `emit` needs, so a busy
transcript view actively slows the run producing it.

**Fix (two independent wins).**

1. **Make the scan O(new events)** — `seq` is monotonic per run and the deque is append-ordered, so the
   offset is arithmetic rather than a filter:

```python
from itertools import islice

def events_after(self, run_id: str, after: int) -> list[RunEvent]:
    with self._lock:
        buf = self._buffers.get(run_id)
        if not buf:
            return []
        start = max(0, after - buf[0].seq + 1)   # seq is dense and ordered within a run
        if start >= len(buf):
            return []
        return list(islice(buf, start, None))
```

   `islice` on a deque still walks to the offset, but it copies only the tail rather than comparing every
   element — and in the steady state (`after` == latest seq) it returns immediately.

2. **Wake on emit instead of polling.** Give each run a `threading.Event` that `emit` sets and the SSE
   generator waits on, with the existing interval as a fallback heartbeat:

```python
# events.py
def waiter(self, run_id: str) -> threading.Event:
    with self._lock:
        return self._waiters.setdefault(run_id, threading.Event())

# in emit(), after appending to the buffer:
self._waiters.get(run_id, _NULL_EVENT).set()

# main.py gen():
await asyncio.to_thread(waiter.wait, poll_interval)
waiter.clear()
```

   This drops idle CPU to ~zero and cuts event latency from up to 400 ms to ~0.

Also raise/remove the `max_duration = 30 * 60` cap (`main.py:489`) or make it configurable — an
orchestrator run with several specialist passes plus a 600 s `ask_user` block routinely exceeds 30
minutes, and today the stream silently closes mid-run.

---

### B5 — `get_graph` performs an unlabelled property match  *(High)*

**Observed.** `graph.py:263-266`:

```cypher
MATCH (n {engagement_id: $eid})
OPTIONAL MATCH (n)-[r]->(m {engagement_id: $eid}) RETURN n, r, m LIMIT $limit
```

**Root cause.** A pattern with no label cannot use any index — every index in `graph/schema.cypher` is
label-scoped (`FOR (i:IP) ON (i.engagement_id)` etc.). Neo4j must plan an `AllNodesScan` and filter on
the property, so `/engagements/{id}/graph` cost scales with the size of the *entire* database, not the
engagement. The cross-engagement `/map` (`graph.py:260`) is `MATCH (n) OPTIONAL MATCH (n)-[r]->(m)` —
also a full scan, with `LIMIT` applied to *rows*, so one hub node with many relationships crowds every
other node out of the payload and the map looks wrong rather than merely truncated.

**Fix.**

```python
LABELS = ("Engagement", "IP", "Port", "Service", "Endpoint", "Finding", "AttackChain")

def get_graph(self, engagement_id=None, limit=1000):
    limit = max(1, min(limit, 5000))
    if engagement_id is None:
        query = ("MATCH (n) WHERE any(l IN labels(n) WHERE l IN $labels) "
                 "WITH n LIMIT $limit OPTIONAL MATCH (n)-[r]->(m) RETURN n, r, m")
        params = {"limit": limit, "labels": list(LABELS)}
    else:
        # UNION over labelled, index-backed scans; LIMIT applied to nodes, not rows.
        query = ("CALL { " + " UNION ".join(
            f"MATCH (n:{l} {{engagement_id: $eid}}) RETURN n" for l in LABELS
        ) + " } WITH n LIMIT $limit "
          "OPTIONAL MATCH (n)-[r]->(m {engagement_id: $eid}) RETURN n, r, m")
        params = {"eid": engagement_id, "limit": limit}
```

Applying `LIMIT` to nodes before expanding relationships also fixes the truncation-shape bug.

---

### B6 — `Service` nodes have no uniqueness constraint  *(High, trivial fix)*

**Observed.** `graph/schema.cypher` constrains `Engagement`, `Run`, `IP`, `Domain`, `Port`, `Endpoint`,
and `Finding`, but `Service` gets only `CREATE INDEX service_last_run ... ON (s.last_run_id)` (line 41).

**Root cause.** `graph.py:100` does `MERGE (p)-[:RUNS]->(s:Service {engagement_id, address, port})`.
Without a backing constraint or composite index on those three properties, each MERGE degenerates to a
label scan over all `Service` nodes, and concurrent runs can race into duplicate `Service` nodes because
nothing enforces the key.

**Fix.** Add to `graph/schema.cypher`:

```cypher
CREATE CONSTRAINT service_key IF NOT EXISTS
  FOR (s:Service) REQUIRE (s.engagement_id, s.address, s.port) IS UNIQUE;

CREATE INDEX service_engagement IF NOT EXISTS
  FOR (s:Service) ON (s.engagement_id);

CREATE INDEX endpoint_engagement IF NOT EXISTS
  FOR (e:Endpoint) ON (e.engagement_id);
```

`apply_schema` runs at startup and is idempotent (`main.py:130`), so this deploys with no migration step.
If duplicate `Service` nodes already exist the constraint creation will fail — dedupe first with a
one-off `MATCH (s:Service) WITH s.engagement_id AS e, s.address AS a, s.port AS p, collect(s) AS ss
WHERE size(ss) > 1 ...` cleanup.

---

### B7 — LLM message history grows unbounded  *(High — cost, not latency)*

**Observed.** `agent.py:266-280` appends the assistant turn and every tool result to `messages` and never
prunes; `provider.complete(messages, specs)` resends the whole list each iteration.

**Root cause.** There is no context-window management. Over the default `max_tool_calls = 40`, input
tokens grow linearly per step and *cumulatively quadratically* over the run. The token budget only counts
`resp.output_tokens` (`agent.py:252`) — input tokens are never measured despite `ProviderResponse`
carrying `input_tokens` (`llm/base.py:42`), so the runaway cost is invisible to the budget that exists to
bound it.

The orchestrator profile mitigates this by design (specialists return one-line summaries,
`subagents.py:225`), which is precisely why the `flat` and single-specialist profiles are the exposed
risk.

**Fix.**

1. Count input tokens in the budget:

```python
result.output_tokens += resp.output_tokens
result.input_tokens  += resp.input_tokens      # add the field to AgentResult
if result.input_tokens + result.output_tokens >= budget.max_output_tokens:
    result.stop_reason = "token budget reached"
    break
```

2. Roll up old turns once the history exceeds a threshold, always preserving the system messages and the
   most recent N exchanges:

```python
def _compact(messages: list[Message], keep: int = 12) -> list[Message]:
    system = [m for m in messages if m.role == "system"]
    body = [m for m in messages if m.role != "system"]
    if len(body) <= keep:
        return messages
    dropped = body[:-keep]
    summary = Message(role="system", content=(
        "Earlier steps (summarized): " +
        "; ".join(m.content[:120] for m in dropped if m.role == "tool")[:4000]))
    return [*system, summary, *body[-keep:]]
```

   Call it at the top of the loop. Tool-result messages must be dropped together with their originating
   assistant turn, or the provider adapters will emit a `tool_result` with no matching `tool_use`
   (`llm/claude.py:71-79`) and the API will reject the request.

---

### B8 — MCP pool holds a global lock across container spawn  *(Medium)*

**Observed.** `mcp/pool.py:67-79` — `_acquire` holds `self._lock` (a single process-wide `RLock`) while
calling `self._factory(spec)`, which is `_default_session_factory` → `MCPSession.start()` → blocks on
`self._connected.result(timeout=self._timeout + 10)`, i.e. up to **130 s** by default.

**Root cause.** One lock guards the whole session map, so a cold start of *one* server blocks acquisition
of *every* server — including already-warm ones — for the duration of a `docker run` plus MCP handshake.

**Fix.** Use a per-key lock so only contenders for the same server serialize:

```python
def _acquire(self, spec, key: str) -> MCPSession:
    with self._lock:
        entry = self._sessions.get(key)
        if entry is not None and not entry.session.closed:
            entry.last_used = self._clock()
            return entry.session
        key_lock = self._key_locks.setdefault(key, threading.Lock())
    with key_lock:                              # only same-server callers wait
        with self._lock:
            entry = self._sessions.get(key)
            if entry is not None and not entry.session.closed:
                entry.last_used = self._clock()
                return entry.session
        session = self._factory(spec)           # slow path, outside the global lock
        with self._lock:
            self.connect_count += 1
            self._sessions[key] = _Entry(session, self._clock())
            self._ensure_reaper()
        return session
```

Note also that `MCPSession.call_tool` serializes on `self._call_lock` (`mcp/session.py:119`) — correct for
one stdio pipe, but it means concurrent runs sharing a pooled server queue behind each other. If MCP
becomes a hot path, pool *k* sessions per key rather than one.

---

### B9 — MCP stdio client never drains stderr → deadlock  *(Medium, trivial fix)*

**Observed.** `mcp/client.py:64-72` spawns with `stderr=subprocess.PIPE` and only reads it on the
connection-closed path (`client.py:170-175`).

**Root cause.** Nothing ever reads the stderr pipe during normal operation. A server that logs verbosely
to stderr fills the 64 KiB pipe buffer, blocks on write, stops responding on stdout, and the client hangs
until its `select` timeout (`client.py:165`) — reported to the operator as an opaque "MCP server timed
out" rather than the real cause. `_read_line`'s `select` only watches `stdout`, so stderr pressure is
invisible.

**Fix.** Redirect stderr to a drained sink:

```python
self._proc = subprocess.Popen(
    [self._command, *self._args],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL if not _capture_stderr() else subprocess.PIPE,
    ...
)
```

or, to keep stderr for diagnostics, start a daemon reader thread on `start()` that appends into a bounded
`collections.deque(maxlen=200)` and report that buffer in the timeout/closed error messages.

---

### B10 — `NetworkMemory.observe` closed-port detection is O(hosts × services)  *(Medium)*

**Observed.** `memory.py:128-141`:

```python
for addr in observed_hosts:
    incoming_keys = {
        (int(getattr(s, "port", 0) or 0), getattr(s, "proto", "tcp") or "tcp")
        for s in (services or []) if getattr(s, "address", None) == addr   # full rescan per host
    }
```

**Root cause.** The incoming service list is rescanned in full for every observed host. A `/24` sweep
producing 250 hosts × 20 services rescans 5 000 entries 250 times = 1.25 M attribute lookups per step,
on the run thread, holding no useful state.

**Fix.** Build the index once, before the host loop:

```python
from collections import defaultdict

incoming_by_host: dict[str, set[tuple[int, str]]] = defaultdict(set)
for s in services or []:
    addr = getattr(s, "address", None)
    if addr:
        incoming_by_host[addr].add(
            (int(getattr(s, "port", 0) or 0), getattr(s, "proto", "tcp") or "tcp"))

for addr in observed_hosts:
    incoming_keys = incoming_by_host[addr]
    ...
```

`_ensure_loaded` (`memory.py:234`) is also not thread-safe: two run threads for the same engagement can
both miss the `self._state` check and double-warm from the graph, doubling the device dict work and
racing on `self._loaded`. Guard the whole method with a lock.

---

### B11 — Query patterns that defeat every index  *(Medium)*

Three separate spots issue leading-wildcard matches against unindexed columns:

| Location | Query | Problem |
|---|---|---|
| `query.py:51` | `(title ILIKE '%q%' OR evidence ILIKE '%q%')` | seq scan on `findings`; `evidence` is long text |
| `repositories.py:176` | `address ILIKE %s OR service ILIKE %s OR product ILIKE %s` | seq scan on `services` |
| `cve_db.py:48` | `lower(product) LIKE '%p%'` | index `cves_product ON cves(lower(product))` is unusable with a leading `%` |

`build_findings_query` also ends with `ORDER BY cvss_score DESC, last_seen DESC` (`query.py:61`) with no
matching index, forcing a sort of the whole filtered set.

**Fix.** Add a migration `0008_search_indexes.sql`:

```sql
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX IF NOT EXISTS findings_title_trgm   ON findings USING gin (title gin_trgm_ops);
CREATE INDEX IF NOT EXISTS services_address_trgm ON services USING gin (address gin_trgm_ops);
CREATE INDEX IF NOT EXISTS cves_product_trgm     ON cves    USING gin (lower(product) gin_trgm_ops);

-- Matches the query planner's ORDER BY for the common "findings for an engagement" read.
CREATE INDEX IF NOT EXISTS findings_eng_score ON findings (engagement_id, cvss_score DESC, last_seen DESC);
CREATE INDEX IF NOT EXISTS run_events_run_seq_uniq ON run_events (run_id, seq);
```

Additionally, `MetricsRepo.kpis` (`repositories.py:188-212`) issues **6 sequential queries** on one
connection for a single dashboard render. Collapse to two — one over `services`, one over `findings` —
using `FILTER` aggregates:

```sql
SELECT count(*) FILTER (WHERE state <> 'false_positive') AS open_issues,
       count(DISTINCT cve) FILTER (WHERE cve IS NOT NULL) AS cves_identified,
       severity, count(*) AS n
FROM findings WHERE engagement_id = %s GROUP BY ROLLUP (severity);
```

---

### B12 — Sandbox loads unbounded tool output into memory  *(Medium)*

**Observed.** `sandbox.py:63-66` calls `container.logs()` twice (once for stdout, once for stderr), each
materializing the complete output as `bytes`. There is no size cap anywhere on the path; the bytes are
then hashed (`audit.py:38`) and handed to `tool.parse` (`orchestrator.py:107`).

**Root cause.** The container has memory and CPU ceilings (`sandbox.py:53-57`) but its *output* has none.
An `nmap -p-` XML dump, a `zap-full-scan` JSON, or a hostile/looping tool can return hundreds of MB into
the API process — which is also running every other request handler.

**Fix.**

```python
_MAX_OUTPUT = int(os.getenv("EYE_TOOL_MAX_OUTPUT_BYTES", str(64 * 1024 * 1024)))

stdout = container.logs(stdout=True, stderr=False)[:_MAX_OUTPUT]
stderr = container.logs(stdout=False, stderr=True)[:_MAX_OUTPUT]
```

Better, stream with `container.logs(stream=True)` and stop at the cap so the full payload is never
resident. Record truncation in the audit detail so the operator knows the parse was partial.

The same applies to `mcp/backend.py:258-284`: `_path_objects` in `file_content` mode reads up to
`max_files = 200` files of `max_bytes = 200_000` each into a single JSON-RPC message — up to 40 MB in one
line-framed write.

---

### B13 — `link_engagement_hosts` full-graph scan on every startup  *(Low)*

**Observed.** `main.py:135` calls `graph.link_engagement_hosts()` at every boot; `graph.py:58-67` runs
`MATCH (i:IP) MATCH (e:Engagement {id: i.engagement_id}) MERGE (e)-[:DISCOVERED]->(i)` over the whole
database, plus the same for `Endpoint`.

**Root cause.** It is described in its own docstring as a *backfill* "for data written before
engagement→host linking existed" — a one-time migration wired into the startup path. Its cost grows with
total graph size forever, and it delays readiness on every restart.

**Fix.** Gate it behind an explicit opt-in and treat it as a migration:

```python
if os.getenv("EYE_GRAPH_BACKFILL_LINKS") == "1":
    graph.link_engagement_hosts()
```

`upsert_service` and `record_finding` already `MERGE (e)-[:DISCOVERED]->(i)` inline (`graph.py:95`,
`graph.py:227`), so nothing written by the current code needs the backfill.

---

## 2. Correctness caveats

### C1 — `findings` upsert silently demotes confirmed findings  *(High)*

`repositories.py:101-107`:

```sql
ON CONFLICT (dedup_key) DO UPDATE SET
    ...
    state = EXCLUDED.state,          -- <-- always the incoming 'suspected'
    confidence = GREATEST(findings.confidence, EXCLUDED.confidence),
```

**Root cause.** Every normalizer constructs findings with the `Finding` default
`state = FindingState.suspected` (`models.py:117`). So a finding that `/validate` promoted to `confirmed`
(`promote_corroborated`, `repositories.py:138`) is reset to `suspected` the next time any tool re-observes
it. Confidence is deliberately protected with `GREATEST`; state is not — an inconsistency in the same
statement, which points to an oversight rather than intent.

The knock-on: `NetworkMemory._is_exploitable_finding` keys "target device" on
`state == confirmed and severity in (high, critical)` (`memory.py:231`), so the demotion also silently
un-flags target devices in the cross-run map.

**Fix.** Make the state transition monotonic, never regressing a human/validation decision:

```sql
state = CASE
          WHEN findings.state = 'false_positive' THEN 'false_positive'   -- triage is sticky
          WHEN findings.state = 'confirmed'      THEN 'confirmed'        -- never demote
          ELSE EXCLUDED.state
        END,
```

Also add `severity = EXCLUDED.severity, title = EXCLUDED.title, evidence = EXCLUDED.evidence` — today a
re-observation that *raises* severity is discarded, because only `state`, `confidence`, `run_id`, and
`cvss_score` are updated.

---

### C2 — `GET /chains` mutates the graph and leaks a node per call  *(High)*

**Observed.** `main.py:594-606`:

```python
@app.get("/engagements/{engagement_id}/chains")
def get_chains(engagement_id: str):
    chains = correlate(findings.list_findings(engagement_id))
    for c in chains:
        graph.write_attack_chain(c)      # write, on a GET
    return chains
```

**Root cause.** `correlate` mints `id=str(uuid.uuid4())` for every chain on every invocation
(`correlation.py:50`, `:70`), and `write_attack_chain` does `MERGE (c:AttackChain {id: $id})`
(`graph.py:296`). Because the id is fresh each time, the MERGE **always creates**. Every dashboard render
that hits `/chains` permanently adds a full set of duplicate `AttackChain` nodes plus one `STEP` edge per
member finding — and `write_attack_chain` issues one query *per step* (`graph.py:301-306`), so the write
cost is O(chains × steps) per page load. The network map then renders N copies of the same chain.

**Fix (two parts).**

1. Make the chain id deterministic so MERGE is genuinely idempotent:

```python
# correlation.py
import hashlib

def _chain_id(engagement_id: str, kind: str, key: str) -> str:
    return hashlib.sha256(f"{engagement_id}|{kind}|{key}".encode()).hexdigest()[:32]

# host chain:            id=_chain_id(engagement_id, "host", host)
# code-to-runtime chain: id=_chain_id(engagement_id, "cwe", s.cwe)
```

2. Separate reading from writing. `GET /chains` should be pure; move the graph write to the existing
   `POST /engagements/{id}/validate`, or add `POST /engagements/{id}/chains` for materialization. A GET
   with side effects is also why any prefetching client silently multiplies the damage.

While here: batch `write_attack_chain`'s step loop into a single `UNWIND` query.

---

### C3 — `graph/query` ignores its `engagement_id` path parameter  *(High)*

**Observed.** `main.py:529-537`:

```python
@app.post("/engagements/{engagement_id}/graph/query")
def graph_query(engagement_id: str, body: CypherQuery):
    ok, reason = is_read_only_cypher(body.cypher)
    ...
    return {"rows": graph.run_read_query(body.cypher)}   # engagement_id never used
```

**Root cause.** The endpoint is *shaped* as engagement-scoped but the parameter is never applied to the
query or used to validate it. Any caller can read the entire cross-engagement, cross-tenant graph through
a URL that appears to be scoped to one engagement. Combined with **S1** (no auth on this route at all)
this is a full-graph read primitive for an unauthenticated caller.

The `is_read_only_cypher` guard (`query.py:73`) is a *write* guard, not a *scope* guard — and it is
lexical, so `MATCH (n) WHERE n.name = 'my dataset'` is rejected for containing `set`, while
`MATCH (n) RETURN n` reads everything.

**Fix.** Enforce the scope structurally rather than lexically — wrap the caller's query so it can only
ever see nodes belonging to the engagement, and bind the id as a parameter:

```python
@app.post("/engagements/{engagement_id}/graph/query")
def graph_query(engagement_id: str, body: CypherQuery,
                principal: Principal = Depends(require("viewer"))):
    ok, reason = is_read_only_cypher(body.cypher)
    if not ok:
        raise HTTPException(400, f"rejected: {reason}")
    if not _load_engagement(engagement_id):
        raise HTTPException(404, "engagement not found")
    try:
        return {"rows": graph.run_read_query(body.cypher, {"eid": engagement_id})}
    except Exception as exc:
        raise HTTPException(400, f"query error: {exc}")
```

and require the query to reference `$eid` (reject it otherwise), so an operator writes
`MATCH (n:IP {engagement_id: $eid}) RETURN n`. The Neo4j READ transaction
(`graph.py:328`) remains the write backstop; this adds the missing *read* boundary. Also cap execution
with `session.run(..., timeout=...)` so an unbounded variable-length path (`MATCH (a)-[*]-(b)`) cannot
pin the graph database.

---

### C4 — `list_engagements` discards the in-memory fallback on an empty DB  *(Medium)*

`main.py:282-287`:

```python
try:
    return engagements.list()          # returns [] on a reachable-but-empty DB
except Exception:
    return list(store.engagements.values())
```

**Root cause.** `_save_engagement` (`main.py:151`) deliberately writes to both stores and swallows the DB
failure, so the in-memory `Store` is the source of truth when Postgres is degraded. But `list()` only
falls back on an *exception*. If the DB is up but the write failed earlier (or the table was truncated),
`list()` succeeds with `[]` and the engagements visible via `GET /engagements/{id}` (which *does* fall
back, `main.py:159-166`) vanish from the index. The two read paths disagree.

**Fix.** Merge rather than choose:

```python
@app.get("/engagements")
def list_engagements():
    merged = {e.id: e for e in store.engagements.values()}
    try:
        for e in engagements.list():
            merged[e.id] = e            # DB wins where both have it
    except Exception:
        pass
    return sorted(merged.values(), key=lambda e: e.created_at, reverse=True)
```

More fundamentally, the dual-store design (**R2**) should be retired once Postgres is a hard dependency.

---

### C5 — `GET /runs/{id}` returns two different response shapes  *(Medium)*

`main.py:442-453` returns `runs.get(run_id)` — a plain `dict` with `updated_at`
(`repositories.py:76-77`) — when Postgres is reachable, and a `Run` **pydantic model** (no `updated_at`,
different serialization of `status`) from `store.runs` otherwise. Clients cannot rely on either.

**Fix.** Have `RunRepo.get` return a `Run` model and add `updated_at` to the model, so both branches
produce one schema. Declare it: `@app.get("/runs/{run_id}", response_model=Run)`.

---

### C6 — SSE tailing has no database fallback  *(Medium)*

`RunEventStore.all_events` falls back to `self._load(run_id)` when the in-memory buffer is missing
(`events.py:153-160`), but `events_after` returns `[]` unconditionally (`events.py:145-151`). After an API
restart, a client that reconnects to a still-running run gets the full transcript from
`GET /runs/{id}/transcript` and then **tails nothing forever** — the run appears frozen.

(In the current single-process design the run itself also dies with the API, so this is mostly a
correctness gap that becomes a live bug the moment runs move to the worker — see **R1**.)

**Fix.** Mirror the `all_events` fallback:

```python
def events_after(self, run_id: str, after: int) -> list[RunEvent]:
    with self._lock:
        buf = self._buffers.get(run_id)
        if buf:
            ...  # binary-search path from B4
    return [e for e in self._load(run_id) if e.seq > after]
```

Add the `(run_id, seq)` index from **B11** so that fallback query is cheap, and make it unique so the
best-effort `_persist` cannot write duplicates on a retry.

---

### C7 — `/changes` reads process-local state while a durable table sits unused  *(Medium)*

`main.py:586-589` serves `memory.deltas_for_run(run_id)`, which reads `self._run_deltas`
(`memory.py:183`) — an in-process dict. Migration `0007_network_memory.sql` created
`network_observations` *specifically* to make this "audit-grade and survive an API restart", and
`memory._record` faithfully writes every change to it (`memory.py:272-287`) — but **nothing ever reads
that table**. The persisted diff log is write-only.

**Fix.** Add the read and prefer it, falling back to memory:

```python
# memory.py
def deltas_for_run(self, run_id: str) -> MemoryDelta:
    delta = self._run_deltas.get(run_id)
    if delta is not None:
        return delta
    return self._load_deltas(run_id)     # SELECT kind, key, change, before, after
                                         # FROM network_observations WHERE run_id = %s ORDER BY id
```

This also bounds `_run_deltas`, which currently grows for the process lifetime (**§4**).

---

### C8 — Reports and chains silently truncate at 1 000 findings  *(Medium)*

`FindingRepo.list_findings` hardcodes `FindingFilters(limit=1000)` (`repositories.py:125`), and
`build_findings_query` clamps to 1 000 anyway (`query.py:55`). `/chains` and `/report`
(`main.py:598`, `main.py:625`) both build on it. A large engagement therefore produces a report that is
quietly incomplete, with the highest-CVSS findings kept (the `ORDER BY`) and everything else dropped —
no error, no warning.

**Fix.** Paginate internally for the aggregate paths:

```python
def iter_findings(self, engagement_id: str, page: int = 1000):
    offset = 0
    while True:
        rows = self._page(engagement_id, limit=page, offset=offset)
        if not rows:
            return
        yield from rows
        offset += page
```

and, at minimum, surface `"truncated": true` in the report header when the cap is hit.

---

### C9 — The tool-call budget is checked only after a whole batch  *(Low)*

`agent.py:267-288` iterates *all* `resp.tool_calls` from one model turn, then checks the budget. A model
returning 10 parallel tool calls on the final permitted step executes all 10, overshooting
`max_tool_calls`. For gated tools this is bounded by the scope guard, but the budget exists precisely to
bound cost and blast radius.

**Fix.** Check inside the loop:

```python
for tc in resp.tool_calls:
    if result.tool_calls_used >= budget.max_tool_calls:
        result.stop_reason = "tool-call budget reached"
        break
    ...
```

---

### C10 — Nested specialists hijack the parent's refusal callback  *(Low)*

`agent.py:238-239`:

```python
if hasattr(provider, "on_refusal"):
    provider.on_refusal = lambda data: emit("refusal", **data)
```

The same `provider` instance is passed down to every specialist (`agent.py:379`), and each nested
`run_agent` reassigns `on_refusal` to *its* `emit` — which stamps `subagent=kind`
(`agent.py:180-181`). The assignment is never restored, so after the first specialist returns, the
orchestrator's own refusal events are attributed to that specialist in the transcript.

**Fix.** Save and restore around the nested call, or pass the emitter explicitly rather than mutating
shared provider state:

```python
previous = getattr(provider, "on_refusal", None)
try:
    ...
finally:
    if hasattr(provider, "on_refusal"):
        provider.on_refusal = previous
```

---

### C11 — Columns that exist but are never written  *(Low, but blocks tenancy)*

| Column | Migration | Writer |
|---|---|---|
| `runs.tool`, `runs.intensity` | `0001_init.sql:16-17` | none — `RunRepo.save` omits them (`repositories.py:54-59`) |
| `runs.tenant_id` | `0002_tenant.sql:5` | none |
| `findings.tenant_id` | `0002_tenant.sql:6` | none — `FindingRepo.upsert` omits it |
| `services.tenant_id` | `0002_tenant.sql:7` | none — `ServiceRepo.upsert` omits it |

**Root cause.** Multi-tenancy landed as a schema change without the corresponding write-path change. The
consequence is not cosmetic: `build_findings_query` accepts a `tenant_id` and emits
`tenant_id = %s` (`query.py:35-37`), but since every row carries the `'default'` column default, that
filter is a no-op that *looks* like isolation. Nothing in `main.py` passes it anyway (**S4**).

**Fix.** Thread `principal.tenant_id` into `PersistenceSink` at run creation and write it on every insert;
then pass it to `findings.query(...)` from the endpoint. Backfill existing rows from
`engagements.tenant_id` in a migration.

---

### C12 — `enrich_finding` discards tool-supplied CVSS scores  *(Low)*

`enrich.py:14` unconditionally assigns `f.cvss_score = score_for_finding(f.cvss_vector, f.severity)`.
`score_for_finding` (`cvss.py:70`) uses the vector when present, otherwise a severity fallback — so a tool
that reported an authoritative numeric score but *no vector* (Snyk, Trivy, several MCP servers) has it
overwritten by a coarse bucket (`high` → 7.5).

**Fix.**

```python
def enrich_finding(f: Finding) -> Finding:
    computed = score_for_finding(f.cvss_vector, f.severity)
    if f.cvss_vector or not f.cvss_score:
        f.cvss_score = computed        # keep a tool-supplied score when we have nothing better
    ...
```

---

### C13 — The worker path is a second-class copy of the API path  *(Medium)*

`app/worker.py:27-43` reimplements run dispatch, and diverges from `main.py` in every way that matters:

- `tools.get(p.get("tool", "nmap"))` can return `None`, which `run_scan` immediately dereferences
  (`orchestrator.py:63` → `getattr(tool, "requires_flag", None)` is fine, but `tool.name` at
  `orchestrator.py:65` raises `AttributeError`). The outer handler catches it and marks the job failed with
  no diagnostic beyond the exception string.
- No `events=`, so worker runs emit **no transcript at all** — the chat UI shows an empty run.
- No `memory=`, so worker runs never feed the cross-run map.
- No `inbox=`, so `ask_user` always times out after 600 s and proceeds autonomously.
- No `enabled_tools` / `profile` support — always the flat generalist.
- No rate limiting.
- `all_tools(db)` is rebuilt per job, re-reading and re-parsing the MCP config each time.

**Fix.** Extract the dispatch from `main.py:382-436` into a shared `app/launcher.py::launch_run(...)`
that both the API and the worker call with identical wiring, and build the tool map once at worker
startup. This is a prerequisite for **R1**.

---

### C14 — Startup does the database work twice, at import time  *(Low)*

`main.py:119` executes `audit = _make_audit()` **at module import**, and `_make_audit` (`main.py:108-116`)
calls `db.migrate()` plus a probe connection. `_startup` (`main.py:122-137`) then calls `db.migrate()`
again. Consequences: migrations race if two processes import simultaneously; and with Postgres down, the
import blocks for the full `pool.open(timeout=5)` before uvicorn even binds a port.

**Fix.** Move sink construction into `_startup`, use a module-level mutable holder, and rely on a single
`migrate()` call guarded by a Postgres advisory lock:

```sql
SELECT pg_advisory_xact_lock(hashtext('pinkeye.migrate'));
```

taken at the top of `Database.migrate`'s transaction, so concurrent api/worker replicas serialize instead
of racing on `schema_migrations`.

---

### C15 — `select_tools` grants everything when a selection matches nothing  *(Low)*

`toolset.py:43-55` — a non-empty `enabled_tools` that matches no registered tool falls back to the full
tool list. The docstring calls this out ("so a run is never silently toolless"), but the failure mode is
the wrong direction: an operator who deselects everything except a renamed tool gets the *entire* library,
including gated offensive tools (which then depend solely on the scope flags). Deny-by-default is the
house rule everywhere else in this codebase.

**Fix.** Return the empty selection and reject at the API boundary with a clear 400:

```python
planner_tools = select_tools(list(TOOLS.values()), body.enabled_tools)
if body.enabled_tools and not planner_tools:
    raise HTTPException(400, f"none of the requested tools exist: {body.enabled_tools}")
```

---

## 3. Security caveats

### S1 — Only 3 of 21 endpoints are authenticated  *(Critical)*

`Depends(require(...))` appears on exactly three routes: `POST /engagements` (`main.py:260`),
`POST /engagements/{id}/sast/upload` (`main.py:303`), and `POST /engagements/{id}/runs`
(`main.py:363`). Unauthenticated and unauthorized:

- `GET /engagements`, `/engagements/{id}` — full signed scopes, including `signature`
- `GET /engagements/{id}/findings`, `/entities`, `/metrics`, `/memory`, `/changes`, `/chains`, `/report`
- `GET /map`, `/engagements/{id}/graph`, `POST /engagements/{id}/graph/query`
- `GET /runs/{id}`, `/runs/{id}/transcript`, `/runs/{id}/events`
- `POST /runs/{id}/reply`, `POST /engagements/{id}/validate`
- `GET /cve`, `/tools`, `/profiles`

**Root cause.** RBAC was built (`auth.py` is complete and correct) but only applied to the write paths
that were being demoed. The `viewer` role in `ROLE_RANK` (`auth.py:12`) has no route that uses it.

**Fix.** Apply it at the router level so new endpoints are secure by default:

```python
app = FastAPI(title="Pinkeye — Control Plane",
              dependencies=[Depends(require("viewer"))])
```

then exempt only `/health` with an explicit `dependencies=[]` on the route. Keep `require("operator")` on
the three write routes and add it to `/validate` and `/runs/{id}/reply` (**S2**).

Note this is only meaningful once `EYE_API_KEYS` is set — `Authenticator.open_dev_mode`
(`auth.py:46-51`) returns a `default`-tenant **admin** for any request when the variable is empty, and
`deploy/docker-compose.yml` never sets it. Add a startup guard:

```python
if authenticator.open_dev_mode and os.getenv("EYE_ENV") == "production":
    raise RuntimeError("EYE_API_KEYS must be set outside development")
```

---

### S2 — Unauthenticated `/reply` can approve intrusive exploitation  *(Critical)*

`POST /runs/{run_id}/reply` (`main.py:469-479`) has no auth dependency. It calls
`run_inbox.deliver(run_id, text)`, which unblocks `_ask_user` (`agent.py:340`) and returns the text to the
model as `f"Operator replied: {reply}"`.

**Root cause.** The docstring correctly argues the reply "can never widen scope" — true, the signed scope
and `requires_flag` gate still bound *what* may run. But the `ask_user(kind="permission")` handshake is
the system's designated human-in-the-loop control for intrusive steps: `DEFAULT_MISSION`
(`agent.py:29-33`), `ORCHESTRATOR_MISSION` (`agent.py:51-53`), `_EXPLOIT_MISSION`
(`subagents.py:70-73`) and `_CREDENTIALS_MISSION` (`subagents.py:80-83`) all require it before exploit,
post_exploit, or credential_attack. So for an engagement whose scope *does* carry `allow_exploit`, an
unauthenticated `POST /runs/{id}/reply {"text": "approved, proceed"}` supplies the only approval
standing between the agent and firing exploits at in-scope hosts. Run ids are UUIDs, but they are handed
out by `POST /runs` and echoed in every transcript event.

**Fix.** `principal: Principal = Depends(require("operator"))`, and record the reply in the audit log
with the approving principal — an approval for an intrusive action belongs in the same defensible record
as the scope decisions it authorizes:

```python
audit.append(AuditEvent(
    engagement_id=..., run_id=run_id, type=EventType.scope_decision,
    tool="ask_user", target="operator_reply", allowed=True,
    detail=f"operator {principal.tenant_id}/{principal.role} replied to run {run_id}"))
```

---

### S3 — Wide-open CORS  *(High, in combination with S1)*

`main.py:56-58`: `allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]`. Because the read
endpoints need no credentials at all (**S1**), any web page a user visits can read the full findings,
graph, transcripts, and signed scopes from a reachable Pinkeye instance, and can `POST /runs/{id}/reply`.

**Fix.** Drive the allowlist from configuration:

```python
origins = [o.strip() for o in os.getenv("EYE_CORS_ORIGINS", "http://localhost:3000").split(",") if o.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins,
                   allow_methods=["GET", "POST"], allow_headers=["X-API-Key", "Content-Type"])
```

---

### S4 — Tenant isolation is declared but never enforced  *(High)*

`build_findings_query` supports `tenant_id` (`query.py:26-37`) — no caller passes it. `EngagementRepo.get`
and `.list` never filter by tenant (`repositories.py:30-45`). `MetricsRepo`, `ServiceRepo.search`,
`GraphClient` — none are tenant-aware. Any principal, of any tenant, reads every other tenant's data by
engagement id. Combined with **C11** (tenant columns never written), tenancy is currently
presentation-only.

**Fix.** Write `tenant_id` on every insert (**C11**), then thread `principal.tenant_id` through every repo
read. Enforce it in the database as well with Postgres row-level security so an omitted `WHERE` clause
fails closed rather than leaking.

---

### S5 — Egress policy is computed but not enforced  *(Medium — known, worth restating)*

`orchestrator.py:103` builds an `EgressPolicy` from the scope for every network tool, and
`sandbox.py:71-83` documents that enforcement is delegated to `EYE_EGRESS_ENFORCER` — which
`docker-compose.yml` does not set. So `_apply_egress` returns immediately and every sandbox container runs
with unrestricted `network_mode="bridge"` egress. The scope guard remains the real control, but the
documented defense-in-depth layer is inert in the shipped configuration.

**Fix.** Either ship a reference enforcer script and wire it in compose, or fail loudly at startup when a
scope carries `allow_exploit`/`allow_credential_attacks` and no enforcer is configured — so the gap is a
deliberate operator decision rather than a silent default.

---

### S6 — Insecure defaults in the shipped configuration  *(Medium)*

- `EYE_SCOPE_SIGNING_KEY: dev-insecure-signing-key` is hardcoded in `docker-compose.yml:31` and defaulted
  in `config.py:15`. Anyone who knows it can forge a scope with arbitrary CIDRs and both offensive flags —
  which defeats the guard entirely, since `_signature_valid` (`scope.py:40`) is the *only* thing standing
  between a `Scope` object and authorization.
- Neo4j credentials are hardcoded in compose (`neo4j/eye-dev-password`).
- `EYE_API_KEYS` is unset → open dev-mode admin (**S1**).

**Fix.** Refuse to start with the default signing key unless `EYE_ENV=development`:

```python
if settings.scope_signing_key == "dev-insecure-signing-key" and os.getenv("EYE_ENV") != "development":
    raise RuntimeError("EYE_SCOPE_SIGNING_KEY must be set to a real secret")
```

and move all three to `deploy/.env` with generated values.

---

### S7 — Docker socket mounted into the API and worker  *(Medium — documented trade-off)*

`docker-compose.yml` mounts `/var/run/docker.sock` into both `api` and `worker`. This is root-equivalent
on the host: any RCE in the API process — including through the LLM-driven tool path — becomes host root.
The compose comment acknowledges this as a Phase 1 trade-off with a brokered rootless runner planned.

Worth restating here because **S1** materially raises its likelihood: an unauthenticated API surface plus
a socket mount means the blast radius of any API-level bug is the whole host. Prioritize **S1** before
shipping anywhere reachable.

---

## 4. Resource leaks (unbounded process-lifetime growth)

Every one of these is a `dict` that only ever grows, in a process designed to run for weeks:

| Structure | Location | Keyed by | Bound |
|---|---|---|---|
| `Store.engagements`, `Store.runs` | `store.py:13-14` | engagement/run | none |
| `RunEventStore._buffers` | `events.py:128` | run | 4 000 events *per run*, unbounded run count |
| `RunEventStore._seq` | `events.py:127` | run | none |
| `RunInbox._queues` | `events.py:74` | run | none |
| `NetworkMemory._state` | `memory.py:66` | engagement (all devices + services) | none |
| `NetworkMemory._run_deltas` | `memory.py:69` | run | none |
| `RateLimiter._buckets` | `ratelimit.py:23` | tenant | bounded by tenant count (acceptable) |
| `exploit._SESSIONS` | `exploit.py:67` | (engagement, host) | none |

A long-lived API accumulates every run it has ever seen. The `_buffers` entry alone is up to 4 000
`RunEvent` pydantic models per run.

**Fix.** Add a shared TTL/LRU eviction, driven from the run's terminal status — the code already knows
exactly when a run is over (`RunEvent.is_terminal`, `events.py:55`):

```python
# events.py
_RETAIN_AFTER_TERMINAL = float(os.getenv("EYE_RUN_RETENTION_SECONDS", "3600"))

def emit(self, run_id, engagement_id, kind, /, **data) -> RunEvent:
    ...
    if event.is_terminal():
        self._retire_at[run_id] = time.monotonic() + _RETAIN_AFTER_TERMINAL
    self._evict_expired()
    return event
```

with the same hook dropping `RunInbox._queues[run_id]`, `NetworkMemory._run_deltas[run_id]`, and
`Store.runs[run_id]`. Because the durable copies already exist (`run_events` table for the transcript,
`network_observations` for the deltas — once **C7** is fixed), eviction costs nothing in capability.
`RateLimiter._buckets` should also be swept of buckets that have refilled to `burst`.

`RateLimiter.allow` (`ratelimit.py:25-39`) is additionally not thread-safe — it read-modify-writes
`bucket.tokens` from concurrent request threads. Wrap it in a `threading.Lock`; the critical section is a
few arithmetic operations.

---

## 5. Redundancy and dead code

### R1 — The job queue and worker service are entirely unwired  *(High)*

`JobQueue.enqueue` (`queue.py:19`) has **zero callers** in the codebase. `app/worker.py` polls
`queue.claim()` every 2 seconds forever, and `docker-compose.yml` runs it as a service documented as
"Scale with `docker compose up --scale worker=N`". Meanwhile `create_run` executes runs in-process
(**B1**). The result: a complete, correct, `FOR UPDATE SKIP LOCKED` durable queue, a worker, a `jobs`
table with an index, and a compose service — all doing nothing but burning a poll cycle, while the actual
execution path has none of their benefits (survives restart, horizontal scale, capacity control).

Two divergent implementations of the same operation is also why **C13** exists.

**Fix.** This is the single highest-leverage architectural change, and it resolves **B1** and **C13** with
it:

```python
# main.py, in create_run — replace the in-process launch
job_id = jobs.enqueue(principal.tenant_id, engagement_id, {
    "run_id": run.id, "target": body.target, "tool": body.tool,
    "mode": body.mode, "intensity": body.intensity.value,
    "objective": body.objective, "auth": body.auth,
    "enabled_tools": body.enabled_tools, "profile": profile,
})
```

with `app/launcher.py::launch_run` (from **C13**) shared by both, and the worker wired with the full
`events` / `memory` / `inbox` set. Two changes make it production-ready:

1. **Cross-process events.** `RunEventStore`'s in-memory buffer is per-process, so an API serving SSE for
   a run executing in a worker sees nothing. Fix **C6** (DB fallback in `events_after`) and this works —
   `run_events` is already persisted, keyed, and ordered by `seq`.
2. **Cross-process inbox.** `RunInbox` is an in-process `queue.Queue`. Back it with a table (or Postgres
   `LISTEN/NOTIFY`) so `/reply` reaches a run in another process.

Add a reaper for jobs stuck in `running` past a timeout — nothing currently un-claims a job whose worker
died.

### R2 — `Store` duplicates every repository  *(Medium)*

`store.py` maintains a parallel in-memory copy of engagements and runs, and five call sites
(`main.py:151-166`, `:283-287`, `:374`, `:450`) juggle "try the DB, fall back to memory". This produces
**C4** and **C5**, doubles the write path, and makes tenancy (**S4**) impossible to enforce consistently.

**Fix.** Once Postgres is a hard dependency (it already is for findings, metrics, entities, CVEs — those
endpoints return `503` when it is down, `main.py:559`), delete `Store` and let engagements/runs return
`503` on the same terms. The fallback only masks failures for two of nineteen endpoints.

### R3 — Duplicated event-sink implementations

`MemoryRunEventSink.emit` (`events.py:103-112`) and `RunEventStore.emit` (`events.py:130-143`) build the
same `RunEvent` with the same seq logic. Likewise `MemoryAuditSink` / `PostgresAuditSink`
(`audit.py:48-89`).

**Fix.** Make `RunEventStore(db=None)` the single implementation — it already degrades to pure in-memory
when `db is None`, which is exactly what `MemoryRunEventSink` provides. Delete the latter and update the
tests to `RunEventStore()`.

### R4 — Duplicated `_env_int` / `_env_float` helpers

Four near-identical implementations: `agent.py:106`, `llm/openai_compat.py:11-22`,
`llm/claude.py:20-30` (inline `_f`/`_i`), `llm/config.py:30-40`.

**Fix.** One `runtime/envutil.py` with `env_int(name, default, minimum=1)` and `env_float(...)`.

### R5 — Duplicated Engagement-MERGE fragments in `graph.py`

`MERGE (e:Engagement {id: $eid}) SET e.engagement_id = $eid` plus
`MERGE (e)-[:DISCOVERED]->(...)` appears in `upsert_service` (`:90`, `:95`), `set_device` (`:140-141`),
and `record_finding` (`:226-227`). Any change to engagement linkage must be made in three places
consistently — exactly the kind of drift that made `link_engagement_hosts` (**B13**) necessary.

**Fix.** Extract module-level Cypher fragment constants and compose them.

### R6 — Duplicated scope-matching logic

`scope._target_in_cidrs` (`scope.py:48-60`) and `EgressPolicy.allows_ip` (`egress.py:28-39`) are the same
function. `scope._domain_in_scope` (`scope.py:92-99`) and `EgressPolicy.allows_host` (`egress.py:41-43`)
are the same function with slightly different normalization (`lstrip("*.")` in both, `rstrip(".")` in one).

**Fix.** Move both matchers into `app/matching.py` and have `scope.py` and `egress.py` import them. This
is security-relevant: a divergence between the guard's notion of "in scope" and the egress policy's is
a silent gap in defense-in-depth.

### R7 — `validation.MetasploitClient` is a dead stub

`validation.py:27-44` defines a gated Metasploit client with `check`/`exploit` — never instantiated
anywhere. The real implementation is `runtime/msf.py::MetasploitRpc` plus
`runtime/exploit.py::MetasploitExploitTool`, with its own gating (`resolve_action`, `exploit.py:41`).

**Fix.** Delete it. Keep `should_confirm` and `CONFIRM_MIN_CONFIDENCE`, which *are* used
(`repositories.py:141`).

### R8 — `_delta_events` duck-types a type it owns

`agent.py:432-452` handles `delta` as either a dict or a `MemoryDelta` for every one of four buckets:

```python
("added", delta.get("added") if isinstance(delta, dict) else getattr(delta, "added", [])),
```

The only producer is `NetworkMemory.observe` (`memory.py:181`), which always returns a `MemoryDelta` —
which already has `to_dict()` (`memory.py:40`).

**Fix.** Normalize once at the boundary: `d = delta if isinstance(delta, dict) else delta.to_dict()`, then
iterate `d.items()`.

### R9 — Unused graph schema

`graph/schema.cypher:15-16` constrains `(:Domain {engagement_id, name})`. No code path creates a `Domain`
node — hostnames become `IP` or `Endpoint` nodes. Either wire domain topology in (`_target_host` already
distinguishes hostnames from IPs, `scope.py:63`) or drop the constraint.

### R10 — `all_tools()` rebuilt per job

`worker.py:35` calls `all_tools(db)` inside `_handle`, so every job re-instantiates 14 tool objects and
re-parses `EYE_MCP_SERVERS` through `wrap_tools_with_mcp` → `load_mcp_config` (`mcp/config.py:78`).
`main.py:71` correctly does this once at import.

**Fix.** Hoist to `main()` in the worker and pass the map into `_handle`.

---

## 6. Suggested sequencing

**Phase 1 — Security (do before any reachable deployment).**
S1 (router-level auth), S2 (`/reply` + audit), C3 (scope `graph/query`), S3 (CORS), S6 (fail on default
secrets). All are small, localized, and independently shippable.

**Phase 2 — Correctness.**
C1 (finding state demotion), C2 (deterministic chain ids + move the write off GET), C4/C5 (consistent
response shapes), C7 (read `network_observations`), C9, C10, C12.

**Phase 3 — Throughput.**
B6 + B5 (graph indexes and labelled queries — hours of work, largest ratio), B3 (pool size + race),
B2 (batch the write path), B1 (dedicated run executor), B4 (event-driven SSE), B11 (search indexes).

**Phase 4 — Architecture.**
R1 (wire the job queue, with C13's shared launcher, C6's DB-backed tail, and a durable inbox), §4
(eviction), B7 (context management), then the R2–R10 cleanups.

**Suggested measurements before/after.** No profiling data was gathered for this review — the analysis is
static. Worth capturing first, so the Phase 3 work is verified rather than assumed:

- `EXPLAIN` on `get_graph` for both variants, before and after B5/B6;
- wall-clock of one `execute_tool_step` against a captured `nmap -p-` XML fixture, before and after B2;
- `pg_stat_activity` connection-wait counts under 4 concurrent runs, before and after B3;
- API `p99` for `GET /health` while 8 agent runs are in flight, before and after B1.
