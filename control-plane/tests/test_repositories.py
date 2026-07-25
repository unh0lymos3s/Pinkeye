"""Data-layer tests that need no live Postgres.

The repos and the migration runner are thin enough that the interesting behaviour is *which*
statements get issued, in what transaction, and whether a connection is borrowed at all. A fake
connection that records SQL exercises exactly that, so these run in CI without a database.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone

import pytest

from app.db.database import Database
from app.models import Finding, Run, RunStatus, Severity
from app.repositories import (
    _UPSERT_FINDING_SQL,
    LIST_PAGE_SIZE,
    FindingRepo,
    PersistenceSink,
    RunRepo,
    ServiceRepo,
)


class FakeCursor:
    def __init__(self, conn):
        self._conn = conn

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def executemany(self, sql, rows):
        self._conn.executemany_calls.append((sql, list(rows)))


class FakeConn:
    """Records every statement, and the transaction nesting depth it was issued at."""

    def __init__(self, results=None):
        self.calls: list[tuple[str, object, int]] = []
        self.executemany_calls: list[tuple[str, list]] = []
        self.tx_depth = 0
        self.tx_opened = 0
        # sql-substring -> list of rows to hand back, popped in order
        self._results = results or {}

    def execute(self, sql, params=None):
        self.calls.append((sql, params, self.tx_depth))
        for needle, queue in self._results.items():
            if needle in sql:
                self._row = queue.pop(0) if queue else None
                break
        else:
            self._row = None
        return self

    def fetchone(self):
        return self._row

    def fetchall(self):
        return self._row or []

    def cursor(self):
        return FakeCursor(self)

    @contextmanager
    def transaction(self):
        self.tx_depth += 1
        self.tx_opened += 1
        try:
            yield self
        finally:
            self.tx_depth -= 1

    def sql(self) -> list[str]:
        return [c[0] for c in self.calls]


class FakeDb:
    def __init__(self, conn=None):
        self.conn = conn or FakeConn()
        self.borrowed = 0

    @contextmanager
    def connection(self):
        self.borrowed += 1
        yield self.conn


# ---- C1: the finding upsert must never demote a triaged state ----

def test_finding_upsert_never_demotes_state():
    sql = " ".join(_UPSERT_FINDING_SQL.split())
    # The bug this replaced was a bare `state = EXCLUDED.state`, which reset every /validate
    # promotion on the next re-observation.
    assert "state = EXCLUDED.state" not in sql
    assert "WHEN findings.state = 'false_positive' THEN 'false_positive'" in sql
    assert "WHEN findings.state = 'confirmed' THEN 'confirmed'" in sql


def test_finding_upsert_refreshes_descriptive_fields():
    sql = " ".join(_UPSERT_FINDING_SQL.split())
    # A rescan that raises severity, retitles, or adds evidence must not be thrown away.
    for clause in ("severity = EXCLUDED.severity", "title = EXCLUDED.title",
                   "evidence = EXCLUDED.evidence", "cvss_score = EXCLUDED.cvss_score"):
        assert clause in sql
    # ...but classification that an earlier tool supplied is only ever added to, never cleared.
    assert "cvss_vector = COALESCE(EXCLUDED.cvss_vector, findings.cvss_vector)" in sql
    assert "cwe = COALESCE(EXCLUDED.cwe, findings.cwe)" in sql
    # cve participates in dedup_key, so an existing value can never be the wrong one.
    assert "cve = COALESCE(findings.cve, EXCLUDED.cve)" in sql


def test_finding_upsert_binds_tenant_id():
    db = FakeDb()
    f = Finding(id="f1", engagement_id="e1", run_id="r1", title="t", category="open-port",
                severity=Severity.high, target="10.0.0.1")
    FindingRepo(db).upsert(f, tenant_id="acme")
    sql, params, _ = db.conn.calls[0]
    assert "INSERT INTO findings" in sql
    assert params[-1] == "acme"  # tenant_id is the last bound column


# ---- bulk write contracts: one round trip, and empty-list safe ----

def _finding(n: int) -> Finding:
    return Finding(id=f"f{n}", engagement_id="e1", run_id="r1", title=f"t{n}",
                   category="open-port", target=f"10.0.0.{n}")


def test_upsert_many_is_one_executemany():
    db = FakeDb()
    assert FindingRepo(db).upsert_many([_finding(1), _finding(2)], "acme") == 2
    assert db.borrowed == 1
    assert len(db.conn.executemany_calls) == 1
    sent_sql, rows = db.conn.executemany_calls[0]
    assert sent_sql == _UPSERT_FINDING_SQL  # identical ON CONFLICT semantics to upsert()
    assert len(rows) == 2
    assert all(r[-1] == "acme" for r in rows)


def test_service_upsert_many_is_one_executemany():
    db = FakeDb()
    rows = [("10.0.0.1", 22, "tcp", "ssh", "OpenSSH"), ("10.0.0.1", 80, "tcp", "http", "nginx")]
    assert ServiceRepo(db).upsert_many("e1", rows, "acme") == 2
    assert db.borrowed == 1
    _, sent = db.conn.executemany_calls[0]
    assert sent[0] == ("e1", "10.0.0.1", 22, "tcp", "ssh", "OpenSSH", "acme")


def test_service_upsert_many_tolerates_short_rows():
    # Normalizers that only know address/port/proto must not have to pad.
    db = FakeDb()
    ServiceRepo(db).upsert_many("e1", [("10.0.0.1", 22, "tcp")])
    _, sent = db.conn.executemany_calls[0]
    assert sent[0] == ("e1", "10.0.0.1", 22, "tcp", "", "", "default")


@pytest.mark.parametrize("empty", [[], (), None])
def test_bulk_writes_borrow_no_connection_when_empty(empty):
    db = FakeDb()
    sink = PersistenceSink(db)
    assert sink.record_findings(empty) == 0
    assert sink.upsert_services("e1", empty) == 0
    assert FindingRepo(db).upsert_many(empty) == 0
    assert ServiceRepo(db).upsert_many("e1", empty) == 0
    assert db.borrowed == 0


def test_tenant_scoped_sink_ignores_a_caller_supplied_tenant():
    # A run cannot write outside the tenant it was launched for, whatever gets passed down.
    db = FakeDb()
    scoped = PersistenceSink(db).for_tenant("acme")
    scoped.record_findings([_finding(1)], tenant_id="attacker")
    _, rows = db.conn.executemany_calls[0]
    assert rows[0][-1] == "acme"


# ---- C8: aggregate reads page past the 1000-row clamp, but stay bounded ----

class PagingFindingRepo(FindingRepo):
    """FindingRepo with `query` stubbed, so paging can be tested without SQL."""

    def __init__(self, total: int):
        self.total = total
        self.pages: list[tuple[int, int]] = []

    def query(self, engagement_id, filters, tenant_id=None):
        self.pages.append((filters.limit, filters.offset))
        rows = []
        for i in range(filters.offset, min(filters.offset + filters.limit, self.total)):
            rows.append({
                "id": f"f{i}", "engagement_id": engagement_id, "run_id": "r1",
                "title": f"t{i}", "category": "open-port", "severity": "info",
                "state": "suspected", "confidence": 0.5, "target": f"10.0.0.{i}",
                "cwe": None, "cve": None, "cvss_score": 0.0, "cvss_vector": None,
                "attack_technique": None, "attack_technique_name": None,
                "evidence": None, "source_tool": None,
            })
        return rows


def test_list_findings_default_keeps_the_single_query_clamp():
    repo = PagingFindingRepo(total=2500)
    out = repo.list_findings("e1")
    assert len(out) == 1000  # historical, caller-facing behaviour is unchanged
    assert repo.pages == [(1000, 0)]


def test_list_findings_all_pages_past_the_clamp():
    repo = PagingFindingRepo(total=2500)
    out = repo.list_findings("e1", all=True)
    assert len(out) == 2500
    assert [f.id for f in out[:2]] == ["f0", "f1"]
    assert repo.pages == [(1000, 0), (1000, 1000), (1000, 2000)]


def test_iter_findings_stops_on_a_short_page_without_an_extra_query():
    repo = PagingFindingRepo(total=1500)
    assert len(list(repo.iter_findings("e1"))) == 1500
    assert repo.pages == [(1000, 0), (1000, 1000)]


def test_iter_findings_stops_on_an_exact_multiple():
    repo = PagingFindingRepo(total=1000)
    assert len(list(repo.iter_findings("e1"))) == 1000
    # A full page means "maybe more", so one extra probe is expected and must come back empty.
    assert repo.pages == [(1000, 0), (1000, 1000)]


def test_iter_findings_honours_the_absolute_ceiling():
    # Paging must not turn a silent truncation into unbounded memory growth.
    repo = PagingFindingRepo(total=10_000)
    out = list(repo.iter_findings("e1", max_rows=2500))
    assert len(out) == 2500
    # The final page is narrowed so the ceiling is never overshot.
    assert repo.pages == [(1000, 0), (1000, 1000), (500, 2000)]


def test_iter_findings_page_size_cannot_exceed_the_query_clamp():
    repo = PagingFindingRepo(total=10)
    list(repo.iter_findings("e1", page=99_999))
    assert repo.pages[0][0] == LIST_PAGE_SIZE


def test_iter_findings_on_an_empty_engagement():
    repo = PagingFindingRepo(total=0)
    assert list(repo.iter_findings("e1")) == []
    assert repo.pages == [(1000, 0)]


# ---- C5: RunRepo.get answers with a typed model, updated_at included ----

def test_run_get_returns_a_run_model_with_updated_at():
    created = datetime(2026, 1, 1, tzinfo=timezone.utc)
    updated = datetime(2026, 1, 2, tzinfo=timezone.utc)
    db = FakeDb(FakeConn({"FROM runs": [("r1", "e1", "10.0.0.1", "running", created, updated)]}))
    run = RunRepo(db).get("r1")
    assert isinstance(run, Run)  # the in-memory fallback's type, so one endpoint shape
    assert run.status is RunStatus.running
    assert run.updated_at == updated
    # The extra field survives serialization, so /runs/{id} can expose it from either branch.
    assert run.model_dump(mode="json")["updated_at"].startswith("2026-01-02T00:00:00")


def test_run_get_returns_none_for_unknown_run():
    assert RunRepo(FakeDb()).get("nope") is None


def test_run_save_writes_tool_intensity_and_tenant():
    db = FakeDb()
    run = Run(id="r1", engagement_id="e1", target="10.0.0.1")
    RunRepo(db).save(run, tenant_id="acme", tool="nmap", intensity="normal")
    sql, params, _ = db.conn.calls[0]
    assert "INSERT INTO runs" in sql
    assert "nmap" in params and "normal" in params and params[-1] == "acme"


# ---- B11b: kpis in two round trips, with the dict shape the UI and generate_report expect ----

def _kpi_conn(counts, finding_rows):
    return FakeConn({"count(DISTINCT address)": [counts], "ROLLUP": [finding_rows]})


def test_kpis_shape_is_unchanged_and_takes_two_queries():
    from app.repositories import MetricsRepo

    conn = _kpi_conn(
        (3, 7, 2),  # hosts, exposed_endpoints, runs
        [("critical", 2, None, None), ("high", 4, None, None), (None, 6, 5, 3)],
    )
    db = FakeDb(conn)
    out = MetricsRepo(db).kpis("e1")

    assert out == {
        "hosts": 3,
        "exposed_endpoints": 7,
        "cves_identified": 3,
        "open_issues": 5,
        "findings_by_severity": {"critical": 2, "high": 4},
        "runs": 2,
    }
    # One borrowed connection, two statements — not the six sequential queries this replaced.
    assert db.borrowed == 1
    assert len(conn.calls) == 2
    # The ROLLUP total row must not leak into the severity histogram.
    assert None not in out["findings_by_severity"]


def test_kpis_on_an_empty_engagement():
    from app.repositories import MetricsRepo

    # ROLLUP still yields its grand-total row when there are no findings at all.
    out = MetricsRepo(FakeDb(_kpi_conn((0, 0, 0), [(None, 0, 0, 0)]))).kpis("e1")
    assert out["findings_by_severity"] == {}
    assert out["open_issues"] == 0 and out["cves_identified"] == 0


# ---- audit sinks: batched append, append-only ----

def test_postgres_audit_append_many_is_one_executemany():
    from app.audit import AuditEvent, EventType, PostgresAuditSink

    db = FakeDb()
    events = [
        AuditEvent(engagement_id="e1", run_id="r1", type=EventType.tool_started, tool="nmap"),
        AuditEvent(engagement_id="e1", run_id="r1", type=EventType.tool_finished, tool="nmap"),
    ]
    PostgresAuditSink(db).append_many(events)
    assert db.borrowed == 1
    sql, rows = db.conn.executemany_calls[0]
    assert "INSERT INTO audit_events" in sql
    assert len(rows) == 2
    # Append-only: the batched path must not introduce an UPDATE or an ON CONFLICT.
    assert "UPDATE" not in sql.upper() and "ON CONFLICT" not in sql.upper()


@pytest.mark.parametrize("empty", [[], (), None])
def test_audit_append_many_is_empty_safe(empty):
    from app.audit import MemoryAuditSink, PostgresAuditSink

    db = FakeDb()
    PostgresAuditSink(db).append_many(empty)
    assert db.borrowed == 0

    mem = MemoryAuditSink()
    mem.append_many(empty)
    assert mem.events == []


def test_memory_and_postgres_sinks_both_satisfy_the_protocol():
    from app.audit import MemoryAuditSink, PostgresAuditSink

    for sink in (MemoryAuditSink(), PostgresAuditSink(FakeDb())):
        assert callable(getattr(sink, "append"))
        assert callable(getattr(sink, "append_many"))


# ---- C14: migrate() serializes its check-and-apply under an advisory lock ----

LOCK = "pg_advisory_xact_lock(hashtext('pinkeye.migrate'))"


def _migrations(tmp_path, names):
    for name in names:
        (tmp_path / name).write_text(f"-- {name}\nSELECT 1;\n")
    return tmp_path


def test_migrate_takes_the_lock_before_reading_schema_migrations(tmp_path):
    conn = FakeConn({"SELECT version FROM schema_migrations": [[]]})
    db = Database("postgresql:///unused")
    db.connection = FakeDb(conn).connection  # type: ignore[method-assign]

    applied = db.migrate(_migrations(tmp_path, ["0001_a.sql", "0002_b.sql"]))

    assert applied == ["0001_a.sql", "0002_b.sql"]
    statements = conn.sql()
    assert LOCK in statements[0], "the lock must precede the tracking-table DDL and the read"
    assert "CREATE TABLE IF NOT EXISTS schema_migrations" in statements[1]
    # Every statement runs inside a transaction — nothing leaks into an implicit one.
    assert all(depth >= 1 for _, _, depth in conn.calls)


def test_migrate_relocks_and_rechecks_each_pending_migration(tmp_path):
    conn = FakeConn({
        "SELECT version FROM schema_migrations": [[]],
        "SELECT 1 FROM schema_migrations WHERE version": [None],
    })
    db = Database("postgresql:///unused")
    db.connection = FakeDb(conn).connection  # type: ignore[method-assign]

    db.migrate(_migrations(tmp_path, ["0001_a.sql"]))

    statements = conn.sql()
    # Two lock acquisitions: one for the tracking table, one for the single pending migration.
    assert statements.count(next(s for s in statements if LOCK in s)) == 2
    # statements[0:3] are the first transaction (lock, tracking DDL, batch pre-read).
    apply_tx = statements[3:]
    assert LOCK in apply_tx[0]
    assert "SELECT 1 FROM schema_migrations WHERE version" in apply_tx[1]
    assert "INSERT INTO schema_migrations" in apply_tx[-1]
    # Separate transactions, so a later failure cannot roll back an earlier success.
    assert conn.tx_opened == 2


def test_migrate_skips_a_version_a_racing_replica_committed(tmp_path):
    # Pre-read saw nothing pending; by the time we hold the lock, another replica has applied it.
    conn = FakeConn({
        "SELECT version FROM schema_migrations": [[]],
        "SELECT 1 FROM schema_migrations WHERE version": [(1,)],
    })
    db = Database("postgresql:///unused")
    db.connection = FakeDb(conn).connection  # type: ignore[method-assign]

    assert db.migrate(_migrations(tmp_path, ["0001_a.sql"])) == []
    assert not any("INSERT INTO schema_migrations" in s for s in conn.sql())


def test_migrate_skips_recorded_versions_without_taking_the_lock(tmp_path):
    conn = FakeConn({"SELECT version FROM schema_migrations": [[("0001_a.sql",)]]})
    db = Database("postgresql:///unused")
    db.connection = FakeDb(conn).connection  # type: ignore[method-assign]

    assert db.migrate(_migrations(tmp_path, ["0001_a.sql"])) == []
    # Only the tracking-table transaction ran: a warm start costs one round trip, not N locks.
    assert conn.tx_opened == 1


def test_migrate_is_ordered_by_filename(tmp_path):
    conn = FakeConn({
        "SELECT version FROM schema_migrations": [[]],
        "SELECT 1 FROM schema_migrations WHERE version": [None, None, None],
    })
    db = Database("postgresql:///unused")
    db.connection = FakeDb(conn).connection  # type: ignore[method-assign]

    applied = db.migrate(_migrations(tmp_path, ["0010_c.sql", "0002_b.sql", "0001_a.sql"]))
    assert applied == ["0001_a.sql", "0002_b.sql", "0010_c.sql"]


# ---- B3: pool sizing is configurable and the lazy init is guarded ----

def test_pool_sizing_reads_env(monkeypatch):
    from app.db import database as dbmod

    monkeypatch.setenv("EYE_PG_POOL_MIN", "3")
    monkeypatch.setenv("EYE_PG_POOL_MAX", "40")
    assert dbmod.env_int("EYE_PG_POOL_MIN", 2, minimum=0) == 3
    assert dbmod.env_int("EYE_PG_POOL_MAX", 32) == 40
    monkeypatch.setenv("EYE_PG_POOL_MAX", "not-a-number")
    assert dbmod.env_int("EYE_PG_POOL_MAX", 32) == 32


def test_get_pool_is_guarded_by_a_lock():
    db = Database("postgresql:///unused")
    import threading

    assert isinstance(db._lock, type(threading.Lock()))
    # Fast path returns the cached pool without acquiring the lock at all.
    sentinel = object()
    db._pool = sentinel
    assert db._get_pool() is sentinel
