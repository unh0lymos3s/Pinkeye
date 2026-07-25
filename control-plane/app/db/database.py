"""Postgres access and migration runner.

The connection pool opens lazily so importing the app (and running tests) doesn't require a live
database. Callers that need durability use `connection()`; if Postgres is unreachable the call
raises and the API layer falls back to its in-memory cache.
"""
from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from pathlib import Path

from ..envknobs import env_int

MIGRATIONS_DIR = Path(__file__).parent / "migrations"

# Transaction-scoped advisory lock serializing the migration check-and-apply across processes
# (C14). hashtext() folds the name into the bigint the lock API takes; the name is a literal, so
# nothing caller-controlled reaches this statement.
_MIGRATE_LOCK = "SELECT pg_advisory_xact_lock(hashtext('pinkeye.migrate'))"


class Database:
    def __init__(self, dsn: str):
        self._dsn = dsn
        self._pool = None
        # Guards lazy pool construction. Without it two threads can each build (and open) a pool;
        # one is then orphaned but never closed, permanently leaking its connections and its
        # background worker thread.
        self._lock = threading.Lock()
        # Negative cache for a failed open. Without it every caller re-pays the full connect timeout
        # while Postgres is down — and since a failed `open()` leaves `_pool` unset, each attempt also
        # built and abandoned a ConnectionPool complete with its background worker threads.
        self._open_error: Exception | None = None
        self._open_failed_at = 0.0

    def _get_pool(self):
        pool = self._pool
        if pool is not None:
            return pool
        with self._lock:
            # Double-checked: another thread may have built the pool while we waited for the lock.
            if self._pool is not None:
                return self._pool

            # Still inside the back-off window from a recent failure: fail immediately rather than
            # serializing every caller behind another connect timeout. The contract is unchanged —
            # `connection()` still raises so the API layer falls back to its in-memory cache.
            retry_after = env_int("EYE_PG_RETRY_SECONDS", 10, minimum=0)
            if self._open_error is not None and time.monotonic() - self._open_failed_at < retry_after:
                raise self._open_error

            from psycopg_pool import ConnectionPool

            min_size = env_int("EYE_PG_POOL_MIN", 2, minimum=0)
            max_size = max(min_size, env_int("EYE_PG_POOL_MAX", 32, minimum=1))
            # open=False + explicit open lets us bound the connect wait instead of blocking
            # forever. Size max_size to at least EYE_MAX_CONCURRENT_RUNS + EYE_API_THREADS/4,
            # and keep the total across api+worker replicas under Postgres max_connections.
            pool = ConnectionPool(self._dsn, min_size=min_size, max_size=max_size, open=False)
            try:
                pool.open(wait=True, timeout=5)
            except Exception as exc:
                # Close the half-built pool before discarding it, or its workers outlive every
                # failed attempt.
                try:
                    pool.close()
                except Exception:
                    pass
                self._open_error, self._open_failed_at = exc, time.monotonic()
                raise
            self._pool = pool
            self._open_error, self._open_failed_at = None, 0.0
            return self._pool

    @contextmanager
    def connection(self):
        with self._get_pool().connection() as conn:
            yield conn

    def migrate(self, migrations_dir: Path | None = None) -> list[str]:
        """Apply any migration files not yet recorded, in filename order. Returns applied versions.

        migrate() has several callers — app.main at import time and again in _startup, app.worker at
        its own startup — and api/worker replicas can boot simultaneously, so the check-and-apply has
        to be serialized across processes: otherwise two callers both read schema_migrations, both
        miss the same version, and both run its DDL. `pg_advisory_xact_lock` does that; being
        transaction-scoped it is released automatically at COMMIT or ROLLBACK, so a migrator that
        crashes mid-flight cannot wedge every other replica the way a session lock would.

        Structure matters here. The lock has to be held *inside* the transaction that both reads
        schema_migrations and writes the version row, or the window between the two is exactly the
        race we are closing. So each pending migration gets its own transaction which (a) takes the
        lock, (b) re-reads schema_migrations for that one version — the batch pre-read below is only a
        fast path, so a warm start never takes the lock at all — and (c) applies the DDL and records
        the version. Per-migration transactions also mean a migration that fails rolls back only
        itself: everything applied before it stays committed, and the exception still propagates so
        the caller does not mistake a partial migration for a complete one.
        """
        migrations_dir = migrations_dir or MIGRATIONS_DIR
        applied: list[str] = []
        with self.connection() as conn:
            # The tracking table itself is created under the lock: concurrent
            # CREATE TABLE IF NOT EXISTS can still collide on the system catalogs.
            with conn.transaction():
                conn.execute(_MIGRATE_LOCK)
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS schema_migrations "
                    "(version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
                )
                done = {
                    r[0] for r in conn.execute("SELECT version FROM schema_migrations").fetchall()
                }
            for path in sorted(migrations_dir.glob("*.sql")):
                version = path.name
                if version in done:
                    continue  # fast path: no lock, no round trip
                sql = path.read_text()
                with conn.transaction():
                    conn.execute(_MIGRATE_LOCK)
                    # Re-checked under the lock. A racing replica that applied this version while we
                    # waited has committed its row by now, so we see it and skip instead of
                    # re-running the DDL.
                    if conn.execute(
                        "SELECT 1 FROM schema_migrations WHERE version = %s", (version,)
                    ).fetchone():
                        continue
                    conn.execute(sql)
                    conn.execute("INSERT INTO schema_migrations (version) VALUES (%s)", (version,))
                applied.append(version)
        return applied
