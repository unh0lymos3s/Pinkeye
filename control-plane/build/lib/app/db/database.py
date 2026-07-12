"""Postgres access and migration runner.

The connection pool opens lazily so importing the app (and running tests) doesn't require a live
database. Callers that need durability use `connection()`; if Postgres is unreachable the call
raises and the API layer falls back to its in-memory cache.
"""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


class Database:
    def __init__(self, dsn: str):
        self._dsn = dsn
        self._pool = None

    def _get_pool(self):
        if self._pool is None:
            from psycopg_pool import ConnectionPool

            # open=False + explicit open lets us bound the connect wait instead of blocking forever.
            pool = ConnectionPool(self._dsn, min_size=1, max_size=8, open=False)
            pool.open(wait=True, timeout=5)
            self._pool = pool
        return self._pool

    @contextmanager
    def connection(self):
        with self._get_pool().connection() as conn:
            yield conn

    def migrate(self, migrations_dir: Path | None = None) -> list[str]:
        """Apply any migration files not yet recorded, in filename order. Returns applied versions."""
        migrations_dir = migrations_dir or MIGRATIONS_DIR
        applied: list[str] = []
        with self.connection() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations "
                "(version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
            )
            done = {r[0] for r in conn.execute("SELECT version FROM schema_migrations").fetchall()}
            for path in sorted(migrations_dir.glob("*.sql")):
                version = path.name
                if version in done:
                    continue
                # Each migration runs in its own transaction; a failure rolls back cleanly.
                with conn.transaction():
                    conn.execute(path.read_text())
                    conn.execute("INSERT INTO schema_migrations (version) VALUES (%s)", (version,))
                applied.append(version)
        return applied
