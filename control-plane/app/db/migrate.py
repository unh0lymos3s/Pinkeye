"""CLI migration tool: `python -m app.db.migrate` applies pending migrations."""
from __future__ import annotations

from ..config import settings
from .database import Database


def main() -> None:
    db = Database(settings.postgres_dsn)
    applied = db.migrate()
    if applied:
        print("applied migrations:", ", ".join(applied))
    else:
        print("no pending migrations")


if __name__ == "__main__":
    main()
