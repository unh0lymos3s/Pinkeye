"""Seed the local CVE database: `python -m app.cve_seed [path.json]`.

Defaults to the bundled starter set. In production, point this at an NVD JSON export (or run it on a
schedule) to keep the offline database current.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from .config import settings
from .cve_db import CveRepo
from .db.database import Database

_DEFAULT = Path(__file__).parent / "data" / "cve_seed.json"


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else _DEFAULT
    records = json.loads(path.read_text())
    db = Database(settings.postgres_dsn)
    db.migrate()
    count = CveRepo(db).seed(records)
    print(f"seeded {count} CVEs from {path}")


if __name__ == "__main__":
    main()
