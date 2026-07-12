"""Scan worker: claims jobs off the queue and executes them, so scanning scales out from the API.

Run with `python -m app.worker`. Each claimed job carries the engagement id and run parameters; the
worker rebuilds the run and drives it through the same scope-guarded orchestrator/agent the API uses.
"""
from __future__ import annotations

import time

from .audit import MemoryAuditSink, PostgresAuditSink
from .config import settings
from .db.database import Database
from .graph import GraphClient
from .models import Intensity, Run
from .queue import JobQueue
from .repositories import EngagementRepo, PersistenceSink

# Reuse the runtime the API uses.
from runtime.agent import run_agent
from runtime.llm.config import get_provider
from runtime.orchestrator import run_scan
from runtime.registry import ToolRegistry
from runtime.sandbox import DockerSandbox
from runtime.toolset import all_tools


def _handle(job: dict, db, graph, audit) -> bool:
    engagements = EngagementRepo(db)
    eng = engagements.get(job["engagement_id"])
    if not eng:
        return False
    p = job["payload"]
    run = Run(id=p["run_id"], engagement_id=eng.id, target=p["target"])
    persistence = PersistenceSink(db)
    tools = {t.name: t for t in all_tools(db)}
    if p.get("mode") == "agent":
        run_agent(eng, run, get_provider("planner"), ToolRegistry(list(tools.values())),
                  DockerSandbox(), graph, audit, persistence)
    else:
        tool = tools.get(p.get("tool", "nmap"))
        run_scan(eng, run, tool, Intensity(p.get("intensity", "light")),
                 DockerSandbox(), graph, audit, persistence)
    return True


def main(poll_seconds: float = 2.0) -> None:
    db = Database(settings.postgres_dsn)
    graph = GraphClient()
    try:
        db.migrate()
        with db.connection():
            pass
        audit = PostgresAuditSink(db)
    except Exception:
        audit = MemoryAuditSink()
    queue = JobQueue(db)
    print("eye worker started; polling for jobs…")
    while True:
        job = queue.claim()
        if not job:
            time.sleep(poll_seconds)
            continue
        try:
            ok = _handle(job, db, graph, audit)
        except Exception as exc:
            print(f"job {job['id']} failed: {exc}")
            ok = False
        queue.finish(job["id"], ok)


if __name__ == "__main__":
    main()
