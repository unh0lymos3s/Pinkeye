#!/usr/bin/env bash
# Verification entrypoint for the Pinkeye backend.
#
# The two packages each ship a `tests/` package with colliding module names, so pytest cannot
# collect them in one run — each suite must run from its own rootdir.
#
# Deliberately no hardcoded pass counts: the suites grow, and a stale "expected" number is worse
# than none — it either nags or, once ignored, hides a real drop. pytest's own exit status is the
# gate; the printed totals are for the reader.
set -uo pipefail
cd "$(dirname "$0")"
VENV="$PWD/.venv/bin/python"

fail=0

echo "=== control-plane ==="
( cd control-plane && "$VENV" -m pytest -q 2>&1 | tail -5 ) || fail=1

echo
echo "=== agent-runtime ==="
( cd agent-runtime && "$VENV" -m pytest -q 2>&1 | tail -5 ) || fail=1

echo
echo "=== import check (catches syntax/name errors the suites may not reach) ==="
"$VENV" - <<'PY' || fail=1
import importlib, sys
mods = [
    "app.main", "app.repositories", "app.graph", "app.memory", "app.events",
    "app.audit", "app.query", "app.scope", "app.config", "app.correlation",
    "app.db.database", "app.worker", "app.uploads", "app.cve_db",
    "runtime.agent", "runtime.orchestrator", "runtime.subagents", "runtime.toolset",
    "runtime.sandbox", "runtime.egress", "runtime.mcp", "runtime.mcp.pool",
    "runtime.mcp.client", "runtime.mcp.backend", "runtime.llm.config",
]
bad = []
for m in mods:
    try:
        importlib.import_module(m)
    except Exception as e:
        bad.append(f"{m}: {type(e).__name__}: {e}")
for b in bad:
    print("IMPORT FAIL", b)
print("imports OK" if not bad else f"{len(bad)} import failures")
sys.exit(1 if bad else 0)
PY

echo
if [ "$fail" -eq 0 ]; then echo "VERIFY: OK"; else echo "VERIFY: FAILURES ABOVE"; fi
exit $fail
