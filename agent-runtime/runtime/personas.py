"""Agent personalities: a named roster of specialist agents loaded from a config file.

Before this module, the roster of who could run what lived in two places at once: `SPECIALISTS` in
`subagents.py` hardcoded the specialist list, and each one's tool subset was *derived* from
`pipeline._TOOL_STAGE` (a persona's tools were "whatever tools happen to share its stage label").
That coupling meant you could not give a persona its own name/look/voice without also reshaping the
pipeline rail, and you could not narrow a persona's toolkit without moving a tool to a new stage.

Personas decouple the two: each persona owns an *explicit* tool list, a display identity (glyph,
accent color, tagline), and a mission written in its own voice, all loaded from
`agents.toml` (or `EYE_AGENTS_CONFIG`, `.toml` or `.json`, picked by extension). `pipeline.py` still
exists and still drives the presentation-only stage rail; it is no longer where a persona's toolkit
comes from.

**Config is capability metadata, never authorization.** A persona listing `exploit` in its `tools`
only means the orchestrator/planner may *offer* that tool to it — `execute_tool_step` still runs the
signed-scope guard and the `requires_flag` gate on every call, unchanged. Loading this file can never
grant a `gated_flag` the guard doesn't understand, and can never hand a persona a tool that isn't
actually registered: every entry is validated against `pipeline.known_tool_names()`, and anything
that doesn't check out is dropped (never invented) with a log line, not a crash. A missing or
unparseable config file falls back to a built-in copy of the shipped roster, so the harness always
has *some* working roster even if the file is deleted or hand-edited into garbage.
"""
from __future__ import annotations

import json
import logging
import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .pipeline import STAGES, known_tool_names

logger = logging.getLogger(__name__)

_ENV_CONFIG = "EYE_AGENTS_CONFIG"
_DEFAULT_CONFIG = Path(__file__).with_name("agents.toml")

# The only gated_flag values the scope guard actually understands (app.models.Scope /
# execute_tool_step). A config asking for anything else would be asking the guard to check a flag
# that doesn't exist — reject the persona outright rather than silently offering an ungated tool.
_VALID_GATED_FLAGS = frozenset({"allow_exploit", "allow_credential_attacks"})


@dataclass(frozen=True)
class Persona:
    """One named agent personality: display identity, the pipeline stage it owns (if any), its
    explicit tool list, and the mission it runs with. Immutable — the loaded roster is shared/cached,
    so nothing downstream should be able to mutate one persona's tools out from under another."""

    id: str
    label: str
    glyph: str
    accent: str
    tagline: str
    stage: str | None            # pipeline stage this persona owns; None for orchestrator/generalist
    tools: tuple[str, ...]       # exact tool names this persona may be offered; never invented
    aliases: tuple[str, ...]     # legacy/alternate profile strings that resolve to this persona
    gated_flag: str | None       # scope attribute required to offer this persona, or None
    mission: str
    orchestrator: bool = False  # delegates to other personas instead of running tools itself
    generalist: bool = False    # one persona, every tool, no delegation (the legacy "flat" agent)

    # Back-compat shims for the pre-persona API (`Specialist.kind`, `Specialist.summary`), so callers
    # written against the old dataclass keep working unchanged against the new one.
    @property
    def kind(self) -> str:
        return self.id

    @property
    def summary(self) -> str:
        return self.tagline


# The roster this module ships is authored once, in `agents.toml`. This literal is a byte-for-byte
# equivalent kept as a Python fallback so the harness still has a full, working roster even if that
# file is deleted, corrupted, or replaced with something that fails to parse — losing the config file
# must degrade to "runs with the default personas", never "the API breaks".
_BUILTIN_ROSTER: list[dict] = [
    {
        "id": "overseer", "label": "Overseer", "glyph": "👁", "accent": "#ff2fb9",
        "tagline": "Lead operator — delegates to the crew.",
        "stage": "", "tools": [], "aliases": ["full"], "gated_flag": "",
        "orchestrator": True, "generalist": False,
        "mission": (
            "You are the Overseer, lead operator of this security assessment. You do not run "
            "scanning tools yourself — you delegate to the specialists on your crew by calling them "
            "as tools, one at a time, reading each one's summary before dispatching the next.\n\n"
            "Start with Scout to map the attack surface, then Viper (dynamic scanning) and/or Warden "
            "(static analysis of an in-scope source artifact), then Oracle to enrich what they found "
            "with threat intel. Give each specialist a clear target and, when useful, a focus "
            "describing what to prioritize based on earlier passes.\n\n"
            "Reaper (exploitation) and Ghost (credentials) are intrusive and only appear on your "
            "roster when the signed engagement scope authorizes them. Before dispatching either one "
            "you MUST call `ask_user` with kind=\"permission\" and get an explicit go-ahead — never "
            "widen beyond what was approved.\n\n"
            "When every needed pass is done, stop and summarize the overall findings and attack "
            "surface for the operator."
        ),
    },
    {
        "id": "scout", "label": "Scout", "glyph": "🛰", "accent": "#38bdf8",
        "tagline": "Maps the ground before anyone steps on it.",
        "stage": "recon", "tools": ["nmap"], "aliases": ["recon"], "gated_flag": "",
        "orchestrator": False, "generalist": False,
        "mission": (
            "You are Scout, the reconnaissance specialist. Map the attack surface of the target: "
            "discover live hosts, open ports, and running services with the recon tools on your "
            "belt. Call one tool at a time, read the result, then decide the next step. Stay within "
            "the authorized scope; if a call is denied, pick a different in-scope action. When you "
            "have mapped the surface, stop and summarize what you found (hosts, ports, services) so "
            "the Overseer can plan deeper passes."
        ),
    },
    {
        "id": "viper", "label": "Viper", "glyph": "🐍", "accent": "#22c55e",
        "tagline": "Strikes the live target where it's soft.",
        "stage": "dynamic scan", "tools": ["nuclei", "ffuf", "nikto", "zap"], "aliases": ["dast"],
        "gated_flag": "", "orchestrator": False, "generalist": False,
        "mission": (
            "You are Viper, the dynamic application security testing specialist. Probe the live "
            "target for vulnerabilities with the dynamic scanners on your belt (web/service "
            "scanners, content discovery). Call one tool at a time, read the result, then decide the "
            "next step. Stay within the authorized scope; if a call is denied, pick a different "
            "in-scope action. These scans do not need operator approval. When you have covered the "
            "dynamic surface, stop and summarize the findings."
        ),
    },
    {
        "id": "warden", "label": "Warden", "glyph": "🛡", "accent": "#f59e0b",
        "tagline": "Reads the source so exploits don't have to.",
        "stage": "static scan", "tools": ["semgrep", "gitleaks", "trivy"], "aliases": ["sast"],
        "gated_flag": "", "orchestrator": False, "generalist": False,
        "mission": (
            "You are Warden, the static application security testing specialist. Analyze the "
            "in-scope source artifact for vulnerabilities, secrets, and vulnerable dependencies with "
            "the static analysis tools on your belt. The target is a source path/artifact, not a "
            "live host. Call one tool at a time, read the result, then decide the next step. Stay "
            "within the authorized scope. These scans do not need operator approval. When you have "
            "analyzed the artifact, stop and summarize the findings."
        ),
    },
    {
        "id": "oracle", "label": "Oracle", "glyph": "🔮", "accent": "#a855f7",
        "tagline": "Turns findings into context: CVEs, reputation, certs.",
        "stage": "threat intel", "tools": ["cve_lookup", "virustotal", "tls_cert"],
        "aliases": ["intel"], "gated_flag": "", "orchestrator": False, "generalist": False,
        "mission": (
            "You are Oracle, the threat-intelligence specialist. Enrich what earlier passes "
            "discovered: look up CVEs for identified products/versions, check the reputation of "
            "hashes/indicators, and inspect TLS certificates with the knowledge tools on your belt. "
            "Call one tool at a time and stay within scope. When you have enriched the available "
            "data, stop and summarize the intelligence you gathered."
        ),
    },
    {
        "id": "reaper", "label": "Reaper", "glyph": "💀", "accent": "#ef4444",
        "tagline": "Confirms what's exploitable — only with a green light.",
        "stage": "exploitation", "tools": ["exploit", "post_exploit"], "aliases": ["exploit"],
        "gated_flag": "allow_exploit", "orchestrator": False, "generalist": False,
        "mission": (
            "You are Reaper, the exploitation specialist. Validate specific vulnerabilities the "
            "Overseer asked you to confirm, using the exploitation tools on your belt. This is "
            "intrusive: you MUST call `ask_user` with kind=\"permission\" and get an explicit "
            "go-ahead before launching ANY exploit or post-exploitation action, and never widen "
            "beyond what was approved. Default to check-only validation. Stay strictly within the "
            "authorized scope. When done, stop and summarize precisely what was validated and what "
            "access (if any) was demonstrated."
        ),
    },
    {
        "id": "ghost", "label": "Ghost", "glyph": "🔑", "accent": "#67e8f9",
        "tagline": "Tries the keys quietly, never brute force.",
        "stage": "credentials", "tools": ["credential_attack"], "aliases": ["credentials"],
        "gated_flag": "allow_credential_attacks", "orchestrator": False, "generalist": False,
        "mission": (
            "You are Ghost, the credential-testing specialist. Test for weak credentials on the "
            "in-scope service the Overseer identified, using the credential tool on your belt. This "
            "is intrusive: you MUST call `ask_user` with kind=\"permission\" and get an explicit "
            "go-ahead before launching any credential attack. Use conservative, low-and-slow "
            "settings (spraying, not brute force). Stay strictly within the authorized scope. When "
            "done, stop and summarize the result without echoing any password material."
        ),
    },
    {
        "id": "jack", "label": "Jack", "glyph": "🃏", "accent": "#facc15",
        "tagline": "One generalist, the whole toolkit, start to finish.",
        "stage": "", "tools": [], "aliases": ["flat"], "gated_flag": "",
        "orchestrator": False, "generalist": True,
        "mission": (
            "You are Jack, a generalist penetration-testing agent working solo with the full "
            "toolkit — recon, dynamic and static scanning, threat intel, and (when authorized) "
            "exploitation and credentials all in one context. Call one tool at a time, read the "
            "result, then decide the next step. Stay within the authorized scope; if a call is "
            "denied, pick a different in-scope action. You MUST call `ask_user` with "
            "kind=\"permission\" and get an explicit go-ahead before any intrusive step — exploit, "
            "post_exploit, or credential_attack. Recon, dynamic (DAST) and static (SAST) scanning do "
            "not need approval. When you have covered the surface, stop and summarize."
        ),
    },
]

# Memoized roster for the default (no-arg, no env-override-change-mid-process) call path — a config
# file is read once per process, like the MCP config. `reload_personas()` clears this for tests that
# swap EYE_AGENTS_CONFIG or rewrite the file mid-session.
_cache: dict[str, "Persona"] | None = None


def _resolve_config_path(path: str | os.PathLike | None) -> Path:
    if path is not None:
        return Path(path)
    env = os.getenv(_ENV_CONFIG)
    if env:
        return Path(env)
    return _DEFAULT_CONFIG


def _load_entries(path: Path) -> list[dict] | None:
    """Parse the config file into raw `[[agent]]`/`agent` tables, picking the parser by extension.
    Returns None (never raises) on any I/O or parse problem so a missing/bad file falls back to the
    built-in roster instead of crashing the API — this is a fail-soft loader by design."""
    try:
        with path.open("rb") as fh:
            data = json.load(fh) if path.suffix.lower() == ".json" else tomllib.load(fh)
    except OSError as exc:
        logger.warning("agents config: could not read %s (%s) — using the built-in roster", path, exc)
        return None
    except (ValueError, tomllib.TOMLDecodeError) as exc:
        logger.warning("agents config: could not parse %s (%s) — using the built-in roster", path, exc)
        return None
    agents = data.get("agent") if isinstance(data, dict) else None
    if not isinstance(agents, list):
        logger.warning("agents config: %s has no [[agent]] tables — using the built-in roster", path)
        return None
    return [a for a in agents if isinstance(a, dict)]


def _coerce(raw: dict, seen_ids: set[str], seen_aliases: set[str]) -> Persona | None:
    """Validate and normalize one raw `[[agent]]` table into a `Persona`, or drop it with a logged
    reason. Every rejection here is a *narrowing* of what the config can do relative to a strictly
    correct table — dropping is always safe; there is no path in this function that can grant a tool
    or a gated_flag the guard doesn't already recognize."""
    pid = str(raw.get("id", "")).strip().lower()
    if not pid:
        logger.warning("agents config: dropping a persona with a missing/blank id")
        return None
    if pid in seen_ids:
        logger.warning("agents config: duplicate persona id %r — keeping the first, dropping this one", pid)
        return None

    orchestrator = bool(raw.get("orchestrator", False))
    generalist = bool(raw.get("generalist", False))

    stage = str(raw.get("stage") or "").strip() or None
    if stage is not None and stage not in STAGES:
        logger.warning("agents config: persona %r has unknown stage %r — dropping the persona", pid, stage)
        return None

    gated_flag = str(raw.get("gated_flag") or "").strip() or None
    if gated_flag is not None and gated_flag not in _VALID_GATED_FLAGS:
        logger.warning(
            "agents config: persona %r has invalid gated_flag %r (must be one of %s) — dropping "
            "the persona", pid, gated_flag, sorted(_VALID_GATED_FLAGS),
        )
        return None

    # Tools: never invent one. The orchestrator delegates rather than running tools, so it always
    # gets an empty list regardless of what the config says; the generalist's toolkit is "everything
    # registered" by definition rather than a hand-maintained list that could drift out of sync;
    # everyone else gets exactly the config's list, minus any name that isn't actually registered.
    known = known_tool_names()
    if orchestrator:
        tools: tuple[str, ...] = ()
    elif generalist:
        tools = tuple(sorted(known))
    else:
        requested = [str(t) for t in (raw.get("tools") or [])]
        kept = [t for t in requested if t in known]
        unknown = [t for t in requested if t not in known]
        if unknown:
            logger.warning(
                "agents config: persona %r lists unregistered tool(s) %s — dropped, not invented",
                pid, unknown,
            )
        tools = tuple(kept)

    aliases: list[str] = []
    for a in (str(x).strip().lower() for x in (raw.get("aliases") or [])):
        if not a:
            continue
        if a in seen_ids or a in seen_aliases:
            logger.warning(
                "agents config: alias %r for persona %r collides with an existing id/alias — "
                "dropping the alias", a, pid,
            )
            continue
        aliases.append(a)

    return Persona(
        id=pid,
        label=str(raw.get("label") or pid.title()),
        glyph=str(raw.get("glyph") or ""),
        accent=str(raw.get("accent") or "#ffffff"),
        tagline=str(raw.get("tagline") or ""),
        stage=stage,
        tools=tools,
        aliases=tuple(aliases),
        gated_flag=gated_flag,
        mission=str(raw.get("mission") or "").strip(),
        orchestrator=orchestrator,
        generalist=generalist,
    )


def _build_roster(entries: list[dict]) -> dict[str, Persona]:
    """Turn validated raw tables into the id -> Persona roster, first-wins on any collision."""
    roster: dict[str, Persona] = {}
    seen_ids: set[str] = set()
    seen_aliases: set[str] = set()
    for raw in entries:
        persona = _coerce(raw, seen_ids, seen_aliases)
        if persona is None:
            continue
        seen_ids.add(persona.id)
        seen_aliases.update(persona.aliases)
        roster[persona.id] = persona
    return roster


def load_personas(path: str | os.PathLike | None = None) -> dict[str, Persona]:
    """Load the persona roster, id -> Persona, in config file order.

    With no `path` argument this reads `EYE_AGENTS_CONFIG` (falling back to the bundled
    `agents.toml`) and memoizes the result for the life of the process — like `mcp/config.py`, a
    config file is read once. Passing an explicit `path` (tests only) always reads fresh and never
    touches the cache, so a test can point at an arbitrary fixture without disturbing others.

    Fails soft at every layer: a missing/unparseable file, or one whose every persona fails
    validation, falls back to the built-in roster — the harness must never end up with zero
    personas or a crash from a bad config.
    """
    global _cache
    use_cache = path is None
    if use_cache and _cache is not None:
        return _cache

    resolved = _resolve_config_path(path)
    entries = _load_entries(resolved)
    if entries is None:
        entries = _BUILTIN_ROSTER

    roster = _build_roster(entries)
    if not roster:
        logger.warning("agents config: %s yielded no valid personas — using the built-in roster", resolved)
        roster = _build_roster(_BUILTIN_ROSTER)

    if use_cache:
        _cache = roster
    return roster


def reload_personas() -> dict[str, Persona]:
    """Drop the memoized roster and reload — for tests that change EYE_AGENTS_CONFIG or the config
    file's contents mid-session and need `load_personas()` to see it."""
    global _cache
    _cache = None
    return load_personas()


def resolve(name: str | None) -> Persona | None:
    """Resolve a profile string to a Persona: id first, then alias, both case-insensitively. `None`
    or blank never defaults to anything here — that's a caller decision (main.py defaults to
    "overseer" before calling this), so `resolve` stays a pure lookup."""
    if not name:
        return None
    key = str(name).strip().lower()
    roster = load_personas()
    if key in roster:
        return roster[key]
    for persona in roster.values():
        if key in persona.aliases:
            return persona
    return None
