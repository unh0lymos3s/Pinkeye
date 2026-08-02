"""Persona roster loading: config-driven agent personalities (runtime/personas.py).

Every failure mode here must degrade — never crash the API — per the loader's fail-soft contract:
an unknown stage or tool, a bad gated_flag, or a missing/unparseable file all fall back to something
that still works (drop the one bad persona, or the whole built-in roster). Nothing in this file
should ever cause `load_personas()` to raise.
"""
from __future__ import annotations

from runtime.personas import load_personas, reload_personas, resolve


def teardown_function(_fn) -> None:
    # Every test here loads an explicit path or mutates the module cache directly; reset it so
    # later tests (and other test modules that import the default roster) see a clean state.
    reload_personas()


def _write(tmp_path, name, text) -> str:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


# ---- the shipped roster --------------------------------------------------------------------------

def test_shipped_toml_yields_eight_personas():
    roster = load_personas()
    assert set(roster) == {
        "overseer", "scout", "viper", "warden", "oracle", "reaper", "ghost", "jack",
    }


def test_orchestrator_and_generalist_flagged_and_toolless_by_design():
    roster = load_personas()
    overseer, jack = roster["overseer"], roster["jack"]
    assert overseer.orchestrator is True and overseer.tools == ()
    assert jack.generalist is True
    # The generalist's toolkit is "every registered tool", never a hand-maintained list that could
    # drift — assert it actually covers every specialist's tools, not just a non-empty guess.
    specialists = [p for p in roster.values() if not p.orchestrator and not p.generalist]
    all_specialist_tools = {t for p in specialists for t in p.tools}
    assert all_specialist_tools <= set(jack.tools)


def test_back_compat_shims():
    scout = load_personas()["scout"]
    assert scout.kind == scout.id == "scout"
    assert scout.summary == scout.tagline


# ---- alias resolution -----------------------------------------------------------------------------

def test_alias_resolution_matches_legacy_profile_names():
    assert resolve("full").id == "overseer"
    assert resolve("recon").id == "scout"
    assert resolve("dast").id == "viper"
    assert resolve("sast").id == "warden"
    assert resolve("intel").id == "oracle"
    assert resolve("exploit").id == "reaper"
    assert resolve("credentials").id == "ghost"
    assert resolve("flat").id == "jack"


def test_resolve_matches_id_directly_and_case_insensitively():
    assert resolve("scout").id == "scout"
    assert resolve("SCOUT").id == "scout"
    assert resolve("  Viper  ").id == "viper"


def test_resolve_unknown_or_blank_returns_none():
    assert resolve("not-a-persona") is None
    assert resolve("") is None
    assert resolve(None) is None


# ---- fail-soft validation ---------------------------------------------------------------------

def test_unknown_tool_in_config_is_dropped_not_invented(tmp_path):
    path = _write(tmp_path, "agents.toml", """
[[agent]]
id = "solo"
label = "Solo"
glyph = "x"
accent = "#111111"
tagline = "test persona"
stage = "recon"
tools = ["nmap", "does_not_exist"]
aliases = []
gated_flag = ""
mission = "test"
""")
    roster = load_personas(path)
    assert roster["solo"].tools == ("nmap",)


def test_invalid_gated_flag_drops_the_persona(tmp_path):
    path = _write(tmp_path, "agents.toml", """
[[agent]]
id = "good"
label = "Good"
glyph = "x"
accent = "#111111"
tagline = "kept"
stage = "recon"
tools = ["nmap"]
aliases = []
gated_flag = ""
mission = "test"

[[agent]]
id = "bad"
label = "Bad"
glyph = "x"
accent = "#111111"
tagline = "dropped"
stage = "exploitation"
tools = ["exploit"]
aliases = []
gated_flag = "sudo_now"
mission = "test"
""")
    roster = load_personas(path)
    assert "good" in roster
    assert "bad" not in roster


def test_unknown_stage_drops_the_persona(tmp_path):
    # A lone bad persona would trip the "never end up with zero personas" fallback and mask the
    # per-entry drop, so pair it with a persona that validates cleanly to isolate the behavior.
    path = _write(tmp_path, "agents.toml", """
[[agent]]
id = "kept"
label = "Kept"
glyph = "x"
accent = "#111111"
tagline = "valid stage"
stage = "recon"
tools = ["nmap"]
aliases = []
gated_flag = ""
mission = "test"

[[agent]]
id = "lost"
label = "Lost"
glyph = "x"
accent = "#111111"
tagline = "dropped"
stage = "not-a-real-stage"
tools = ["nmap"]
aliases = []
gated_flag = ""
mission = "test"
""")
    roster = load_personas(path)
    assert "kept" in roster
    assert "lost" not in roster


def test_every_persona_invalid_falls_back_to_builtin_roster(tmp_path):
    path = _write(tmp_path, "agents.toml", """
[[agent]]
id = "lost"
label = "Lost"
glyph = "x"
accent = "#111111"
tagline = "dropped"
stage = "not-a-real-stage"
tools = ["nmap"]
aliases = []
gated_flag = ""
mission = "test"
""")
    roster = load_personas(path)
    assert set(roster) == {
        "overseer", "scout", "viper", "warden", "oracle", "reaper", "ghost", "jack",
    }


def test_duplicate_id_first_wins(tmp_path):
    path = _write(tmp_path, "agents.toml", """
[[agent]]
id = "dup"
label = "First"
glyph = "x"
accent = "#111111"
tagline = "kept"
stage = "recon"
tools = ["nmap"]
aliases = []
gated_flag = ""
mission = "test"

[[agent]]
id = "dup"
label = "Second"
glyph = "x"
accent = "#222222"
tagline = "dropped"
stage = "recon"
tools = ["nmap"]
aliases = []
gated_flag = ""
mission = "test"
""")
    roster = load_personas(path)
    assert roster["dup"].label == "First"


def test_duplicate_alias_first_wins(tmp_path):
    path = _write(tmp_path, "agents.toml", """
[[agent]]
id = "one"
label = "One"
glyph = "x"
accent = "#111111"
tagline = "keeps the alias"
stage = "recon"
tools = ["nmap"]
aliases = ["shared"]
gated_flag = ""
mission = "test"

[[agent]]
id = "two"
label = "Two"
glyph = "x"
accent = "#222222"
tagline = "alias collides, dropped"
stage = "recon"
tools = ["nmap"]
aliases = ["shared"]
gated_flag = ""
mission = "test"
""")
    roster = load_personas(path)
    assert roster["two"].aliases == ()
    assert resolve("shared") is None  # resolve() reads the cached default roster, not this fixture


def test_missing_file_falls_back_to_builtin_roster(tmp_path):
    roster = load_personas(str(tmp_path / "does-not-exist.toml"))
    assert set(roster) == {
        "overseer", "scout", "viper", "warden", "oracle", "reaper", "ghost", "jack",
    }


def test_unparseable_file_falls_back_to_builtin_roster(tmp_path):
    path = _write(tmp_path, "agents.toml", "this is not valid toml [[[")
    roster = load_personas(path)
    assert set(roster) == {
        "overseer", "scout", "viper", "warden", "oracle", "reaper", "ghost", "jack",
    }


def test_env_override_is_picked_up_after_reload(tmp_path, monkeypatch):
    path = _write(tmp_path, "agents.toml", """
[[agent]]
id = "only"
label = "Only"
glyph = "x"
accent = "#111111"
tagline = "the only persona in this override"
stage = "recon"
tools = ["nmap"]
aliases = []
gated_flag = ""
mission = "test"
""")
    monkeypatch.setenv("EYE_AGENTS_CONFIG", path)
    roster = reload_personas()
    assert set(roster) == {"only"}
    # Restore the env and the cache within the test itself rather than relying on teardown-hook
    # ordering against monkeypatch's own fixture finalizer.
    monkeypatch.undo()
    reload_personas()


# ---- a persona's registry is exactly its own tools ------------------------------------------------

def test_persona_tools_do_not_leak_across_personas():
    roster = load_personas()
    assert set(roster["scout"].tools) == {"nmap"}
    assert set(roster["viper"].tools) == {"nuclei", "ffuf", "nikto", "zap"}
    assert set(roster["warden"].tools) == {"semgrep", "gitleaks", "trivy"}
    assert set(roster["oracle"].tools) == {"cve_lookup", "virustotal", "tls_cert"}
    assert set(roster["reaper"].tools) == {"exploit", "post_exploit"}
    assert set(roster["ghost"].tools) == {"credential_attack"}
    # No overlap between any two specialists' toolkits.
    specialists = [p for p in roster.values() if not p.orchestrator and not p.generalist]
    for i, a in enumerate(specialists):
        for b in specialists[i + 1:]:
            assert not (set(a.tools) & set(b.tools))
