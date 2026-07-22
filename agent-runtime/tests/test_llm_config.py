"""Provider selection: env vars, JSON config file, fallback parsing, and backward compatibility.

Provider construction is lazy (SDKs import only on first .complete), so get_provider() can be tested
without anthropic/openai installed and without any network.
"""
import json

import pytest

from runtime.llm.claude import ClaudeProvider
from runtime.llm.config import get_provider
from runtime.llm.openai_compat import OpenAICompatProvider, _resolve_api_key
from runtime.llm.ollama import OllamaProvider
from runtime.llm.refusal import RefusalAwareProvider

_LLM_ENV = [
    "EYE_LLM_PROVIDER", "EYE_LLM_MODEL", "EYE_LLM_PLANNER_MODEL", "EYE_LLM_BASE_URL",
    "EYE_LLM_FALLBACK_MODELS", "EYE_LLM_CONFIG", "EYE_LLM_MAX_TOKENS",
]


@pytest.fixture(autouse=True)
def _clear_llm_env(monkeypatch):
    for var in _LLM_ENV:
        monkeypatch.delenv(var, raising=False)


def test_default_is_bare_ollama_provider():
    # With no env/config, the harness defaults to a local Ollama at localhost:11434.
    provider = get_provider()
    assert isinstance(provider, OllamaProvider)
    assert not isinstance(provider, RefusalAwareProvider)
    assert provider._base_url == "http://localhost:11434/v1"
    assert provider._model == "minimax-m3:cloud"


def test_ollama_honors_configurable_base_url(monkeypatch):
    monkeypatch.setenv("EYE_LLM_PROVIDER", "ollama")
    monkeypatch.setenv("EYE_LLM_MODEL", "llama3.1")
    monkeypatch.setenv("EYE_LLM_BASE_URL", "http://ollama-host:11434/v1")

    provider = get_provider()
    assert isinstance(provider, OllamaProvider)
    assert provider._base_url == "http://ollama-host:11434/v1"
    assert provider._model == "llama3.1"


def test_env_fallbacks_wrap_in_refusal_aware_provider(monkeypatch):
    monkeypatch.setenv("EYE_LLM_PROVIDER", "ollama")
    monkeypatch.setenv("EYE_LLM_FALLBACK_MODELS", "dolphin-mixtral, claude:claude-fable-5")

    provider = get_provider()
    assert isinstance(provider, RefusalAwareProvider)
    assert isinstance(provider.primary, OllamaProvider)
    assert len(provider.fallbacks) == 2
    # Bare "dolphin-mixtral" reuses the primary provider (ollama); "claude:..." switches provider.
    assert isinstance(provider.fallbacks[0], OllamaProvider)
    assert provider.fallbacks[0]._model == "dolphin-mixtral"
    assert isinstance(provider.fallbacks[1], ClaudeProvider)
    assert provider.fallbacks[1]._model == "claude-fable-5"


def test_json_config_file_is_read(tmp_path, monkeypatch):
    cfg = tmp_path / "router.json"
    cfg.write_text(json.dumps({
        "provider": "openai",
        "model": "gpt-4o-mini",
        "base_url": "http://proxy:4000/v1",
        "fallbacks": ["ollama:llama3.1"],
    }))
    monkeypatch.setenv("EYE_LLM_CONFIG", str(cfg))

    provider = get_provider()
    assert isinstance(provider, RefusalAwareProvider)
    assert isinstance(provider.primary, OpenAICompatProvider)
    assert provider.primary._model == "gpt-4o-mini"
    assert provider.primary._base_url == "http://proxy:4000/v1"
    assert isinstance(provider.fallbacks[0], OllamaProvider)


def test_env_overrides_file(tmp_path, monkeypatch):
    cfg = tmp_path / "router.json"
    cfg.write_text(json.dumps({"provider": "openai", "model": "gpt-4o"}))
    monkeypatch.setenv("EYE_LLM_CONFIG", str(cfg))
    monkeypatch.setenv("EYE_LLM_PROVIDER", "claude")
    monkeypatch.setenv("EYE_LLM_MODEL", "claude-fable-5")

    provider = get_provider()
    assert isinstance(provider, ClaudeProvider)  # env provider wins over file
    assert provider._model == "claude-fable-5"


def test_missing_config_file_is_ignored(monkeypatch):
    monkeypatch.setenv("EYE_LLM_CONFIG", "/no/such/file.json")
    provider = get_provider()
    assert isinstance(provider, OllamaProvider)  # falls back to defaults, does not raise


def test_openai_key_resolution_prefers_explicit_then_env(monkeypatch):
    # A keyed OpenAI-compatible endpoint must actually authenticate: resolve EYE_LLM_API_KEY
    # (or OPENAI_API_KEY) rather than forcing the "not-needed" placeholder.
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("EYE_LLM_API_KEY", "sk-project")
    assert _resolve_api_key(None) == "sk-project"

    monkeypatch.delenv("EYE_LLM_API_KEY")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai")
    assert _resolve_api_key(None) == "sk-openai"

    # Ollama passes an explicit placeholder key, which wins and keeps it keyless.
    assert _resolve_api_key("ollama") == "ollama"


def test_keyless_local_server_falls_back_to_placeholder(monkeypatch):
    monkeypatch.delenv("EYE_LLM_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert _resolve_api_key(None) == "not-needed"
