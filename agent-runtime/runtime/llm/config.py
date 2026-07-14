"""Per-role provider selection.

Different agent roles can use different models (a cheap local model for parsing/triage, a stronger
model for planning). Configuration is by environment variable so the harness stays model-agnostic:

    EYE_LLM_PROVIDER        claude | openai | ollama   (default: claude)
    EYE_LLM_MODEL           model id for the default provider
    EYE_LLM_<ROLE>_MODEL    optional per-role override, e.g. EYE_LLM_PLANNER_MODEL
    EYE_LLM_MAX_TOKENS      per-call output cap (default 8192)
    EYE_LLM_BASE_URL        base URL for openai/ollama providers (points at a local server,
                            a remote Ollama, or a LiteLLM/vLLM proxy)
    EYE_LLM_FALLBACK_MODELS comma list of "provider:model" (or bare "model") tried in order when
                            the primary model refuses an authorized step -- see refusal.py
    EYE_LLM_CONFIG          path to a JSON file with the same knobs; re-read on every call so
                            editing it hot-swaps the model/fallbacks for the next run, no restart.
                            Shape: {"provider","model","base_url","fallbacks":[...]}. Explicit env
                            vars override file values; the file overrides built-in defaults.
"""
from __future__ import annotations

import json
import os

from .base import LLMProvider

DEFAULT_MAX_TOKENS = 8192
DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434/v1"


def _max_tokens() -> int:
    """Per-call output cap. Larger than the old 2048 so a multi-tool step isn't truncated, but a
    bad/zero value falls back to the default rather than disabling the cap."""
    raw = os.getenv("EYE_LLM_MAX_TOKENS")
    if raw is None:
        return DEFAULT_MAX_TOKENS
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_MAX_TOKENS
    return value if value > 0 else DEFAULT_MAX_TOKENS


def _load_file_config() -> dict:
    """Read EYE_LLM_CONFIG (JSON) if set. Re-read every call so an edit hot-swaps the next run.
    A missing/broken file is ignored (falls back to env/defaults) rather than breaking the run."""
    path = os.getenv("EYE_LLM_CONFIG")
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _build_one(provider: str, model: str | None, base_url: str | None,
               max_tokens: int) -> LLMProvider:
    """Instantiate a single provider. Shared by the primary and every fallback."""
    provider = provider.lower()
    if provider == "claude":
        from .claude import ClaudeProvider

        return ClaudeProvider(model=model or "claude-fable-5", max_tokens=max_tokens)
    if provider == "openai":
        from .openai_compat import OpenAICompatProvider

        return OpenAICompatProvider(model=model or "gpt-4o", base_url=base_url, max_tokens=max_tokens)
    if provider == "ollama":
        from .ollama import OllamaProvider

        return OllamaProvider(model=model or "gemma4:cloud",
                              base_url=base_url or DEFAULT_OLLAMA_BASE_URL)
    raise ValueError(f"unknown EYE_LLM_PROVIDER: {provider}")


def _parse_fallbacks(raw: object, default_provider: str, base_url: str | None,
                     max_tokens: int) -> list[LLMProvider]:
    """Parse a fallback spec into ordered providers. Each entry is "provider:model" or a bare
    "model" (which reuses the primary provider). Accepts a comma string (env) or a list (file)."""
    if not raw:
        return []
    if isinstance(raw, str):
        entries = [e.strip() for e in raw.split(",") if e.strip()]
    elif isinstance(raw, list):
        entries = [str(e).strip() for e in raw if str(e).strip()]
    else:
        return []
    out: list[LLMProvider] = []
    for entry in entries:
        if ":" in entry:
            prov, _, model = entry.partition(":")
            prov, model = prov.strip(), model.strip()
        else:
            prov, model = default_provider, entry
        # Only OpenAI-compatible providers share the primary's base_url; a claude fallback ignores it.
        fb_base = base_url if prov.lower() in ("openai", "ollama") else None
        out.append(_build_one(prov, model or None, fb_base, max_tokens))
    return out


def get_provider(role: str = "planner") -> LLMProvider:
    file_cfg = _load_file_config()

    provider = (os.getenv("EYE_LLM_PROVIDER") or file_cfg.get("provider") or "claude").lower()
    model = (os.getenv(f"EYE_LLM_{role.upper()}_MODEL") or os.getenv("EYE_LLM_MODEL")
             or file_cfg.get("model"))
    base_url = os.getenv("EYE_LLM_BASE_URL") or file_cfg.get("base_url")
    max_tokens = _max_tokens()

    primary = _build_one(provider, model, base_url, max_tokens)

    fallback_spec = os.getenv("EYE_LLM_FALLBACK_MODELS") or file_cfg.get("fallbacks")
    fallbacks = _parse_fallbacks(fallback_spec, provider, base_url, max_tokens)
    if not fallbacks:
        return primary  # unchanged path -- no wrapping when nothing is configured

    from .refusal import RefusalAwareProvider

    return RefusalAwareProvider(primary, fallbacks)
