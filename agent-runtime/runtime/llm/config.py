"""Per-role provider selection.

Different agent roles can use different models (a cheap local model for parsing/triage, a stronger
model for planning). Configuration is by environment variable so the harness stays model-agnostic:

    EYE_LLM_PROVIDER      claude | openai | ollama   (default: claude)
    EYE_LLM_MODEL         model id for the default provider
    EYE_LLM_<ROLE>_MODEL  optional per-role override, e.g. EYE_LLM_PLANNER_MODEL
"""
from __future__ import annotations

import os

from .base import LLMProvider


def get_provider(role: str = "planner") -> LLMProvider:
    provider = os.getenv("EYE_LLM_PROVIDER", "claude").lower()
    model = os.getenv(f"EYE_LLM_{role.upper()}_MODEL") or os.getenv("EYE_LLM_MODEL")

    if provider == "claude":
        from .claude import ClaudeProvider

        return ClaudeProvider(model=model or "claude-fable-5")
    if provider == "openai":
        from .openai_compat import OpenAICompatProvider

        return OpenAICompatProvider(model=model or "gpt-4o", base_url=os.getenv("EYE_LLM_BASE_URL"))
    if provider == "ollama":
        from .ollama import OllamaProvider

        return OllamaProvider(model=model or "llama3.1")
    raise ValueError(f"unknown EYE_LLM_PROVIDER: {provider}")
