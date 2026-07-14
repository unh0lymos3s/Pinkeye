"""Ollama adapter. Ollama exposes an OpenAI-compatible endpoint, so we reuse that adapter and just
point it at the Ollama server (a local container in this stack).

The default model is ``gemma4:cloud`` — an Ollama Cloud model: requests still go through the local
Ollama server, which proxies them to Ollama's cloud (needs an account/API key; no GPU required).
Point ``model`` at a locally pulled model (e.g. ``llama3.1``) instead to keep all data on-host with
no egress."""
from __future__ import annotations

from .openai_compat import OpenAICompatProvider


class OllamaProvider(OpenAICompatProvider):
    def __init__(self, model: str = "gemma4:cloud", base_url: str = "http://localhost:11434/v1"):
        super().__init__(model=model, base_url=base_url, api_key="ollama")
