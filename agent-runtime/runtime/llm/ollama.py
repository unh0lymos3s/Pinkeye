"""Local Ollama adapter. Ollama exposes an OpenAI-compatible endpoint, so we reuse that adapter
and just point it at the local server. This keeps all data on-host with no egress."""
from __future__ import annotations

from .openai_compat import OpenAICompatProvider


class OllamaProvider(OpenAICompatProvider):
    def __init__(self, model: str = "llama3.1", base_url: str = "http://localhost:11434/v1"):
        super().__init__(model=model, base_url=base_url, api_key="ollama")
