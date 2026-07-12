"""Scripted provider for tests. Returns a preset sequence of responses so the agent loop can be
exercised deterministically without any real model or network."""
from __future__ import annotations

from .base import LLMProvider, Message, ProviderResponse, ToolSpec


class FakeProvider(LLMProvider):
    def __init__(self, script: list[ProviderResponse]):
        self._script = list(script)
        self.calls: list[list[Message]] = []  # captured conversations, for assertions

    def complete(self, messages: list[Message], tools: list[ToolSpec]) -> ProviderResponse:
        self.calls.append(list(messages))
        if self._script:
            return self._script.pop(0)
        # Ran out of script -> end the loop with a final message.
        return ProviderResponse(text="done")
