"""Anthropic Claude adapter. The SDK is imported lazily so the harness runs without it installed."""
from __future__ import annotations

import os

from .base import LLMProvider, Message, ProviderResponse, ToolCall, ToolSpec


class ClaudeProvider(LLMProvider):
    def __init__(self, model: str = "claude-fable-5", api_key: str | None = None, max_tokens: int = 8192):
        self._model = model
        self._api_key = api_key
        self._max_tokens = max_tokens
        self._client = None

    def _get_client(self):
        if self._client is None:
            import anthropic

            def _f(name, default):
                try:
                    return float(os.getenv(name, ""))
                except ValueError:
                    return default

            def _i(name, default):
                try:
                    return int(os.getenv(name, ""))
                except ValueError:
                    return default

            # Fail fast rather than hang on an unreachable endpoint (see openai_compat).
            self._client = anthropic.Anthropic(
                api_key=self._api_key,
                timeout=_f("EYE_LLM_TIMEOUT", 120.0),
                max_retries=_i("EYE_LLM_MAX_RETRIES", 1),
            )
        return self._client

    def complete(self, messages: list[Message], tools: list[ToolSpec]) -> ProviderResponse:
        # Anthropic keeps the system prompt separate from the message list.
        system = "\n".join(m.content for m in messages if m.role == "system")
        api_messages = _to_anthropic_messages([m for m in messages if m.role != "system"])
        api_tools = [
            {"name": t.name, "description": t.description, "input_schema": t.parameters} for t in tools
        ]
        resp = self._get_client().messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            system=system,
            messages=api_messages,
            tools=api_tools or None,
        )
        text, calls = "", []
        for block in resp.content:
            if block.type == "text":
                text += block.text
            elif block.type == "tool_use":
                calls.append(ToolCall(id=block.id, name=block.name, arguments=dict(block.input)))
        return ProviderResponse(
            text=text,
            tool_calls=calls,
            input_tokens=resp.usage.input_tokens,
            output_tokens=resp.usage.output_tokens,
        )


def _to_anthropic_messages(messages: list[Message]) -> list[dict]:
    out: list[dict] = []
    for m in messages:
        if m.role == "tool":
            out.append(
                {
                    "role": "user",
                    "content": [
                        {"type": "tool_result", "tool_use_id": m.tool_call_id, "content": m.content}
                    ],
                }
            )
        elif m.role == "assistant" and m.tool_calls:
            # Assistant turn that requested tools: text (if any) followed by tool_use blocks.
            blocks: list[dict] = []
            if m.content:
                blocks.append({"type": "text", "text": m.content})
            for tc in m.tool_calls:
                blocks.append({"type": "tool_use", "id": tc.id, "name": tc.name, "input": tc.arguments})
            out.append({"role": "assistant", "content": blocks})
        else:
            out.append({"role": m.role, "content": m.content})
    return out
