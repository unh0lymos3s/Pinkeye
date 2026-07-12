"""OpenAI-compatible adapter. Works with OpenAI and any server exposing the same chat API
(vLLM, LM Studio, LiteLLM, etc.) by pointing base_url at it."""
from __future__ import annotations

import json

from .base import LLMProvider, Message, ProviderResponse, ToolCall, ToolSpec


class OpenAICompatProvider(LLMProvider):
    def __init__(self, model: str, base_url: str | None = None, api_key: str | None = None):
        self._model = model
        self._base_url = base_url
        self._api_key = api_key
        self._client = None

    def _get_client(self):
        if self._client is None:
            import openai

            self._client = openai.OpenAI(base_url=self._base_url, api_key=self._api_key or "not-needed")
        return self._client

    def complete(self, messages: list[Message], tools: list[ToolSpec]) -> ProviderResponse:
        api_tools = [
            {
                "type": "function",
                "function": {"name": t.name, "description": t.description, "parameters": t.parameters},
            }
            for t in tools
        ]
        resp = self._get_client().chat.completions.create(
            model=self._model,
            messages=_to_openai_messages(messages),
            tools=api_tools or None,
        )
        choice = resp.choices[0].message
        calls = [
            ToolCall(id=tc.id, name=tc.function.name, arguments=json.loads(tc.function.arguments or "{}"))
            for tc in (choice.tool_calls or [])
        ]
        usage = resp.usage
        return ProviderResponse(
            text=choice.content or "",
            tool_calls=calls,
            input_tokens=getattr(usage, "prompt_tokens", 0),
            output_tokens=getattr(usage, "completion_tokens", 0),
        )


def _to_openai_messages(messages: list[Message]) -> list[dict]:
    out: list[dict] = []
    for m in messages:
        if m.role == "tool":
            out.append({"role": "tool", "tool_call_id": m.tool_call_id, "content": m.content})
        elif m.role == "assistant" and m.tool_calls:
            out.append(
                {
                    "role": "assistant",
                    "content": m.content or None,
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)},
                        }
                        for tc in m.tool_calls
                    ],
                }
            )
        else:
            out.append({"role": m.role, "content": m.content})
    return out
