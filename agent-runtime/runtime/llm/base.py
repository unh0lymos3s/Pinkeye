"""Model-agnostic LLM interface.

Everything above this line (the agent loop, tools, scope guard) is provider-independent. Adapters
below translate to Claude / OpenAI-compatible / Ollama. Swapping models never touches the harness.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Protocol


@dataclass
class Message:
    role: str  # "system" | "user" | "assistant" | "tool"
    content: str = ""
    # For tool-result messages: which tool call this answers.
    tool_call_id: Optional[str] = None
    # For assistant turns that requested tools: the calls made, so history stays valid across turns.
    tool_calls: list["ToolCall"] = field(default_factory=list)


@dataclass
class ToolSpec:
    """A tool the model may call, described in a provider-neutral way."""

    name: str
    description: str
    parameters: dict[str, Any]  # JSON Schema for the arguments


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class ProviderResponse:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0


class LLMProvider(Protocol):
    """One method: given a conversation and the available tools, return the next step."""

    def complete(self, messages: list[Message], tools: list[ToolSpec]) -> ProviderResponse: ...
