"""Tool registry: maps tool names to implementations and describes them to the model.

Every registered tool is offered to the LLM as the same shape — {target, intensity} — so the model
picks *what* to run and *where*, while the harness owns *how* (command construction, sandboxing,
scope enforcement). A tool the model asks for that isn't registered simply can't be run.
"""
from __future__ import annotations

from app.models import Intensity

from .llm.base import ToolSpec
from .tools.base import Tool

# Shared JSON Schema for every tool call: a target and an optional intensity ceiling.
_PARAM_SCHEMA = {
    "type": "object",
    "properties": {
        "target": {"type": "string", "description": "Host, IP, URL, or artifact path to act on."},
        "intensity": {
            "type": "string",
            "enum": [i.value for i in Intensity],
            "description": "How aggressive to be; capped by the engagement scope.",
        },
    },
    "required": ["target"],
}


class ToolRegistry:
    def __init__(self, tools: list[Tool] | None = None):
        self._tools: dict[str, Tool] = {}
        for tool in tools or []:
            self.register(tool)

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def specs(self) -> list[ToolSpec]:
        return [
            ToolSpec(name=t.name, description=t.description, parameters=_PARAM_SCHEMA)
            for t in self._tools.values()
        ]
