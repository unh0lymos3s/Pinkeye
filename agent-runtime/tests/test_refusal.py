"""Refusal detection + reinforced-authorization + fallback routing — no real model or network.

These exercise the reliability path for safety-tuned local models: a refusal (apologetic text, no
tool call) must be recognized, the authorization re-asserted, and a more cooperative model tried.
"""
from runtime.llm.base import Message, ProviderResponse, ToolCall, ToolSpec
from runtime.llm.fake import FakeProvider
from runtime.llm.refusal import REINFORCEMENT_SYSTEM, RefusalAwareProvider, is_refusal

REFUSAL_TEXT = "I'm sorry, but I can't help with that. As an AI, it would be against my guidelines."
PLANNING_TEXT = "I will scan the host with nmap to enumerate open ports, then probe the services."


def _refusal() -> ProviderResponse:
    return ProviderResponse(text=REFUSAL_TEXT)


def _tool() -> ProviderResponse:
    return ProviderResponse(tool_calls=[ToolCall(id="c1", name="nmap", arguments={"target": "x"})])


def _messages() -> list[Message]:
    return [Message(role="system", content="mission"), Message(role="user", content="Seed. Begin.")]


def test_is_refusal_recognizes_common_declines():
    assert is_refusal(REFUSAL_TEXT)
    assert is_refusal("I cannot assist with hacking or penetration testing.")
    assert is_refusal("I must decline. This request raises ethical concerns.")


def test_is_refusal_ignores_normal_planning_and_empty():
    assert not is_refusal(PLANNING_TEXT)
    assert not is_refusal("")
    # A cue buried in a long substantive turn is treated as work, not a refusal.
    assert not is_refusal(PLANNING_TEXT + " as an AI planner. " + "Detail. " * 120)


def test_reinforced_retry_can_succeed_without_fallback():
    # Primary refuses first, then cooperates once authorization is re-asserted.
    primary = FakeProvider([_refusal(), _tool()])
    fallback = FakeProvider([_tool()])
    wrapper = RefusalAwareProvider(primary, [fallback])

    resp = wrapper.complete(_messages(), [])

    assert resp.tool_calls  # cooperated
    assert len(primary.calls) == 2  # initial + reinforced retry
    assert not fallback.calls  # fallback never needed
    # The retried conversation carries the reinforcement system message.
    assert any(m.content == REINFORCEMENT_SYSTEM for m in primary.calls[1])


def test_falls_back_when_primary_keeps_refusing():
    primary = FakeProvider([_refusal(), _refusal()])  # initial + reinforced retry both refuse
    fallback = FakeProvider([_tool()])
    events: list[dict] = []
    wrapper = RefusalAwareProvider(primary, [fallback], on_refusal=events.append)

    resp = wrapper.complete(_messages(), [])

    assert resp.tool_calls  # fallback cooperated
    assert len(primary.calls) == 2 and len(fallback.calls) == 1
    # Fallback got the reinforced conversation, not the bare one.
    assert any(m.content == REINFORCEMENT_SYSTEM for m in fallback.calls[0])
    stages = [e["stage"] for e in events]
    assert stages == ["reinforce", "fallback"]


def test_cooperative_primary_never_triggers_fallback():
    primary = FakeProvider([_tool()])
    fallback = FakeProvider([_tool()])
    events: list[dict] = []
    wrapper = RefusalAwareProvider(primary, [fallback], on_refusal=events.append)

    resp = wrapper.complete(_messages(), [])

    assert resp.tool_calls
    assert len(primary.calls) == 1 and not fallback.calls
    assert not events


def test_all_refuse_returns_last_response_so_loop_terminates():
    primary = FakeProvider([_refusal(), _refusal()])
    fallback = FakeProvider([_refusal()])
    events: list[dict] = []
    wrapper = RefusalAwareProvider(primary, [fallback], on_refusal=events.append)

    resp = wrapper.complete(_messages(), [])

    assert not resp.tool_calls and is_refusal(resp.text)
    assert events[-1]["stage"] == "exhausted"


def test_on_refusal_callback_that_raises_never_breaks_routing():
    def boom(_data):
        raise RuntimeError("sink down")

    primary = FakeProvider([_refusal(), _refusal()])
    fallback = FakeProvider([_tool()])
    wrapper = RefusalAwareProvider(primary, [fallback], on_refusal=boom)

    resp = wrapper.complete(_messages(), [ToolSpec("nmap", "d", {})])
    assert resp.tool_calls  # routing survived the failing callback
