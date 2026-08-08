from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from TOSKill.AI.decision_context import build_decision_context
from TOSKill.AI.graph import memory_store
from TOSKill.AI.state import create_initial_state, update_state
from TOSKill.config import settings
from TOSKill.AI.graph import ai_decision
from TOSKill.api.ai_chat_websocket import AIChatManager


def test_chat_is_converted_to_structured_scan_factors():
    context = build_decision_context(
        {},
        "请优先测试 XSS 和 SQL注入，但跳过弱口令。只读扫描，低并发，不要修改目标。",
        version=1,
        pause_id="pause-1",
        timestamp="2026-08-07T12:00:00",
    )

    requested = {item["task"] for item in context["requested_tasks"]}
    excluded = {item["task"] for item in context["excluded_tasks"]}

    assert {"xss_scan", "sqli_scan"}.issubset(requested)
    assert "weakpass_scan" in excluded
    assert {"xss_scan", "sqli_scan"}.issubset(set(context["priority_tasks"]))
    assert context["risk_tolerance"] == "low_impact"
    assert any(item["kind"] == "safety" for item in context["user_constraints"])
    assert context["messages"][0]["pause_id"] == "pause-1"
    assert context["latest_request"].startswith("请优先测试")


def test_latest_explicit_task_instruction_overrides_previous_instruction():
    first = build_decision_context({}, "跳过 XSS 扫描。", version=1)
    second = build_decision_context(first, "改为执行 XSS 扫描。", version=2)

    requested = {item["task"] for item in second["requested_tasks"]}
    excluded = {item["task"] for item in second["excluded_tasks"]}

    assert "xss_scan" in requested
    assert "xss_scan" not in excluded
    assert second["version"] == 2
    assert len(second["messages"]) == 2


@pytest.mark.asyncio
async def test_paused_websocket_chat_persists_structured_context():
    session_id = "decision-context-integration"
    state = create_initial_state("https://example.com", task_id=session_id)
    state = update_state(
        state,
        scan_status="paused_for_chat",
        pause_info={"pause_id": "pause-test"},
    )
    memory_store.save_session(session_id, state)

    manager = AIChatManager()
    manager.connections[session_id] = AsyncMock()
    manager.chat_client = MagicMock()
    manager.chat_client.chat.completions.create = AsyncMock(
        return_value=type(
            "Response",
            (),
            {"choices": [type("Choice", (), {"message": type("Message", (), {"content": "收到，稍后按要求调整扫描。"})()})()]},
        )()
    )

    try:
        await manager._handle_chat(
            session_id,
            {"content": "请优先执行 XSS，跳过弱口令，保持低风险。", "pause_id": "pause-test"},
        )
        stored = memory_store.get_session(session_id)
        requested = {item["task"] for item in stored["decision_context"]["requested_tasks"]}
        excluded = {item["task"] for item in stored["decision_context"]["excluded_tasks"]}
        assert "xss_scan" in requested
        assert "weakpass_scan" in excluded
        assert stored["decision_context"]["risk_tolerance"] == "low_impact"
        assert stored["decision_context_version"] == 1
        request = manager.chat_client.chat.completions.create.await_args.kwargs
        assert request["max_tokens"] == settings.CHAT_MAX_TOKENS
        assert [message["role"] for message in request["messages"]].count("system") == 1
        assert "扫描上下文" in request["messages"][0]["content"]
    finally:
        memory_store.delete_session(session_id)


@pytest.mark.asyncio
async def test_ai_decision_replanning_filters_exclusions_and_prioritizes_requests():
    state = create_initial_state("https://example.com", task_id="ai-decision-replan")
    state.update({
        "mode": "full_scan",
        "websocket_session_id": "ai-decision-replan",
        "user_choice": "resume_after_chat",
        "decision_context": {
            "version": 1,
            "requested_tasks": [{"task": "xss_scan"}],
            "priority_tasks": ["xss_scan"],
            "excluded_tasks": [{"task": "port_scan"}],
            "user_constraints": [],
            "messages": [],
        },
    })
    llm = MagicMock()
    llm.invoke.return_value = MagicMock(
        content="Thought: 用户要求优先测试 XSS\nAction: port_scan\nReason: 默认顺序"
    )

    with patch("TOSKill.AI.graph.get_scan_strategy", return_value=""), \
         patch("TOSKill.AI.graph.get_llm", return_value=llm), \
         patch("TOSKill.AI.graph.memory_store.get_websocket_callback", return_value=None):
        result = await ai_decision(state)

    assert result["next_task"] == "xss_scan"
    assert "port_scan" in result["skipped_tasks"]
    assert result["decision_history"][-1]["decision_source"] == "structured_context"
