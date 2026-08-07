"""Focused regression tests for the no_fallback_strict decision contract."""

import asyncio

from TOSKill.AI import graph
from TOSKill.AI.state import create_initial_state


def test_initial_state_disables_fallback():
    state = create_initial_state("http://127.0.0.1:8080", mode="full_scan")
    assert state["fallback_rule_set"] is None
    assert state["enable_fallback"] is False
    assert state["repair_required"] is False
    assert state["exec_script"] == ""
    assert graph.get_fallback_tools("sqli_scan") == []


def test_ai_decision_failure_enters_repair(monkeypatch):
    state = create_initial_state("http://127.0.0.1:8080", mode="full_scan")
    state["task_id"] = "strict-decision-test"

    monkeypatch.setattr(graph, "get_scan_strategy", lambda **_: "")

    def fail_llm():
        raise RuntimeError("simulated model outage")

    monkeypatch.setattr(graph, "get_llm", fail_llm)
    result = asyncio.run(graph.ai_decision(state))

    assert result["repair_required"] is True
    assert result["task_status"] == "repair_required"
    assert result["fallback_rule_set"] is None
    assert result["enable_fallback"] is False
    assert result["exec_script"] == ""
    assert result["next_task"] == ""
    assert result["repair_prompt_info"]["mode"] == "no_fallback_strict"


def test_state_updates_preserve_cross_node_fields():
    from TOSKill.AI.state import update_state

    state = update_state({"task_id": "state-flow", "target": "http://example.test"})
    state = update_state(
        state,
        next_task="xss_scan",
        user_directed_params={"timeout": 10},
        task_result={"success": True},
    )
    assert state["target"] == "http://example.test"
    assert state["next_task"] == "xss_scan"
    assert state["user_directed_params"]["timeout"] == 10
    assert state["task_result"]["success"] is True
    assert state["history_context"] == {}
    assert state["fallback_rule_set"] is None
    assert state["enable_fallback"] is False


def test_memory_store_update_is_persisted():
    from TOSKill.AI.graph import memory_store

    session_id = "state-persist-strict"
    memory_store.save_session(session_id, create_initial_state("http://example.test"))
    before = memory_store.get_session_version(session_id)
    memory_store.update_session(session_id, task_status="running", next_task="xss_scan")
    state = memory_store.get_session(session_id)
    assert state["task_status"] == "running"
    assert state["next_task"] == "xss_scan"
    assert state["_version"] > before
    assert state["fallback_rule_set"] is None
    memory_store.delete_session(session_id)
