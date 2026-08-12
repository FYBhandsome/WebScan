from unittest.mock import AsyncMock

import pytest

from TOSKill.AI.graph import AgentOrchestrator, memory_store
from TOSKill.AI.state import create_initial_state


@pytest.fixture(autouse=True)
def clear_scan_state():
    memory_store._sessions.clear()
    memory_store._websocket_callbacks.clear()
    yield
    memory_store._sessions.clear()
    memory_store._websocket_callbacks.clear()


@pytest.mark.asyncio
async def test_sequential_scans_in_one_conversation_use_distinct_checkpoint_threads():
    orchestrator = AgentOrchestrator()
    orchestrator._initialized = True
    orchestrator.info_graph = AsyncMock()
    orchestrator.info_graph.ainvoke.side_effect = lambda state, config: state

    first = create_initial_state("first.example", task_id="same-session")
    first["websocket_session_id"] = "same-session"
    first["run_id"] = "same-session:first-run"

    second = create_initial_state("second.example", task_id="same-session")
    second["websocket_session_id"] = "same-session"
    second["run_id"] = "same-session:second-run"

    await orchestrator.run_info_collection(first)
    await orchestrator.run_info_collection(second)

    configs = [call.kwargs["config"] for call in orchestrator.info_graph.ainvoke.await_args_list]
    assert configs == [
        {"configurable": {"thread_id": "same-session:first-run"}},
        {"configurable": {"thread_id": "same-session:second-run"}},
    ]


@pytest.mark.asyncio
async def test_resume_uses_the_active_runs_checkpoint_thread():
    orchestrator = AgentOrchestrator()
    orchestrator._initialized = True
    orchestrator.info_graph = AsyncMock()
    orchestrator.info_graph.aget_state.return_value = None
    orchestrator.info_graph.ainvoke.return_value = {
        "task_id": "same-session",
        "run_id": "same-session:active-run",
        "mode": "info_collection",
        "is_complete": True,
    }
    orchestrator.vuln_graph = AsyncMock()
    orchestrator.vuln_graph.aget_state.return_value = None
    orchestrator.intent_graph = AsyncMock()
    orchestrator.intent_graph.aget_state.return_value = None

    state = create_initial_state("active.example", task_id="same-session")
    state["websocket_session_id"] = "same-session"
    state["run_id"] = "same-session:active-run"
    memory_store.save_session("same-session", state)

    await orchestrator.resume_workflow("same-session", "continue")

    expected = {"configurable": {"thread_id": "same-session:active-run"}}
    orchestrator.info_graph.aget_state.assert_awaited_with(expected)
    assert orchestrator.info_graph.ainvoke.await_args.kwargs["config"] == expected
