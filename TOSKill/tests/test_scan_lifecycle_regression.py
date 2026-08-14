import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from TOSKill.AI.graph import AgentOrchestrator, MemoryStore, memory_store, router
from TOSKill.AI.state import create_initial_state, update_state
from TOSKill.api.ai_chat_websocket import AIChatManager
from TOSKill.api.scan_api import ToolExecuteRequest, _execute_tools_async, api_execute_tool
from TOSKill.config import settings


class _RunningTask:
    def done(self):
        return False


def _close_and_return_task(coro):
    """Prevent background work during handler-level regression tests."""
    coro.close()
    return _RunningTask()


def _websocket():
    websocket = AsyncMock()
    websocket.client = SimpleNamespace(host="127.0.0.1")
    return websocket


def _save_session(session_id, **updates):
    state = create_initial_state("example.com", task_id=session_id)
    if updates:
        state = update_state(state, **updates)
    memory_store.save_session(session_id, state)
    return state


@pytest.mark.asyncio
async def test_disconnect_reconnect_keeps_session_and_cancels_delayed_cleanup():
    session_id = "lifecycle-reconnect"
    manager = AIChatManager()
    websocket_one = _websocket()
    websocket_two = _websocket()
    running_task = asyncio.create_task(asyncio.sleep(60))
    manager.tasks[session_id] = running_task

    try:
        await manager.connect(websocket_one, session_id=session_id)
        manager.disconnect(session_id, websocket_one)
        cleanup_task = manager._disconnect_cleanup[session_id]

        resumed_session = await manager.connect(websocket_two, session_id=session_id)
        await asyncio.sleep(0)

        assert resumed_session == session_id
        assert manager.connections[session_id] is websocket_two
        assert cleanup_task.cancelled() or cleanup_task.done()
        connected_payload = websocket_two.send_json.call_args_list[0].args[0]["payload"]
        assert connected_payload["resumed"] is True
    finally:
        manager.disconnect(session_id, websocket_two)
        running_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await running_task
        memory_store.delete_session(session_id)


def test_service_restart_restores_session_pending_interaction_and_pause(tmp_path, monkeypatch):
    db_path = tmp_path / "restart.db"
    monkeypatch.setattr(settings, "DB_PATH", str(db_path))
    session_id = "lifecycle-restart"
    state = create_initial_state("example.com", task_id=session_id)
    state = update_state(
        state,
        run_type="interactive",
        scan_status="paused_for_chat",
        pause_info={
            "pause_id": f"{session_id}:pause:1",
            "session_id": session_id,
            "interaction_id": "interaction-1",
            "status": "paused",
        },
    )

    first_store = MemoryStore()
    second_store = None
    try:
        first_store.save_session(session_id, state)
        first_store.append_chat(session_id, "user", "优先检查登录接口")
        first_store.set_pending_interaction(
            session_id,
            {"type": "interaction_required", "interaction_id": "interaction-1"},
        )
        assert first_store.save_scan_pause(session_id, state["pause_info"])
    finally:
        first_store.stop_cleanup_task()

    try:
        second_store = MemoryStore()
        restored = second_store.get_session(session_id)
        assert restored is not None
        assert restored["scan_status"] == "paused_for_chat"
        assert restored["pause_info"]["pause_id"] == f"{session_id}:pause:1"
        assert second_store.get_pending_interaction(session_id)["interaction_id"] == "interaction-1"
        assert second_store.get_chat_history(session_id)[-1]["content"] == "优先检查登录接口"
        assert second_store.get_scan_pause(f"{session_id}:pause:1")["status"] == "paused"
    finally:
        if second_store is not None:
            second_store.stop_cleanup_task()


@pytest.mark.asyncio
async def test_duplicate_interactive_start_is_rejected_without_second_task():
    session_id = "lifecycle-duplicate-start"
    manager = AIChatManager()
    manager._send = AsyncMock()
    created_tasks = []

    def fake_create_task(coro):
        task = _close_and_return_task(coro)
        created_tasks.append(task)
        return task

    try:
        with patch("TOSKill.api.ai_chat_websocket.asyncio.create_task", side_effect=fake_create_task):
            await manager._handle_start_scan(
                session_id,
                {"target": "example.com", "scan_mode": "full"},
            )
            await manager._handle_start_scan(
                session_id,
                {"target": "example.com", "scan_mode": "full"},
            )

        assert len(created_tasks) == 1
        error_messages = [
            call.args[1]
            for call in manager._send.call_args_list
            if len(call.args) > 1 and call.args[1].get("type") == "error"
        ]
        assert error_messages
        assert error_messages[-1]["payload"]["code"] == "SCAN_ALREADY_RUNNING"
    finally:
        memory_store.delete_session(session_id)


@pytest.mark.asyncio
async def test_duplicate_pause_requests_reuse_one_pause_id():
    session_id = "lifecycle-duplicate-pause"
    manager = AIChatManager()
    manager._send_multi = AsyncMock()
    state = create_initial_state("example.com", task_id=session_id)
    state = update_state(state, run_type="interactive", workflow_node="user_interact")
    memory_store.save_session(session_id, state)
    memory_store.set_pending_interaction(
        session_id,
        {
            "type": "interaction_required",
            "interaction_id": "interaction-1",
            "payload": {"next_task": "baseinfo_scan"},
        },
    )

    try:
        payload = {"request_id": "pause-request", "interaction_id": "interaction-1"}
        await asyncio.gather(
            manager._handle_pause_for_chat(session_id, payload),
            manager._handle_pause_for_chat(session_id, payload),
        )

        stored = memory_store.get_session(session_id)
        assert stored["scan_status"] == "paused_for_chat"
        pause_ids = {
            call.args[1]["payload"]["pause_id"]
            for call in manager._send_multi.call_args_list
            if call.args[1].get("type") == "scan_paused_for_chat"
        }
        assert pause_ids == {stored["pause_info"]["pause_id"]}
    finally:
        memory_store.delete_session(session_id)


@pytest.mark.asyncio
async def test_duplicate_resume_requests_execute_workflow_once():
    session_id = "lifecycle-duplicate-resume"
    manager = AIChatManager()
    manager._send_multi = AsyncMock()
    pause_id = f"{session_id}:pause:1"
    _save_session(
        session_id,
        run_type="interactive",
        scan_status="paused_for_chat",
        pause_info={"pause_id": pause_id, "session_id": session_id, "status": "paused"},
    )
    orchestrator = MagicMock()
    orchestrator._ensure_initialized = AsyncMock()

    async def resume_once(*_args, **_kwargs):
        await asyncio.sleep(0.01)
        return {}

    orchestrator.resume_workflow = AsyncMock(side_effect=resume_once)

    try:
        with patch("TOSKill.api.ai_chat_websocket.get_agent_orchestrator", return_value=orchestrator):
            await asyncio.gather(
                manager._handle_resume_scan(session_id, {"pause_id": pause_id, "request_id": "resume-1"}),
                manager._handle_resume_scan(session_id, {"pause_id": pause_id, "request_id": "resume-2"}),
            )

        orchestrator.resume_workflow.assert_awaited_once()
        assert memory_store.get_session(session_id)["scan_status"] == "running"
    finally:
        memory_store.delete_session(session_id)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("scan_mode", "expected_mode"),
    [("info", "info_collection"), ("vuln", "vuln_scan"), ("full", "full_scan")],
)
async def test_console_interactive_mode_regression(scan_mode, expected_mode):
    session_id = f"lifecycle-console-{scan_mode}"
    manager = AIChatManager()
    try:
        with patch(
            "TOSKill.api.ai_chat_websocket.asyncio.create_task",
            side_effect=_close_and_return_task,
        ):
            await manager._handle_start_scan(
                session_id,
                {"target": "example.com", "scan_mode": scan_mode},
            )
        state = memory_store.get_session(session_id)
        assert state["mode"] == expected_mode
        assert state["report_type"] == expected_mode
        assert state["run_type"] == "interactive"
        assert manager.run_types[session_id] == "interactive"
    finally:
        memory_store.delete_session(session_id)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("scan_mode", "expected_mode"),
    [("info", "info_collection"), ("vuln", "vuln_scan"), ("full", "full_scan")],
)
async def test_scan_view_automatic_mode_regression(scan_mode, expected_mode):
    session_id = f"lifecycle-auto-{scan_mode}"
    manager = AIChatManager()
    try:
        with patch(
            "TOSKill.api.ai_chat_websocket.asyncio.create_task",
            side_effect=_close_and_return_task,
        ):
            await manager._handle_start_auto_scan(
                session_id,
                {"target": "example.com", "scan_mode": scan_mode},
            )
        state = memory_store.get_session(session_id)
        assert state["mode"] == expected_mode
        assert state["report_type"] == expected_mode
        assert state["run_type"] == "automatic"
        assert state["scan_status"] == "queued"
    finally:
        memory_store.delete_session(session_id)


def test_full_scan_info_stage_finishes_without_early_report():
    state = create_initial_state(
        "http://example.com",
        task_id="lifecycle-full-stage-router",
        mode="full_scan",
    )
    state = update_state(
        state,
        workflow_mode="full_scan",
        mode="info_collection",
        next_task="end",
    )

    assert state["report_type"] == "full_scan"
    assert router(state) == "phase_complete"
    assert router(update_state(state, workflow_mode="info_collection")) == "report_generation"


@pytest.mark.asyncio
async def test_full_scan_resume_continues_into_vulnerability_stage():
    session_id = "lifecycle-full-resume"
    orchestrator = AgentOrchestrator()
    orchestrator._initialized = True
    checkpoint = SimpleNamespace(values={
        "mode": "info_collection",
        "workflow_mode": "full_scan",
    })
    info_result = update_state(
        create_initial_state("http://example.com", task_id=session_id, mode="full_scan"),
        workflow_mode="full_scan",
        mode="info_collection",
        next_task="",
        is_complete=False,
    )
    vuln_result = update_state(
        info_result,
        mode="vuln_scan",
        __interrupt__=("waiting",),
    )
    orchestrator.info_graph = MagicMock(
        aget_state=AsyncMock(return_value=checkpoint),
        ainvoke=AsyncMock(return_value=info_result),
    )
    orchestrator.vuln_graph = MagicMock(
        aget_state=AsyncMock(return_value=SimpleNamespace(values={})),
        ainvoke=AsyncMock(return_value=vuln_result),
    )
    orchestrator.intent_graph = MagicMock(
        aget_state=AsyncMock(return_value=SimpleNamespace(values={})),
    )
    orchestrator.report_graph = MagicMock(ainvoke=AsyncMock())
    memory_store.save_session(session_id, info_result)

    try:
        result = await orchestrator.resume_workflow(session_id, "1")

        orchestrator.info_graph.ainvoke.assert_awaited_once()
        orchestrator.vuln_graph.ainvoke.assert_awaited_once()
        orchestrator.report_graph.ainvoke.assert_not_awaited()
        assert result["mode"] == "vuln_scan"
        assert result["__interrupt__"] == ("waiting",)
    finally:
        memory_store.delete_session(session_id)


@pytest.mark.asyncio
async def test_full_scan_vulnerability_stage_finishes_with_report():
    session_id = "lifecycle-full-report"
    orchestrator = AgentOrchestrator()
    vuln_result = update_state(
        create_initial_state("http://example.com", task_id=session_id, mode="full_scan"),
        workflow_mode="full_scan",
        mode="vuln_scan",
        is_complete=False,
    )
    report_result = update_state(
        vuln_result,
        mode="full_scan",
        is_complete=True,
        report="complete",
    )
    orchestrator.vuln_graph = MagicMock(ainvoke=AsyncMock())
    orchestrator.report_graph = MagicMock(ainvoke=AsyncMock(return_value=report_result))

    result = await orchestrator._continue_full_scan(session_id, vuln_result)

    orchestrator.vuln_graph.ainvoke.assert_not_awaited()
    orchestrator.report_graph.ainvoke.assert_awaited_once()
    assert result["is_complete"] is True
    assert result["report"] == "complete"


@pytest.mark.asyncio
async def test_tools_view_single_tool_mode_regression():
    session_id = "lifecycle-single-tool"
    manager = AIChatManager()
    manager._send = AsyncMock()
    tool = MagicMock()
    tool.invoke.return_value = {"success": True, "data": {"ok": True}}

    with patch("TOSKill.api.ai_chat_websocket.get_tool_by_name", return_value=tool):
        await manager._handle_execute_tool(
            session_id,
            {"tool_name": "baseinfo_scan", "target": "example.com"},
        )

    event_types = [call.args[1]["type"] for call in manager._send.call_args_list]
    assert event_types == ["tool_execution_started", "tool_execution_completed"]
    completed_payload = manager._send.call_args_list[-1].args[1]["payload"]
    assert completed_payload["tool_category"] == "info_collection"
    assert completed_payload["information_summary"] == [{"label": "ok", "value": "是"}]
    assert "未发现漏洞" not in completed_payload["result_summary"]
    tool.invoke.assert_called_once_with("example.com")


@pytest.mark.asyncio
async def test_tools_view_single_tool_rest_api_regression():
    tool = MagicMock()
    tool.invoke.return_value = {"success": True, "data": {"ok": True}}
    request = ToolExecuteRequest(
        tool_name="baseinfo_scan",
        target="https://example.com/",
        analyze=False,
    )

    with patch("TOSKill.api.scan_api.get_tool_by_name", return_value=tool), \
         patch("TOSKill.api.scan_api.get_analyzer") as get_analyzer:
        response = await api_execute_tool(request)

    assert response.code == 200
    assert response.data["tool_name"] == "baseinfo_scan"
    assert response.data["tool_category"] == "info_collection"
    assert response.data["success"] is True
    assert "analysis" not in response.data
    get_analyzer.assert_not_called()
    tool.invoke.assert_called_once_with("example.com")


@pytest.mark.asyncio
async def test_tools_view_rest_api_propagates_tool_failure():
    tool = MagicMock()
    tool.invoke.return_value = {
        "success": False,
        "data": {"failure_type": "provider_unavailable"},
        "error": "外部服务不可用",
    }
    request = ToolExecuteRequest(
        tool_name="webside_query_scan",
        target="https://example.com/",
        analyze=False,
    )

    with patch("TOSKill.api.scan_api.get_tool_by_name", return_value=tool):
        response = await api_execute_tool(request)

    assert response.data["success"] is False
    assert response.data["error"] == "外部服务不可用"
    assert response.data["information_summary"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("tool_name", ["sqli_scan", "xss_scan"])
async def test_vulnerability_tool_rest_api_preserves_complete_url(tool_name):
    tool = MagicMock()
    tool.invoke.return_value = {"success": True, "data": {"ok": True}}
    target = "https://example.com/search.php?q=test"
    request = ToolExecuteRequest(
        tool_name=tool_name,
        target=target,
        analyze=False,
    )

    with patch("TOSKill.api.scan_api.get_tool_by_name", return_value=tool):
        response = await api_execute_tool(request)

    assert response.code == 200
    assert response.data["target"] == target
    tool.invoke.assert_called_once_with(target)


@pytest.mark.asyncio
async def test_vulnerability_tools_in_automatic_scan_preserve_complete_url():
    sqli_tool = MagicMock(spec=["invoke"])
    xss_tool = MagicMock(spec=["invoke"])
    sqli_tool.invoke.return_value = {"success": True, "data": {}}
    xss_tool.invoke.return_value = {"success": True, "data": {}}
    tools = {"sqli_scan": sqli_tool, "xss_scan": xss_tool}
    target = "https://example.com/search.php?q=test"

    with patch(
        "TOSKill.api.scan_api.get_tool_by_name",
        side_effect=lambda name: tools[name],
    ):
        results, errors = await _execute_tools_async(target, list(tools))

    assert errors == []
    assert [result["tool"] for result in results] == ["sqli_scan", "xss_scan"]
    sqli_tool.invoke.assert_called_once_with(target)
    xss_tool.invoke.assert_called_once_with(target)
