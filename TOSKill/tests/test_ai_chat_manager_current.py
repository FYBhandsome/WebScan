"""Current AIChatManager protocol regression tests.

These tests intentionally use the fields consumed by the current frontend:
target, scan_mode, params, next_task, status and completed_tasks.
"""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.mark.asyncio
async def test_start_scan_transmits_next_task_and_queues_status():
    from TOSKill.api import ai_chat_websocket as ws_module
    from TOSKill.api.ai_chat_websocket import AIChatManager

    manager = AIChatManager()
    manager._run_scan = MagicMock()
    memory = MagicMock()
    memory.get_session.return_value = None
    task = MagicMock()

    with patch.object(ws_module, "memory_store", memory), \
         patch.object(ws_module, "_safe_set_task_status") as set_status, \
         patch("asyncio.create_task", return_value=task):
        await manager._handle_start_scan(
            "session-current",
            {
                "target": "http://testasp.vulnweb.com",
                "scan_mode": "info_collection",
                "params": {"next_task": "baseinfo_scan", "timeout": 30},
            },
        )

    saved_state = memory.save_session.call_args.args[1]
    assert saved_state["target"] == "http://testasp.vulnweb.com"
    assert saved_state["mode"] == "info_collection"
    assert saved_state["user_directed_next_task"] == "baseinfo_scan"
    assert saved_state["user_directed_params"]["timeout"] == 30
    set_status.assert_called_once()
    assert set_status.call_args.args[:2] == ("session-current", ws_module.STATUS_QUEUED)


@pytest.mark.asyncio
async def test_status_event_uses_stable_frontend_field_names():
    from TOSKill.api import ai_chat_websocket as ws_module
    from TOSKill.api.ai_chat_websocket import AIChatManager

    manager = AIChatManager()
    manager._send = AsyncMock()
    memory = MagicMock()
    memory.get_session.return_value = {
        "task_id": "session-current",
        "target": "http://testasp.vulnweb.com",
        "mode": "info_collection",
        "completed_tasks": ["baseinfo_scan"],
        "is_complete": False,
        "risk_confidence": 0.8,
    }

    with patch.object(ws_module, "memory_store", memory):
        await manager._handle_get_status("session-current", {})

    message = manager._send.await_args.args[1]
    state = message["payload"]["state"]
    assert message["type"] == "status"
    assert state["task_id"] == "session-current"
    assert state["mode"] == "info_collection"
    assert state["completed_tasks"] == ["baseinfo_scan"]
    assert state["is_complete"] is False
    assert state["risk_confidence"] == 0.8


def test_waiting_input_status_contains_structured_fields():
    from TOSKill.api import ai_chat_websocket as ws_module

    with patch.object(ws_module, "_safe_set_task_status") as set_status:
        ws_module._sync_interrupt_status(
            "session-current",
            {
                "task_status": "waiting_user_input",
                "pending_input_request": {
                    "fields": [{"name": "timeout", "type": "number", "required": True}]
                },
            },
        )

    set_status.assert_called_once()
    kwargs = set_status.call_args.kwargs
    assert kwargs["waiting_input"]["fields"][0]["name"] == "timeout"
    assert kwargs["stage"] == "等待用户输入"


def test_canonical_scan_modes_are_not_downgraded_to_info_collection():
    from TOSKill.api.ai_chat_websocket import SCAN_MODE_MAP

    assert SCAN_MODE_MAP["info_collection"] == "info_collection"
    assert SCAN_MODE_MAP["vuln_scan"] == "vuln_scan"
    assert SCAN_MODE_MAP["full_scan"] == "full_scan"


def test_execute_task_initializes_user_directed_params():
    import inspect
    from TOSKill.AI.graph import execute_task

    source = inspect.getsource(execute_task)
    assert 'user_directed_params = dict(state.get("user_directed_params", {}) or {})' in source
