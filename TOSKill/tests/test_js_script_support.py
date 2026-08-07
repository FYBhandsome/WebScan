"""
JS/Python 脚本支持回归测试。

覆盖点：
- JS 文件允许进入校验与注册链路
- JS 工具通过 Node 受控执行
- WS 脚本上传携带 language 字段
- stop_scan 进入取消态
"""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def test_validate_file_upload_accepts_js_extension():
    from TOSKill.AI.script_safety import validate_file_upload

    result = validate_file_upload("demo.js", b"function run(target){ return {success:true}; }")
    assert result.is_valid is True


def test_validate_script_full_accepts_js_when_filename_provided():
    from TOSKill.AI.script_safety import validate_script_full

    script = "function run(target) { return { success: true, target }; }"
    success, message, details = validate_script_full(script, "demo.js")
    assert success is True
    assert "通过" in message or message
    assert details.get("language") in ("js", None)


def test_normalize_legacy_js_payload_without_filename():
    from TOSKill.AI.script_safety import normalize_script_for_registration

    success, message, normalized = normalize_script_for_registration(
        "function run(target) { return { success: true, target }; }",
        script_name="legacy_js_upload",
    )
    assert success is True, message
    assert normalized.language == "js"
    assert normalized.filename.endswith(".js")


def test_register_script_as_tool_marks_js_language_and_tool_name():
    from TOSKill.AI.tools import ScriptManager

    manager = ScriptManager.get_instance()
    result = manager.register_script_as_tool(
        script_content='function run(target) { return { success: true, target: target }; } module.exports = { run };',
        script_name="demo.js",
        description="demo js tool",
        category="custom",
    )

    assert result["success"] is True
    assert result["language"] == "js"
    assert result["tool_name"].endswith("demo")
    assert result["tool"].name == result["tool_name"]


def test_python_script_still_registers_with_python_path():
    from TOSKill.AI.tools import ScriptManager

    manager = ScriptManager.get_instance()
    result = manager.register_script_as_tool(
        script_content="def run(target):\n    return {'success': True, 'target': target}\n",
        script_name="py_demo",
        description="demo py tool",
        category="custom",
    )

    assert result["success"] is True
    assert result["language"] == "py"
    assert result["tool_name"].endswith("py_demo")


@pytest.mark.asyncio
async def test_ws_script_upload_transmits_language_for_js():
    from TOSKill.api.ai_chat_websocket import AIChatManager
    import TOSKill.api.ai_chat_websocket as ws_module

    manager = AIChatManager()
    manager._send = AsyncMock()

    with patch("TOSKill.AI.tools.script_manager") as script_manager, \
         patch.object(ws_module, "get_agent_orchestrator") as get_orchestrator:
        script_manager.analyze_script_with_ai = AsyncMock(return_value={"tool_name": "demo", "description": "demo", "category": "custom"})
        script_manager.register_script_as_tool.return_value = {
            "success": True,
            "tool_name": "demo",
            "language": "js",
        }
        orchestrator = MagicMock()
        orchestrator._ensure_initialized = AsyncMock()
        orchestrator.resume_workflow = AsyncMock(return_value={"is_complete": True})
        get_orchestrator.return_value = orchestrator

        await manager._handle_script_content(
            "session-js",
            {
                "script_content": "function run(target) { return { success: true, target }; }",
                "script_name": "demo.js",
                "filename": "demo.js",
                "language": "js",
            },
        )

    called_kwargs = script_manager.register_script_as_tool.call_args.kwargs
    assert called_kwargs["script_name"].endswith(".js")
    registered_msg = [call.args[1] for call in manager._send.await_args_list if call.args[1]["type"] == "script_registered"][0]
    assert registered_msg["payload"]["language"] == "js"


@pytest.mark.asyncio
async def test_stop_scan_marks_cancelled_and_sets_stop_requested():
    from TOSKill.api.ai_chat_websocket import AIChatManager
    import TOSKill.api.ai_chat_websocket as ws_module

    manager = AIChatManager()
    manager._send = AsyncMock()
    task = MagicMock()
    task.done.return_value = False
    task.cancel = MagicMock()
    manager.tasks["session-stop"] = task

    state = {
        "task_id": "session-stop",
        "should_continue": True,
        "is_complete": False,
    }
    memory = MagicMock()
    memory.get_session.return_value = state

    with patch.object(ws_module, "memory_store", memory), \
         patch.object(ws_module, "_safe_set_task_status") as set_status:
        await manager._handle_stop_scan("session-stop", {})

    saved_state = memory.save_session.call_args.args[1]
    assert saved_state["stop_requested"] is True
    assert saved_state["task_status"] == "cancelled"
    assert task.cancel.called
    assert any(call.args[1]["type"] == "scan_cancelled" for call in manager._send.await_args_list)
    assert set_status.called
