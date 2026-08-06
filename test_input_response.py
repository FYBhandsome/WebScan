"""SubTask 2.4 自测：_handle_input_response 多字段结构化响应 + resume 恢复调度

验证：
1. 纯函数 _parse_input_fields / _apply_input_to_state
2. _handle_input_response 提交多字段后：state 回填 user_directed_params / extracted_params、
   chat_history 追加、resume_workflow 以 {"params": {...}} 调用、返回 input_received 消息
3. 旧单字段格式 {field, value} 向下兼容
4. 空 fields 返回 EMPTY_FIELDS 错误
5. resume 失败不崩溃，返回 RESUME_FAILED 错误
6. 中断结果同步 waiting_user_input 状态到 TaskStatusStore
"""
import asyncio
import sys
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, "d:/AI_WebSecurity")

from TOSKill.api.ai_chat_websocket import (  # noqa: E402
    AIChatManager,
    _parse_input_fields,
    _apply_input_to_state,
)
from TOSKill.AI.task_status_store import (  # noqa: E402
    STATUS_COMPLETED,
    STATUS_EXCEPTION,
    STATUS_WAITING_USER_INPUT,
    STATUS_RUNNING,
)

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}  {detail}")


# ── 1. 纯函数 _parse_input_fields ────────────────────────────────
def test_parse_input_fields():
    print("\n=== test_parse_input_fields ===")
    # 新多字段格式
    r = _parse_input_fields({"fields": [
        {"field": "dvwa_base_url", "value": "http://127.0.0.1:8080/setup.php"},
        {"field": "cookie", "value": "abc=1"},
    ]})
    check("多字段解析长度", len(r) == 2, r)
    check("多字段解析内容", r[0]["field"] == "dvwa_base_url" and r[0]["value"] == "http://127.0.0.1:8080/setup.php", r)

    # 旧单字段格式
    r2 = _parse_input_fields({"field": "x", "value": "y"})
    check("旧单字段兼容", r2 == [{"field": "x", "value": "y"}], r2)

    # 空
    check("空 fields 列表", _parse_input_fields({"fields": []}) == [])
    check("缺 fields 缺 field", _parse_input_fields({}) == [])
    check("过滤无 field 项", _parse_input_fields({"fields": [{"field": "", "value": "z"}, {"field": "a", "value": "b"}]}) == [{"field": "a", "value": "b"}])


# ── 2. 纯函数 _apply_input_to_state ───────────────────────────────
def test_apply_input_to_state():
    print("\n=== test_apply_input_to_state ===")
    state = {"target": "t", "user_directed_params": {"old": "1"}, "extracted_params": {}}
    new = _apply_input_to_state(state, {"dvwa_base_url": "http://x"})
    check("user_directed_params 合并", new["user_directed_params"] == {"old": "1", "dvwa_base_url": "http://x"}, new["user_directed_params"])
    check("extracted_params 合并", new["extracted_params"] == {"dvwa_base_url": "http://x"}, new["extracted_params"])
    check("不修改原 state（浅拷贝）", state["user_directed_params"] == {"old": "1"})
    check("空 params 原样返回", _apply_input_to_state(state, {}) is state)


# ── 3. _handle_input_response 多字段 + resume + 完成 ─────────────
async def test_handle_input_response_multifield():
    print("\n=== test_handle_input_response_multifield ===")
    mgr = AIChatManager()
    sent = []
    mgr._send = AsyncMock(side_effect=lambda sid, msg: sent.append(msg))
    mgr._send_error = AsyncMock(side_effect=lambda sid, err, **kw: sent.append({"_error": err, "_code": kw.get("error_code")}))

    state = {"task_id": "s1", "target": "t", "user_directed_params": {}, "extracted_params": {}}
    saved_states = []
    chat_appends = []

    mm = MagicMock()
    mm.get_session = MagicMock(return_value=dict(state))
    mm.append_chat = MagicMock(side_effect=lambda sid, role, content: chat_appends.append((role, content)))
    mm.save_session = MagicMock(side_effect=lambda sid, s: saved_states.append(s))

    orch = MagicMock()
    orch._ensure_initialized = AsyncMock()
    resume_result = {"is_complete": True, "target": "t", "completed_tasks": ["a"], "vulnerabilities": [{"id": 1}], "report": "r"}
    orch.resume_workflow = AsyncMock(return_value=resume_result)

    status_calls = []
    with patch("TOSKill.api.ai_chat_websocket.memory_store", mm), \
         patch("TOSKill.api.ai_chat_websocket.get_agent_orchestrator", return_value=orch), \
         patch("TOSKill.api.ai_chat_websocket._safe_set_task_status", side_effect=lambda tid, st, **kw: status_calls.append((st, kw))):
        await mgr._handle_input_response("s1", {"fields": [
            {"field": "dvwa_base_url", "value": "http://127.0.0.1:8080/setup.php"}
        ]})

    # resume 调用参数
    check("resume_workflow 被调用", orch.resume_workflow.called)
    call_args = orch.resume_workflow.call_args
    check("resume 传入 session_id", call_args.args[0] == "s1", call_args.args)
    check("resume 传入 {params:{...}} 格式", call_args.args[1] == {"params": {"dvwa_base_url": "http://127.0.0.1:8080/setup.php"}}, str(call_args.args))

    # chat_history 追加
    check("append_chat 被调用", len(chat_appends) == 1, chat_appends)
    check("append_chat role=user", chat_appends[0][0] == "user")
    check("append_chat 含参数名", "dvwa_base_url" in chat_appends[0][1])

    # state 回填
    check("save_session 被调用", len(saved_states) == 1, saved_states)
    check("user_directed_params 含 dvwa_base_url",
          saved_states[0].get("user_directed_params", {}).get("dvwa_base_url") == "http://127.0.0.1:8080/setup.php",
          saved_states[0].get("user_directed_params"))
    check("extracted_params 含 dvwa_base_url",
          saved_states[0].get("extracted_params", {}).get("dvwa_base_url") == "http://127.0.0.1:8080/setup.php")

    # 消息
    input_msg = next((m for m in sent if m.get("type") == "input_received"), None)
    check("返回 input_received 消息", input_msg is not None, sent)
    check("input_received 含 fields", input_msg and input_msg["payload"].get("fields") == [{"field": "dvwa_base_url", "value": "http://127.0.0.1:8080/setup.php"}])
    check("input_received resumed=True", input_msg and input_msg["payload"].get("resumed") is True)

    # 完成消息（is_complete）
    comp_msg = next((m for m in sent if m.get("type") == "scan_completed"), None)
    check("is_complete 推送 scan_completed", comp_msg is not None, sent)

    # 状态同步
    check("set_status 写 COMPLETED", any(st == STATUS_COMPLETED for st, _ in status_calls), status_calls)


# ── 4. 旧单字段格式兼容 ───────────────────────────────────────────
async def test_handle_input_response_legacy_single_field():
    print("\n=== test_handle_input_response_legacy_single_field ===")
    mgr = AIChatManager()
    sent = []
    mgr._send = AsyncMock(side_effect=lambda sid, msg: sent.append(msg))
    mgr._send_error = AsyncMock(side_effect=lambda sid, err, **kw: sent.append({"_error": err}))

    mm = MagicMock()
    mm.get_session = MagicMock(return_value={"task_id": "s2", "user_directed_params": {}, "extracted_params": {}})
    mm.append_chat = MagicMock()
    mm.save_session = MagicMock()

    orch = MagicMock()
    orch._ensure_initialized = AsyncMock()
    orch.resume_workflow = AsyncMock(return_value={"is_complete": False})

    with patch("TOSKill.api.ai_chat_websocket.memory_store", mm), \
         patch("TOSKill.api.ai_chat_websocket.get_agent_orchestrator", return_value=orch), \
         patch("TOSKill.api.ai_chat_websocket._safe_set_task_status"):
        await mgr._handle_input_response("s2", {"field": "x", "value": "y"})

    check("旧格式 resume 传 {params:{x:y}}", orch.resume_workflow.call_args.args[1] == {"params": {"x": "y"}}, str(orch.resume_workflow.call_args.args))
    saved = mm.save_session.call_args.args[1]
    check("旧格式 state 含 x", saved["user_directed_params"].get("x") == "y", saved.get("user_directed_params"))
    input_msg = next((m for m in sent if m.get("type") == "input_received"), None)
    check("旧格式返回 input_received", input_msg is not None, sent)


# ── 5. 空 fields 错误 ─────────────────────────────────────────────
async def test_handle_input_response_empty_fields():
    print("\n=== test_handle_input_response_empty_fields ===")
    mgr = AIChatManager()
    sent = []
    mgr._send = AsyncMock(side_effect=lambda sid, msg: sent.append(msg))
    mgr._send_error = AsyncMock(side_effect=lambda sid, err, **kw: sent.append({"_error": err, "_code": kw.get("error_code")}))

    mm = MagicMock()
    mm.get_session = MagicMock(return_value={})
    mm.append_chat = MagicMock()
    mm.save_session = MagicMock()
    orch = MagicMock()
    orch.resume_workflow = AsyncMock()

    with patch("TOSKill.api.ai_chat_websocket.memory_store", mm), \
         patch("TOSKill.api.ai_chat_websocket.get_agent_orchestrator", return_value=orch):
        await mgr._handle_input_response("s3", {"fields": []})

    check("空 fields 调用 _send_error", any(m.get("_error") for m in sent), sent)
    check("空 fields 错误码 EMPTY_FIELDS", any(m.get("_code") == "EMPTY_FIELDS" for m in sent), sent)
    check("空 fields 不调用 resume", not orch.resume_workflow.called)


# ── 6. resume 失败不崩溃 ──────────────────────────────────────────
async def test_handle_input_response_resume_failure():
    print("\n=== test_handle_input_response_resume_failure ===")
    mgr = AIChatManager()
    sent = []
    mgr._send = AsyncMock(side_effect=lambda sid, msg: sent.append(msg))
    mgr._send_error = AsyncMock(side_effect=lambda sid, err, **kw: sent.append({"_error": err, "_code": kw.get("error_code")}))

    mm = MagicMock()
    mm.get_session = MagicMock(return_value={"user_directed_params": {}, "extracted_params": {}})
    mm.append_chat = MagicMock()
    mm.save_session = MagicMock()
    orch = MagicMock()
    orch._ensure_initialized = AsyncMock()
    orch.resume_workflow = AsyncMock(side_effect=RuntimeError("boom"))

    status_calls = []
    with patch("TOSKill.api.ai_chat_websocket.memory_store", mm), \
         patch("TOSKill.api.ai_chat_websocket.get_agent_orchestrator", return_value=orch), \
         patch("TOSKill.api.ai_chat_websocket._safe_set_task_status", side_effect=lambda tid, st, **kw: status_calls.append(st)):
        await mgr._handle_input_response("s4", {"fields": [{"field": "a", "value": "b"}]})

    check("resume 失败返回错误", any(m.get("_error") for m in sent), sent)
    check("resume 失败错误码 RESUME_FAILED", any(m.get("_code") == "RESUME_FAILED" for m in sent), sent)
    check("resume 失败写 EXCEPTION 状态", STATUS_EXCEPTION in status_calls, status_calls)


# ── 7. 中断结果同步 waiting_user_input ────────────────────────────
async def test_handle_input_response_interrupt_status():
    print("\n=== test_handle_input_response_interrupt_status ===")
    mgr = AIChatManager()
    sent = []
    mgr._send = AsyncMock(side_effect=lambda sid, msg: sent.append(msg))
    mgr._send_error = AsyncMock()

    mm = MagicMock()
    mm.get_session = MagicMock(return_value={"user_directed_params": {}, "extracted_params": {}})
    mm.append_chat = MagicMock()
    mm.save_session = MagicMock()
    orch = MagicMock()
    orch._ensure_initialized = AsyncMock()
    orch.resume_workflow = AsyncMock(return_value={
        "__interrupt__": True,
        "task_status": "waiting_user_input",
        "pending_input_request": {"fields": [{"name": "dvwa_base_url"}]},
    })

    status_calls = []
    with patch("TOSKill.api.ai_chat_websocket.memory_store", mm), \
         patch("TOSKill.api.ai_chat_websocket.get_agent_orchestrator", return_value=orch), \
         patch("TOSKill.api.ai_chat_websocket._safe_set_task_status", side_effect=lambda tid, st, **kw: status_calls.append((st, kw))):
        await mgr._handle_input_response("s5", {"fields": [{"field": "dvwa_base_url", "value": "http://x"}]})

    check("中断写 waiting_user_input", any(st == STATUS_WAITING_USER_INPUT for st, _ in status_calls), status_calls)
    check("中断 waiting_input 含 fields", any(kw.get("waiting_input", {}).get("fields") for st, kw in status_calls if st == STATUS_WAITING_USER_INPUT), status_calls)
    check("中断不写 COMPLETED", not any(st == STATUS_COMPLETED for st, _ in status_calls), status_calls)


async def main():
    test_parse_input_fields()
    test_apply_input_to_state()
    await test_handle_input_response_multifield()
    await test_handle_input_response_legacy_single_field()
    await test_handle_input_response_empty_fields()
    await test_handle_input_response_resume_failure()
    await test_handle_input_response_interrupt_status()

    print(f"\n{'='*50}")
    print(f"结果: {PASS} passed, {FAIL} failed")
    print(f"{'='*50}")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
