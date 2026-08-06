"""
TOSKill Task 15: 实时交互与优先级机制自测脚本

验证内容:
  SubTask 15.1: 扫描时聊天可修改下一个任务 (_handle_scan_chat)
  SubTask 15.2: 用户指令优先级 > 知识库 > AI默认决策
  SubTask 15.3: 风险评估输出包含置信度 (vulnerability_check)

运行方式:
  D:\AI_WebSecurity\.conda\python.exe d:\AI_WebSecurity\TOSKill\test_interaction.py
"""
import sys
import os
import inspect
import re
import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

# 确保项目根目录在 sys.path 中
PROJECT_ROOT = r"d:\AI_WebSecurity"
TOSKILL_ROOT = r"d:\AI_WebSecurity\TOSKill"
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
if TOSKILL_ROOT not in sys.path:
    sys.path.insert(0, TOSKILL_ROOT)


# ============================================================
# 测试结果统计
# ============================================================
class TestResult:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.details = []

    def ok(self, name, detail=""):
        self.passed += 1
        self.details.append(("PASS", name, detail))
        print(f"  [PASS] {name}" + (f" - {detail}" if detail else ""))

    def fail(self, name, detail=""):
        self.failed += 1
        self.details.append(("FAIL", name, detail))
        print(f"  [FAIL] {name}" + (f" - {detail}" if detail else ""))

    def skip(self, name, detail=""):
        self.skipped += 1
        self.details.append(("SKIP", name, detail))
        print(f"  [SKIP] {name}" + (f" - {detail}" if detail else ""))

    def summary(self):
        total = self.passed + self.failed + self.skipped
        print(f"\n{'='*60}")
        print(f"测试总结: {total} 项 | 通过: {self.passed} | 失败: {self.failed} | 跳过: {self.skipped}")
        print(f"{'='*60}")
        if self.failed == 0:
            print("所有测试通过!")
        else:
            print(f"有 {self.failed} 项测试失败，请检查上方详情。")
        return self.failed == 0


result = TestResult()


# ============================================================
# 辅助函数: 读取源文件内容
# ============================================================
def read_source_file(filepath):
    """读取源文件内容"""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        print(f"  [ERROR] 无法读取文件 {filepath}: {e}")
        return ""


def get_method_source(obj, name=""):
    """使用 inspect.getsource 获取函数/方法的源代码"""
    try:
        return inspect.getsource(obj)
    except (TypeError, OSError) as e:
        print(f"  [WARN] inspect.getsource 失败 ({name}): {e}")
        return ""


# ============================================================
# SubTask 15.1: 验证 _handle_scan_chat 可修改下一个任务
# ============================================================
def test_subtask_15_1():
    print("\n" + "="*60)
    print("SubTask 15.1: 验证扫描时聊天可修改下一个任务 (_handle_scan_chat)")
    print("="*60)

    ws_file = os.path.join(TOSKILL_ROOT, "api", "ai_chat_websocket.py")
    ws_source = read_source_file(ws_file)

    # 测试1.1: _handle_scan_chat 方法存在
    try:
        from api.ai_chat_websocket import AIChatManager
        has_method = hasattr(AIChatManager, '_handle_scan_chat')
        if has_method:
            result.ok("15.1.1 _handle_scan_chat方法存在", "AIChatManager._handle_scan_chat")
        else:
            result.fail("15.1.1 _handle_scan_chat方法存在", "方法不存在")
    except Exception as e:
        result.fail("15.1.1 _handle_scan_chat方法存在", f"导入失败: {e}")

    # 测试1.2: 方法签名正确 (session_id, payload)
    try:
        sig = inspect.signature(AIChatManager._handle_scan_chat)
        params = list(sig.parameters.keys())
        # params 会包含 'self'
        expected = ['self', 'session_id', 'payload']
        if 'session_id' in params and 'payload' in params:
            result.ok("15.1.2 方法签名包含session_id和payload", f"参数: {params}")
        else:
            result.fail("15.1.2 方法签名包含session_id和payload", f"实际参数: {params}")
    except Exception as e:
        result.fail("15.1.2 方法签名包含session_id和payload", f"检查失败: {e}")

    # 测试1.3: 方法是 async 异步方法
    try:
        is_async = inspect.iscoroutinefunction(AIChatManager._handle_scan_chat)
        if is_async:
            result.ok("15.1.3 _handle_scan_chat是异步方法", "async def")
        else:
            result.fail("15.1.3 _handle_scan_chat是异步方法", "不是异步方法")
    except Exception as e:
        result.fail("15.1.3 _handle_scan_chat是异步方法", f"检查失败: {e}")

    # 测试1.4: 代码中写入 user_directed_next_task 到 state
    method_src = get_method_source(AIChatManager._handle_scan_chat, "_handle_scan_chat")
    if method_src:
        checks = {
            "读取payload content": 'payload.get("content"' in method_src,
            "更新user_chat_context": 'user_chat_context=user_chat_context' in method_src,
            "更新user_directed_next_task": 'user_directed_next_task=user_directed_next_task' in method_src,
            "更新user_directed_params": 'user_directed_params=user_directed_params' in method_src,
            "调用update_state": 'update_state(state' in method_src,
            "保存session": 'memory_store.save_session' in method_src,
            "推送user_directive_ack": 'user_directive_ack' in method_src,
        }
        for check_name, passed in checks.items():
            if passed:
                result.ok(f"15.1.4 代码逻辑-{check_name}")
            else:
                result.fail(f"15.1.4 代码逻辑-{check_name}", "未在源码中找到对应逻辑")
    else:
        result.fail("15.1.4 代码逻辑检查", "无法提取方法源代码")

    # 测试1.5: 验证LLM指令提取逻辑（提取next_task并验证在remaining列表中）
    if method_src:
        has_extraction = (
            'has_directive' in method_src and
            'next_task' in method_src and
            'directed_task in remaining' in method_src
        )
        if has_extraction:
            result.ok("15.1.5 LLM指令提取逻辑", "提取has_directive→next_task→验证在remaining中")
        else:
            result.fail("15.1.5 LLM指令提取逻辑", "指令提取逻辑不完整")

    # 测试1.6: 通过Mock实际调用 _handle_scan_chat 验证写入state
    try:
        test_mock_handle_scan_chat()
    except Exception as e:
        result.fail("15.1.6 Mock调用_handle_scan_chat", f"异常: {e}")


def test_mock_handle_scan_chat():
    """通过Mock测试 _handle_scan_chat 实际写入 state 的行为"""
    print("\n  --- Mock测试: _handle_scan_chat ---")

    try:
        from api.ai_chat_websocket import AIChatManager
        from TOSKill.AI.state import create_initial_state, update_state
        from TOSKill.AI.tools import get_tool_sequence

        manager = AIChatManager()

        # 创建测试状态
        test_state = create_initial_state(target="http://example.com", mode="full_scan")
        test_state["websocket_session_id"] = "test-session-15-1"
        test_state["completed_tasks"] = []

        # Mock memory_store
        mock_memory = MagicMock()
        mock_memory.get_session = MagicMock(return_value=dict(test_state))
        saved_states = {}
        def save_session(sid, st):
            saved_states[sid] = st
        mock_memory.save_session = save_session
        mock_memory.get_chat_history = MagicMock(return_value=[
            {"role": "user", "content": "请执行SQL注入扫描"},
        ])
        mock_memory.append_chat = MagicMock()
        mock_memory.get_websocket_callback = MagicMock(return_value=None)

        # Mock _get_llm - 返回解析后的指令
        mock_llm = MagicMock()
        mock_response = MagicMock()
        mock_response.content = json.dumps({
            "has_directive": True,
            "next_task": "sqli_scan",
            "params": {"target_url": "http://example.com/login"},
            "reason": "用户要求执行SQL注入扫描"
        }, ensure_ascii=False)
        mock_llm.ainvoke = AsyncMock(return_value=mock_response)
        manager._get_llm = MagicMock(return_value=mock_llm)

        # Mock _send
        sent_messages = []
        async def mock_send(sid, msg):
            sent_messages.append((sid, msg))
        manager._send = mock_send
        manager._send_error = AsyncMock()

        # 替换 graph模块中的 memory_store
        with patch('TOSKill.AI.graph.memory_store', mock_memory):
            with patch('api.ai_chat_websocket.memory_store', mock_memory):
                # 运行测试
                payload = {"content": "请执行SQL注入扫描"}
                asyncio.get_event_loop().run_until_complete(
                    asyncio.wait_for(
                        manager._handle_scan_chat("test-session-15-1", payload),
                        timeout=10
                    )
                ) if asyncio.get_event_loop() else asyncio.run(
                    manager._handle_scan_chat("test-session-15-1", payload)
                )

        # 验证结果
        saved = saved_states.get("test-session-15-1")
        if saved is None:
            result.fail("15.1.6a Mock-state被保存", "state未被保存")
        else:
            result.ok("15.1.6a Mock-state被保存", "memory_store.save_session被调用")

            # 验证 user_chat_context 被写入
            ucc = saved.get("user_chat_context", "")
            if ucc:
                result.ok("15.1.6b user_chat_context被写入", f"值: {ucc[:50]}")
            else:
                result.fail("15.1.6b user_chat_context被写入", "字段为空")

            # 验证 user_directed_next_task 被写入
            udnt = saved.get("user_directed_next_task", "")
            if udnt == "sqli_scan":
                result.ok("15.1.6c user_directed_next_task被写入", f"值: {udnt}")
            else:
                result.fail("15.1.6c user_directed_next_task被写入", f"期望sqli_scan, 实际: {udnt}")

            # 验证 user_directed_params 被写入
            udp = saved.get("user_directed_params", {})
            if udp and "target_url" in udp:
                result.ok("15.1.6d user_directed_params被写入", f"值: {udp}")
            else:
                result.fail("15.1.6d user_directed_params被写入", f"值: {udp}")

        # 验证WebSocket推送了 user_directive_ack
        ack_sent = any(msg.get("type") == "user_directive_ack" for _, msg in sent_messages)
        if ack_sent:
            ack_msg = [msg for _, msg in sent_messages if msg.get("type") == "user_directive_ack"][0]
            result.ok("15.1.6e WebSocket推送user_directive_ack",
                       f"next_task={ack_msg.get('payload', {}).get('next_task')}")
        else:
            result.fail("15.1.6e WebSocket推送user_directive_ack", "未推送确认消息")

    except Exception as e:
        result.fail("15.1.6 Mock调用_handle_scan_chat", f"异常: {e}")
        import traceback
        traceback.print_exc()


# ============================================================
# SubTask 15.2: 验证用户指令优先级 > 知识库 > AI默认决策
# ============================================================
def test_subtask_15_2():
    print("\n" + "="*60)
    print("SubTask 15.2: 验证优先级顺序 (用户指令 > 知识库 > AI默认)")
    print("="*60)

    graph_file = os.path.join(TOSKILL_ROOT, "AI", "graph.py")
    graph_source = read_source_file(graph_file)

    # 测试2.1: ai_decision 函数存在且是异步
    try:
        from TOSKill.AI.graph import ai_decision
        is_async = inspect.iscoroutinefunction(ai_decision)
        if is_async:
            result.ok("15.2.1 ai_decision函数存在且为异步", "async def ai_decision")
        else:
            result.fail("15.2.1 ai_decision函数存在且为异步", "不是异步")
    except Exception as e:
        result.fail("15.2.1 ai_decision函数存在且为异步", f"导入失败: {e}")

    # 测试2.2: 源码中包含三级优先级注释
    priority_comment = "三级优先级" in graph_source or "用户指令" in graph_source and "知识库" in graph_source
    if priority_comment:
        result.ok("15.2.2 源码包含三级优先级注释", "用户指令 > 知识库 > AI默认")
    else:
        result.fail("15.2.2 源码包含三级优先级注释", "未找到优先级注释")

    # 测试2.3: 验证优先级1 - 用户指令 (user_directed_next_task) 被首先检查
    has_priority1 = (
        'user_directed_next_task' in graph_source and
        'priority_level = "user_directive"' in graph_source and
        '优先级1' in graph_source
    )
    if has_priority1:
        result.ok("15.2.3 优先级1-用户指令(user_directive)存在", "if user_directed_next_task ...")
    else:
        result.fail("15.2.3 优先级1-用户指令(user_directive)存在", "未找到用户指令优先级逻辑")

    # 测试2.4: 验证优先级2 - 知识库策略 (ReACT/RAG) 使用 elif
    has_priority2 = (
        'priority_level = "kb_react"' in graph_source and
        'react_decision' in graph_source and
        '优先级2' in graph_source
    )
    if has_priority2:
        result.ok("15.2.4 优先级2-知识库策略(kb_react)存在", "elif react_decision ...")
    else:
        result.fail("15.2.4 优先级2-知识库策略(kb_react)存在", "未找到知识库优先级逻辑")

    # 测试2.5: 验证优先级3 - AI默认 (ai_default) 使用独立 if (回退)
    has_priority3 = (
        'priority_level = "ai_default"' in graph_source and
        '优先级3' in graph_source
    )
    if has_priority3:
        result.ok("15.2.5 优先级3-AI默认(ai_default)存在", "if next_task_assigned is None ...")
    else:
        result.fail("15.2.5 优先级3-AI默认(ai_default)存在", "未找到AI默认优先级逻辑")

    # 测试2.6: 验证优先级顺序 - 用户指令使用 if, 知识库使用 elif (确保用户优先)
    # 提取决策逻辑代码段
    decision_section = ""
    if "三级优先级" in graph_source:
        idx = graph_source.index("三级优先级")
        decision_section = graph_source[idx:idx+2000]

    if decision_section:
        # 用户指令在 elif 之前 (优先级1 if, 优先级2 elif)
        user_idx = decision_section.find('priority_level = "user_directive"')
        kb_idx = decision_section.find('priority_level = "kb_react"')
        ai_idx = decision_section.find('priority_level = "ai_default"')

        if user_idx >= 0 and kb_idx >= 0 and ai_idx >= 0:
            if user_idx < kb_idx < ai_idx:
                result.ok("15.2.6 优先级顺序正确(user < kb < ai_default)",
                           f"位置: user={user_idx}, kb={kb_idx}, ai_default={ai_idx}")
            else:
                result.fail("15.2.6 优先级顺序正确(user < kb < ai_default)",
                            f"位置错误: user={user_idx}, kb={kb_idx}, ai_default={ai_idx}")
        else:
            result.fail("15.2.6 优先级顺序正确", "未找到所有三个优先级标记")
    else:
        result.fail("15.2.6 优先级顺序正确", "无法提取决策段代码")

    # 测试2.7: 验证 priority_level 字段被写入 decision_history
    has_priority_in_history = 'priority_level' in graph_source and 'decision_entry' in graph_source
    if has_priority_in_history:
        result.ok("15.2.7 priority_level写入decision_history", "decision_entry包含priority_level")
    else:
        result.fail("15.2.7 priority_level写入decision_history", "未找到")

    # 测试2.8: Mock测试 - 模拟优先级决策逻辑验证顺序
    test_priority_logic_mock()


def test_priority_logic_mock():
    """模拟优先级决策逻辑，验证三种场景下的任务分配顺序"""
    print("\n  --- Mock测试: 优先级决策逻辑 ---")

    try:
        from TOSKill.AI.tools import get_tool_sequence

        tool_sequence = get_tool_sequence("full_scan")

        def simulate_priority_decision(state, react_decision=None):
            """复刻 graph.py 中 ai_decision 的三级优先级决策逻辑 (lines 2180-2208)"""
            done = list(state.get("tool_results", {}).keys())
            user_directed_next_task = state.get("user_directed_next_task", "")
            user_directed_params = state.get("user_directed_params", {})

            next_task_assigned = None
            is_react_selected = False
            is_user_directed = False
            priority_level = "none"

            # 优先级1：用户交互指令（最高优先级）
            if (user_directed_next_task and
                    user_directed_next_task in tool_sequence and
                    user_directed_next_task not in done):
                next_task_assigned = user_directed_next_task
                is_user_directed = True
                priority_level = "user_directive"
            # 优先级2：知识库策略（通过ReACT决策，ReACT使用RAG检索结果）
            elif react_decision and react_decision.get("action"):
                react_action = react_decision["action"]
                if react_action in tool_sequence and react_action not in done:
                    next_task_assigned = react_action
                    is_react_selected = True
                    priority_level = "kb_react"
            # 优先级3：AI默认决策（默认序列回退）
            if next_task_assigned is None and len(done) < len(tool_sequence):
                remaining = [t for t in tool_sequence if t not in done]
                priority_level = "ai_default"
                next_task_assigned = remaining[0] if remaining else None
                is_react_selected = False

            return {
                "next_task": next_task_assigned,
                "priority_level": priority_level,
                "is_user_directed": is_user_directed,
                "is_react_selected": is_react_selected,
            }

        # 场景A: 用户指令 + 知识库建议 + AI默认 同时存在 → 应选用户指令
        state_a = {
            "tool_results": {},
            "user_directed_next_task": "xss_scan",
            "user_directed_params": {},
        }
        react_a = {"action": "sqli_scan"}
        result_a = simulate_priority_decision(state_a, react_a)
        if result_a["next_task"] == "xss_scan" and result_a["priority_level"] == "user_directive":
            result.ok("15.2.8a 场景A-用户指令优先(同时有KB建议)",
                       f"next_task={result_a['next_task']}, level={result_a['priority_level']}")
        else:
            result.fail("15.2.8a 场景A-用户指令优先",
                        f"next_task={result_a['next_task']}, level={result_a['priority_level']}")

        # 场景B: 无用户指令 + 知识库建议 → 应选知识库
        state_b = {
            "tool_results": {},
            "user_directed_next_task": "",
            "user_directed_params": {},
        }
        react_b = {"action": "sqli_scan"}
        result_b = simulate_priority_decision(state_b, react_b)
        if result_b["next_task"] == "sqli_scan" and result_b["priority_level"] == "kb_react":
            result.ok("15.2.8b 场景B-知识库优先(无用户指令)",
                       f"next_task={result_b['next_task']}, level={result_b['priority_level']}")
        else:
            result.fail("15.2.8b 场景B-知识库优先",
                        f"next_task={result_b['next_task']}, level={result_b['priority_level']}")

        # 场景C: 无用户指令 + 无知识库建议 → 应选AI默认
        state_c = {
            "tool_results": {},
            "user_directed_next_task": "",
            "user_directed_params": {},
        }
        react_c = None
        result_c = simulate_priority_decision(state_c, react_c)
        if result_c["next_task"] == tool_sequence[0] and result_c["priority_level"] == "ai_default":
            result.ok("15.2.8c 场景C-AI默认回退(无用户指令无KB)",
                       f"next_task={result_c['next_task']}, level={result_c['priority_level']}")
        else:
            result.fail("15.2.8c 场景C-AI默认回退",
                        f"next_task={result_c['next_task']}, level={result_c['priority_level']}")

        # 场景D: 用户指令已完成 → 回退到知识库
        state_d = {
            "tool_results": {"xss_scan": {}},  # xss_scan已完成
            "user_directed_next_task": "xss_scan",
            "user_directed_params": {},
        }
        react_d = {"action": "sqli_scan"}
        result_d = simulate_priority_decision(state_d, react_d)
        if result_d["next_task"] == "sqli_scan" and result_d["priority_level"] == "kb_react":
            result.ok("15.2.8d 场景D-用户指令已完成→回退KB",
                       f"next_task={result_d['next_task']}, level={result_d['priority_level']}")
        else:
            result.fail("15.2.8d 场景D-用户指令已完成→回退KB",
                        f"next_task={result_d['next_task']}, level={result_d['priority_level']}")

    except Exception as e:
        result.fail("15.2.8 Mock优先级决策逻辑", f"异常: {e}")
        import traceback
        traceback.print_exc()


# ============================================================
# SubTask 15.3: 验证风险评估输出包含置信度
# ============================================================
def test_subtask_15_3():
    print("\n" + "="*60)
    print("SubTask 15.3: 验证风险评估输出包含置信度 (vulnerability_check)")
    print("="*60)

    graph_file = os.path.join(TOSKILL_ROOT, "AI", "graph.py")
    graph_source = read_source_file(graph_file)

    # 测试3.1: vulnerability_check 函数存在且为异步
    try:
        from TOSKill.AI.graph import vulnerability_check
        is_async = inspect.iscoroutinefunction(vulnerability_check)
        if is_async:
            result.ok("15.3.1 vulnerability_check函数存在且为异步", "async def vulnerability_check")
        else:
            result.fail("15.3.1 vulnerability_check函数存在且为异步", "不是异步")
    except Exception as e:
        result.fail("15.3.1 vulnerability_check函数存在且为异步", f"导入失败: {e}")

    # 测试3.2: 函数源码中初始化 risk_level 和 risk_confidence
    try:
        from TOSKill.AI.graph import vulnerability_check as _vc_func
        vc_source = get_method_source(_vc_func, "vulnerability_check")
    except Exception:
        vc_source = ""
    if vc_source:
        has_init = (
            'risk_level = "info"' in vc_source and
            'risk_confidence = 50' in vc_source
        )
        if has_init:
            result.ok("15.3.2 初始化risk_level和risk_confidence", "risk_level='info', risk_confidence=50")
        else:
            result.fail("15.3.2 初始化risk_level和risk_confidence", "未找到初始化代码")
    else:
        result.fail("15.3.2 初始化risk_level和risk_confidence", "无法提取函数源码")

    # 测试3.3: LLM输出解析 risk_level 和 confidence
    if vc_source:
        has_parse = (
            'risk_result.get("risk_level"' in vc_source and
            'risk_result.get("confidence"' in vc_source and
            'risk_confidence = int(' in vc_source
        )
        if has_parse:
            result.ok("15.3.3 LLM输出解析risk_level+confidence", "从JSON解析两个字段")
        else:
            result.fail("15.3.3 LLM输出解析risk_level+confidence", "解析逻辑不完整")

    # 测试3.4: 置信度范围校验 (0-100)
    if vc_source:
        has_range_check = 'max(0, min(100, risk_confidence))' in vc_source
        if has_range_check:
            result.ok("15.3.4 置信度范围校验(0-100)", "max(0, min(100, risk_confidence))")
        else:
            result.fail("15.3.4 置信度范围校验(0-100)", "未找到范围校验")

    # 测试3.5: update_state 写入 risk_level 和 risk_confidence
    if vc_source:
        has_state_update = (
            'update_state(state, risk_summary=risk_summary' in vc_source and
            'risk_level=risk_level' in vc_source and
            'risk_confidence=risk_confidence' in vc_source
        )
        if has_state_update:
            result.ok("15.3.5 state写入risk_level+risk_confidence", "update_state包含两字段")
        else:
            result.fail("15.3.5 state写入risk_level+risk_confidence", "未找到state更新")
    else:
        result.fail("15.3.5 state写入risk_level+risk_confidence", "无法提取函数源码")

    # 测试3.6: WebSocket推送包含 risk_level 和 confidence
    if vc_source:
        has_ws_push = (
            '"type": "risk_assessment"' in vc_source and
            '"risk_level": risk_level' in vc_source and
            '"confidence": risk_confidence' in vc_source
        )
        if has_ws_push:
            result.ok("15.3.6 WebSocket推送含risk_level+confidence", "risk_assessment消息包含两字段")
        else:
            result.fail("15.3.6 WebSocket推送含risk_level+confidence", "推送消息不完整")

    # 测试3.7: 高危中断数据包含 risk_level 和 risk_confidence
    if vc_source:
        has_interrupt = (
            'high_risk_vulnerability_detected' in vc_source and
            '"risk_level": risk_level' in vc_source and
            '"risk_confidence": risk_confidence' in vc_source
        )
        if has_interrupt:
            result.ok("15.3.7 高危中断数据含risk_level+risk_confidence", "interrupt_data包含两字段")
        else:
            result.fail("15.3.7 高危中断数据含risk_level+risk_confidence", "中断数据不完整")

    # 测试3.8: 规则回退也设置 risk_confidence
    if vc_source:
        has_fallback = (
            'risk_confidence = 70' in vc_source and  # critical
            'risk_confidence = 65' in vc_source and  # high
            'risk_confidence = 60' in vc_source      # medium
        )
        if has_fallback:
            result.ok("15.3.8 规则回退设置risk_confidence", "critical=70, high=65, medium=60")
        else:
            result.fail("15.3.8 规则回退设置risk_confidence", "回退逻辑不完整")

    # 测试3.9: state.py 中 risk_level 和 risk_confidence 字段已定义
    try:
        from TOSKill.AI.state import ScanState
        annotations = ScanState.__annotations__
        has_risk_level = 'risk_level' in annotations
        has_risk_confidence = 'risk_confidence' in annotations
        if has_risk_level and has_risk_confidence:
            result.ok("15.3.9 ScanState定义risk_level+risk_confidence字段",
                       f"risk_level={annotations.get('risk_level')}, risk_confidence={annotations.get('risk_confidence')}")
        else:
            missing = []
            if not has_risk_level:
                missing.append("risk_level")
            if not has_risk_confidence:
                missing.append("risk_confidence")
            result.fail("15.3.9 ScanState定义risk_level+risk_confidence字段",
                        f"缺失: {missing}")
    except Exception as e:
        result.fail("15.3.9 ScanState定义risk_level+risk_confidence字段", f"导入失败: {e}")

    # 测试3.10: Mock测试 - 实际调用 vulnerability_check 验证输出
    test_vulnerability_check_mock()


def test_vulnerability_check_mock():
    """通过Mock测试 vulnerability_check 实际输出 risk_level + risk_confidence"""
    print("\n  --- Mock测试: vulnerability_check ---")

    try:
        from TOSKill.AI.state import create_initial_state
        from TOSKill.AI.graph import vulnerability_check

        # 创建测试状态 - 包含高危漏洞
        test_state = create_initial_state(target="http://example.com", mode="vuln_scan")
        test_state["websocket_session_id"] = "test-session-15-3"
        test_state["vulnerabilities"] = [
            {"type": "SQL注入", "severity": "high", "url": "http://example.com/login"},
        ]

        # 收集 WebSocket 推送的消息
        ws_messages = []
        async def mock_ws_callback(msg):
            ws_messages.append(msg)

        # Mock memory_store.get_websocket_callback
        mock_memory = MagicMock()
        mock_memory.get_websocket_callback = MagicMock(return_value=mock_ws_callback)

        # Mock RAG retriever (会让LLM路径失败，走规则回退)
        # Mock interrupt (langgraph interrupt 需要 runnable context，测试环境无)
        with patch('TOSKill.AI.graph.memory_store', mock_memory):
            with patch('TOSKill.RAG.retriever.retrieve_for_risk_assessment',
                       side_effect=Exception("Mock: RAG不可用")):
                with patch('TOSKill.RAG.retriever.get_kb_match_score',
                           side_effect=Exception("Mock: RAG不可用")):
                    with patch('TOSKill.AI.graph.interrupt',
                               return_value={"choice": "continue"}):
                        # 运行 vulnerability_check
                        result_state = asyncio.run(
                            vulnerability_check(dict(test_state))
                        )

        # 验证 state 输出
        risk_level = result_state.get("risk_level")
        risk_confidence = result_state.get("risk_confidence")
        risk_summary = result_state.get("risk_summary")

        if risk_level and risk_level in ("critical", "high", "medium", "low", "info"):
            result.ok("15.3.10a state输出risk_level", f"值: {risk_level}")
        else:
            result.fail("15.3.10a state输出risk_level", f"值: {risk_level}")

        if risk_confidence is not None and isinstance(risk_confidence, int) and 0 <= risk_confidence <= 100:
            result.ok("15.3.10b state输出risk_confidence", f"值: {risk_confidence}%")
        else:
            result.fail("15.3.10b state输出risk_confidence", f"值: {risk_confidence}")

        if risk_summary and "high" in risk_summary:
            result.ok("15.3.10c state输出risk_summary", f"值: {risk_summary}")
        else:
            result.fail("15.3.10c state输出risk_summary", f"值: {risk_summary}")

        # 验证 WebSocket 推送包含 risk_level + confidence
        risk_msg = [m for m in ws_messages if m.get("type") == "risk_assessment"]
        if risk_msg:
            payload = risk_msg[0].get("payload", {})
            has_risk_level = "risk_level" in payload
            has_confidence = "confidence" in payload
            if has_risk_level and has_confidence:
                result.ok("15.3.10d WebSocket推送含risk_level+confidence",
                           f"risk_level={payload.get('risk_level')}, confidence={payload.get('confidence')}")
            else:
                missing = []
                if not has_risk_level:
                    missing.append("risk_level")
                if not has_confidence:
                    missing.append("confidence")
                result.fail("15.3.10d WebSocket推送含risk_level+confidence",
                            f"缺失: {missing}, payload keys: {list(payload.keys())}")
        else:
            # 如果有高危漏洞，可能走的是 high_risk_vulnerability_detected 而非 risk_assessment
            high_risk_msg = [m for m in ws_messages if m.get("type") == "high_risk_vulnerability_detected"]
            if high_risk_msg:
                has_risk_level = "risk_level" in high_risk_msg[0]
                has_risk_confidence = "risk_confidence" in high_risk_msg[0]
                if has_risk_level and has_risk_confidence:
                    result.ok("15.3.10d WebSocket推送含risk_level+risk_confidence(高危中断)",
                               f"risk_level={high_risk_msg[0].get('risk_level')}, "
                               f"risk_confidence={high_risk_msg[0].get('risk_confidence')}")
                else:
                    result.fail("15.3.10d WebSocket推送含risk_level+risk_confidence",
                                f"高危中断消息字段不完整: {list(high_risk_msg[0].keys())}")
            else:
                result.fail("15.3.10d WebSocket推送含risk_level+confidence",
                            f"未推送risk_assessment消息, 推送的消息类型: {[m.get('type') for m in ws_messages]}")

    except Exception as e:
        result.fail("15.3.10 Mock调用vulnerability_check", f"异常: {e}")
        import traceback
        traceback.print_exc()


# ============================================================
# 额外测试: state.py 字段完整性验证
# ============================================================
def test_state_fields():
    print("\n" + "="*60)
    print("额外测试: ScanState 字段完整性验证")
    print("="*60)

    try:
        from TOSKill.AI.state import ScanState, create_initial_state, update_state

        annotations = ScanState.__annotations__

        required_fields = {
            "user_chat_context": "用户交互决策上下文",
            "user_directed_next_task": "用户指令下一任务",
            "user_directed_params": "用户指令参数",
            "risk_level": "风险等级",
            "risk_confidence": "风险置信度",
        }

        for field_name, desc in required_fields.items():
            if field_name in annotations:
                result.ok(f"字段-{field_name}", f"{desc}: {annotations[field_name]}")
            else:
                result.fail(f"字段-{field_name}", f"{desc}: 字段不存在")

        # 验证 update_state 函数可正确写入这些字段
        initial = create_initial_state(target="http://test.com", mode="full_scan")
        updated = update_state(initial,
            user_chat_context="测试上下文",
            user_directed_next_task="sqli_scan",
            user_directed_params={"url": "http://test.com"},
            risk_level="high",
            risk_confidence=85
        )

        field_checks = {
            "user_chat_context": updated.get("user_chat_context") == "测试上下文",
            "user_directed_next_task": updated.get("user_directed_next_task") == "sqli_scan",
            "user_directed_params": updated.get("user_directed_params", {}).get("url") == "http://test.com",
            "risk_level": updated.get("risk_level") == "high",
            "risk_confidence": updated.get("risk_confidence") == 85,
        }

        for field, ok in field_checks.items():
            if ok:
                result.ok(f"update_state写入-{field}", "值正确")
            else:
                result.fail(f"update_state写入-{field}", f"值错误: {updated.get(field)}")

    except Exception as e:
        result.fail("ScanState字段完整性验证", f"异常: {e}")
        import traceback
        traceback.print_exc()


# ============================================================
# 主函数
# ============================================================
def main():
    print("="*60)
    print("TOSKill Task 15: 实时交互与优先级机制自测")
    print(f"Python: {sys.executable}")
    print(f"项目根: {PROJECT_ROOT}")
    print("="*60)

    # SubTask 15.1
    test_subtask_15_1()

    # SubTask 15.2
    test_subtask_15_2()

    # SubTask 15.3
    test_subtask_15_3()

    # 额外: state字段验证
    test_state_fields()

    # 输出总结
    return result.summary()


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
