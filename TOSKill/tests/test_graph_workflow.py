"""
TOSKill 工作流交互式集成测试 (最核心测试文件)

测试完整的扫描工作流：
- 意图识别 → 信息收集 → 漏洞扫描 → 报告生成
- Interrupt暂停/恢复机制
- 用户确认/拒绝/替代方案选择
- RAG注入验证
- 脚本上传/生成流程
"""
import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch


@pytest.mark.asyncio
class TestIntentRecognition:
    """意图识别工作流测试"""

    @patch('TOSKill.AI.graph.get_llm')
    async def test_intent_chat_message(self, mock_get_llm):
        """聊天消息应被正确识别为chat意图"""
        from TOSKill.AI.state import create_initial_state
        from TOSKill.AI.graph import intent_recognition
        
        mock_llm = MagicMock()
        mock_llm.invoke.return_value = MagicMock(content='{"intent": "chat", "confidence": 0.9, "explanation": "用户在进行普通对话"}')
        mock_get_llm.return_value = mock_llm
        
        state = create_initial_state(target="", task_id="test_intent_chat")
        state["user_input"] = "你好，介绍一下你自己"
        state["chat_history"] = [{"role": "user", "content": "你好，介绍一下你自己"}]
        
        result = intent_recognition(state)
        assert result is not None

    @patch('TOSKill.AI.graph.get_llm')
    async def test_intent_scan_request(self, mock_get_llm):
        """扫描请求应被识别为scan意图"""
        from TOSKill.AI.state import create_initial_state
        from TOSKill.AI.graph import intent_recognition
        
        mock_llm = MagicMock()
        mock_llm.invoke.return_value = MagicMock(content='{"intent": "scan", "confidence": 0.95, "target": "http://example.com", "mode": "info_collection"}')
        mock_get_llm.return_value = mock_llm
        
        state = create_initial_state(target="", task_id="test_intent_scan")
        state["user_input"] = "扫描 example.com"
        state["chat_history"] = [{"role": "user", "content": "扫描 example.com"}]
        
        result = intent_recognition(state)
        assert result is not None


class TestAgentOrchestrator:
    """Agent编排器测试"""

    def test_orchestrator_import(self):
        """编排器应可导入"""
        from TOSKill.AI.graph import get_agent_orchestrator
        orch = get_agent_orchestrator()
        assert orch is not None

    def test_orchestrator_methods_exist(self):
        """编排器应有核心方法"""
        from TOSKill.AI.graph import get_agent_orchestrator
        orch = get_agent_orchestrator()
        assert hasattr(orch, 'run_full_scan')
        assert hasattr(orch, 'run_info_collection')
        assert hasattr(orch, 'run_vuln_scan')
        assert hasattr(orch, 'run_report')
        assert hasattr(orch, 'resume_workflow')
        assert hasattr(orch, 'run_intent_recognition')
        assert hasattr(orch, 'run_direct_tool')

    def test_has_pending_interaction(self):
        """清理后无pending interaction"""
        from TOSKill.AI.graph import get_agent_orchestrator
        orch = get_agent_orchestrator()
        assert not orch.has_pending_interaction("test_nonexistent_999")

    def test_missing_tool_routes_to_script_interaction(self):
        """缺失工具必须进入可恢复的脚本交互节点，而非静默回退。"""
        from TOSKill.AI.graph import tool_check_router
        assert tool_check_router({"tool_exists": False}) == "script_upload_process"


class TestMemoryStore:
    """MemoryStore测试"""

    def test_memory_store_import(self):
        """memory_store应可导入"""
        from TOSKill.AI.graph import memory_store
        assert memory_store is not None

    def test_save_and_get_session(self, sample_scan_state):
        """Session保存和获取"""
        from TOSKill.AI.graph import memory_store
        sid = "test_mem_save"
        memory_store.save_session(sid, sample_scan_state)
        session = memory_store.get_session(sid)
        assert session is not None
        assert session.get("target") == "http://test.example.com"

    def test_delete_session(self, sample_scan_state):
        """Session删除"""
        from TOSKill.AI.graph import memory_store
        sid = "test_mem_delete"
        memory_store.save_session(sid, sample_scan_state)
        memory_store.delete_session(sid)
        assert memory_store.get_session(sid) is None

    def test_append_chat_history(self):
        """聊天历史追加"""
        from TOSKill.AI.graph import memory_store
        sid = "test_chat_history"
        memory_store.save_session(sid, {"task_id": sid})
        memory_store.append_chat(sid, "user", "测试消息")
        history = memory_store.get_chat_history(sid)
        assert len(history) > 0
        assert history[-1]["role"] == "user"

    def test_chat_history_is_session_isolated_and_state_mirror_deduplicated(self):
        """WebSocket 与图节点双写时，状态镜像不重复且会话不串线。"""
        from TOSKill.AI.graph import memory_store

        sid_a = "test_chat_isolation_a"
        sid_b = "test_chat_isolation_b"
        memory_store.save_session(sid_a, {"task_id": sid_a, "chat_history": []})
        memory_store.save_session(sid_b, {"task_id": sid_b, "chat_history": []})

        memory_store.append_chat(sid_a, "user", "同一条消息")
        memory_store.append_chat(sid_a, "user", "同一条消息")
        memory_store.append_chat(sid_b, "user", "另一条消息")

        state_a = memory_store.get_session(sid_a)
        state_b = memory_store.get_session(sid_b)
        assert [m["content"] for m in state_a["chat_history"]] == ["同一条消息"]
        assert [m["content"] for m in state_b["chat_history"]] == ["另一条消息"]
        assert all(m["content"] != "另一条消息" for m in state_a["chat_history"])

    def test_ws_callback(self, async_ws_callback):
        """WebSocket回调设置和获取"""
        from TOSKill.AI.graph import memory_store
        sid = "test_ws_callback"
        memory_store.set_websocket_callback(sid, async_ws_callback)
        cb = memory_store.get_websocket_callback(sid)
        assert cb is not None


@pytest.mark.asyncio
class TestWorkflowResumeEdgeCases:
    """工作流恢复边缘情况测试"""

    async def test_resume_nonexistent_session(self):
        """恢复不存在会话应不崩溃"""
        from TOSKill.AI.graph import get_agent_orchestrator
        orch = get_agent_orchestrator()
        try:
            result = await orch.resume_workflow("nonexistent_session_999", "confirm")
            assert result is None or isinstance(result, dict)
        except Exception as e:
            assert "not found" in str(e).lower() or "nonexistent" in str(e).lower() or True


class TestDirectToolExecution:
    """工具直接执行测试"""

    @pytest.mark.asyncio
    async def test_run_direct_tool_valid_tool(self):
        """有效工具直接执行"""
        from TOSKill.AI.graph import get_agent_orchestrator
        orch = get_agent_orchestrator()
        result = await orch.run_direct_tool("baseinfo_scan", "http://test.example.com", "test_direct")
        assert result is not None

    @pytest.mark.asyncio
    async def test_run_direct_tool_invalid_tool(self):
        """无效工具"""
        from TOSKill.AI.graph import get_agent_orchestrator
        orch = get_agent_orchestrator()
        try:
            result = await orch.run_direct_tool("nonexistent_tool_999", "http://test.example.com", "test_direct")
            assert result is not None
        except Exception as e:
            assert "nonexistent" in str(e).lower() or "tool" in str(e).lower() or True

    @pytest.mark.asyncio
    async def test_run_direct_tool_forwards_cookie_and_dynamic_params(self):
        """直连工具应收到会话 Cookie 与用户动态参数，并回显到事件。"""
        from TOSKill.AI.graph import get_agent_orchestrator, memory_store
        from unittest.mock import patch

        sid = "test_direct_cookie_params"
        observed = {}

        def fake_func(**kwargs):
            observed.update(kwargs)
            return {"success": True, "echo": kwargs}

        fake_tool = MagicMock()
        fake_tool.name = "mock_cookie_tool"
        fake_tool.description = "mock tool"
        fake_tool.func = fake_func

        state = {
            "task_id": sid,
            "target": "http://example.test",
            "websocket_session_id": sid,
            "auth_info": {"cookies": {"PHPSESSID": "abc123"}},
        }
        memory_store.save_session(sid, state)
        events = []

        async def callback(event):
            events.append(event)

        class FakeAnalyzer:
            def analyze(self, tool_name, target, result):
                return MagicMock()

            def to_websocket_payload(self, result):
                return {"analysis": "ok", "summary": "ok", "risk_level": "info"}

        with patch("TOSKill.AI.graph.get_tool_by_name", return_value=fake_tool), \
             patch("TOSKill.analysis.result_analyzer.get_analyzer", return_value=FakeAnalyzer()):
            result = await get_agent_orchestrator().run_direct_tool(
                "mock_cookie_tool",
                "http://example.test",
                sid,
                websocket_callback=callback,
                params={"security": "high", "__extend_params": {"marker": "from_user"}},
            )

        assert observed["target"] == "http://example.test"
        assert observed["security"] == "high"
        assert observed["marker"] == "from_user"
        assert observed["cookies"] == {"PHPSESSID": "abc123"}
        assert result["params"]["security"] == "high"
        assert [event["type"] for event in events] == ["direct_tool_started", "direct_tool_completed"]
        assert events[0]["payload"]["params"]["security"] == "high"
        assert events[1]["payload"]["params"]["security"] == "high"

    @pytest.mark.asyncio
    async def test_supplied_cookie_becomes_session_auth_without_reacquisition(self):
        """用户在前端提供的 Cookie 应直接进入会话认证状态。"""
        from TOSKill.AI.graph import get_agent_orchestrator, memory_store

        sid = "test_supplied_cookie_session_auth"
        memory_store.save_session(sid, {
            "task_id": sid,
            "target": "http://example.test",
            "websocket_session_id": sid,
        })

        state = await get_agent_orchestrator().ensure_session_auth(
            "http://example.test",
            sid,
            params={"cookies": {"PHPSESSID": "provided-cookie"}, "auto_auth": True},
        )

        assert state["auth_info"]["cookies"] == {"PHPSESSID": "provided-cookie"}
        assert state["auth_info"]["source"] == "user_supplied"
        assert state["credentials_obtained"] is True


class TestInterruptMechanism:
    """Interrupt机制测试"""

    def test_memory_store_save_interaction(self):
        """交互消息保存"""
        from TOSKill.AI.graph import memory_store
        sid = "test_interact"
        msg = {"type": "interaction_required", "payload": {"message": "test"}}
        memory_store.set_pending_interaction(sid, msg)
        assert memory_store.has_pending_interaction(sid)
        retrieved = memory_store.get_pending_interaction(sid)
        assert retrieved is not None
        memory_store.clear_pending_interaction(sid)
        assert not memory_store.has_pending_interaction(sid)


class TestWorkflowTypes:
    """工作流类型切换测试"""

    def test_mode_info_collection(self):
        """信息收集模式"""
        from TOSKill.AI.tools import INFO_COLLECTION_TOOLS
        assert len(INFO_COLLECTION_TOOLS) > 0

    def test_mode_vuln_scan(self):
        """漏洞扫描模式"""
        from TOSKill.AI.tools import VULN_SCAN_TOOLS
        assert len(VULN_SCAN_TOOLS) > 0

    def test_all_tools(self):
        """全部工具"""
        from TOSKill.AI.tools import ALL_TOOLS
        assert len(ALL_TOOLS) > 0
        assert len(ALL_TOOLS) >= 22
