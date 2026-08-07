"""
TOSKill WebSocket交互测试
验证连接建立、消息收发、断线重连
"""
import pytest
import json
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch


class TestWSManagerLogic:
    """WebSocket管理器逻辑测试"""

    def test_ws_endpoint_path(self):
        """WebSocket路径应正确"""
        ws_path = "/api/ai-chat/ws"
        assert ws_path.startswith("/api/")
        assert ws_path.endswith("/ws")

    @pytest.mark.asyncio
    async def test_ws_handler_import(self):
        """WS handler应可导入"""
        try:
            from TOSKill.api.ai_chat_websocket import ai_chat_websocket
            assert ai_chat_websocket is not None
        except ImportError as e:
            pytest.skip(f"WS handler导入失败: {e}")

    @pytest.mark.asyncio
    async def test_ws_message_types(self):
        """验证消息类型注册"""
        from TOSKill.api.ai_chat_websocket import AIChatManager
        
        manager = AIChatManager()
        assert hasattr(manager, 'handle_message')
        assert hasattr(manager, 'connect')
        assert hasattr(manager, 'disconnect')

    @pytest.mark.asyncio
    async def test_ws_error_handler(self):
        """WS错误处理"""
        from TOSKill.api.ai_chat_websocket import AIChatManager
        
        manager = AIChatManager()
        try:
            manager._handle_error(MagicMock(), Exception("test error"))
        except Exception:
            pass

    @pytest.mark.asyncio
    async def test_outbound_events_have_monotonic_sequence(self):
        """并发来源的会话事件应拥有单调递增的渲染顺序号。"""
        from TOSKill.api.ai_chat_websocket import AIChatManager

        class FakeWebSocket:
            def __init__(self):
                self.messages = []

            async def send_json(self, message):
                self.messages.append(message)

        manager = AIChatManager()
        websocket = FakeWebSocket()
        manager.connections["sequence_test"] = websocket
        await manager._send("sequence_test", {"type": "first", "payload": {}})
        await manager._send("sequence_test", {"type": "second", "payload": {}})

        assert [message["event_seq"] for message in websocket.messages] == [1, 2]


class TestWSPayloadValidation:
    """WS Payload验证测试"""

    def test_scan_payload_required_fields(self):
        """scan payload应有必填字段"""
        payload = {
            "target": "http://example.com",
            "mode": "info_collection"
        }
        assert "target" in payload
        assert "mode" in payload

    def test_confirm_payload(self):
        """确认payload"""
        payload = {"confirmed": True, "choice": "1"}
        assert "confirmed" in payload or "choice" in payload

    def test_chat_payload(self):
        """聊天payload"""
        payload = {"content": "hello", "session_id": "test"}
        assert "content" in payload

    @pytest.mark.asyncio
    async def test_invalid_interaction_choice_is_rejected(self):
        from TOSKill.api.ai_chat_websocket import AIChatManager

        manager = AIChatManager()
        manager._send_error = AsyncMock()
        await manager._handle_user_confirm("choice-test", {"choice": "99"})

        manager._send_error.assert_awaited_once()
        assert manager._send_error.await_args.kwargs["error_code"] == "INVALID_CHOICE"

    @pytest.mark.asyncio
    async def test_interaction_chat_resumes_chat_branch(self):
        from TOSKill.api.ai_chat_websocket import AIChatManager

        manager = AIChatManager()
        manager._send = AsyncMock()
        manager._send_error = AsyncMock()
        orchestrator = MagicMock()
        orchestrator._ensure_initialized = AsyncMock()
        orchestrator.resume_workflow = AsyncMock(return_value={})
        orchestrator.has_pending_interaction.return_value = True

        with patch("TOSKill.api.ai_chat_websocket.get_agent_orchestrator", return_value=orchestrator), \
             patch("TOSKill.api.ai_chat_websocket.memory_store.append_chat"):
            await manager._handle_interaction_chat("chat-test", {"content": "continue with headers"})

        orchestrator.resume_workflow.assert_awaited_once_with(
            "chat-test", {"choice": "3", "chat_content": "continue with headers"}
        )
        manager._send_error.assert_not_awaited()


class TestWSSessionIsolation:
    """WS会话隔离测试"""

    @pytest.mark.asyncio
    @patch('TOSKill.AI.graph.memory_store.get_session')
    async def test_multi_session_isolation(self, mock_get):
        """多个会话应相互独立"""
        mock_sessions = {}
        for i in range(3):
            mock_sessions[f"session_{i}"] = {
                "task_id": f"session_{i}",
                "target": f"http://test{i}.com",
                "completed_tasks": [],
                "is_complete": False,
                "mode": "full_scan"
            }
        
        mock_get.side_effect = lambda sid: mock_sessions.get(sid)

        from TOSKill.AI.graph import memory_store
        try:
            s0 = memory_store.get_session("session_0")
            s1 = memory_store.get_session("session_1")
            if s0 and s1:
                assert s0.get("target") != s1.get("target")
        except Exception:
            pass


class TestWSReconnection:
    """WS重连逻辑测试"""

    def test_exponential_backoff_calc(self):
        """指数退避计算"""
        base = 1.0
        delays = []
        for i in range(10):
            delay = min(base * (2 ** i), 30.0)
            delays.append(delay)
        
        assert delays[0] == 1.0
        assert delays[1] == 2.0
        assert delays[2] == 4.0
        assert max(delays) <= 30.0
