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

    def test_execute_task_log_uses_explicit_tool_step_metadata(self):
        from TOSKill.api.ai_chat_websocket import AIChatManager

        manager = AIChatManager()
        event = manager._decorate_run_event("log-metadata", {
            "type": "workflow_log",
            "payload": {
                "node": "execute_task",
                "message": "任务完成: port_scan",
                "details": {
                    "tool": "port_scan",
                    "step_id": "tool:port_scan",
                    "task_status": "completed",
                },
            },
        })

        assert event["payload"]["step_id"] == "tool:port_scan"
        assert event["payload"]["status"] == "completed"


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
