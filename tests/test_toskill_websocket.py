# -*- coding:utf-8 -*-
"""
TOSKill WebSocket 测试用例

测试消息类型处理、数据传输完整性、消息确认和重传等。
"""

import pytest
import sys
import asyncio
import json
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock
from datetime import datetime

# Legacy MessageBuilder/MessageBuffer protocol; use the current AIChatManager
# tests under TOSKill/tests instead.
pytest.skip(
    "legacy WebSocket tests superseded by TOSKill/tests/test_websocket.py",
    allow_module_level=True,
)

project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))


@pytest.mark.websocket
class TestMessageBuilder:
    """消息构建器测试"""
    
    def test_generate_message_id(self):
        """测试生成消息ID"""
        from TOSKill.api.ai_chat_websocket import MessageBuilder
        
        msg_id = MessageBuilder.generate_message_id()
        
        assert msg_id is not None
        assert isinstance(msg_id, str)
        assert len(msg_id) > 0
    
    def test_generate_timestamp(self):
        """测试生成时间戳"""
        from TOSKill.api.ai_chat_websocket import MessageBuilder
        
        timestamp = MessageBuilder.generate_timestamp()
        
        assert timestamp is not None
        assert isinstance(timestamp, str)
    
    def test_calculate_hash(self):
        """测试计算消息哈希"""
        from TOSKill.api.ai_chat_websocket import MessageBuilder
        
        msg_id = "test_id"
        timestamp = datetime.now().isoformat()
        msg_type = "test_type"
        payload = {"key": "value"}
        
        hash_value = MessageBuilder.calculate_hash(msg_id, timestamp, msg_type, payload)
        
        assert hash_value is not None
        assert isinstance(hash_value, str)
        assert len(hash_value) == 16
    
    def test_build_message(self):
        """测试构建消息"""
        from TOSKill.api.ai_chat_websocket import MessageBuilder
        
        message = MessageBuilder.build("test_type", {"key": "value"})
        
        assert "message_id" in message
        assert "timestamp" in message
        assert "message_type" in message
        assert "message_hash" in message
        assert "payload" in message
        assert message["message_type"] == "test_type"
        assert message["payload"] == {"key": "value"}
    
    def test_build_message_with_id(self):
        """测试带ID构建消息"""
        from TOSKill.api.ai_chat_websocket import MessageBuilder
        
        message = MessageBuilder.build("test_type", {"key": "value"}, message_id="custom_id")
        
        assert message["message_id"] == "custom_id"
    
    def test_verify_message_valid(self):
        """测试验证有效消息"""
        from TOSKill.api.ai_chat_websocket import MessageBuilder
        
        message = MessageBuilder.build("test_type", {"key": "value"})
        
        is_valid = MessageBuilder.verify(message)
        
        assert is_valid == True
    
    def test_verify_message_invalid(self):
        """测试验证无效消息"""
        from TOSKill.api.ai_chat_websocket import MessageBuilder
        
        message = {
            "message_id": "test_id",
            "timestamp": datetime.now().isoformat(),
            "message_type": "test_type",
            "message_hash": "invalid_hash",
            "payload": {"key": "value"}
        }
        
        is_valid = MessageBuilder.verify(message)
        
        assert is_valid == False
    
    def test_verify_message_missing_fields(self):
        """测试验证缺少字段的消息"""
        from TOSKill.api.ai_chat_websocket import MessageBuilder
        
        message = {"message_id": "test_id"}
        
        is_valid = MessageBuilder.verify(message)
        
        assert is_valid == False


@pytest.mark.websocket
class TestMessageBuffer:
    """消息缓存测试"""
    
    def test_add_message(self):
        """测试添加消息"""
        from TOSKill.api.ai_chat_websocket import MessageBuffer, MessageBuilder
        
        buffer = MessageBuffer()
        message = MessageBuilder.build("test_type", {"key": "value"})
        
        buffer.add("session_1", message)
        
        assert buffer.get("session_1", message["message_id"]) == message
    
    def test_get_nonexistent_message(self):
        """测试获取不存在的消息"""
        from TOSKill.api.ai_chat_websocket import MessageBuffer
        
        buffer = MessageBuffer()
        
        result = buffer.get("session_1", "nonexistent_id")
        
        assert result is None
    
    def test_get_recent_messages(self):
        """测试获取最近消息"""
        from TOSKill.api.ai_chat_websocket import MessageBuffer, MessageBuilder
        
        buffer = MessageBuffer()
        
        for i in range(5):
            message = MessageBuilder.build("test_type", {"index": i})
            buffer.add("session_1", message)
        
        recent = buffer.get_recent("session_1", count=3)
        
        assert len(recent) == 3
    
    def test_get_recent_empty_session(self):
        """测试获取空会话的最近消息"""
        from TOSKill.api.ai_chat_websocket import MessageBuffer
        
        buffer = MessageBuffer()
        
        recent = buffer.get_recent("nonexistent_session", count=10)
        
        assert recent == []
    
    def test_clear_session(self):
        """测试清除会话"""
        from TOSKill.api.ai_chat_websocket import MessageBuffer, MessageBuilder
        
        buffer = MessageBuffer()
        message = MessageBuilder.build("test_type", {"key": "value"})
        buffer.add("session_1", message)
        
        buffer.clear("session_1")
        
        assert buffer.get("session_1", message["message_id"]) is None
    
    def test_max_size_limit(self):
        """测试最大大小限制"""
        from TOSKill.api.ai_chat_websocket import MessageBuffer, MessageBuilder
        
        buffer = MessageBuffer(max_size=5)
        
        for i in range(10):
            message = MessageBuilder.build("test_type", {"index": i})
            buffer.add("session_1", message)
        
        recent = buffer.get_recent("session_1", count=20)
        
        assert len(recent) <= 5


@pytest.mark.websocket
class TestAIChatManager:
    """AI聊天管理器测试"""
    
    @pytest.fixture
    def manager(self):
        from TOSKill.api.ai_chat_websocket import AIChatManager
        return AIChatManager()
    
    @pytest.fixture
    def mock_websocket(self):
        mock_ws = AsyncMock()
        mock_ws.accept = AsyncMock()
        mock_ws.send_json = AsyncMock()
        return mock_ws
    
    @pytest.mark.asyncio
    async def test_connect(self, manager, mock_websocket):
        """测试连接"""
        session_id = await manager.connect(mock_websocket)
        
        assert session_id is not None
        assert session_id in manager.connections
        mock_websocket.accept.assert_called_once()
    
    def test_disconnect(self, manager, mock_websocket):
        """测试断开连接"""
        manager.connections["test_session"] = mock_websocket
        manager.acked_messages["test_session"] = set()
        
        manager.disconnect("test_session")
        
        assert "test_session" not in manager.connections
        assert "test_session" not in manager.acked_messages
    
    @pytest.mark.asyncio
    async def test_send_message(self, manager, mock_websocket):
        """测试发送消息"""
        manager.connections["test_session"] = mock_websocket
        
        await manager._send("test_session", "test_type", {"key": "value"})
        
        mock_websocket.send_json.assert_called_once()
        call_args = mock_websocket.send_json.call_args[0][0]
        assert call_args["message_type"] == "test_type"
    
    @pytest.mark.asyncio
    async def test_send_to_nonexistent_session(self, manager):
        """测试发送到不存在的会话"""
        await manager._send("nonexistent_session", "test_type", {"key": "value"})
    
    @pytest.mark.asyncio
    async def test_send_error(self, manager, mock_websocket):
        """测试发送错误消息"""
        manager.connections["test_session"] = mock_websocket
        
        await manager._send_error("test_session", "Test error")
        
        mock_websocket.send_json.assert_called_once()
        call_args = mock_websocket.send_json.call_args[0][0]
        assert call_args["message_type"] == "error"
        assert "Test error" in call_args["payload"]["error"]


@pytest.mark.websocket
class TestMessageHandlers:
    """消息处理器测试"""
    
    @pytest.fixture
    def manager(self):
        from TOSKill.api.ai_chat_websocket import AIChatManager
        return AIChatManager()
    
    @pytest.fixture
    def mock_websocket(self):
        mock_ws = AsyncMock()
        mock_ws.accept = AsyncMock()
        mock_ws.send_json = AsyncMock()
        return mock_ws
    
    @pytest.mark.asyncio
    async def test_handle_user_input(self, manager, mock_websocket, clean_memory_store):
        """测试处理用户输入"""
        manager.connections["test_session"] = mock_websocket
        
        await manager._handle_user_input("test_session", {"content": "Hello"})
        
        mock_websocket.send_json.assert_called()
    
    @pytest.mark.asyncio
    async def test_handle_user_choice(self, manager, mock_websocket, clean_memory_store):
        """测试处理用户选择"""
        manager.connections["test_session"] = mock_websocket
        
        future = asyncio.Future()
        manager.pending_choices["test_session"] = future
        
        await manager._handle_user_choice("test_session", {"choice": "1"})
        
        assert future.result() == "1"
    
    @pytest.mark.asyncio
    async def test_handle_start_scan(self, manager, mock_websocket, clean_memory_store):
        """测试处理开始扫描"""
        manager.connections["test_session"] = mock_websocket
        
        await manager._handle_start_scan("test_session", {"target": "example.com", "scan_mode": "full"})
        
        assert "test_session" in manager.scan_tasks
    
    @pytest.mark.asyncio
    async def test_handle_stop_scan(self, manager, mock_websocket):
        """测试处理停止扫描"""
        manager.connections["test_session"] = mock_websocket
        
        mock_task = AsyncMock()
        manager.scan_tasks["test_session"] = mock_task
        
        await manager._handle_stop_scan("test_session", {})
        
        assert "test_session" not in manager.scan_tasks
    
    @pytest.mark.asyncio
    async def test_handle_get_history(self, manager, mock_websocket, clean_memory_store):
        """测试处理获取历史"""
        manager.connections["test_session"] = mock_websocket
        
        await manager._handle_get_history("test_session", {})
        
        mock_websocket.send_json.assert_called()
    
    @pytest.mark.asyncio
    async def test_handle_get_status(self, manager, mock_websocket, clean_memory_store):
        """测试处理获取状态"""
        manager.connections["test_session"] = mock_websocket
        
        await manager._handle_get_status("test_session", {})
        
        mock_websocket.send_json.assert_called()
    
    @pytest.mark.asyncio
    async def test_handle_chat(self, manager, mock_websocket, clean_memory_store):
        """测试处理聊天"""
        manager.connections["test_session"] = mock_websocket
        
        with patch('TOSKill.api.ai_chat_websocket.chat', new_callable=AsyncMock) as mock_chat:
            mock_chat.return_value = "AI response"
            
            await manager._handle_chat("test_session", {"content": "Hello"})
            
            mock_websocket.send_json.assert_called()
    
    @pytest.mark.asyncio
    async def test_handle_execute_tool(self, manager, mock_websocket, clean_memory_store):
        """测试处理执行工具"""
        manager.connections["test_session"] = mock_websocket
        
        with patch('TOSKill.api.ai_chat_websocket.execute_tool') as mock_execute:
            mock_execute.return_value = {"result": "success"}
            
            await manager._handle_execute_tool("test_session", {
                "tool_name": "baseinfo_scan",
                "target": "example.com"
            })
            
            mock_websocket.send_json.assert_called()


@pytest.mark.websocket
class TestMessageAck:
    """消息确认测试"""
    
    @pytest.fixture
    def manager(self):
        from TOSKill.api.ai_chat_websocket import AIChatManager
        return AIChatManager()
    
    @pytest.mark.asyncio
    async def test_handle_message_ack(self, manager):
        """测试处理消息确认"""
        manager.acked_messages["test_session"] = set()
        
        await manager._handle_message_ack("test_session", {"message_id": "msg_123"})
        
        assert "msg_123" in manager.acked_messages["test_session"]
    
    @pytest.mark.asyncio
    async def test_message_ack_without_id(self, manager):
        """测试无ID的消息确认"""
        manager.acked_messages["test_session"] = set()
        
        await manager._handle_message_ack("test_session", {})
        
        assert len(manager.acked_messages["test_session"]) == 0


@pytest.mark.websocket
class TestMessageRetransmit:
    """消息重传测试"""
    
    @pytest.fixture
    def manager(self):
        from TOSKill.api.ai_chat_websocket import AIChatManager
        return AIChatManager()
    
    @pytest.fixture
    def mock_websocket(self):
        mock_ws = AsyncMock()
        mock_ws.accept = AsyncMock()
        mock_ws.send_json = AsyncMock()
        return mock_ws
    
    @pytest.mark.asyncio
    async def test_handle_retransmit_existing_message(self, manager, mock_websocket):
        """测试重传存在的消息"""
        from TOSKill.api.ai_chat_websocket import message_buffer, MessageBuilder
        
        manager.connections["test_session"] = mock_websocket
        message = MessageBuilder.build("test_type", {"key": "value"}, message_id="msg_123")
        message_buffer.add("test_session", message)
        
        await manager._handle_message_retransmit("test_session", {"message_id": "msg_123"})
        
        mock_websocket.send_json.assert_called()
    
    @pytest.mark.asyncio
    async def test_handle_retransmit_nonexistent_message(self, manager, mock_websocket):
        """测试重传不存在的消息"""
        manager.connections["test_session"] = mock_websocket
        
        await manager._handle_message_retransmit("test_session", {"message_id": "nonexistent"})
        
        mock_websocket.send_json.assert_called()
    
    @pytest.mark.asyncio
    async def test_handle_retransmit_batch(self, manager, mock_websocket):
        """测试批量重传"""
        from TOSKill.api.ai_chat_websocket import message_buffer, MessageBuilder
        
        manager.connections["test_session"] = mock_websocket
        
        for i in range(5):
            message = MessageBuilder.build("test_type", {"index": i})
            message_buffer.add("test_session", message)
        
        await manager._handle_message_retransmit("test_session", {"count": 3})
        
        mock_websocket.send_json.assert_called()


@pytest.mark.websocket
class TestMessageVerification:
    """消息验证测试"""
    
    @pytest.fixture
    def manager(self):
        from TOSKill.api.ai_chat_websocket import AIChatManager
        return AIChatManager()
    
    @pytest.fixture
    def mock_websocket(self):
        mock_ws = AsyncMock()
        mock_ws.accept = AsyncMock()
        mock_ws.send_json = AsyncMock()
        return mock_ws
    
    @pytest.mark.asyncio
    async def test_handle_verify_valid_message(self, manager, mock_websocket):
        """测试验证有效消息"""
        from TOSKill.api.ai_chat_websocket import MessageBuilder
        
        manager.connections["test_session"] = mock_websocket
        message = MessageBuilder.build("test_type", {"key": "value"})
        
        await manager._handle_verify_message("test_session", {"message": message})
        
        mock_websocket.send_json.assert_called()
        call_args = mock_websocket.send_json.call_args[0][0]
        assert call_args["payload"]["is_valid"] == True
    
    @pytest.mark.asyncio
    async def test_handle_verify_invalid_message(self, manager, mock_websocket):
        """测试验证无效消息"""
        manager.connections["test_session"] = mock_websocket
        
        invalid_message = {
            "message_id": "test_id",
            "message_hash": "invalid_hash"
        }
        
        await manager._handle_verify_message("test_session", {"message": invalid_message})
        
        mock_websocket.send_json.assert_called()
        call_args = mock_websocket.send_json.call_args[0][0]
        assert call_args["payload"]["is_valid"] == False


@pytest.mark.websocket
class TestDataIntegrity:
    """数据完整性测试"""
    
    def test_hash_consistency(self):
        """测试哈希一致性"""
        from TOSKill.api.ai_chat_websocket import MessageBuilder
        
        msg_id = "test_id"
        timestamp = "2024-01-01T12:00:00"
        msg_type = "test_type"
        payload = {"key": "value"}
        
        hash1 = MessageBuilder.calculate_hash(msg_id, timestamp, msg_type, payload)
        hash2 = MessageBuilder.calculate_hash(msg_id, timestamp, msg_type, payload)
        
        assert hash1 == hash2
    
    def test_hash_different_for_different_payloads(self):
        """测试不同载荷产生不同哈希"""
        from TOSKill.api.ai_chat_websocket import MessageBuilder
        
        msg_id = "test_id"
        timestamp = "2024-01-01T12:00:00"
        msg_type = "test_type"
        
        hash1 = MessageBuilder.calculate_hash(msg_id, timestamp, msg_type, {"key": "value1"})
        hash2 = MessageBuilder.calculate_hash(msg_id, timestamp, msg_type, {"key": "value2"})
        
        assert hash1 != hash2
    
    def test_message_roundtrip(self):
        """测试消息往返"""
        from TOSKill.api.ai_chat_websocket import MessageBuilder
        
        original_payload = {
            "target": "example.com",
            "scan_mode": "full",
            "tools": ["baseinfo_scan", "port_scan"]
        }
        
        message = MessageBuilder.build("start_scan", original_payload)
        is_valid = MessageBuilder.verify(message)
        
        assert is_valid == True
        assert message["payload"] == original_payload


@pytest.mark.websocket
class TestWebSocketConnection:
    """WebSocket连接测试"""
    
    @pytest.mark.asyncio
    async def test_websocket_endpoint(self, mock_websocket):
        """测试WebSocket端点"""
        from TOSKill.api.ai_chat_websocket import manager
        
        session_id = await manager.connect(mock_websocket)
        
        assert session_id is not None
        assert session_id in manager.connections
        
        manager.disconnect(session_id)
    
    @pytest.mark.asyncio
    async def test_websocket_disconnect_cleanup(self, mock_websocket):
        """测试WebSocket断开清理"""
        from TOSKill.api.ai_chat_websocket import manager
        
        session_id = await manager.connect(mock_websocket)
        manager.acked_messages[session_id] = {"msg1", "msg2"}
        
        manager.disconnect(session_id)
        
        assert session_id not in manager.connections
        assert session_id not in manager.acked_messages


@pytest.mark.websocket
class TestAuthNotifications:
    """认证通知测试"""
    
    @pytest.fixture
    def manager(self):
        from TOSKill.api.ai_chat_websocket import AIChatManager
        return AIChatManager()
    
    @pytest.fixture
    def mock_websocket(self):
        mock_ws = AsyncMock()
        mock_ws.accept = AsyncMock()
        mock_ws.send_json = AsyncMock()
        return mock_ws
    
    @pytest.mark.asyncio
    async def test_send_auth_expired(self, manager, mock_websocket, clean_memory_store):
        """测试发送认证过期通知"""
        manager.connections["test_session"] = mock_websocket
        
        await manager.send_auth_expired("test_session", "认证已过期")
        
        mock_websocket.send_json.assert_called()
        call_args = mock_websocket.send_json.call_args[0][0]
        assert call_args["message_type"] == "auth_expired"
    
    @pytest.mark.asyncio
    async def test_send_auth_refresh_required(self, manager, mock_websocket):
        """测试发送认证刷新请求"""
        manager.connections["test_session"] = mock_websocket
        
        await manager.send_auth_refresh_required("test_session", retry_count=1)
        
        mock_websocket.send_json.assert_called()
        call_args = mock_websocket.send_json.call_args[0][0]
        assert call_args["message_type"] == "auth_refresh_required"
    
    @pytest.mark.asyncio
    async def test_send_auth_refresh_success(self, manager, mock_websocket, mock_auth_state, clean_memory_store):
        """测试发送认证刷新成功通知"""
        manager.connections["test_session"] = mock_websocket
        clean_memory_store.save_session("test_session", mock_auth_state)
        
        await manager.send_auth_refresh_success("test_session", {"auth_info": {"type": "cookies"}})
        
        mock_websocket.send_json.assert_called()
        call_args = mock_websocket.send_json.call_args[0][0]
        assert call_args["message_type"] == "auth_refresh_success"


@pytest.mark.websocket
class TestAuthHandlers:
    """认证处理器测试"""
    
    @pytest.fixture
    def manager(self):
        from TOSKill.api.ai_chat_websocket import AIChatManager
        return AIChatManager()
    
    @pytest.fixture
    def mock_websocket(self):
        mock_ws = AsyncMock()
        mock_ws.accept = AsyncMock()
        mock_ws.send_json = AsyncMock()
        return mock_ws
    
    @pytest.mark.asyncio
    async def test_handle_auth_provide(self, manager, mock_websocket, clean_memory_store):
        """测试处理认证信息提供"""
        manager.connections["test_session"] = mock_websocket
        
        await manager._handle_auth_provide("test_session", {
            "auth_type": "cookies",
            "credentials": {
                "cookies": {"session": "test_value"}
            }
        })
        
        assert "test_session" in manager.auth_sessions
        mock_websocket.send_json.assert_called()
    
    @pytest.mark.asyncio
    async def test_handle_auth_refresh_reauth(self, manager, mock_websocket):
        """测试处理认证刷新-重新认证"""
        manager.connections["test_session"] = mock_websocket
        
        await manager._handle_auth_refresh("test_session", {"action": "reauth"})
        
        mock_websocket.send_json.assert_called()
    
    @pytest.mark.asyncio
    async def test_handle_auth_refresh_skip(self, manager, mock_websocket, clean_memory_store):
        """测试处理认证刷新-跳过"""
        manager.connections["test_session"] = mock_websocket
        
        await manager._handle_auth_refresh("test_session", {"action": "skip"})
        
        mock_websocket.send_json.assert_called()
    
    @pytest.mark.asyncio
    async def test_handle_auth_refresh_cancel(self, manager, mock_websocket):
        """测试处理认证刷新-取消"""
        manager.connections["test_session"] = mock_websocket
        manager.scan_tasks["test_session"] = AsyncMock()
        
        await manager._handle_auth_refresh("test_session", {"action": "cancel"})
        
        assert "test_session" not in manager.scan_tasks
    
    @pytest.mark.asyncio
    async def test_handle_auth_status_check(self, manager, mock_websocket, mock_auth_state, clean_memory_store):
        """测试处理认证状态检查"""
        manager.connections["test_session"] = mock_websocket
        clean_memory_store.save_session("test_session", mock_auth_state)
        
        await manager._handle_auth_status_check("test_session", {})
        
        mock_websocket.send_json.assert_called()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-m", "websocket"])
