"""
AI对话WebSocket测试用例

测试WebSocket连接、消息处理和扫描功能
"""
import pytest
import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

# Legacy protocol: current coverage lives under TOSKill/tests.
pytest.skip(
    "legacy WebSocket tests superseded by TOSKill/tests/test_websocket.py",
    allow_module_level=True,
)


class TestAIChatConnectionManager:
    """AIChatConnectionManager 测试类"""
    
    @pytest.fixture
    def manager(self):
        from TOSKill.api.ai_chat_websocket import AIChatConnectionManager
        return AIChatConnectionManager()
    
    @pytest.fixture
    def mock_websocket(self):
        ws = AsyncMock()
        ws.accept = AsyncMock()
        ws.send_json = AsyncMock()
        ws.receive_json = AsyncMock()
        return ws
    
    @pytest.mark.asyncio
    async def test_connect_creates_session(self, manager, mock_websocket):
        """测试连接创建会话"""
        session_id = await manager.connect(mock_websocket)
        
        assert session_id is not None
        assert session_id in manager.active_connections
        mock_websocket.accept.assert_called_once()
        mock_websocket.send_json.assert_called_once()
        
        sent_message = mock_websocket.send_json.call_args[0][0]
        assert sent_message["type"] == "connected"
        assert "session_id" in sent_message["payload"]
    
    @pytest.mark.asyncio
    async def test_connect_with_custom_session_id(self, manager, mock_websocket):
        """测试使用自定义会话ID连接"""
        custom_id = "custom_session_123"
        session_id = await manager.connect(mock_websocket, custom_id)
        
        assert session_id == custom_id
    
    def test_disconnect_removes_connection(self, manager, mock_websocket):
        """测试断开连接移除会话"""
        session_id = "test_session"
        manager.active_connections[session_id] = mock_websocket
        
        manager.disconnect(session_id)
        
        assert session_id not in manager.active_connections
    
    def test_disconnect_cancels_running_task(self, manager, mock_websocket):
        """测试断开连接取消运行中的任务"""
        session_id = "test_session"
        manager.active_connections[session_id] = mock_websocket
        
        mock_task = MagicMock()
        mock_task.done.return_value = False
        mock_task.cancel = MagicMock()
        manager.session_tasks[session_id] = mock_task
        
        manager.disconnect(session_id)
        
        mock_task.cancel.assert_called_once()
        assert session_id not in manager.session_tasks
    
    @pytest.mark.asyncio
    async def test_send_message_to_existing_session(self, manager, mock_websocket):
        """测试向存在的会话发送消息"""
        session_id = "test_session"
        manager.active_connections[session_id] = mock_websocket
        
        message = {"type": "test", "payload": {"data": "value"}}
        await manager.send_message(session_id, message)
        
        mock_websocket.send_json.assert_called_once_with(message)
    
    @pytest.mark.asyncio
    async def test_send_message_to_nonexistent_session(self, manager):
        """测试向不存在的会话发送消息"""
        message = {"type": "test", "payload": {"data": "value"}}
        
        await manager.send_message("nonexistent", message)
    
    @pytest.mark.asyncio
    async def test_send_error_message(self, manager, mock_websocket):
        """测试发送错误消息"""
        session_id = "test_session"
        manager.active_connections[session_id] = mock_websocket
        
        await manager._send_error(session_id, "测试错误", code=400)
        
        sent_message = mock_websocket.send_json.call_args[0][0]
        assert sent_message["type"] == "error"
        assert sent_message["payload"]["error"] == "测试错误"
        assert sent_message["payload"]["code"] == 400
    
    @pytest.mark.asyncio
    async def test_handle_message_routes_to_correct_handler(self, manager):
        """测试消息路由到正确的处理器"""
        session_id = "test_session"
        
        manager._handle_user_input = AsyncMock()
        
        message = {"type": "user_input", "payload": {"content": "test"}}
        await manager.handle_message(session_id, message)
        
        manager._handle_user_input.assert_called_once_with(session_id, {"content": "test"})
    
    @pytest.mark.asyncio
    async def test_handle_unknown_message_type(self, manager):
        """测试处理未知消息类型"""
        session_id = "test_session"
        
        message = {"type": "unknown_type", "payload": {}}
        await manager.handle_message(session_id, message)
    
    @pytest.mark.asyncio
    async def test_handle_user_input(self, manager, mock_websocket):
        """测试处理用户输入"""
        session_id = "test_session"
        manager.active_connections[session_id] = mock_websocket
        
        with patch('TOSKill.api.ai_chat_websocket.memory_store') as mock_store:
            mock_store.get_session.return_value = {}
            mock_store.save_session = MagicMock()
            
            payload = {"content": "Hello"}
            await manager._handle_user_input(session_id, payload)
            
            mock_store.append_chat.assert_called_once_with(session_id, "user", "Hello")
    
    @pytest.mark.asyncio
    async def test_handle_start_scan_without_target(self, manager, mock_websocket):
        """测试没有目标的扫描请求"""
        session_id = "test_session"
        manager.active_connections[session_id] = mock_websocket
        
        payload = {"target": "", "scan_mode": "info"}
        await manager._handle_start_scan(session_id, payload)
        
        sent_message = mock_websocket.send_json.call_args[0][0]
        assert sent_message["type"] == "error"
        assert "目标地址不能为空" in sent_message["payload"]["error"]
    
    @pytest.mark.asyncio
    async def test_handle_get_history(self, manager, mock_websocket):
        """测试获取历史记录"""
        session_id = "test_session"
        manager.active_connections[session_id] = mock_websocket
        
        with patch('TOSKill.api.ai_chat_websocket.memory_store') as mock_store:
            mock_store.get_chat_history.return_value = [
                {"role": "user", "content": "test"}
            ]
            
            await manager._handle_get_history(session_id, {})
            
            sent_message = mock_websocket.send_json.call_args[0][0]
            assert sent_message["type"] == "history"
            assert "history" in sent_message["payload"]
    
    @pytest.mark.asyncio
    async def test_handle_get_status_with_active_session(self, manager, mock_websocket):
        """测试获取活动会话状态"""
        session_id = "test_session"
        manager.active_connections[session_id] = mock_websocket
        
        with patch('TOSKill.api.ai_chat_websocket.memory_store') as mock_store:
            mock_store.get_session.return_value = {
                "task_id": "task_123",
                "target": "example.com",
                "mode": "info_collection",
                "completed_tasks": ["baseinfo_scan"],
                "vulnerabilities": [],
                "is_complete": False
            }
            
            await manager._handle_get_status(session_id, {})
            
            sent_message = mock_websocket.send_json.call_args[0][0]
            assert sent_message["type"] == "status"
            assert sent_message["payload"]["state"]["task_id"] == "task_123"
    
    @pytest.mark.asyncio
    async def test_handle_get_status_without_session(self, manager, mock_websocket):
        """测试获取不存在会话的状态"""
        session_id = "test_session"
        manager.active_connections[session_id] = mock_websocket
        
        with patch('TOSKill.api.ai_chat_websocket.memory_store') as mock_store:
            mock_store.get_session.return_value = None
            
            await manager._handle_get_status(session_id, {})
            
            sent_message = mock_websocket.send_json.call_args[0][0]
            assert sent_message["type"] == "status"
            assert sent_message["payload"]["state"] is None
    
    @pytest.mark.asyncio
    async def test_handle_execute_tool_without_params(self, manager, mock_websocket):
        """测试缺少参数的工具执行"""
        session_id = "test_session"
        manager.active_connections[session_id] = mock_websocket
        
        payload = {"tool_name": "", "target": ""}
        await manager._handle_execute_tool(session_id, payload)
        
        sent_message = mock_websocket.send_json.call_args[0][0]
        assert sent_message["type"] == "error"
    
    @pytest.mark.asyncio
    async def test_handle_execute_tool_nonexistent_tool(self, manager, mock_websocket):
        """测试执行不存在的工具"""
        session_id = "test_session"
        manager.active_connections[session_id] = mock_websocket
        
        with patch('TOSKill.api.ai_chat_websocket.get_tool_by_name') as mock_get_tool:
            mock_get_tool.return_value = None
            
            payload = {"tool_name": "nonexistent_tool", "target": "example.com"}
            await manager._handle_execute_tool(session_id, payload)
            
            sent_message = mock_websocket.send_json.call_args[0][0]
            assert sent_message["type"] == "error"


class TestMessageHandlerMapping:
    """消息处理器映射测试"""
    
    def test_all_handlers_exist(self):
        """测试所有定义的处理器方法都存在"""
        from TOSKill.api.ai_chat_websocket import AIChatConnectionManager
        
        manager = AIChatConnectionManager()
        
        for message_type, handler_name in AIChatConnectionManager.MESSAGE_HANDLERS.items():
            assert hasattr(manager, handler_name), f"处理器 {handler_name} 不存在"
    
    def test_scan_mode_mapping(self):
        """测试扫描模式映射"""
        from TOSKill.api.ai_chat_websocket import AIChatConnectionManager
        
        assert AIChatConnectionManager.SCAN_MODE_MAP["info"] == "info_collection"
        assert AIChatConnectionManager.SCAN_MODE_MAP["vuln"] == "vuln_scan"
        assert AIChatConnectionManager.SCAN_MODE_MAP["full"] == "full_scan"


class TestWebSocketEndpoint:
    """WebSocket端点测试"""
    
    @pytest.mark.asyncio
    async def test_endpoint_handles_json_decode_error(self):
        """测试端点处理JSON解析错误"""
        from TOSKill.api.ai_chat_websocket import ai_chat_manager, ai_chat_websocket_endpoint
        
        mock_websocket = AsyncMock()
        mock_websocket.accept = AsyncMock()
        mock_websocket.send_json = AsyncMock()
        mock_websocket.receive_json = AsyncMock(side_effect=[
            json.JSONDecodeError("test", "test", 0),
            Exception("disconnect")
        ])
        
        with patch('TOSKill.api.ai_chat_websocket.ai_chat_manager', ai_chat_manager):
            pass
