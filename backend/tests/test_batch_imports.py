"""
批量测试文件

测试所有核心模块的导入和基本功能
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


class TestImports:
    """测试模块导入"""
    
    def test_import_logging_utils(self):
        """测试日志工具模块导入"""
        from backend.utils.logging_utils import (
            setup_structured_logging,
            set_request_id,
            get_request_id,
            JsonFormatter,
            ConsoleFormatter
        )
        assert setup_structured_logging is not None
        assert set_request_id is not None
        assert get_request_id is not None
        assert JsonFormatter is not None
        assert ConsoleFormatter is not None
    
    def test_import_session_memory(self):
        """测试会话记忆模块导入"""
        from backend.ai_agents.memory import (
            SessionMemoryManager,
            SessionCheckpoint,
            session_memory,
            get_memory_manager
        )
        assert SessionMemoryManager is not None
        assert SessionCheckpoint is not None
        assert session_memory is not None
        assert get_memory_manager is not None
    
    @pytest.mark.skip(reason="pocsuite3 registered_pocs attribute issue")
    def test_import_api_router(self):
        """测试API路由模块导入"""
        from backend.api import api_router
        assert api_router is not None


class TestLoggingUtils:
    """测试日志工具功能"""
    
    def test_set_and_get_request_id(self):
        """测试请求ID设置和获取"""
        from backend.utils.logging_utils import set_request_id, get_request_id, clear_request_id
        
        clear_request_id()
        assert get_request_id() is None
        
        request_id = set_request_id("test-123")
        assert request_id == "test-123"
        assert get_request_id() == "test-123"
        
        clear_request_id()
        assert get_request_id() is None
    
    def test_auto_generate_request_id(self):
        """测试自动生成请求ID"""
        from backend.utils.logging_utils import set_request_id, get_request_id, clear_request_id
        
        clear_request_id()
        request_id = set_request_id()
        assert request_id is not None
        assert len(request_id) > 0
        assert get_request_id() == request_id
        
        clear_request_id()
    
    def test_json_formatter(self):
        """测试JSON格式化器"""
        import logging
        from backend.utils.logging_utils import JsonFormatter
        
        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test message",
            args=(),
            exc_info=None
        )
        
        formatted = formatter.format(record)
        assert '"message": "Test message"' in formatted
        assert '"level": "INFO"' in formatted


class TestSessionMemory:
    """测试会话记忆功能"""
    
    def test_create_session(self):
        """测试创建会话"""
        from backend.ai_agents.memory import get_memory_manager
        
        manager = get_memory_manager()
        session_id = manager.create_session()
        
        assert session_id is not None
        assert len(session_id) > 0
        
        manager.delete_session(session_id)
    
    def test_save_and_load_session(self):
        """测试保存和加载会话"""
        from backend.ai_agents.memory import get_memory_manager
        
        manager = get_memory_manager()
        session_id = manager.create_session()
        
        test_data = {"key": "value", "number": 123}
        manager.save_session(session_id, test_data)
        
        loaded_data = manager.load_session(session_id)
        assert loaded_data is not None
        assert loaded_data.get("key") == "value"
        assert loaded_data.get("number") == 123
        
        manager.delete_session(session_id)
    
    def test_add_message(self):
        """测试添加消息"""
        from backend.ai_agents.memory import get_memory_manager
        
        manager = get_memory_manager()
        session_id = manager.create_session()
        
        manager.add_message(session_id, "user", "Hello")
        manager.add_message(session_id, "assistant", "Hi there!")
        
        history = manager.get_message_history(session_id)
        assert len(history) == 2
        assert history[0]["role"] == "user"
        assert history[0]["content"] == "Hello"
        assert history[1]["role"] == "assistant"
        
        manager.delete_session(session_id)
    
    def test_delete_session(self):
        """测试删除会话"""
        from backend.ai_agents.memory import get_memory_manager
        
        manager = get_memory_manager()
        session_id = manager.create_session()
        
        assert manager.get_session(session_id) is not None
        
        result = manager.delete_session(session_id)
        assert result is True
        assert manager.get_session(session_id) is None


class TestAgentState:
    """测试AgentState功能"""
    
    def test_agent_state_creation(self):
        """测试AgentState创建"""
        from TOSKill.AI.state import AgentState
        
        state = AgentState(target="http://example.com", task_id="test-123")
        
        assert state.target == "http://example.com"
        assert state.task_id == "test-123"
        assert state.workflow_status == "idle"
    
    def test_agent_state_chat_history(self):
        """测试AgentState聊天历史"""
        from TOSKill.AI.state import AgentState
        
        state = AgentState(target="http://example.com", task_id="test-123")
        
        state.append_chat_history("user", "Hello")
        state.append_chat_history("assistant", "Hi!")
        
        history = state.chat_history
        assert len(history) == 2
        assert history[0]["role"] == "user"
        assert history[1]["role"] == "assistant"
    
    def test_agent_state_to_dict(self):
        """测试AgentState转换为字典"""
        from TOSKill.AI.state import AgentState
        
        state = AgentState(target="http://example.com", task_id="test-123")
        state_dict = state.to_dict()
        
        assert isinstance(state_dict, dict)
        assert state_dict["target"] == "http://example.com"
        assert state_dict["task_id"] == "test-123"
    
    def test_agent_state_websocket_callback(self):
        """测试AgentState WebSocket回调"""
        from TOSKill.AI.state import AgentState
        
        state = AgentState(target="http://example.com", task_id="test-123")
        
        callback_called = []
        
        async def test_callback(message):
            callback_called.append(message)
        
        state.set_websocket_callback(test_callback)
        assert state._websocket_callback is not None


class TestAPIRoutes:
    """测试API路由"""
    
    def test_api_router_exists(self):
        """测试API路由器存在"""
        from backend.api import api_router
        assert api_router is not None
    
    def test_report_router_prefix(self):
        """测试报告路由前缀"""
        from backend.api.report import router
        assert router.prefix == "/reports"
    
    def test_scan_router_exists(self):
        """测试扫描路由器存在"""
        from backend.api.scan import router
        assert router is not None
    
    def test_tasks_router_exists(self):
        """测试任务路由器存在"""
        from backend.api.tasks import router
        assert router is not None


class TestWebSocketHandler:
    """测试WebSocket处理器"""
    
    def test_websocket_manager_exists(self):
        """测试WebSocket管理器存在"""
        from backend.api.websocket import manager
        assert manager is not None
    
    def test_ai_chat_manager_exists(self):
        """测试AI聊天管理器存在"""
        from backend.api.ai_chat_websocket import ai_chat_manager
        assert ai_chat_manager is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
