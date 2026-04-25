# -*- coding:utf-8 -*-
"""
对话历史记忆测试模块

测试对话历史的记忆存储功能：
- sync_chat_history 方法
- 对话历史增量同步
- 对话历史恢复
"""

import sys
import os
import pytest
import time
from datetime import datetime
from unittest.mock import patch, MagicMock
from typing import Dict, Any, List

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

from TOSKill.AI.state import AgentState
from TOSKill.AI.memory.session_memory import SessionMemoryManager, get_memory_manager


class TestSyncChatHistory:
    """测试 sync_chat_history 方法"""
    
    def setup_method(self):
        """每个测试方法前的设置"""
        self.manager = get_memory_manager()
        self.test_session_ids = []
    
    def teardown_method(self):
        """每个测试方法后的清理"""
        for session_id in self.test_session_ids:
            self.manager.delete_session(session_id)
    
    def test_sync_chat_history_basic(self):
        """测试基本对话历史同步"""
        state = AgentState(
            target="http://example.com",
            task_id="test-chat-001",
            chat_instance_id="session-chat-001"
        )
        self.test_session_ids.append("session-chat-001")
        
        state.append_chat_history("user", "你好")
        state.append_chat_history("assistant", "你好！有什么可以帮助你的？")
        
        result = state.sync_chat_history()
        
        assert result is True
        
        history = self.manager.get_message_history("session-chat-001")
        assert len(history) == 2
        assert history[0]["role"] == "user"
        assert history[0]["content"] == "你好"
    
    def test_sync_chat_history_auto_create_session(self):
        """测试自动创建会话"""
        state = AgentState(
            target="http://example.com",
            task_id="test-chat-002",
            chat_instance_id="auto-create-chat-002"
        )
        self.test_session_ids.append("auto-create-chat-002")
        
        assert "auto-create-chat-002" not in self.manager._sessions
        
        state.append_chat_history("user", "测试消息")
        result = state.sync_chat_history()
        
        assert result is True
        assert "auto-create-chat-002" in self.manager._sessions
    
    def test_sync_chat_history_with_task_id(self):
        """测试使用 task_id 作为 session_id"""
        state = AgentState(
            target="http://example.com",
            task_id="test-chat-003"
        )
        self.test_session_ids.append("test-chat-003")
        
        state.append_chat_history("user", "测试")
        result = state.sync_chat_history()
        
        assert result is True
        
        history = self.manager.get_message_history("test-chat-003")
        assert len(history) == 1
    
    def test_sync_chat_history_with_custom_messages(self):
        """测试同步自定义消息列表"""
        state = AgentState(
            target="http://example.com",
            task_id="test-chat-004",
            chat_instance_id="session-chat-004"
        )
        self.test_session_ids.append("session-chat-004")
        
        custom_messages = [
            {"role": "user", "content": "自定义消息1", "timestamp": datetime.now().isoformat()},
            {"role": "assistant", "content": "自定义消息2", "timestamp": datetime.now().isoformat()}
        ]
        
        result = state.sync_chat_history(messages=custom_messages)
        
        assert result is True
        
        history = self.manager.get_message_history("session-chat-004")
        assert len(history) == 2


class TestChatHistoryIncrementalSync:
    """测试对话历史增量同步"""
    
    def setup_method(self):
        """每个测试方法前的设置"""
        self.manager = get_memory_manager()
        self.test_session_ids = []
    
    def teardown_method(self):
        """每个测试方法后的清理"""
        for session_id in self.test_session_ids:
            self.manager.delete_session(session_id)
    
    def test_incremental_sync_new_messages(self):
        """测试增量同步新消息"""
        state = AgentState(
            target="http://example.com",
            task_id="test-incremental-001",
            chat_instance_id="session-incremental-001"
        )
        self.test_session_ids.append("session-incremental-001")
        
        state.append_chat_history("user", "消息1")
        state.sync_chat_history()
        
        history_before = self.manager.get_message_history("session-incremental-001")
        assert len(history_before) == 1
        
        state.append_chat_history("assistant", "消息2")
        state.append_chat_history("user", "消息3")
        state.sync_chat_history()
        
        history_after = self.manager.get_message_history("session-incremental-001")
        assert len(history_after) == 3
    
    def test_incremental_sync_avoids_duplicates(self):
        """测试增量同步避免重复"""
        state = AgentState(
            target="http://example.com",
            task_id="test-incremental-002",
            chat_instance_id="session-incremental-002"
        )
        self.test_session_ids.append("session-incremental-002")
        
        state.append_chat_history("user", "消息1")
        state.sync_chat_history()
        
        state.sync_chat_history()
        
        history = self.manager.get_message_history("session-incremental-002")
        assert len(history) == 1
    
    def test_incremental_sync_with_timestamp_check(self):
        """测试基于时间戳的增量同步"""
        state = AgentState(
            target="http://example.com",
            task_id="test-incremental-003",
            chat_instance_id="session-incremental-003"
        )
        self.test_session_ids.append("session-incremental-003")
        
        timestamp1 = datetime.now().isoformat()
        state.chat_history.append({"role": "user", "content": "消息1", "timestamp": timestamp1})
        state.sync_chat_history()
        
        time.sleep(0.01)
        timestamp2 = datetime.now().isoformat()
        state.chat_history.append({"role": "assistant", "content": "消息2", "timestamp": timestamp2})
        state.sync_chat_history()
        
        history = self.manager.get_message_history("session-incremental-003")
        assert len(history) == 2
    
    def test_incremental_sync_multiple_batches(self):
        """测试多批次增量同步"""
        state = AgentState(
            target="http://example.com",
            task_id="test-incremental-004",
            chat_instance_id="session-incremental-004"
        )
        self.test_session_ids.append("session-incremental-004")
        
        for i in range(5):
            state.append_chat_history("user", f"批次1-消息{i}")
        state.sync_chat_history()
        
        history1 = self.manager.get_message_history("session-incremental-004")
        assert len(history1) == 5
        
        for i in range(5):
            state.append_chat_history("assistant", f"批次2-消息{i}")
        state.sync_chat_history()
        
        history2 = self.manager.get_message_history("session-incremental-004")
        assert len(history2) == 10


class TestChatHistoryRecovery:
    """测试对话历史恢复"""
    
    def setup_method(self):
        """每个测试方法前的设置"""
        self.manager = get_memory_manager()
        self.test_session_ids = []
    
    def teardown_method(self):
        """每个测试方法后的清理"""
        for session_id in self.test_session_ids:
            self.manager.delete_session(session_id)
    
    def test_recover_chat_history_from_session(self):
        """测试从会话恢复对话历史"""
        state = AgentState(
            target="http://example.com",
            task_id="test-recovery-001",
            chat_instance_id="session-recovery-001"
        )
        self.test_session_ids.append("session-recovery-001")
        
        state.append_chat_history("user", "原始消息1")
        state.append_chat_history("assistant", "原始消息2")
        state.sync_chat_history()
        
        new_state = AgentState(
            target="http://example.com",
            task_id="test-recovery-001-new",
            chat_instance_id="session-recovery-001"
        )
        
        loaded_state = AgentState.load_from_session_memory("session-recovery-001")
        
        assert loaded_state is not None
        assert len(loaded_state.chat_history) == 2
        assert loaded_state.chat_history[0]["content"] == "原始消息1"
    
    def test_recover_chat_history_preserves_order(self):
        """测试恢复对话历史保持顺序"""
        state = AgentState(
            target="http://example.com",
            task_id="test-recovery-002",
            chat_instance_id="session-recovery-002"
        )
        self.test_session_ids.append("session-recovery-002")
        
        messages = [
            ("user", "消息1"),
            ("assistant", "消息2"),
            ("user", "消息3"),
            ("assistant", "消息4"),
            ("user", "消息5")
        ]
        
        for role, content in messages:
            state.append_chat_history(role, content)
        
        state.sync_chat_history()
        state.save_to_session_memory()
        
        loaded_state = AgentState.load_from_session_memory("session-recovery-002")
        
        assert loaded_state is not None
        for i, (role, content) in enumerate(messages):
            assert loaded_state.chat_history[i]["role"] == role
            assert loaded_state.chat_history[i]["content"] == content
    
    def test_recover_chat_history_with_metadata(self):
        """测试恢复带元数据的对话历史"""
        state = AgentState(
            target="http://example.com",
            task_id="test-recovery-003",
            chat_instance_id="session-recovery-003"
        )
        self.test_session_ids.append("session-recovery-003")
        
        state.append_chat_history("user", "测试消息")
        state.chat_history[0]["metadata"] = {"source": "test", "version": "1.0"}
        
        state.sync_chat_history()
        state.save_to_session_memory()
        
        loaded_state = AgentState.load_from_session_memory("session-recovery-003")
        
        assert loaded_state is not None
        assert len(loaded_state.chat_history) == 1
    
    def test_recover_empty_chat_history(self):
        """测试恢复空对话历史"""
        state = AgentState(
            target="http://example.com",
            task_id="test-recovery-004",
            chat_instance_id="session-recovery-004"
        )
        self.test_session_ids.append("session-recovery-004")
        
        state.sync_chat_history()
        state.save_to_session_memory()
        
        loaded_state = AgentState.load_from_session_memory("session-recovery-004")
        
        assert loaded_state is not None
        assert loaded_state.chat_history == []


class TestAppendChatHistory:
    """测试 append_chat_history 方法"""
    
    def test_append_chat_history_basic(self):
        """测试基本追加对话历史"""
        state = AgentState(
            target="http://example.com",
            task_id="test-append-001"
        )
        
        state.append_chat_history("user", "测试消息")
        
        assert len(state.chat_history) == 1
        assert state.chat_history[0]["role"] == "user"
        assert state.chat_history[0]["content"] == "测试消息"
        assert "timestamp" in state.chat_history[0]
    
    def test_append_chat_history_multiple(self):
        """测试追加多条对话历史"""
        state = AgentState(
            target="http://example.com",
            task_id="test-append-002"
        )
        
        for i in range(5):
            state.append_chat_history("user" if i % 2 == 0 else "assistant", f"消息{i}")
        
        assert len(state.chat_history) == 5
    
    def test_append_chat_history_roles(self):
        """测试不同角色的对话历史"""
        state = AgentState(
            target="http://example.com",
            task_id="test-append-003"
        )
        
        state.append_chat_history("user", "用户消息")
        state.append_chat_history("assistant", "助手消息")
        state.append_chat_history("system", "系统消息")
        
        assert len(state.chat_history) == 3
        assert state.chat_history[0]["role"] == "user"
        assert state.chat_history[1]["role"] == "assistant"
        assert state.chat_history[2]["role"] == "system"
    
    def test_append_chat_history_timestamp_format(self):
        """测试时间戳格式"""
        state = AgentState(
            target="http://example.com",
            task_id="test-append-004"
        )
        
        state.append_chat_history("user", "测试")
        
        timestamp = state.chat_history[0]["timestamp"]
        assert isinstance(timestamp, str)
        parsed = datetime.fromisoformat(timestamp)
        assert parsed is not None


class TestChatHistoryIntegration:
    """测试对话历史集成功能"""
    
    def setup_method(self):
        """每个测试方法前的设置"""
        self.manager = get_memory_manager()
        self.test_session_ids = []
    
    def teardown_method(self):
        """每个测试方法后的清理"""
        for session_id in self.test_session_ids:
            self.manager.delete_session(session_id)
    
    def test_full_chat_flow(self):
        """测试完整对话流程"""
        state = AgentState(
            target="http://example.com",
            task_id="test-flow-001",
            chat_instance_id="session-flow-001"
        )
        self.test_session_ids.append("session-flow-001")
        
        state.append_chat_history("user", "你好，请帮我扫描这个网站")
        state.sync_chat_history()
        
        state.append_chat_history("assistant", "好的，我将为您扫描 http://example.com")
        state.sync_chat_history()
        
        state.append_chat_history("user", "使用快速扫描模式")
        state.sync_chat_history()
        
        state.save_to_session_memory()
        
        loaded_state = AgentState.load_from_session_memory("session-flow-001")
        
        assert loaded_state is not None
        assert len(loaded_state.chat_history) == 3
        
        history = self.manager.get_message_history("session-flow-001")
        assert len(history) == 3
    
    def test_chat_history_with_state_changes(self):
        """测试对话历史与状态变化"""
        state = AgentState(
            target="http://example.com",
            task_id="test-flow-002",
            chat_instance_id="session-flow-002"
        )
        self.test_session_ids.append("session-flow-002")
        
        state.append_chat_history("user", "开始扫描")
        state.set_workflow_running()
        state.sync_chat_history()
        
        state.append_chat_history("assistant", "扫描已开始")
        state.update_stage_status("planning", "running", "executing", 50)
        state.sync_chat_history()
        
        state.save_to_session_memory()
        
        loaded_state = AgentState.load_from_session_memory("session-flow-002")
        
        assert loaded_state is not None
        assert loaded_state.workflow_status == "running"
        assert len(loaded_state.chat_history) == 2
    
    def test_chat_history_persistence_across_sessions(self):
        """测试跨会话的对话历史持久化"""
        state1 = AgentState(
            target="http://example.com",
            task_id="test-persist-001",
            chat_instance_id="session-persist-001"
        )
        self.test_session_ids.append("session-persist-001")
        
        state1.append_chat_history("user", "第一条消息")
        state1.sync_chat_history()
        state1.save_to_session_memory()
        
        state2 = AgentState.load_from_session_memory("session-persist-001")
        
        state2.append_chat_history("user", "第二条消息")
        state2.sync_chat_history()
        state2.save_to_session_memory()
        
        state3 = AgentState.load_from_session_memory("session-persist-001")
        
        assert state3 is not None
        assert len(state3.chat_history) == 2


class TestChatHistoryEdgeCases:
    """测试对话历史边界情况"""
    
    def setup_method(self):
        """每个测试方法前的设置"""
        self.manager = get_memory_manager()
        self.test_session_ids = []
    
    def teardown_method(self):
        """每个测试方法后的清理"""
        for session_id in self.test_session_ids:
            self.manager.delete_session(session_id)
    
    def test_sync_empty_chat_history(self):
        """测试同步空对话历史"""
        state = AgentState(
            target="http://example.com",
            task_id="test-edge-001",
            chat_instance_id="session-edge-001"
        )
        self.test_session_ids.append("session-edge-001")
        
        result = state.sync_chat_history()
        
        assert result is True
        
        history = self.manager.get_message_history("session-edge-001")
        assert history == []
    
    def test_sync_large_chat_history(self):
        """测试同步大量对话历史"""
        state = AgentState(
            target="http://example.com",
            task_id="test-edge-002",
            chat_instance_id="session-edge-002"
        )
        self.test_session_ids.append("session-edge-002")
        
        for i in range(100):
            state.append_chat_history("user" if i % 2 == 0 else "assistant", f"消息{i}")
        
        result = state.sync_chat_history()
        
        assert result is True
        
        history = self.manager.get_message_history("session-edge-002", limit=200)
        assert len(history) == 100
    
    def test_sync_unicode_chat_history(self):
        """测试同步 Unicode 对话历史"""
        state = AgentState(
            target="http://example.com",
            task_id="test-edge-003",
            chat_instance_id="session-edge-003"
        )
        self.test_session_ids.append("session-edge-003")
        
        unicode_messages = [
            "你好，世界！",
            "こんにちは世界",
            "안녕하세요 세계",
            "مرحبا بالعالم",
            "Привет мир",
            "🌍🎉🚀💡"
        ]
        
        for msg in unicode_messages:
            state.append_chat_history("user", msg)
        
        result = state.sync_chat_history()
        
        assert result is True
        
        history = self.manager.get_message_history("session-edge-003")
        for i, msg in enumerate(unicode_messages):
            assert history[i]["content"] == msg
    
    def test_sync_special_characters(self):
        """测试同步特殊字符"""
        state = AgentState(
            target="http://example.com",
            task_id="test-edge-004",
            chat_instance_id="session-edge-004"
        )
        self.test_session_ids.append("session-edge-004")
        
        special_content = "特殊字符: <>&\"'\\n\\t\\r<script>alert('xss')</script>"
        state.append_chat_history("user", special_content)
        
        result = state.sync_chat_history()
        
        assert result is True
        
        history = self.manager.get_message_history("session-edge-004")
        assert history[0]["content"] == special_content
    
    def test_sync_very_long_message(self):
        """测试同步超长消息"""
        state = AgentState(
            target="http://example.com",
            task_id="test-edge-005",
            chat_instance_id="session-edge-005"
        )
        self.test_session_ids.append("session-edge-005")
        
        long_message = "测试消息" * 1000
        state.append_chat_history("user", long_message)
        
        result = state.sync_chat_history()
        
        assert result is True
        
        history = self.manager.get_message_history("session-edge-005")
        assert history[0]["content"] == long_message


def run_tests():
    """运行所有测试"""
    import subprocess
    result = subprocess.run(
        [sys.executable, "-m", "pytest", __file__, "-v", "--tb=short"],
        capture_output=True,
        text=True,
        cwd=project_root
    )
    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)
    return result.returncode


if __name__ == "__main__":
    exit_code = run_tests()
    sys.exit(exit_code)
