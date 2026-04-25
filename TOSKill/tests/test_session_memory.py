# -*- coding:utf-8 -*-
"""
SessionMemoryManager 测试模块

测试会话记忆管理器的核心功能：
- 会话创建和删除
- 消息历史记录
- 状态保存和加载
"""

import sys
import os
import pytest
import time
from unittest.mock import patch, MagicMock
from typing import Dict, Any, List

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

from TOSKill.AI.memory.session_memory import (
    SessionMemoryManager,
    SessionCheckpoint,
    get_memory_manager,
    session_memory
)


class TestSessionCheckpoint:
    """测试 SessionCheckpoint 类"""
    
    def test_checkpoint_initialization(self):
        """测试检查点初始化"""
        checkpoint = SessionCheckpoint("test-session-001", "test-thread-001")
        
        assert checkpoint.session_id == "test-session-001"
        assert checkpoint.thread_id == "test-thread-001"
        assert checkpoint.channel_values == {}
        assert checkpoint.message_history == []
        assert checkpoint.created_at > 0
        assert checkpoint.updated_at > 0
    
    def test_checkpoint_update(self):
        """测试检查点更新"""
        checkpoint = SessionCheckpoint("test-session-002", "test-thread-002")
        original_updated_at = checkpoint.updated_at
        
        time.sleep(0.01)
        checkpoint.update({"key1": "value1", "key2": "value2"})
        
        assert "key1" in checkpoint.channel_values
        assert checkpoint.channel_values["key1"] == "value1"
        assert checkpoint.updated_at > original_updated_at
    
    def test_checkpoint_update_merge(self):
        """测试检查点更新合并"""
        checkpoint = SessionCheckpoint("test-session-003", "test-thread-003")
        checkpoint.update({"key1": "value1"})
        checkpoint.update({"key2": "value2"})
        
        assert checkpoint.channel_values["key1"] == "value1"
        assert checkpoint.channel_values["key2"] == "value2"
    
    def test_checkpoint_add_message(self):
        """测试检查点添加消息"""
        checkpoint = SessionCheckpoint("test-session-004", "test-thread-004")
        
        checkpoint.add_message("user", "你好")
        checkpoint.add_message("assistant", "你好！有什么可以帮助你的？")
        
        assert len(checkpoint.message_history) == 2
        assert checkpoint.message_history[0]["role"] == "user"
        assert checkpoint.message_history[0]["content"] == "你好"
        assert checkpoint.message_history[1]["role"] == "assistant"
        assert "timestamp" in checkpoint.message_history[0]
    
    def test_checkpoint_add_message_with_metadata(self):
        """测试检查点添加带元数据的消息"""
        checkpoint = SessionCheckpoint("test-session-005", "test-thread-005")
        
        metadata = {"source": "websocket", "client_id": "client-001"}
        checkpoint.add_message("user", "测试消息", metadata=metadata)
        
        assert len(checkpoint.message_history) == 1
        assert checkpoint.message_history[0]["metadata"] == metadata


class TestSessionMemoryManagerSingleton:
    """测试 SessionMemoryManager 单例模式"""
    
    def test_singleton_pattern(self):
        """测试单例模式"""
        manager1 = SessionMemoryManager()
        manager2 = SessionMemoryManager()
        
        assert manager1 is manager2
    
    def test_get_memory_manager_returns_singleton(self):
        """测试 get_memory_manager 返回单例"""
        manager1 = get_memory_manager()
        manager2 = get_memory_manager()
        
        assert manager1 is manager2
        assert manager1 is session_memory


class TestSessionMemoryManagerSessionOperations:
    """测试 SessionMemoryManager 会话操作"""
    
    def setup_method(self):
        """每个测试方法前的设置"""
        self.manager = SessionMemoryManager()
        self.test_session_ids = []
    
    def teardown_method(self):
        """每个测试方法后的清理"""
        for session_id in self.test_session_ids:
            self.manager.delete_session(session_id)
    
    def test_create_session_with_id(self):
        """测试使用指定ID创建会话"""
        session_id = self.manager.create_session("test-session-100")
        self.test_session_ids.append(session_id)
        
        assert session_id == "test-session-100"
        assert session_id in self.manager._sessions
    
    def test_create_session_auto_id(self):
        """测试自动生成ID创建会话"""
        session_id = self.manager.create_session()
        self.test_session_ids.append(session_id)
        
        assert session_id is not None
        assert len(session_id) > 0
        assert session_id in self.manager._sessions
    
    def test_create_session_generates_thread_id(self):
        """测试创建会话时生成线程ID"""
        session_id = self.manager.create_session("test-session-101")
        self.test_session_ids.append(session_id)
        
        checkpoint = self.manager._sessions.get(session_id)
        assert checkpoint is not None
        assert checkpoint.thread_id is not None
        assert checkpoint.thread_id in self.manager._session_threads
    
    def test_delete_session(self):
        """测试删除会话"""
        session_id = self.manager.create_session("test-session-102")
        
        result = self.manager.delete_session(session_id)
        
        assert result is True
        assert session_id not in self.manager._sessions
    
    def test_delete_nonexistent_session(self):
        """测试删除不存在的会话"""
        result = self.manager.delete_session("nonexistent-session")
        
        assert result is False
    
    def test_delete_session_clears_thread_mapping(self):
        """测试删除会话时清除线程映射"""
        session_id = self.manager.create_session("test-session-103")
        checkpoint = self.manager._sessions.get(session_id)
        thread_id = checkpoint.thread_id
        
        self.manager.delete_session(session_id)
        
        assert thread_id not in self.manager._session_threads


class TestSessionMemoryManagerStateOperations:
    """测试 SessionMemoryManager 状态操作"""
    
    def setup_method(self):
        """每个测试方法前的设置"""
        self.manager = SessionMemoryManager()
        self.test_session_ids = []
    
    def teardown_method(self):
        """每个测试方法后的清理"""
        for session_id in self.test_session_ids:
            self.manager.delete_session(session_id)
    
    def test_save_session_state(self):
        """测试保存会话状态"""
        session_id = self.manager.create_session("test-session-200")
        self.test_session_ids.append(session_id)
        
        state_data = {
            "target": "http://example.com",
            "task_id": "task-001",
            "progress": 50
        }
        
        result = self.manager.save_session(session_id, state_data)
        
        assert result is True
        
        checkpoint = self.manager._sessions.get(session_id)
        assert checkpoint.channel_values["target"] == "http://example.com"
        assert checkpoint.channel_values["progress"] == 50
    
    def test_save_session_auto_create(self):
        """测试保存状态时自动创建会话"""
        state_data = {"key": "value"}
        
        result = self.manager.save_session("auto-create-session", state_data)
        self.test_session_ids.append("auto-create-session")
        
        assert result is True
        assert "auto-create-session" in self.manager._sessions
    
    def test_save_session_update(self):
        """测试更新会话状态"""
        session_id = self.manager.create_session("test-session-201")
        self.test_session_ids.append(session_id)
        
        self.manager.save_session(session_id, {"key1": "value1"})
        self.manager.save_session(session_id, {"key2": "value2"})
        
        checkpoint = self.manager._sessions.get(session_id)
        assert checkpoint.channel_values["key1"] == "value1"
        assert checkpoint.channel_values["key2"] == "value2"


class TestSessionMemoryManagerMessageOperations:
    """测试 SessionMemoryManager 消息操作"""
    
    def setup_method(self):
        """每个测试方法前的设置"""
        self.manager = SessionMemoryManager()
        self.test_session_ids = []
    
    def teardown_method(self):
        """每个测试方法后的清理"""
        for session_id in self.test_session_ids:
            self.manager.delete_session(session_id)
    
    def test_add_message(self):
        """测试添加消息"""
        session_id = self.manager.create_session("test-session-300")
        self.test_session_ids.append(session_id)
        
        result = self.manager.add_message(session_id, "user", "测试消息")
        
        assert result is True
        
        history = self.manager.get_message_history(session_id)
        assert len(history) == 1
        assert history[0]["role"] == "user"
        assert history[0]["content"] == "测试消息"
    
    def test_add_message_with_metadata(self):
        """测试添加带元数据的消息"""
        session_id = self.manager.create_session("test-session-301")
        self.test_session_ids.append(session_id)
        
        metadata = {"source": "api", "version": "1.0"}
        result = self.manager.add_message(session_id, "system", "系统消息", metadata=metadata)
        
        assert result is True
        
        history = self.manager.get_message_history(session_id)
        assert history[0]["metadata"] == metadata
    
    def test_add_message_to_nonexistent_session(self):
        """测试向不存在的会话添加消息"""
        result = self.manager.add_message("nonexistent", "user", "消息")
        
        assert result is False
    
    def test_get_message_history_limit(self):
        """测试获取消息历史限制"""
        session_id = self.manager.create_session("test-session-302")
        self.test_session_ids.append(session_id)
        
        for i in range(10):
            self.manager.add_message(session_id, "user", f"消息{i}")
        
        history = self.manager.get_message_history(session_id, limit=5)
        
        assert len(history) == 5
        assert history[0]["content"] == "消息5"
        assert history[4]["content"] == "消息9"
    
    def test_get_message_history_empty(self):
        """测试获取空消息历史"""
        session_id = self.manager.create_session("test-session-303")
        self.test_session_ids.append(session_id)
        
        history = self.manager.get_message_history(session_id)
        
        assert history == []
    
    def test_get_message_history_nonexistent_session(self):
        """测试获取不存在会话的消息历史"""
        history = self.manager.get_message_history("nonexistent-session")
        
        assert history == []


class TestSessionMemoryManagerThreadSafety:
    """测试 SessionMemoryManager 线程安全"""
    
    def setup_method(self):
        """每个测试方法前的设置"""
        self.manager = SessionMemoryManager()
        self.test_session_ids = []
    
    def teardown_method(self):
        """每个测试方法后的清理"""
        for session_id in self.test_session_ids:
            self.manager.delete_session(session_id)
    
    def test_concurrent_session_creation(self):
        """测试并发会话创建"""
        import threading
        
        created_sessions = []
        lock = threading.Lock()
        
        def create_session(index):
            session_id = self.manager.create_session(f"concurrent-session-{index}")
            with lock:
                created_sessions.append(session_id)
                self.test_session_ids.append(session_id)
        
        threads = []
        for i in range(10):
            t = threading.Thread(target=create_session, args=(i,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        assert len(created_sessions) == 10
        for session_id in created_sessions:
            assert session_id in self.manager._sessions
    
    def test_concurrent_message_adding(self):
        """测试并发消息添加"""
        import threading
        
        session_id = self.manager.create_session("concurrent-msg-session")
        self.test_session_ids.append(session_id)
        
        def add_message(index):
            self.manager.add_message(session_id, "user", f"消息{index}")
        
        threads = []
        for i in range(20):
            t = threading.Thread(target=add_message, args=(i,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        history = self.manager.get_message_history(session_id, limit=100)
        assert len(history) == 20


class TestSessionMemoryManagerEdgeCases:
    """测试 SessionMemoryManager 边界情况"""
    
    def setup_method(self):
        """每个测试方法前的设置"""
        self.manager = SessionMemoryManager()
        self.test_session_ids = []
    
    def teardown_method(self):
        """每个测试方法后的清理"""
        for session_id in self.test_session_ids:
            self.manager.delete_session(session_id)
    
    def test_save_large_state_data(self):
        """测试保存大量状态数据"""
        session_id = self.manager.create_session("test-large-state")
        self.test_session_ids.append(session_id)
        
        large_data = {
            f"key_{i}": f"value_{i}" * 100
            for i in range(100)
        }
        
        result = self.manager.save_session(session_id, large_data)
        
        assert result is True
        
        checkpoint = self.manager._sessions.get(session_id)
        assert len(checkpoint.channel_values) == 100
    
    def test_save_nested_state_data(self):
        """测试保存嵌套状态数据"""
        session_id = self.manager.create_session("test-nested-state")
        self.test_session_ids.append(session_id)
        
        nested_data = {
            "level1": {
                "level2": {
                    "level3": {
                        "value": "deep_value"
                    }
                }
            }
        }
        
        result = self.manager.save_session(session_id, nested_data)
        
        assert result is True
        
        checkpoint = self.manager._sessions.get(session_id)
        assert checkpoint.channel_values["level1"]["level2"]["level3"]["value"] == "deep_value"
    
    def test_special_characters_in_message(self):
        """测试消息中的特殊字符"""
        session_id = self.manager.create_session("test-special-chars")
        self.test_session_ids.append(session_id)
        
        special_content = "特殊字符: <>&\"'\\n\\t\\r 测试中文 emoji: 😀🎉"
        
        result = self.manager.add_message(session_id, "user", special_content)
        
        assert result is True
        
        history = self.manager.get_message_history(session_id)
        assert history[0]["content"] == special_content
    
    def test_empty_session_id(self):
        """测试空会话ID"""
        session_id = self.manager.create_session("")
        self.test_session_ids.append(session_id)
        
        assert session_id == ""
        assert "" in self.manager._sessions


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
