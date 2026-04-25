# -*- coding:utf-8 -*-
"""
AgentState 持久化测试模块

测试 AgentState 的状态持久化功能：
- save_to_session_memory 方法
- load_from_session_memory 方法
- 状态序列化和反序列化
"""

import sys
import os
import pytest
import json
import time
from datetime import datetime
from unittest.mock import patch, MagicMock
from typing import Dict, Any, List

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

from TOSKill.AI.state import AgentState, DataIntegrityError, StatePersistenceError
from TOSKill.AI.memory.session_memory import SessionMemoryManager, get_memory_manager


class TestAgentStateSaveToSessionMemory:
    """测试 AgentState.save_to_session_memory 方法"""
    
    def setup_method(self):
        """每个测试方法前的设置"""
        self.manager = get_memory_manager()
        self.test_session_ids = []
    
    def teardown_method(self):
        """每个测试方法后的清理"""
        for session_id in self.test_session_ids:
            self.manager.delete_session(session_id)
    
    def test_save_to_session_memory_basic(self):
        """测试基本保存功能"""
        state = AgentState(
            target="http://example.com",
            task_id="test-save-001",
            chat_instance_id="session-save-001"
        )
        self.test_session_ids.append("session-save-001")
        
        state.planned_tasks = ["task1", "task2"]
        state.completed_tasks = ["task1"]
        
        result = state.save_to_session_memory()
        
        assert result is True
        
        checkpoint = self.manager._sessions.get("session-save-001")
        assert checkpoint is not None
        assert checkpoint.channel_values["target"] == "http://example.com"
        assert checkpoint.channel_values["task_id"] == "test-save-001"
    
    def test_save_to_session_memory_with_task_id(self):
        """测试使用 task_id 作为 session_id"""
        state = AgentState(
            target="http://example.com",
            task_id="test-save-002"
        )
        self.test_session_ids.append("test-save-002")
        
        result = state.save_to_session_memory()
        
        assert result is True
        assert "test-save-002" in self.manager._sessions
    
    def test_save_to_session_memory_includes_metadata(self):
        """测试保存包含元数据"""
        state = AgentState(
            target="http://example.com",
            task_id="test-save-003",
            chat_instance_id="session-save-003"
        )
        self.test_session_ids.append("session-save-003")
        
        state.save_to_session_memory()
        
        checkpoint = self.manager._sessions.get("session-save-003")
        assert "_state_metadata" in checkpoint.channel_values
        assert "saved_at" in checkpoint.channel_values["_state_metadata"]
        assert checkpoint.channel_values["_state_metadata"]["task_id"] == "test-save-003"
    
    def test_save_to_session_memory_preserves_workflow_status(self):
        """测试保存工作流状态"""
        state = AgentState(
            target="http://example.com",
            task_id="test-save-004",
            chat_instance_id="session-save-004"
        )
        self.test_session_ids.append("session-save-004")
        
        state.set_workflow_running()
        state.save_to_session_memory()
        
        checkpoint = self.manager._sessions.get("session-save-004")
        assert checkpoint.channel_values["workflow_status"] == "running"
    
    def test_save_to_session_memory_preserves_vulnerabilities(self):
        """测试保存漏洞数据"""
        state = AgentState(
            target="http://example.com",
            task_id="test-save-005",
            chat_instance_id="session-save-005"
        )
        self.test_session_ids.append("session-save-005")
        
        state.add_vulnerability({"type": "SQLi", "severity": "high"})
        state.add_vulnerability({"type": "XSS", "severity": "medium"})
        
        state.save_to_session_memory()
        
        checkpoint = self.manager._sessions.get("session-save-005")
        assert len(checkpoint.channel_values["vulnerabilities"]) == 2
    
    def test_save_to_session_memory_preserves_tool_results(self):
        """测试保存工具结果"""
        state = AgentState(
            target="http://example.com",
            task_id="test-save-006",
            chat_instance_id="session-save-006"
        )
        self.test_session_ids.append("session-save-006")
        
        state.tool_results = {
            "portscan": {"ports": [80, 443]},
            "baseinfo": {"server": "nginx"}
        }
        
        state.save_to_session_memory()
        
        checkpoint = self.manager._sessions.get("session-save-006")
        assert "portscan" in checkpoint.channel_values["tool_results"]
        assert checkpoint.channel_values["tool_results"]["portscan"]["ports"] == [80, 443]
    
    def test_save_to_session_memory_auto_create_session(self):
        """测试自动创建会话"""
        state = AgentState(
            target="http://example.com",
            task_id="test-save-007",
            chat_instance_id="auto-create-session-007"
        )
        self.test_session_ids.append("auto-create-session-007")
        
        assert "auto-create-session-007" not in self.manager._sessions
        
        result = state.save_to_session_memory()
        
        assert result is True
        assert "auto-create-session-007" in self.manager._sessions
    
    def test_save_to_session_memory_update_existing(self):
        """测试更新已存在的会话"""
        state = AgentState(
            target="http://example.com",
            task_id="test-save-008",
            chat_instance_id="session-save-008"
        )
        self.test_session_ids.append("session-save-008")
        
        state.planned_tasks = ["task1"]
        state.save_to_session_memory()
        
        state.planned_tasks = ["task1", "task2", "task3"]
        state.completed_tasks = ["task1"]
        state.save_to_session_memory()
        
        checkpoint = self.manager._sessions.get("session-save-008")
        assert len(checkpoint.channel_values["planned_tasks"]) == 3
        assert len(checkpoint.channel_values["completed_tasks"]) == 1


class TestAgentStateLoadFromSessionMemory:
    """测试 AgentState.load_from_session_memory 方法"""
    
    def setup_method(self):
        """每个测试方法前的设置"""
        self.manager = get_memory_manager()
        self.test_session_ids = []
    
    def teardown_method(self):
        """每个测试方法后的清理"""
        for session_id in self.test_session_ids:
            self.manager.delete_session(session_id)
    
    def test_load_from_session_memory_basic(self):
        """测试基本加载功能"""
        original_state = AgentState(
            target="http://example.com",
            task_id="test-load-001",
            chat_instance_id="session-load-001"
        )
        self.test_session_ids.append("session-load-001")
        
        original_state.planned_tasks = ["task1", "task2"]
        original_state.completed_tasks = ["task1"]
        original_state.save_to_session_memory()
        
        loaded_state = AgentState.load_from_session_memory("session-load-001")
        
        assert loaded_state is not None
        assert loaded_state.target == "http://example.com"
        assert loaded_state.task_id == "test-load-001"
        assert loaded_state.planned_tasks == ["task1", "task2"]
        assert loaded_state.completed_tasks == ["task1"]
    
    def test_load_from_session_memory_nonexistent(self):
        """测试加载不存在的会话"""
        loaded_state = AgentState.load_from_session_memory("nonexistent-session")
        
        assert loaded_state is None
    
    def test_load_from_session_memory_preserves_vulnerabilities(self):
        """测试加载漏洞数据"""
        original_state = AgentState(
            target="http://example.com",
            task_id="test-load-002",
            chat_instance_id="session-load-002"
        )
        self.test_session_ids.append("session-load-002")
        
        original_state.add_vulnerability({"type": "SQLi", "severity": "high"})
        original_state.add_vulnerability({"type": "XSS", "severity": "medium"})
        original_state.save_to_session_memory()
        
        loaded_state = AgentState.load_from_session_memory("session-load-002")
        
        assert loaded_state is not None
        assert len(loaded_state.vulnerabilities) == 2
        assert loaded_state.vulnerabilities[0]["type"] == "SQLi"
    
    def test_load_from_session_memory_preserves_workflow_status(self):
        """测试加载工作流状态"""
        original_state = AgentState(
            target="http://example.com",
            task_id="test-load-003",
            chat_instance_id="session-load-003"
        )
        self.test_session_ids.append("session-load-003")
        
        original_state.set_workflow_running()
        original_state.pause_workflow("测试暂停")
        original_state.save_to_session_memory()
        
        loaded_state = AgentState.load_from_session_memory("session-load-003")
        
        assert loaded_state is not None
        assert loaded_state.workflow_status == "paused"
        assert loaded_state.workflow_paused is True
    
    def test_load_from_session_memory_preserves_chat_history(self):
        """测试加载聊天历史"""
        original_state = AgentState(
            target="http://example.com",
            task_id="test-load-004",
            chat_instance_id="session-load-004"
        )
        self.test_session_ids.append("session-load-004")
        
        original_state.append_chat_history("user", "你好")
        original_state.append_chat_history("assistant", "你好！")
        original_state.save_to_session_memory()
        
        loaded_state = AgentState.load_from_session_memory("session-load-004")
        
        assert loaded_state is not None
        assert len(loaded_state.chat_history) == 2
        assert loaded_state.chat_history[0]["role"] == "user"
    
    def test_load_from_session_memory_preserves_metadata(self):
        """测试加载元数据"""
        original_state = AgentState(
            target="http://example.com",
            task_id="test-load-005",
            chat_instance_id="session-load-005"
        )
        self.test_session_ids.append("session-load-005")
        
        original_state.save_to_session_memory()
        
        loaded_state = AgentState.load_from_session_memory("session-load-005")
        
        assert loaded_state is not None
        assert "_state_metadata" in loaded_state.persistence_metadata
        assert "saved_at" in loaded_state.persistence_metadata


class TestAgentStateSerialization:
    """测试 AgentState 序列化和反序列化"""
    
    def test_to_dict_basic(self):
        """测试基本序列化"""
        state = AgentState(
            target="http://example.com",
            task_id="test-serial-001"
        )
        
        state_dict = state.to_dict()
        
        assert state_dict["target"] == "http://example.com"
        assert state_dict["task_id"] == "test-serial-001"
        assert "created_at" in state_dict
        assert "updated_at" in state_dict
    
    def test_from_dict_basic(self):
        """测试基本反序列化"""
        data = {
            "target": "http://test.com",
            "task_id": "test-serial-002",
            "planned_tasks": ["task1", "task2"],
            "completed_tasks": ["task1"]
        }
        
        state = AgentState.from_dict(data)
        
        assert state.target == "http://test.com"
        assert state.task_id == "test-serial-002"
        assert state.planned_tasks == ["task1", "task2"]
        assert state.completed_tasks == ["task1"]
    
    def test_serialization_roundtrip(self):
        """测试序列化往返"""
        original_state = AgentState(
            target="http://example.com",
            task_id="test-serial-003"
        )
        
        original_state.planned_tasks = ["task1", "task2", "task3"]
        original_state.completed_tasks = ["task1"]
        original_state.tool_results = {"tool1": {"result": "success"}}
        original_state.vulnerabilities = [{"type": "SQLi"}]
        original_state.append_chat_history("user", "测试消息")
        original_state.add_error("test error")
        
        state_dict = original_state.to_dict()
        restored_state = AgentState.from_dict(state_dict)
        
        assert restored_state.target == original_state.target
        assert restored_state.task_id == original_state.task_id
        assert restored_state.planned_tasks == original_state.planned_tasks
        assert restored_state.completed_tasks == original_state.completed_tasks
        assert restored_state.tool_results == original_state.tool_results
        assert restored_state.vulnerabilities == original_state.vulnerabilities
        assert len(restored_state.chat_history) == 1
        assert restored_state.errors == original_state.errors
    
    def test_serialization_with_nested_data(self):
        """测试嵌套数据序列化"""
        state = AgentState(
            target="http://example.com",
            task_id="test-serial-004"
        )
        
        state.target_context = {
            "server": "nginx",
            "ports": [80, 443, 8080],
            "headers": {
                "X-Frame-Options": "DENY",
                "Content-Security-Policy": "default-src 'self'"
            },
            "technologies": ["React", "Node.js", "MongoDB"]
        }
        
        state_dict = state.to_dict()
        restored_state = AgentState.from_dict(state_dict)
        
        assert restored_state.target_context["server"] == "nginx"
        assert restored_state.target_context["ports"] == [80, 443, 8080]
        assert "X-Frame-Options" in restored_state.target_context["headers"]
    
    def test_serialization_with_stage_status(self):
        """测试阶段状态序列化"""
        state = AgentState(
            target="http://example.com",
            task_id="test-serial-005"
        )
        
        state.update_stage_status("planning", "running", "executing", 50, "正在规划")
        state.update_stage_status("tool_execution", "pending", None, 0, None)
        
        state_dict = state.to_dict()
        restored_state = AgentState.from_dict(state_dict)
        
        assert restored_state.stage_status["planning"]["status"] == "running"
        assert restored_state.stage_status["planning"]["progress"] == 50
        assert restored_state.stage_status["tool_execution"]["status"] == "pending"
    
    def test_serialization_preserves_datetime_fields(self):
        """测试日期时间字段序列化"""
        state = AgentState(
            target="http://example.com",
            task_id="test-serial-006"
        )
        
        state_dict = state.to_dict()
        
        assert "created_at" in state_dict
        assert "updated_at" in state_dict
        
        restored_state = AgentState.from_dict(state_dict)
        assert restored_state.created_at == state.created_at


class TestAgentStateDataIntegrity:
    """测试 AgentState 数据完整性"""
    
    def test_validate_data_integrity_valid(self):
        """测试有效数据完整性验证"""
        state = AgentState(
            target="http://example.com",
            task_id="test-integrity-001"
        )
        
        state.execution_history = [{"task": "test", "timestamp": 123}]
        state.tool_results = {"tool1": {}}
        state.vulnerabilities = [{"type": "SQLi"}]
        state.chat_history = [{"role": "user", "content": "test"}]
        
        result = state.validate_data_integrity()
        
        assert result["is_valid"] is True
        assert len(result["errors"]) == 0
    
    def test_validate_data_integrity_missing_field(self):
        """测试缺少字段的数据完整性"""
        state = AgentState(
            target="http://example.com",
            task_id="test-integrity-002"
        )
        
        state.execution_history = None
        
        result = state.validate_data_integrity()
        
        assert result["is_valid"] is False
        assert any("execution_history" in e for e in result["errors"])
    
    def test_validate_data_integrity_wrong_type(self):
        """测试错误类型的数据完整性"""
        state = AgentState(
            target="http://example.com",
            task_id="test-integrity-003"
        )
        
        state.tool_results = "not a dict"
        
        result = state.validate_data_integrity()
        
        assert result["is_valid"] is False
    
    def test_ensure_data_integrity_fixes_issues(self):
        """测试 ensure_data_integrity 修复问题"""
        state = AgentState(
            target="http://example.com",
            task_id="test-integrity-004"
        )
        
        state.execution_history = "not a list"
        state.tool_results = "not a dict"
        state.vulnerabilities = None
        
        state.ensure_data_integrity()
        
        assert isinstance(state.execution_history, list)
        assert isinstance(state.tool_results, dict)
        assert isinstance(state.vulnerabilities, list)
    
    def test_ensure_data_integrity_raises_on_invalid(self):
        """测试 ensure_data_integrity 在无效数据时抛出异常"""
        state = AgentState(
            target="",
            task_id=""
        )
        
        state.target = None
        state.task_id = None
        
        with pytest.raises(DataIntegrityError):
            state.ensure_data_integrity()


class TestAgentStatePersistenceEdgeCases:
    """测试 AgentState 持久化边界情况"""
    
    def setup_method(self):
        """每个测试方法前的设置"""
        self.manager = get_memory_manager()
        self.test_session_ids = []
    
    def teardown_method(self):
        """每个测试方法后的清理"""
        for session_id in self.test_session_ids:
            self.manager.delete_session(session_id)
    
    def test_save_load_with_large_data(self):
        """测试大数据量保存加载"""
        state = AgentState(
            target="http://example.com",
            task_id="test-edge-001",
            chat_instance_id="session-edge-001"
        )
        self.test_session_ids.append("session-edge-001")
        
        for i in range(100):
            state.execution_history.append({
                "step_number": i,
                "task": f"task_{i}",
                "timestamp": time.time(),
                "result": {"data": f"result_{i}" * 10}
            })
        
        for i in range(50):
            state.vulnerabilities.append({
                "type": f"vuln_{i}",
                "severity": "high",
                "description": f"描述_{i}" * 20
            })
        
        state.save_to_session_memory()
        loaded_state = AgentState.load_from_session_memory("session-edge-001")
        
        assert loaded_state is not None
        assert len(loaded_state.execution_history) == 100
        assert len(loaded_state.vulnerabilities) == 50
    
    def test_save_load_with_unicode(self):
        """测试 Unicode 数据保存加载"""
        state = AgentState(
            target="http://example.com",
            task_id="test-edge-002",
            chat_instance_id="session-edge-002"
        )
        self.test_session_ids.append("session-edge-002")
        
        state.append_chat_history("user", "你好，世界！🌍🎉")
        state.append_chat_history("assistant", "你好！我可以帮助你进行安全测试。")
        state.add_vulnerability({
            "type": "SQL注入",
            "description": "发现SQL注入漏洞，位置：/搜索接口",
            "severity": "高危"
        })
        
        state.save_to_session_memory()
        loaded_state = AgentState.load_from_session_memory("session-edge-002")
        
        assert loaded_state is not None
        assert loaded_state.chat_history[0]["content"] == "你好，世界！🌍🎉"
        assert loaded_state.vulnerabilities[0]["type"] == "SQL注入"
    
    def test_save_load_with_special_characters(self):
        """测试特殊字符数据保存加载"""
        state = AgentState(
            target="http://example.com",
            task_id="test-edge-003",
            chat_instance_id="session-edge-003"
        )
        self.test_session_ids.append("session-edge-003")
        
        special_content = "特殊字符: <>&\"'\\n\\t\\r<script>alert('xss')</script>"
        state.append_chat_history("user", special_content)
        
        state.save_to_session_memory()
        loaded_state = AgentState.load_from_session_memory("session-edge-003")
        
        assert loaded_state is not None
        assert loaded_state.chat_history[0]["content"] == special_content
    
    def test_save_load_preserves_empty_collections(self):
        """测试空集合保存加载"""
        state = AgentState(
            target="http://example.com",
            task_id="test-edge-004",
            chat_instance_id="session-edge-004"
        )
        self.test_session_ids.append("session-edge-004")
        
        state.planned_tasks = []
        state.completed_tasks = []
        state.vulnerabilities = []
        state.execution_history = []
        state.tool_results = {}
        
        state.save_to_session_memory()
        loaded_state = AgentState.load_from_session_memory("session-edge-004")
        
        assert loaded_state is not None
        assert loaded_state.planned_tasks == []
        assert loaded_state.completed_tasks == []
        assert loaded_state.vulnerabilities == []
        assert loaded_state.execution_history == []
        assert loaded_state.tool_results == {}


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
