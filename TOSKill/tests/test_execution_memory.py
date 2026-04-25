# -*- coding:utf-8 -*-
"""
任务执行记忆测试模块

测试任务执行历史的记忆存储功能：
- sync_execution_history 方法
- 执行历史增量同步
- 执行历史恢复
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


class TestSyncExecutionHistory:
    """测试 sync_execution_history 方法"""
    
    def setup_method(self):
        """每个测试方法前的设置"""
        self.manager = get_memory_manager()
        self.test_session_ids = []
    
    def teardown_method(self):
        """每个测试方法后的清理"""
        for session_id in self.test_session_ids:
            self.manager.delete_session(session_id)
    
    def test_sync_execution_history_basic(self):
        """测试基本执行历史同步"""
        state = AgentState(
            target="http://example.com",
            task_id="test-exec-001",
            chat_instance_id="session-exec-001"
        )
        self.test_session_ids.append("session-exec-001")
        
        state.add_execution_step("baseinfo", {"server": "nginx"}, "success")
        state.add_execution_step("portscan", {"ports": [80, 443]}, "success")
        
        result = state.sync_execution_history()
        
        assert result is True
        
        checkpoint = self.manager._sessions.get("session-exec-001")
        assert checkpoint is not None
        assert "execution_history" in checkpoint.channel_values
        assert len(checkpoint.channel_values["execution_history"]) == 2
    
    def test_sync_execution_history_auto_create_session(self):
        """测试自动创建会话"""
        state = AgentState(
            target="http://example.com",
            task_id="test-exec-002",
            chat_instance_id="auto-create-exec-002"
        )
        self.test_session_ids.append("auto-create-exec-002")
        
        assert "auto-create-exec-002" not in self.manager._sessions
        
        state.add_execution_step("test", {}, "success")
        result = state.sync_execution_history()
        
        assert result is True
        assert "auto-create-exec-002" in self.manager._sessions
    
    def test_sync_execution_history_with_task_id(self):
        """测试使用 task_id 作为 session_id"""
        state = AgentState(
            target="http://example.com",
            task_id="test-exec-003"
        )
        self.test_session_ids.append("test-exec-003")
        
        state.add_execution_step("test", {}, "success")
        result = state.sync_execution_history()
        
        assert result is True
        
        checkpoint = self.manager._sessions.get("test-exec-003")
        assert checkpoint is not None
    
    def test_sync_execution_history_with_custom_steps(self):
        """测试同步自定义执行步骤列表"""
        state = AgentState(
            target="http://example.com",
            task_id="test-exec-004",
            chat_instance_id="session-exec-004"
        )
        self.test_session_ids.append("session-exec-004")
        
        custom_steps = [
            {"step_number": 1, "task": "custom1", "timestamp": time.time(), "status": "success"},
            {"step_number": 2, "task": "custom2", "timestamp": time.time(), "status": "success"}
        ]
        
        result = state.sync_execution_history(steps=custom_steps)
        
        assert result is True
        
        checkpoint = self.manager._sessions.get("session-exec-004")
        assert len(checkpoint.channel_values["execution_history"]) == 2


class TestExecutionHistoryIncrementalSync:
    """测试执行历史增量同步"""
    
    def setup_method(self):
        """每个测试方法前的设置"""
        self.manager = get_memory_manager()
        self.test_session_ids = []
    
    def teardown_method(self):
        """每个测试方法后的清理"""
        for session_id in self.test_session_ids:
            self.manager.delete_session(session_id)
    
    def test_incremental_sync_new_steps(self):
        """测试增量同步新步骤"""
        state = AgentState(
            target="http://example.com",
            task_id="test-incremental-exec-001",
            chat_instance_id="session-incremental-exec-001"
        )
        self.test_session_ids.append("session-incremental-exec-001")
        
        state.add_execution_step("step1", {}, "success")
        state.sync_execution_history()
        
        checkpoint = self.manager._sessions.get("session-incremental-exec-001")
        assert len(checkpoint.channel_values["execution_history"]) == 1
        
        state.add_execution_step("step2", {}, "success")
        state.add_execution_step("step3", {}, "success")
        state.sync_execution_history()
        
        checkpoint = self.manager._sessions.get("session-incremental-exec-001")
        assert len(checkpoint.channel_values["execution_history"]) == 3
    
    def test_incremental_sync_avoids_duplicates(self):
        """测试增量同步避免重复"""
        state = AgentState(
            target="http://example.com",
            task_id="test-incremental-exec-002",
            chat_instance_id="session-incremental-exec-002"
        )
        self.test_session_ids.append("session-incremental-exec-002")
        
        state.add_execution_step("step1", {}, "success")
        state.sync_execution_history()
        
        state.sync_execution_history()
        
        checkpoint = self.manager._sessions.get("session-incremental-exec-002")
        assert len(checkpoint.channel_values["execution_history"]) == 1
    
    def test_incremental_sync_with_step_number_check(self):
        """测试基于步骤编号的增量同步"""
        state = AgentState(
            target="http://example.com",
            task_id="test-incremental-exec-003",
            chat_instance_id="session-incremental-exec-003"
        )
        self.test_session_ids.append("session-incremental-exec-003")
        
        state.add_execution_step("step1", {}, "success")
        state.sync_execution_history()
        
        state.add_execution_step("step2", {}, "success")
        state.sync_execution_history()
        
        checkpoint = self.manager._sessions.get("session-incremental-exec-003")
        history = checkpoint.channel_values["execution_history"]
        step_numbers = [s.get("step_number") for s in history]
        assert 1 in step_numbers
        assert 2 in step_numbers
    
    def test_incremental_sync_with_timestamp_check(self):
        """测试基于时间戳的增量同步"""
        state = AgentState(
            target="http://example.com",
            task_id="test-incremental-exec-004",
            chat_instance_id="session-incremental-exec-004"
        )
        self.test_session_ids.append("session-incremental-exec-004")
        
        timestamp1 = time.time()
        state.execution_history.append({
            "step_number": 1,
            "task": "step1",
            "timestamp": timestamp1,
            "status": "success"
        })
        state.sync_execution_history()
        
        time.sleep(0.01)
        timestamp2 = time.time()
        state.execution_history.append({
            "step_number": 2,
            "task": "step2",
            "timestamp": timestamp2,
            "status": "success"
        })
        state.sync_execution_history()
        
        checkpoint = self.manager._sessions.get("session-incremental-exec-004")
        assert len(checkpoint.channel_values["execution_history"]) == 2
    
    def test_incremental_sync_multiple_batches(self):
        """测试多批次增量同步"""
        state = AgentState(
            target="http://example.com",
            task_id="test-incremental-exec-005",
            chat_instance_id="session-incremental-exec-005"
        )
        self.test_session_ids.append("session-incremental-exec-005")
        
        for i in range(5):
            state.add_execution_step(f"batch1-step{i}", {}, "success")
        state.sync_execution_history()
        
        checkpoint = self.manager._sessions.get("session-incremental-exec-005")
        assert len(checkpoint.channel_values["execution_history"]) == 5
        
        for i in range(5):
            state.add_execution_step(f"batch2-step{i}", {}, "success")
        state.sync_execution_history()
        
        checkpoint = self.manager._sessions.get("session-incremental-exec-005")
        assert len(checkpoint.channel_values["execution_history"]) == 10


class TestExecutionHistoryRecovery:
    """测试执行历史恢复"""
    
    def setup_method(self):
        """每个测试方法前的设置"""
        self.manager = get_memory_manager()
        self.test_session_ids = []
    
    def teardown_method(self):
        """每个测试方法后的清理"""
        for session_id in self.test_session_ids:
            self.manager.delete_session(session_id)
    
    def test_recover_execution_history_from_session(self):
        """测试从会话恢复执行历史"""
        state = AgentState(
            target="http://example.com",
            task_id="test-recovery-exec-001",
            chat_instance_id="session-recovery-exec-001"
        )
        self.test_session_ids.append("session-recovery-exec-001")
        
        state.add_execution_step("baseinfo", {"server": "nginx"}, "success")
        state.add_execution_step("portscan", {"ports": [80, 443]}, "success")
        state.sync_execution_history()
        state.save_to_session_memory()
        
        loaded_state = AgentState.load_from_session_memory("session-recovery-exec-001")
        
        assert loaded_state is not None
        assert len(loaded_state.execution_history) == 2
        assert loaded_state.execution_history[0]["task"] == "baseinfo"
    
    def test_recover_execution_history_preserves_order(self):
        """测试恢复执行历史保持顺序"""
        state = AgentState(
            target="http://example.com",
            task_id="test-recovery-exec-002",
            chat_instance_id="session-recovery-exec-002"
        )
        self.test_session_ids.append("session-recovery-exec-002")
        
        tasks = ["baseinfo", "portscan", "subdomain", "waf_detect", "vuln_scan"]
        for task in tasks:
            state.add_execution_step(task, {}, "success")
        
        state.sync_execution_history()
        state.save_to_session_memory()
        
        loaded_state = AgentState.load_from_session_memory("session-recovery-exec-002")
        
        assert loaded_state is not None
        for i, task in enumerate(tasks):
            assert loaded_state.execution_history[i]["task"] == task
    
    def test_recover_execution_history_with_results(self):
        """测试恢复带结果的执行历史"""
        state = AgentState(
            target="http://example.com",
            task_id="test-recovery-exec-003",
            chat_instance_id="session-recovery-exec-003"
        )
        self.test_session_ids.append("session-recovery-exec-003")
        
        state.add_execution_step("portscan", {"ports": [80, 443, 8080]}, "success")
        state.add_execution_step("sqli_scan", {"vulnerabilities": []}, "success")
        
        state.sync_execution_history()
        state.save_to_session_memory()
        
        loaded_state = AgentState.load_from_session_memory("session-recovery-exec-003")
        
        assert loaded_state is not None
        assert loaded_state.execution_history[0]["result"]["ports"] == [80, 443, 8080]
    
    def test_recover_empty_execution_history(self):
        """测试恢复空执行历史"""
        state = AgentState(
            target="http://example.com",
            task_id="test-recovery-exec-004",
            chat_instance_id="session-recovery-exec-004"
        )
        self.test_session_ids.append("session-recovery-exec-004")
        
        state.sync_execution_history()
        state.save_to_session_memory()
        
        loaded_state = AgentState.load_from_session_memory("session-recovery-exec-004")
        
        assert loaded_state is not None
        assert loaded_state.execution_history == []


class TestAddExecutionStep:
    """测试 add_execution_step 方法"""
    
    def test_add_execution_step_basic(self):
        """测试基本添加执行步骤"""
        state = AgentState(
            target="http://example.com",
            task_id="test-add-step-001"
        )
        
        state.add_execution_step("baseinfo", {"server": "nginx"}, "success")
        
        assert len(state.execution_history) == 1
        assert state.execution_history[0]["task"] == "baseinfo"
        assert state.execution_history[0]["status"] == "success"
        assert "timestamp" in state.execution_history[0]
    
    def test_add_execution_step_multiple(self):
        """测试添加多个执行步骤"""
        state = AgentState(
            target="http://example.com",
            task_id="test-add-step-002"
        )
        
        for i in range(5):
            state.add_execution_step(f"task{i}", {"index": i}, "success")
        
        assert len(state.execution_history) == 5
    
    def test_add_execution_step_auto_numbering(self):
        """测试自动步骤编号"""
        state = AgentState(
            target="http://example.com",
            task_id="test-add-step-003"
        )
        
        for i in range(1, 4):
            state.add_execution_step(f"task{i}", {}, "success")
        
        for i, step in enumerate(state.execution_history, 1):
            assert step["step_number"] == i
    
    def test_add_execution_step_with_status(self):
        """测试不同状态的执行步骤"""
        state = AgentState(
            target="http://example.com",
            task_id="test-add-step-004"
        )
        
        state.add_execution_step("success_task", {}, "success")
        state.add_execution_step("failed_task", {}, "failed")
        state.add_execution_step("running_task", {}, "running")
        
        assert state.execution_history[0]["status"] == "success"
        assert state.execution_history[1]["status"] == "failed"
        assert state.execution_history[2]["status"] == "running"
    
    def test_add_execution_step_with_step_type(self):
        """测试不同步骤类型"""
        state = AgentState(
            target="http://example.com",
            task_id="test-add-step-005"
        )
        
        state.add_execution_step("tool_exec", {}, "success", step_type="tool_execution")
        state.add_execution_step("planning", {}, "success", step_type="planning")
        
        assert state.execution_history[0]["step_type"] == "tool_execution"
        assert state.execution_history[1]["step_type"] == "planning"


class TestAddScanResult:
    """测试 add_scan_result 方法"""
    
    def test_add_scan_result_basic(self):
        """测试基本添加扫描结果"""
        state = AgentState(
            target="http://example.com",
            task_id="test-scan-001"
        )
        
        state.add_scan_result(
            tool_name="portscan",
            result={"ports": [80, 443]},
            execution_time=1.5,
            success=True
        )
        
        assert "portscan" in state.tool_results
        assert len(state.execution_history) == 1
        assert state.execution_history[0]["tool_name"] == "portscan"
    
    def test_add_scan_result_with_vulnerabilities(self):
        """测试添加带漏洞的扫描结果"""
        state = AgentState(
            target="http://example.com",
            task_id="test-scan-002"
        )
        
        state.add_scan_result(
            tool_name="sqli_scan",
            result={
                "vulnerabilities": [
                    {"type": "SQLi", "severity": "high"},
                    {"type": "SQLi", "severity": "medium"}
                ]
            },
            execution_time=2.0,
            success=True
        )
        
        assert len(state.vulnerabilities) == 2
        assert state.vulnerabilities[0]["_source_tool"] == "sqli_scan"
    
    def test_add_scan_result_with_context_update(self):
        """测试添加扫描结果更新上下文"""
        state = AgentState(
            target="http://example.com",
            task_id="test-scan-003"
        )
        
        state.add_scan_result(
            tool_name="portscan",
            result={"ports": [80, 443, 8080]},
            execution_time=1.0,
            success=True
        )
        
        assert "open_ports" in state.target_context
        assert 80 in state.target_context["open_ports"]
    
    def test_add_scan_result_failed(self):
        """测试添加失败的扫描结果"""
        state = AgentState(
            target="http://example.com",
            task_id="test-scan-004"
        )
        
        state.add_scan_result(
            tool_name="failed_tool",
            result={"error": "Connection refused"},
            execution_time=0.5,
            success=False
        )
        
        assert "failed_tool" in state.tool_results
        assert state.execution_history[0]["success"] is False


class TestExecutionHistoryIntegration:
    """测试执行历史集成功能"""
    
    def setup_method(self):
        """每个测试方法前的设置"""
        self.manager = get_memory_manager()
        self.test_session_ids = []
    
    def teardown_method(self):
        """每个测试方法后的清理"""
        for session_id in self.test_session_ids:
            self.manager.delete_session(session_id)
    
    def test_full_execution_flow(self):
        """测试完整执行流程"""
        state = AgentState(
            target="http://example.com",
            task_id="test-flow-exec-001",
            chat_instance_id="session-flow-exec-001"
        )
        self.test_session_ids.append("session-flow-exec-001")
        
        state.add_execution_step("baseinfo", {"server": "nginx"}, "success")
        state.sync_execution_history()
        
        state.add_execution_step("portscan", {"ports": [80, 443]}, "success")
        state.sync_execution_history()
        
        state.add_execution_step("vuln_scan", {"vulnerabilities": []}, "success")
        state.sync_execution_history()
        
        state.save_to_session_memory()
        
        loaded_state = AgentState.load_from_session_memory("session-flow-exec-001")
        
        assert loaded_state is not None
        assert len(loaded_state.execution_history) == 3
    
    def test_execution_history_with_state_changes(self):
        """测试执行历史与状态变化"""
        state = AgentState(
            target="http://example.com",
            task_id="test-flow-exec-002",
            chat_instance_id="session-flow-exec-002"
        )
        self.test_session_ids.append("session-flow-exec-002")
        
        state.set_workflow_running()
        state.add_execution_step("planning", {}, "success")
        state.sync_execution_history()
        
        state.update_stage_status("planning", "completed", None, 100)
        state.add_execution_step("execution", {}, "success")
        state.sync_execution_history()
        
        state.save_to_session_memory()
        
        loaded_state = AgentState.load_from_session_memory("session-flow-exec-002")
        
        assert loaded_state is not None
        assert loaded_state.workflow_status == "running"
        assert len(loaded_state.execution_history) == 2
    
    def test_execution_history_persistence_across_sessions(self):
        """测试跨会话的执行历史持久化"""
        state1 = AgentState(
            target="http://example.com",
            task_id="test-persist-exec-001",
            chat_instance_id="session-persist-exec-001"
        )
        self.test_session_ids.append("session-persist-exec-001")
        
        state1.add_execution_step("step1", {}, "success")
        state1.sync_execution_history()
        state1.save_to_session_memory()
        
        state2 = AgentState.load_from_session_memory("session-persist-exec-001")
        
        state2.add_execution_step("step2", {}, "success")
        state2.sync_execution_history()
        state2.save_to_session_memory()
        
        state3 = AgentState.load_from_session_memory("session-persist-exec-001")
        
        assert state3 is not None
        assert len(state3.execution_history) == 2


class TestExecutionHistoryEdgeCases:
    """测试执行历史边界情况"""
    
    def setup_method(self):
        """每个测试方法前的设置"""
        self.manager = get_memory_manager()
        self.test_session_ids = []
    
    def teardown_method(self):
        """每个测试方法后的清理"""
        for session_id in self.test_session_ids:
            self.manager.delete_session(session_id)
    
    def test_sync_empty_execution_history(self):
        """测试同步空执行历史"""
        state = AgentState(
            target="http://example.com",
            task_id="test-edge-exec-001",
            chat_instance_id="session-edge-exec-001"
        )
        self.test_session_ids.append("session-edge-exec-001")
        
        result = state.sync_execution_history()
        
        assert result is True
        
        checkpoint = self.manager._sessions.get("session-edge-exec-001")
        assert "execution_history" not in checkpoint.channel_values or \
               checkpoint.channel_values["execution_history"] == []
    
    def test_sync_large_execution_history(self):
        """测试同步大量执行历史"""
        state = AgentState(
            target="http://example.com",
            task_id="test-edge-exec-002",
            chat_instance_id="session-edge-exec-002"
        )
        self.test_session_ids.append("session-edge-exec-002")
        
        for i in range(100):
            state.add_execution_step(f"task_{i}", {"data": f"result_{i}"}, "success")
        
        result = state.sync_execution_history()
        
        assert result is True
        
        checkpoint = self.manager._sessions.get("session-edge-exec-002")
        assert len(checkpoint.channel_values["execution_history"]) == 100
    
    def test_sync_execution_with_nested_results(self):
        """测试同步嵌套结果的执行历史"""
        state = AgentState(
            target="http://example.com",
            task_id="test-edge-exec-003",
            chat_instance_id="session-edge-exec-003"
        )
        self.test_session_ids.append("session-edge-exec-003")
        
        nested_result = {
            "level1": {
                "level2": {
                    "level3": {
                        "data": ["item1", "item2", "item3"]
                    }
                }
            }
        }
        
        state.add_execution_step("nested_task", nested_result, "success")
        state.sync_execution_history()
        
        checkpoint = self.manager._sessions.get("session-edge-exec-003")
        saved_result = checkpoint.channel_values["execution_history"][0]["result"]
        assert saved_result["level1"]["level2"]["level3"]["data"] == ["item1", "item2", "item3"]
    
    def test_sync_unicode_execution_history(self):
        """测试同步 Unicode 执行历史"""
        state = AgentState(
            target="http://example.com",
            task_id="test-edge-exec-004",
            chat_instance_id="session-edge-exec-004"
        )
        self.test_session_ids.append("session-edge-exec-004")
        
        state.add_execution_step("中文任务", {"描述": "测试结果"}, "success")
        state.add_execution_step("日本語タスク", {"説明": "テスト結果"}, "success")
        
        result = state.sync_execution_history()
        
        assert result is True
        
        checkpoint = self.manager._sessions.get("session-edge-exec-004")
        assert checkpoint.channel_values["execution_history"][0]["task"] == "中文任务"
    
    def test_sync_special_characters_in_results(self):
        """测试同步包含特殊字符的结果"""
        state = AgentState(
            target="http://example.com",
            task_id="test-edge-exec-005",
            chat_instance_id="session-edge-exec-005"
        )
        self.test_session_ids.append("session-edge-exec-005")
        
        special_result = {
            "error": "特殊字符: <>&\"'\\n\\t\\r",
            "payload": "<script>alert('xss')</script>"
        }
        
        state.add_execution_step("xss_test", special_result, "success")
        state.sync_execution_history()
        
        checkpoint = self.manager._sessions.get("session-edge-exec-005")
        saved_result = checkpoint.channel_values["execution_history"][0]["result"]
        assert saved_result["error"] == "特殊字符: <>&\"'\\n\\t\\r"


class TestGetExecutionSummary:
    """测试 get_execution_summary 方法"""
    
    def test_get_execution_summary_basic(self):
        """测试基本执行摘要"""
        state = AgentState(
            target="http://example.com",
            task_id="test-summary-001"
        )
        
        state.add_scan_result("tool1", {}, 1.0, True)
        state.add_scan_result("tool2", {}, 2.0, True)
        state.add_scan_result("tool3", {}, 0.5, False)
        
        summary = state.get_execution_summary()
        
        assert summary["task_id"] == "test-summary-001"
        assert summary["target"] == "http://example.com"
        assert summary["total_tools_executed"] == 3
        assert summary["successful_executions"] == 2
    
    def test_get_execution_summary_with_vulnerabilities(self):
        """测试带漏洞的执行摘要"""
        state = AgentState(
            target="http://example.com",
            task_id="test-summary-002"
        )
        
        state.add_scan_result(
            "sqli_scan",
            {"vulnerabilities": [{"type": "SQLi"}]},
            1.0,
            True
        )
        state.add_vulnerability({"type": "XSS"})
        
        summary = state.get_execution_summary()
        
        assert summary["total_vulnerabilities"] == 2
    
    def test_get_execution_summary_with_errors(self):
        """测试带错误的执行摘要"""
        state = AgentState(
            target="http://example.com",
            task_id="test-summary-003"
        )
        
        state.add_error("error1")
        state.add_error("error2")
        
        summary = state.get_execution_summary()
        
        assert summary["total_errors"] == 2


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
