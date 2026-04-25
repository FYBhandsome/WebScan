"""
状态传递测试模块

测试节点间状态传递、子图间状态传递和状态完整性
"""
import pytest
import asyncio
import json
import tempfile
import os
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime

from TOSKill.AI.state import (
    AgentState,
    DataIntegrityError,
    StatePersistenceError
)
from TOSKill.AI.graph import AgentGraph, AgentOrchestrator


class TestAgentStateCreation:
    """测试AgentState创建"""
    
    def test_state_creation_with_required_fields(self):
        """测试使用必需字段创建状态"""
        state = AgentState(
            target="http://example.com",
            task_id="test-001"
        )
        
        assert state.target == "http://example.com"
        assert state.task_id == "test-001"
        assert state.workflow_status == "idle"
        assert state.is_complete is False
    
    def test_state_creation_with_all_fields(self):
        """测试使用所有字段创建状态"""
        state = AgentState(
            target="http://example.com",
            task_id="test-002",
            user_id="user-001",
            websocket_session_id="session-001",
            planned_tasks=["baseinfo", "portscan"],
            completed_tasks=["baseinfo"],
            vulnerabilities=[{"type": "xss"}]
        )
        
        assert state.target == "http://example.com"
        assert state.task_id == "test-002"
        assert state.user_id == "user-001"
        assert state.websocket_session_id == "session-001"
        assert len(state.planned_tasks) == 2
        assert len(state.completed_tasks) == 1
        assert len(state.vulnerabilities) == 1
    
    def test_state_default_values(self):
        """测试状态默认值"""
        state = AgentState(
            target="http://example.com",
            task_id="test-003"
        )
        
        assert state.planned_tasks == []
        assert state.completed_tasks == []
        assert state.tool_results == {}
        assert state.vulnerabilities == []
        assert state.errors == []
        assert state.chat_history == []
        assert state.execution_history == []


class TestAgentStateSerialization:
    """测试AgentState序列化"""
    
    @pytest.fixture
    def sample_state(self):
        """创建示例状态"""
        state = AgentState(
            target="http://example.com",
            task_id="test-serial-001",
            user_id="user-001",
            planned_tasks=["baseinfo"],
            completed_tasks=["baseinfo"],
            vulnerabilities=[{"type": "xss", "severity": "high"}]
        )
        return state
    
    def test_to_dict(self, sample_state):
        """测试转换为字典"""
        result = sample_state.to_dict()
        
        assert isinstance(result, dict)
        assert result["target"] == "http://example.com"
        assert result["task_id"] == "test-serial-001"
        assert result["user_id"] == "user-001"
        assert result["planned_tasks"] == ["baseinfo"]
        assert result["completed_tasks"] == ["baseinfo"]
        assert len(result["vulnerabilities"]) == 1
    
    def test_from_dict(self, sample_state):
        """测试从字典创建"""
        data = sample_state.to_dict()
        
        restored = AgentState.from_dict(data)
        
        assert restored.target == sample_state.target
        assert restored.task_id == sample_state.task_id
        assert restored.user_id == sample_state.user_id
        assert restored.planned_tasks == sample_state.planned_tasks
        assert restored.completed_tasks == sample_state.completed_tasks
    
    def test_serialization_roundtrip(self, sample_state):
        """测试序列化往返"""
        data = sample_state.to_dict()
        restored = AgentState.from_dict(data)
        data2 = restored.to_dict()
        
        assert data["target"] == data2["target"]
        assert data["task_id"] == data2["task_id"]
        assert data["vulnerabilities"] == data2["vulnerabilities"]


class TestAgentStateIntegrity:
    """测试AgentState完整性"""
    
    @pytest.fixture
    def valid_state(self):
        """创建有效状态"""
        state = AgentState(
            target="http://example.com",
            task_id="test-integrity-001"
        )
        state.execution_history = [{"task": "test", "timestamp": "2024-01-01"}]
        state.tool_results = {"baseinfo": {"server": "nginx"}}
        state.vulnerabilities = [{"type": "xss"}]
        state.chat_history = [{"role": "user", "content": "hello"}]
        return state
    
    def test_validate_data_integrity_valid(self, valid_state):
        """测试验证有效数据完整性"""
        result = valid_state.validate_data_integrity()
        
        assert result["is_valid"] is True
        assert len(result["errors"]) == 0
    
    def test_validate_data_integrity_missing_field(self):
        """测试验证缺少字段"""
        state = AgentState(
            target="http://example.com",
            task_id="test-integrity-002"
        )
        state.execution_history = None
        
        result = state.validate_data_integrity()
        
        assert result["is_valid"] is False
        assert any("execution_history" in e for e in result["errors"])
    
    def test_validate_data_integrity_wrong_type(self):
        """测试验证错误类型"""
        state = AgentState(
            target="http://example.com",
            task_id="test-integrity-003"
        )
        state.vulnerabilities = "not a list"
        
        result = state.validate_data_integrity()
        
        assert result["is_valid"] is False
    
    def test_ensure_data_integrity(self, valid_state):
        """测试确保数据完整性"""
        valid_state.ensure_data_integrity()
        
        assert isinstance(valid_state.execution_history, list)
        assert isinstance(valid_state.tool_results, dict)
        assert isinstance(valid_state.vulnerabilities, list)
    
    def test_ensure_data_integrity_auto_fix(self):
        """测试自动修复数据完整性"""
        state = AgentState(
            target="http://example.com",
            task_id="test-integrity-004"
        )
        state.execution_history = "invalid"
        state.tool_results = None
        state.vulnerabilities = []
        
        state.ensure_data_integrity()
        
        assert isinstance(state.execution_history, list)
        assert isinstance(state.tool_results, dict)
        assert isinstance(state.vulnerabilities, list)


class TestAgentStatePersistence:
    """测试AgentState持久化"""
    
    @pytest.fixture
    def sample_state(self):
        """创建示例状态"""
        state = AgentState(
            target="http://example.com",
            task_id="test-persist-001",
            planned_tasks=["baseinfo"],
            completed_tasks=["baseinfo"]
        )
        return state
    
    def test_save_to_file(self, sample_state):
        """测试保存到文件"""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "state.json")
            
            result = sample_state.save_to_file(filepath)
            
            assert result == filepath
            assert os.path.exists(filepath)
            
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            assert data["task_id"] == "test-persist-001"
            assert "_metadata" in data
    
    def test_load_from_file(self, sample_state):
        """测试从文件加载"""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "state.json")
            sample_state.save_to_file(filepath)
            
            loaded = AgentState.load_from_file(filepath)
            
            assert loaded.target == sample_state.target
            assert loaded.task_id == sample_state.task_id
            assert loaded.planned_tasks == sample_state.planned_tasks
    
    def test_persistence_roundtrip(self, sample_state):
        """测试持久化往返"""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "state.json")
            
            sample_state.save_to_file(filepath)
            loaded = AgentState.load_from_file(filepath)
            
            assert loaded.to_dict()["target"] == sample_state.to_dict()["target"]


class TestNodeStateTransfer:
    """测试节点间状态传递"""
    
    @pytest.fixture
    def state(self):
        """创建测试状态"""
        state = AgentState(
            target="http://example.com",
            task_id="test-node-transfer-001"
        )
        
        async def mock_callback(msg):
            pass
        
        state.set_websocket_callback(mock_callback)
        return state
    
    def test_state_update_context(self, state):
        """测试更新上下文"""
        state.update_context("server", "nginx")
        state.update_context("ports", [80, 443])
        
        assert state.target_context["server"] == "nginx"
        assert state.target_context["ports"] == [80, 443]
    
    def test_state_add_vulnerability(self, state):
        """测试添加漏洞"""
        vuln1 = {"type": "xss", "severity": "high"}
        vuln2 = {"type": "sqli", "severity": "critical"}
        
        state.add_vulnerability(vuln1)
        state.add_vulnerability(vuln2)
        
        assert len(state.vulnerabilities) == 2
        assert state.vulnerabilities[0] == vuln1
        assert state.vulnerabilities[1] == vuln2
    
    def test_state_add_error(self, state):
        """测试添加错误"""
        state.add_error("Error 1")
        state.add_error("Error 2")
        
        assert len(state.errors) == 2
        assert "Error 1" in state.errors
    
    def test_state_add_execution_step(self, state):
        """测试添加执行步骤"""
        state.add_execution_step("baseinfo", {"server": "nginx"}, "success")
        
        assert len(state.execution_history) == 1
        assert state.execution_history[0]["task"] == "baseinfo"
        assert state.execution_history[0]["status"] == "success"
    
    def test_state_merge_tool_results(self, state):
        """测试合并工具结果"""
        state.tool_results = {"baseinfo": {"server": "nginx"}}
        
        new_results = {"portscan": {"ports": [80, 443]}}
        state.merge_tool_results(new_results)
        
        assert "baseinfo" in state.tool_results
        assert "portscan" in state.tool_results
    
    def test_state_merge_tool_results_no_overwrite(self, state):
        """测试合并不覆盖已存在结果"""
        state.tool_results = {"baseinfo": {"server": "nginx"}}
        
        new_results = {"baseinfo": {"server": "apache"}}
        state.merge_tool_results(new_results, overwrite=False)
        
        assert state.tool_results["baseinfo"]["server"] == "nginx"


class TestSubgraphStateTransfer:
    """测试子图间状态传递"""
    
    @pytest.fixture
    def orchestrator(self):
        """创建编排器"""
        return AgentOrchestrator()
    
    @pytest.fixture
    def state(self):
        """创建测试状态"""
        state = AgentState(
            target="http://example.com",
            task_id="test-subgraph-transfer-001"
        )
        
        async def mock_callback(msg):
            pass
        
        state.set_websocket_callback(mock_callback)
        return state
    
    def test_get_all_scan_data(self, state):
        """测试获取所有扫描数据"""
        state.tool_results = {"baseinfo": {"server": "nginx"}}
        state.vulnerabilities = [{"type": "xss"}]
        state.completed_tasks = ["baseinfo"]
        
        data = state.get_all_scan_data()
        
        assert data["task_id"] == state.task_id
        assert data["target"] == state.target
        assert data["tool_results"] == state.tool_results
        assert data["vulnerabilities"] == state.vulnerabilities
    
    def test_import_scan_data_merge(self, state):
        """测试导入扫描数据（合并模式）"""
        scan_data = {
            "tool_results": {"portscan": {"ports": [80]}},
            "vulnerabilities": [{"type": "sqli"}],
            "completed_tasks": ["portscan"]
        }
        
        state.import_scan_data(scan_data, merge=True)
        
        assert "portscan" in state.tool_results
        assert len(state.vulnerabilities) == 1
        assert "portscan" in state.completed_tasks
    
    def test_import_scan_data_replace(self, state):
        """测试导入扫描数据（替换模式）"""
        state.tool_results = {"baseinfo": {"server": "nginx"}}
        
        scan_data = {
            "tool_results": {"portscan": {"ports": [80]}},
            "vulnerabilities": [],
            "completed_tasks": ["portscan"]
        }
        
        state.import_scan_data(scan_data, merge=False)
        
        assert "baseinfo" not in state.tool_results
        assert "portscan" in state.tool_results
    
    def test_track_data_flow(self, state):
        """测试追踪数据流转"""
        state.tool_results = {"baseinfo": {"server": "nginx"}}
        
        flow = state.track_data_flow("info_graph", "vuln_graph", ["tool_results"])
        
        assert flow["from"] == "info_graph"
        assert flow["to"] == "vuln_graph"
        assert "tool_results" in flow["data_snapshot"]
        assert "timestamp" in flow
    
    @pytest.mark.asyncio
    async def test_state_preserved_across_subgraphs(self, orchestrator, state):
        """测试状态在子图间保持"""
        state.completed_tasks = ["baseinfo"]
        state.tool_results = {"baseinfo": {"server": "nginx"}}
        
        original_tasks = state.completed_tasks.copy()
        original_results = state.tool_results.copy()
        
        with patch.object(orchestrator.info_graph, 'run', new_callable=AsyncMock) as mock_info:
            with patch.object(orchestrator.vuln_graph, 'run', new_callable=AsyncMock) as mock_vuln:
                with patch.object(orchestrator.report_graph, 'run', new_callable=AsyncMock) as mock_report:
                    mock_info.return_value = state
                    mock_vuln.return_value = state
                    mock_report.return_value = state
                    
                    await orchestrator.run_full_scan(state)
                    
                    assert state.completed_tasks[0] == original_tasks[0]
                    assert state.tool_results["baseinfo"] == original_results["baseinfo"]


class TestStateWorkflowManagement:
    """测试状态工作流管理"""
    
    @pytest.fixture
    def state(self):
        """创建测试状态"""
        return AgentState(
            target="http://example.com",
            task_id="test-workflow-001"
        )
    
    def test_set_workflow_running(self, state):
        """测试设置工作流运行状态"""
        state.set_workflow_running()
        
        assert state.workflow_status == "running"
        assert state.workflow_paused is False
    
    def test_set_workflow_completed(self, state):
        """测试设置工作流完成状态"""
        state.set_workflow_completed()
        
        assert state.workflow_status == "completed"
        assert state.is_complete is True
    
    def test_set_workflow_failed(self, state):
        """测试设置工作流失败状态"""
        state.set_workflow_failed("测试错误")
        
        assert state.workflow_status == "failed"
        assert "测试错误" in state.errors
    
    def test_pause_workflow(self, state):
        """测试暂停工作流"""
        state.pause_workflow("等待用户确认")
        
        assert state.workflow_paused is True
        assert state.workflow_status == "paused"
        assert state.persistence_metadata["pause_reason"] == "等待用户确认"
    
    def test_resume_workflow(self, state):
        """测试恢复工作流"""
        state.pause_workflow("测试暂停")
        state.resume_workflow()
        
        assert state.workflow_paused is False
        assert state.workflow_status == "running"


class TestStateWebSocketIntegration:
    """测试状态WebSocket集成"""
    
    @pytest.fixture
    def state_with_callback(self):
        """创建带回调的状态"""
        state = AgentState(
            target="http://example.com",
            task_id="test-ws-001"
        )
        
        state.messages_sent = []
        
        async def mock_callback(message):
            state.messages_sent.append(message)
        
        state.set_websocket_callback(mock_callback)
        return state
    
    @pytest.mark.asyncio
    async def test_send_message_to_frontend(self, state_with_callback):
        """测试发送消息到前端"""
        await state_with_callback.send_message_to_frontend("test_type", {"data": "test"})
        
        assert len(state_with_callback.messages_sent) == 1
        assert state_with_callback.messages_sent[0]["type"] == "test_type"
    
    @pytest.mark.asyncio
    async def test_broadcast_progress(self, state_with_callback):
        """测试广播进度"""
        await state_with_callback.broadcast_progress("planning", 50, "测试进度")
        
        assert len(state_with_callback.messages_sent) == 1
        assert state_with_callback.messages_sent[0]["type"] == "progress"
    
    @pytest.mark.asyncio
    async def test_send_ai_message(self, state_with_callback):
        """测试发送AI消息"""
        await state_with_callback.send_ai_message("测试消息")
        
        assert len(state_with_callback.messages_sent) == 1
        assert len(state_with_callback.chat_history) > 0
    
    @pytest.mark.asyncio
    async def test_send_error(self, state_with_callback):
        """测试发送错误"""
        await state_with_callback.send_error("测试错误")
        
        assert len(state_with_callback.messages_sent) == 1
        assert "测试错误" in state_with_callback.errors
    
    @pytest.mark.asyncio
    async def test_request_user_confirmation(self, state_with_callback):
        """测试请求用户确认"""
        task = asyncio.create_task(
            state_with_callback.request_user_confirmation("确认吗？")
        )
        
        await asyncio.sleep(0.1)
        
        assert state_with_callback._pending_confirmation is True
        assert state_with_callback.workflow_paused is True
        
        state_with_callback.set_user_confirmation_result("confirm")
        
        result = await asyncio.wait_for(task, timeout=1.0)
        
        assert result == "confirm"


class TestStateMemoryIntegration:
    """测试状态记忆集成"""
    
    @pytest.fixture
    def state(self):
        """创建测试状态"""
        return AgentState(
            target="http://example.com",
            task_id="test-memory-001",
            chat_instance_id="chat-001"
        )
    
    def test_save_to_session_memory(self, state):
        """测试保存到会话记忆"""
        with patch('TOSKill.AI.state.get_memory_manager') as mock_get_manager:
            mock_manager = MagicMock()
            mock_manager.save_session.return_value = True
            mock_get_manager.return_value = mock_manager
            
            result = state.save_to_session_memory()
            
            assert result is True
            mock_manager.save_session.assert_called_once()
    
    def test_load_from_session_memory(self, state):
        """测试从会话记忆加载"""
        with patch('TOSKill.AI.state.get_memory_manager') as mock_get_manager:
            mock_manager = MagicMock()
            mock_manager._sessions = {
                "chat-001": MagicMock(
                    channel_values={
                        "target": "http://example.com",
                        "task_id": "test-memory-001"
                    }
                )
            }
            mock_get_manager.return_value = mock_manager
            
            loaded = AgentState.load_from_session_memory("chat-001")
            
            assert loaded is not None
            assert loaded.target == "http://example.com"
    
    def test_sync_chat_history(self, state):
        """测试同步聊天历史"""
        state.chat_history = [
            {"role": "user", "content": "hello", "timestamp": "2024-01-01T00:00:00"}
        ]
        
        with patch('TOSKill.AI.state.get_memory_manager') as mock_get_manager:
            mock_manager = MagicMock()
            mock_manager._sessions = {}
            mock_manager.create_session = MagicMock()
            mock_manager._sessions["chat-001"] = MagicMock(
                message_history=[],
                channel_values={}
            )
            mock_manager.add_message = MagicMock()
            mock_get_manager.return_value = mock_manager
            
            result = state.sync_chat_history()
            
            assert result is True


class TestStateProgressTracking:
    """测试状态进度追踪"""
    
    @pytest.fixture
    def state(self):
        """创建测试状态"""
        return AgentState(
            target="http://example.com",
            task_id="test-progress-001"
        )
    
    def test_update_stage_status(self, state):
        """测试更新阶段状态"""
        state.update_stage_status("planning", "running", "sub_task", 50, "测试日志")
        
        assert state.stage_status["planning"]["status"] == "running"
        assert state.stage_status["planning"]["progress"] == 50
        assert len(state.stage_status["planning"]["logs"]) == 1
    
    def test_get_progress(self, state):
        """测试获取总进度"""
        state.update_stage_status("planning", "running", None, 50)
        state.update_stage_status("tool_execution", "running", None, 30)
        
        progress = state.get_progress()
        
        assert 0 <= progress <= 100
    
    def test_get_execution_summary(self, state):
        """测试获取执行摘要"""
        state.completed_tasks = ["baseinfo", "portscan"]
        state.vulnerabilities = [{"type": "xss"}]
        state.errors = ["error1"]
        state.execution_history = [{"task": "test"}]
        
        summary = state.get_execution_summary()
        
        assert summary["task_id"] == state.task_id
        assert summary["total_tools_executed"] == 2
        assert summary["total_vulnerabilities"] == 1
        assert summary["total_errors"] == 1


class TestStateChecksum:
    """测试状态校验和"""
    
    def test_calculate_checksum(self):
        """测试计算校验和"""
        state1 = AgentState(target="http://example.com", task_id="test-001")
        state2 = AgentState(target="http://example.com", task_id="test-001")
        state3 = AgentState(target="http://different.com", task_id="test-001")
        
        checksum1 = state1._calculate_checksum()
        checksum2 = state2._calculate_checksum()
        checksum3 = state3._calculate_checksum()
        
        assert checksum1 == checksum2
        assert checksum1 != checksum3
    
    def test_checksum_in_saved_file(self):
        """测试保存文件包含校验和"""
        state = AgentState(target="http://example.com", task_id="test-checksum-001")
        
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "state.json")
            state.save_to_file(filepath)
            
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            assert "checksum" in data["_metadata"]
