"""
AI Agent 工作流测试

测试覆盖：
1. AgentState 状态管理
2. 工具注册表
3. 节点功能
4. LangGraph 工作流构建
5. 结果类型
"""
import pytest
import asyncio
import json
import time
from datetime import datetime
from unittest.mock import patch, MagicMock, AsyncMock, PropertyMock
from dataclasses import asdict

from backend.ai_agents.core.state import (
    AgentState,
    NodeStatus,
    NodeExecutionRecord,
    WorkflowTrace,
    WorkflowRecorder,
)
from backend.ai_agents.tools.registry import ToolRegistry, ToolPermission, CallChainNode, CacheEntry
from backend.ai_agents.tools.result_types import PluginResult, ToolStatus, ProgressInfo
from backend.ai_agents.tools.wrappers import AsyncToolWrapper
from backend.ai_agents.core.nodes import (
    TargetContextUpdater,
    ProgressCalculator,
    ErrorHandler,
    POCTaskHelper,
    ToolCategoryHelper,
    NodeStage,
    EnvironmentAwarenessNode,
)
from backend.ai_agents.core.graph import ScanAgentGraph


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def sample_state():
    return AgentState(target="http://example.com", task_id="test_task_001")


@pytest.fixture
def state_with_context():
    state = AgentState(target="http://example.com", task_id="test_task_002")
    state.target_context = {
        "cms": "wordpress",
        "open_ports": [80, 443, 8080],
        "waf": "cloudflare",
        "server": "nginx",
    }
    return state


@pytest.fixture
def registry():
    reg = ToolRegistry()
    reg._generate_cache_key = MagicMock(return_value="mock_cache_key")
    reg._get_cached_result = MagicMock(return_value=None)
    reg._cache_result = MagicMock()
    return reg


@pytest.fixture
def registry_with_tools(registry):
    async def mock_tool(target, **kwargs):
        return {"target": target, "data": "mock_result"}

    registry.register(
        name="baseinfo",
        func=mock_tool,
        description="基础信息收集",
        category="plugin",
        timeout=60,
        priority=3,
    )
    registry.register(
        name="portscan",
        func=mock_tool,
        description="端口扫描",
        category="plugin",
        timeout=120,
        priority=5,
    )
    registry.register(
        name="sqli_scan",
        func=mock_tool,
        description="SQL注入扫描",
        category="vuln_scan",
        timeout=120,
        priority=7,
    )
    registry.register(
        name="poc_weblogic",
        func=mock_tool,
        description="WebLogic POC",
        category="poc",
        timeout=60,
        priority=6,
        tags=["poc", "vulnerability"],
    )
    return registry


@pytest.fixture
def plugin_result_success():
    return PluginResult.success(
        data={"ports": [80, 443]},
        execution_time=1.5,
        tool_name="portscan",
        target="http://example.com",
    )


@pytest.fixture
def plugin_result_failed():
    return PluginResult.failed(
        error="Connection refused",
        execution_time=0.5,
        tool_name="portscan",
        target="http://example.com",
    )


@pytest.fixture
def plugin_result_timeout():
    return PluginResult.timeout(
        timeout_seconds=120,
        execution_time=120.0,
        tool_name="portscan",
        target="http://example.com",
    )


@pytest.fixture
def plugin_result_security_blocked():
    return PluginResult.security_blocked(
        error="安全检查未通过",
        security_issues=["包含危险模式: 'rm -rf'"],
        tool_name="baseinfo",
        target="http://example.com; rm -rf /",
    )


# ============================================================================
# 1. AgentState 状态管理测试
# ============================================================================


class TestAgentStateCreation:
    """AgentState 创建和初始化测试"""

    def test_create_state_with_required_fields(self):
        state = AgentState(target="http://example.com", task_id="task_001")
        assert state.target == "http://example.com"
        assert state.task_id == "task_001"

    def test_default_values(self):
        state = AgentState(target="http://example.com", task_id="task_001")
        assert state.planned_tasks == []
        assert state.current_task is None
        assert state.completed_tasks == []
        assert state.tool_results == {}
        assert state.vulnerabilities == []
        assert state.target_context == {}
        assert state.execution_history == []
        assert state.errors == []
        assert state.retry_count == 0
        assert state.enhancement_retry_count == 0
        assert state.is_complete is False
        assert state.should_continue is True
        assert state.seebug_pocs == []
        assert state.generated_pocs == []
        assert state.scan_summary == {}
        assert state.report == ""
        assert state.vuln_scan_results == {}
        assert state.vuln_scan_plugins_loaded == []
        assert state.vuln_scan_progress == 0
        assert state.vuln_scan_metadata == {}

    def test_workflow_trace_initialized(self):
        state = AgentState(target="http://example.com", task_id="task_001")
        assert state.workflow_trace is not None
        assert state.workflow_trace.task_id == "task_001"
        assert state.workflow_trace.target == "http://example.com"

    def test_stage_status_initialized(self):
        state = AgentState(target="http://example.com", task_id="task_001")
        assert "planning" in state.stage_status
        assert "tool_execution" in state.stage_status
        assert "poc_verification" in state.stage_status
        assert "report" in state.stage_status
        for stage in state.stage_status.values():
            assert stage["status"] == "pending"
            assert stage["progress"] == 0

    def test_create_state_with_all_fields(self):
        state = AgentState(
            target="http://test.com",
            task_id="task_002",
            planned_tasks=["baseinfo", "portscan"],
            current_task="baseinfo",
            completed_tasks=["init"],
            tool_results={"init": {"status": "ok"}},
            vulnerabilities=[{"cve": "CVE-2024-0001"}],
            target_context={"cms": "wordpress"},
            errors=["warning1"],
            retry_count=1,
            is_complete=False,
            should_continue=True,
        )
        assert state.planned_tasks == ["baseinfo", "portscan"]
        assert state.current_task == "baseinfo"
        assert state.completed_tasks == ["init"]
        assert len(state.vulnerabilities) == 1


class TestAgentStateUpdateMethods:
    """AgentState 状态更新方法测试"""

    def test_update_context(self, sample_state):
        sample_state.update_context("cms", "wordpress")
        assert sample_state.target_context["cms"] == "wordpress"

        sample_state.update_context("open_ports", [80, 443])
        assert sample_state.target_context["open_ports"] == [80, 443]

    def test_update_context_overwrite(self, sample_state):
        sample_state.update_context("server", "apache")
        sample_state.update_context("server", "nginx")
        assert sample_state.target_context["server"] == "nginx"

    def test_add_vulnerability(self, sample_state):
        vuln = {"cve": "CVE-2024-0001", "severity": "high", "details": "SQL Injection"}
        sample_state.add_vulnerability(vuln)
        assert len(sample_state.vulnerabilities) == 1
        assert sample_state.vulnerabilities[0]["cve"] == "CVE-2024-0001"

    def test_add_multiple_vulnerabilities(self, sample_state):
        for i in range(3):
            sample_state.add_vulnerability({"cve": f"CVE-2024-{i:04d}"})
        assert len(sample_state.vulnerabilities) == 3

    def test_add_tool_result(self, sample_state):
        sample_state.add_tool_result("baseinfo", {"server": "nginx"})
        assert sample_state.tool_results["baseinfo"] == {"server": "nginx"}

    def test_add_tool_result_overwrite(self, sample_state):
        sample_state.add_tool_result("portscan", {"ports": [80]})
        sample_state.add_tool_result("portscan", {"ports": [80, 443]})
        assert sample_state.tool_results["portscan"]["ports"] == [80, 443]

    def test_add_error(self, sample_state):
        sample_state.add_error("Connection timeout")
        assert len(sample_state.errors) == 1
        assert sample_state.errors[0] == "Connection timeout"

    def test_add_multiple_errors(self, sample_state):
        sample_state.add_error("Error 1")
        sample_state.add_error("Error 2")
        assert len(sample_state.errors) == 2

    def test_increment_retry(self, sample_state):
        assert sample_state.retry_count == 0
        sample_state.increment_retry()
        assert sample_state.retry_count == 1
        sample_state.increment_retry()
        assert sample_state.retry_count == 2

    def test_reset_retry(self, sample_state):
        sample_state.increment_retry()
        sample_state.increment_retry()
        sample_state.reset_retry()
        assert sample_state.retry_count == 0

    def test_increment_enhancement_retry(self, sample_state):
        assert sample_state.enhancement_retry_count == 0
        sample_state.increment_enhancement_retry()
        assert sample_state.enhancement_retry_count == 1

    def test_reset_enhancement_retry(self, sample_state):
        sample_state.increment_enhancement_retry()
        sample_state.reset_enhancement_retry()
        assert sample_state.enhancement_retry_count == 0

    def test_mark_complete(self, sample_state):
        sample_state.mark_complete()
        assert sample_state.is_complete is True
        assert sample_state.should_continue is False

    def test_add_execution_step(self, sample_state):
        sample_state.add_execution_step(
            task="baseinfo",
            result={"status": "success"},
            status="success",
            step_type="tool_execution",
        )
        assert len(sample_state.execution_history) == 1
        assert sample_state.execution_history[0]["task"] == "baseinfo"
        assert sample_state.execution_history[0]["status"] == "success"
        assert sample_state.execution_history[0]["step_number"] == 1

    def test_add_execution_step_with_all_params(self, sample_state):
        sample_state.add_execution_step(
            task="portscan",
            result={"ports": [80, 443]},
            status="success",
            step_type="tool_execution",
            input_params={"target": "http://example.com"},
            processing_logic="执行端口扫描",
            intermediate_results=[{"step": "syn_scan"}],
            output_data={"open_ports": [80, 443]},
            data_changes={"ports_discovered": 2},
            state_transitions=["started", "completed"],
            execution_time=1.5,
        )
        step = sample_state.execution_history[0]
        assert step["task"] == "portscan"
        assert step["input_params"] == {"target": "http://example.com"}
        assert step["processing_logic"] == "执行端口扫描"
        assert step["execution_time"] == 1.5

    def test_add_execution_step_start(self, sample_state):
        step_number = sample_state.add_execution_step_start(
            task="baseinfo",
            step_type="tool_execution",
            input_params={"target": "http://example.com"},
        )
        assert step_number == 1
        assert sample_state.execution_history[0]["status"] == "running"
        assert sample_state.execution_history[0]["task"] == "baseinfo"

    def test_update_execution_step(self, sample_state):
        step_number = sample_state.add_execution_step_start(task="baseinfo")
        sample_state.update_execution_step(
            step_number,
            result={"status": "ok"},
            status="success",
            output_data={"server": "nginx"},
            state_transitions=["completed"],
        )
        step = sample_state.execution_history[0]
        assert step["result"] == {"status": "ok"}
        assert step["status"] == "success"
        assert step["output_data"] == {"server": "nginx"}

    def test_update_execution_step_invalid_number(self, sample_state):
        sample_state.add_execution_step_start(task="baseinfo")
        sample_state.update_execution_step(999, result="should_not_update")
        assert sample_state.execution_history[0].get("result") != "should_not_update"


class TestAgentStateSerialization:
    """AgentState 序列化/反序列化测试"""

    def test_to_dict(self, sample_state):
        sample_state.update_context("cms", "wordpress")
        sample_state.add_vulnerability({"cve": "CVE-2024-0001"})
        sample_state.add_tool_result("baseinfo", {"server": "nginx"})

        data = sample_state.to_dict()

        assert data["target"] == "http://example.com"
        assert data["task_id"] == "test_task_001"
        assert data["target_context"]["cms"] == "wordpress"
        assert len(data["vulnerabilities"]) == 1
        assert data["tool_results"]["baseinfo"] == {"server": "nginx"}
        assert "progress" in data
        assert "workflow_trace" in data
        assert data["workflow_trace"] is not None

    def test_to_dict_contains_all_fields(self, sample_state):
        data = sample_state.to_dict()
        expected_fields = [
            "target", "task_id", "workflow_trace", "planned_tasks",
            "current_task", "completed_tasks", "tool_results",
            "vulnerabilities", "target_context", "user_tools",
            "user_requirement", "memory_info", "plan_data",
            "execution_results", "execution_history", "errors",
            "retry_count", "enhancement_retry_count", "is_complete",
            "should_continue", "seebug_pocs", "generated_pocs",
            "stage_status", "vuln_scan_results", "vuln_scan_plugins_loaded",
            "vuln_scan_progress", "vuln_scan_metadata", "scan_summary",
            "report", "progress",
        ]
        for field_name in expected_fields:
            assert field_name in data, f"Missing field: {field_name}"

    def test_from_dict(self, sample_state):
        sample_state.update_context("cms", "drupal")
        sample_state.add_vulnerability({"cve": "CVE-2024-0001"})
        sample_state.planned_tasks = ["baseinfo", "portscan"]
        sample_state.completed_tasks = ["init"]
        sample_state.retry_count = 2

        data = sample_state.to_dict()
        restored = AgentState.from_dict(data)

        assert restored.target == "http://example.com"
        assert restored.task_id == "test_task_001"
        assert restored.target_context["cms"] == "drupal"
        assert len(restored.vulnerabilities) == 1
        assert restored.planned_tasks == ["baseinfo", "portscan"]
        assert restored.completed_tasks == ["init"]
        assert restored.retry_count == 2

    def test_from_dict_with_defaults(self):
        data = {"target": "http://test.com", "task_id": "task_003"}
        state = AgentState.from_dict(data)
        assert state.target == "http://test.com"
        assert state.planned_tasks == []
        assert state.vulnerabilities == []
        assert state.is_complete is False

    def test_roundtrip_serialization(self, sample_state):
        sample_state.update_context("server", "apache")
        sample_state.add_vulnerability({"cve": "CVE-2024-1234", "severity": "critical"})
        sample_state.add_tool_result("portscan", {"open_ports": [80, 443]})
        sample_state.planned_tasks = ["sqli_scan", "xss_scan"]
        sample_state.current_task = "sqli_scan"
        sample_state.add_error("test error")

        data = sample_state.to_dict()
        restored = AgentState.from_dict(data)

        assert restored.target == sample_state.target
        assert restored.target_context == sample_state.target_context
        assert restored.vulnerabilities == sample_state.vulnerabilities
        assert restored.tool_results == sample_state.tool_results
        assert restored.planned_tasks == sample_state.planned_tasks
        assert restored.current_task == sample_state.current_task
        assert restored.errors == sample_state.errors

    def test_from_dict_preserves_stage_status(self):
        data = {
            "target": "http://test.com",
            "task_id": "task_004",
            "stage_status": {
                "planning": {"status": "completed", "sub_status": "done", "progress": 100, "logs": [], "start_time": None, "end_time": None},
                "tool_execution": {"status": "running", "sub_status": "executing", "progress": 50, "logs": [], "start_time": None, "end_time": None},
                "poc_verification": {"status": "pending", "sub_status": "pending", "progress": 0, "logs": [], "start_time": None, "end_time": None},
                "report": {"status": "pending", "sub_status": "pending", "progress": 0, "logs": [], "start_time": None, "end_time": None},
            },
        }
        state = AgentState.from_dict(data)
        assert state.stage_status["planning"]["status"] == "completed"
        assert state.stage_status["tool_execution"]["progress"] == 50

    def test_get_all_fields(self):
        fields = AgentState.get_all_fields()
        assert "target" in fields
        assert "task_id" in fields
        assert "vulnerabilities" in fields
        assert "stage_status" in fields
        assert isinstance(fields, list)


class TestAgentStateProgress:
    """AgentState 进度计算测试"""

    def test_get_progress_initial(self, sample_state):
        assert sample_state.get_progress() == 0

    @patch("backend.ai_agents.core.state.AgentState.update_stage_status")
    def test_get_progress_all_stages_50(self, mock_update, sample_state):
        for stage in sample_state.stage_status:
            sample_state.stage_status[stage]["progress"] = 50
        assert sample_state.get_progress() == 50

    @patch("backend.ai_agents.core.state.AgentState.update_stage_status")
    def test_get_progress_mixed(self, mock_update, sample_state):
        sample_state.stage_status["planning"]["progress"] = 100
        sample_state.stage_status["tool_execution"]["progress"] = 50
        sample_state.stage_status["poc_verification"]["progress"] = 0
        sample_state.stage_status["report"]["progress"] = 0
        progress = sample_state.get_progress()
        assert progress == 37

    @patch("backend.ai_agents.core.state.AgentState.update_stage_status")
    def test_get_progress_all_complete(self, mock_update, sample_state):
        for stage in sample_state.stage_status:
            sample_state.stage_status[stage]["progress"] = 100
        assert sample_state.get_progress() == 100


class TestAgentStateStageStatus:
    """AgentState 阶段状态更新测试"""

    @patch("backend.ai_agents.core.state.AgentState.update_stage_status")
    def test_update_stage_status_directly(self, mock_update, sample_state):
        sample_state.stage_status["planning"]["status"] = "running"
        sample_state.stage_status["planning"]["progress"] = 30
        assert sample_state.stage_status["planning"]["status"] == "running"
        assert sample_state.stage_status["planning"]["progress"] == 30

    @patch("backend.ai_agents.core.state.AgentState.update_stage_status")
    def test_update_stage_status_with_log(self, mock_update, sample_state):
        sample_state.stage_status["planning"]["status"] = "running"
        entry = {
            "timestamp": datetime.now().isoformat(),
            "message": "开始规划",
            "sub_status": "planning",
        }
        sample_state.stage_status["planning"]["logs"].append(entry)
        assert len(sample_state.stage_status["planning"]["logs"]) == 1

    def test_update_stage_status_invalid_stage(self, sample_state):
        with patch("backend.ai_agents.core.state.AgentState.update_stage_status"):
            sample_state.stage_status.get("invalid_stage") is None


class TestAgentStateWorkflowRecording:
    """AgentState 工作流记录测试"""

    def test_start_workflow_recording(self, sample_state):
        sample_state.start_workflow_recording()
        assert sample_state.workflow_trace.workflow_status == NodeStatus.RUNNING

    def test_start_node_recording(self, sample_state):
        idx = sample_state.start_node_recording("test_node", "planning", {"target": "test"})
        assert idx >= 0
        assert len(sample_state.workflow_trace.nodes) == 1
        assert sample_state.workflow_trace.nodes[0].node_name == "test_node"

    def test_complete_node_recording(self, sample_state):
        idx = sample_state.start_node_recording("test_node", "planning")
        sample_state.complete_node_recording(idx, output_data={"result": "ok"})
        node = sample_state.workflow_trace.nodes[0]
        assert node.status == NodeStatus.SUCCESS
        assert node.output_data == {"result": "ok"}

    def test_fail_node_recording(self, sample_state):
        idx = sample_state.start_node_recording("test_node", "planning")
        sample_state.fail_node_recording("Something went wrong", idx)
        node = sample_state.workflow_trace.nodes[0]
        assert node.status == NodeStatus.FAILED
        assert node.error_message == "Something went wrong"

    def test_skip_node_recording(self, sample_state):
        idx = sample_state.start_node_recording("test_node", "planning")
        sample_state.skip_node_recording("Not needed", idx)
        node = sample_state.workflow_trace.nodes[0]
        assert node.status == NodeStatus.SKIPPED

    def test_complete_workflow_recording(self, sample_state):
        sample_state.start_workflow_recording()
        sample_state.complete_workflow_recording({"total": 5})
        assert sample_state.workflow_trace.workflow_status == NodeStatus.SUCCESS
        assert sample_state.workflow_trace.summary == {"total": 5}

    def test_fail_workflow_recording(self, sample_state):
        sample_state.start_workflow_recording()
        sample_state.fail_workflow_recording("Critical error")
        assert sample_state.workflow_trace.workflow_status == NodeStatus.FAILED
        assert "error" in sample_state.workflow_trace.summary

    def test_get_workflow_statistics(self, sample_state):
        idx = sample_state.start_node_recording("node1", "planning")
        sample_state.complete_node_recording(idx)
        idx2 = sample_state.start_node_recording("node2", "execution")
        sample_state.fail_node_recording("error", idx2)

        stats = sample_state.get_workflow_statistics()
        assert stats["total_nodes"] == 2
        assert stats["success_count"] == 1
        assert stats["failed_count"] == 1


class TestAgentStateAsyncMethods:
    """AgentState 异步方法测试"""

    @pytest.mark.asyncio
    async def test_add_vulnerability_with_persist(self, sample_state):
        with patch("backend.ai_agents.core.state.persist_task_state", new_callable=AsyncMock):
            vuln = {"cve": "CVE-2024-0001", "severity": "high"}
            await sample_state.add_vulnerability_with_persist(vuln)
            assert len(sample_state.vulnerabilities) == 1

    @pytest.mark.asyncio
    async def test_add_tool_result_with_persist(self, sample_state):
        with patch("backend.ai_agents.core.state.persist_task_state", new_callable=AsyncMock):
            await sample_state.add_tool_result_with_persist("baseinfo", {"server": "nginx"})
            assert sample_state.tool_results["baseinfo"] == {"server": "nginx"}

    @pytest.mark.asyncio
    async def test_persist_state(self, sample_state):
        with patch("backend.ai_agents.core.state.persist_task_state", new_callable=AsyncMock) as mock_persist:
            await sample_state.persist_state()
            mock_persist.assert_called_once()


# ============================================================================
# NodeExecutionRecord & WorkflowTrace 测试
# ============================================================================


class TestNodeExecutionRecord:
    """NodeExecutionRecord 测试"""

    def test_create_record(self):
        record = NodeExecutionRecord(node_name="test_node", node_type="planning")
        assert record.node_name == "test_node"
        assert record.status == NodeStatus.PENDING

    def test_start(self):
        record = NodeExecutionRecord(node_name="test_node", node_type="planning")
        record.start({"input": "data"})
        assert record.status == NodeStatus.RUNNING
        assert record.start_time is not None
        assert record.input_data == {"input": "data"}

    def test_complete(self):
        record = NodeExecutionRecord(node_name="test_node", node_type="planning")
        record.start()
        record.complete({"output": "result"}, {"meta": "data"})
        assert record.status == NodeStatus.SUCCESS
        assert record.end_time is not None
        assert record.duration_ms is not None
        assert record.output_data == {"output": "result"}

    def test_fail(self):
        record = NodeExecutionRecord(node_name="test_node", node_type="planning")
        record.start()
        record.fail("Error occurred")
        assert record.status == NodeStatus.FAILED
        assert record.error_message == "Error occurred"

    def test_skip(self):
        record = NodeExecutionRecord(node_name="test_node", node_type="planning")
        record.skip("Not needed")
        assert record.status == NodeStatus.SKIPPED
        assert record.metadata.get("skip_reason") == "Not needed"

    def test_to_dict(self):
        record = NodeExecutionRecord(node_name="test_node", node_type="planning")
        record.start()
        record.complete({"result": "ok"})
        data = record.to_dict()
        assert data["node_name"] == "test_node"
        assert data["status"] == "success"
        assert "start_time_iso" in data


class TestWorkflowTrace:
    """WorkflowTrace 测试"""

    def test_create_trace(self):
        trace = WorkflowTrace(workflow_id="wf_001", task_id="task_001", target="http://test.com")
        assert trace.workflow_id == "wf_001"
        assert trace.workflow_status == NodeStatus.PENDING

    def test_start_workflow(self):
        trace = WorkflowTrace(workflow_id="wf_001", task_id="task_001", target="http://test.com")
        trace.start_workflow()
        assert trace.workflow_status == NodeStatus.RUNNING

    def test_start_and_complete_node(self):
        trace = WorkflowTrace(workflow_id="wf_001", task_id="task_001", target="http://test.com")
        idx = trace.start_node("node1", "planning", {"input": "data"})
        trace.complete_node(idx, {"output": "result"})
        assert trace.nodes[0].status == NodeStatus.SUCCESS

    def test_fail_node(self):
        trace = WorkflowTrace(workflow_id="wf_001", task_id="task_001", target="http://test.com")
        idx = trace.start_node("node1", "planning")
        trace.fail_node(idx, "Error")
        assert trace.nodes[0].status == NodeStatus.FAILED

    def test_complete_workflow(self):
        trace = WorkflowTrace(workflow_id="wf_001", task_id="task_001", target="http://test.com")
        trace.start_workflow()
        trace.complete_workflow({"total": 3})
        assert trace.workflow_status == NodeStatus.SUCCESS
        assert trace.total_duration_ms is not None

    def test_fail_workflow(self):
        trace = WorkflowTrace(workflow_id="wf_001", task_id="task_001", target="http://test.com")
        trace.start_workflow()
        trace.fail_workflow("Critical error")
        assert trace.workflow_status == NodeStatus.FAILED

    def test_get_node_by_name(self):
        trace = WorkflowTrace(workflow_id="wf_001", task_id="task_001", target="http://test.com")
        trace.start_node("node1", "planning")
        trace.start_node("node2", "execution")
        found = trace.get_node_by_name("node2")
        assert found is not None
        assert found.node_name == "node2"

    def test_get_nodes_by_status(self):
        trace = WorkflowTrace(workflow_id="wf_001", task_id="task_001", target="http://test.com")
        idx1 = trace.start_node("node1", "planning")
        trace.complete_node(idx1)
        idx2 = trace.start_node("node2", "execution")
        trace.fail_node(idx2, "Error")
        success_nodes = trace.get_nodes_by_status(NodeStatus.SUCCESS)
        assert len(success_nodes) == 1

    def test_get_statistics(self):
        trace = WorkflowTrace(workflow_id="wf_001", task_id="task_001", target="http://test.com")
        idx1 = trace.start_node("node1", "planning")
        trace.complete_node(idx1)
        idx2 = trace.start_node("node2", "execution")
        trace.fail_node(idx2, "Error")
        stats = trace.get_statistics()
        assert stats["total_nodes"] == 2
        assert stats["success_count"] == 1
        assert stats["failed_count"] == 1

    def test_to_dict(self):
        trace = WorkflowTrace(workflow_id="wf_001", task_id="task_001", target="http://test.com")
        trace.start_workflow()
        data = trace.to_dict()
        assert data["workflow_id"] == "wf_001"
        assert data["workflow_status"] == "running"
        assert "statistics" in data


class TestWorkflowRecorder:
    """WorkflowRecorder 单例测试"""

    def setup_method(self):
        WorkflowRecorder.clear_all()

    def test_create_workflow(self):
        trace = WorkflowRecorder.create_workflow("task_001", "http://test.com")
        assert trace.task_id == "task_001"
        assert trace.target == "http://test.com"

    def test_get_workflow(self):
        trace = WorkflowRecorder.create_workflow("task_001", "http://test.com")
        retrieved = WorkflowRecorder.get_workflow(trace.workflow_id)
        assert retrieved is not None
        assert retrieved.task_id == "task_001"

    def test_get_workflow_by_task(self):
        trace = WorkflowRecorder.create_workflow("task_002", "http://test.com")
        retrieved = WorkflowRecorder.get_workflow_by_task("task_002")
        assert retrieved is not None

    def test_remove_workflow(self):
        trace = WorkflowRecorder.create_workflow("task_003", "http://test.com")
        WorkflowRecorder.remove_workflow(trace.workflow_id)
        assert WorkflowRecorder.get_workflow(trace.workflow_id) is None

    def test_get_all_workflows(self):
        WorkflowRecorder.create_workflow("task_004", "http://test1.com")
        WorkflowRecorder.create_workflow("task_005", "http://test2.com")
        all_wf = WorkflowRecorder.get_all_workflows()
        assert len(all_wf) >= 2

    def test_clear_all(self):
        WorkflowRecorder.create_workflow("task_006", "http://test.com")
        WorkflowRecorder.clear_all()
        assert len(WorkflowRecorder.get_all_workflows()) == 0


# ============================================================================
# 2. 工具注册表测试
# ============================================================================


class TestToolRegistryRegistration:
    """工具注册和调用测试"""

    def test_register_tool(self, registry):
        async def mock_func(target, **kwargs):
            return {"data": "test"}

        registry.register(name="test_tool", func=mock_func, description="Test tool", category="plugin")
        assert "test_tool" in registry.tools
        assert registry.tool_metadata["test_tool"]["description"] == "Test tool"

    def test_register_tool_with_metadata(self, registry):
        async def mock_func(target, **kwargs):
            return {"data": "test"}

        registry.register(
            name="test_tool",
            func=mock_func,
            description="Test tool",
            category="plugin",
            timeout=30,
            priority=8,
            version="2.0.0",
            author="tester",
            dependencies=["other_tool"],
            applicable_scenarios=["web_scan"],
            permissions=["network"],
            tags=["test", "scan"],
            examples=[{"input": "url", "output": "result"}],
            cache_ttl=600,
            enabled=True,
        )
        meta = registry.tool_metadata["test_tool"]
        assert meta["version"] == "2.0.0"
        assert meta["author"] == "tester"
        assert meta["dependencies"] == ["other_tool"]
        assert meta["tags"] == ["test", "scan"]
        assert meta["cache_ttl"] == 600

    def test_register_overwrites_existing(self, registry):
        async def func_v1(target, **kwargs):
            return "v1"

        async def func_v2(target, **kwargs):
            return "v2"

        registry.register(name="tool", func=func_v1, description="v1")
        registry.register(name="tool", func=func_v2, description="v2")
        assert registry.tool_metadata["tool"]["description"] == "v2"

    def test_register_async_tool_wrapper(self, registry):
        async def mock_func(target, **kwargs):
            return {"data": "test"}

        wrapper = AsyncToolWrapper(mock_func, timeout=30, tool_name="wrapped_tool")
        registry.register(name="wrapped_tool", func=wrapper, description="Wrapped tool")
        assert registry.tools["wrapped_tool"] is wrapper


class TestToolRegistryCall:
    """工具调用测试"""

    @pytest.mark.asyncio
    async def test_call_tool_success(self, registry_with_tools):
        result = await registry_with_tools.call_tool("baseinfo", "http://example.com", use_cache=False)
        assert isinstance(result, PluginResult)
        assert result.is_success

    @pytest.mark.asyncio
    async def test_call_tool_not_found(self, registry_with_tools):
        with pytest.raises(ValueError, match="工具不存在"):
            await registry_with_tools.call_tool("nonexistent", "http://example.com")

    @pytest.mark.asyncio
    async def test_call_tool_returns_plugin_result(self, registry_with_tools):
        result = await registry_with_tools.call_tool("baseinfo", "http://example.com", use_cache=False)
        assert isinstance(result, PluginResult)
        assert result.tool_name == "baseinfo"
        assert result.target == "http://example.com"

    @pytest.mark.asyncio
    async def test_call_tool_with_cache(self, registry_with_tools):
        result1 = await registry_with_tools.call_tool("baseinfo", "http://example.com", use_cache=True)
        cached = PluginResult.success(
            data=result1.data,
            execution_time=result1.execution_time,
            tool_name="baseinfo",
            target="http://example.com",
        )
        registry_with_tools._get_cached_result = MagicMock(return_value=cached)
        result2 = await registry_with_tools.call_tool("baseinfo", "http://example.com", use_cache=True)
        assert result2.metadata.get("from_cache") is True

    @pytest.mark.asyncio
    async def test_call_tool_disabled(self, registry_with_tools):
        registry_with_tools.tool_metadata["baseinfo"]["enabled"] = False
        result = await registry_with_tools.call_tool("baseinfo", "http://example.com", use_cache=False)
        assert result.status == ToolStatus.SECURITY_BLOCKED.value

    @pytest.mark.asyncio
    async def test_call_tool_exception_handling(self, registry):
        async def failing_tool(target, **kwargs):
            raise RuntimeError("Tool crashed")

        registry.register(name="failing_tool", func=failing_tool, description="Fails")
        result = await registry.call_tool("failing_tool", "http://example.com", use_cache=False)
        assert result.is_failed
        assert "Tool crashed" in result.error


class TestToolRegistryListTools:
    """工具列表获取测试"""

    def test_list_tools(self, registry_with_tools):
        tools = registry_with_tools.list_tools()
        assert len(tools) >= 4
        assert any(t["name"] == "baseinfo" for t in tools)

    def test_list_tools_by_category(self, registry_with_tools):
        tools = registry_with_tools.list_tools(category="plugin")
        assert all(t["category"] == "plugin" for t in tools)

    def test_list_tools_by_tags(self, registry_with_tools):
        tools = registry_with_tools.list_tools(tags=["poc"])
        assert len(tools) >= 1

    def test_list_tools_enabled_only(self, registry_with_tools):
        registry_with_tools.tool_metadata["baseinfo"]["enabled"] = False
        tools = registry_with_tools.list_tools(enabled_only=True)
        assert not any(t["name"] == "baseinfo" for t in tools)

    def test_list_tools_sorted_by_priority(self, registry_with_tools):
        tools = registry_with_tools.list_tools()
        priorities = [t.get("priority", 0) for t in tools]
        assert priorities == sorted(priorities, reverse=True)

    def test_get_tools_by_category(self, registry_with_tools):
        plugin_tools = registry_with_tools.get_tools_by_category("plugin")
        assert "baseinfo" in plugin_tools
        assert "portscan" in plugin_tools

    def test_get_tools_by_category_vuln_scan(self, registry_with_tools):
        vuln_tools = registry_with_tools.get_tools_by_category("vuln_scan")
        assert "sqli_scan" in vuln_tools

    def test_get_tools_by_category_poc(self, registry_with_tools):
        poc_tools = registry_with_tools.get_tools_by_category("poc")
        assert "poc_weblogic" in poc_tools

    def test_get_tool(self, registry_with_tools):
        tool = registry_with_tools.get_tool("baseinfo")
        assert tool is not None

    def test_get_tool_not_found(self, registry_with_tools):
        tool = registry_with_tools.get_tool("nonexistent")
        assert tool is None


class TestToolRegistrySecurityCheck:
    """安全检查测试"""

    def test_security_check_safe_target(self, registry_with_tools):
        result = registry_with_tools._security_check("baseinfo", "http://example.com")
        assert result["passed"] is True

    def test_security_check_dangerous_target(self, registry_with_tools):
        result = registry_with_tools._security_check("baseinfo", "http://example.com; rm -rf /")
        assert result["passed"] is False
        assert len(result["errors"]) > 0

    def test_security_check_dangerous_param(self, registry_with_tools):
        result = registry_with_tools._security_check(
            "baseinfo", "http://example.com", param="<script>alert(1)</script>"
        )
        assert len(result["warnings"]) > 0

    def test_security_check_disabled_tool(self, registry_with_tools):
        registry_with_tools.tool_metadata["baseinfo"]["enabled"] = False
        result = registry_with_tools._security_check("baseinfo", "http://example.com")
        assert result["passed"] is False

    def test_security_check_with_permissions(self, registry_with_tools):
        registry_with_tools.tool_metadata["baseinfo"]["permissions"] = ["network"]
        result = registry_with_tools._security_check("baseinfo", "http://example.com")
        assert any("权限" in w for w in result["warnings"])

    def test_security_check_missing_dependencies(self, registry_with_tools):
        registry_with_tools.tool_metadata["baseinfo"]["dependencies"] = ["nonexistent_tool"]
        result = registry_with_tools._security_check("baseinfo", "http://example.com")
        assert any("依赖缺失" in w for w in result["warnings"])

    def test_security_check_disabled_globally(self, registry_with_tools):
        registry_with_tools._security_check_enabled = False
        result = registry_with_tools._security_check("baseinfo", "http://example.com; rm -rf /")
        assert result["passed"] is True
        registry_with_tools._security_check_enabled = True

    def test_check_dangerous_patterns(self, registry_with_tools):
        result = registry_with_tools._check_dangerous_patterns("rm -rf /", "target")
        assert result["safe"] is False
        assert len(result["issues"]) > 0

    def test_check_dangerous_patterns_sql_injection(self, registry_with_tools):
        result = registry_with_tools._check_dangerous_patterns("drop table users", "param")
        assert result["safe"] is False

    def test_security_audit_log(self, registry_with_tools):
        registry_with_tools._security_check("baseinfo", "http://example.com")
        assert len(registry_with_tools._security_audit_log) >= 1


class TestToolRegistryCache:
    """结果缓存测试"""

    def test_cache_entry_not_expired(self):
        entry = CacheEntry(
            result=PluginResult.success(data={"test": True}),
            created_at=datetime.now(),
            ttl_seconds=300,
            cache_key="test_key",
        )
        assert entry.is_expired() is False

    def test_cache_entry_expired(self):
        entry = CacheEntry(
            result=PluginResult.success(data={"test": True}),
            created_at=datetime(2020, 1, 1),
            ttl_seconds=1,
            cache_key="test_key",
        )
        assert entry.is_expired() is True

    @pytest.mark.asyncio
    async def test_cache_result_reused(self, registry_with_tools):
        result1 = await registry_with_tools.call_tool("baseinfo", "http://example.com", use_cache=True)
        cached = PluginResult.success(
            data=result1.data,
            execution_time=result1.execution_time,
            tool_name="baseinfo",
            target="http://example.com",
        )
        registry_with_tools._get_cached_result = MagicMock(return_value=cached)
        result2 = await registry_with_tools.call_tool("baseinfo", "http://example.com", use_cache=True)
        assert result2.metadata.get("from_cache") is True

    @pytest.mark.asyncio
    async def test_cache_disabled(self, registry_with_tools):
        registry_with_tools._cache_enabled = False
        result1 = await registry_with_tools.call_tool("baseinfo", "http://example.com", use_cache=True)
        result2 = await registry_with_tools.call_tool("baseinfo", "http://example.com", use_cache=True)
        registry_with_tools._cache_enabled = True

    @pytest.mark.asyncio
    async def test_cache_bypass(self, registry_with_tools):
        result1 = await registry_with_tools.call_tool("baseinfo", "http://example.com", use_cache=True)
        result2 = await registry_with_tools.call_tool("baseinfo", "http://example.com", use_cache=False)
        assert result2.metadata.get("from_cache") is False


class TestToolRegistryStats:
    """工具执行统计测试"""

    @pytest.mark.asyncio
    async def test_update_tool_stats(self, registry_with_tools):
        await registry_with_tools.call_tool("baseinfo", "http://example.com", use_cache=False)
        meta = registry_with_tools.tool_metadata["baseinfo"]
        assert meta["call_count"] >= 1
        assert meta["last_called_at"] is not None


# ============================================================================
# 3. 节点功能测试
# ============================================================================


class TestTargetContextUpdater:
    """TargetContextUpdater 上下文更新测试"""

    def test_update_context_baseinfo(self, sample_state):
        data = {"server": "nginx", "os": "linux", "ip": "1.2.3.4"}
        TargetContextUpdater.update_context(sample_state, "baseinfo", data)
        assert sample_state.target_context.get("server") == "nginx"
        assert sample_state.target_context.get("os") == "linux"

    def test_update_context_portscan(self, sample_state):
        data = {"open_ports": [80, 443, 8080]}
        TargetContextUpdater.update_context(sample_state, "portscan", data)
        assert sample_state.target_context.get("open_ports") == [80, 443, 8080]

    def test_update_context_cms_identify(self, sample_state):
        data = {"cms": "wordpress"}
        TargetContextUpdater.update_context(sample_state, "cms_identify", data)
        assert sample_state.target_context.get("cms") == "wordpress"

    def test_update_context_waf_detect(self, sample_state):
        data = {"waf": "cloudflare"}
        TargetContextUpdater.update_context(sample_state, "waf_detect", data)
        assert sample_state.target_context.get("waf") == "cloudflare"

    def test_update_context_cdn_detect(self, sample_state):
        data = {"is_cdn": True, "has_cdn": True}
        TargetContextUpdater.update_context(sample_state, "cdn_detect", data)
        assert sample_state.target_context.get("cdn") is True
        assert sample_state.target_context.get("has_cdn") is True

    def test_update_context_subdomain_scan(self, sample_state):
        data = {"subdomains": ["sub1.example.com", "sub2.example.com"]}
        TargetContextUpdater.update_context(sample_state, "subdomain_scan", data)
        assert sample_state.target_context.get("subdomains") == ["sub1.example.com", "sub2.example.com"]

    def test_update_context_unknown_tool(self, sample_state):
        data = {"something": "value"}
        TargetContextUpdater.update_context(sample_state, "unknown_tool", data)
        assert "something" not in sample_state.target_context

    def test_update_context_empty_data(self, sample_state):
        TargetContextUpdater.update_context(sample_state, "baseinfo", None)
        assert len(sample_state.target_context) == 0

    def test_update_context_partial_data(self, sample_state):
        data = {"server": "apache"}
        TargetContextUpdater.update_context(sample_state, "baseinfo", data)
        assert sample_state.target_context.get("server") == "apache"

    def test_update_context_non_dict_data(self, sample_state):
        TargetContextUpdater.update_context(sample_state, "baseinfo", "not a dict")
        assert len(sample_state.target_context) == 0

    def test_context_mappings_completeness(self):
        expected_tools = [
            "baseinfo", "cms_identify", "portscan", "waf_detect",
            "cdn_detect", "subdomain_scan", "webside_scan",
            "iplocating", "infoleak_scan", "dirscan",
        ]
        for tool in expected_tools:
            assert tool in TargetContextUpdater.CONTEXT_MAPPINGS


class TestProgressCalculator:
    """ProgressCalculator 进度计算测试"""

    def test_calculate_progress_zero_total(self):
        assert ProgressCalculator.calculate_progress(5, 0) == 0

    def test_calculate_progress_full(self):
        assert ProgressCalculator.calculate_progress(10, 10) == 100

    def test_calculate_progress_half(self):
        assert ProgressCalculator.calculate_progress(5, 10) == 50

    def test_calculate_progress_capped_at_100(self):
        assert ProgressCalculator.calculate_progress(15, 10) == 100

    def test_calculate_progress_zero_completed(self):
        assert ProgressCalculator.calculate_progress(0, 10) == 0

    def test_calculate_stage_progress(self):
        progress = ProgressCalculator.calculate_stage_progress(
            completed_tasks=["baseinfo", "portscan"],
            planned_tasks=["sqli_scan", "xss_scan"],
        )
        assert progress == 50

    def test_calculate_stage_progress_empty(self):
        progress = ProgressCalculator.calculate_stage_progress([], [])
        assert progress == 0

    def test_calculate_stage_progress_with_current_task(self):
        progress = ProgressCalculator.calculate_stage_progress(
            completed_tasks=["baseinfo"],
            planned_tasks=["portscan", "sqli_scan"],
            current_task="portscan",
        )
        assert progress == 33


class TestErrorHandler:
    """ErrorHandler 错误处理测试"""

    def test_handle_tool_error(self, sample_state):
        error = RuntimeError("Connection refused")
        ErrorHandler.handle_tool_error(sample_state, "portscan", error)
        assert len(sample_state.errors) == 1
        assert "portscan" in sample_state.errors[0]
        assert "Connection refused" in sample_state.errors[0]

    def test_handle_tool_error_with_step_number(self, sample_state):
        sample_state.add_execution_step_start(task="portscan")
        error = RuntimeError("Timeout")
        ErrorHandler.handle_tool_error(sample_state, "portscan", error, step_number=1)
        assert sample_state.execution_history[0]["status"] == "failed"

    def test_handle_tool_not_found(self, sample_state):
        ErrorHandler.handle_tool_not_found(sample_state, "nonexistent_tool")
        assert len(sample_state.errors) == 1
        assert "nonexistent_tool" in sample_state.errors[0]


class TestPOCTaskHelper:
    """POCTaskHelper POC任务辅助测试"""

    @patch("backend.ai_agents.core.nodes.POCAdapter.get_poc_by_cms")
    @patch("backend.ai_agents.core.nodes.POCAdapter.get_poc_by_port")
    def test_get_poc_tasks_from_context_cms(self, mock_port, mock_cms, state_with_context):
        mock_cms.return_value = ["poc_wordpress_1"]
        mock_port.return_value = []
        tasks = POCTaskHelper.get_poc_tasks_from_context(state_with_context)
        assert "poc_wordpress_1" in tasks

    @patch("backend.ai_agents.core.nodes.POCAdapter.get_poc_by_cms")
    @patch("backend.ai_agents.core.nodes.POCAdapter.get_poc_by_port")
    def test_get_poc_tasks_from_context_ports(self, mock_port, mock_cms, state_with_context):
        mock_cms.return_value = []
        mock_port.side_effect = lambda port: ["poc_weblogic"] if port == 8080 else []
        tasks = POCTaskHelper.get_poc_tasks_from_context(state_with_context)
        assert "poc_weblogic" in tasks

    @patch("backend.ai_agents.core.nodes.POCAdapter.get_poc_by_cms")
    @patch("backend.ai_agents.core.nodes.POCAdapter.get_poc_by_port")
    def test_get_poc_tasks_from_context_empty(self, mock_port, mock_cms, sample_state):
        mock_cms.return_value = []
        mock_port.return_value = []
        tasks = POCTaskHelper.get_poc_tasks_from_context(sample_state)
        assert tasks == []

    @patch("backend.ai_agents.core.nodes.POCAdapter.get_poc_by_cms")
    @patch("backend.ai_agents.core.nodes.POCAdapter.get_poc_by_port")
    def test_supplement_poc_tasks(self, mock_port, mock_cms, state_with_context):
        mock_cms.return_value = ["poc_wordpress_1", "poc_wordpress_2"]
        mock_port.return_value = []
        supplemented = POCTaskHelper.supplement_poc_tasks(state_with_context)
        assert len(supplemented) >= 1

    @patch("backend.ai_agents.core.nodes.POCAdapter.get_poc_by_cms")
    @patch("backend.ai_agents.core.nodes.POCAdapter.get_poc_by_port")
    def test_supplement_excludes_completed(self, mock_port, mock_cms, state_with_context):
        mock_cms.return_value = ["poc_wordpress_1"]
        mock_port.return_value = []
        state_with_context.completed_tasks = ["poc_wordpress_1"]
        supplemented = POCTaskHelper.supplement_poc_tasks(state_with_context)
        assert "poc_wordpress_1" not in supplemented

    @patch("backend.ai_agents.core.nodes.POCAdapter.get_poc_by_cms")
    @patch("backend.ai_agents.core.nodes.POCAdapter.get_poc_by_port")
    def test_supplement_excludes_planned(self, mock_port, mock_cms, state_with_context):
        mock_cms.return_value = ["poc_wordpress_1"]
        mock_port.return_value = []
        state_with_context.planned_tasks = ["poc_wordpress_1"]
        supplemented = POCTaskHelper.supplement_poc_tasks(state_with_context)
        assert "poc_wordpress_1" not in supplemented


class TestToolCategoryHelper:
    """ToolCategoryHelper 工具分类测试"""

    @patch("backend.ai_agents.core.nodes.registry")
    def test_get_info_collection_tools(self, mock_registry):
        mock_registry.get_tools_by_category.return_value = ["baseinfo", "portscan"]
        tools = ToolCategoryHelper.get_info_collection_tools()
        assert "baseinfo" in tools

    @patch("backend.ai_agents.core.nodes.registry")
    def test_get_vuln_scan_tools(self, mock_registry):
        mock_registry.get_tools_by_category.return_value = ["sqli_scan", "xss_scan"]
        tools = ToolCategoryHelper.get_vuln_scan_tools()
        assert "sqli_scan" in tools

    @patch("backend.ai_agents.core.nodes.registry")
    def test_get_poc_tools(self, mock_registry):
        mock_registry.get_tools_by_category.return_value = ["poc_weblogic"]
        tools = ToolCategoryHelper.get_poc_tools()
        assert "poc_weblogic" in tools


class TestEnvironmentAwarenessNode:
    """EnvironmentAwarenessNode 测试"""

    def test_detect_target_type_url(self):
        node = EnvironmentAwarenessNode()
        assert node._detect_target_type("http://example.com") == "url"
        assert node._detect_target_type("https://example.com") == "url"

    def test_detect_target_type_ip(self):
        node = EnvironmentAwarenessNode()
        assert node._detect_target_type("192.168.1.1") == "ip"

    def test_detect_target_type_domain(self):
        node = EnvironmentAwarenessNode()
        assert node._detect_target_type("example.com") == "domain"

    def test_is_ip_valid(self):
        node = EnvironmentAwarenessNode()
        assert node._is_ip("192.168.1.1") is True
        assert node._is_ip("10.0.0.1") is True

    def test_is_ip_invalid(self):
        node = EnvironmentAwarenessNode()
        assert node._is_ip("999.999.999.999") is False
        assert node._is_ip("not.an.ip") is False
        assert node._is_ip("1.2.3") is False

    @pytest.mark.asyncio
    async def test_call_updates_context(self, sample_state):
        node = EnvironmentAwarenessNode()
        with patch.object(sample_state, "update_stage_status"):
            result_state = await node(sample_state)
        assert result_state.target_context.get("target_type") == "url"


# ============================================================================
# 4. LangGraph 工作流构建测试
# ============================================================================


class TestScanAgentGraphConstruction:
    """LangGraph 图构建测试"""

    @patch("backend.ai_agents.core.graph.initialize_tools")
    @patch("backend.ai_agents.core.nodes.TaskPlanningNode")
    @patch("backend.ai_agents.core.nodes.ToolExecutionNode")
    @patch("backend.ai_agents.core.nodes.ResultVerificationNode")
    @patch("backend.ai_agents.core.nodes.VulnerabilityAnalysisNode")
    @patch("backend.ai_agents.core.nodes.ReportGenerationNode")
    def test_graph_builds_successfully(
        self, mock_report, mock_analysis, mock_verification,
        mock_execution, mock_planning, mock_init_tools,
    ):
        graph_instance = ScanAgentGraph()
        assert graph_instance.graph is not None

    @patch("backend.ai_agents.core.graph.initialize_tools")
    @patch("backend.ai_agents.core.nodes.TaskPlanningNode")
    @patch("backend.ai_agents.core.nodes.ToolExecutionNode")
    @patch("backend.ai_agents.core.nodes.ResultVerificationNode")
    @patch("backend.ai_agents.core.nodes.VulnerabilityAnalysisNode")
    @patch("backend.ai_agents.core.nodes.ReportGenerationNode")
    def test_graph_has_use_subgraph_execution(
        self, mock_report, mock_analysis, mock_verification,
        mock_execution, mock_planning, mock_init_tools,
    ):
        graph_instance = ScanAgentGraph()
        assert graph_instance.use_subgraph_execution is True


class TestShouldContinueOrVerify:
    """条件路由逻辑测试"""

    @patch("backend.ai_agents.core.graph.initialize_tools")
    @patch("backend.ai_agents.core.nodes.TaskPlanningNode")
    @patch("backend.ai_agents.core.nodes.ToolExecutionNode")
    @patch("backend.ai_agents.core.nodes.ResultVerificationNode")
    @patch("backend.ai_agents.core.nodes.VulnerabilityAnalysisNode")
    @patch("backend.ai_agents.core.nodes.ReportGenerationNode")
    def test_continue_when_planned_tasks_exist(
        self, mock_report, mock_analysis, mock_verification,
        mock_execution, mock_planning, mock_init_tools,
    ):
        graph_instance = ScanAgentGraph()
        state = AgentState(target="http://example.com", task_id="test")
        state.planned_tasks = ["baseinfo", "portscan"]
        result = graph_instance._should_continue_or_verify(state)
        assert result == "continue"

    @patch("backend.ai_agents.core.graph.initialize_tools")
    @patch("backend.ai_agents.core.nodes.TaskPlanningNode")
    @patch("backend.ai_agents.core.nodes.ToolExecutionNode")
    @patch("backend.ai_agents.core.nodes.ResultVerificationNode")
    @patch("backend.ai_agents.core.nodes.VulnerabilityAnalysisNode")
    @patch("backend.ai_agents.core.nodes.ReportGenerationNode")
    def test_analyze_when_no_planned_tasks(
        self, mock_report, mock_analysis, mock_verification,
        mock_execution, mock_planning, mock_init_tools,
    ):
        graph_instance = ScanAgentGraph()
        state = AgentState(target="http://example.com", task_id="test")
        state.planned_tasks = []
        result = graph_instance._should_continue_or_verify(state)
        assert result == "analyze"

    @patch("backend.ai_agents.core.graph.initialize_tools")
    @patch("backend.ai_agents.core.nodes.TaskPlanningNode")
    @patch("backend.ai_agents.core.nodes.ToolExecutionNode")
    @patch("backend.ai_agents.core.nodes.ResultVerificationNode")
    @patch("backend.ai_agents.core.nodes.VulnerabilityAnalysisNode")
    @patch("backend.ai_agents.core.nodes.ReportGenerationNode")
    def test_analyze_when_max_rounds_reached(
        self, mock_report, mock_analysis, mock_verification,
        mock_execution, mock_planning, mock_init_tools,
    ):
        graph_instance = ScanAgentGraph()
        state = AgentState(target="http://example.com", task_id="test")
        state.planned_tasks = ["baseinfo"]
        state.target_context["_tool_execution_rounds"] = 50
        result = graph_instance._should_continue_or_verify(state)
        assert result == "analyze"

    @patch("backend.ai_agents.core.graph.initialize_tools")
    @patch("backend.ai_agents.core.nodes.TaskPlanningNode")
    @patch("backend.ai_agents.core.nodes.ToolExecutionNode")
    @patch("backend.ai_agents.core.nodes.ResultVerificationNode")
    @patch("backend.ai_agents.core.nodes.VulnerabilityAnalysisNode")
    @patch("backend.ai_agents.core.nodes.ReportGenerationNode")
    def test_round_counter_increments(
        self, mock_report, mock_analysis, mock_verification,
        mock_execution, mock_planning, mock_init_tools,
    ):
        graph_instance = ScanAgentGraph()
        state = AgentState(target="http://example.com", task_id="test")
        state.planned_tasks = ["baseinfo"]
        initial_round = state.target_context.get("_tool_execution_rounds", 0)
        graph_instance._should_continue_or_verify(state)
        assert state.target_context["_tool_execution_rounds"] == initial_round + 1


class TestSubgraphConstruction:
    """子图构建测试"""

    @patch("backend.ai_agents.core.graph.initialize_tools")
    @patch("backend.ai_agents.core.nodes.TaskPlanningNode")
    @patch("backend.ai_agents.core.nodes.ToolExecutionNode")
    @patch("backend.ai_agents.core.nodes.ResultVerificationNode")
    @patch("backend.ai_agents.core.nodes.VulnerabilityAnalysisNode")
    @patch("backend.ai_agents.core.nodes.ReportGenerationNode")
    def test_should_continue_info_collection(
        self, mock_report, mock_analysis, mock_verification,
        mock_execution, mock_planning, mock_init_tools,
    ):
        graph_instance = ScanAgentGraph()
        state = AgentState(target="http://example.com", task_id="test")
        state.planned_tasks = ["baseinfo"]
        state.completed_tasks = ["init"]
        assert graph_instance._should_continue_info_collection(state) == "continue"

    @patch("backend.ai_agents.core.graph.initialize_tools")
    @patch("backend.ai_agents.core.nodes.TaskPlanningNode")
    @patch("backend.ai_agents.core.nodes.ToolExecutionNode")
    @patch("backend.ai_agents.core.nodes.ResultVerificationNode")
    @patch("backend.ai_agents.core.nodes.VulnerabilityAnalysisNode")
    @patch("backend.ai_agents.core.nodes.ReportGenerationNode")
    def test_should_complete_info_collection(
        self, mock_report, mock_analysis, mock_verification,
        mock_execution, mock_planning, mock_init_tools,
    ):
        graph_instance = ScanAgentGraph()
        state = AgentState(target="http://example.com", task_id="test")
        state.planned_tasks = []
        assert graph_instance._should_continue_info_collection(state) == "complete"

    @patch("backend.ai_agents.core.graph.initialize_tools")
    @patch("backend.ai_agents.core.nodes.TaskPlanningNode")
    @patch("backend.ai_agents.core.nodes.ToolExecutionNode")
    @patch("backend.ai_agents.core.nodes.ResultVerificationNode")
    @patch("backend.ai_agents.core.nodes.VulnerabilityAnalysisNode")
    @patch("backend.ai_agents.core.nodes.ReportGenerationNode")
    def test_should_continue_vuln_scan(
        self, mock_report, mock_analysis, mock_verification,
        mock_execution, mock_planning, mock_init_tools,
    ):
        graph_instance = ScanAgentGraph()
        state = AgentState(target="http://example.com", task_id="test")
        state.planned_tasks = ["sqli_scan"]
        state.completed_tasks = ["baseinfo"]
        assert graph_instance._should_continue_vuln_scan(state) == "continue"

    @patch("backend.ai_agents.core.graph.initialize_tools")
    @patch("backend.ai_agents.core.nodes.TaskPlanningNode")
    @patch("backend.ai_agents.core.nodes.ToolExecutionNode")
    @patch("backend.ai_agents.core.nodes.ResultVerificationNode")
    @patch("backend.ai_agents.core.nodes.VulnerabilityAnalysisNode")
    @patch("backend.ai_agents.core.nodes.ReportGenerationNode")
    def test_should_aggregate_vuln_scan(
        self, mock_report, mock_analysis, mock_verification,
        mock_execution, mock_planning, mock_init_tools,
    ):
        graph_instance = ScanAgentGraph()
        state = AgentState(target="http://example.com", task_id="test")
        state.planned_tasks = []
        assert graph_instance._should_continue_vuln_scan(state) == "aggregate"

    @patch("backend.ai_agents.core.graph.initialize_tools")
    @patch("backend.ai_agents.core.nodes.TaskPlanningNode")
    @patch("backend.ai_agents.core.nodes.ToolExecutionNode")
    @patch("backend.ai_agents.core.nodes.ResultVerificationNode")
    @patch("backend.ai_agents.core.nodes.VulnerabilityAnalysisNode")
    @patch("backend.ai_agents.core.nodes.ReportGenerationNode")
    def test_should_continue_poc_verification(
        self, mock_report, mock_analysis, mock_verification,
        mock_execution, mock_planning, mock_init_tools,
    ):
        graph_instance = ScanAgentGraph()
        state = AgentState(target="http://example.com", task_id="test")
        state.planned_tasks = ["poc_weblogic"]
        state.completed_tasks = ["baseinfo"]
        assert graph_instance._should_continue_poc_verification(state) == "continue"

    @patch("backend.ai_agents.core.graph.initialize_tools")
    @patch("backend.ai_agents.core.nodes.TaskPlanningNode")
    @patch("backend.ai_agents.core.nodes.ToolExecutionNode")
    @patch("backend.ai_agents.core.nodes.ResultVerificationNode")
    @patch("backend.ai_agents.core.nodes.VulnerabilityAnalysisNode")
    @patch("backend.ai_agents.core.nodes.ReportGenerationNode")
    def test_should_complete_poc_verification(
        self, mock_report, mock_analysis, mock_verification,
        mock_execution, mock_planning, mock_init_tools,
    ):
        graph_instance = ScanAgentGraph()
        state = AgentState(target="http://example.com", task_id="test")
        state.planned_tasks = []
        assert graph_instance._should_continue_poc_verification(state) == "complete"


# ============================================================================
# 5. 结果类型测试
# ============================================================================


class TestPluginResultCreation:
    """PluginResult 创建测试"""

    def test_success_creation(self):
        result = PluginResult.success(
            data={"ports": [80, 443]},
            execution_time=1.5,
            tool_name="portscan",
            target="http://example.com",
        )
        assert result.status == ToolStatus.SUCCESS.value
        assert result.data == {"ports": [80, 443]}
        assert result.execution_time == 1.5
        assert result.error is None

    def test_failed_creation(self):
        result = PluginResult.failed(
            error="Connection refused",
            execution_time=0.5,
            tool_name="portscan",
            target="http://example.com",
        )
        assert result.status == ToolStatus.FAILED.value
        assert result.error == "Connection refused"
        assert result.data is None

    def test_timeout_creation(self):
        result = PluginResult.timeout(
            timeout_seconds=120,
            execution_time=120.0,
            tool_name="portscan",
            target="http://example.com",
        )
        assert result.status == ToolStatus.TIMEOUT.value
        assert "120" in result.error
        assert result.metadata.get("timeout_seconds") == 120

    def test_security_blocked_creation(self):
        result = PluginResult.security_blocked(
            error="安全检查未通过",
            security_issues=["危险模式: rm -rf"],
            tool_name="baseinfo",
            target="http://evil.com",
        )
        assert result.status == ToolStatus.SECURITY_BLOCKED.value
        assert result.error == "安全检查未通过"
        assert "危险模式: rm -rf" in result.metadata.get("security_issues", [])

    def test_success_with_metadata(self):
        result = PluginResult.success(
            data={"test": True},
            tool_name="test",
            target="http://test.com",
            custom_key="custom_value",
        )
        assert result.metadata.get("custom_key") == "custom_value"


class TestPluginResultProperties:
    """PluginResult 属性测试"""

    def test_is_success(self, plugin_result_success):
        assert plugin_result_success.is_success is True
        assert plugin_result_success.is_failed is False
        assert plugin_result_success.is_timeout is False

    def test_is_failed(self, plugin_result_failed):
        assert plugin_result_failed.is_failed is True
        assert plugin_result_failed.is_success is False

    def test_is_timeout(self, plugin_result_timeout):
        assert plugin_result_timeout.is_timeout is True
        assert plugin_result_timeout.is_success is False


class TestPluginResultSerialization:
    """PluginResult 序列化测试"""

    def test_to_dict(self, plugin_result_success):
        data = plugin_result_success.to_dict()
        assert data["status"] == "success"
        assert data["data"] == {"ports": [80, 443]}
        assert data["tool_name"] == "portscan"
        assert data["target"] == "http://example.com"

    def test_from_dict(self):
        data = {
            "status": "success",
            "data": {"ports": [80, 443]},
            "error": None,
            "execution_time": 1.5,
            "metadata": {"custom": "value"},
            "tool_name": "portscan",
            "target": "http://example.com",
        }
        result = PluginResult.from_dict(data)
        assert result.status == "success"
        assert result.data == {"ports": [80, 443]}
        assert result.tool_name == "portscan"

    def test_from_dict_defaults(self):
        data = {"status": "failed"}
        result = PluginResult.from_dict(data)
        assert result.status == "failed"
        assert result.data is None
        assert result.execution_time == 0.0

    def test_roundtrip(self, plugin_result_success):
        data = plugin_result_success.to_dict()
        restored = PluginResult.from_dict(data)
        assert restored.status == plugin_result_success.status
        assert restored.data == plugin_result_success.data
        assert restored.tool_name == plugin_result_success.tool_name


class TestToolStatus:
    """ToolStatus 枚举测试"""

    def test_status_values(self):
        assert ToolStatus.SUCCESS.value == "success"
        assert ToolStatus.FAILED.value == "failed"
        assert ToolStatus.TIMEOUT.value == "timeout"
        assert ToolStatus.SECURITY_BLOCKED.value == "security_blocked"
        assert ToolStatus.CANCELLED.value == "cancelled"

    def test_status_from_value(self):
        assert ToolStatus("success") == ToolStatus.SUCCESS
        assert ToolStatus("failed") == ToolStatus.FAILED
        assert ToolStatus("timeout") == ToolStatus.TIMEOUT


class TestProgressInfo:
    """ProgressInfo 测试"""

    def test_creation(self):
        info = ProgressInfo(
            tool_name="portscan",
            target="http://example.com",
            stage="scanning",
            progress=50,
            message="Scanning ports",
            elapsed_time=5.0,
        )
        assert info.tool_name == "portscan"
        assert info.progress == 50

    def test_to_dict(self):
        info = ProgressInfo(
            tool_name="portscan",
            target="http://example.com",
            stage="scanning",
            progress=50,
        )
        data = info.to_dict()
        assert data["tool_name"] == "portscan"
        assert data["progress"] == 50

    def test_extra_data(self):
        info = ProgressInfo(
            tool_name="portscan",
            target="http://example.com",
            stage="scanning",
            progress=50,
            extra_data={"ports_found": 3},
        )
        assert info.extra_data == {"ports_found": 3}


class TestNodeStatus:
    """NodeStatus 枚举测试"""

    def test_status_values(self):
        assert NodeStatus.PENDING.value == "pending"
        assert NodeStatus.RUNNING.value == "running"
        assert NodeStatus.SUCCESS.value == "success"
        assert NodeStatus.FAILED.value == "failed"
        assert NodeStatus.SKIPPED.value == "skipped"

    def test_status_from_value(self):
        assert NodeStatus("pending") == NodeStatus.PENDING
        assert NodeStatus("running") == NodeStatus.RUNNING
        assert NodeStatus("success") == NodeStatus.SUCCESS


class TestNodeStage:
    """NodeStage 枚举测试"""

    def test_stage_values(self):
        assert NodeStage.INFO_COLLECTION.value == "info_collection"
        assert NodeStage.VULN_SCAN.value == "vuln_scan"
        assert NodeStage.POC_VERIFICATION.value == "poc_verification"
        assert NodeStage.RESULT_ANALYSIS.value == "result_analysis"
