# -*- coding:utf-8 -*-
"""
AI决策修复验证测试脚本

测试内容：
1. TestAIDecisionFailureHandling: 测试失败处理逻辑
2. TestModeSwitchStateTransfer: 测试模式切换状态传递
3. TestToolRegistration: 测试工具注册
4. TestStateFieldMapping: 测试状态字段映射
"""

import sys
import os
import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import Dict, Any, List
from datetime import datetime

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

from TOSKill.AI.state import AgentState
from TOSKill.AI.nodes import AIDecisionNode, ExecuteAnalyzeNode
from TOSKill.tools import (
    ALL_TOOLS,
    get_all_tool_names,
    get_tool_by_name,
    TOOL_COUNT,
    TOOLS_BY_CATEGORY,
)


class TestToolRegistration:
    """测试工具注册"""
    
    def test_total_tool_count(self):
        """测试工具总数是否为36个"""
        assert len(ALL_TOOLS) == 36, f"预期36个工具，实际{len(ALL_TOOLS)}个"
    
    def test_all_tools_have_name(self):
        """测试所有工具都有name属性"""
        for idx, tool in enumerate(ALL_TOOLS):
            assert hasattr(tool, 'name'), f"工具索引{idx}缺少name属性"
            assert tool.name, f"工具索引{idx}的name属性为空"
    
    def test_all_tools_have_description(self):
        """测试所有工具都有description属性"""
        for idx, tool in enumerate(ALL_TOOLS):
            assert hasattr(tool, 'description'), f"工具{tool.name if hasattr(tool, 'name') else idx}缺少description属性"
    
    def test_all_tools_are_callable(self):
        """测试所有工具都可调用"""
        for idx, tool in enumerate(ALL_TOOLS):
            is_callable = (
                hasattr(tool, 'invoke') and callable(getattr(tool, 'invoke')) or
                hasattr(tool, 'run') and callable(getattr(tool, 'run')) or
                hasattr(tool, '_run') and callable(getattr(tool, '_run')) or
                hasattr(tool, 'func') and callable(getattr(tool, 'func')) or
                callable(tool)
            )
            assert is_callable, f"工具{tool.name if hasattr(tool, 'name') else idx}不可调用"
    
    def test_tool_categories(self):
        """测试工具类别"""
        expected_categories = ["info_collection", "poc", "vuln_scan", "report"]
        for category in expected_categories:
            assert category in TOOLS_BY_CATEGORY, f"缺少工具类别: {category}"
            assert len(TOOLS_BY_CATEGORY[category]) > 0, f"工具类别{category}为空"
    
    def test_tool_count_by_category(self):
        """测试各类别工具数量"""
        assert TOOL_COUNT["info_collection"] == 13, f"信息收集工具数量不正确: {TOOL_COUNT['info_collection']}"
        assert TOOL_COUNT["poc"] == 12, f"POC工具数量不正确: {TOOL_COUNT['poc']}"
        assert TOOL_COUNT["vuln_scan"] == 8, f"漏洞扫描工具数量不正确: {TOOL_COUNT['vuln_scan']}"
        assert TOOL_COUNT["report"] == 3, f"报告工具数量不正确: {TOOL_COUNT['report']}"
    
    def test_get_tool_by_name(self):
        """测试根据名称获取工具"""
        tool_names = get_all_tool_names()
        assert len(tool_names) == 36, f"工具名称数量不正确: {len(tool_names)}"
        
        for name in tool_names[:5]:
            tool = get_tool_by_name(name)
            assert tool is not None, f"无法获取工具: {name}"
            assert tool.name == name, f"工具名称不匹配: {tool.name} != {name}"
    
    def test_ai_decision_node_tool_loading(self):
        """测试AI决策节点加载工具"""
        node = AIDecisionNode()
        assert len(node.available_tool_names) == 36, f"AI决策节点加载的工具数量不正确: {len(node.available_tool_names)}"
        assert node.tools_description is not None, "工具描述为空"


class TestStateFieldMapping:
    """测试状态字段映射"""
    
    def test_state_initialization(self):
        """测试状态初始化"""
        state = AgentState(target="http://example.com", task_id="test-001")
        
        assert state.target == "http://example.com"
        assert state.task_id == "test-001"
        assert state.planned_tasks == []
        assert state.completed_tasks == []
        assert state.errors == []
        assert state.vulnerabilities == []
        assert state.execution_history == []
        assert state.tool_results == {}
        assert state.next_mode == "info"
    
    def test_state_to_dict(self):
        """测试状态转换为字典"""
        state = AgentState(target="http://example.com", task_id="test-001")
        state.planned_tasks = ["baseinfo", "portscan"]
        state.completed_tasks = ["baseinfo"]
        state.errors = ["test_error: error message"]
        
        state_dict = state.to_dict()
        
        assert "target" in state_dict
        assert "task_id" in state_dict
        assert "planned_tasks" in state_dict
        assert "completed_tasks" in state_dict
        assert "errors" in state_dict
        assert "next_mode" in state_dict
        assert state_dict["target"] == "http://example.com"
        assert state_dict["planned_tasks"] == ["baseinfo", "portscan"]
    
    def test_state_from_dict(self):
        """测试从字典创建状态"""
        data = {
            "target": "http://test.com",
            "task_id": "test-002",
            "planned_tasks": ["sqli_scan"],
            "completed_tasks": ["baseinfo", "portscan"],
            "errors": ["old_tool: failed"],
            "next_mode": "vuln_scan"
        }
        
        state = AgentState.from_dict(data)
        
        assert state.target == "http://test.com"
        assert state.task_id == "test-002"
        assert state.planned_tasks == ["sqli_scan"]
        assert state.completed_tasks == ["baseinfo", "portscan"]
        assert state.errors == ["old_tool: failed"]
        assert state.next_mode == "vuln_scan"
    
    def test_state_mode_field(self):
        """测试模式字段"""
        state = AgentState(target="http://example.com", task_id="test-003")
        
        assert hasattr(state, 'next_mode')
        assert state.next_mode == "info"
        
        state.next_mode = "quick"
        assert state.next_mode == "quick"
        
        state.next_mode = "deep"
        assert state.next_mode == "deep"
    
    def test_state_execution_history(self):
        """测试执行历史记录"""
        state = AgentState(target="http://example.com", task_id="test-004")
        
        state.add_execution_step("baseinfo", {"success": True}, "success")
        
        assert len(state.execution_history) == 1
        assert state.execution_history[0]["task"] == "baseinfo"
        assert state.execution_history[0]["status"] == "success"
    
    def test_state_error_tracking(self):
        """测试错误追踪"""
        state = AgentState(target="http://example.com", task_id="test-005")
        
        state.add_error("portscan: Connection refused")
        state.add_error("sqli_scan: Timeout")
        
        assert len(state.errors) == 2
        assert "portscan: Connection refused" in state.errors
        assert "sqli_scan: Timeout" in state.errors
    
    def test_state_vulnerability_tracking(self):
        """测试漏洞追踪"""
        state = AgentState(target="http://example.com", task_id="test-006")
        
        vuln1 = {"type": "SQLi", "severity": "high", "location": "/search?id=1"}
        vuln2 = {"type": "XSS", "severity": "medium", "location": "/comment"}
        
        state.add_vulnerability(vuln1)
        state.add_vulnerability(vuln2)
        
        assert len(state.vulnerabilities) == 2
        assert state.vulnerabilities[0]["type"] == "SQLi"
        assert state.vulnerabilities[1]["type"] == "XSS"
    
    def test_state_data_integrity(self):
        """测试数据完整性验证"""
        state = AgentState(target="http://example.com", task_id="test-007")
        
        validation = state.validate_data_integrity()
        
        assert "is_valid" in validation
        assert "errors" in validation
        assert "warnings" in validation
        assert "field_status" in validation


class TestAIDecisionFailureHandling:
    """测试AI决策失败处理逻辑"""
    
    def test_get_failed_tools_from_errors(self):
        """测试从错误列表提取失败工具"""
        state = AgentState(target="http://example.com", task_id="test-fail-001")
        state.errors = [
            "portscan: Connection refused",
            "sqli_scan: Timeout error",
            "xss_scan: Invalid target"
        ]
        
        node = AIDecisionNode()
        failed_tools = node._get_failed_tools(state)
        
        assert "portscan" in failed_tools
        assert "sqli_scan" in failed_tools
        assert "xss_scan" in failed_tools
        assert len(failed_tools) == 3
    
    def test_failed_tools_deduplication(self):
        """测试失败工具去重"""
        state = AgentState(target="http://example.com", task_id="test-fail-002")
        state.errors = [
            "portscan: Connection refused",
            "portscan: Another error",
            "sqli_scan: Timeout"
        ]
        
        node = AIDecisionNode()
        failed_tools = node._get_failed_tools(state)
        
        assert failed_tools.count("portscan") == 1
        assert len(failed_tools) == 2
    
    def test_check_target_reachable_no_history(self):
        """测试无历史记录时的可达性检查"""
        state = AgentState(target="http://example.com", task_id="test-reach-001")
        
        node = AIDecisionNode()
        result = node._check_target_reachable(state)
        
        assert result["reachable"] == True
        assert result["confidence"] == "low"
    
    def test_check_target_reachable_with_success(self):
        """测试有成功记录时的可达性检查"""
        state = AgentState(target="http://example.com", task_id="test-reach-002")
        state.execution_history = [
            {"success": True, "tool_name": "baseinfo"},
            {"success": True, "tool_name": "portscan"},
        ]
        
        node = AIDecisionNode()
        result = node._check_target_reachable(state)
        
        assert result["reachable"] == True
        assert result["confidence"] == "high"
    
    def test_check_target_reachable_with_connection_errors(self):
        """测试有连接错误时的可达性检查"""
        state = AgentState(target="http://example.com", task_id="test-reach-003")
        state.execution_history = [
            {"success": False, "error": "Connection refused", "tool_name": "portscan"},
            {"success": False, "error": "Network unreachable", "tool_name": "subdomain"},
        ]
        
        node = AIDecisionNode()
        result = node._check_target_reachable(state)
        
        assert result["reachable"] == False
        assert result["confidence"] == "high"
    
    def test_format_execution_history_summary(self):
        """测试执行历史摘要格式化"""
        state = AgentState(target="http://example.com", task_id="test-hist-001")
        state.execution_history = [
            {"tool_name": "baseinfo", "success": True, "execution_time": 1.5, "result": {}},
            {"tool_name": "portscan", "success": False, "execution_time": 2.0, "error": "Timeout"},
        ]
        
        node = AIDecisionNode()
        summary = node._format_execution_history_summary(state, limit=5)
        
        assert "baseinfo" in summary
        assert "portscan" in summary
    
    @pytest.mark.asyncio
    async def test_ai_decision_excludes_failed_tools(self):
        """测试AI决策排除失败工具"""
        state = AgentState(target="http://example.com", task_id="test-decision-001")
        state.errors = ["portscan: Connection refused"]
        state.completed_tasks = ["baseinfo"]
        
        mock_callback = AsyncMock()
        state.set_websocket_callback(mock_callback)
        
        node = AIDecisionNode()
        
        failed_tools = node._get_failed_tools(state)
        
        assert "portscan" in failed_tools
        
        available_tools = [t for t in node.available_tool_names if t not in failed_tools]
        assert "portscan" not in available_tools


class TestModeSwitchStateTransfer:
    """测试模式切换状态传递"""
    
    def test_mode_initial_value(self):
        """测试模式初始值"""
        state = AgentState(target="http://example.com", task_id="test-mode-001")
        assert state.next_mode == "info"
    
    def test_mode_switch_to_quick(self):
        """测试切换到快速模式"""
        state = AgentState(target="http://example.com", task_id="test-mode-002")
        state.next_mode = "quick"
        
        assert state.next_mode == "quick"
        
        state_dict = state.to_dict()
        assert state_dict["next_mode"] == "quick"
    
    def test_mode_switch_to_deep(self):
        """测试切换到深度模式"""
        state = AgentState(target="http://example.com", task_id="test-mode-003")
        state.next_mode = "deep"
        
        assert state.next_mode == "deep"
        
        restored_state = AgentState.from_dict(state.to_dict())
        assert restored_state.next_mode == "deep"
    
    def test_mode_persistence_across_serialization(self):
        """测试模式在序列化中的持久化"""
        original_state = AgentState(target="http://example.com", task_id="test-mode-004")
        original_state.next_mode = "standard"
        original_state.completed_tasks = ["baseinfo", "portscan"]
        original_state.vulnerabilities = [{"type": "XSS"}]
        
        state_dict = original_state.to_dict()
        
        assert state_dict["next_mode"] == "standard"
        
        restored_state = AgentState.from_dict(state_dict)
        
        assert restored_state.next_mode == "standard"
        assert restored_state.completed_tasks == ["baseinfo", "portscan"]
        assert len(restored_state.vulnerabilities) == 1
    
    def test_mode_affects_tool_selection(self):
        """测试模式影响工具选择"""
        node = ExecuteAnalyzeNode()
        
        quick_check = node._check_tool_suitable_for_mode("sqli_scan", "quick")
        assert quick_check["suitable"] == False
        
        standard_check = node._check_tool_suitable_for_mode("sqli_scan", "standard")
        assert standard_check["suitable"] == True
        
        deep_check = node._check_tool_suitable_for_mode("sqli_scan", "deep")
        assert deep_check["suitable"] == True
    
    def test_mode_allowed_tools(self):
        """测试各模式允许的工具"""
        node = ExecuteAnalyzeNode()
        
        quick_allowed = ["baseinfo", "portscan", "waf_detect", "cdn_detect"]
        for tool in quick_allowed:
            result = node._check_tool_suitable_for_mode(tool, "quick")
            assert result["suitable"] == True, f"工具{tool}应该在quick模式下可用"
        
        stealth_allowed = ["baseinfo", "subdomain", "cdn_detect"]
        for tool in stealth_allowed:
            result = node._check_tool_suitable_for_mode(tool, "stealth")
            assert result["suitable"] == True, f"工具{tool}应该在stealth模式下可用"


class TestCompleteWorkflow:
    """测试完整工作流"""
    
    @pytest.mark.asyncio
    async def test_workflow_state_transitions(self):
        """测试工作流状态转换"""
        state = AgentState(target="http://example.com", task_id="test-workflow-001")
        
        mock_callback = AsyncMock()
        state.set_websocket_callback(mock_callback)
        
        assert state.workflow_status == "idle"
        
        state.set_workflow_running()
        assert state.workflow_status == "running"
        assert state.workflow_paused == False
        
        state.pause_workflow("测试暂停")
        assert state.workflow_status == "paused"
        assert state.workflow_paused == True
        
        state.resume_workflow()
        assert state.workflow_status == "running"
        assert state.workflow_paused == False
        
        state.set_workflow_completed()
        assert state.workflow_status == "completed"
        assert state.is_complete == True
    
    @pytest.mark.asyncio
    async def test_tool_execution_flow(self):
        """测试工具执行流程"""
        state = AgentState(target="http://example.com", task_id="test-exec-001")
        
        mock_callback = AsyncMock()
        state.set_websocket_callback(mock_callback)
        
        state.planned_tasks = ["baseinfo"]
        
        assert len(state.planned_tasks) == 1
        assert "baseinfo" in state.planned_tasks
    
    def test_error_handling_in_workflow(self):
        """测试工作流中的错误处理"""
        state = AgentState(target="http://example.com", task_id="test-error-001")
        
        state.add_error("test_tool: Test error message")
        
        assert len(state.errors) == 1
        assert "test_tool" in state.errors[0]
        
        state_dict = state.to_dict()
        assert "errors" in state_dict
        assert len(state_dict["errors"]) == 1
    
    def test_vulnerability_aggregation(self):
        """测试漏洞聚合"""
        state = AgentState(target="http://example.com", task_id="test-vuln-001")
        
        state.add_scan_result(
            tool_name="sqli_scan",
            result={
                "vulnerabilities": [
                    {"type": "SQLi", "severity": "high"},
                    {"type": "SQLi", "severity": "medium"}
                ]
            },
            execution_time=1.5,
            success=True
        )
        
        assert len(state.vulnerabilities) == 2
        assert state.vulnerabilities[0]["type"] == "SQLi"
        assert state.vulnerabilities[0]["_source_tool"] == "sqli_scan"
    
    def test_execution_history_tracking(self):
        """测试执行历史追踪"""
        state = AgentState(target="http://example.com", task_id="test-history-001")
        
        state.add_scan_result(
            tool_name="baseinfo",
            result={"server": "nginx"},
            execution_time=1.0,
            success=True
        )
        
        state.add_scan_result(
            tool_name="portscan",
            result={"ports": [80, 443]},
            execution_time=2.0,
            success=True
        )
        
        assert len(state.execution_history) == 2
        
        summary = state.get_execution_summary()
        assert summary["total_tools_executed"] == 2
        assert summary["successful_executions"] == 2


class TestExecuteAnalyzeNodeFailureHandling:
    """测试执行分析节点的失败处理"""
    
    def test_analyze_error_type_network(self):
        """测试网络错误类型分析"""
        node = ExecuteAnalyzeNode()
        
        result = node._analyze_error_type("Connection refused")
        assert result["type"] == "network"
        assert result["severity"] == "high"
        assert result["retryable"] == True
        
        result = node._analyze_error_type("Network unreachable")
        assert result["type"] == "network"
    
    def test_analyze_error_type_timeout(self):
        """测试超时错误类型分析"""
        node = ExecuteAnalyzeNode()
        
        result = node._analyze_error_type("Connection timeout")
        assert result["type"] == "timeout"
        assert result["severity"] == "medium"
        assert result["retryable"] == True
    
    def test_analyze_error_type_dns(self):
        """测试DNS错误类型分析"""
        node = ExecuteAnalyzeNode()
        
        result = node._analyze_error_type("DNS resolution failed")
        assert result["type"] == "dns"
        assert result["severity"] == "high"
        assert result["retryable"] == False
    
    def test_analyze_error_type_permission(self):
        """测试权限错误类型分析"""
        node = ExecuteAnalyzeNode()
        
        result = node._analyze_error_type("Permission denied")
        assert result["type"] == "permission"
        assert result["severity"] == "medium"
        assert result["retryable"] == False
    
    def test_analyze_error_type_waf(self):
        """测试WAF错误类型分析"""
        node = ExecuteAnalyzeNode()
        
        result = node._analyze_error_type("Blocked by WAF")
        assert result["type"] == "waf"
        assert result["severity"] == "medium"
    
    def test_get_similar_tools(self):
        """测试获取相似工具"""
        node = ExecuteAnalyzeNode()
        
        similar = node._get_similar_tools("portscan")
        assert isinstance(similar, list)
        
        similar = node._get_similar_tools("sqli_scan")
        assert isinstance(similar, list)
    
    def test_get_alternative_tools(self):
        """测试获取替代工具"""
        state = AgentState(target="http://example.com", task_id="test-alt-001")
        state.errors = ["portscan: failed"]
        state.completed_tasks = ["baseinfo"]
        
        node = ExecuteAnalyzeNode()
        
        alternatives = node._get_alternative_tools("portscan", "network", state)
        assert isinstance(alternatives, list)
        
        for tool in alternatives:
            assert tool not in state.completed_tasks
    
    def test_check_tool_before_execution_completed(self):
        """测试已完成工具检查"""
        state = AgentState(target="http://example.com", task_id="test-check-001")
        state.completed_tasks = ["baseinfo"]
        
        node = ExecuteAnalyzeNode()
        
        result = node._check_tool_before_execution("baseinfo", state)
        
        assert result["can_execute"] == False
        assert result["skip"] == True
    
    def test_check_tool_before_execution_failed(self):
        """测试失败工具检查"""
        state = AgentState(target="http://example.com", task_id="test-check-002")
        state.errors = ["portscan: Connection refused"]
        
        node = ExecuteAnalyzeNode()
        
        result = node._check_tool_before_execution("portscan", state)
        
        assert result["can_execute"] == False
        assert result["skip"] == True


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
