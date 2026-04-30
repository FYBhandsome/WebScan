# -*- coding:utf-8 -*-
"""
TOSKill 工作流测试用例

测试完整扫描流程、暂停/恢复功能、认证信息传递等。
"""

import pytest
import sys
import asyncio
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock
from datetime import datetime, timedelta

project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))


@pytest.mark.workflow
class TestScanWorkflow:
    """扫描工作流测试"""
    
    @pytest.fixture
    def mock_orchestrator(self):
        """创建模拟编排器"""
        from TOSKill.AI.graph import AgentOrchestrator
        orchestrator = AgentOrchestrator()
        return orchestrator
    
    @pytest.fixture
    def mock_state(self, test_session_id):
        """创建模拟状态"""
        from TOSKill.AI.state import create_initial_state
        return create_initial_state(target="test.example.com", task_id=test_session_id)
    
    def test_create_initial_state(self, test_session_id):
        """测试创建初始状态"""
        from TOSKill.AI.state import create_initial_state
        
        state = create_initial_state(target="example.com", task_id=test_session_id)
        
        assert state["target"] == "example.com"
        assert state["task_id"] == test_session_id
        assert state["mode"] == "info_collection"
        assert state["is_complete"] == False
        assert state["completed_tasks"] == []
        assert state["tool_results"] == {}
    
    def test_update_state(self, mock_state):
        """测试更新状态"""
        from TOSKill.AI.state import update_state
        
        updated = update_state(
            mock_state,
            target="updated.example.com",
            mode="vuln_scan"
        )
        
        assert updated["target"] == "updated.example.com"
        assert updated["mode"] == "vuln_scan"
    
    def test_append_chat(self, mock_state):
        """测试追加聊天历史"""
        from TOSKill.AI.state import append_chat
        
        updated = append_chat(mock_state, "user", "Hello")
        
        assert len(updated["chat_history"]) == 1
        assert updated["chat_history"][0]["role"] == "user"
        assert updated["chat_history"][0]["content"] == "Hello"
    
    def test_get_state_summary(self, mock_state):
        """测试获取状态摘要"""
        from TOSKill.AI.state import get_state_summary, update_state
        
        updated = update_state(
            mock_state,
            completed_tasks=["task1", "task2"],
            vulnerabilities=[{"type": "xss"}]
        )
        
        summary = get_state_summary(updated)
        
        assert summary["completed_tasks"] == 2
        assert summary["vulnerabilities"] == 1
        assert summary["is_complete"] == False


@pytest.mark.workflow
class TestInfoCollectionWorkflow:
    """信息收集工作流测试"""
    
    @pytest.fixture
    def mock_state(self, test_session_id):
        from TOSKill.AI.state import create_initial_state
        return create_initial_state(target="example.com", task_id=test_session_id, mode="info_collection")
    
    def test_info_collection_tool_sequence(self):
        """测试信息收集工具序列"""
        from TOSKill.AI.tools import TOOL_SEQUENCE_INFO
        
        assert len(TOOL_SEQUENCE_INFO) > 0
        assert "baseinfo_scan" in TOOL_SEQUENCE_INFO
        assert "port_scan" in TOOL_SEQUENCE_INFO
        assert "subdomain_scan" in TOOL_SEQUENCE_INFO
    
    def test_get_tool_sequence_by_mode(self):
        """测试按模式获取工具序列"""
        from TOSKill.AI.tools import get_tool_sequence
        
        info_tools = get_tool_sequence("info_collection")
        vuln_tools = get_tool_sequence("vuln_scan")
        full_tools = get_tool_sequence("full_scan")
        
        assert len(info_tools) > 0
        assert len(vuln_tools) > 0
        assert len(full_tools) == len(info_tools) + len(vuln_tools)
    
    @pytest.mark.asyncio
    async def test_run_info_collection(self, mock_state, clean_memory_store):
        """测试运行信息收集"""
        from TOSKill.AI.core import run_info_collection
        
        clean_memory_store.save_session(mock_state["task_id"], mock_state)
        
        with patch('TOSKill.AI.graph.get_agent_orchestrator') as mock_get_orch:
            mock_orch = MagicMock()
            mock_orch.run_info_collection = AsyncMock(return_value=mock_state)
            mock_get_orch.return_value = mock_orch
            
            result = await run_info_collection("example.com", mock_state["task_id"])
            
            assert result is not None
            assert "session_id" in result


@pytest.mark.workflow
class TestVulnScanWorkflow:
    """漏洞扫描工作流测试"""
    
    @pytest.fixture
    def mock_state(self, test_session_id):
        from TOSKill.AI.state import create_initial_state
        return create_initial_state(target="example.com", task_id=test_session_id, mode="vuln_scan")
    
    def test_vuln_scan_tool_sequence(self):
        """测试漏洞扫描工具序列"""
        from TOSKill.AI.tools import TOOL_SEQUENCE_VULN
        
        assert len(TOOL_SEQUENCE_VULN) > 0
        assert "sqli_scan" in TOOL_SEQUENCE_VULN
        assert "xss_scan" in TOOL_SEQUENCE_VULN
    
    @pytest.mark.asyncio
    async def test_run_vuln_scan(self, mock_state, clean_memory_store):
        """测试运行漏洞扫描"""
        from TOSKill.AI.core import run_vuln_scan
        
        clean_memory_store.save_session(mock_state["task_id"], mock_state)
        
        with patch('TOSKill.AI.graph.get_agent_orchestrator') as mock_get_orch:
            mock_orch = MagicMock()
            mock_orch.run_vuln_scan = AsyncMock(return_value=mock_state)
            mock_get_orch.return_value = mock_orch
            
            result = await run_vuln_scan("example.com", mock_state["task_id"])
            
            assert result is not None


@pytest.mark.workflow
class TestFullScanWorkflow:
    """完整扫描工作流测试"""
    
    @pytest.fixture
    def mock_state(self, test_session_id):
        from TOSKill.AI.state import create_initial_state
        return create_initial_state(target="example.com", task_id=test_session_id, mode="full_scan")
    
    @pytest.mark.asyncio
    async def test_run_full_scan(self, mock_state, clean_memory_store):
        """测试运行完整扫描"""
        from TOSKill.AI.core import run_full_scan
        
        clean_memory_store.save_session(mock_state["task_id"], mock_state)
        
        with patch('TOSKill.AI.graph.get_agent_orchestrator') as mock_get_orch:
            mock_orch = MagicMock()
            mock_orch.run_full_scan = AsyncMock(return_value=mock_state)
            mock_get_orch.return_value = mock_orch
            
            result = await run_full_scan("example.com", mock_state["task_id"])
            
            assert result is not None
    
    @pytest.mark.asyncio
    async def test_run_scan_mode_routing(self, mock_state, clean_memory_store):
        """测试扫描模式路由"""
        from TOSKill.AI.core import run_scan
        
        clean_memory_store.save_session(mock_state["task_id"], mock_state)
        
        modes = ["info", "info_collection", "vuln", "vuln_scan", "full", "full_scan"]
        
        for mode in modes:
            with patch('TOSKill.AI.core.run_info_collection', new_callable=AsyncMock) as mock_info:
                with patch('TOSKill.AI.core.run_vuln_scan', new_callable=AsyncMock) as mock_vuln:
                    with patch('TOSKill.AI.core.run_full_scan', new_callable=AsyncMock) as mock_full:
                        mock_info.return_value = {"session_id": mock_state["task_id"]}
                        mock_vuln.return_value = {"session_id": mock_state["task_id"]}
                        mock_full.return_value = {"session_id": mock_state["task_id"]}
                        
                        result = await run_scan(mode, "example.com", mock_state["task_id"])
                        
                        assert result is not None


@pytest.mark.workflow
class TestWorkflowPauseResume:
    """工作流暂停/恢复测试"""
    
    @pytest.fixture
    def mock_state(self, test_session_id):
        from TOSKill.AI.state import create_initial_state
        return create_initial_state(target="example.com", task_id=test_session_id)
    
    def test_set_pending_interaction(self, mock_state, clean_memory_store):
        """测试设置待处理交互"""
        interaction_data = {
            "type": "interaction_required",
            "session_id": mock_state["task_id"],
            "next_task": "baseinfo_scan"
        }
        
        clean_memory_store.set_pending_interaction(mock_state["task_id"], interaction_data)
        
        assert clean_memory_store.has_pending_interaction(mock_state["task_id"])
        assert clean_memory_store.get_pending_interaction(mock_state["task_id"]) == interaction_data
    
    def test_clear_pending_interaction(self, mock_state, clean_memory_store):
        """测试清除待处理交互"""
        interaction_data = {
            "type": "interaction_required",
            "session_id": mock_state["task_id"]
        }
        
        clean_memory_store.set_pending_interaction(mock_state["task_id"], interaction_data)
        clean_memory_store.clear_pending_interaction(mock_state["task_id"])
        
        assert not clean_memory_store.has_pending_interaction(mock_state["task_id"])
    
    def test_resume_workflow(self, mock_state, clean_memory_store):
        """测试恢复工作流"""
        from TOSKill.AI.graph import get_agent_orchestrator
        
        clean_memory_store.save_session(mock_state["task_id"], mock_state)
        
        orchestrator = get_agent_orchestrator()
        result = orchestrator.resume_workflow(mock_state["task_id"], "1")
        
        assert result == True
    
    def test_resume_nonexistent_workflow(self, clean_memory_store):
        """测试恢复不存在的工作流"""
        from TOSKill.AI.graph import get_agent_orchestrator
        
        orchestrator = get_agent_orchestrator()
        result = orchestrator.resume_workflow("nonexistent_session", "1")
        
        assert result == False
    
    def test_get_pending_interaction(self, mock_state, clean_memory_store):
        """测试获取待处理交互"""
        from TOSKill.AI.graph import get_agent_orchestrator
        
        clean_memory_store.save_session(mock_state["task_id"], mock_state)
        
        orchestrator = get_agent_orchestrator()
        pending = orchestrator.get_pending_interaction(mock_state["task_id"])
        
        assert pending is None or isinstance(pending, dict)


@pytest.mark.workflow
class TestToolExecution:
    """工具执行测试"""
    
    def test_execute_tool_success(self):
        """测试执行工具成功"""
        from TOSKill.AI.core import execute_tool
        
        with patch('TOSKill.AI.core.get_tool_by_name') as mock_get_tool:
            mock_tool = MagicMock()
            mock_tool.invoke.return_value = {"success": True, "data": {}}
            mock_get_tool.return_value = mock_tool
            
            result = execute_tool("baseinfo_scan", "example.com")
            
            assert result["tool_name"] == "baseinfo_scan"
            assert "timestamp" in result
    
    def test_execute_nonexistent_tool(self):
        """测试执行不存在的工具"""
        from TOSKill.AI.core import execute_tool
        
        with pytest.raises(ValueError) as exc_info:
            execute_tool("nonexistent_tool_xyz", "example.com")
        
        assert "不存在" in str(exc_info.value)
    
    def test_execute_tools_batch(self):
        """测试批量执行工具"""
        from TOSKill.AI.core import execute_tools_batch
        
        with patch('TOSKill.AI.core.get_tool_by_name') as mock_get_tool:
            mock_tool = MagicMock()
            mock_tool.invoke.return_value = {"success": True, "data": {}}
            mock_get_tool.return_value = mock_tool
            
            result = execute_tools_batch(["baseinfo_scan", "port_scan"], "example.com")
            
            assert "results" in result
            assert "errors" in result
            assert result["total"] == 2
    
    def test_execute_tools_batch_with_errors(self):
        """测试批量执行工具带错误"""
        from TOSKill.AI.core import execute_tools_batch
        
        with patch('TOSKill.AI.core.get_tool_by_name') as mock_get_tool:
            mock_get_tool.side_effect = [None, MagicMock(invoke=MagicMock(return_value={}))]
            
            result = execute_tools_batch(["nonexistent", "baseinfo_scan"], "example.com")
            
            assert len(result["errors"]) > 0


@pytest.mark.workflow
class TestAuthPropagation:
    """认证信息传递测试"""
    
    @pytest.fixture
    def auth_state(self, test_session_id):
        from TOSKill.AI.state import create_initial_state, update_state
        
        state = create_initial_state(target="example.com", task_id=test_session_id)
        
        auth_info = {
            "type": "cookies",
            "cookies": {"session": "test_session_value"},
            "headers": {},
            "token": "",
            "source": "test"
        }
        
        return update_state(
            state,
            auth_info=auth_info,
            auth_timestamp=datetime.now().isoformat(),
            auth_expires_at=(datetime.now() + timedelta(minutes=30)).isoformat(),
            credentials_obtained=True
        )
    
    def test_invoke_tool_with_auth(self, auth_state):
        """测试带认证信息调用工具"""
        from TOSKill.AI.tools import invoke_tool_with_auth
        
        mock_tool = MagicMock()
        mock_tool.invoke.return_value = {"success": True}
        
        result = invoke_tool_with_auth(mock_tool, "example.com", auth_state)
        
        mock_tool.invoke.assert_called_once()
        call_args = mock_tool.invoke.call_args[0][0]
        assert "cookies" in call_args
    
    def test_invoke_tool_without_auth(self):
        """测试不带认证信息调用工具"""
        from TOSKill.AI.tools import invoke_tool_with_auth
        
        mock_tool = MagicMock()
        mock_tool.invoke.return_value = {"success": True}
        
        result = invoke_tool_with_auth(mock_tool, "example.com", None)
        
        mock_tool.invoke.assert_called_once()
        call_args = mock_tool.invoke.call_args[0][0]
        assert call_args["target"] == "example.com"
    
    def test_extract_auth_from_result(self):
        """测试从结果提取认证信息"""
        from TOSKill.AI.tools import extract_auth_from_result
        
        result = {
            "cookies_obtained": {"session": "new_session"},
            "tokens_obtained": "new_token",
            "authentication_used": True
        }
        
        auth_info = extract_auth_from_result(result)
        
        assert "auth_info" in auth_info
        assert auth_info["auth_info"]["cookies"] == {"session": "new_session"}
        assert auth_info["auth_info"]["token"] == "new_token"
    
    def test_auth_state_propagation(self, auth_state, clean_memory_store):
        """测试认证状态在工作流中传递"""
        clean_memory_store.save_session(auth_state["task_id"], auth_state)
        
        saved_state = clean_memory_store.get_session(auth_state["task_id"])
        
        assert saved_state["auth_info"]["cookies"]["session"] == "test_session_value"
        assert saved_state["credentials_obtained"] == True


@pytest.mark.workflow
class TestReportGeneration:
    """报告生成测试"""
    
    @pytest.fixture
    def completed_state(self, test_session_id):
        from TOSKill.AI.state import create_initial_state, update_state
        
        state = create_initial_state(target="example.com", task_id=test_session_id)
        
        return update_state(
            state,
            completed_tasks=["baseinfo_scan", "sqli_scan"],
            tool_results={
                "baseinfo_scan": {"success": True, "data": {"server": "nginx"}},
                "sqli_scan": {"success": True, "data": {"vulnerable": False}}
            },
            vulnerabilities=[],
            is_complete=True
        )
    
    @pytest.mark.asyncio
    async def test_generate_report(self, completed_state, clean_memory_store):
        """测试生成报告"""
        from TOSKill.AI.core import generate_report
        
        clean_memory_store.save_session(completed_state["task_id"], completed_state)
        
        with patch('TOSKill.AI.graph.get_agent_orchestrator') as mock_get_orch:
            mock_orch = MagicMock()
            mock_orch.run_report = AsyncMock(return_value=completed_state)
            mock_get_orch.return_value = mock_orch
            
            result = await generate_report(completed_state["task_id"])
            
            assert result is not None
    
    def test_report_generation_with_vulnerabilities(self, test_session_id, clean_memory_store):
        """测试带漏洞的报告生成"""
        from TOSKill.AI.state import create_initial_state, update_state
        
        state = create_initial_state(target="example.com", task_id=test_session_id)
        
        state = update_state(
            state,
            completed_tasks=["sqli_scan"],
            tool_results={
                "sqli_scan": {
                    "success": True,
                    "data": {"vulnerable": True, "injection_type": "error-based"}
                }
            },
            vulnerabilities=[{
                "type": "sqli",
                "severity": "high",
                "url": "http://example.com/page?id=1"
            }]
        )
        
        clean_memory_store.save_session(test_session_id, state)
        
        saved = clean_memory_store.get_session(test_session_id)
        assert len(saved["vulnerabilities"]) == 1


@pytest.mark.workflow
class TestWorkflowErrorHandling:
    """工作流错误处理测试"""
    
    def test_tool_execution_error(self, test_session_id, clean_memory_store):
        """测试工具执行错误"""
        from TOSKill.AI.state import create_initial_state, update_state
        
        state = create_initial_state(target="example.com", task_id=test_session_id)
        
        state = update_state(
            state,
            errors=["Tool execution failed: timeout"]
        )
        
        clean_memory_store.save_session(test_session_id, state)
        
        saved = clean_memory_store.get_session(test_session_id)
        assert len(saved["errors"]) == 1
    
    def test_multiple_errors_accumulation(self, test_session_id, clean_memory_store):
        """测试多个错误累积"""
        from TOSKill.AI.state import create_initial_state, update_state
        
        state = create_initial_state(target="example.com", task_id=test_session_id)
        
        errors = ["Error 1", "Error 2", "Error 3"]
        state = update_state(state, errors=errors)
        
        clean_memory_store.save_session(test_session_id, state)
        
        saved = clean_memory_store.get_session(test_session_id)
        assert len(saved["errors"]) == 3
    
    @pytest.mark.asyncio
    async def test_scan_with_invalid_target(self, clean_memory_store):
        """测试无效目标的扫描"""
        from TOSKill.AI.core import run_scan
        
        with patch('TOSKill.AI.core.run_full_scan') as mock_run:
            mock_run.side_effect = ValueError("Invalid target")
            
            with pytest.raises(ValueError):
                await run_scan("full", "", "test_session")


@pytest.mark.workflow
class TestWorkflowStateManagement:
    """工作流状态管理测试"""
    
    def test_state_persistence(self, test_session_id, clean_memory_store):
        """测试状态持久化"""
        from TOSKill.AI.state import create_initial_state, update_state
        
        state = create_initial_state(target="example.com", task_id=test_session_id)
        
        clean_memory_store.save_session(test_session_id, state)
        
        saved = clean_memory_store.get_session(test_session_id)
        assert saved["target"] == "example.com"
    
    def test_state_update_preserves_data(self, test_session_id, clean_memory_store):
        """测试状态更新保留数据"""
        from TOSKill.AI.state import create_initial_state, update_state
        
        state = create_initial_state(target="example.com", task_id=test_session_id)
        clean_memory_store.save_session(test_session_id, state)
        
        updated = update_state(state, mode="vuln_scan", target="updated.example.com")
        clean_memory_store.save_session(test_session_id, updated)
        
        saved = clean_memory_store.get_session(test_session_id)
        assert saved["mode"] == "vuln_scan"
        assert saved["target"] == "updated.example.com"
        assert saved["task_id"] == test_session_id
    
    def test_state_version_increment(self, test_session_id, clean_memory_store):
        """测试状态版本递增"""
        from TOSKill.AI.state import create_initial_state
        
        state = create_initial_state(target="example.com", task_id=test_session_id)
        
        version1 = clean_memory_store.save_session(test_session_id, state)
        version2 = clean_memory_store.save_session(test_session_id, state)
        
        assert version2 > version1


@pytest.mark.workflow
class TestIntentRecognition:
    """意图识别测试"""
    
    @pytest.mark.asyncio
    async def test_intent_recognition_scan(self, mock_scan_state, clean_memory_store):
        """测试扫描意图识别"""
        from TOSKill.AI.graph import intent_recognition
        from TOSKill.AI.state import update_state
        
        state = update_state(mock_scan_state, user_input="扫描 example.com")
        clean_memory_store.save_session(state["task_id"], state)
        
        with patch('TOSKill.AI.graph.get_llm') as mock_llm:
            mock_response = MagicMock()
            mock_response.content = '{"intent_type": "scan", "tool_name": "", "target": "example.com", "confidence": 0.9}'
            mock_llm.return_value.invoke.return_value = mock_response
            
            result = await intent_recognition(state)
            
            assert result["intent_type"] == "scan"
    
    @pytest.mark.asyncio
    async def test_intent_recognition_tool(self, mock_scan_state, clean_memory_store):
        """测试工具调用意图识别"""
        from TOSKill.AI.graph import intent_recognition
        from TOSKill.AI.state import update_state
        
        state = update_state(mock_scan_state, user_input="使用 sqli_scan 扫描 example.com")
        clean_memory_store.save_session(state["task_id"], state)
        
        with patch('TOSKill.AI.graph.get_llm') as mock_llm:
            mock_response = MagicMock()
            mock_response.content = '{"intent_type": "tool", "tool_name": "sqli_scan", "target": "example.com", "confidence": 0.9}'
            mock_llm.return_value.invoke.return_value = mock_response
            
            result = await intent_recognition(state)
            
            assert result["intent_type"] == "tool"
    
    @pytest.mark.asyncio
    async def test_intent_recognition_chat(self, mock_scan_state, clean_memory_store):
        """测试聊天意图识别"""
        from TOSKill.AI.graph import intent_recognition
        from TOSKill.AI.state import update_state
        
        state = update_state(mock_scan_state, user_input="你好，请介绍一下SQL注入")
        clean_memory_store.save_session(state["task_id"], state)
        
        with patch('TOSKill.AI.graph.get_llm') as mock_llm:
            mock_response = MagicMock()
            mock_response.content = '{"intent_type": "chat", "tool_name": "", "target": "", "confidence": 0.9}'
            mock_llm.return_value.invoke.return_value = mock_response
            
            result = await intent_recognition(state)
            
            assert result["intent_type"] == "chat"


@pytest.mark.workflow
class TestToolExistenceCheck:
    """工具存在性检查测试"""
    
    @pytest.mark.asyncio
    async def test_tool_exists(self, mock_scan_state, clean_memory_store):
        """测试工具存在"""
        from TOSKill.AI.graph import tool_existence_check
        from TOSKill.AI.state import update_state
        
        state = update_state(mock_scan_state, direct_tool="baseinfo_scan")
        clean_memory_store.save_session(state["task_id"], state)
        
        result = await tool_existence_check(state)
        
        assert result["tool_exists"] == True
    
    @pytest.mark.asyncio
    async def test_tool_not_exists(self, mock_scan_state, clean_memory_store):
        """测试工具不存在"""
        from TOSKill.AI.graph import tool_existence_check
        from TOSKill.AI.state import update_state
        
        state = update_state(mock_scan_state, direct_tool="nonexistent_tool_xyz")
        clean_memory_store.save_session(state["task_id"], state)
        
        result = await tool_existence_check(state)
        
        assert result["tool_exists"] == False


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-m", "workflow"])
