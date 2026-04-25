"""
完整工作流测试模块

测试完整扫描流程、记忆化恢复和错误处理
"""
import pytest
import asyncio
import json
import tempfile
import os
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime

from TOSKill.AI.graph import (
    AgentGraph,
    AgentOrchestrator,
    ExecutionStage,
    get_agent_graph,
    get_agent_orchestrator
)
from TOSKill.AI.state import AgentState
from TOSKill.AI.nodes import (
    AIDecisionNode,
    UserInteractNode,
    ExecuteAnalyzeNode,
    ChatNegotiateNode,
    ScriptToolNode,
    VulnerabilityAnalysisNode,
    ReportGenerationNode
)


class TestFullScanWorkflow:
    """测试完整扫描流程"""
    
    @pytest.fixture
    def orchestrator(self):
        """创建编排器"""
        return AgentOrchestrator()
    
    @pytest.fixture
    def mock_state(self):
        """创建模拟状态"""
        state = AgentState(
            target="http://example.com",
            task_id="test-full-scan-001",
            websocket_session_id="session-001"
        )
        
        async def mock_callback(message):
            pass
        
        state.set_websocket_callback(mock_callback)
        return state
    
    @pytest.mark.asyncio
    async def test_full_scan_workflow_success(self, orchestrator, mock_state):
        """测试完整扫描流程成功"""
        with patch.object(orchestrator.info_graph, 'run', new_callable=AsyncMock) as mock_info:
            with patch.object(orchestrator.vuln_graph, 'run', new_callable=AsyncMock) as mock_vuln:
                with patch.object(orchestrator.report_graph, 'run', new_callable=AsyncMock) as mock_report:
                    mock_info.return_value = mock_state
                    mock_vuln.return_value = mock_state
                    mock_report.return_value = mock_state
                    
                    result = await orchestrator.run_full_scan(mock_state)
                    
                    assert result.is_complete is True
                    assert result.workflow_status == "completed"
                    mock_info.assert_called_once()
                    mock_vuln.assert_called_once()
                    mock_report.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_full_scan_workflow_with_vulnerabilities(self, orchestrator, mock_state):
        """测试完整扫描流程发现漏洞"""
        def add_vulnerabilities(state):
            state.vulnerabilities.append({
                "type": "xss",
                "severity": "high",
                "location": "/search?q=test"
            })
            state.completed_tasks.append("xss_scan")
            return state
        
        with patch.object(orchestrator.info_graph, 'run', new_callable=AsyncMock) as mock_info:
            with patch.object(orchestrator.vuln_graph, 'run', new_callable=AsyncMock) as mock_vuln:
                with patch.object(orchestrator.report_graph, 'run', new_callable=AsyncMock) as mock_report:
                    mock_info.return_value = mock_state
                    mock_vuln.side_effect = add_vulnerabilities
                    mock_report.return_value = mock_state
                    
                    result = await orchestrator.run_full_scan(mock_state)
                    
                    assert len(result.vulnerabilities) > 0
                    assert "xss_scan" in result.completed_tasks
    
    @pytest.mark.asyncio
    async def test_full_scan_workflow_stages(self, orchestrator, mock_state):
        """测试完整扫描流程阶段更新"""
        stages_recorded = []
        
        def record_stage(stage):
            def wrapper(state):
                stages_recorded.append(stage)
                return state
            return wrapper
        
        with patch.object(orchestrator.info_graph, 'run', new_callable=AsyncMock) as mock_info:
            with patch.object(orchestrator.vuln_graph, 'run', new_callable=AsyncMock) as mock_vuln:
                with patch.object(orchestrator.report_graph, 'run', new_callable=AsyncMock) as mock_report:
                    mock_info.side_effect = record_stage("info")
                    mock_vuln.side_effect = record_stage("vuln")
                    mock_report.side_effect = record_stage("report")
                    
                    await orchestrator.run_full_scan(mock_state)
                    
                    assert stages_recorded == ["info", "vuln", "report"]
    
    @pytest.mark.asyncio
    async def test_full_scan_workflow_cleanup(self, orchestrator, mock_state):
        """测试完整扫描流程清理"""
        with patch.object(orchestrator.info_graph, 'run', new_callable=AsyncMock) as mock_info:
            with patch.object(orchestrator.vuln_graph, 'run', new_callable=AsyncMock) as mock_vuln:
                with patch.object(orchestrator.report_graph, 'run', new_callable=AsyncMock) as mock_report:
                    mock_info.return_value = mock_state
                    mock_vuln.return_value = mock_state
                    mock_report.return_value = mock_state
                    
                    await orchestrator.run_full_scan(mock_state)
                    
                    assert mock_state.task_id not in orchestrator._active_states


class TestMemoryRecovery:
    """测试记忆化恢复"""
    
    @pytest.fixture
    def orchestrator(self):
        """创建编排器"""
        return AgentOrchestrator()
    
    @pytest.fixture
    def mock_state(self):
        """创建模拟状态"""
        state = AgentState(
            target="http://example.com",
            task_id="test-recovery-001",
            websocket_session_id="session-recovery-001"
        )
        
        async def mock_callback(message):
            pass
        
        state.set_websocket_callback(mock_callback)
        return state
    
    @pytest.mark.asyncio
    async def test_resume_from_initial_stage(self, orchestrator, mock_state):
        """测试从初始阶段恢复"""
        orchestrator._memory_manager._sessions["session-recovery-001"] = MagicMock(
            channel_values={
                "target": "http://example.com",
                "task_id": "test-recovery-001",
                "_checkpoint": {"stage": "initial"}
            }
        )
        
        with patch.object(orchestrator.info_graph, 'run', new_callable=AsyncMock) as mock_info:
            with patch.object(orchestrator.vuln_graph, 'run', new_callable=AsyncMock) as mock_vuln:
                with patch.object(orchestrator.report_graph, 'run', new_callable=AsyncMock) as mock_report:
                    mock_info.return_value = mock_state
                    mock_vuln.return_value = mock_state
                    mock_report.return_value = mock_state
                    
                    result = await orchestrator.resume_from_memory("session-recovery-001")
                    
                    mock_info.assert_called_once()
                    mock_vuln.assert_called_once()
                    mock_report.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_resume_from_info_collection_stage(self, orchestrator, mock_state):
        """测试从信息收集阶段恢复"""
        orchestrator._memory_manager._sessions["session-recovery-001"] = MagicMock(
            channel_values={
                "target": "http://example.com",
                "task_id": "test-recovery-001",
                "completed_tasks": ["baseinfo"],
                "_checkpoint": {"stage": "info_collection"}
            }
        )
        
        with patch.object(orchestrator.vuln_graph, 'run', new_callable=AsyncMock) as mock_vuln:
            with patch.object(orchestrator.report_graph, 'run', new_callable=AsyncMock) as mock_report:
                mock_vuln.return_value = mock_state
                mock_report.return_value = mock_state
                
                result = await orchestrator.resume_from_memory("session-recovery-001")
                
                mock_vuln.assert_called_once()
                mock_report.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_resume_from_vuln_scan_stage(self, orchestrator, mock_state):
        """测试从漏洞扫描阶段恢复"""
        orchestrator._memory_manager._sessions["session-recovery-001"] = MagicMock(
            channel_values={
                "target": "http://example.com",
                "task_id": "test-recovery-001",
                "vulnerabilities": [{"type": "xss"}],
                "_checkpoint": {"stage": "vuln_scan"}
            }
        )
        
        with patch.object(orchestrator.report_graph, 'run', new_callable=AsyncMock) as mock_report:
            mock_report.return_value = mock_state
            
            result = await orchestrator.resume_from_memory("session-recovery-001")
            
            mock_report.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_resume_completed_task(self, orchestrator, mock_state):
        """测试恢复已完成的任务"""
        orchestrator._memory_manager._sessions["session-recovery-001"] = MagicMock(
            channel_values={
                "target": "http://example.com",
                "task_id": "test-recovery-001",
                "is_complete": True,
                "_checkpoint": {"stage": "completed"}
            }
        )
        
        result = await orchestrator.resume_from_memory("session-recovery-001")
        
        assert result.is_complete is True
    
    @pytest.mark.asyncio
    async def test_resume_non_existent_session(self, orchestrator):
        """测试恢复不存在的会话"""
        with pytest.raises(ValueError) as exc_info:
            await orchestrator.resume_from_memory("non-existent-session")
        
        assert "不存在" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_resume_preserves_state_data(self, orchestrator, mock_state):
        """测试恢复保持状态数据"""
        original_data = {
            "target": "http://example.com",
            "task_id": "test-recovery-001",
            "completed_tasks": ["baseinfo", "portscan"],
            "vulnerabilities": [{"type": "xss", "severity": "high"}],
            "tool_results": {"baseinfo": {"server": "nginx"}},
            "_checkpoint": {"stage": "vuln_scan"}
        }
        
        orchestrator._memory_manager._sessions["session-recovery-001"] = MagicMock(
            channel_values=original_data
        )
        
        with patch.object(orchestrator.report_graph, 'run', new_callable=AsyncMock) as mock_report:
            mock_report.return_value = mock_state
            
            result = await orchestrator.resume_from_memory("session-recovery-001")
            
            assert result.completed_tasks == ["baseinfo", "portscan"]


class TestErrorHandling:
    """测试错误处理"""
    
    @pytest.fixture
    def orchestrator(self):
        """创建编排器"""
        return AgentOrchestrator()
    
    @pytest.fixture
    def mock_state(self):
        """创建模拟状态"""
        state = AgentState(
            target="http://example.com",
            task_id="test-error-001",
            websocket_session_id="session-error-001"
        )
        
        async def mock_callback(message):
            pass
        
        state.set_websocket_callback(mock_callback)
        return state
    
    @pytest.mark.asyncio
    async def test_info_collection_failure(self, orchestrator, mock_state):
        """测试信息收集失败"""
        with patch.object(orchestrator.info_graph, 'run', new_callable=AsyncMock) as mock_info:
            mock_info.side_effect = Exception("信息收集失败")
            
            with pytest.raises(Exception) as exc_info:
                await orchestrator.run_full_scan(mock_state)
            
            assert "信息收集失败" in str(exc_info.value)
            assert orchestrator._session_stages[mock_state.task_id] == ExecutionStage.FAILED
    
    @pytest.mark.asyncio
    async def test_vuln_scan_failure(self, orchestrator, mock_state):
        """测试漏洞扫描失败"""
        with patch.object(orchestrator.info_graph, 'run', new_callable=AsyncMock) as mock_info:
            with patch.object(orchestrator.vuln_graph, 'run', new_callable=AsyncMock) as mock_vuln:
                mock_info.return_value = mock_state
                mock_vuln.side_effect = Exception("漏洞扫描失败")
                
                with pytest.raises(Exception) as exc_info:
                    await orchestrator.run_full_scan(mock_state)
                
                assert "漏洞扫描失败" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_report_generation_failure(self, orchestrator, mock_state):
        """测试报告生成失败"""
        with patch.object(orchestrator.info_graph, 'run', new_callable=AsyncMock) as mock_info:
            with patch.object(orchestrator.vuln_graph, 'run', new_callable=AsyncMock) as mock_vuln:
                with patch.object(orchestrator.report_graph, 'run', new_callable=AsyncMock) as mock_report:
                    mock_info.return_value = mock_state
                    mock_vuln.return_value = mock_state
                    mock_report.side_effect = Exception("报告生成失败")
                    
                    with pytest.raises(Exception) as exc_info:
                        await orchestrator.run_full_scan(mock_state)
                    
                    assert "报告生成失败" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_network_error_handling(self, orchestrator, mock_state):
        """测试网络错误处理"""
        def simulate_network_error(state):
            state.errors.append("baseinfo: Connection refused")
            state.completed_tasks = []
            return state
        
        with patch.object(orchestrator.info_graph, 'run', new_callable=AsyncMock) as mock_info:
            mock_info.side_effect = simulate_network_error
            
            result = await orchestrator.info_graph.run(mock_state)
            
            assert len(result.errors) > 0
            assert "Connection refused" in result.errors[0]
    
    @pytest.mark.asyncio
    async def test_timeout_error_handling(self, orchestrator, mock_state):
        """测试超时错误处理"""
        def simulate_timeout(state):
            state.errors.append("portscan: Timeout after 30 seconds")
            return state
        
        with patch.object(orchestrator.info_graph, 'run', new_callable=AsyncMock) as mock_info:
            mock_info.side_effect = simulate_timeout
            
            result = await orchestrator.info_graph.run(mock_state)
            
            assert "Timeout" in result.errors[0]
    
    @pytest.mark.asyncio
    async def test_partial_failure_recovery(self, orchestrator, mock_state):
        """测试部分失败恢复"""
        mock_state.completed_tasks = ["baseinfo"]
        mock_state.errors = ["portscan: Connection refused"]
        
        orchestrator._memory_manager._sessions["session-error-001"] = MagicMock(
            channel_values={
                "target": "http://example.com",
                "task_id": "test-error-001",
                "completed_tasks": ["baseinfo"],
                "errors": ["portscan: Connection refused"],
                "_checkpoint": {"stage": "info_collection"}
            }
        )
        
        with patch.object(orchestrator.vuln_graph, 'run', new_callable=AsyncMock) as mock_vuln:
            with patch.object(orchestrator.report_graph, 'run', new_callable=AsyncMock) as mock_report:
                mock_vuln.return_value = mock_state
                mock_report.return_value = mock_state
                
                result = await orchestrator.resume_from_memory("session-error-001")
                
                assert "baseinfo" in result.completed_tasks


class TestCheckpointManagement:
    """测试检查点管理"""
    
    @pytest.fixture
    def orchestrator(self):
        """创建编排器"""
        return AgentOrchestrator()
    
    @pytest.fixture
    def mock_state(self):
        """创建模拟状态"""
        state = AgentState(
            target="http://example.com",
            task_id="test-checkpoint-001",
            websocket_session_id="session-checkpoint-001"
        )
        
        async def mock_callback(message):
            pass
        
        state.set_websocket_callback(mock_callback)
        return state
    
    def test_save_checkpoint(self, orchestrator, mock_state):
        """测试保存检查点"""
        with patch.object(orchestrator._memory_manager, 'save_session') as mock_save:
            orchestrator._save_checkpoint("session-checkpoint-001", mock_state, ExecutionStage.INFO_COLLECTION)
            
            mock_save.assert_called_once()
            call_args = mock_save.call_args[0]
            assert call_args[0] == "session-checkpoint-001"
            
            saved_data = call_args[1]
            assert "_checkpoint" in saved_data
            assert saved_data["_checkpoint"]["stage"] == "info_collection"
    
    @pytest.mark.asyncio
    async def test_checkpoints_saved_at_each_stage(self, orchestrator, mock_state):
        """测试每个阶段保存检查点"""
        checkpoints = []
        
        def capture_checkpoint(session_id, state_data):
            if "_checkpoint" in state_data:
                checkpoints.append(state_data["_checkpoint"]["stage"])
        
        with patch.object(orchestrator._memory_manager, 'save_session', side_effect=capture_checkpoint):
            with patch.object(orchestrator.info_graph, 'run', new_callable=AsyncMock) as mock_info:
                with patch.object(orchestrator.vuln_graph, 'run', new_callable=AsyncMock) as mock_vuln:
                    with patch.object(orchestrator.report_graph, 'run', new_callable=AsyncMock) as mock_report:
                        mock_info.return_value = mock_state
                        mock_vuln.return_value = mock_state
                        mock_report.return_value = mock_state
                        
                        await orchestrator.run_full_scan(mock_state)
                        
                        assert "initial" in checkpoints
                        assert "info_collection" in checkpoints
                        assert "vuln_scan" in checkpoints
                        assert "completed" in checkpoints


class TestConcurrentWorkflows:
    """测试并发工作流"""
    
    @pytest.fixture
    def orchestrator(self):
        """创建编排器"""
        return AgentOrchestrator()
    
    @pytest.mark.asyncio
    async def test_multiple_concurrent_scans(self, orchestrator):
        """测试多个并发扫描"""
        states = []
        for i in range(3):
            state = AgentState(
                target=f"http://example{i}.com",
                task_id=f"test-concurrent-{i}",
                websocket_session_id=f"session-concurrent-{i}"
            )
            
            async def mock_callback(msg):
                pass
            
            state.set_websocket_callback(mock_callback)
            states.append(state)
        
        with patch.object(orchestrator.info_graph, 'run', new_callable=AsyncMock) as mock_info:
            with patch.object(orchestrator.vuln_graph, 'run', new_callable=AsyncMock) as mock_vuln:
                with patch.object(orchestrator.report_graph, 'run', new_callable=AsyncMock) as mock_report:
                    mock_info.side_effect = lambda s: s
                    mock_vuln.side_effect = lambda s: s
                    mock_report.side_effect = lambda s: s
                    
                    tasks = [orchestrator.run_full_scan(state) for state in states]
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    
                    assert len(results) == 3
                    for result in results:
                        if not isinstance(result, Exception):
                            assert result.is_complete is True


class TestWorkflowMetrics:
    """测试工作流指标"""
    
    @pytest.fixture
    def orchestrator(self):
        """创建编排器"""
        return AgentOrchestrator()
    
    @pytest.fixture
    def mock_state(self):
        """创建模拟状态"""
        state = AgentState(
            target="http://example.com",
            task_id="test-metrics-001"
        )
        
        async def mock_callback(message):
            pass
        
        state.set_websocket_callback(mock_callback)
        return state
    
    @pytest.mark.asyncio
    async def test_execution_summary_generated(self, orchestrator, mock_state):
        """测试生成执行摘要"""
        mock_state.completed_tasks = ["baseinfo", "portscan", "sqli_scan"]
        mock_state.vulnerabilities = [{"type": "xss"}, {"type": "sqli"}]
        mock_state.errors = ["timeout_error"]
        
        summary = mock_state.get_execution_summary()
        
        assert summary["total_tools_executed"] == 3
        assert summary["total_vulnerabilities"] == 2
        assert summary["total_errors"] == 1
    
    @pytest.mark.asyncio
    async def test_progress_tracking(self, orchestrator, mock_state):
        """测试进度追踪"""
        mock_state.update_stage_status("planning", "running", None, 50)
        mock_state.update_stage_status("tool_execution", "running", None, 30)
        
        progress = mock_state.get_progress()
        
        assert 0 <= progress <= 100


class TestWorkflowConfiguration:
    """测试工作流配置"""
    
    @pytest.fixture
    def orchestrator(self):
        """创建编排器"""
        return AgentOrchestrator()
    
    @pytest.fixture
    def mock_state(self):
        """创建模拟状态"""
        state = AgentState(
            target="http://example.com",
            task_id="test-config-001"
        )
        
        async def mock_callback(message):
            pass
        
        state.set_websocket_callback(mock_callback)
        return state
    
    @pytest.mark.asyncio
    async def test_custom_scan_mode(self, orchestrator, mock_state):
        """测试自定义扫描模式"""
        mock_state.next_mode = "quick"
        
        with patch.object(orchestrator.info_graph, 'run', new_callable=AsyncMock) as mock_info:
            mock_info.return_value = mock_state
            
            result = await orchestrator.run_info_collection(mock_state)
            
            assert result.next_mode == "quick"
    
    @pytest.mark.asyncio
    async def test_user_preferences_preserved(self, orchestrator, mock_state):
        """测试用户偏好保持"""
        mock_state.user_name = "测试用户"
        mock_state.user_choice = "1"
        
        with patch.object(orchestrator.info_graph, 'run', new_callable=AsyncMock) as mock_info:
            with patch.object(orchestrator.vuln_graph, 'run', new_callable=AsyncMock) as mock_vuln:
                with patch.object(orchestrator.report_graph, 'run', new_callable=AsyncMock) as mock_report:
                    mock_info.return_value = mock_state
                    mock_vuln.return_value = mock_state
                    mock_report.return_value = mock_state
                    
                    result = await orchestrator.run_full_scan(mock_state)
                    
                    assert result.user_name == "测试用户"


class TestIntegrationScenarios:
    """集成测试场景"""
    
    @pytest.fixture
    def orchestrator(self):
        """创建编排器"""
        return AgentOrchestrator()
    
    @pytest.fixture
    def full_mock_state(self):
        """创建完整模拟状态"""
        state = AgentState(
            target="http://testphp.vulnweb.com",
            task_id="test-integration-001",
            websocket_session_id="session-integration-001"
        )
        
        messages = []
        
        async def mock_callback(message):
            messages.append(message)
        
        state.set_websocket_callback(mock_callback)
        state._messages = messages
        return state
    
    @pytest.mark.asyncio
    async def test_complete_scan_with_findings(self, orchestrator, full_mock_state):
        """测试完整扫描发现漏洞"""
        def info_collection_result(state):
            state.completed_tasks = ["baseinfo", "portscan", "dirscan"]
            state.tool_results = {
                "baseinfo": {"server": "Apache", "title": "Test Site"},
                "portscan": {"ports": [80, 443]},
                "dirscan": {"directories": ["/admin", "/backup"]}
            }
            return state
        
        def vuln_scan_result(state):
            state.vulnerabilities = [
                {"type": "sqli", "severity": "high", "location": "/search?id=1"},
                {"type": "xss", "severity": "medium", "location": "/search?q=test"}
            ]
            state.completed_tasks.extend(["sqli_scan", "xss_scan"])
            return state
        
        def report_result(state):
            state.report = "# 安全扫描报告\n\n发现2个漏洞"
            state.is_complete = True
            return state
        
        with patch.object(orchestrator.info_graph, 'run', new_callable=AsyncMock) as mock_info:
            with patch.object(orchestrator.vuln_graph, 'run', new_callable=AsyncMock) as mock_vuln:
                with patch.object(orchestrator.report_graph, 'run', new_callable=AsyncMock) as mock_report:
                    mock_info.side_effect = info_collection_result
                    mock_vuln.side_effect = vuln_scan_result
                    mock_report.side_effect = report_result
                    
                    result = await orchestrator.run_full_scan(full_mock_state)
                    
                    assert result.is_complete is True
                    assert len(result.vulnerabilities) == 2
                    assert len(result.completed_tasks) == 5
                    assert result.report is not None
    
    @pytest.mark.asyncio
    async def test_scan_with_user_interaction(self, orchestrator, full_mock_state):
        """测试带用户交互的扫描"""
        user_interactions = []
        
        async def mock_user_confirm(prompt, options):
            user_interactions.append({"prompt": prompt, "options": options})
            return "confirm"
        
        with patch.object(full_mock_state, 'request_user_confirmation', new_callable=AsyncMock) as mock_confirm:
            mock_confirm.side_effect = mock_user_confirm
            
            with patch.object(orchestrator.info_graph, 'run', new_callable=AsyncMock) as mock_info:
                with patch.object(orchestrator.vuln_graph, 'run', new_callable=AsyncMock) as mock_vuln:
                    with patch.object(orchestrator.report_graph, 'run', new_callable=AsyncMock) as mock_report:
                        mock_info.return_value = full_mock_state
                        mock_vuln.return_value = full_mock_state
                        mock_report.return_value = full_mock_state
                        
                        await orchestrator.run_full_scan(full_mock_state)
    
    @pytest.mark.asyncio
    async def test_scan_with_memory_persistence(self, orchestrator, full_mock_state):
        """测试带记忆持久化的扫描"""
        saved_checkpoints = []
        
        def capture_save(session_id, state_data):
            if "_checkpoint" in state_data:
                saved_checkpoints.append({
                    "session_id": session_id,
                    "stage": state_data["_checkpoint"]["stage"]
                })
        
        with patch.object(orchestrator._memory_manager, 'save_session', side_effect=capture_save):
            with patch.object(orchestrator.info_graph, 'run', new_callable=AsyncMock) as mock_info:
                with patch.object(orchestrator.vuln_graph, 'run', new_callable=AsyncMock) as mock_vuln:
                    with patch.object(orchestrator.report_graph, 'run', new_callable=AsyncMock) as mock_report:
                        mock_info.return_value = full_mock_state
                        mock_vuln.return_value = full_mock_state
                        mock_report.return_value = full_mock_state
                        
                        await orchestrator.run_full_scan(full_mock_state)
                        
                        assert len(saved_checkpoints) > 0
                        stages = [cp["stage"] for cp in saved_checkpoints]
                        assert "completed" in stages
