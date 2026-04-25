"""
子图测试模块

测试InfoCollectionGraph、VulnScanGraph、ReportGraph和子图切换
"""
import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime

from TOSKill.AI.graph import (
    InfoCollectionGraph,
    VulnScanGraph,
    ReportGraph,
    AgentOrchestrator,
    ExecutionStage,
    get_agent_orchestrator
)
from TOSKill.AI.state import AgentState


class TestInfoCollectionGraphInitialization:
    """测试InfoCollectionGraph初始化"""
    
    def test_info_collection_graph_init(self):
        """测试InfoCollectionGraph正确初始化"""
        graph = InfoCollectionGraph()
        
        assert graph.decision_node is not None
        assert graph.user_interact_node is not None
        assert graph.execute_node is not None
        assert graph.chat_node is not None
        assert graph.graph is not None
    
    def test_info_collection_graph_nodes(self):
        """测试InfoCollectionGraph包含正确节点"""
        graph = InfoCollectionGraph()
        
        expected_nodes = ["decision", "user_interact", "execute", "chat"]
        
        for node_name in expected_nodes:
            assert node_name in graph.graph.nodes, f"缺少节点: {node_name}"
    
    def test_info_collection_graph_entry_point(self):
        """测试InfoCollectionGraph入口点"""
        graph = InfoCollectionGraph()
        
        assert graph.graph.get_entry_point() == "decision"


class TestInfoCollectionGraphRouter:
    """测试InfoCollectionGraph路由"""
    
    @pytest.fixture
    def graph(self):
        """创建InfoCollectionGraph实例"""
        return InfoCollectionGraph()
    
    @pytest.fixture
    def mock_state(self):
        """创建模拟状态"""
        state = AgentState(
            target="http://example.com",
            task_id="test-info-001"
        )
        return state
    
    def test_info_router_returns_end_when_complete(self, graph, mock_state):
        """测试任务完成时路由到end"""
        mock_state.is_complete = True
        
        result = graph._info_router(mock_state)
        
        assert result == "end"
    
    def test_info_router_returns_end_when_completed_tasks_exceed_limit(self, graph, mock_state):
        """测试完成任务超过限制时路由到end"""
        mock_state.is_complete = False
        mock_state.completed_tasks = ["task1", "task2", "task3", "task4", "task5"]
        
        result = graph._info_router(mock_state)
        
        assert result == "end"
    
    def test_info_router_returns_execute_when_has_planned_tasks(self, graph, mock_state):
        """测试有计划任务时路由到execute"""
        mock_state.is_complete = False
        mock_state.completed_tasks = []
        mock_state.planned_tasks = ["baseinfo"]
        
        result = graph._info_router(mock_state)
        
        assert result == "execute"
    
    def test_info_router_returns_chat_when_no_tasks(self, graph, mock_state):
        """测试无任务时路由到chat"""
        mock_state.is_complete = False
        mock_state.completed_tasks = []
        mock_state.planned_tasks = []
        
        result = graph._info_router(mock_state)
        
        assert result == "chat"


class TestInfoCollectionGraphExecution:
    """测试InfoCollectionGraph执行"""
    
    @pytest.fixture
    def graph(self):
        """创建InfoCollectionGraph实例"""
        return InfoCollectionGraph()
    
    @pytest.fixture
    def mock_state_with_callback(self):
        """创建带WebSocket回调的模拟状态"""
        state = AgentState(
            target="http://example.com",
            task_id="test-info-002"
        )
        
        async def mock_callback(message):
            pass
        
        state.set_websocket_callback(mock_callback)
        return state
    
    @pytest.mark.asyncio
    async def test_run_broadcasts_progress(self, graph, mock_state_with_callback):
        """测试运行时广播进度"""
        with patch.object(mock_state_with_callback, 'broadcast_progress', new_callable=AsyncMock) as mock_broadcast:
            with patch.object(graph.graph, 'ainvoke', new_callable=AsyncMock) as mock_invoke:
                mock_invoke.return_value = mock_state_with_callback
                
                await graph.run(mock_state_with_callback)
                
                mock_broadcast.assert_called()
    
    @pytest.mark.asyncio
    async def test_run_handles_exception(self, graph, mock_state_with_callback):
        """测试运行异常处理"""
        with patch.object(graph.graph, 'ainvoke', new_callable=AsyncMock) as mock_invoke:
            mock_invoke.side_effect = Exception("信息收集失败")
            
            with pytest.raises(Exception):
                await graph.run(mock_state_with_callback)


class TestVulnScanGraphInitialization:
    """测试VulnScanGraph初始化"""
    
    def test_vuln_scan_graph_init(self):
        """测试VulnScanGraph正确初始化"""
        graph = VulnScanGraph()
        
        assert graph.decision_node is not None
        assert graph.user_interact_node is not None
        assert graph.execute_node is not None
        assert graph.vuln_analysis_node is not None
        assert graph.graph is not None
    
    def test_vuln_scan_graph_nodes(self):
        """测试VulnScanGraph包含正确节点"""
        graph = VulnScanGraph()
        
        expected_nodes = ["decision", "user_interact", "execute", "vuln_analysis"]
        
        for node_name in expected_nodes:
            assert node_name in graph.graph.nodes, f"缺少节点: {node_name}"
    
    def test_vuln_scan_graph_entry_point(self):
        """测试VulnScanGraph入口点"""
        graph = VulnScanGraph()
        
        assert graph.graph.get_entry_point() == "decision"


class TestVulnScanGraphRouter:
    """测试VulnScanGraph路由"""
    
    @pytest.fixture
    def graph(self):
        """创建VulnScanGraph实例"""
        return VulnScanGraph()
    
    @pytest.fixture
    def mock_state(self):
        """创建模拟状态"""
        state = AgentState(
            target="http://example.com",
            task_id="test-vuln-001"
        )
        return state
    
    def test_vuln_router_returns_end_when_complete(self, graph, mock_state):
        """测试任务完成时路由到end"""
        mock_state.is_complete = True
        
        result = graph._vuln_router(mock_state)
        
        assert result == "end"
    
    def test_vuln_router_returns_analyze_when_has_vulnerabilities(self, graph, mock_state):
        """测试发现漏洞时路由到analyze"""
        mock_state.is_complete = False
        mock_state.vulnerabilities = [{"type": "xss", "severity": "high"}]
        mock_state.planned_tasks = []
        
        result = graph._vuln_router(mock_state)
        
        assert result == "analyze"
    
    def test_vuln_router_returns_execute_when_has_planned_tasks(self, graph, mock_state):
        """测试有计划任务时路由到execute"""
        mock_state.is_complete = False
        mock_state.vulnerabilities = []
        mock_state.planned_tasks = ["sqli_scan"]
        
        result = graph._vuln_router(mock_state)
        
        assert result == "execute"
    
    def test_vuln_router_returns_end_when_nothing_to_do(self, graph, mock_state):
        """测试无任务时路由到end"""
        mock_state.is_complete = False
        mock_state.vulnerabilities = []
        mock_state.planned_tasks = []
        
        result = graph._vuln_router(mock_state)
        
        assert result == "end"


class TestVulnScanGraphExecution:
    """测试VulnScanGraph执行"""
    
    @pytest.fixture
    def graph(self):
        """创建VulnScanGraph实例"""
        return VulnScanGraph()
    
    @pytest.fixture
    def mock_state_with_callback(self):
        """创建带WebSocket回调的模拟状态"""
        state = AgentState(
            target="http://example.com",
            task_id="test-vuln-002"
        )
        
        async def mock_callback(message):
            pass
        
        state.set_websocket_callback(mock_callback)
        return state
    
    @pytest.mark.asyncio
    async def test_run_broadcasts_progress(self, graph, mock_state_with_callback):
        """测试运行时广播进度"""
        with patch.object(mock_state_with_callback, 'broadcast_progress', new_callable=AsyncMock) as mock_broadcast:
            with patch.object(graph.graph, 'ainvoke', new_callable=AsyncMock) as mock_invoke:
                mock_invoke.return_value = mock_state_with_callback
                
                await graph.run(mock_state_with_callback)
                
                mock_broadcast.assert_called()
    
    @pytest.mark.asyncio
    async def test_run_handles_exception(self, graph, mock_state_with_callback):
        """测试运行异常处理"""
        with patch.object(graph.graph, 'ainvoke', new_callable=AsyncMock) as mock_invoke:
            mock_invoke.side_effect = Exception("漏洞扫描失败")
            
            with pytest.raises(Exception):
                await graph.run(mock_state_with_callback)


class TestReportGraphInitialization:
    """测试ReportGraph初始化"""
    
    def test_report_graph_init(self):
        """测试ReportGraph正确初始化"""
        graph = ReportGraph()
        
        assert graph.report_node is not None
        assert graph.graph is not None
    
    def test_report_graph_nodes(self):
        """测试ReportGraph包含正确节点"""
        graph = ReportGraph()
        
        assert "report" in graph.graph.nodes
    
    def test_report_graph_entry_point(self):
        """测试ReportGraph入口点"""
        graph = ReportGraph()
        
        assert graph.graph.get_entry_point() == "report"


class TestReportGraphExecution:
    """测试ReportGraph执行"""
    
    @pytest.fixture
    def graph(self):
        """创建ReportGraph实例"""
        return ReportGraph()
    
    @pytest.fixture
    def mock_state_with_callback(self):
        """创建带WebSocket回调的模拟状态"""
        state = AgentState(
            target="http://example.com",
            task_id="test-report-001"
        )
        state.vulnerabilities = [
            {"type": "xss", "severity": "high", "location": "/search"}
        ]
        state.completed_tasks = ["baseinfo", "sqli_scan"]
        
        async def mock_callback(message):
            pass
        
        state.set_websocket_callback(mock_callback)
        return state
    
    @pytest.mark.asyncio
    async def test_run_broadcasts_progress(self, graph, mock_state_with_callback):
        """测试运行时广播进度"""
        with patch.object(mock_state_with_callback, 'broadcast_progress', new_callable=AsyncMock) as mock_broadcast:
            with patch.object(graph.graph, 'ainvoke', new_callable=AsyncMock) as mock_invoke:
                mock_invoke.return_value = mock_state_with_callback
                
                await graph.run(mock_state_with_callback)
                
                mock_broadcast.assert_called()
    
    @pytest.mark.asyncio
    async def test_run_handles_exception(self, graph, mock_state_with_callback):
        """测试运行异常处理"""
        with patch.object(graph.graph, 'ainvoke', new_callable=AsyncMock) as mock_invoke:
            mock_invoke.side_effect = Exception("报告生成失败")
            
            with pytest.raises(Exception):
                await graph.run(mock_state_with_callback)


class TestAgentOrchestratorInitialization:
    """测试AgentOrchestrator初始化"""
    
    def test_orchestrator_init(self):
        """测试AgentOrchestrator正确初始化"""
        orchestrator = AgentOrchestrator()
        
        assert orchestrator.info_graph is not None
        assert orchestrator.vuln_graph is not None
        assert orchestrator.report_graph is not None
        assert orchestrator._active_states == {}
        assert orchestrator._session_stages == {}
    
    def test_get_agent_orchestrator_singleton(self):
        """测试get_agent_orchestrator返回单例"""
        orchestrator1 = get_agent_orchestrator()
        orchestrator2 = get_agent_orchestrator()
        
        assert orchestrator1 is orchestrator2


class TestAgentOrchestratorSubgraphSwitching:
    """测试AgentOrchestrator子图切换"""
    
    @pytest.fixture
    def orchestrator(self):
        """创建AgentOrchestrator实例"""
        return AgentOrchestrator()
    
    @pytest.fixture
    def mock_state_with_callback(self):
        """创建带WebSocket回调的模拟状态"""
        state = AgentState(
            target="http://example.com",
            task_id="test-orchestrator-001",
            websocket_session_id="session-001"
        )
        
        async def mock_callback(message):
            pass
        
        state.set_websocket_callback(mock_callback)
        return state
    
    @pytest.mark.asyncio
    async def test_run_full_scan_executes_all_subgraphs(self, orchestrator, mock_state_with_callback):
        """测试完整扫描执行所有子图"""
        with patch.object(orchestrator.info_graph, 'run', new_callable=AsyncMock) as mock_info:
            with patch.object(orchestrator.vuln_graph, 'run', new_callable=AsyncMock) as mock_vuln:
                with patch.object(orchestrator.report_graph, 'run', new_callable=AsyncMock) as mock_report:
                    mock_info.return_value = mock_state_with_callback
                    mock_vuln.return_value = mock_state_with_callback
                    mock_report.return_value = mock_state_with_callback
                    
                    result = await orchestrator.run_full_scan(mock_state_with_callback)
                    
                    mock_info.assert_called_once()
                    mock_vuln.assert_called_once()
                    mock_report.assert_called_once()
                    
                    assert result.is_complete is True
    
    @pytest.mark.asyncio
    async def test_run_full_scan_updates_session_stages(self, orchestrator, mock_state_with_callback):
        """测试完整扫描更新会话阶段"""
        with patch.object(orchestrator.info_graph, 'run', new_callable=AsyncMock) as mock_info:
            with patch.object(orchestrator.vuln_graph, 'run', new_callable=AsyncMock) as mock_vuln:
                with patch.object(orchestrator.report_graph, 'run', new_callable=AsyncMock) as mock_report:
                    mock_info.return_value = mock_state_with_callback
                    mock_vuln.return_value = mock_state_with_callback
                    mock_report.return_value = mock_state_with_callback
                    
                    await orchestrator.run_full_scan(mock_state_with_callback)
                    
                    assert mock_state_with_callback.task_id in orchestrator._session_stages
                    assert orchestrator._session_stages[mock_state_with_callback.task_id] == ExecutionStage.COMPLETED
    
    @pytest.mark.asyncio
    async def test_run_full_scan_handles_failure(self, orchestrator, mock_state_with_callback):
        """测试完整扫描失败处理"""
        with patch.object(orchestrator.info_graph, 'run', new_callable=AsyncMock) as mock_info:
            mock_info.side_effect = Exception("信息收集失败")
            
            with pytest.raises(Exception):
                await orchestrator.run_full_scan(mock_state_with_callback)
            
            assert orchestrator._session_stages[mock_state_with_callback.task_id] == ExecutionStage.FAILED
    
    @pytest.mark.asyncio
    async def test_run_individual_subgraphs(self, orchestrator, mock_state_with_callback):
        """测试单独运行子图"""
        with patch.object(orchestrator.info_graph, 'run', new_callable=AsyncMock) as mock_info:
            mock_info.return_value = mock_state_with_callback
            
            result = await orchestrator.run_info_collection(mock_state_with_callback)
            
            mock_info.assert_called_once()
            assert result == mock_state_with_callback
        
        with patch.object(orchestrator.vuln_graph, 'run', new_callable=AsyncMock) as mock_vuln:
            mock_vuln.return_value = mock_state_with_callback
            
            result = await orchestrator.run_vuln_scan(mock_state_with_callback)
            
            mock_vuln.assert_called_once()
        
        with patch.object(orchestrator.report_graph, 'run', new_callable=AsyncMock) as mock_report:
            mock_report.return_value = mock_state_with_callback
            
            result = await orchestrator.run_report(mock_state_with_callback)
            
            mock_report.assert_called_once()


class TestAgentOrchestratorSessionManagement:
    """测试AgentOrchestrator会话管理"""
    
    @pytest.fixture
    def orchestrator(self):
        """创建AgentOrchestrator实例"""
        return AgentOrchestrator()
    
    @pytest.fixture
    def mock_state(self):
        """创建模拟状态"""
        state = AgentState(
            target="http://example.com",
            task_id="test-session-001",
            websocket_session_id="session-001"
        )
        return state
    
    def test_get_session_state(self, orchestrator, mock_state):
        """测试获取会话状态"""
        orchestrator._memory_manager._sessions["session-001"] = MagicMock(
            channel_values={"target": "http://example.com"}
        )
        
        result = orchestrator.get_session_state("session-001")
        
        assert result is not None
        assert result["target"] == "http://example.com"
    
    def test_get_session_state_not_found(self, orchestrator):
        """测试获取不存在的会话状态"""
        result = orchestrator.get_session_state("non-existent")
        
        assert result is None
    
    def test_get_session_stage(self, orchestrator, mock_state):
        """测试获取会话阶段"""
        orchestrator._memory_manager._sessions["session-001"] = MagicMock(
            channel_values={
                "_checkpoint": {"stage": "info_collection"}
            }
        )
        
        result = orchestrator.get_session_stage("session-001")
        
        assert result == "info_collection"
    
    def test_get_all_sessions(self, orchestrator):
        """测试获取所有会话"""
        orchestrator._memory_manager._sessions = {
            "session-001": MagicMock(
                channel_values={
                    "target": "http://example.com",
                    "_checkpoint": {"stage": "completed", "task_id": "task-001"}
                },
                created_at=1000.0,
                updated_at=2000.0
            ),
            "session-002": MagicMock(
                channel_values={
                    "target": "http://test.com",
                    "_checkpoint": {"stage": "vuln_scan", "task_id": "task-002"}
                },
                created_at=1000.0,
                updated_at=2000.0
            )
        }
        
        result = orchestrator.get_all_sessions()
        
        assert len(result) == 2
    
    def test_get_active_sessions(self, orchestrator):
        """测试获取活动会话"""
        orchestrator._memory_manager._sessions = {
            "session-001": MagicMock(
                channel_values={
                    "_checkpoint": {"stage": "completed"}
                },
                created_at=1000.0,
                updated_at=2000.0
            ),
            "session-002": MagicMock(
                channel_values={
                    "_checkpoint": {"stage": "vuln_scan"}
                },
                created_at=1000.0,
                updated_at=2000.0
            )
        }
        
        result = orchestrator.get_active_sessions()
        
        assert len(result) == 1
        assert result[0]["session_id"] == "session-002"
    
    def test_delete_session(self, orchestrator):
        """测试删除会话"""
        with patch.object(orchestrator._memory_manager, 'delete_session', return_value=True) as mock_delete:
            result = orchestrator.delete_session("session-001")
            
            mock_delete.assert_called_once_with("session-001")
            assert result is True


class TestExecutionStage:
    """测试ExecutionStage枚举"""
    
    def test_execution_stage_values(self):
        """测试ExecutionStage枚举值"""
        assert ExecutionStage.INITIAL.value == "initial"
        assert ExecutionStage.INFO_COLLECTION.value == "info_collection"
        assert ExecutionStage.VULN_SCAN.value == "vuln_scan"
        assert ExecutionStage.REPORT.value == "report"
        assert ExecutionStage.COMPLETED.value == "completed"
        assert ExecutionStage.FAILED.value == "failed"


class TestSubgraphDataFlow:
    """测试子图间数据流转"""
    
    @pytest.fixture
    def orchestrator(self):
        """创建AgentOrchestrator实例"""
        return AgentOrchestrator()
    
    @pytest.fixture
    def mock_state_with_data(self):
        """创建带数据的模拟状态"""
        state = AgentState(
            target="http://example.com",
            task_id="test-dataflow-001"
        )
        state.completed_tasks = ["baseinfo", "portscan"]
        state.tool_results = {
            "baseinfo": {"server": "nginx"},
            "portscan": {"ports": [80, 443]}
        }
        state.vulnerabilities = [
            {"type": "info", "severity": "low"}
        ]
        
        async def mock_callback(message):
            pass
        
        state.set_websocket_callback(mock_callback)
        return state
    
    @pytest.mark.asyncio
    async def test_data_preserved_between_subgraphs(self, orchestrator, mock_state_with_data):
        """测试数据在子图间保持"""
        original_tool_results = mock_state_with_data.tool_results.copy()
        original_vulnerabilities = mock_state_with_data.vulnerabilities.copy()
        
        with patch.object(orchestrator.info_graph, 'run', new_callable=AsyncMock) as mock_info:
            with patch.object(orchestrator.vuln_graph, 'run', new_callable=AsyncMock) as mock_vuln:
                with patch.object(orchestrator.report_graph, 'run', new_callable=AsyncMock) as mock_report:
                    mock_info.return_value = mock_state_with_data
                    mock_vuln.return_value = mock_state_with_data
                    mock_report.return_value = mock_state_with_data
                    
                    await orchestrator.run_full_scan(mock_state_with_data)
                    
                    assert mock_state_with_data.tool_results["baseinfo"] == original_tool_results["baseinfo"]
                    assert mock_state_with_data.vulnerabilities[0] == original_vulnerabilities[0]
    
    @pytest.mark.asyncio
    async def test_vulnerabilities_accumulate_across_subgraphs(self, orchestrator, mock_state_with_data):
        """测试漏洞在子图间累积"""
        initial_vuln_count = len(mock_state_with_data.vulnerabilities)
        
        def add_vulnerability(state):
            state.vulnerabilities.append({"type": "xss", "severity": "high"})
            return state
        
        with patch.object(orchestrator.info_graph, 'run', new_callable=AsyncMock) as mock_info:
            with patch.object(orchestrator.vuln_graph, 'run', new_callable=AsyncMock) as mock_vuln:
                with patch.object(orchestrator.report_graph, 'run', new_callable=AsyncMock) as mock_report:
                    mock_info.return_value = mock_state_with_data
                    mock_vuln.side_effect = add_vulnerability
                    mock_report.return_value = mock_state_with_data
                    
                    await orchestrator.run_full_scan(mock_state_with_data)
                    
                    assert len(mock_state_with_data.vulnerabilities) > initial_vuln_count
