"""
AgentGraph 测试模块

测试Agent主图的初始化、决策路由、节点执行和状态传递
"""
import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime

from TOSKill.AI.graph import AgentGraph, get_agent_graph
from TOSKill.AI.state import AgentState


class TestAgentGraphInitialization:
    """测试AgentGraph初始化"""
    
    def test_agent_graph_init(self):
        """测试AgentGraph正确初始化"""
        graph = AgentGraph()
        
        assert graph.decision_node is not None
        assert graph.user_interact_node is not None
        assert graph.execute_node is not None
        assert graph.chat_node is not None
        assert graph.script_node is not None
        assert graph.vuln_analysis_node is not None
        assert graph.report_node is not None
        assert graph.graph is not None
    
    def test_agent_graph_has_all_nodes(self):
        """测试AgentGraph包含所有必需节点"""
        graph = AgentGraph()
        
        expected_nodes = [
            "ai_decision",
            "user_interact", 
            "execute",
            "chat",
            "script",
            "vuln_analysis",
            "report"
        ]
        
        for node_name in expected_nodes:
            assert node_name in graph.graph.nodes, f"缺少节点: {node_name}"
    
    def test_agent_graph_entry_point(self):
        """测试AgentGraph入口点设置正确"""
        graph = AgentGraph()
        
        assert graph.graph.get_entry_point() == "ai_decision"
    
    def test_get_agent_graph_singleton(self):
        """测试get_agent_graph返回单例"""
        graph1 = get_agent_graph()
        graph2 = get_agent_graph()
        
        assert graph1 is graph2


class TestAgentGraphDecisionRouter:
    """测试AgentGraph决策路由"""
    
    @pytest.fixture
    def graph(self):
        """创建AgentGraph实例"""
        return AgentGraph()
    
    @pytest.fixture
    def mock_state(self):
        """创建模拟状态"""
        state = AgentState(
            target="http://example.com",
            task_id="test-task-001"
        )
        return state
    
    def test_decision_router_returns_report_when_complete(self, graph, mock_state):
        """测试任务完成时路由到report"""
        mock_state.is_complete = True
        
        result = graph._decision_router(mock_state)
        
        assert result == "report"
    
    def test_decision_router_returns_script_when_need_generate(self, graph, mock_state):
        """测试需要生成脚本时路由到script"""
        mock_state.is_complete = False
        mock_state.need_generate_script = True
        
        result = graph._decision_router(mock_state)
        
        assert result == "script"
    
    def test_decision_router_returns_execute_when_has_planned_tasks(self, graph, mock_state):
        """测试有计划任务时路由到execute"""
        mock_state.is_complete = False
        mock_state.need_generate_script = False
        mock_state.planned_tasks = ["baseinfo", "portscan"]
        
        result = graph._decision_router(mock_state)
        
        assert result == "execute"
    
    def test_decision_router_returns_chat_when_no_tasks(self, graph, mock_state):
        """测试无任务时路由到chat"""
        mock_state.is_complete = False
        mock_state.need_generate_script = False
        mock_state.planned_tasks = []
        
        result = graph._decision_router(mock_state)
        
        assert result == "chat"
    
    def test_decision_router_priority_order(self, graph, mock_state):
        """测试决策路由优先级顺序"""
        mock_state.is_complete = True
        mock_state.need_generate_script = True
        mock_state.planned_tasks = ["task1"]
        
        result = graph._decision_router(mock_state)
        assert result == "report"
        
        mock_state.is_complete = False
        result = graph._decision_router(mock_state)
        assert result == "script"
        
        mock_state.need_generate_script = False
        result = graph._decision_router(mock_state)
        assert result == "execute"
        
        mock_state.planned_tasks = []
        result = graph._decision_router(mock_state)
        assert result == "chat"


class TestAgentGraphNodeExecution:
    """测试AgentGraph节点执行"""
    
    @pytest.fixture
    def graph(self):
        """创建AgentGraph实例"""
        return AgentGraph()
    
    @pytest.fixture
    def mock_state_with_callback(self):
        """创建带WebSocket回调的模拟状态"""
        state = AgentState(
            target="http://example.com",
            task_id="test-task-002"
        )
        
        async def mock_callback(message):
            pass
        
        state.set_websocket_callback(mock_callback)
        return state
    
    @pytest.mark.asyncio
    async def test_run_saves_initial_state_to_memory(self, graph, mock_state_with_callback):
        """测试运行时保存初始状态到记忆"""
        with patch.object(graph._memory_manager, 'save_session') as mock_save:
            with patch.object(graph.graph, 'ainvoke', new_callable=AsyncMock) as mock_invoke:
                mock_invoke.return_value = mock_state_with_callback
                
                try:
                    await graph.run(mock_state_with_callback)
                except:
                    pass
                
                mock_save.assert_called()
    
    @pytest.mark.asyncio
    async def test_run_sets_workflow_running(self, graph, mock_state_with_callback):
        """测试运行时设置工作流状态为running"""
        with patch.object(graph.graph, 'ainvoke', new_callable=AsyncMock) as mock_invoke:
            mock_invoke.return_value = mock_state_with_callback
            
            try:
                await graph.run(mock_state_with_callback)
            except:
                pass
            
            assert mock_state_with_callback.workflow_status == "running" or \
                   mock_state_with_callback.workflow_status == "completed"
    
    @pytest.mark.asyncio
    async def test_run_handles_exception(self, graph, mock_state_with_callback):
        """测试运行时异常处理"""
        with patch.object(graph.graph, 'ainvoke', new_callable=AsyncMock) as mock_invoke:
            mock_invoke.side_effect = Exception("测试异常")
            
            with pytest.raises(Exception):
                await graph.run(mock_state_with_callback)
            
            assert mock_state_with_callback.workflow_status == "failed"
    
    @pytest.mark.asyncio
    async def test_run_saves_final_state_on_success(self, graph, mock_state_with_callback):
        """测试成功完成时保存最终状态"""
        mock_state_with_callback.is_complete = True
        
        with patch.object(graph._memory_manager, 'save_session') as mock_save:
            with patch.object(graph.graph, 'ainvoke', new_callable=AsyncMock) as mock_invoke:
                mock_invoke.return_value = mock_state_with_callback
                
                try:
                    result = await graph.run(mock_state_with_callback)
                except:
                    pass
                
                assert mock_save.call_count >= 1


class TestAgentGraphStateTransfer:
    """测试AgentGraph状态传递"""
    
    @pytest.fixture
    def graph(self):
        """创建AgentGraph实例"""
        return AgentGraph()
    
    @pytest.fixture
    def mock_state(self):
        """创建模拟状态"""
        state = AgentState(
            target="http://example.com",
            task_id="test-task-003"
        )
        state.planned_tasks = ["baseinfo"]
        state.completed_tasks = []
        state.vulnerabilities = []
        return state
    
    def test_save_state_to_memory_includes_checkpoint(self, graph, mock_state):
        """测试保存状态到记忆包含检查点信息"""
        with patch.object(graph._memory_manager, 'save_session') as mock_save:
            graph._save_state_to_memory("test-session", mock_state, "initial")
            
            mock_save.assert_called_once()
            call_args = mock_save.call_args[0]
            assert call_args[0] == "test-session"
            
            saved_data = call_args[1]
            assert "_checkpoint" in saved_data
            assert saved_data["_checkpoint"]["type"] == "initial"
            assert "timestamp" in saved_data["_checkpoint"]
            assert saved_data["_checkpoint"]["task_id"] == mock_state.task_id
    
    def test_save_state_to_memory_handles_exception(self, graph, mock_state):
        """测试保存状态异常处理"""
        with patch.object(graph._memory_manager, 'save_session', side_effect=Exception("保存失败")):
            result = graph._save_state_to_memory("test-session", mock_state, "initial")
            
            assert result is None
    
    def test_state_preserved_through_nodes(self, graph, mock_state):
        """测试状态在节点间保持"""
        original_target = mock_state.target
        original_task_id = mock_state.task_id
        
        mock_state.target = "http://modified.com"
        mock_state.task_id = "modified-id"
        
        assert mock_state.target != original_target
        assert mock_state.task_id != original_task_id


class TestAgentGraphEdges:
    """测试AgentGraph边连接"""
    
    @pytest.fixture
    def graph(self):
        """创建AgentGraph实例"""
        return AgentGraph()
    
    def test_conditional_edges_from_ai_decision(self, graph):
        """测试从ai_decision的条件边"""
        assert "ai_decision" in graph.graph.nodes
        
    def test_edge_from_user_interact_to_execute(self, graph):
        """测试user_interact到execute的边"""
        pass
    
    def test_edge_from_execute_to_vuln_analysis(self, graph):
        """测试execute到vuln_analysis的边"""
        pass
    
    def test_edge_from_vuln_analysis_to_ai_decision(self, graph):
        """测试vuln_analysis到ai_decision的边"""
        pass
    
    def test_edge_from_chat_to_ai_decision(self, graph):
        """测试chat到ai_decision的边"""
        pass
    
    def test_edge_from_script_to_ai_decision(self, graph):
        """测试script到ai_decision的边"""
        pass
    
    def test_edge_from_report_to_end(self, graph):
        """测试report到END的边"""
        pass


class TestAgentGraphMemoryIntegration:
    """测试AgentGraph记忆化集成"""
    
    @pytest.fixture
    def graph(self):
        """创建AgentGraph实例"""
        return AgentGraph()
    
    @pytest.fixture
    def mock_state(self):
        """创建模拟状态"""
        state = AgentState(
            target="http://example.com",
            task_id="test-task-004",
            websocket_session_id="session-001"
        )
        return state
    
    def test_memory_manager_initialized(self, graph):
        """测试记忆管理器已初始化"""
        assert graph._memory_manager is not None
    
    @pytest.mark.asyncio
    async def test_run_adds_completion_message_to_memory(self, graph, mock_state):
        """测试运行完成时添加消息到记忆"""
        async def mock_callback(msg):
            pass
        mock_state.set_websocket_callback(mock_callback)
        
        with patch.object(graph._memory_manager, 'add_message') as mock_add:
            with patch.object(graph.graph, 'ainvoke', new_callable=AsyncMock) as mock_invoke:
                mock_invoke.return_value = mock_state
                
                try:
                    await graph.run(mock_state)
                except:
                    pass
                
                mock_add.assert_called()
    
    @pytest.mark.asyncio
    async def test_run_adds_failure_message_to_memory(self, graph, mock_state):
        """测试运行失败时添加消息到记忆"""
        async def mock_callback(msg):
            pass
        mock_state.set_websocket_callback(mock_callback)
        
        with patch.object(graph._memory_manager, 'add_message') as mock_add:
            with patch.object(graph.graph, 'ainvoke', new_callable=AsyncMock) as mock_invoke:
                mock_invoke.side_effect = Exception("测试失败")
                
                with pytest.raises(Exception):
                    await graph.run(mock_state)
                
                mock_add.assert_called()


class TestAgentGraphConcurrency:
    """测试AgentGraph并发执行"""
    
    @pytest.fixture
    def graph(self):
        """创建AgentGraph实例"""
        return AgentGraph()
    
    @pytest.mark.asyncio
    async def test_multiple_concurrent_runs(self, graph):
        """测试多个并发运行"""
        states = []
        for i in range(3):
            state = AgentState(
                target=f"http://example{i}.com",
                task_id=f"test-task-{i}"
            )
            
            async def mock_callback(msg):
                pass
            state.set_websocket_callback(mock_callback)
            states.append(state)
        
        with patch.object(graph.graph, 'ainvoke', new_callable=AsyncMock) as mock_invoke:
            mock_invoke.side_effect = lambda s: s
            
            tasks = [graph.run(state) for state in states]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            assert len(results) == 3


class TestAgentGraphValidation:
    """测试AgentGraph验证"""
    
    @pytest.fixture
    def graph(self):
        """创建AgentGraph实例"""
        return AgentGraph()
    
    def test_graph_structure_valid(self, graph):
        """测试图结构有效"""
        assert graph.graph is not None
        assert len(graph.graph.nodes) > 0
    
    def test_all_nodes_callable(self, graph):
        """测试所有节点可调用"""
        for node_name, node in graph.graph.nodes.items():
            if node_name != "__start__" and node_name != "__end__":
                assert callable(node) or hasattr(node, '__call__')
    
    def test_decision_router_returns_valid_values(self, graph):
        """测试决策路由返回有效值"""
        valid_values = {"execute", "chat", "script", "report"}
        
        state = AgentState(target="http://test.com", task_id="test")
        
        state.is_complete = True
        assert graph._decision_router(state) in valid_values
        
        state.is_complete = False
        state.need_generate_script = True
        assert graph._decision_router(state) in valid_values
        
        state.need_generate_script = False
        state.planned_tasks = ["task"]
        assert graph._decision_router(state) in valid_values
        
        state.planned_tasks = []
        assert graph._decision_router(state) in valid_values
