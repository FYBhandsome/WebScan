"""
LangGraph 多子图架构 - WebSocket版本

实现三个子图：
1. 信息收集子图 (InfoCollectionGraph)
2. 漏洞扫描子图 (VulnScanGraph)  
3. 报告生成子图 (ReportGraph)

所有子图支持WebSocket实时通信，每一步执行结果都返回给前端。
"""
import logging
import asyncio
from typing import Dict, Any, Optional, Callable, Awaitable
from datetime import datetime

from langgraph.graph import StateGraph, END

from .state import AgentState
from .nodes import (
    AIDecisionNode,
    UserInteractNode,
    ExecuteAnalyzeNode,
    ChatNegotiateNode,
    ScriptToolNode,
    VulnerabilityAnalysisNode,
    ReportGenerationNode
)

logger = logging.getLogger(__name__)


class AgentGraph:
    """Agent主图 - WebSocket版本"""
    
    def __init__(self):
        self.decision_node = AIDecisionNode()
        self.user_interact_node = UserInteractNode()
        self.execute_node = ExecuteAnalyzeNode()
        self.chat_node = ChatNegotiateNode()
        self.script_node = ScriptToolNode()
        self.vuln_analysis_node = VulnerabilityAnalysisNode()
        self.report_node = ReportGenerationNode()
        
        self.graph = self._build_graph()
        logger.info("Agent主图初始化完成 (WebSocket模式)")
    
    def _build_graph(self) -> StateGraph:
        """构建主图"""
        workflow = StateGraph(AgentState)
        
        workflow.add_node("ai_decision", self.decision_node)
        workflow.add_node("user_interact", self.user_interact_node)
        workflow.add_node("execute", self.execute_node)
        workflow.add_node("chat", self.chat_node)
        workflow.add_node("script", self.script_node)
        workflow.add_node("vuln_analysis", self.vuln_analysis_node)
        workflow.add_node("report", self.report_node)
        
        workflow.set_entry_point("ai_decision")
        
        workflow.add_conditional_edges(
            "ai_decision",
            self._decision_router,
            {
                "execute": "user_interact",
                "chat": "chat",
                "script": "script",
                "report": "report"
            }
        )
        
        workflow.add_edge("user_interact", "execute")
        workflow.add_edge("execute", "vuln_analysis")
        workflow.add_edge("vuln_analysis", "ai_decision")
        workflow.add_edge("chat", "ai_decision")
        workflow.add_edge("script", "ai_decision")
        workflow.add_edge("report", END)
        
        return workflow.compile()
    
    def _decision_router(self, state: AgentState) -> str:
        """决策路由"""
        if state.is_complete:
            return "report"
        
        if state.need_generate_script:
            return "script"
        
        if state.planned_tasks:
            return "execute"
        
        return "chat"
    
    async def run(self, state: AgentState) -> AgentState:
        """运行图"""
        logger.info(f"[{state.task_id}] 开始运行Agent图")
        
        state.set_workflow_running()
        
        try:
            result = await self.graph.ainvoke(state)
            state.set_workflow_completed()
            logger.info(f"[{state.task_id}] Agent图运行完成")
            return result
        except Exception as e:
            logger.error(f"[{state.task_id}] Agent图运行失败: {e}")
            state.set_workflow_failed(str(e))
            raise


class InfoCollectionGraph:
    """信息收集子图"""
    
    def __init__(self):
        self.decision_node = AIDecisionNode()
        self.user_interact_node = UserInteractNode()
        self.execute_node = ExecuteAnalyzeNode()
        self.chat_node = ChatNegotiateNode()
        
        self.graph = self._build_graph()
        logger.info("信息收集子图初始化完成")
    
    def _build_graph(self) -> StateGraph:
        """构建信息收集子图"""
        workflow = StateGraph(AgentState)
        
        workflow.add_node("decision", self.decision_node)
        workflow.add_node("user_interact", self.user_interact_node)
        workflow.add_node("execute", self.execute_node)
        workflow.add_node("chat", self.chat_node)
        
        workflow.set_entry_point("decision")
        
        workflow.add_conditional_edges(
            "decision",
            self._info_router,
            {
                "execute": "user_interact",
                "chat": "chat",
                "end": END
            }
        )
        
        workflow.add_edge("user_interact", "execute")
        workflow.add_edge("execute", "decision")
        workflow.add_edge("chat", "decision")
        
        return workflow.compile()
    
    def _info_router(self, state: AgentState) -> str:
        """信息收集路由"""
        if state.is_complete or len(state.completed_tasks) >= 5:
            return "end"
        
        if state.planned_tasks:
            return "execute"
        
        return "chat"
    
    async def run(self, state: AgentState) -> AgentState:
        """运行信息收集子图"""
        logger.info(f"[{state.task_id}] 开始运行信息收集子图")
        
        await state.broadcast_progress("planning", 10, "开始信息收集阶段", "info_collection_start")
        
        try:
            result = await self.graph.ainvoke(state)
            await state.broadcast_progress("planning", 100, "信息收集完成", "info_collection_complete")
            return result
        except Exception as e:
            logger.error(f"信息收集子图运行失败: {e}")
            await state.send_error(f"信息收集失败: {str(e)}")
            raise


class VulnScanGraph:
    """漏洞扫描子图"""
    
    def __init__(self):
        self.decision_node = AIDecisionNode()
        self.user_interact_node = UserInteractNode()
        self.execute_node = ExecuteAnalyzeNode()
        self.vuln_analysis_node = VulnerabilityAnalysisNode()
        
        self.graph = self._build_graph()
        logger.info("漏洞扫描子图初始化完成")
    
    def _build_graph(self) -> StateGraph:
        """构建漏洞扫描子图"""
        workflow = StateGraph(AgentState)
        
        workflow.add_node("decision", self.decision_node)
        workflow.add_node("user_interact", self.user_interact_node)
        workflow.add_node("execute", self.execute_node)
        workflow.add_node("vuln_analysis", self.vuln_analysis_node)
        
        workflow.set_entry_point("decision")
        
        workflow.add_conditional_edges(
            "decision",
            self._vuln_router,
            {
                "execute": "user_interact",
                "analyze": "vuln_analysis",
                "end": END
            }
        )
        
        workflow.add_edge("user_interact", "execute")
        workflow.add_edge("execute", "decision")
        workflow.add_edge("vuln_analysis", END)
        
        return workflow.compile()
    
    def _vuln_router(self, state: AgentState) -> str:
        """漏洞扫描路由"""
        if state.is_complete:
            return "end"
        
        if len(state.vulnerabilities) > 0 and not state.planned_tasks:
            return "analyze"
        
        if state.planned_tasks:
            return "execute"
        
        return "end"
    
    async def run(self, state: AgentState) -> AgentState:
        """运行漏洞扫描子图"""
        logger.info(f"[{state.task_id}] 开始运行漏洞扫描子图")
        
        await state.broadcast_progress("tool_execution", 10, "开始漏洞扫描阶段", "vuln_scan_start")
        
        try:
            result = await self.graph.ainvoke(state)
            await state.broadcast_progress("tool_execution", 100, "漏洞扫描完成", "vuln_scan_complete")
            return result
        except Exception as e:
            logger.error(f"漏洞扫描子图运行失败: {e}")
            await state.send_error(f"漏洞扫描失败: {str(e)}")
            raise


class ReportGraph:
    """报告生成子图"""
    
    def __init__(self):
        self.report_node = ReportGenerationNode()
        
        self.graph = self._build_graph()
        logger.info("报告生成子图初始化完成")
    
    def _build_graph(self) -> StateGraph:
        """构建报告生成子图"""
        workflow = StateGraph(AgentState)
        
        workflow.add_node("report", self.report_node)
        
        workflow.set_entry_point("report")
        workflow.add_edge("report", END)
        
        return workflow.compile()
    
    async def run(self, state: AgentState) -> AgentState:
        """运行报告生成子图"""
        logger.info(f"[{state.task_id}] 开始运行报告生成子图")
        
        await state.broadcast_progress("report", 10, "开始生成报告", "report_start")
        
        try:
            result = await self.graph.ainvoke(state)
            await state.broadcast_progress("report", 100, "报告生成完成", "report_complete")
            return result
        except Exception as e:
            logger.error(f"报告生成子图运行失败: {e}")
            await state.send_error(f"报告生成失败: {str(e)}")
            raise


class AgentOrchestrator:
    """Agent编排器 - 管理多个子图的执行"""
    
    def __init__(self):
        self.info_graph = InfoCollectionGraph()
        self.vuln_graph = VulnScanGraph()
        self.report_graph = ReportGraph()
        
        self._active_states: Dict[str, AgentState] = {}
        logger.info("Agent编排器初始化完成")
    
    async def run_full_scan(self, state: AgentState) -> AgentState:
        """运行完整扫描流程"""
        logger.info(f"[{state.task_id}] 开始完整扫描流程")
        
        self._active_states[state.task_id] = state
        
        try:
            await state.send_ai_message(f"开始对目标 {state.target} 进行安全扫描...")
            
            state = await self.info_graph.run(state)
            
            state = await self.vuln_graph.run(state)
            
            state = await self.report_graph.run(state)
            
            state.is_complete = True
            await state.send_ai_message("扫描任务已完成！")
            
            logger.info(f"[{state.task_id}] 完整扫描流程完成")
            return state
            
        except Exception as e:
            logger.error(f"完整扫描流程失败: {e}")
            await state.send_error(f"扫描失败: {str(e)}")
            raise
        finally:
            if state.task_id in self._active_states:
                del self._active_states[state.task_id]
    
    async def run_info_collection(self, state: AgentState) -> AgentState:
        """仅运行信息收集"""
        return await self.info_graph.run(state)
    
    async def run_vuln_scan(self, state: AgentState) -> AgentState:
        """仅运行漏洞扫描"""
        return await self.vuln_graph.run(state)
    
    async def run_report(self, state: AgentState) -> AgentState:
        """仅生成报告"""
        return await self.report_graph.run(state)
    
    def get_active_state(self, task_id: str) -> Optional[AgentState]:
        """获取活动状态"""
        return self._active_states.get(task_id)
    
    def get_all_active_tasks(self) -> Dict[str, AgentState]:
        """获取所有活动任务"""
        return self._active_states.copy()


agent_graph = AgentGraph()
agent_orchestrator = AgentOrchestrator()


def get_agent_graph() -> AgentGraph:
    """获取Agent图实例"""
    return agent_graph


def get_agent_orchestrator() -> AgentOrchestrator:
    """获取Agent编排器实例"""
    return agent_orchestrator
