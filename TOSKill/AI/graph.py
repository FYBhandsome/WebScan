"""
LangGraph 多子图架构 - WebSocket版本

实现三个子图：
1. 信息收集子图 (InfoCollectionGraph)
2. 漏洞扫描子图 (VulnScanGraph)  
3. 报告生成子图 (ReportGraph)

所有子图支持WebSocket实时通信，每一步执行结果都返回给前端。
支持记忆化集成，可在执行过程中保存和恢复状态。
"""
import logging
import asyncio
from typing import Dict, Any, Optional, Callable, Awaitable, List
from datetime import datetime
from enum import Enum

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
from .memory.session_memory import get_memory_manager

logger = logging.getLogger(__name__)


class AgentGraph:
    """Agent主图 - WebSocket版本，支持记忆化集成"""
    
    def __init__(self):
        self.decision_node = AIDecisionNode()
        self.user_interact_node = UserInteractNode()
        self.execute_node = ExecuteAnalyzeNode()
        self.chat_node = ChatNegotiateNode()
        self.script_node = ScriptToolNode()
        self.vuln_analysis_node = VulnerabilityAnalysisNode()
        self.report_node = ReportGenerationNode()
        
        self.graph = self._build_graph()
        self._memory_manager = get_memory_manager()
        logger.info("Agent主图初始化完成 (WebSocket模式 + 记忆化支持)")
    
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
        """
        运行图 - 支持记忆化集成
        
        执行流程：
        1. 保存初始状态到记忆
        2. 执行图
        3. 保存最终状态到记忆
        """
        logger.info(f"[{state.task_id}] 开始运行Agent图")
        
        session_id = state.websocket_session_id or state.task_id
        
        self._save_state_to_memory(session_id, state, "initial")
        
        state.set_workflow_running()
        
        try:
            result = await self.graph.ainvoke(state)
            state.set_workflow_completed()
            
            self._save_state_to_memory(session_id, state, "final")
            
            self._memory_manager.add_message(
                session_id, 
                "system", 
                f"任务完成: {state.task_id}",
                {"status": "completed", "target": state.target}
            )
            
            logger.info(f"[{state.task_id}] Agent图运行完成")
            return result
        except Exception as e:
            logger.error(f"[{state.task_id}] Agent图运行失败: {e}")
            state.set_workflow_failed(str(e))
            
            self._save_state_to_memory(session_id, state, "failed")
            
            self._memory_manager.add_message(
                session_id,
                "system",
                f"任务失败: {str(e)}",
                {"status": "failed", "error": str(e)}
            )
            raise
    
    def _save_state_to_memory(self, session_id: str, state: AgentState, checkpoint_type: str):
        """
        保存状态到记忆
        
        Args:
            session_id: 会话ID
            state: Agent状态
            checkpoint_type: 检查点类型 (initial/intermediate/final/failed)
        """
        try:
            state_data = state.to_dict()
            state_data["_checkpoint"] = {
                "type": checkpoint_type,
                "timestamp": datetime.now().isoformat(),
                "task_id": state.task_id
            }
            
            self._memory_manager.save_session(session_id, state_data)
            logger.debug(f"[{state.task_id}] 状态已保存到记忆: {checkpoint_type}")
        except Exception as e:
            logger.warning(f"[{state.task_id}] 保存状态到记忆失败: {e}")


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


class ExecutionStage(Enum):
    """执行阶段枚举"""
    INITIAL = "initial"
    INFO_COLLECTION = "info_collection"
    VULN_SCAN = "vuln_scan"
    REPORT = "report"
    COMPLETED = "completed"
    FAILED = "failed"


class AgentOrchestrator:
    """
    Agent编排器 - 管理多个子图的执行，支持记忆化集成
    
    功能特性：
    - 子图执行后保存中间状态到记忆
    - 支持从记忆恢复状态继续执行
    - 会话管理功能
    """
    
    def __init__(self):
        self.info_graph = InfoCollectionGraph()
        self.vuln_graph = VulnScanGraph()
        self.report_graph = ReportGraph()
        
        self._active_states: Dict[str, AgentState] = {}
        self._memory_manager = get_memory_manager()
        self._session_stages: Dict[str, ExecutionStage] = {}
        logger.info("Agent编排器初始化完成 (支持记忆化)")
    
    async def run_full_scan(self, state: AgentState) -> AgentState:
        """
        运行完整扫描流程 - 支持记忆化集成
        
        执行流程：
        1. 保存初始状态
        2. 执行信息收集子图 -> 保存中间状态
        3. 执行漏洞扫描子图 -> 保存中间状态
        4. 执行报告生成子图 -> 保存最终状态
        """
        logger.info(f"[{state.task_id}] 开始完整扫描流程")
        
        session_id = state.websocket_session_id or state.task_id
        self._active_states[state.task_id] = state
        self._session_stages[state.task_id] = ExecutionStage.INITIAL
        
        self._save_checkpoint(session_id, state, ExecutionStage.INITIAL)
        
        try:
            await state.send_ai_message(f"开始对目标 {state.target} 进行安全扫描...")
            
            state = await self.info_graph.run(state)
            self._session_stages[state.task_id] = ExecutionStage.INFO_COLLECTION
            self._save_checkpoint(session_id, state, ExecutionStage.INFO_COLLECTION)
            self._memory_manager.add_message(
                session_id, "system", "信息收集阶段完成",
                {"stage": "info_collection", "completed_tasks": len(state.completed_tasks)}
            )
            
            state = await self.vuln_graph.run(state)
            self._session_stages[state.task_id] = ExecutionStage.VULN_SCAN
            self._save_checkpoint(session_id, state, ExecutionStage.VULN_SCAN)
            self._memory_manager.add_message(
                session_id, "system", "漏洞扫描阶段完成",
                {"stage": "vuln_scan", "vulnerabilities_found": len(state.vulnerabilities)}
            )
            
            state = await self.report_graph.run(state)
            self._session_stages[state.task_id] = ExecutionStage.REPORT
            self._save_checkpoint(session_id, state, ExecutionStage.REPORT)
            
            state.is_complete = True
            self._session_stages[state.task_id] = ExecutionStage.COMPLETED
            self._save_checkpoint(session_id, state, ExecutionStage.COMPLETED)
            
            await state.send_ai_message("扫描任务已完成！")
            
            self._memory_manager.add_message(
                session_id, "system", f"扫描任务完成: {state.task_id}",
                {"stage": "completed", "target": state.target}
            )
            
            logger.info(f"[{state.task_id}] 完整扫描流程完成")
            return state
            
        except Exception as e:
            logger.error(f"完整扫描流程失败: {e}")
            state.set_workflow_failed(str(e))
            self._session_stages[state.task_id] = ExecutionStage.FAILED
            self._save_checkpoint(session_id, state, ExecutionStage.FAILED)
            
            self._memory_manager.add_message(
                session_id, "system", f"扫描任务失败: {str(e)}",
                {"stage": "failed", "error": str(e)}
            )
            
            await state.send_error(f"扫描失败: {str(e)}")
            raise
        finally:
            if state.task_id in self._active_states:
                del self._active_states[state.task_id]
    
    def _save_checkpoint(self, session_id: str, state: AgentState, stage: ExecutionStage):
        """
        保存检查点到记忆
        
        Args:
            session_id: 会话ID
            state: Agent状态
            stage: 当前执行阶段
        """
        try:
            state_data = state.to_dict()
            state_data["_checkpoint"] = {
                "stage": stage.value,
                "timestamp": datetime.now().isoformat(),
                "task_id": state.task_id
            }
            
            self._memory_manager.save_session(session_id, state_data)
            logger.debug(f"[{state.task_id}] 检查点已保存: {stage.value}")
        except Exception as e:
            logger.warning(f"[{state.task_id}] 保存检查点失败: {e}")
    
    async def resume_from_memory(self, session_id: str) -> AgentState:
        """
        从记忆恢复状态并继续执行
        
        Args:
            session_id: 会话ID
            
        Returns:
            AgentState: 恢复后的状态
            
        Raises:
            ValueError: 如果会话不存在或无法恢复
        """
        checkpoint = self._memory_manager._sessions.get(session_id)
        if not checkpoint:
            raise ValueError(f"会话不存在: {session_id}")
        
        state_data = checkpoint.channel_values
        if not state_data:
            raise ValueError(f"会话状态为空: {session_id}")
        
        state = AgentState.from_dict(state_data)
        
        checkpoint_info = state_data.get("_checkpoint", {})
        stage = checkpoint_info.get("stage", "initial")
        
        logger.info(f"[{session_id}] 从记忆恢复状态，当前阶段: {stage}")
        
        if stage in ["completed", "failed"]:
            logger.info(f"[{session_id}] 任务已{stage}，无需继续执行")
            return state
        
        self._active_states[state.task_id] = state
        
        try:
            if stage in ["initial", "info_collection"]:
                if stage == "initial":
                    await state.send_ai_message(f"从记忆恢复，继续对目标 {state.target} 进行安全扫描...")
                
                if stage != "info_collection":
                    state = await self.info_graph.run(state)
                    self._save_checkpoint(session_id, state, ExecutionStage.INFO_COLLECTION)
            
            if stage in ["initial", "info_collection", "vuln_scan"]:
                if stage != "vuln_scan":
                    state = await self.vuln_graph.run(state)
                    self._save_checkpoint(session_id, state, ExecutionStage.VULN_SCAN)
            
            state = await self.report_graph.run(state)
            self._save_checkpoint(session_id, state, ExecutionStage.REPORT)
            
            state.is_complete = True
            self._save_checkpoint(session_id, state, ExecutionStage.COMPLETED)
            
            await state.send_ai_message("扫描任务已完成！")
            
            logger.info(f"[{session_id}] 从记忆恢复执行完成")
            return state
            
        except Exception as e:
            logger.error(f"[{session_id}] 从记忆恢复执行失败: {e}")
            state.set_workflow_failed(str(e))
            self._save_checkpoint(session_id, state, ExecutionStage.FAILED)
            raise
        finally:
            if state.task_id in self._active_states:
                del self._active_states[state.task_id]
    
    def get_session_state(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        获取会话状态
        
        Args:
            session_id: 会话ID
            
        Returns:
            会话状态字典，如果不存在返回None
        """
        checkpoint = self._memory_manager._sessions.get(session_id)
        if checkpoint:
            return checkpoint.channel_values
        return None
    
    def get_session_stage(self, session_id: str) -> Optional[str]:
        """
        获取会话当前执行阶段
        
        Args:
            session_id: 会话ID
            
        Returns:
            执行阶段字符串，如果不存在返回None
        """
        state_data = self.get_session_state(session_id)
        if state_data:
            return state_data.get("_checkpoint", {}).get("stage")
        return None
    
    def get_all_sessions(self) -> List[Dict[str, Any]]:
        """
        获取所有会话信息
        
        Returns:
            会话信息列表
        """
        sessions = []
        for session_id, checkpoint in self._memory_manager._sessions.items():
            state_data = checkpoint.channel_values
            checkpoint_info = state_data.get("_checkpoint", {})
            
            sessions.append({
                "session_id": session_id,
                "task_id": checkpoint_info.get("task_id", ""),
                "stage": checkpoint_info.get("stage", "unknown"),
                "timestamp": checkpoint_info.get("timestamp", ""),
                "target": state_data.get("target", ""),
                "is_complete": state_data.get("is_complete", False),
                "created_at": checkpoint.created_at,
                "updated_at": checkpoint.updated_at
            })
        
        return sessions
    
    def get_active_sessions(self) -> List[Dict[str, Any]]:
        """
        获取所有活动会话（未完成且未失败的）
        
        Returns:
            活动会话信息列表
        """
        all_sessions = self.get_all_sessions()
        return [
            s for s in all_sessions 
            if s["stage"] not in ["completed", "failed"]
        ]
    
    def delete_session(self, session_id: str) -> bool:
        """
        删除会话
        
        Args:
            session_id: 会话ID
            
        Returns:
            是否删除成功
        """
        return self._memory_manager.delete_session(session_id)
    
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
