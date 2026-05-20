"""
LangGraph 图构建

构建支持自主规划、代码生成、环境感知的完整Agent工作流。

日志记录:
- 时间戳:所有日志包含时间戳
- 操作类型:节点进入/退出、状态变更、决策结果、错误信息
- 对象标识:任务ID、节点名称、状态键名
- 详细描述:操作的具体内容和结果
"""
import json
import logging
import time
from typing import Dict, Any, Literal, Optional, Union
from langgraph.graph import StateGraph, END

from .state import AgentState
from .nodes import (
    TaskPlanningNode,
    ToolExecutionNode,
    ResultVerificationNode,
    VulnerabilityAnalysisNode,
    ReportGenerationNode
)

from ..agent_config import agent_config

logger = logging.getLogger(__name__)


class LogHelper:
    _CATEGORIES = {
        "node_entry": ("NODE_ENTRY", "info"),
        "node_exit": ("NODE_EXIT", "info"),
        "state_change": ("STATE_CHANGE", "info"),
        "decision": ("DECISION", "info"),
        "edge_traversal": ("EDGE_TRAVERSAL", "info"),
        "error": ("ERROR", "error"),
        "variable": ("VARIABLE", "debug"),
    }

    def __init__(self, logger_instance: logging.Logger = None):
        self._logger = logger_instance or logger

    def _log(self, category: str, task_id: str, message: str, details: Any = None, level: str = None):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        tag, default_level = self._CATEGORIES.get(category, (category.upper(), "info"))
        log_level = level or default_level
        log_msg = f"[{timestamp}] [{tag}] 任务ID: {task_id}, {message}"
        if details:
            log_msg += f", 详情: {details}"
        getattr(self._logger, log_level)(log_msg)

    def _log_debug(self, category: str, task_id: str, message: str, data: Any = None):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        tag = self._CATEGORIES.get(category, (category.upper(),))[0] + "_DEBUG"
        data_str = json.dumps(data, ensure_ascii=False, default=str) if data else "None"
        self._logger.debug(f"[{timestamp}] [{tag}] 任务ID: {task_id}, {message}, 完整数据: {data_str}")

    def node_entry(self, node_name: str, task_id: str, details: Dict[str, Any] = None):
        self._log("node_entry", task_id, f"节点: {node_name}", details)
        self._log_debug("node_entry", task_id, f"节点: {node_name}", details)

    def node_exit(self, node_name: str, task_id: str, status: str, details: Dict[str, Any] = None):
        self._log("node_exit", task_id, f"节点: {node_name}, 状态: {status}", details)
        self._log_debug("node_exit", task_id, f"节点: {node_name}, 状态: {status}", details)

    def state_change(self, task_id: str, key: str, old_value: Any, new_value: Any):
        self._log("state_change", task_id, f"键: {key}, 旧值: {old_value}, 新值: {new_value}")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self._logger.debug(f"[{timestamp}] [STATE_CHANGE_DEBUG] 任务ID: {task_id}, 键: {key}, 旧值类型: {type(old_value).__name__}, 新值类型: {type(new_value).__name__}")

    def decision(self, task_id: str, decision_type: str, decision: str, reason: str = ""):
        msg = f"类型: {decision_type}, 决策: {decision}"
        if reason:
            msg += f", 原因: {reason}"
        self._log("decision", task_id, msg)

    def edge_traversal(self, task_id: str, from_node: str, to_node: str, condition: str = "", state_snapshot: Dict[str, Any] = None):
        msg = f"边: {from_node} → {to_node}"
        if condition:
            msg += f", 条件: {condition}"
        self._log("edge_traversal", task_id, msg)
        if state_snapshot:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            self._logger.debug(f"[{timestamp}] [EDGE_STATE_SNAPSHOT] 任务ID: {task_id}, 状态快照: {json.dumps(state_snapshot, ensure_ascii=False, default=str)[:500]}")

    def error(self, task_id: str, node_name: str, error: Exception, context: Dict[str, Any] = None):
        self._log("error", task_id, f"节点: {node_name}, 错误: {str(error)}", context)
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self._logger.debug(f"[{timestamp}] [ERROR_DEBUG] 任务ID: {task_id}, 异常类型: {type(error).__name__}, 堆栈: {error.__traceback__}")

    def variable_value(self, task_id: str, node_name: str, var_name: str, var_value: Any, var_type: str = None):
        value_str = str(var_value)[:100] if var_value is not None else "None"
        type_str = var_type or type(var_value).__name__ if var_value is not None else "NoneType"
        self._log("variable", task_id, f"节点: {node_name}, 变量: {var_name}, 值: {value_str}, 类型: {type_str}")


log_helper = LogHelper()


class ScanAgentGraph:
    """
    扫描Agent图类
    
    负责构建和编译LangGraph工作流。
    """
    
    def __init__(self):
        """
        初始化扫描Agent图
        """
        logger.info("🔧 初始化扫描Agent图")
        
        # 初始化所有工具
        initialize_tools()
        
        # 创建核心节点实例
        self.planning_node = TaskPlanningNode()
        self.execution_node = ToolExecutionNode()
        self.verification_node = ResultVerificationNode()
        self.analysis_node = VulnerabilityAnalysisNode()
        self.report_node = ReportGenerationNode()
        
        # 构建图（保留用于兼容性，但默认使用子图顺序执行）
        self.graph = self._build_graph()
        
        # 设置默认执行模式：子图顺序执行（更灵活、更易调试）
        self.use_subgraph_execution = True
        
        logger.info("✅ 扫描Agent图构建完成（默认使用子图顺序执行模式）")
    
    def _build_graph(self) -> StateGraph:
        """
        构建LangGraph图 (简化版)

        实现简化的工作流:
        - 任务规划 → 工具执行
        - 工具执行 → 结果验证 → 循环/漏洞分析
        - 漏洞分析 → 报告生成 → 结束

        Returns:
            StateGraph: 编译后的图
        """
        log_helper.node_entry("_build_graph", "GRAPH_BUILD", {"total_nodes": 5})

        # 创建状态图
        workflow = StateGraph(AgentState)

        # 添加核心节点
        workflow.add_node("task_planning", self.planning_node)
        workflow.add_node("tool_execution", self.execution_node)
        workflow.add_node("result_verification", self.verification_node)
        workflow.add_node("vulnerability_analysis", self.analysis_node)
        workflow.add_node("report_generation", self.report_node)

        # 设置入口点:从任务规划开始
        workflow.set_entry_point("task_planning")

        # 基础流程:任务规划 → 工具执行
        workflow.add_edge("task_planning", "tool_execution")

        # 工具流程:执行→验证→循环/分析
        workflow.add_edge("tool_execution", "result_verification")
        workflow.add_conditional_edges(
            "result_verification",
            self._should_continue_or_verify,
            {
                "continue": "tool_execution",
                "analyze": "vulnerability_analysis"
            }
        )

        # 后续流程:分析→报告→结束
        workflow.add_edge("vulnerability_analysis", "report_generation")
        workflow.add_edge("report_generation", END)

        logger.info("📊 LangGraph图边定义完成")
        log_helper.node_exit("_build_graph", "GRAPH_BUILD", "success", {"nodes_count": 5, "edges_count": 5})
        return workflow
    
    def _should_continue_or_verify(self, state: AgentState) -> Literal["continue", "analyze"]:
        """
        判断是否继续执行工具

        Args:
            state: Agent当前状态

        Returns:
            Literal["continue", "analyze"]: 下一步节点名称
        """
        max_tool_rounds = 50
        tool_round_key = "_tool_execution_rounds"
        current_round = state.target_context.get(tool_round_key, 0)

        log_helper.variable_value(state.task_id, "_should_continue_or_verify", "current_round", current_round)
        log_helper.variable_value(state.task_id, "_should_continue_or_verify", "planned_tasks", state.planned_tasks)

        if current_round >= max_tool_rounds:
            logger.warning(f"[{state.task_id}] ⚠️ 已达到工具执行最大轮次({max_tool_rounds}),强制进入分析阶段")
            log_helper.edge_traversal(
                task_id=state.task_id,
                from_node="result_verification",
                to_node="vulnerability_analysis",
                condition=f"max_rounds_reached={max_tool_rounds}"
            )
            log_helper.decision(
                task_id=state.task_id,
                decision_type="SHOULD_CONTINUE",
                decision="analyze",
                reason=f"达到工具执行最大轮次({max_tool_rounds})"
            )
            return "analyze"

        state.target_context[tool_round_key] = current_round + 1
        log_helper.state_change(state.task_id, tool_round_key, current_round, current_round + 1)

        if state.planned_tasks:
            logger.info(f"[{state.task_id}] 🔄 继续执行工具: {state.planned_tasks[0]}")
            log_helper.edge_traversal(
                task_id=state.task_id,
                from_node="result_verification",
                to_node="tool_execution",
                condition=f"next_task={state.planned_tasks[0]}"
            )
            log_helper.decision(
                task_id=state.task_id,
                decision_type="SHOULD_CONTINUE",
                decision="continue",
                reason=f"继续执行工具: {state.planned_tasks[0]}"
            )
            return "continue"

        logger.info(f"[{state.task_id}] 📋 所有任务已完成,进入分析阶段")
        log_helper.edge_traversal(
            task_id=state.task_id,
            from_node="result_verification",
            to_node="vulnerability_analysis",
            condition="all_tasks_completed"
        )
        log_helper.decision(
            task_id=state.task_id,
            decision_type="SHOULD_CONTINUE",
            decision="analyze",
            reason="所有任务已完成"
        )
        return "analyze"

    def _build_info_collection_graph(self) -> StateGraph:
        """
        构建信息收集子图
        
        负责环境感知、任务规划和信息收集工具执行阶段。
        只执行 backend/plugins 目录下的信息收集工具。
        
        Returns:
            StateGraph: 信息收集子图
        """
        log_helper.node_entry("_build_info_collection_graph", "SUBGRAPH_BUILD", {"total_nodes": 4})

        from .nodes import (
            EnvironmentAwarenessNode,
            InfoTaskPlanningNode,
            InfoToolExecutionNode,
            InfoResultVerificationNode
        )

        workflow = StateGraph(AgentState)

        env_node = EnvironmentAwarenessNode()
        planning_node = InfoTaskPlanningNode()
        execution_node = InfoToolExecutionNode()
        verification_node = InfoResultVerificationNode()

        workflow.add_node("environment_awareness", env_node)
        workflow.add_node("info_task_planning", planning_node)
        workflow.add_node("info_tool_execution", execution_node)
        workflow.add_node("info_result_verification", verification_node)

        workflow.set_entry_point("environment_awareness")
        workflow.add_edge("environment_awareness", "info_task_planning")
        workflow.add_edge("info_task_planning", "info_tool_execution")
        workflow.add_edge("info_tool_execution", "info_result_verification")
        workflow.add_conditional_edges(
            "info_result_verification",
            self._should_continue_info_collection,
            {
                "continue": "info_tool_execution",
                "complete": END
            }
        )

        logger.info("📊 信息收集子图构建完成 (4节点)")
        log_helper.node_exit("_build_info_collection_graph", "SUBGRAPH_BUILD", "success", {"nodes_count": 4, "edges_count": 4})
        return workflow

    def _should_continue_info_collection(self, state: AgentState) -> str:
        """
        决定是否继续信息收集
        
        Args:
            state: Agent状态
            
        Returns:
            str: "continue" 或 "complete"
        """
        if state.planned_tasks and len(state.completed_tasks) < 50:
            return "continue"
        return "complete"

    def _build_vuln_scan_graph(self) -> StateGraph:
        """
        构建漏洞扫描子图
        
        负责执行 backend/vulnerability_scan_plugins 目录下的漏洞扫描工具。
        
        Returns:
            StateGraph: 漏洞扫描子图
        """
        log_helper.node_entry("_build_vuln_scan_graph", "SUBGRAPH_BUILD", {"total_nodes": 3})

        from .nodes import (
            VulnScanPlanningNode,
            VulnToolExecutionNode,
            VulnResultAggregationNode
        )

        workflow = StateGraph(AgentState)

        planning_node = VulnScanPlanningNode()
        execution_node = VulnToolExecutionNode()
        aggregation_node = VulnResultAggregationNode()

        workflow.add_node("vuln_scan_planning", planning_node)
        workflow.add_node("vuln_tool_execution", execution_node)
        workflow.add_node("vuln_result_aggregation", aggregation_node)

        workflow.set_entry_point("vuln_scan_planning")
        workflow.add_edge("vuln_scan_planning", "vuln_tool_execution")
        workflow.add_conditional_edges(
            "vuln_tool_execution",
            self._should_continue_vuln_scan,
            {
                "continue": "vuln_tool_execution",
                "aggregate": "vuln_result_aggregation"
            }
        )
        workflow.add_edge("vuln_result_aggregation", END)

        logger.info("📊 漏洞扫描子图构建完成 (3节点)")
        log_helper.node_exit("_build_vuln_scan_graph", "SUBGRAPH_BUILD", "success", {"nodes_count": 3, "edges_count": 3})
        return workflow

    def _should_continue_vuln_scan(self, state: AgentState) -> str:
        """
        决定是否继续漏洞扫描
        
        Args:
            state: Agent状态
            
        Returns:
            str: "continue" 或 "aggregate"
        """
        if state.planned_tasks and len(state.completed_tasks) < 50:
            return "continue"
        return "aggregate"

    def _build_poc_verification_graph(self) -> StateGraph:
        """
        构建POC验证子图
        
        负责执行POC验证，确认漏洞可利用性。
        
        Returns:
            StateGraph: POC验证子图
        """
        log_helper.node_entry("_build_poc_verification_graph", "SUBGRAPH_BUILD", {"total_nodes": 3})

        from .nodes import (
            PocTaskPlanningNode,
            PocExecutionNode,
            PocResultVerificationNode
        )

        workflow = StateGraph(AgentState)

        planning_node = PocTaskPlanningNode()
        execution_node = PocExecutionNode()
        verification_node = PocResultVerificationNode()

        workflow.add_node("poc_task_planning", planning_node)
        workflow.add_node("poc_execution", execution_node)
        workflow.add_node("poc_result_verification", verification_node)

        workflow.set_entry_point("poc_task_planning")
        workflow.add_edge("poc_task_planning", "poc_execution")
        workflow.add_edge("poc_execution", "poc_result_verification")
        workflow.add_conditional_edges(
            "poc_result_verification",
            self._should_continue_poc_verification,
            {
                "continue": "poc_execution",
                "complete": END
            }
        )

        logger.info("📊 POC验证子图构建完成 (3节点)")
        log_helper.node_exit("_build_poc_verification_graph", "SUBGRAPH_BUILD", "success", {"nodes_count": 3, "edges_count": 4})
        return workflow

    def _should_continue_poc_verification(self, state: AgentState) -> str:
        """
        决定是否继续POC验证
        
        Args:
            state: Agent状态
            
        Returns:
            str: "continue" 或 "complete"
        """
        if state.planned_tasks and len(state.completed_tasks) < 50:
            return "continue"
        return "complete"

    def _build_result_analysis_graph(self) -> StateGraph:
        """
        构建结果分析子图
        
        负责漏洞分析和报告生成阶段。
        
        Returns:
            StateGraph: 结果分析子图
        """
        log_helper.node_entry("_build_result_analysis_graph", "SUBGRAPH_BUILD", {"total_nodes": 2})

        workflow = StateGraph(AgentState)

        workflow.add_node("vulnerability_analysis", self.analysis_node)
        workflow.add_node("report_generation", self.report_node)

        workflow.set_entry_point("vulnerability_analysis")
        workflow.add_edge("vulnerability_analysis", "report_generation")
        workflow.add_edge("report_generation", END)

        logger.info("📊 结果分析子图构建完成")
        log_helper.node_exit("_build_result_analysis_graph", "SUBGRAPH_BUILD", "success", {"nodes_count": 2, "edges_count": 2})
        return workflow

    def get_info_collection_graph(self):
        """
        获取信息收集子图（可编译和独立执行）
        
        Returns:
            StateGraph: 信息收集子图
        """
        return self._build_info_collection_graph()

    def get_vulnerability_scan_graph(self):
        """
        获取漏洞扫描子图（可编译和独立执行）
        
        Returns:
            StateGraph: 漏洞扫描子图
        """
        return self._build_vulnerability_scan_graph()

    def get_result_analysis_graph(self):
        """
        获取结果分析子图（可编译和独立执行）
        
        Returns:
            StateGraph: 结果分析子图
        """
        return self._build_result_analysis_graph()

    def compile_info_collection(self):
        """
        编译信息收集子图
        
        Returns:
            编译后的信息收集子图
        """
        return self.get_info_collection_graph().compile()

    def compile_vulnerability_scan(self):
        """
        编译漏洞扫描子图
        
        Returns:
            编译后的漏洞扫描子图
        """
        return self.get_vulnerability_scan_graph().compile()

    def compile_result_analysis(self):
        """
        编译结果分析子图
        
        Returns:
            编译后的结果分析子图
        """
        return self.get_result_analysis_graph().compile()

    async def invoke_info_collection(self, initial_state: AgentState) -> AgentState:
        """
        执行信息收集子图
        
        Args:
            initial_state: 初始状态
            
        Returns:
            AgentState: 执行后的状态
        """
        logger.info(f"🚀 开始执行信息收集子图: {initial_state.task_id}")
        log_helper.node_entry("invoke_info_collection", initial_state.task_id, {"target": initial_state.target})
        
        try:
            compiled_graph = self.compile_info_collection()
            config = {"recursion_limit": 100}
            final_state = await compiled_graph.ainvoke(initial_state, config=config)
            
            if isinstance(final_state, dict):
                final_state = AgentState.from_dict(final_state)
            
            logger.info(f"✅ 信息收集子图执行完成: {final_state.task_id}")
            log_helper.node_exit("invoke_info_collection", initial_state.task_id, "success", {
                "planned_tasks": final_state.planned_tasks
            })
            
            return final_state
        except Exception as e:
            logger.error(f"❌ 信息收集子图执行失败: {initial_state.task_id}, 错误: {str(e)}")
            log_helper.error(initial_state.task_id, "invoke_info_collection", e, {"target": initial_state.target})
            raise

    async def invoke_vulnerability_scan(self, initial_state: AgentState) -> AgentState:
        """
        执行漏洞扫描子图
        
        Args:
            initial_state: 初始状态（通常是信息收集子图的输出）
            
        Returns:
            AgentState: 执行后的状态
        """
        logger.info(f"🚀 开始执行漏洞扫描子图: {initial_state.task_id}")
        log_helper.node_entry("invoke_vulnerability_scan", initial_state.task_id, {"target": initial_state.target})
        
        try:
            compiled_graph = self.compile_vulnerability_scan()
            config = {"recursion_limit": 200}
            final_state = await compiled_graph.ainvoke(initial_state, config=config)
            
            if isinstance(final_state, dict):
                final_state = AgentState.from_dict(final_state)
            
            logger.info(f"✅ 漏洞扫描子图执行完成: {final_state.task_id}")
            log_helper.node_exit("invoke_vulnerability_scan", initial_state.task_id, "success", {
                "completed_tasks": len(final_state.completed_tasks),
                "vulnerabilities_found": len(final_state.vulnerabilities)
            })
            
            return final_state
        except Exception as e:
            logger.error(f"❌ 漏洞扫描子图执行失败: {initial_state.task_id}, 错误: {str(e)}")
            log_helper.error(initial_state.task_id, "invoke_vulnerability_scan", e, {"target": initial_state.target})
            raise

    async def invoke_vuln_scan(self, initial_state: AgentState) -> AgentState:
        """
        执行漏洞扫描子图（使用 vulnerability_scan_plugins 工具）
        
        Args:
            initial_state: 初始状态（通常是信息收集子图的输出）
            
        Returns:
            AgentState: 执行后的状态
        """
        logger.info(f"🚀 开始执行漏洞扫描子图: {initial_state.task_id}")
        log_helper.node_entry("invoke_vuln_scan", initial_state.task_id, {"target": initial_state.target})
        
        try:
            compiled_graph = self._build_vuln_scan_graph().compile()
            config = {"recursion_limit": 100}
            final_state = await compiled_graph.ainvoke(initial_state, config=config)
            
            if isinstance(final_state, dict):
                final_state = AgentState.from_dict(final_state)
            
            logger.info(f"✅ 漏洞扫描子图执行完成: {final_state.task_id}")
            log_helper.node_exit("invoke_vuln_scan", initial_state.task_id, "success", {
                "vulnerabilities_found": len(final_state.vulnerabilities)
            })
            
            return final_state
        except Exception as e:
            logger.error(f"❌ 漏洞扫描子图执行失败: {initial_state.task_id}, 错误: {str(e)}")
            log_helper.error(initial_state.task_id, "invoke_vuln_scan", e, {"target": initial_state.target})
            raise

    async def invoke_poc_verification(self, initial_state: AgentState) -> AgentState:
        """
        执行POC验证子图
        
        Args:
            initial_state: 初始状态（通常是漏洞扫描子图的输出）
            
        Returns:
            AgentState: 执行后的状态
        """
        logger.info(f"🚀 开始执行POC验证子图: {initial_state.task_id}")
        log_helper.node_entry("invoke_poc_verification", initial_state.task_id, {"target": initial_state.target})
        
        try:
            compiled_graph = self._build_poc_verification_graph().compile()
            config = {"recursion_limit": 200}
            final_state = await compiled_graph.ainvoke(initial_state, config=config)
            
            if isinstance(final_state, dict):
                final_state = AgentState.from_dict(final_state)
            
            logger.info(f"✅ POC验证子图执行完成: {final_state.task_id}")
            log_helper.node_exit("invoke_poc_verification", initial_state.task_id, "success", {
                "completed_tasks": len(final_state.completed_tasks)
            })
            
            return final_state
        except Exception as e:
            logger.error(f"❌ POC验证子图执行失败: {initial_state.task_id}, 错误: {str(e)}")
            log_helper.error(initial_state.task_id, "invoke_poc_verification", e, {"target": initial_state.target})
            raise

    async def invoke_result_analysis(self, initial_state: AgentState) -> AgentState:
        """
        执行结果分析子图
        
        Args:
            initial_state: 初始状态（通常是漏洞扫描子图的输出）
            
        Returns:
            AgentState: 执行后的状态
        """
        logger.info(f"🚀 开始执行结果分析子图: {initial_state.task_id}")
        log_helper.node_entry("invoke_result_analysis", initial_state.task_id, {"target": initial_state.target})
        
        try:
            compiled_graph = self.compile_result_analysis()
            config = {"recursion_limit": 100}
            final_state = await compiled_graph.ainvoke(initial_state, config=config)
            
            if isinstance(final_state, dict):
                final_state = AgentState.from_dict(final_state)
            
            logger.info(f"✅ 结果分析子图执行完成: {final_state.task_id}")
            log_helper.node_exit("invoke_result_analysis", initial_state.task_id, "success", {
                "vulnerabilities": len(final_state.vulnerabilities)
            })
            
            return final_state
        except Exception as e:
            logger.error(f"❌ 结果分析子图执行失败: {initial_state.task_id}, 错误: {str(e)}")
            log_helper.error(initial_state.task_id, "invoke_result_analysis", e, {"target": initial_state.target})
            raise

    async def invoke_subgraphs_sequential(self, initial_state: AgentState) -> AgentState:
        """
        依次执行所有子图（验证子图之间的数据传递）
        
        执行顺序：
        1. 信息收集子图 (invoke_info_collection)
        2. 漏洞扫描子图 (invoke_vuln_scan)
        3. POC验证子图 (invoke_poc_verification)
        4. 结果分析子图 (invoke_result_analysis)
        
        Args:
            initial_state: 初始状态
            
        Returns:
            AgentState: 最终状态
        """
        logger.info(f"🚀 开始依次执行所有子图: {initial_state.task_id}")
        log_helper.node_entry("invoke_subgraphs_sequential", initial_state.task_id, {"target": initial_state.target})
        
        try:
            state1 = await self.invoke_info_collection(initial_state)
            logger.info(f"✅ 信息收集子图完成: {len(getattr(state1, 'completed_tasks', []))} 个任务完成")
            
            state2 = await self.invoke_vuln_scan(state1)
            logger.info(f"✅ 漏洞扫描子图完成: {len(getattr(state2, 'vulnerabilities', []))} 个漏洞发现")
            
            state3 = await self.invoke_poc_verification(state2)
            logger.info(f"✅ POC验证子图完成")
            
            final_state = await self.invoke_result_analysis(state3)
            
            logger.info(f"✅ 所有子图依次执行完成: {getattr(final_state, 'task_id', initial_state.task_id)}")
            log_helper.node_exit("invoke_subgraphs_sequential", initial_state.task_id, "success", {
                "completed_tasks": len(getattr(final_state, 'completed_tasks', [])),
                "vulnerabilities_found": len(getattr(final_state, 'vulnerabilities', []))
            })
            
            return final_state
        except Exception as e:
            logger.error(f"❌ 子图依次执行失败: {initial_state.task_id}, 错误: {str(e)}")
            log_helper.error(initial_state.task_id, "invoke_subgraphs_sequential", e, {"target": initial_state.target})
            raise

    def compile(self):
        """
        编译完整图
        
        Returns:
            编译后的可执行图
        """
        return self.graph.compile()
    
    async def invoke(self, initial_state: AgentState) -> AgentState:
        """
        执行Agent工作流(增强版)
        
        根据配置选择执行方式:
        - 子图顺序执行模式 (默认): 更灵活、更易调试、递归限制更高
        - 统一图执行模式: 性能更好、单次编译
        
        Args:
            initial_state: 初始状态
            
        Returns:
            AgentState: 最终状态
        """
        logger.info(f"🚀 开始执行Agent工作流: {initial_state.task_id}, 执行模式: {'子图顺序执行' if self.use_subgraph_execution else '统一图执行'}")
        log_helper.node_entry("invoke", initial_state.task_id, {
            "target": initial_state.target,
            "execution_mode": "subgraph_sequential" if self.use_subgraph_execution else "unified_graph"
        })
        
        try:
            if self.use_subgraph_execution:
                # 使用子图顺序执行模式（默认）
                final_state = await self.invoke_subgraphs_sequential(initial_state)
            else:
                # 使用统一图执行模式
                compiled_graph = self.compile()
                config = {"recursion_limit": 25}
                final_state = await compiled_graph.ainvoke(initial_state, config=config)
            
            # 处理返回的状态对象，可能是字典形式
            task_id = getattr(final_state, 'task_id', initial_state.task_id)
            completed_tasks = getattr(final_state, 'completed_tasks', [])
            vulnerabilities = getattr(final_state, 'vulnerabilities', [])
            errors = getattr(final_state, 'errors', [])
            
            logger.info(f"✅ Agent工作流执行完成: {task_id}, 执行模式: {'子图顺序执行' if self.use_subgraph_execution else '统一图执行'}")
            log_helper.node_exit("invoke", initial_state.task_id, "success", {
                "completed_tasks": len(completed_tasks),
                "vulnerabilities_found": len(vulnerabilities),
                "errors_count": len(errors),
                "execution_mode": "subgraph_sequential" if self.use_subgraph_execution else "unified_graph"
            })
            
            return final_state
        except Exception as e:
            logger.error(f"❌ Agent工作流执行失败: {initial_state.task_id}, 错误: {str(e)}")
            log_helper.error(initial_state.task_id, "invoke", e, {"target": initial_state.target})
            raise
    

def create_agent_graph() -> ScanAgentGraph:
    """
    创建Agent图实例
    
    Returns:
        ScanAgentGraph: Agent图实例
    """
    return ScanAgentGraph()


def initialize_tools():
    """
    初始化所有工具
    
    注册所有插件和POC到工具注册表。
    """
    from ..tools.registry import registry
    from ..tools.adapters import PluginAdapter, POCAdapter
    
    logger.info("🔧 开始初始化工具...")
    
    # 注册插件 - 注意：传递函数引用而不是调用结果
    registry.register(
        name="baseinfo",
        func=PluginAdapter.adapt_baseinfo,
        description="基础信息收集(域名、IP、服务器、OS等)",
        category="plugin",
        timeout=60,
        priority=3
    )
    
    registry.register(
        name="portscan",
        func=PluginAdapter.adapt_portscan,
        description="TCP端口扫描,识别开放端口和服务",
        category="plugin",
        timeout=120,
        priority=5
    )
    
    registry.register(
        name="waf_detect",
        func=PluginAdapter.adapt_waf_detect,
        description="WAF(Web应用防火墙)检测",
        category="plugin",
        timeout=60,
        priority=4
    )
    
    registry.register(
        name="cdn_detect",
        func=PluginAdapter.adapt_cdn_detect,
        description="CDN(内容分发网络)检测",
        category="plugin",
        timeout=30,
        priority=4
    )
    
    registry.register(
        name="cms_identify",
        func=PluginAdapter.adapt_cms_identify,
        description="CMS(内容管理系统)识别",
        category="plugin",
        timeout=15,
        priority=4
    )
    
    registry.register(
        name="infoleak_scan",
        func=PluginAdapter.adapt_infoleak_scan,
        description="信息泄露扫描",
        category="plugin",
        timeout=30,
        priority=3
    )
    
    registry.register(
        name="subdomain_scan",
        func=PluginAdapter.adapt_subdomain_scan,
        description="子域名枚举",
        category="plugin",
        timeout=60,
        priority=3
    )
    
    registry.register(
        name="webside_scan",
        func=PluginAdapter.adapt_webside_scan,
        description="站点信息收集",
        category="plugin",
        timeout=30,
        priority=3
    )
    
    registry.register(
        name="webweight_scan",
        func=PluginAdapter.adapt_webweight_scan,
        description="网站权重查询",
        category="plugin",
        timeout=30,
        priority=2
    )
    
    registry.register(
        name="iplocating",
        func=PluginAdapter.adapt_iplocating,
        description="IP地址定位",
        category="plugin",
        timeout=30,
        priority=3
    )
    
    registry.register(
        name="loginfo",
        func=PluginAdapter.adapt_loginfo,
        description="日志信息分析",
        category="plugin",
        timeout=30,
        priority=2
    )
    
    registry.register(
        name="randheader",
        func=PluginAdapter.adapt_randheader,
        description="随机HTTP请求头生成",
        category="plugin",
        timeout=30,
        priority=2
    )
    
    registry.register(
        name="dirscan",
        func=PluginAdapter.adapt_dirscan,
        description="目录扫描(敏感目录和文件爆破)",
        category="plugin",
        timeout=180,
        priority=5
    )
    
    logger.info(f"✅ 工具初始化完成,共注册 {len(registry.tools)} 个工具")
    
    logger.info("🔧 开始注册POC工具...")
    pocs = POCAdapter.get_all_pocs()
    for poc_name, poc_module in pocs.items():
        def create_poc_func(poc_name=poc_name, poc_module=poc_module):
            async def poc_func(target: str, timeout: Optional[float] = None, progress_callback=None, **kwargs):
                return await POCAdapter.adapt_poc(
                    target=target,
                    poc_name=poc_name,
                    poc_module=poc_module,
                    timeout=timeout,
                    progress_callback=progress_callback
                )
            return poc_func
        
        registry.register(
            name=poc_name,
            func=create_poc_func(),
            description=f"POC漏洞检测: {poc_name}",
            category="poc",
            timeout=POCAdapter.DEFAULT_POC_TIMEOUT,
            priority=6,
            tags=["poc", "vulnerability", "exploit"],
            enabled=True
        )
    
    logger.info(f"✅ POC工具初始化完成,共注册 {len(pocs)} 个POC工具")
    
    registry.register(
        name="sqli_scan",
        func=PluginAdapter.adapt_sqli_scan,
        description="SQL注入漏洞扫描(检测基于错误、时间盲注、布尔盲注等SQL注入)",
        category="vuln_scan",
        timeout=120,
        priority=7,
        tags=["vulnerability", "sqli", "injection", "security"]
    )
    
    registry.register(
        name="xss_scan",
        func=PluginAdapter.adapt_xss_scan,
        description="XSS漏洞扫描(检测反射型、存储型、DOM型XSS)",
        category="vuln_scan",
        timeout=120,
        priority=7,
        tags=["vulnerability", "xss", "security"]
    )
    
    registry.register(
        name="csrf_scan",
        func=PluginAdapter.adapt_csrf_scan,
        description="CSRF漏洞扫描(检测CSRF令牌缺失、Referer验证缺失)",
        category="vuln_scan",
        timeout=60,
        priority=6,
        tags=["vulnerability", "csrf", "security"]
    )
    
    registry.register(
        name="vuln_infoleak_scan",
        func=PluginAdapter.adapt_vuln_infoleak_scan,
        description="敏感信息泄露扫描(检测敏感文件、敏感信息模式)",
        category="vuln_scan",
        timeout=60,
        priority=5,
        tags=["vulnerability", "infoleak", "security"]
    )
    
    registry.register(
        name="crawler",
        func=PluginAdapter.adapt_crawler,
        description="Web爬虫(自动发现页面、链接、表单和参数)",
        category="plugin",
        timeout=300,
        priority=1,
        tags=["crawler", "spider", "discovery"]
    )
    
    registry.register(
        name="fileupload_scan",
        func=PluginAdapter.adapt_fileupload_scan,
        description="文件上传漏洞扫描(检测上传点、绕过技术)",
        category="vuln_scan",
        timeout=120,
        priority=8,
        tags=["vulnerability", "fileupload", "rce", "security"]
    )
    
    registry.register(
        name="cmdi_scan",
        func=PluginAdapter.adapt_cmdi_scan,
        description="命令注入漏洞扫描(检测OS命令执行漏洞)",
        category="vuln_scan",
        timeout=180,
        priority=9,
        tags=["vulnerability", "cmdi", "rce", "security"]
    )
    
    registry.register(
        name="weakpass_scan",
        func=PluginAdapter.adapt_weakpass_scan,
        description="弱口令扫描(检测常见用户名密码组合)",
        category="vuln_scan",
        timeout=300,
        priority=7,
        tags=["vulnerability", "weakpass", "brute-force", "security"]
    )
    
    registry.register(
        name="lfi_scan",
        func=PluginAdapter.adapt_lfi_scan,
        description="文件包含漏洞扫描(检测LFI/RFI/目录遍历)",
        category="vuln_scan",
        timeout=180,
        priority=8,
        tags=["vulnerability", "lfi", "rfi", "path-traversal", "security"]
    )
    
    registry.register(
        name="ssrf_scan",
        func=PluginAdapter.adapt_ssrf_scan,
        description="SSRF漏洞扫描(检测服务端请求伪造)",
        category="vuln_scan",
        timeout=180,
        priority=8,
        tags=["vulnerability", "ssrf", "security"]
    )
    
    logger.info(f"✅ 漏洞扫描工具初始化完成,共注册 10 个漏洞扫描工具")
