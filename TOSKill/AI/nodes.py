"""
LangGraph 节点定义

仅包含具体节点实现类，基类和辅助类已迁移到 base.py 和 helpers.py。
"""
import logging
import json
from typing import Dict, Any, List

from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser

from .state import AgentState
from .base import (
    BasePlanningNode, BaseToolExecutionNode, BaseResultVerificationNode,
    NodeStage
)
from .helpers import TargetContextUpdater, ProgressCalculator
from .tools.registry import registry
from .agent_config import agent_config

logger = logging.getLogger(__name__)


INFO_COLLECTION_TOOLS = [
    "baseinfo", "portscan", "waf_detect", "cdn_detect", "cms_identify",
    "subdomain_scan", "webside_scan", "webweight_scan", "iplocating",
    "infoleak_scan", "dirscan", "loginfo", "randheader", "crawler"
]

VULN_SCAN_TOOLS = [
    "sqli_scan", "xss_scan", "csrf_scan", "vuln_infoleak_scan",
    "fileupload_scan", "cmdi_scan", "weakpass_scan", "lfi_scan", "ssrf_scan"
]


class VulnerabilityAnalysisNode:
    """漏洞分析节点"""
    
    def __init__(self):
        from ..analyzers.vuln_analyzer import VulnerabilityAnalyzer
        self.analyzer = VulnerabilityAnalyzer()
        logger.info("🔍 漏洞分析节点初始化")
    
    async def __call__(self, state: AgentState) -> AgentState:
        logger.info(f"[{state.task_id}] 🔍 开始漏洞分析 | 漏洞数: {len(state.vulnerabilities)}")
        
        if not state.vulnerabilities:
            logger.info(f"[{state.task_id}] ✅ 未发现漏洞")
            state.add_execution_step("vulnerability_analysis", {"total": 0}, "success", step_type="analysis")
            return state
        
        unique_vulns = self.analyzer.deduplicate(state.vulnerabilities)
        sorted_vulns = self.analyzer.sort_by_severity(unique_vulns)
        state.vulnerabilities = sorted_vulns
        
        logger.info(f"[{state.task_id}] ✅ 漏洞分析完成 | 总数: {len(sorted_vulns)}")
        state.add_execution_step("vulnerability_analysis", {"total": len(sorted_vulns)}, "success", step_type="analysis")
        return state


class ReportGenerationNode:
    """报告生成节点"""
    
    def __init__(self):
        from ..analyzers.enhanced_report_gen import ReportGenerator
        self.report_gen = ReportGenerator()
        logger.info("📄 报告生成节点初始化")
    
    async def __call__(self, state: AgentState) -> AgentState:
        logger.info(f"[{state.task_id}] 📄 开始生成扫描报告")
        
        reports = {
            "final_report": self.report_gen.generate_report(state),
            "execution_trace_report": self.report_gen.generate_execution_trace_report(state),
            "html_execution_trace": self.report_gen.generate_html_execution_trace(state)
        }
        
        state.tool_results.update(reports)
        state.scan_summary = {
            "target": state.target,
            "vulnerabilities_count": len(state.vulnerabilities),
            "completed_tasks": len(state.completed_tasks)
        }
        state.mark_complete()
        
        logger.info(f"[{state.task_id}] ✅ 报告生成完成")
        state.add_execution_step("report_generation", reports, "success", step_type="report_generation")
        return state


class EnvironmentAwarenessNode:
    """环境感知节点"""
    
    def __init__(self):
        from ..code_execution.environment import EnvironmentAwareness
        self.env_awareness = EnvironmentAwareness()
        logger.info("🔍 环境感知节点初始化完成")
    
    async def __call__(self, state: AgentState) -> AgentState:
        logger.info(f"[{state.task_id}] 🔍 开始环境感知")
        
        env_report = self.env_awareness.get_environment_report()
        state.update_context("environment_info", env_report)
        state.update_context("os_system", env_report["os_info"]["system"])
        
        logger.info(f"[{state.task_id}] ✅ 环境感知完成")
        state.add_execution_step("environment_awareness", env_report, "success")
        return state


class InfoTaskPlanningNode(BasePlanningNode):
    """信息收集任务规划节点"""
    
    def __init__(self):
        super().__init__(stage=NodeStage.INFO_COLLECTION)
    
    def _get_valid_tools(self) -> List[str]:
        return INFO_COLLECTION_TOOLS
    
    async def _plan_tasks(self, state: AgentState) -> List[str]:
        if self.use_llm:
            return await self._llm_planning(state, tools_category="info")
        return ["baseinfo", "portscan", "cms_identify", "waf_detect", "cdn_detect"]


class InfoToolExecutionNode(BaseToolExecutionNode):
    """信息收集工具执行节点"""
    
    def __init__(self):
        super().__init__(stage=NodeStage.INFO_COLLECTION)
    
    async def _execute_tool(self, state: AgentState, tool_name: str):
        tool_wrapper = registry.get_tool(tool_name)
        if tool_wrapper is None:
            raise ValueError(f"工具未注册: {tool_name}")
        return await tool_wrapper.execute(state.target)
    
    async def _handle_success(self, state: AgentState, tool_name: str, result, step_number: int):
        state.tool_results[tool_name] = result.data
        if result.data:
            TargetContextUpdater.update_context(state, tool_name, result.data)
        self._mark_task_completed(state, tool_name)
        logger.info(f"[{state.task_id}] ✅ 工具执行成功: {tool_name}")
        state.update_execution_step(step_number, result=result.data, status="success", state_transitions=["completed"])
    
    async def _handle_failure(self, state: AgentState, tool_name: str, result, step_number: int):
        logger.warning(f"[{state.task_id}] ⚠️ 工具执行失败: {tool_name}")
        state.add_error(f"工具执行失败: {tool_name}")
        state.update_execution_step(step_number, result={"error": result.error}, status="failed", state_transitions=["failed"])
        self._mark_task_completed(state, tool_name)


class InfoResultVerificationNode(BaseResultVerificationNode):
    """信息收集结果验证节点"""
    
    def __init__(self):
        super().__init__(stage=NodeStage.INFO_COLLECTION)
    
    async def _verify_results(self, state: AgentState) -> None:
        pass


class VulnScanPlanningNode(BasePlanningNode):
    """漏洞扫描任务规划节点"""
    
    def __init__(self):
        super().__init__(stage=NodeStage.VULN_SCAN)
    
    def _get_valid_tools(self) -> List[str]:
        return VULN_SCAN_TOOLS
    
    async def _plan_tasks(self, state: AgentState) -> List[str]:
        if self.use_llm:
            return await self._llm_planning(state, tools_category="vuln")
        return ["sqli_scan", "xss_scan", "csrf_scan", "vuln_infoleak_scan"]


class VulnToolExecutionNode(BaseToolExecutionNode):
    """漏洞扫描工具执行节点"""
    
    def __init__(self):
        super().__init__(stage=NodeStage.VULN_SCAN)
    
    async def _execute_tool(self, state: AgentState, tool_name: str):
        if tool_name not in registry.tools:
            raise ValueError(f"工具未注册: {tool_name}")
        tool_wrapper = registry.tools[tool_name]
        return await tool_wrapper.execute(state.target)
    
    async def _handle_success(self, state: AgentState, tool_name: str, result, step_number: int):
        state.tool_results[tool_name] = result.data
        
        if isinstance(result.data, dict):
            for key in ["vulnerabilities", "fileupload_results", "cmdi_results", "weakpass_results", "lfi_results", "ssrf_results"]:
                if key in result.data and result.data[key]:
                    vulns = result.data[key]
                    if isinstance(vulns, list):
                        for vuln in vulns:
                            state.add_vulnerability(vuln)
                    elif isinstance(vulns, dict):
                        state.add_vulnerability(vulns)
        
        self._mark_task_completed(state, tool_name)
        logger.info(f"[{state.task_id}] ✅ 漏洞扫描工具执行成功: {tool_name}")
        state.update_execution_step(step_number, result=result.data, status="success", state_transitions=["completed"])
    
    async def _handle_failure(self, state: AgentState, tool_name: str, result, step_number: int):
        logger.warning(f"[{state.task_id}] ⚠️ 漏洞扫描工具执行失败: {tool_name}")
        state.add_error(f"漏洞扫描工具执行失败: {tool_name}")
        state.update_execution_step(step_number, result={"error": result.error if hasattr(result, 'error') else "未知错误"}, status="failed", state_transitions=["failed"])
        self._mark_task_completed(state, tool_name)


class VulnResultAggregationNode:
    """漏洞扫描结果汇总节点"""
    
    def __init__(self):
        logger.info("📊 漏洞扫描结果汇总节点初始化")
    
    async def __call__(self, state: AgentState) -> AgentState:
        logger.info(f"[{state.task_id}] 📊 汇总漏洞扫描结果")
        
        total_vulns = len(state.vulnerabilities)
        state.vuln_scan_results = {
            "total_vulnerabilities": total_vulns,
            "vulnerabilities": state.vulnerabilities,
            "tools_used": [t for t in state.completed_tasks if t in VULN_SCAN_TOOLS]
        }
        state.update_stage_status("tool_execution", "completed", "完成", 100, f"发现 {total_vulns} 个漏洞")
        
        logger.info(f"[{state.task_id}] ✅ 漏洞扫描结果汇总完成: 发现 {total_vulns} 个漏洞")
        return state


class AIDecisionNode:
    """AI 决策节点"""
    
    def __init__(self):
        self._init_llm()
        logger.info("🧠 AI决策节点初始化完成")
    
    def _init_llm(self) -> None:
        self.llm = None
        self.use_llm = False
        if agent_config.ENABLE_LLM_PLANNING:
            self.llm = ChatOpenAI(
                model=agent_config.MODEL_ID,
                temperature=agent_config.TEMPERATURE,
                api_key=agent_config.OPENAI_API_KEY,
                base_url=agent_config.OPENAI_BASE_URL
            )
            self.use_llm = True
    
    async def __call__(self, state: AgentState) -> AgentState:
        logger.info(f"[{state.task_id}] 🧠 开始AI决策")
        
        if self.use_llm:
            decision = await self._llm_decision(state)
        else:
            decision = self._rule_based_decision(state)
        
        state.target_context["next_action"] = decision["action"]
        
        if decision["action"] == "tool":
            state.planned_tasks = decision.get("tasks", [])
            state.current_task = state.planned_tasks[0] if state.planned_tasks else None
            logger.info(f"[{state.task_id}] 🧠 AI决策: 执行工具 | 任务: {state.planned_tasks}")
        else:
            logger.info(f"[{state.task_id}] 🧠 AI决策: 结束扫描")
        
        state.add_execution_step("ai_decision", decision, "success", step_type="decision")
        return state
    
    async def _llm_decision(self, state: AgentState) -> Dict[str, Any]:
        available_tools = registry.list_tools()
        tools_desc = "\n".join([f"- {t['name']}: {t['description']}" for t in available_tools])
        context_info = f"\n目标上下文: {json.dumps(state.target_context, ensure_ascii=False)}" if state.target_context else ""
        
        system_prompt = """你是Web安全扫描专家，负责分析当前扫描状态并决定下一步行动。
## 可用工具
{tools}
## 输出格式
{{"action": "tool" 或 "end", "tasks": ["task1"], "reason": "决策理由"}}"""
        
        user_prompt = f"目标: {state.target}{context_info}\n已完成任务: {state.completed_tasks}\n已发现漏洞: {len(state.vulnerabilities)} 个"
        
        prompt = ChatPromptTemplate.from_messages([("system", system_prompt), ("human", user_prompt)])
        chain = prompt | self.llm | JsonOutputParser()
        result = await chain.ainvoke({"tools": tools_desc, "target": state.target})
        
        logger.info(f"[{state.task_id}] 🧠 LLM决策结果: {result}")
        return result
    
    def _rule_based_decision(self, state: AgentState) -> Dict[str, Any]:
        completed_info = set(state.completed_tasks) & set(INFO_COLLECTION_TOOLS)
        completed_vuln = set(state.completed_tasks) & set(VULN_SCAN_TOOLS)
        
        if len(completed_info) < 3:
            remaining = [t for t in INFO_COLLECTION_TOOLS if t not in state.completed_tasks]
            return {"action": "tool", "tasks": remaining[:3], "reason": "继续信息收集"}
        
        if len(completed_vuln) < 3:
            remaining = [t for t in VULN_SCAN_TOOLS if t not in state.completed_tasks]
            return {"action": "tool", "tasks": remaining[:3], "reason": "继续漏洞扫描"}
        
        return {"action": "end", "reason": "已完成基本扫描任务"}


class ToolExecutionNode(BaseToolExecutionNode):
    """统一的工具执行节点"""
    
    def __init__(self):
        super().__init__(stage=NodeStage.INFO_COLLECTION)
    
    async def _execute_tool(self, state: AgentState, tool_name: str):
        tool_wrapper = registry.get_tool(tool_name)
        if tool_wrapper is None:
            raise ValueError(f"工具未注册: {tool_name}")
        return await tool_wrapper.execute(state.target)
    
    async def _handle_success(self, state: AgentState, tool_name: str, result, step_number: int):
        state.tool_results[tool_name] = result.data
        
        if result.data:
            TargetContextUpdater.update_context(state, tool_name, result.data)
            
            if tool_name in VULN_SCAN_TOOLS and isinstance(result.data, dict):
                for key in ["vulnerabilities", "fileupload_results", "cmdi_results", "weakpass_results", "lfi_results", "ssrf_results"]:
                    if key in result.data and result.data[key]:
                        vulns = result.data[key]
                        if isinstance(vulns, list):
                            for vuln in vulns:
                                state.add_vulnerability(vuln)
                        elif isinstance(vulns, dict):
                            state.add_vulnerability(vulns)
        
        self._mark_task_completed(state, tool_name)
        logger.info(f"[{state.task_id}] ✅ 工具执行成功: {tool_name}")
        state.update_execution_step(step_number, result=result.data, status="success", state_transitions=["completed"])
    
    async def _handle_failure(self, state: AgentState, tool_name: str, result, step_number: int):
        logger.warning(f"[{state.task_id}] ⚠️ 工具执行失败: {tool_name}")
        state.add_error(f"工具执行失败: {tool_name}")
        state.update_execution_step(step_number, result={"error": result.error if hasattr(result, 'error') else "未知错误"}, status="failed", state_transitions=["failed"])
        self._mark_task_completed(state, tool_name)
