"""
LangGraph 节点定义

原子化节点设计：
- 环境感知、AI决策、用户交互、执行分析、聊天协商、脚本管理
完全兼容原有漏洞分析、报告生成等功能。

新增安全检测节点：
- 端口扫描、子域名枚举、目录扫描、SSL证书检测
- 敏感信息泄露、SQL注入深度检测、XSS深度检测
- SSRF检测、文件上传漏洞检测
"""
import logging
import json
import os
import time
import asyncio
import socket
import ssl
import re
from typing import Dict, Any, List, Optional, TypedDict, Callable
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from datetime import datetime
from urllib.parse import urlparse

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
from .tools.info_tools import get_info_tools, INFO_COLLECTION_TOOLS
from .tools.vuln_tools import VULN_SCAN_TOOLS
from .agent_config import agent_config

logger = logging.getLogger(__name__)


# ==================== 节点输入输出定义 ====================
class NodeInput(TypedDict, total=False):
    """节点输入定义"""
    target: str
    context: Dict[str, Any]
    params: Dict[str, Any]
    previous_results: Dict[str, Any]


class NodeOutput(TypedDict, total=False):
    """节点输出定义"""
    success: bool
    data: Dict[str, Any]
    vulnerabilities: List[Dict[str, Any]]
    errors: List[str]
    metadata: Dict[str, Any]


@dataclass
class NodeResult:
    """节点执行结果"""
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    execution_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "data": self.data,
            "vulnerabilities": self.vulnerabilities,
            "errors": self.errors,
            "execution_time": self.execution_time,
            "metadata": self.metadata
        }


# ==================== 安全检测节点基类 ====================
class BaseSecurityNode(ABC):
    """
    安全检测节点基类
    
    提供统一的节点接口、输入输出验证、日志记录和错误处理
    """
    
    node_name: str = "base_security_node"
    node_description: str = "安全检测节点基类"
    node_category: str = "security"
    node_timeout: int = 60
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.node_name}")
        self._validate_node_config()
        self.logger.info(f"🔒 [{self.node_name}] 节点初始化完成")
    
    def _validate_node_config(self) -> None:
        """验证节点配置"""
        if not self.node_name:
            raise ValueError("节点名称不能为空")
        if self.node_timeout <= 0:
            raise ValueError(f"节点超时时间必须大于0: {self.node_timeout}")
    
    def validate_input(self, state: AgentState) -> bool:
        """验证输入数据"""
        if not state.target:
            self.logger.error(f"[{self.node_name}] 缺少目标地址")
            return False
        return True
    
    def validate_output(self, result: NodeResult) -> bool:
        """验证输出数据"""
        if not isinstance(result, NodeResult):
            self.logger.error(f"[{self.node_name}] 输出类型错误")
            return False
        return True
    
    async def __call__(self, state: AgentState) -> AgentState:
        """执行节点"""
        start_time = time.time()
        self.logger.info(f"[{state.task_id}] 🔒 [{self.node_name}] 开始执行 | 目标: {state.target}")
        
        try:
            if not self.validate_input(state):
                raise ValueError(f"输入验证失败: {self.node_name}")
            
            state.add_execution_step_start(self.node_name, step_type="security_scan")
            
            result = await self.execute(state)
            
            if not self.validate_output(result):
                raise ValueError(f"输出验证失败: {self.node_name}")
            
            result.execution_time = time.time() - start_time
            
            state.tool_results[self.node_name] = result.data
            if result.vulnerabilities:
                for vuln in result.vulnerabilities:
                    state.add_vulnerability(vuln)
            if result.errors:
                for error in result.errors:
                    state.add_error(error)
            
            state.add_execution_step(
                self.node_name,
                {"result": result.to_dict()},
                "success" if result.success else "failed",
                step_type="security_scan"
            )
            
            self.logger.info(
                f"[{state.task_id}] ✅ [{self.node_name}] 执行完成 | "
                f"耗时: {result.execution_time:.2f}s | "
                f"漏洞数: {len(result.vulnerabilities)}"
            )
            
        except Exception as e:
            self.logger.error(f"[{state.task_id}] ❌ [{self.node_name}] 执行失败: {e}")
            state.add_error(f"[{self.node_name}] 执行失败: {str(e)}")
            state.add_execution_step(
                self.node_name,
                {"error": str(e)},
                "failed",
                step_type="security_scan"
            )
        
        return state
    
    @abstractmethod
    async def execute(self, state: AgentState) -> NodeResult:
        """执行具体的安全检测逻辑"""
        pass


# ==================== 数据流验证器 ====================
class DataFlowValidator:
    """节点间数据流验证器"""
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """验证URL格式"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    @staticmethod
    def validate_domain(domain: str) -> bool:
        """验证域名格式"""
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """验证IP地址格式"""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(pattern, ip):
            return False
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    
    @staticmethod
    def validate_port(port: int) -> bool:
        """验证端口号"""
        return isinstance(port, int) and 0 < port <= 65535
    
    @staticmethod
    def extract_domain(target: str) -> Optional[str]:
        """从目标中提取域名"""
        if DataFlowValidator.validate_domain(target):
            return target
        if DataFlowValidator.validate_url(target):
            parsed = urlparse(target)
            return parsed.netloc.split(':')[0]
        return None


# 可用任务列表（用于AI决策判断）
available_task_names = [t['name'] for t in registry.list_tools()]


# ==================== 原有节点（完全保留）====================
class VulnerabilityAnalysisNode:
    """漏洞分析节点"""
    
    def __init__(self):
        from backend.ai_agents.analyzers.vuln_analyzer import VulnerabilityAnalyzer
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
    """报告生成节点 - 使用统一的报告服务"""
    
    def __init__(self, output_dir: str = None):
        from backend.services.report_service import ReportService, ReportFormat
        self.report_service = ReportService(output_dir=output_dir or "reports")
        self.ReportFormat = ReportFormat
        logger.info("📄 报告生成节点初始化 | 使用统一报告服务")
    
    async def __call__(self, state: AgentState) -> AgentState:
        logger.info(f"[{state.task_id}] 📄 开始生成扫描报告")
        
        try:
            vuln_list = self._prepare_vulnerabilities(state)
            
            report_data = await self.report_service.generate_report(
                task_id=state.task_id,
                task_name=f"安全扫描任务-{state.target}",
                target=state.target,
                vulnerabilities=vuln_list,
                execution_history=state.execution_history,
                tool_results=state.tool_results,
                target_context=state.target_context,
                include_ai_analysis=True,
                scan_time=state.execution_history[0].get("timestamp_iso") if state.execution_history else None
            )
            
            json_path = self.report_service.save_report(report_data, self.ReportFormat.JSON)
            html_path = self.report_service.save_report(report_data, self.ReportFormat.HTML)
            md_path = self.report_service.save_report(report_data, self.ReportFormat.MARKDOWN)
            
            reports = {
                "final_report": report_data.to_dict(),
                "execution_trace_report": self._generate_execution_trace(state),
                "html_execution_trace": self.report_service.generate_html_report(report_data),
                "saved_files": {
                    "json": json_path,
                    "html": html_path,
                    "markdown": md_path
                }
            }
            
            state.tool_results.update(reports)
            state.scan_summary = {
                "target": state.target,
                "vulnerabilities_count": len(state.vulnerabilities),
                "completed_tasks": len(state.completed_tasks),
                "risk_score": report_data.risk_assessment.score,
                "risk_level": report_data.risk_assessment.level
            }
            state.mark_complete()
            
            logger.info(f"[{state.task_id}] ✅ 报告生成完成 | 已保存到: {json_path}")
            state.add_execution_step("report_generation", {
                "status": "success",
                "files_saved": reports["saved_files"],
                "vulnerabilities_count": len(state.vulnerabilities)
            }, "success", step_type="report_generation")
            
        except Exception as e:
            logger.error(f"[{state.task_id}] ❌ 报告生成失败: {e}")
            state.add_error(f"报告生成失败: {str(e)}")
            state.add_execution_step("report_generation", {"error": str(e)}, "failed", step_type="report_generation")
        
        return state
    
    def _prepare_vulnerabilities(self, state: AgentState) -> List[Dict[str, Any]]:
        """准备漏洞数据"""
        vuln_list = []
        for vuln in state.vulnerabilities:
            vuln_data = {
                "title": vuln.get("title", vuln.get("name", "未知漏洞")),
                "name": vuln.get("name", vuln.get("title", "未知漏洞")),
                "severity": vuln.get("severity", "info"),
                "url": vuln.get("url", state.target),
                "description": vuln.get("description", ""),
                "remediation": vuln.get("remediation", "")
            }
            vuln_list.append(vuln_data)
        return vuln_list
    
    def _generate_execution_trace(self, state: AgentState) -> Dict[str, Any]:
        """生成执行轨迹报告"""
        return {
            "task_id": state.task_id,
            "target": state.target,
            "execution_history": state.execution_history,
            "completed_tasks": state.completed_tasks,
            "tool_results_summary": {k: type(v).__name__ for k, v in state.tool_results.items()},
            "total_steps": len(state.execution_history),
            "total_tools_used": len(state.completed_tasks)
        }


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


# ==================== 新增：Demo风格原子节点 ====================
class AIDecisionNode:
    """AI 决策节点（兼容Demo逻辑）"""
    
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
        
        # 重置标记
        state.need_generate_script = False
        
        if self.use_llm:
            decision = await self._llm_decision(state)
        else:
            decision = self._rule_based_decision(state)
        
        state.target_context["next_action"] = decision["action"]
        
        if decision["action"] == "tool":
            state.planned_tasks = decision.get("tasks", [])
            state.current_task = state.planned_tasks[0] if state.planned_tasks else None
            
            # Demo逻辑：判断任务是否存在，不存在则标记需要生成脚本
            task = state.planned_tasks[0] if state.planned_tasks else None
            if task and task not in available_task_names:
                logger.info(f"[{state.task_id}] ⚠️ 任务 {task} 不存在，需要生成脚本")
                state.need_generate_script = True
            else:
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
## 可用任务
{tools}
## 规则
1. 如果任务不存在/不支持，只输出：need_script
2. 否则只输出任务名，或者决策结果
## 输出格式
{{"action": "tool" 或 "end", "tasks": ["task1"], "reason": "决策理由"}}"""
        
        user_prompt = f"目标: {state.target}{context_info}\n已完成任务: {state.completed_tasks}\n已发现漏洞: {len(state.vulnerabilities)} 个\n聊天历史总结: {state.chat_summary}"
        
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


class UserInteractNode:
    """用户交互节点（Demo原子节点）"""
    
    def __init__(self):
        logger.info("👤 用户交互节点初始化完成")
    
    async def __call__(self, state: AgentState) -> AgentState:
        print("\n" + "="*60)
        task = state.planned_tasks[0] if state.planned_tasks else "无"
        print(f"🎯 目标：{state.target} | AI推荐任务：{task}")
        print("【1】执行扫描 【2】停止并生成报告 【3】和AI聊天 【4】上传自定义脚本 【5】AI生成脚本")
        
        choice = input("请输入指令：").strip()
        state.user_choice = choice
        
        logger.info(f"[{state.task_id}] 👤 用户选择: {choice}")
        return state


class ExecuteAnalyzeNode:
    """执行+分析节点（Demo原子节点）"""
    
    def __init__(self):
        self.tool_executor = ToolExecutionNode()
        self._init_llm()
        logger.info("⚡ 执行分析节点初始化完成")
    
    def _init_llm(self):
        self.llm = ChatOpenAI(
            model=agent_config.MODEL_ID,
            temperature=0.1,
            api_key=agent_config.OPENAI_API_KEY,
            base_url=agent_config.OPENAI_BASE_URL
        )
    
    async def __call__(self, state: AgentState) -> AgentState:
        print("\n" + "="*60)
        task = state.current_task
        logger.info(f"[{state.task_id}] ⚡ 开始执行并分析: {task}")
        
        # 1. 执行工具
        state = await self.tool_executor(state)
        
        # 2. 获取结果
        res = state.tool_results.get(task, {})
        
        # 3. AI自动分析结果
        exec_log = f"[执行] {task} → {res}"
        analysis = await self.llm.ainvoke(f"简要3点分析这个扫描结果：{res}")
        analysis = analysis.content.strip()
        analyze_log = f"[分析] {analysis}"
        
        print("\n🧾 AI分析结果：\n" + analysis)
        
        # 4. 更新历史
        state.append_chat_history("system", exec_log + "\n" + analyze_log)
        state.task_history = getattr(state, 'task_history', [])
        state.task_history.append(exec_log)
        state.task_history.append(analyze_log)
        
        logger.info(f"[{state.task_id}] ✅ 执行分析完成: {task}")
        return state


class ChatNegotiateNode:
    """聊天协商节点（Demo原子节点，带记忆）"""
    
    def __init__(self):
        self.llm = ChatOpenAI(
            model=agent_config.MODEL_ID,
            temperature=0.7,
            api_key=agent_config.OPENAI_API_KEY,
            base_url=agent_config.OPENAI_BASE_URL
        )
        logger.info("💬 聊天协商节点初始化完成")
    
    async def __call__(self, state: AgentState) -> AgentState:
        print("\n" + "="*60)
        print("🔹 实时记忆聊天（输入 stop 退出）")
        
        name = state.user_name
        chat_hist = state.chat_history.copy()
        task_history = getattr(state, 'task_history', [])
        
        while True:
            # AI回复
            prompt = f"""
你是安全助手，称呼用户为 {name}
上下文：
任务历史：{task_history}
聊天历史：{chat_hist}
目标：{state.target}
简洁回复，不要太长。
"""
            ai_msg = await self.llm.ainvoke(prompt)
            ai_msg = ai_msg.content.strip()
            print(f"\n🤖 AI：{ai_msg}")
            chat_hist.append({"role": "assistant", "content": ai_msg})
            
            # 用户输入
            user_msg = input("👤 你：").strip()
            chat_hist.append({"role": "user", "content": user_msg})
            
            # 记住名字
            if "我叫" in user_msg:
                name = user_msg.replace("我叫", "").strip()
                print(f"✅ 已记住名字：{name}")
            
            # 退出聊天
            if user_msg.lower() == "stop":
                break
        
        # 聊天总结
        summary = await self.llm.ainvoke(f"总结这段聊天内容：{chat_hist}")
        summary = summary.content.strip()
        print(f"\n✅ 聊天总结：{summary}")
        
        # 更新状态
        state.chat_history = chat_hist
        state.chat_summary = summary
        state.user_name = name
        state.task_history = task_history
        
        logger.info(f"[{state.task_id}] 💬 聊天完成，总结: {summary[:50]}...")
        return state


class ScriptToolNode:
    """脚本管理节点（Demo原子节点）"""
    
    def __init__(self):
        self.llm = ChatOpenAI(
            model=agent_config.MODEL_ID,
            temperature=0.1,
            api_key=agent_config.OPENAI_API_KEY,
            base_url=agent_config.OPENAI_BASE_URL
        )
        logger.info("📜 脚本管理节点初始化完成")
    
    def _save_script(self, script_name: str, code: str) -> str:
        path = f"custom_scripts/generated/{script_name}.py"
        with open(path, "w", encoding="utf-8") as f:
            f.write(code.strip())
        return path
    
    async def __call__(self, state: AgentState) -> AgentState:
        print("\n" + "="*60)
        print("🔹 自定义脚本管理")
        res = {}
        
        choice = state.user_choice
        if choice == "4":
            # 上传脚本
            path = input("输入脚本本地路径：").strip()
            if os.path.exists(path):
                new_path = self._save_script("uploaded_script", open(path, encoding='utf-8').read())
                test_result, msg = load_and_test_script(new_path, state.target)
                res = test_result or {"error": msg}
                print(f"✅ 脚本上传完成: {msg}")
            else:
                print("❌ 文件不存在")
        
        elif choice == "5" or state.need_generate_script:
            # AI生成脚本
            desc = input("描述你想要的脚本功能：").strip()
            print("🤖 AI正在生成脚本...")
            
            code = await self.llm.ainvoke(f"""
生成Python扫描脚本，纯代码无任何解释，必须包含 run(target) 函数，返回字典结果。
功能：{desc}
不要加markdown格式，直接输出代码。
""")
            code = code.content.replace("```python", "").replace("```", "").strip()
            
            # 验证代码
            is_valid, error_msg = validate_script_code(code)
            if not is_valid:
                print(f"⚠️ 生成的代码验证失败: {error_msg}")
            else:
                import time
                timestamp = int(time.time())
                new_path = self._save_script(f"{timestamp}_generated", code)
                print(f"\n📝 脚本已保存：{new_path}")
                
                test_result, msg = load_and_test_script(new_path, state.target)
                res = test_result or {"error": msg}
                print(f"执行结果：{res}")
        
        # 更新状态
        state.append_chat_history("system", f"自定义脚本执行结果：{res}")
        state.tool_results["custom_script"] = res
        task_history = getattr(state, 'task_history', [])
        task_history.append(f"[脚本任务] {res}")
        state.task_history = task_history
        
        logger.info(f"[{state.task_id}] 📜 脚本任务完成: {res}")
        return state


# ==================== 新增安全检测节点 ====================

class PortScanNode(BaseSecurityNode):
    """
    端口扫描节点
    
    输入:
        - target: 目标域名或IP地址
        - context: 可选的上下文信息
    
    输出:
        - open_ports: 开放端口列表
        - services: 端口服务信息
        - vulnerabilities: 发现的安全问题
    """
    
    node_name = "port_scan"
    node_description = "端口扫描，检测开放端口和服务版本"
    node_category = "recon"
    node_timeout = 180
    
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
        1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017
    ]
    
    SERVICE_MAP = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
        1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy",
        8443: "HTTPS-Alt", 27017: "MongoDB"
    }
    
    async def execute(self, state: AgentState) -> NodeResult:
        target = DataFlowValidator.extract_domain(state.target) or state.target
        
        if not DataFlowValidator.validate_ip(target) and not DataFlowValidator.validate_domain(target):
            return NodeResult(
                success=False,
                errors=[f"无效的目标地址: {target}"]
            )
        
        open_ports = []
        services = []
        vulnerabilities = []
        
        try:
            ip = await self._resolve_domain(target)
            
            scan_tasks = [self._scan_port(ip, port) for port in self.COMMON_PORTS]
            results = await asyncio.gather(*scan_tasks, return_exceptions=True)
            
            for port, result in zip(self.COMMON_PORTS, results):
                if isinstance(result, dict) and result.get("open"):
                    service_info = {
                        "port": port,
                        "service": self.SERVICE_MAP.get(port, "unknown"),
                        "state": "open",
                        "banner": result.get("banner", "")
                    }
                    open_ports.append(port)
                    services.append(service_info)
                    
                    vuln = self._check_port_vulnerability(port, result.get("banner", ""))
                    if vuln:
                        vulnerabilities.append(vuln)
            
            return NodeResult(
                success=True,
                data={
                    "target": target,
                    "ip": ip,
                    "open_ports": open_ports,
                    "services": services,
                    "total_open": len(open_ports)
                },
                vulnerabilities=vulnerabilities,
                metadata={"scan_type": "tcp_connect", "ports_scanned": len(self.COMMON_PORTS)}
            )
            
        except Exception as e:
            return NodeResult(
                success=False,
                errors=[f"端口扫描失败: {str(e)}"]
            )
    
    async def _resolve_domain(self, target: str) -> str:
        """解析域名为IP地址"""
        if DataFlowValidator.validate_ip(target):
            return target
        try:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(None, socket.gethostbyname, target)
            return result
        except socket.gaierror:
            raise ValueError(f"无法解析域名: {target}")
    
    async def _scan_port(self, ip: str, port: int, timeout: float = 2.0) -> Dict[str, Any]:
        """扫描单个端口"""
        try:
            loop = asyncio.get_running_loop()
            
            def _connect():
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                banner = ""
                if result == 0:
                    try:
                        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')[:200]
                    except Exception:
                        pass
                sock.close()
                return {"open": result == 0, "banner": banner}
            
            return await loop.run_in_executor(None, _connect)
        except Exception:
            return {"open": False, "banner": ""}
    
    def _check_port_vulnerability(self, port: int, banner: str) -> Optional[Dict[str, Any]]:
        """检查端口是否存在已知漏洞"""
        high_risk_ports = {21: "FTP可能存在匿名登录", 23: "Telnet不安全", 
                          139: "NetBIOS可能泄露信息", 445: "SMB可能存在漏洞",
                          3389: "RDP可能存在暴力破解风险"}
        
        if port in high_risk_ports:
            return {
                "title": f"{self.SERVICE_MAP.get(port, '未知服务')}安全风险",
                "severity": "medium",
                "port": port,
                "description": high_risk_ports[port],
                "remediation": "建议关闭不必要的服务端口或加强访问控制"
            }
        return None


class SubdomainEnumNode(BaseSecurityNode):
    """
    子域名枚举节点
    
    输入:
        - target: 主域名
        - context: 可选的上下文信息
    
    输出:
        - subdomains: 发现的子域名列表
        - ips: 子域名对应的IP地址
        - vulnerabilities: 发现的安全问题
    """
    
    node_name = "subdomain_enum"
    node_description = "子域名枚举，发现目标的子域名"
    node_category = "recon"
    node_timeout = 300
    
    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
        "vpn", "admin", "portal", "ssh", "api", "dev", "test", "staging", "app",
        "blog", "shop", "store", "cdn", "static", "assets", "img", "images",
        "m", "mobile", "wap", "forum", "bbs", "wiki", "docs", "help", "support"
    ]
    
    async def execute(self, state: AgentState) -> NodeResult:
        domain = DataFlowValidator.extract_domain(state.target)
        
        if not domain:
            return NodeResult(
                success=False,
                errors=[f"无法从目标提取有效域名: {state.target}"]
            )
        
        subdomains = []
        subdomain_ips = {}
        vulnerabilities = []
        
        try:
            scan_tasks = [
                self._check_subdomain(domain, sub) 
                for sub in self.COMMON_SUBDOMAINS
            ]
            results = await asyncio.gather(*scan_tasks, return_exceptions=True)
            
            for sub, result in zip(self.COMMON_SUBDOMAINS, results):
                if isinstance(result, dict) and result.get("exists"):
                    full_domain = f"{sub}.{domain}"
                    subdomains.append(full_domain)
                    if result.get("ip"):
                        subdomain_ips[full_domain] = result["ip"]
            
            for subdomain in subdomains:
                vuln = self._check_subdomain_security(subdomain)
                if vuln:
                    vulnerabilities.append(vuln)
            
            return NodeResult(
                success=True,
                data={
                    "domain": domain,
                    "subdomains": subdomains,
                    "subdomain_ips": subdomain_ips,
                    "total_found": len(subdomains)
                },
                vulnerabilities=vulnerabilities,
                metadata={"scan_method": "dns_bruteforce", "wordlist_size": len(self.COMMON_SUBDOMAINS)}
            )
            
        except Exception as e:
            return NodeResult(
                success=False,
                errors=[f"子域名枚举失败: {str(e)}"]
            )
    
    async def _check_subdomain(self, domain: str, subdomain: str) -> Dict[str, Any]:
        """检查子域名是否存在"""
        full_domain = f"{subdomain}.{domain}"
        try:
            loop = asyncio.get_running_loop()
            ip = await loop.run_in_executor(None, socket.gethostbyname, full_domain)
            return {"exists": True, "ip": ip}
        except socket.gaierror:
            return {"exists": False, "ip": None}
        except Exception:
            return {"exists": False, "ip": None}
    
    def _check_subdomain_security(self, subdomain: str) -> Optional[Dict[str, Any]]:
        """检查子域名安全问题"""
        sensitive_keywords = ["admin", "test", "dev", "staging", "internal"]
        for keyword in sensitive_keywords:
            if keyword in subdomain.lower():
                return {
                    "title": f"敏感子域名发现: {subdomain}",
                    "severity": "low",
                    "url": subdomain,
                    "description": f"发现可能包含敏感信息的子域名: {subdomain}",
                    "remediation": "确保敏感子域名有适当的访问控制"
                }
        return None


class DirScanNode(BaseSecurityNode):
    """
    目录扫描节点
    
    输入:
        - target: 目标URL
        - context: 可选的上下文信息
    
    输出:
        - directories: 发现的目录列表
        - files: 发现的敏感文件
        - vulnerabilities: 发现的安全问题
    """
    
    node_name = "dir_scan"
    node_description = "目录扫描，发现隐藏目录和敏感文件"
    node_category = "recon"
    node_timeout = 300
    
    COMMON_PATHS = [
        "/admin", "/administrator", "/admin.php", "/wp-admin", "/phpmyadmin",
        "/backup", "/backups", "/old", "/test", "/temp", "/tmp",
        "/.git", "/.svn", "/.env", "/.htaccess", "/.htpasswd",
        "/config", "/conf", "/configuration.php", "/config.php",
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
        "/server-status", "/server-info", "/phpinfo.php",
        "/api", "/api/v1", "/api/v2", "/graphql",
        "/uploads", "/upload", "/files", "/images", "/assets",
        "/login", "/signin", "/register", "/signup",
        "/.well-known", "/.well-known/security.txt"
    ]
    
    SENSITIVE_FILES = [
        ".env", "web.config", "web.config.bak", "app.config",
        "database.yml", "credentials.json", "secrets.json",
        "id_rsa", "id_rsa.pub", ".pem", ".key",
        "backup.sql", "dump.sql", "database.sql",
        "phpinfo.php", "info.php", "test.php"
    ]
    
    async def execute(self, state: AgentState) -> NodeResult:
        import aiohttp
        
        if not DataFlowValidator.validate_url(state.target):
            if not state.target.startswith(('http://', 'https://')):
                target = f"http://{state.target}"
            else:
                target = state.target
        else:
            target = state.target
        
        directories = []
        sensitive_files = []
        vulnerabilities = []
        
        try:
            async with aiohttp.ClientSession() as session:
                scan_tasks = [
                    self._scan_path(session, target, path) 
                    for path in self.COMMON_PATHS
                ]
                results = await asyncio.gather(*scan_tasks, return_exceptions=True)
                
                for path, result in zip(self.COMMON_PATHS, results):
                    if isinstance(result, dict) and result.get("exists"):
                        path_info = {
                            "path": path,
                            "status": result.get("status"),
                            "size": result.get("size"),
                            "content_type": result.get("content_type")
                        }
                        
                        if any(sf in path for sf in self.SENSITIVE_FILES):
                            sensitive_files.append(path_info)
                            vulnerabilities.append({
                                "title": f"敏感文件暴露: {path}",
                                "severity": "high",
                                "url": f"{target}{path}",
                                "description": f"发现可能包含敏感信息的文件: {path}",
                                "remediation": "删除或限制访问敏感文件"
                            })
                        else:
                            directories.append(path_info)
            
            return NodeResult(
                success=True,
                data={
                    "target": target,
                    "directories": directories,
                    "sensitive_files": sensitive_files,
                    "total_directories": len(directories),
                    "total_sensitive_files": len(sensitive_files)
                },
                vulnerabilities=vulnerabilities,
                metadata={"scan_method": "http_bruteforce", "paths_scanned": len(self.COMMON_PATHS)}
            )
            
        except Exception as e:
            return NodeResult(
                success=False,
                errors=[f"目录扫描失败: {str(e)}"]
            )
    
    async def _scan_path(self, session, target: str, path: str) -> Dict[str, Any]:
        """扫描单个路径"""
        try:
            url = f"{target.rstrip('/')}{path}"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5), allow_redirects=False) as response:
                if response.status in [200, 301, 302, 403]:
                    return {
                        "exists": True,
                        "status": response.status,
                        "size": response.content_length or 0,
                        "content_type": response.headers.get('Content-Type', '')
                    }
                return {"exists": False}
        except Exception:
            return {"exists": False}


class SSLCertificateNode(BaseSecurityNode):
    """
    SSL证书检测节点
    
    输入:
        - target: 目标域名
        - context: 可选的上下文信息
    
    输出:
        - certificate: SSL证书信息
        - vulnerabilities: 证书相关的安全问题
    """
    
    node_name = "ssl_certificate"
    node_description = "SSL证书检测，验证证书有效性和安全性"
    node_category = "security"
    node_timeout = 60
    
    async def execute(self, state: AgentState) -> NodeResult:
        domain = DataFlowValidator.extract_domain(state.target)
        
        if not domain:
            return NodeResult(
                success=False,
                errors=[f"无法从目标提取有效域名: {state.target}"]
            )
        
        vulnerabilities = []
        certificate_info = {}
        
        try:
            context = ssl.create_default_context()
            
            loop = asyncio.get_running_loop()
            
            def _get_cert():
                with socket.create_connection((domain, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        return ssock.getpeercert()
            
            cert = await loop.run_in_executor(None, _get_cert)
            
            certificate_info = {
                "domain": domain,
                "subject": dict(x[0] for x in cert.get('subject', [])),
                "issuer": dict(x[0] for x in cert.get('issuer', [])),
                "version": cert.get('version'),
                "serial_number": cert.get('serialNumber'),
                "not_before": cert.get('notBefore'),
                "not_after": cert.get('notAfter'),
                "san": [x[1] for x in cert.get('subjectAltName', [])] if cert.get('subjectAltName') else []
            }
            
            from datetime import datetime
            not_after = datetime.strptime(cert.get('notAfter'), '%b %d %H:%M:%S %Y %Z')
            days_remaining = (not_after - datetime.now()).days
            
            if days_remaining < 0:
                vulnerabilities.append({
                    "title": "SSL证书已过期",
                    "severity": "critical",
                    "url": f"https://{domain}",
                    "description": f"SSL证书已于 {cert.get('notAfter')} 过期",
                    "remediation": "立即更新SSL证书"
                })
            elif days_remaining < 30:
                vulnerabilities.append({
                    "title": "SSL证书即将过期",
                    "severity": "high",
                    "url": f"https://{domain}",
                    "description": f"SSL证书将在 {days_remaining} 天后过期",
                    "remediation": "尽快更新SSL证书"
                })
            
            if 'CN' in certificate_info['subject']:
                cert_cn = certificate_info['subject']['CN']
                if cert_cn != domain and not cert_cn.startswith('*.'):
                    vulnerabilities.append({
                        "title": "SSL证书域名不匹配",
                        "severity": "medium",
                        "url": f"https://{domain}",
                        "description": f"证书CN ({cert_cn}) 与域名 ({domain}) 不匹配",
                        "remediation": "使用正确的SSL证书"
                    })
            
            return NodeResult(
                success=True,
                data={
                    "certificate": certificate_info,
                    "days_remaining": days_remaining,
                    "is_valid": days_remaining > 0
                },
                vulnerabilities=vulnerabilities,
                metadata={"check_type": "ssl_certificate_validation"}
            )
            
        except ssl.SSLCertVerificationError as e:
            return NodeResult(
                success=True,
                data={
                    "certificate": None,
                    "is_valid": False,
                    "error": str(e)
                },
                vulnerabilities=[{
                    "title": "SSL证书验证失败",
                    "severity": "high",
                    "url": f"https://{domain}",
                    "description": f"SSL证书验证失败: {str(e)}",
                    "remediation": "检查并修复SSL证书配置"
                }],
                metadata={"check_type": "ssl_certificate_validation"}
            )
        except Exception as e:
            return NodeResult(
                success=False,
                errors=[f"SSL证书检测失败: {str(e)}"]
            )


class SensitiveInfoLeakNode(BaseSecurityNode):
    """
    敏感信息泄露检测节点
    
    输入:
        - target: 目标URL
        - context: 可选的上下文信息
    
    输出:
        - leaks: 发现的敏感信息
        - vulnerabilities: 安全问题列表
    """
    
    node_name = "sensitive_info_leak"
    node_description = "敏感信息泄露检测，发现暴露的敏感数据"
    node_category = "vuln_scan"
    node_timeout = 120
    
    SENSITIVE_PATTERNS = {
        "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        "phone_cn": r'1[3-9]\d{9}',
        "id_card_cn": r'\d{17}[\dXx]',
        "api_key": r'(?i)(api[_-]?key|apikey|access[_-]?token)\s*[=:]\s*["\']?[\w-]{16,}',
        "aws_key": r'AKIA[0-9A-Z]{16}',
        "private_key": r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
        "password": r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?[^\s"\']{6,}',
        "jwt": r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
        "credit_card": r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
        "ip_address": r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    }
    
    async def execute(self, state: AgentState) -> NodeResult:
        import aiohttp
        
        if not state.target.startswith(('http://', 'https://')):
            target = f"http://{state.target}"
        else:
            target = state.target
        
        leaks = []
        vulnerabilities = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(target, timeout=aiohttp.ClientTimeout(total=30)) as response:
                    content = await response.text()
                    headers = dict(response.headers)
            
            for leak_type, pattern in self.SENSITIVE_PATTERNS.items():
                matches = re.findall(pattern, content)
                if matches:
                    unique_matches = list(set(matches))[:10]
                    leaks.append({
                        "type": leak_type,
                        "count": len(matches),
                        "samples": unique_matches[:5]
                    })
                    
                    severity = "high" if leak_type in ["private_key", "aws_key", "password"] else "medium"
                    vulnerabilities.append({
                        "title": f"敏感信息泄露: {leak_type}",
                        "severity": severity,
                        "url": target,
                        "description": f"发现 {len(matches)} 处 {leak_type} 类型的敏感信息",
                        "remediation": "移除或加密敏感信息"
                    })
            
            header_leaks = self._check_headers(headers)
            leaks.extend(header_leaks["leaks"])
            vulnerabilities.extend(header_leaks["vulnerabilities"])
            
            return NodeResult(
                success=True,
                data={
                    "target": target,
                    "leaks": leaks,
                    "total_leaks": len(leaks)
                },
                vulnerabilities=vulnerabilities,
                metadata={"scan_type": "content_pattern_matching"}
            )
            
        except Exception as e:
            return NodeResult(
                success=False,
                errors=[f"敏感信息检测失败: {str(e)}"]
            )
    
    def _check_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """检查HTTP头中的敏感信息"""
        leaks = []
        vulnerabilities = []
        
        sensitive_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
        for header in sensitive_headers:
            if header in headers:
                leaks.append({
                    "type": f"header_{header.lower().replace('-', '_')}",
                    "value": headers[header]
                })
                vulnerabilities.append({
                    "title": f"HTTP头信息泄露: {header}",
                    "severity": "low",
                    "description": f"{header} 头暴露了服务器信息: {headers[header]}",
                    "remediation": f"移除或隐藏 {header} 响应头"
                })
        
        return {"leaks": leaks, "vulnerabilities": vulnerabilities}


class SQLInjectionDeepNode(BaseSecurityNode):
    """
    SQL注入深度检测节点
    
    输入:
        - target: 目标URL
        - context: 可选的上下文信息(包括参数列表)
    
    输出:
        - injection_points: 发现的注入点
        - vulnerabilities: SQL注入漏洞列表
    """
    
    node_name = "sqli_deep_scan"
    node_description = "SQL注入深度检测，检测各种类型的SQL注入"
    node_category = "vuln_scan"
    node_timeout = 300
    
    SQL_PAYLOADS = [
        "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*",
        "1' AND '1'='1", "1' AND '1'='2",
        "1 OR 1=1", "1 OR 1=1--", "1 OR 1=1/*",
        "'; DROP TABLE users--", "'; WAITFOR DELAY '0:0:5'--",
        "1' AND SLEEP(5)--", "1' AND BENCHMARK(5000000,SHA1('test'))--",
        "1' UNION SELECT NULL--", "1' UNION SELECT NULL,NULL--",
        "-1' UNION SELECT 1,2,3--", "1' ORDER BY 1--",
        "admin'--", "admin'#", "admin'/*"
    ]
    
    ERROR_PATTERNS = [
        r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySqlException",
        r"PostgreSQL.*ERROR", r"Warning.*pg_", r"ORA-\d{5}",
        r"Microsoft SQL Server", r"SQLite3::SQLException",
        r"Syntax error.*query", r"Unclosed quotation mark"
    ]
    
    async def execute(self, state: AgentState) -> NodeResult:
        import aiohttp
        
        if not state.target.startswith(('http://', 'https://')):
            target = f"http://{state.target}"
        else:
            target = state.target
        
        injection_points = []
        vulnerabilities = []
        
        try:
            parsed = urlparse(target)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            params = self._extract_params(target)
            if not params:
                params = {"id": "1", "page": "1"}
            
            async with aiohttp.ClientSession() as session:
                for param, value in params.items():
                    for payload in self.SQL_PAYLOADS[:10]:
                        result = await self._test_injection(
                            session, base_url, param, value, payload
                        )
                        
                        if result.get("vulnerable"):
                            injection_points.append({
                                "parameter": param,
                                "payload": payload,
                                "type": result.get("injection_type", "unknown"),
                                "evidence": result.get("evidence")
                            })
                            
                            vulnerabilities.append({
                                "title": f"SQL注入漏洞: 参数 {param}",
                                "severity": "critical",
                                "url": base_url,
                                "parameter": param,
                                "description": f"在参数 {param} 发现SQL注入漏洞",
                                "evidence": result.get("evidence"),
                                "remediation": "使用参数化查询或预编译语句"
                            })
                            break
            
            return NodeResult(
                success=True,
                data={
                    "target": target,
                    "injection_points": injection_points,
                    "total_injections": len(injection_points)
                },
                vulnerabilities=vulnerabilities,
                metadata={"scan_type": "sqli_deep", "payloads_tested": len(self.SQL_PAYLOADS)}
            )
            
        except Exception as e:
            return NodeResult(
                success=False,
                errors=[f"SQL注入检测失败: {str(e)}"]
            )
    
    def _extract_params(self, url: str) -> Dict[str, str]:
        """提取URL参数"""
        parsed = urlparse(url)
        params = {}
        if parsed.query:
            for pair in parsed.query.split('&'):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    params[key] = value
        return params
    
    async def _test_injection(self, session, url: str, param: str, 
                              original_value: str, payload: str) -> Dict[str, Any]:
        """测试SQL注入"""
        try:
            test_url = f"{url}?{param}={payload}"
            start_time = time.time()
            
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                content = await response.text()
                response_time = time.time() - start_time
            
            for pattern in self.ERROR_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    return {
                        "vulnerable": True,
                        "injection_type": "error_based",
                        "evidence": f"错误信息匹配: {pattern}"
                    }
            
            if response_time > 5:
                return {
                    "vulnerable": True,
                    "injection_type": "time_based",
                    "evidence": f"响应时间: {response_time:.2f}s"
                }
            
            return {"vulnerable": False}
            
        except Exception:
            return {"vulnerable": False}


class XSSDeepScanNode(BaseSecurityNode):
    """
    XSS深度检测节点
    
    输入:
        - target: 目标URL
        - context: 可选的上下文信息
    
    输出:
        - xss_points: 发现的XSS注入点
        - vulnerabilities: XSS漏洞列表
    """
    
    node_name = "xss_deep_scan"
    node_description = "XSS深度检测，检测反射型、存储型XSS"
    node_category = "vuln_scan"
    node_timeout = 300
    
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<body onload=alert('XSS')>",
        "<iframe src='javascript:alert(1)'>",
        "'\"><script>alert('XSS')</script>",
        "<input onfocus=alert('XSS') autofocus>",
        "<marquee onstart=alert('XSS')>",
        "<details open ontoggle=alert('XSS')>",
        "<a href=\"javascript:alert('XSS')\">click</a>",
        "<div onmouseover=\"alert('XSS')\">hover</div>",
        "\"><script>alert(String.fromCharCode(88,83,83))</script>",
        "<img src=\"x\" onerror=\"eval(atob('YWxlcnQoJ1hTUycp'))\">",
        "'-alert('XSS')-'"
    ]
    
    CONTEXT_BREAKERS = {
        "html": ["'", "\"", ">", "<"],
        "attribute": ["'", "\"", ">"],
        "javascript": ["'", "\"", "</script>"],
        "url": ["'", "\"", "javascript:"]
    }
    
    async def execute(self, state: AgentState) -> NodeResult:
        import aiohttp
        
        if not state.target.startswith(('http://', 'https://')):
            target = f"http://{state.target}"
        else:
            target = state.target
        
        xss_points = []
        vulnerabilities = []
        
        try:
            parsed = urlparse(target)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            params = self._extract_params(target)
            if not params:
                params = {"q": "test", "search": "test", "input": "test"}
            
            async with aiohttp.ClientSession() as session:
                for param, value in params.items():
                    for payload in self.XSS_PAYLOADS[:8]:
                        result = await self._test_xss(
                            session, base_url, param, payload
                        )
                        
                        if result.get("vulnerable"):
                            xss_points.append({
                                "parameter": param,
                                "payload": payload,
                                "context": result.get("context", "unknown"),
                                "evidence": result.get("evidence")
                            })
                            
                            vulnerabilities.append({
                                "title": f"XSS漏洞: 参数 {param}",
                                "severity": "high",
                                "url": base_url,
                                "parameter": param,
                                "description": f"在参数 {param} 发现XSS漏洞",
                                "xss_type": result.get("xss_type", "reflected"),
                                "remediation": "对用户输入进行HTML编码和验证"
                            })
                            break
            
            return NodeResult(
                success=True,
                data={
                    "target": target,
                    "xss_points": xss_points,
                    "total_xss": len(xss_points)
                },
                vulnerabilities=vulnerabilities,
                metadata={"scan_type": "xss_deep", "payloads_tested": len(self.XSS_PAYLOADS)}
            )
            
        except Exception as e:
            return NodeResult(
                success=False,
                errors=[f"XSS检测失败: {str(e)}"]
            )
    
    def _extract_params(self, url: str) -> Dict[str, str]:
        """提取URL参数"""
        parsed = urlparse(url)
        params = {}
        if parsed.query:
            for pair in parsed.query.split('&'):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    params[key] = value
        return params
    
    async def _test_xss(self, session, url: str, param: str, payload: str) -> Dict[str, Any]:
        """测试XSS漏洞"""
        try:
            import urllib.parse
            encoded_payload = urllib.parse.quote(payload)
            test_url = f"{url}?{param}={encoded_payload}"
            
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                content = await response.text()
            
            if payload in content:
                return {
                    "vulnerable": True,
                    "context": "html",
                    "xss_type": "reflected",
                    "evidence": f"Payload未过滤直接输出"
                }
            
            unencoded_payload = payload.replace("<", "&lt;").replace(">", "&gt;")
            if unencoded_payload in content and payload not in content:
                return {
                    "vulnerable": False,
                    "context": "html_encoded"
                }
            
            for context, breakers in self.CONTEXT_BREAKERS.items():
                for breaker in breakers:
                    if breaker in payload and breaker in content:
                        return {
                            "vulnerable": True,
                            "context": context,
                            "xss_type": "reflected",
                            "evidence": f"在{context}上下文中发现注入点"
                        }
            
            return {"vulnerable": False}
            
        except Exception:
            return {"vulnerable": False}


class SSRFScanNode(BaseSecurityNode):
    """
    SSRF检测节点
    
    输入:
        - target: 目标URL
        - context: 可选的上下文信息
    
    输出:
        - ssrf_points: 发现的SSRF注入点
        - vulnerabilities: SSRF漏洞列表
    """
    
    node_name = "ssrf_scan"
    node_description = "SSRF检测，检测服务器端请求伪造漏洞"
    node_category = "vuln_scan"
    node_timeout = 180
    
    SSRF_PAYLOADS = [
        "http://127.0.0.1",
        "http://localhost",
        "http://[::1]",
        "http://0.0.0.0",
        "http://127.0.0.1:22",
        "http://127.0.0.1:3306",
        "http://127.0.0.1:6379",
        "http://169.254.169.254",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal",
        "file:///etc/passwd",
        "file:///c:/windows/win.ini",
        "dict://127.0.0.1:6379/info",
        "gopher://127.0.0.1:6379/_INFO"
    ]
    
    INTERNAL_RESPONSES = [
        "root:", "[extensions]", "SSH-", "MySQL", "Redis",
        "ami-id", "instance-id", "local-hostname", "metadata"
    ]
    
    async def execute(self, state: AgentState) -> NodeResult:
        import aiohttp
        
        if not state.target.startswith(('http://', 'https://')):
            target = f"http://{state.target}"
        else:
            target = state.target
        
        ssrf_points = []
        vulnerabilities = []
        
        try:
            parsed = urlparse(target)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            params = self._extract_params(target)
            if not params:
                params = {"url": "http://example.com", "target": "http://example.com"}
            
            async with aiohttp.ClientSession() as session:
                for param, value in params.items():
                    for payload in self.SSRF_PAYLOADS[:8]:
                        result = await self._test_ssrf(
                            session, base_url, param, payload
                        )
                        
                        if result.get("vulnerable"):
                            ssrf_points.append({
                                "parameter": param,
                                "payload": payload,
                                "evidence": result.get("evidence")
                            })
                            
                            vulnerabilities.append({
                                "title": f"SSRF漏洞: 参数 {param}",
                                "severity": "high",
                                "url": base_url,
                                "parameter": param,
                                "description": f"在参数 {param} 发现SSRF漏洞",
                                "remediation": "验证和限制用户提供的URL"
                            })
                            break
            
            return NodeResult(
                success=True,
                data={
                    "target": target,
                    "ssrf_points": ssrf_points,
                    "total_ssrf": len(ssrf_points)
                },
                vulnerabilities=vulnerabilities,
                metadata={"scan_type": "ssrf", "payloads_tested": len(self.SSRF_PAYLOADS)}
            )
            
        except Exception as e:
            return NodeResult(
                success=False,
                errors=[f"SSRF检测失败: {str(e)}"]
            )
    
    def _extract_params(self, url: str) -> Dict[str, str]:
        """提取URL参数"""
        parsed = urlparse(url)
        params = {}
        if parsed.query:
            for pair in parsed.query.split('&'):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    params[key] = value
        return params
    
    async def _test_ssrf(self, session, url: str, param: str, payload: str) -> Dict[str, Any]:
        """测试SSRF漏洞"""
        try:
            import urllib.parse
            encoded_payload = urllib.parse.quote(payload, safe='')
            test_url = f"{url}?{param}={encoded_payload}"
            
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=15)) as response:
                content = await response.text()
            
            for pattern in self.INTERNAL_RESPONSES:
                if pattern in content:
                    return {
                        "vulnerable": True,
                        "evidence": f"响应中包含内部服务特征: {pattern}"
                    }
            
            return {"vulnerable": False}
            
        except Exception:
            return {"vulnerable": False}


class FileUploadScanNode(BaseSecurityNode):
    """
    文件上传漏洞检测节点
    
    输入:
        - target: 目标URL
        - context: 可选的上下文信息
    
    输出:
        - upload_points: 发现的上传点
        - vulnerabilities: 文件上传漏洞列表
    """
    
    node_name = "file_upload_scan"
    node_description = "文件上传漏洞检测，检测恶意文件上传风险"
    node_category = "vuln_scan"
    node_timeout = 180
    
    MALICIOUS_FILES = {
        "php_webshell": {
            "filename": "test.php",
            "content": b"<?php echo 'VULN_TEST'; ?>",
            "content_type": "application/octet-stream"
        },
        "php_alternative": {
            "filename": "test.php5",
            "content": b"<?php echo 'VULN_TEST'; ?>",
            "content_type": "application/octet-stream"
        },
        "php_double_ext": {
            "filename": "test.php.jpg",
            "content": b"<?php echo 'VULN_TEST'; ?>",
            "content_type": "image/jpeg"
        },
        "php_null_byte": {
            "filename": "test.php%00.jpg",
            "content": b"<?php echo 'VULN_TEST'; ?>",
            "content_type": "image/jpeg"
        },
        "phtml": {
            "filename": "test.phtml",
            "content": b"<?php echo 'VULN_TEST'; ?>",
            "content_type": "application/octet-stream"
        },
        "jsp_shell": {
            "filename": "test.jsp",
            "content": b"<% out.println(\"VULN_TEST\"); %>",
            "content_type": "application/octet-stream"
        },
        "asp_shell": {
            "filename": "test.asp",
            "content": b"<% Response.Write(\"VULN_TEST\") %>",
            "content_type": "application/octet-stream"
        },
        "config_bypass": {
            "filename": ".htaccess",
            "content": b"AddType application/x-httpd-php .jpg",
            "content_type": "text/plain"
        }
    }
    
    UPLOAD_ENDPOINTS = [
        "/upload", "/upload.php", "/api/upload", "/file/upload",
        "/uploadfile", "/uploadfiles", "/attachments", "/files",
        "/api/v1/upload", "/user/upload", "/admin/upload"
    ]
    
    async def execute(self, state: AgentState) -> NodeResult:
        import aiohttp
        
        if not state.target.startswith(('http://', 'https://')):
            target = f"http://{state.target}"
        else:
            target = state.target
        
        upload_points = []
        vulnerabilities = []
        
        try:
            parsed = urlparse(target)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            async with aiohttp.ClientSession() as session:
                for endpoint in self.UPLOAD_ENDPOINTS:
                    upload_url = f"{base_url}{endpoint}"
                    
                    for file_type, file_info in self.MALICIOUS_FILES.items():
                        result = await self._test_upload(
                            session, upload_url, file_info
                        )
                        
                        if result.get("vulnerable"):
                            upload_points.append({
                                "endpoint": endpoint,
                                "file_type": file_type,
                                "filename": file_info["filename"],
                                "evidence": result.get("evidence")
                            })
                            
                            vulnerabilities.append({
                                "title": f"文件上传漏洞: {endpoint}",
                                "severity": "critical",
                                "url": upload_url,
                                "description": f"可通过 {endpoint} 上传恶意文件 {file_info['filename']}",
                                "remediation": "限制文件类型、检查文件内容、重命名上传文件"
                            })
                            break
            
            return NodeResult(
                success=True,
                data={
                    "target": target,
                    "upload_points": upload_points,
                    "total_vulnerable": len(upload_points)
                },
                vulnerabilities=vulnerabilities,
                metadata={"scan_type": "file_upload", "files_tested": len(self.MALICIOUS_FILES)}
            )
            
        except Exception as e:
            return NodeResult(
                success=False,
                errors=[f"文件上传检测失败: {str(e)}"]
            )
    
    async def _test_upload(self, session, url: str, file_info: Dict[str, Any]) -> Dict[str, Any]:
        """测试文件上传"""
        try:
            data = aiohttp.FormData()
            data.add_field(
                'file',
                file_info['content'],
                filename=file_info['filename'],
                content_type=file_info['content_type']
            )
            
            async with session.post(url, data=data, timeout=aiohttp.ClientTimeout(total=15)) as response:
                content = await response.text()
                
                if response.status in [200, 201, 301, 302]:
                    success_indicators = [
                        "success", "uploaded", "file saved", "VULN_TEST",
                        file_info['filename'], "upload successful"
                    ]
                    
                    for indicator in success_indicators:
                        if indicator.lower() in content.lower():
                            return {
                                "vulnerable": True,
                                "evidence": f"上传成功，响应包含: {indicator}"
                            }
                
                return {"vulnerable": False}
                
        except Exception:
            return {"vulnerable": False}


# ==================== 节点注册表 ====================
SECURITY_NODES = {
    "port_scan": PortScanNode,
    "subdomain_enum": SubdomainEnumNode,
    "dir_scan": DirScanNode,
    "ssl_certificate": SSLCertificateNode,
    "sensitive_info_leak": SensitiveInfoLeakNode,
    "sqli_deep_scan": SQLInjectionDeepNode,
    "xss_deep_scan": XSSDeepScanNode,
    "ssrf_scan": SSRFScanNode,
    "file_upload_scan": FileUploadScanNode
}


def get_security_node(node_name: str) -> Optional[BaseSecurityNode]:
    """获取安全检测节点实例"""
    node_class = SECURITY_NODES.get(node_name)
    if node_class:
        return node_class()
    return None


def list_security_nodes() -> List[Dict[str, str]]:
    """列出所有安全检测节点"""
    return [
        {
            "name": name,
            "description": cls.node_description,
            "category": cls.node_category,
            "timeout": cls.node_timeout
        }
        for name, cls in SECURITY_NODES.items()
    ]