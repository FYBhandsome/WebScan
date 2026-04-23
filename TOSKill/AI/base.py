"""
抽象基类模块

定义节点基类和核心数据结构。
"""
import logging
import asyncio
import json
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from enum import Enum

from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from pydantic import BaseModel

from .state import AgentState
from .tools.registry import registry
from .agent_config import agent_config

logger = logging.getLogger(__name__)


class PlanningResponse(BaseModel):
    """规划响应模型，用于LLM规划器的输出解析"""
    plan: List[str]
    reasoning: str


class NodeStage(Enum):
    """节点阶段枚举"""
    INFO_COLLECTION = "info_collection"
    VULN_SCAN = "vuln_scan"
    RESULT_ANALYSIS = "result_analysis"


class BasePlanningNode(ABC):
    """规划节点基类"""
    
    def __init__(self, stage: NodeStage = NodeStage.INFO_COLLECTION):
        self.stage = stage
        self._init_llm()
        logger.info(f"📋 {self.__class__.__name__} 初始化完成 | 阶段: {stage.value}")
    
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
        logger.info(f"[{state.task_id}] 📋 开始{self.stage.value}任务规划 | 目标: {state.target}")
        state.update_stage_status(self.stage.value, "running", "planning", 10, f"规划{self.stage.value}任务")
        
        tasks = await self._plan_tasks(state)
        tasks = self._filter_valid_tasks(tasks)
        state.planned_tasks = tasks
        state.current_task = tasks[0] if tasks else None
        
        logger.info(f"[{state.task_id}] ✅ 任务规划完成 | 任务数: {len(tasks)}")
        state.update_stage_status(self.stage.value, "running", "executing", 30, f"规划了 {len(tasks)} 个任务")
        state.add_execution_step(f"{self.stage.value}_planning", {"tasks": tasks}, "success", step_type="planning")
        return state
    
    @abstractmethod
    async def _plan_tasks(self, state: AgentState) -> List[str]:
        pass

    @abstractmethod
    def _get_valid_tools(self) -> List[str]:
        pass
    
    def _filter_valid_tasks(self, tasks: List[str]) -> List[str]:
        valid_tools = set(self._get_valid_tools())
        return [t for t in tasks if t in valid_tools]
    
    async def _llm_planning(self, state: AgentState, tools_category: str = "all") -> List[str]:
        available_tools = registry.list_tools()
        if tools_category == "info":
            available_tools = [t for t in available_tools if t.get("category") in ["plugin"]]
        elif tools_category == "vuln":
            available_tools = [t for t in available_tools if t.get("category") in ["vuln_scan", "poc"]]
        
        tools_desc = "\n".join([f"- {t['name']}: {t['description']}" for t in available_tools])
        context_info = f"\n目标上下文: {json.dumps(state.target_context, ensure_ascii=False)}" if state.target_context else ""
        system_prompt = self._build_llm_prompt(tools_category)
        user_prompt = f"目标: {state.target}{context_info}"
        
        prompt = ChatPromptTemplate.from_messages([("system", system_prompt), ("human", user_prompt)])
        chain = prompt | self.llm | JsonOutputParser(pydantic_object=PlanningResponse)
        result = await chain.ainvoke({"tools": tools_desc, "target": state.target})
        
        tasks = self._extract_tasks_from_result(result)
        if tasks:
            return tasks
        raise ValueError("无法从LLM结果中提取有效任务列表")
    
    def _build_llm_prompt(self, tools_category: str = "all") -> str:
        if tools_category == "info":
            return """你是Web安全扫描专家，负责为目标规划信息收集任务序列。
## 可用工具
{tools}
## 规划原则
1. 按照基础信息收集优先原则排列任务
2. 根据目标特征选择合适的工具组合
## 输出格式
{{"plan": ["task1", "task2"], "reasoning": "规划理由"}}"""
        elif tools_category == "vuln":
            return """你是Web安全扫描专家，负责为目标规划漏洞扫描任务序列。
## 可用工具
{tools}
## 规划原则
1. 根据目标上下文选择合适的漏洞扫描工具
2. 优先检测高风险漏洞类型
## 输出格式
{{"plan": ["task1", "task2"], "reasoning": "规划理由"}}"""
        return """你是Web安全扫描专家，负责为目标规划最优扫描任务序列。
## 可用工具
{tools}
## 输出格式
{{"plan": ["task1", "task2"], "reasoning": "规划理由"}}"""
    
    def _extract_tasks_from_result(self, result: Any) -> List[str]:
        if result is None:
            return []
        if isinstance(result, PlanningResponse):
            return result.plan if isinstance(result.plan, list) else []
        if isinstance(result, dict):
            if 'plan' in result and isinstance(result['plan'], list):
                return result['plan']
            return []
        if isinstance(result, list):
            return result if all(isinstance(item, str) for item in result) else []
        if isinstance(result, str):
            parsed = json.loads(result)
            return self._extract_tasks_from_result(parsed)
        return []


class BaseToolExecutionNode(ABC):
    """工具执行节点基类"""
    
    def __init__(self, stage: NodeStage = NodeStage.INFO_COLLECTION, max_concurrent: int = None):
        self.stage = stage
        self.semaphore = asyncio.Semaphore(max_concurrent or agent_config.MAX_CONCURRENT_TOOLS)
        logger.info(f"🔧 {self.__class__.__name__} 初始化完成 | 阶段: {stage.value}")
    
    async def __call__(self, state: AgentState) -> AgentState:
        if not state.current_task:
            logger.info(f"[{state.task_id}] ⏹️ 没有待执行任务")
            return state
        
        task = state.current_task
        logger.info(f"[{state.task_id}] 🔧 开始执行工具 | 工具: {task}")
        
        step_number = state.add_execution_step_start(task, step_type="tool_execution")
        
        async with self.semaphore:
            result = await self._execute_tool(state, task)
            if result.success:
                await self._handle_success(state, task, result, step_number)
            else:
                await self._handle_failure(state, task, result, step_number)
        
        return state
    
    @abstractmethod
    async def _execute_tool(self, state: AgentState, tool_name: str):
        pass
    
    @abstractmethod
    async def _handle_success(self, state: AgentState, tool_name: str, result, step_number: int):
        pass
    
    @abstractmethod
    async def _handle_failure(self, state: AgentState, tool_name: str, result, step_number: int):
        pass
    
    def _mark_task_completed(self, state: AgentState, task: str) -> None:
        if task in state.planned_tasks:
            state.planned_tasks.remove(task)
        state.completed_tasks.append(task)
        state.current_task = state.planned_tasks[0] if state.planned_tasks else None


class BaseResultVerificationNode(ABC):
    """结果验证节点基类"""
    
    def __init__(self, stage: NodeStage = NodeStage.INFO_COLLECTION):
        self.stage = stage
        logger.info(f"🔍 {self.__class__.__name__} 初始化完成 | 阶段: {stage.value}")
    
    async def __call__(self, state: AgentState) -> AgentState:
        logger.info(f"[{state.task_id}] 🔍 开始验证{self.stage.value}结果")
        await self._verify_results(state)
        
        if not state.planned_tasks:
            logger.info(f"[{state.task_id}] ✅ 所有{self.stage.value}任务已完成")
            state.update_stage_status(self.stage.value, "completed", "完成", 100, f"完成 {len(state.completed_tasks)} 个任务")
        else:
            state.current_task = state.planned_tasks[0]
        
        return state
    
    @abstractmethod
    async def _verify_results(self, state: AgentState) -> None:
        pass
