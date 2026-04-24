"""
LangGraph 节点定义

定义Agent工作流中的各个节点函数。
优化版本：
- 移除未使用的代码
- 提取公共逻辑到工具类
- 动态获取工具列表
- 优化 AI 提示词构建
- 增强代码注释
"""
import logging
import asyncio
import json
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from datetime import datetime
from enum import Enum

from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from pydantic import BaseModel

from .state import AgentState
from ..tools.registry import registry
from ..tools.adapters import PluginAdapter, POCAdapter
from ..agent_config import agent_config
from ..utils.priority import TaskPriorityManager

logger = logging.getLogger(__name__)


# ============================================================================
# 数据模型定义
# ============================================================================

class PlanningResponse(BaseModel):
    """规划响应模型，用于LLM规划器的输出解析"""
    plan: List[str]
    reasoning: str


class NodeStage(Enum):
    """节点阶段枚举"""
    INFO_COLLECTION = "info_collection"
    VULN_SCAN = "vuln_scan"
    POC_VERIFICATION = "poc_verification"
    RESULT_ANALYSIS = "result_analysis"


# ============================================================================
# 工具类定义
# ============================================================================

class TargetContextUpdater:
    """
    目标上下文更新器
    
    统一管理目标上下文的更新逻辑，根据工具执行结果自动更新状态中的上下文信息。
    使用映射表将工具返回的数据字段映射到状态上下文字段。
    """
    
    CONTEXT_MAPPINGS = {
        "baseinfo": {"server": "server", "os": "os", "ip": "ip", "domain": "domain", "title": "title", "headers": "headers"},
        "cms_identify": {"cms": "cms"},
        "portscan": {"open_ports": "open_ports"},
        "waf_detect": {"waf": "waf"},
        "cdn_detect": {"cdn": "is_cdn", "has_cdn": "has_cdn"},
        "subdomain_scan": {"subdomains": "subdomains"},
        "webside_scan": {"side_domains": "side_domains"},
        "iplocating": {"location": "location"},
        "infoleak_scan": {"leaks": "leaks"},
        "dirscan": {"directories": "directories"}
    }
    
    @classmethod
    def update_context(cls, state: AgentState, tool_name: str, data: Dict[str, Any]) -> None:
        """
        根据工具名称更新目标上下文
        
        Args:
            state: Agent状态对象
            tool_name: 工具名称
            data: 工具返回的数据字典
        """
        if not data or not isinstance(data, dict):
            logger.warning(f"工具 {tool_name} 返回数据无效")
            return
        
        if tool_name not in cls.CONTEXT_MAPPINGS:
            logger.debug(f"工具 {tool_name} 无上下文映射配置")
            return
        
        mapping = cls.CONTEXT_MAPPINGS[tool_name]
        for state_key, data_key in mapping.items():
            value = data.get(data_key)
            if value is not None:
                state.update_context(state_key, value)
                logger.debug(f"更新上下文: {state_key} = {value}")


class ProgressCalculator:
    """
    进度计算器
    
    统一管理进度计算逻辑，提供多种进度计算方法。
    """
    
    @staticmethod
    def calculate_progress(completed: int, total: int) -> int:
        """
        计算百分比进度
        
        Args:
            completed: 已完成数量
            total: 总数量
            
        Returns:
            int: 进度百分比（0-100）
        """
        if total <= 0:
            return 0
        return min(100, int((completed / total) * 100))
    
    @staticmethod
    def calculate_stage_progress(
        completed_tasks: List[str], 
        planned_tasks: List[str], 
        current_task: Optional[str] = None
    ) -> int:
        """
        计算阶段进度
        
        Args:
            completed_tasks: 已完成任务列表
            planned_tasks: 计划任务列表
            current_task: 当前任务（可选）
            
        Returns:
            int: 阶段进度百分比
        """
        completed = len(completed_tasks)
        remaining = len(planned_tasks)
        total = completed + remaining
        return ProgressCalculator.calculate_progress(completed, total)


class ErrorHandler:
    """
    错误处理器
    
    统一管理错误处理逻辑，提供标准化的错误记录和状态更新方法。
    """
    
    @staticmethod
    def handle_tool_error(
        state: AgentState, 
        tool_name: str, 
        error: Exception, 
        step_number: Optional[int] = None
    ) -> None:
        """
        处理工具执行错误
        
        Args:
            state: Agent状态对象
            tool_name: 工具名称
            error: 异常对象
            step_number: 执行步骤号（可选）
        """
        error_msg = str(error)
        logger.error(f"[{state.task_id}] ❌ 工具 {tool_name} 执行错误: {error_msg}")
        state.add_error(f"工具执行错误 {tool_name}: {error_msg}")
        
        if step_number is not None:
            state.update_execution_step(
                step_number, 
                result={"error": error_msg}, 
                status="failed", 
                state_transitions=["failed", "error"]
            )
    
    @staticmethod
    def handle_tool_not_found(state: AgentState, tool_name: str) -> None:
        """
        处理工具未找到错误
        
        Args:
            state: Agent状态对象
            tool_name: 工具名称
        """
        logger.warning(f"[{state.task_id}] ⚠️ 工具未注册: {tool_name}")
        state.add_error(f"工具未注册: {tool_name}")


class POCTaskHelper:
    """
    POC任务辅助类
    
    统一管理POC任务的补充和获取逻辑，根据CMS类型和开放端口智能推荐POC任务。
    """
    
    @staticmethod
    def get_poc_tasks_from_context(state: AgentState) -> List[str]:
        """
        根据目标上下文获取POC任务列表
        
        Args:
            state: Agent状态对象
            
        Returns:
            List[str]: POC任务名称列表
        """
        poc_tasks = set()
        
        cms = state.target_context.get("cms", "").lower()
        if cms:
            cms_pocs = POCAdapter.get_poc_by_cms(cms)
            poc_tasks.update(cms_pocs)
        
        open_ports = state.target_context.get("open_ports", [])
        for port in open_ports:
            port_pocs = POCAdapter.get_poc_by_port(port)
            poc_tasks.update(port_pocs)
        
        return list(poc_tasks)
    
    @staticmethod
    def supplement_poc_tasks(state: AgentState) -> List[str]:
        """
        基于上下文补充POC任务（排除已完成和已计划的任务）
        
        Args:
            state: Agent状态对象
            
        Returns:
            List[str]: 需要补充的POC任务列表
        """
        supplement_tasks = []
        all_poc_tasks = POCTaskHelper.get_poc_tasks_from_context(state)
        
        for poc in all_poc_tasks:
            if poc not in state.completed_tasks and poc not in state.planned_tasks:
                supplement_tasks.append(poc)
                logger.info(f"[{state.task_id}] ➕ 补充POC任务: {poc}")
        
        return supplement_tasks


class ToolCategoryHelper:
    """
    工具分类辅助类
    
    从工具注册表动态获取不同分类的工具列表，替代硬编码的工具列表。
    """
    
    @staticmethod
    def get_info_collection_tools() -> List[str]:
        """
        获取信息收集工具列表
        
        Returns:
            List[str]: 信息收集工具名称列表
        """
        plugin_tools = registry.get_tools_by_category("plugin")
        return plugin_tools
    
    @staticmethod
    def get_vuln_scan_tools() -> List[str]:
        """
        获取漏洞扫描工具列表
        
        Returns:
            List[str]: 漏洞扫描工具名称列表
        """
        vuln_tools = registry.get_tools_by_category("vuln_scan")
        return vuln_tools
    
    @staticmethod
    def get_poc_tools() -> List[str]:
        """
        获取POC工具列表
        
        Returns:
            List[str]: POC工具名称列表
        """
        poc_tools = registry.get_tools_by_category("poc")
        return poc_tools


# ============================================================================
# 基类定义
# ============================================================================

class BasePlanningNode(ABC):
    """
    规划节点基类
    
    提供统一的规划逻辑框架，支持LLM增强规划和规则化规划两种模式。
    子类需要实现具体的规划逻辑。
    """
    
    def __init__(self, stage: NodeStage = NodeStage.INFO_COLLECTION):
        """
        初始化规划节点
        
        Args:
            stage: 节点阶段
        """
        self.priority_manager = TaskPriorityManager()
        self.stage = stage
        self._init_llm()
        logger.info(f"📋 {self.__class__.__name__} 初始化完成 | 阶段: {stage.value}")
    
    def _init_llm(self) -> None:
        """初始化LLM（如果启用）"""
        self.llm = None
        self.use_llm = False
        
        if agent_config.ENABLE_LLM_PLANNING:
            self.llm = ChatOpenAI(
                model=agent_config.MODEL_ID,
                temperature=0,
                api_key=agent_config.OPENAI_API_KEY,
                base_url=agent_config.OPENAI_BASE_URL
            )
            self.use_llm = True
    
    async def __call__(self, state: AgentState) -> AgentState:
        """
        执行规划
        
        Args:
            state: Agent状态对象
            
        Returns:
            AgentState: 更新后的状态对象
        """
        logger.info(f"[{state.task_id}] 📋 开始{self.stage.value}任务规划 | 目标: {state.target} | 当前上下文: {len(state.target_context)} 项")
        
        node_index = state.start_node_recording(
            f"{self.stage.value}_planning",
            "planning",
            {"target": state.target, "stage": self.stage.value}
        )
        
        state.update_stage_status(self.stage.value, "running", "planning", 10, f"规划{self.stage.value}任务")
        
        try:
            logger.debug(f"[{state.task_id}] 📝 开始调用 _plan_tasks 方法")
            tasks = await self._plan_tasks(state)
            logger.debug(f"[{state.task_id}] 📝 原始规划任务: {tasks}")
            
            tasks = self._filter_valid_tasks(tasks)
            logger.debug(f"[{state.task_id}] 📝 过滤后有效任务: {tasks}")
            
            state.planned_tasks = tasks
            state.current_task = tasks[0] if tasks else None
            
            logger.info(f"[{state.task_id}] ✅ 任务规划完成 | 任务数: {len(tasks)} | 任务列表: {tasks}")
            state.update_stage_status(self.stage.value, "running", "executing", 30, f"规划了 {len(tasks)} 个任务")
            
            state.add_execution_step(f"{self.stage.value}_planning", {"tasks": tasks}, "success", step_type="planning")
            
            state.complete_node_recording(
                node_index,
                output_data={"tasks": tasks, "task_count": len(tasks)},
                metadata={"stage": self.stage.value}
            )
            
        except Exception as e:
            logger.error(f"[{state.task_id}] ❌ 任务规划失败 | 错误类型: {type(e).__name__} | 错误信息: {str(e)}", exc_info=True)
            state.add_error(f"任务规划失败: {str(e)}")
            
            state.fail_node_recording(str(e), node_index, output_data={"error": str(e)})
            
            fallback_tasks = self._get_fallback_tasks()
            state.planned_tasks = fallback_tasks
            state.current_task = fallback_tasks[0] if fallback_tasks else None
            
            logger.warning(f"[{state.task_id}] ⚠️ 使用备用任务列表 | 任务数: {len(fallback_tasks)} | 任务列表: {fallback_tasks}")
            state.update_stage_status(self.stage.value, "failed", "error", 0, f"规划失败，使用默认任务")
        
        return state
    
    @abstractmethod
    async def _plan_tasks(self, state: AgentState) -> List[str]:
        """规划任务列表（子类实现）"""
        pass
    
    @abstractmethod
    def _get_fallback_tasks(self) -> List[str]:
        """获取备用任务列表（子类实现）"""
        pass
    
    @abstractmethod
    def _get_valid_tools(self) -> List[str]:
        """获取有效工具列表（子类实现）"""
        pass
    
    def _filter_valid_tasks(self, tasks: List[str]) -> List[str]:
        """
        过滤出有效的任务
        
        Args:
            tasks: 原始任务列表
            
        Returns:
            List[str]: 有效任务列表
        """
        valid_tools = set(self._get_valid_tools())
        return [t for t in tasks if t in valid_tools]


class BaseToolExecutionNode(ABC):
    """
    工具执行节点基类
    
    提供统一的工具执行逻辑框架，包含并发控制、错误处理、结果处理等通用功能。
    子类需要实现具体的工具执行和结果处理逻辑。
    """
    
    def __init__(self, stage: NodeStage = NodeStage.INFO_COLLECTION, max_concurrent: int = None):
        """
        初始化工具执行节点
        
        Args:
            stage: 节点阶段
            max_concurrent: 最大并发数
        """
        self.stage = stage
        self.semaphore = asyncio.Semaphore(max_concurrent or agent_config.MAX_CONCURRENT_TOOLS)
        logger.info(f"🔧 {self.__class__.__name__} 初始化完成 | 阶段: {stage.value} | 最大并发: {max_concurrent or agent_config.MAX_CONCURRENT_TOOLS}")
    
    async def __call__(self, state: AgentState) -> AgentState:
        """
        执行工具
        
        Args:
            state: Agent状态对象
            
        Returns:
            AgentState: 更新后的状态对象
        """
        if not state.current_task:
            logger.info(f"[{state.task_id}] ⏹️ 没有待执行任务 | 已完成: {len(state.completed_tasks)} | 待执行: {len(state.planned_tasks)}")
            return state
        
        task = state.current_task
        logger.info(f"[{state.task_id}] 🔧 开始执行工具 | 工具: {task} | 目标: {state.target} | 阶段: {self.stage.value}")
        
        progress = ProgressCalculator.calculate_stage_progress(state.completed_tasks, state.planned_tasks, state.current_task)
        logger.debug(f"[{state.task_id}] 📊 当前进度: {progress}%")
        
        node_index = state.start_node_recording(
            task,
            "tool_execution",
            {"target": state.target, "tool_name": task, "stage": self.stage.value}
        )
        
        step_number = state.add_execution_step_start(
            task,
            step_type="tool_execution",
            input_params={"target": state.target, "tool_name": task, "stage": self.stage.value},
            processing_logic=f"执行{task}工具"
        )
        logger.debug(f"[{state.task_id}] 📝 创建执行步骤 | 步骤号: {step_number}")
        
        try:
            logger.debug(f"[{state.task_id}] 🔄 获取信号量锁，准备执行工具")
            async with self.semaphore:
                logger.debug(f"[{state.task_id}] 🔒 获取信号量锁成功，开始执行工具: {task}")
                result = await self._execute_tool(state, task)
                logger.debug(f"[{state.task_id}] 📦 工具执行返回 | 工具: {task} | 成功: {result.success if hasattr(result, 'success') else 'N/A'}")
                
                if result.success:
                    await self._handle_success(state, task, result, step_number)
                    state.complete_node_recording(
                        node_index,
                        output_data={"success": True, "result_keys": list(result.keys()) if isinstance(result, dict) else []},
                        metadata={"tool_name": task, "stage": self.stage.value}
                    )
                else:
                    await self._handle_failure(state, task, result, step_number)
                    state.fail_node_recording(
                        result.get("error", "Unknown error") if isinstance(result, dict) else "Unknown error",
                        node_index,
                        output_data={"success": False}
                    )
                    
        except ValueError as e:
            logger.warning(f"[{state.task_id}] ⚠️ 工具未注册 | 工具: {task} | 错误: {str(e)}")
            ErrorHandler.handle_tool_not_found(state, task)
            state.fail_node_recording(f"Tool not registered: {task}", node_index)
            self._mark_task_completed(state, task)
            
        except Exception as e:
            logger.error(f"[{state.task_id}] ❌ 工具执行异常 | 工具: {task} | 错误类型: {type(e).__name__} | 错误: {str(e)}", exc_info=True)
            ErrorHandler.handle_tool_error(state, task, e, step_number)
            state.fail_node_recording(str(e), node_index, output_data={"exception_type": type(e).__name__})
            self._mark_task_completed(state, task)
        
        return state
    
    @abstractmethod
    async def _execute_tool(self, state: AgentState, tool_name: str):
        """执行具体工具（子类实现）"""
        pass
    
    @abstractmethod
    async def _handle_success(self, state: AgentState, tool_name: str, result, step_number: int):
        """处理执行成功（子类实现）"""
        pass
    
    @abstractmethod
    async def _handle_failure(self, state: AgentState, tool_name: str, result, step_number: int):
        """处理执行失败（子类实现）"""
        pass
    
    def _mark_task_completed(self, state: AgentState, task: str) -> None:
        """
        标记任务完成
        
        Args:
            state: Agent状态对象
            task: 任务名称
        """
        if task in state.planned_tasks:
            state.planned_tasks.remove(task)
        state.completed_tasks.append(task)
        state.current_task = state.planned_tasks[0] if state.planned_tasks else None
    
    def _update_progress(self, state: AgentState, message: str = None) -> None:
        """
        更新进度
        
        Args:
            state: Agent状态对象
            message: 进度消息
        """
        progress = ProgressCalculator.calculate_stage_progress(state.completed_tasks, state.planned_tasks)
        msg = message or "执行任务中"
        state.update_stage_status(self.stage.value, "running", "executing", progress, msg)
    
    def _handle_retry(self, state: AgentState, tool_name: str, step_number: int, error_msg: str) -> bool:
        """
        处理重试逻辑
        
        Args:
            state: Agent状态对象
            tool_name: 工具名称
            step_number: 步骤号
            error_msg: 错误消息
            
        Returns:
            bool: 是否应该继续重试
        """
        state.increment_retry()
        
        if state.retry_count < agent_config.MAX_RETRIES:
            logger.warning(f"[{state.task_id}] 🔄 工具 {tool_name} 重试 {state.retry_count}/{agent_config.MAX_RETRIES}")
            return True
        else:
            logger.error(f"[{state.task_id}] ❌ 工具 {tool_name} 达到最大重试次数")
            self._mark_task_completed(state, tool_name)
            state.reset_retry()
            state.update_execution_step(step_number, status="failed", state_transitions=["failed", "max_retries_reached"])
            return False


class BaseResultVerificationNode(ABC):
    """
    结果验证节点基类
    
    提供统一的结果验证逻辑框架，检查任务完成状态并决定下一步操作。
    """
    
    def __init__(self, stage: NodeStage = NodeStage.INFO_COLLECTION):
        """
        初始化结果验证节点
        
        Args:
            stage: 节点阶段
        """
        self.stage = stage
        logger.info(f"🔍 {self.__class__.__name__} 初始化完成 | 阶段: {stage.value}")
    
    async def __call__(self, state: AgentState) -> AgentState:
        """
        验证结果
        
        Args:
            state: Agent状态对象
            
        Returns:
            AgentState: 更新后的状态对象
        """
        logger.info(f"[{state.task_id}] 🔍 开始验证{self.stage.value}结果 | 已完成任务: {len(state.completed_tasks)} | 待执行任务: {len(state.planned_tasks)}")
        
        node_index = state.start_node_recording(
            f"{self.stage.value}_verification",
            "verification",
            {"completed_tasks": len(state.completed_tasks), "planned_tasks": len(state.planned_tasks)}
        )
        
        await self._verify_results(state)
        
        if not state.planned_tasks:
            logger.info(f"[{state.task_id}] ✅ 所有{self.stage.value}任务已完成 | 总计完成: {len(state.completed_tasks)} 个任务")
            state.update_stage_status(self.stage.value, "completed", "完成", 100, f"完成 {len(state.completed_tasks)} 个任务")
            state.complete_node_recording(
                node_index,
                output_data={"all_completed": True, "total_completed": len(state.completed_tasks)},
                metadata={"stage": self.stage.value}
            )
        else:
            state.current_task = state.planned_tasks[0]
            logger.info(f"[{state.task_id}] 📋 待执行任务 | 数量: {len(state.planned_tasks)} | 下一个任务: {state.current_task}")
            state.complete_node_recording(
                node_index,
                output_data={"all_completed": False, "remaining_tasks": len(state.planned_tasks), "next_task": state.current_task},
                metadata={"stage": self.stage.value}
            )
        
        return state
    
    async def _verify_results(self, state: AgentState) -> None:
        """
        验证结果（子类可重写）
        
        默认实现为空，子类可根据需要重写。
        """
        pass


# ============================================================================
# 环境感知节点
# ============================================================================

class EnvironmentAwarenessNode:
    """
    环境感知节点
    
    分析目标特征，初始化扫描环境，为后续任务规划提供基础信息。
    """
    
    def __init__(self):
        logger.info("🌍 环境感知节点初始化")
    
    async def __call__(self, state: AgentState) -> AgentState:
        """
        执行环境感知
        
        Args:
            state: Agent状态对象
            
        Returns:
            AgentState: 更新后的状态对象
        """
        logger.info(f"[{state.task_id}] 🌍 开始环境感知 | 目标: {state.target}")
        
        node_index = state.start_node_recording(
            "environment_awareness",
            "awareness",
            {"target": state.target}
        )
        
        state.update_stage_status("environment_awareness", "running", "感知中", 5, "分析目标特征")
        
        try:
            target_type = self._detect_target_type(state.target)
            state.update_context("target_type", target_type)
            
            state.add_execution_step(
                "environment_awareness",
                {"target": state.target, "target_type": target_type},
                "success",
                step_type="awareness"
            )
            
            logger.info(f"[{state.task_id}] ✅ 环境感知完成 | 目标类型: {target_type}")
            state.update_stage_status("environment_awareness", "completed", "完成", 10, "环境感知完成")
            
            state.complete_node_recording(
                node_index,
                output_data={"target_type": target_type},
                metadata={"target": state.target}
            )
            
        except Exception as e:
            logger.error(f"[{state.task_id}] ❌ 环境感知失败: {str(e)}")
            state.add_error(f"环境感知失败: {str(e)}")
            state.fail_node_recording(str(e), node_index)
        
        return state
    
    def _detect_target_type(self, target: str) -> str:
        """
        检测目标类型
        
        Args:
            target: 目标地址
            
        Returns:
            str: 目标类型（url/ip/domain）
        """
        if target.startswith(("http://", "https://")):
            return "url"
        elif self._is_ip(target):
            return "ip"
        else:
            return "domain"
    
    def _is_ip(self, target: str) -> bool:
        """
        检查是否为IP地址
        
        Args:
            target: 目标地址
            
        Returns:
            bool: 是否为IP地址
        """
        parts = target.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False


# ============================================================================
# 任务规划节点
# ============================================================================

class TaskPlanningNode(BasePlanningNode):
    """
    任务规划节点
    
    根据用户需求和目标特征，生成扫描任务计划。
    支持LLM增强规划和规则化规划两种模式。
    """
    
    def __init__(self):
        super().__init__(stage=NodeStage.INFO_COLLECTION)
        if self.use_llm:
            logger.info("🤖 启用LLM增强任务规划")
        else:
            logger.info("📋 使用规则化任务规划")
    
    async def _plan_tasks(self, state: AgentState) -> List[str]:
        """规划任务"""
        if self.use_llm:
            return await self._llm_planning(state)
        return await self._rule_based_planning(state)
    
    def _get_fallback_tasks(self) -> List[str]:
        return agent_config.DEFAULT_SCAN_TASKS.copy()
    
    def _get_valid_tools(self) -> List[str]:
        return [t["name"] for t in registry.list_tools()]
    
    async def _rule_based_planning(self, state: AgentState) -> List[str]:
        """
        规则化任务规划
        
        Args:
            state: Agent状态对象
            
        Returns:
            List[str]: 任务列表
        """
        tasks = agent_config.DEFAULT_SCAN_TASKS.copy()
        
        if state.target_context:
            poc_tasks = POCTaskHelper.get_poc_tasks_from_context(state)
            for poc in poc_tasks:
                if poc not in tasks:
                    tasks.append(poc)
        
        return tasks
    
    async def _llm_planning(self, state: AgentState) -> List[str]:
        """
        LLM增强任务规划（增强版）
        
        使用大语言模型智能规划扫描任务序列。
        整合多种上下文信息，实现智能化的任务规划。
        
        Args:
            state: Agent状态对象
            
        Returns:
            List[str]: 任务列表
        """
        available_tools = registry.list_tools()
        tools_desc = self._format_tools_description(available_tools)
        
        context_info = self._build_context_info(state)
        
        system_prompt = self._build_llm_prompt()
        
        user_prompt_parts = [f"目标: {state.target}"]
        
        if state.user_requirement:
            user_prompt_parts.append(f"\n用户需求: {state.user_requirement}")
        
        if state.target_context:
            user_prompt_parts.append(f"\n目标特征: {json.dumps(state.target_context, ensure_ascii=False)}")
        
        if state.completed_tasks:
            user_prompt_parts.append(f"\n已完成任务: {', '.join(state.completed_tasks)}")
        
        if state.execution_history:
            recent_count = min(3, len(state.execution_history))
            user_prompt_parts.append(f"\n最近执行步骤数: {recent_count}")
        
        if state.vulnerabilities:
            user_prompt_parts.append(f"\n已发现漏洞数: {len(state.vulnerabilities)}")
        
        user_prompt = "\n".join(user_prompt_parts) + context_info
        
        try:
            logger.info(f"[{state.task_id}] 📝 LLM规划输入 - 目标: {state.target}")
            logger.debug(f"[{state.task_id}] 📝 上下文信息长度: {len(context_info)} 字符")
            logger.debug(f"[{state.task_id}] 📝 用户需求: {state.user_requirement or '无'}")
            logger.debug(f"[{state.task_id}] 📝 已完成任务: {state.completed_tasks}")
            logger.debug(f"[{state.task_id}] 📝 执行历史条数: {len(state.execution_history)}")
            logger.debug(f"[{state.task_id}] 📝 已发现漏洞数: {len(state.vulnerabilities)}")
            
            prompt = ChatPromptTemplate.from_messages([("system", system_prompt), ("human", user_prompt)])
            chain = prompt | self.llm | JsonOutputParser(pydantic_object=PlanningResponse)
            result = await chain.ainvoke({"tools": tools_desc, "target": state.target})
            
            logger.info(f"[{state.task_id}] 📝 LLM规划结果: {result}")
            
            tasks = self._extract_tasks_from_result(result)
            
            tasks = self._remove_completed_tasks(tasks, state.completed_tasks)
            
            if tasks:
                if isinstance(result, dict) and 'reasoning' in result:
                    logger.info(f"[{state.task_id}] 📝 规划理由: {result['reasoning']}")
                return tasks
            
            raise ValueError("无法从LLM结果中提取有效任务列表")
                
        except Exception as e:
            logger.error(f"[{state.task_id}] ❌ LLM规划失败: {str(e)}，切换到规则化规划")
            return await self._rule_based_planning(state)
    
    def _remove_completed_tasks(self, tasks: List[str], completed_tasks: List[str]) -> List[str]:
        """
        从任务列表中移除已完成的任务
        
        Args:
            tasks: 原始任务列表
            completed_tasks: 已完成任务列表
            
        Returns:
            List[str]: 过滤后的任务列表
        """
        completed_set = set(completed_tasks)
        filtered_tasks = [task for task in tasks if task not in completed_set]
        
        if len(filtered_tasks) < len(tasks):
            removed_count = len(tasks) - len(filtered_tasks)
            logger.info(f"移除了 {removed_count} 个已完成的任务")
        
        return filtered_tasks
    
    def _format_tools_description(self, tools: List[Dict]) -> str:
        """
        格式化工具描述
        
        Args:
            tools: 工具列表
            
        Returns:
            str: 格式化后的工具描述
        """
        return "\n".join([f"- {t['name']}: {t['description']}" for t in tools])
    
    def _build_context_info(self, state: AgentState) -> str:
        """
        构建完整的上下文信息（增强版）
        
        整合多种数据源：
        - 用户需求 (user_requirement)
        - 目标上下文 (target_context)
        - 执行历史 (execution_history)
        - 已完成任务 (completed_tasks)
        - 已发现漏洞 (vulnerabilities)
        
        Args:
            state: Agent状态对象
            
        Returns:
            str: 完整的上下文信息字符串
        """
        context_sections = []
        
        user_req_info = self._build_user_requirement_info(state)
        if user_req_info:
            context_sections.append(user_req_info)
        
        target_ctx_info = self._build_target_context_info(state)
        if target_ctx_info:
            context_sections.append(target_ctx_info)
        
        completed_info = self._build_completed_tasks_info(state)
        if completed_info:
            context_sections.append(completed_info)
        
        history_info = self._build_execution_history_info(state)
        if history_info:
            context_sections.append(history_info)
        
        vuln_info = self._build_vulnerabilities_info(state)
        if vuln_info:
            context_sections.append(vuln_info)
        
        if context_sections:
            return "\n\n" + "\n\n".join(context_sections)
        return ""
    
    def _build_user_requirement_info(self, state: AgentState) -> str:
        """
        构建用户需求信息
        
        Args:
            state: Agent状态对象
            
        Returns:
            str: 用户需求信息字符串
        """
        if not state.user_requirement:
            return ""
        
        return f"""## 用户需求
{state.user_requirement}

**重要提示**: 请根据用户的具体需求调整扫描策略和任务优先级。"""
    
    def _build_target_context_info(self, state: AgentState) -> str:
        """
        构建目标上下文信息
        
        Args:
            state: Agent状态对象
            
        Returns:
            str: 目标上下文信息字符串
        """
        if not state.target_context:
            return ""
        
        context_parts = []
        for key, value in state.target_context.items():
            if value:
                if isinstance(value, list):
                    formatted_value = ", ".join(str(v) for v in value) if value else "无"
                elif isinstance(value, dict):
                    formatted_value = json.dumps(value, ensure_ascii=False)
                else:
                    formatted_value = str(value)
                context_parts.append(f"  - {key}: {formatted_value}")
        
        if context_parts:
            return f"""## 目标上下文信息
{chr(10).join(context_parts)}"""
        return ""
    
    def _build_completed_tasks_info(self, state: AgentState) -> str:
        """
        构建已完成任务信息
        
        Args:
            state: Agent状态对象
            
        Returns:
            str: 已完成任务信息字符串
        """
        if not state.completed_tasks:
            return ""
        
        tasks_str = ", ".join(state.completed_tasks)
        return f"""## 已完成的任务
已执行: {tasks_str}

**注意**: 请避免重复规划已完成的任务，除非有特殊需要。"""
    
    def _build_execution_history_info(self, state: AgentState, max_items: int = 5) -> str:
        """
        构建执行历史信息（用于优化后续规划）
        
        Args:
            state: Agent状态对象
            max_items: 最大显示条数
            
        Returns:
            str: 执行历史信息字符串
        """
        if not state.execution_history:
            return ""
        
        recent_history = state.execution_history[-max_items:] if len(state.execution_history) > max_items else state.execution_history
        
        history_parts = []
        for step in recent_history:
            task = step.get("task", "未知任务")
            status = step.get("status", "未知状态")
            result_summary = self._summarize_step_result(step)
            
            history_parts.append(f"  - {task}: {status}")
            if result_summary:
                history_parts.append(f"    结果: {result_summary}")
        
        if history_parts:
            history_str = "\n".join(history_parts)
            return f"""## 最近执行历史（用于优化后续规划）
{history_str}

**规划建议**: 请根据执行历史中的成功/失败情况，优化后续任务的规划。"""
        return ""
    
    def _summarize_step_result(self, step: Dict[str, Any]) -> str:
        """
        总结执行步骤的结果
        
        Args:
            step: 执行步骤字典
            
        Returns:
            str: 结果摘要
        """
        result = step.get("result", {})
        if not result:
            return ""
        
        if isinstance(result, dict):
            if "error" in result:
                return f"错误: {result['error']}"
            
            data = result.get("data", {})
            if isinstance(data, dict):
                keys = list(data.keys())[:3]
                if keys:
                    return f"获取数据: {', '.join(keys)}"
        
        return ""
    
    def _build_vulnerabilities_info(self, state: AgentState) -> str:
        """
        构建已发现漏洞信息
        
        Args:
            state: Agent状态对象
            
        Returns:
            str: 漏洞信息字符串
        """
        if not state.vulnerabilities:
            return ""
        
        vuln_parts = []
        for i, vuln in enumerate(state.vulnerabilities[:5], 1):
            cve = vuln.get("cve", "未知")
            severity = vuln.get("severity", "未知")
            details = vuln.get("details", "")[:50]
            vuln_parts.append(f"  {i}. {cve} (严重度: {severity})")
            if details:
                vuln_parts.append(f"     详情: {details}...")
        
        if vuln_parts:
            vuln_str = "\n".join(vuln_parts)
            total = len(state.vulnerabilities)
            return f"""## 已发现的漏洞（共 {total} 个）
{vuln_str}

**规划建议**: 请根据已发现的漏洞类型，优先规划相关的深度检测任务。"""
        return ""
    
    def _build_llm_prompt(self) -> str:
        """
        构建LLM规划提示词（增强版）
        
        提示词包含：
        - 角色定义
        - 可用工具列表
        - 执行规则和阶段划分
        - 上下文信息处理指导
        - 输出格式要求
        
        Returns:
            str: 提示词字符串
        """
        return """你是Web安全扫描专家，负责为目标规划最优扫描任务序列。

## 可用工具
{tools}

## 重要规则 - 必须遵守

### 1. 必须使用所有可用工具
- 你**必须**在计划中包含所有可用的工具，不能遗漏任何工具
- 每个工具都有其独特的安全检测价值，必须全部执行
- 如果某个工具不适用，也应在计划中列出，执行时会自动跳过

### 2. 执行顺序原则

**第一阶段：基础信息收集（必须全部执行）**
- baseinfo: 获取基础HTTP信息（必须）
- portscan: 端口扫描（必须）
- cms_identify: CMS识别（必须）
- waf_detect: WAF检测（必须）
- cdn_detect: CDN检测（必须）
- iplocating: IP地址定位（必须）

**第二阶段：深度信息收集（必须全部执行）**
- subdomain_scan: 子域名枚举（必须）
- webside_scan: 站点信息收集（必须）
- webweight_scan: 网站权重查询（必须）
- infoleak_scan: 信息泄露检测（必须）
- dirscan: 目录扫描（必须）
- crawler: Web爬虫（必须）

**第三阶段：漏洞扫描（必须全部执行）**
- sqli_scan: SQL注入扫描（必须）
- xss_scan: XSS漏洞扫描（必须）
- csrf_scan: CSRF漏洞扫描（必须）
- vuln_infoleak_scan: 敏感信息泄露扫描（必须）
- fileupload_scan: 文件上传漏洞扫描（必须）
- cmdi_scan: 命令注入扫描（必须）
- weakpass_scan: 弱口令扫描（必须）
- lfi_scan: 文件包含漏洞扫描（必须）
- ssrf_scan: SSRF漏洞扫描（必须）

**第四阶段：POC验证（根据端口和CMS选择）**
- 根据开放端口选择对应POC
- 根据识别的CMS选择对应POC

### 3. 上下文信息处理（重要）

你将收到以下上下文信息，请仔细分析并据此优化规划：

**用户需求**: 
- 如果用户有特定需求，优先满足用户需求
- 根据需求调整任务优先级和执行顺序
- 示例：用户关注SQL注入，则优先执行sqli_scan

**目标上下文信息**:
- CMS类型：根据CMS选择对应的漏洞扫描策略
- 开放端口：根据端口选择对应的POC验证
- WAF/CDN：调整扫描策略以绕过防护

**已完成的任务**:
- 避免重复规划已完成的任务
- 如果某些任务已完成，跳过这些任务

**执行历史**:
- 分析历史中的成功/失败情况
- 如果某些工具执行失败，考虑是否需要重试或调整策略
- 根据历史结果优化后续任务

**已发现的漏洞**:
- 根据已发现的漏洞类型，优先规划相关的深度检测任务
- 示例：发现SQL注入，优先执行数据库相关的深度扫描

### 4. 输出格式
返回JSON格式:
{{
  "plan": ["task1", "task2", ...],
  "reasoning": "规划理由说明（必须包含：如何响应用户需求、如何利用上下文信息、为什么选择这个顺序）"
}}

### 5. 示例输出
{{
  "plan": ["baseinfo", "portscan", "cms_identify", "waf_detect", "cdn_detect", "iplocating", "subdomain_scan", "webside_scan", "webweight_scan", "infoleak_scan", "dirscan", "crawler", "sqli_scan", "xss_scan", "csrf_scan", "vuln_infoleak_scan", "fileupload_scan", "cmdi_scan", "weakpass_scan", "lfi_scan", "ssrf_scan"],
  "reasoning": "执行完整的安全扫描流程，包含所有信息收集和漏洞检测工具。根据用户需求重点关注SQL注入检测，已识别目标为WordPress CMS，将优先执行相关漏洞扫描。"
}}

## 注意事项
- 计划必须包含所有可用工具（排除已完成的任务）
- 按照阶段顺序排列任务
- 不要遗漏任何安全检测工具
- 完整性比效率更重要
- 必须在reasoning中说明如何利用上下文信息"""
    
    def _extract_tasks_from_result(self, result: Any) -> List[str]:
        """
        从LLM结果中提取任务列表
        
        Args:
            result: LLM返回的结果
            
        Returns:
            List[str]: 任务列表
        """
        if result is None:
            return []
        
        if isinstance(result, PlanningResponse):
            return result.plan if isinstance(result.plan, list) else []
        
        if isinstance(result, dict):
            if 'plan' in result and isinstance(result['plan'], list):
                return result['plan']
            if all(isinstance(v, str) for v in result.values()):
                return list(result.values())
            return []
        
        if isinstance(result, list):
            return result if all(isinstance(item, str) for item in result) else []
        
        if isinstance(result, str):
            try:
                parsed = json.loads(result)
                return self._extract_tasks_from_result(parsed)
            except json.JSONDecodeError:
                return []
        
        logger.warning(f"无法识别的LLM结果类型: {type(result)}")
        return []


# ============================================================================
# 工具执行节点
# ============================================================================

class ToolExecutionNode(BaseToolExecutionNode):
    """
    工具执行节点
    
    执行当前规划的任务，调用相应的工具并更新状态。
    支持POC结果处理和漏洞记录。
    """
    
    def __init__(self):
        super().__init__(stage=NodeStage.INFO_COLLECTION)
    
    async def _execute_tool(self, state: AgentState, tool_name: str):
        """执行工具"""
        return await registry.call_tool(tool_name, state.target)
    
    async def _handle_success(self, state: AgentState, tool_name: str, result, step_number: int):
        """处理执行成功"""
        state.tool_results[tool_name] = result
        TargetContextUpdater.update_context(state, tool_name, result.get("data", {}))
        
        if tool_name.startswith("poc_"):
            self._process_poc_result(state, tool_name, result)
        
        self._mark_task_completed(state, tool_name)
        logger.info(f"[{state.task_id}] ✅ 工具 {tool_name} 执行完成")
        
        state.update_execution_step(
            step_number,
            result=result,
            status="success",
            output_data={"tool_status": result.get("status"), "has_data": "data" in result},
            state_transitions=["completed", "next_task"]
        )
        
        self._update_progress(state, f"完成 {tool_name}")
    
    async def _handle_failure(self, state: AgentState, tool_name: str, result, step_number: int):
        """处理执行失败"""
        error_msg = result.get("error", "未知错误")
        logger.error(f"[{state.task_id}] ❌ 工具 {tool_name} 执行失败: {error_msg}")
        state.add_error(f"工具执行失败 {tool_name}: {error_msg}")
        
        state.update_execution_step(step_number, result=result, status="failed", output_data={"error": error_msg}, state_transitions=["failed"])
        
        self._handle_retry(state, tool_name, step_number, error_msg)
    
    def _process_poc_result(self, state: AgentState, tool_name: str, result: Dict[str, Any]):
        """
        处理POC执行结果
        
        Args:
            state: Agent状态对象
            tool_name: 工具名称
            result: 执行结果
        """
        data = result.get("data", {})
        if data.get("vulnerable"):
            vuln_info = {
                "cve": tool_name.replace("poc_", ""),
                "target": state.target,
                "severity": self._get_severity(tool_name),
                "details": data.get("message", ""),
                "poc_name": tool_name
            }
            state.add_vulnerability(vuln_info)
            logger.warning(f"[{state.task_id}] 🚨 发现漏洞: {vuln_info}")
    
    def _get_severity(self, poc_name: str) -> str:
        """
        获取POC的严重度
        
        Args:
            poc_name: POC名称
            
        Returns:
            str: 严重度级别
        """
        poc_lower = poc_name.lower()
        severity_map = {
            "cve_2020_2551": "critical",
            "cve_2023_21839": "critical",
            "cve_2022_22965": "critical"
        }
        
        for key, severity in severity_map.items():
            if key in poc_lower:
                return severity
        
        return "high" if "cve" in poc_lower else "medium"


# ============================================================================
# 结果验证节点
# ============================================================================

class ResultVerificationNode(BaseResultVerificationNode):
    """
    结果验证节点
    
    验证扫描结果，根据上下文补充任务，决定是否继续执行。
    """
    
    def __init__(self):
        super().__init__(stage=NodeStage.INFO_COLLECTION)
    
    async def _verify_results(self, state: AgentState) -> None:
        """验证结果并补充任务"""
        supplement_tasks = POCTaskHelper.supplement_poc_tasks(state)
        for task in supplement_tasks:
            state.planned_tasks.append(task)
        
        state.add_execution_step("result_verification", {"planned_tasks": state.planned_tasks}, "success", step_type="result_verification")


# ============================================================================
# 漏洞分析节点
# ============================================================================

class VulnerabilityAnalysisNode:
    """
    漏洞分析节点
    
    分析发现的漏洞，进行去重、排序和严重度评估。
    """
    
    def __init__(self):
        from ..analyzers.vuln_analyzer import VulnerabilityAnalyzer
        self.analyzer = VulnerabilityAnalyzer()
        logger.info("🔍 漏洞分析节点初始化")
    
    async def __call__(self, state: AgentState) -> AgentState:
        """分析漏洞"""
        logger.info(f"[{state.task_id}] 🔍 开始漏洞分析 | 发现漏洞数: {len(state.vulnerabilities)} | 目标: {state.target}")
        
        node_index = state.start_node_recording(
            "vulnerability_analysis",
            "analysis",
            {"vulnerabilities_count": len(state.vulnerabilities), "target": state.target}
        )
        
        if not state.vulnerabilities:
            logger.info(f"[{state.task_id}] ✅ 未发现漏洞")
            state.add_execution_step("vulnerability_analysis", {"total": 0, "vulnerabilities": []}, "success", step_type="analysis")
            state.complete_node_recording(node_index, output_data={"total": 0, "vulnerabilities": []})
            return state
        
        try:
            logger.debug(f"[{state.task_id}] 📊 开始漏洞去重处理")
            unique_vulns = self.analyzer.deduplicate(state.vulnerabilities)
            logger.debug(f"[{state.task_id}] 📊 去重完成 | 原始: {len(state.vulnerabilities)} | 去重后: {len(unique_vulns)}")
            
            logger.debug(f"[{state.task_id}] 📊 开始按严重度排序")
            sorted_vulns = self.analyzer.sort_by_severity(unique_vulns)
            state.vulnerabilities = sorted_vulns
            
            severity_counts = {}
            for vuln in sorted_vulns:
                sev = vuln.get('severity', 'unknown')
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            logger.info(f"[{state.task_id}] ✅ 漏洞分析完成 | 总数: {len(sorted_vulns)} | 严重度分布: {severity_counts}")
            state.add_execution_step("vulnerability_analysis", {"total": len(sorted_vulns), "vulnerabilities": sorted_vulns}, "success", step_type="analysis")
            
            state.complete_node_recording(
                node_index,
                output_data={"total": len(sorted_vulns), "severity_distribution": severity_counts},
                metadata={"original_count": len(state.vulnerabilities), "deduplicated_count": len(unique_vulns)}
            )
        except Exception as e:
            logger.error(f"[{state.task_id}] ❌ 漏洞分析失败 | 错误类型: {type(e).__name__} | 错误: {str(e)}", exc_info=True)
            state.add_error(f"漏洞分析失败: {str(e)}")
            state.add_execution_step("vulnerability_analysis", {"total": len(state.vulnerabilities), "vulnerabilities": state.vulnerabilities, "error": str(e)}, "failed", step_type="analysis")
            state.fail_node_recording(str(e), node_index)
        
        return state


# ============================================================================
# 报告生成节点
# ============================================================================

class ReportGenerationNode:
    """
    报告生成节点
    
    使用增强版报告生成器，集成 AI 分析功能。
    """
    
    def __init__(self):
        from ..analyzers.enhanced_report_gen import EnhancedReportGenerator
        self.report_gen = EnhancedReportGenerator(auto_ai_analysis=True)
        logger.info("📄 报告生成节点初始化（增强版 + AI分析）")
    
    async def __call__(self, state: AgentState) -> AgentState:
        """生成报告"""
        logger.info(f"[{state.task_id}] 📄 开始生成扫描报告 | 目标: {state.target} | 漏洞数: {len(state.vulnerabilities)} | 已完成任务: {len(state.completed_tasks)}")
        
        node_index = state.start_node_recording(
            "report_generation",
            "report_generation",
            {"target": state.target, "vulnerabilities_count": len(state.vulnerabilities), "completed_tasks": len(state.completed_tasks)}
        )
        
        try:
            logger.debug(f"[{state.task_id}] 📝 调用增强版报告生成器（含AI分析）")
            reports = await self._generate_reports_with_ai(state)
            logger.debug(f"[{state.task_id}] 📝 报告生成完成 | 报告类型: {list(reports.keys())}")
            
            state.tool_results.update(reports)
            
            state.scan_summary = {
                "target": state.target,
                "vulnerabilities_count": len(state.vulnerabilities),
                "completed_tasks": len(state.completed_tasks),
                "errors_count": len(state.errors)
            }
            
            if "ai_analysis" in reports:
                state.ai_analysis = reports["ai_analysis"]
                logger.info(f"[{state.task_id}] 🧠 AI分析结果已集成到状态")
            
            if "final_report" in reports:
                state.report = reports["final_report"].get("summary", "")
            
            state.mark_complete()
            
            logger.info(f"[{state.task_id}] ✅ 报告生成完成 | 漏洞数: {len(state.vulnerabilities)} | 任务数: {len(state.completed_tasks)} | 错误数: {len(state.errors)}")
            state.add_execution_step("report_generation", reports, "success", step_type="report_generation", processing_logic="生成增强版扫描报告，集成AI分析结果")
            
            state.complete_node_recording(
                node_index,
                output_data={"report_types": list(reports.keys()), "vulnerabilities_count": len(state.vulnerabilities)},
                metadata={"has_ai_analysis": "ai_analysis" in reports}
            )
            
            state.complete_workflow_recording({
                "total_vulnerabilities": len(state.vulnerabilities),
                "total_tasks": len(state.completed_tasks),
                "total_errors": len(state.errors)
            })
            
        except Exception as e:
            logger.error(f"[{state.task_id}] ❌ 报告生成失败 | 错误类型: {type(e).__name__} | 错误: {str(e)}", exc_info=True)
            state.add_error(f"报告生成失败: {str(e)}")
            state.mark_complete()
            
            state.fail_node_recording(str(e), node_index)
            state.fail_workflow_recording(str(e))
        
        return state
    
    async def _generate_reports_with_ai(self, state: AgentState) -> Dict[str, Any]:
        """
        使用 AI 分析生成增强版报告
        
        Args:
            state: Agent状态对象
            
        Returns:
            Dict[str, Any]: 报告数据字典
        """
        try:
            report_data = await self.report_gen.generate_from_state(state, task_name=f"安全扫描 - {state.target}")
            
            json_report = self.report_gen.generate_json_report(report_data)
            html_report = self.report_gen.generate_html_report(report_data)
            
            reports = {
                "final_report": json.loads(json_report),
                "json_report": json_report,
                "html_report": html_report,
                "enhanced_report": {
                    "task_id": report_data.task_id,
                    "task_name": report_data.task_name,
                    "target": report_data.target.url,
                    "vulnerabilities_count": len(report_data.vulnerabilities),
                    "timing": {
                        "start_time": report_data.timing.start_time,
                        "end_time": report_data.timing.end_time,
                        "total_duration_ms": report_data.timing.total_duration_ms
                    },
                    "generated_at": datetime.now().isoformat()
                },
                "ai_analysis": {
                    "vulnerability_causes": report_data.ai_analysis.vulnerability_causes,
                    "exploitation_risks": report_data.ai_analysis.exploitation_risks,
                    "remediation_priorities": report_data.ai_analysis.remediation_priorities,
                    "business_impact": report_data.ai_analysis.business_impact,
                    "analysis_evidence": report_data.ai_analysis.analysis_evidence
                },
                "execution_trace": {
                    "task_id": report_data.task_id,
                    "execution_history": report_data.raw_data.get("execution_history", []),
                    "tool_flow": [
                        {"step_number": step.step_number, "tool_name": step.tool_name, "timestamp": step.timestamp}
                        for step in report_data.tool_execution_flow
                    ],
                    "graph_flow": {
                        "subgraphs": [
                            {
                                "subgraph_id": sg.subgraph_id,
                                "subgraph_name": sg.subgraph_name,
                                "nodes": [{"node_id": n.node_id, "node_name": n.node_name, "status": n.status} for n in sg.nodes]
                            }
                            for sg in report_data.graph_flow.subgraphs
                        ]
                    }
                }
            }
            
            logger.info(f"[{state.task_id}] 📊 报告生成统计 | 漏洞数: {len(report_data.vulnerabilities)} | 工具执行步骤: {len(report_data.tool_execution_flow)} | AI分析成因: {len(report_data.ai_analysis.vulnerability_causes)}")
            
            return reports
            
        except Exception as e:
            logger.error(f"[{state.task_id}] ❌ AI报告生成失败: {e}，使用简化报告")
            raise


# ============================================================================
# 漏洞扫描节点
# ============================================================================

class VulnerabilityScanNode:
    """
    漏洞扫描节点
    
    执行漏洞扫描插件，检测SQL注入、XSS、CSRF等漏洞。
    """
    
    def __init__(self):
        from backend.vulnerability_scan_plugins.manager import plugin_manager
        self.plugin_manager = plugin_manager
        logger.info("🔍 漏洞扫描节点初始化完成")
    
    async def __call__(self, state: AgentState) -> AgentState:
        """执行漏洞扫描"""
        logger.info(f"[{state.task_id}] 🔍 开始漏洞扫描 | 目标: {state.target}")
        state.update_stage_status("tool_execution", "running", "初始化", 10, "加载漏洞扫描插件")
        
        node_index = state.start_node_recording(
            "vulnerability_scan",
            "vuln_scan",
            {"target": state.target}
        )
        
        try:
            logger.debug(f"[{state.task_id}] 📦 加载漏洞扫描插件")
            self.plugin_manager.load_plugins_from_directory()
            
            loaded_plugins = self.plugin_manager.list_plugins(enabled_only=True)
            state.vuln_scan_plugins_loaded = [p.name for p in loaded_plugins]
            
            logger.info(f"[{state.task_id}] 📦 已加载 {len(loaded_plugins)} 个漏洞扫描插件 | 插件列表: {state.vuln_scan_plugins_loaded}")
            state.update_stage_status("tool_execution", "running", "扫描中", 30, f"使用 {len(loaded_plugins)} 个插件扫描")
            
            logger.debug(f"[{state.task_id}] 🔬 开始执行所有插件扫描")
            results = await self.plugin_manager.scan_all_async(
                target=state.target,
                plugin_names=state.vuln_scan_plugins_loaded,
                max_concurrent=2
            )
            logger.debug(f"[{state.task_id}] 🔬 扫描完成，开始聚合结果")
            
            aggregated = self.plugin_manager.aggregate_results(results)
            
            self._update_scan_results(state, aggregated)
            
            logger.info(f"[{state.task_id}] ✅ 漏洞扫描完成 | 发现漏洞: {aggregated['total_vulnerabilities']} 个 | 扫描耗时: {aggregated['scan_summary']['total_duration']:.2f}s")
            
            state.complete_node_recording(
                node_index,
                output_data={
                    "total_vulnerabilities": aggregated['total_vulnerabilities'],
                    "plugins_used": len(state.vuln_scan_plugins_loaded),
                    "scan_duration": aggregated['scan_summary']['total_duration']
                },
                metadata={"plugins": state.vuln_scan_plugins_loaded}
            )
            
        except Exception as e:
            logger.error(f"[{state.task_id}] ❌ 漏洞扫描失败 | 错误类型: {type(e).__name__} | 错误: {str(e)}", exc_info=True)
            state.add_error(f"漏洞扫描失败: {str(e)}")
            state.update_stage_status("tool_execution", "failed", "失败", 0, str(e))
            
            state.fail_node_recording(str(e), node_index)
        
        return state
    
    def _update_scan_results(self, state: AgentState, aggregated: Dict) -> None:
        """
        更新扫描结果
        
        Args:
            state: Agent状态对象
            aggregated: 聚合后的扫描结果
        """
        state.vuln_scan_results = aggregated
        state.vuln_scan_progress = 100
        state.vuln_scan_metadata = {
            "plugins_used": len(state.vuln_scan_plugins_loaded),
            "total_vulnerabilities": aggregated["total_vulnerabilities"],
            "scan_duration": aggregated["scan_summary"]["total_duration"]
        }
        
        for vuln in aggregated["vulnerabilities"]:
            state.add_vulnerability(vuln)
        
        state.update_stage_status("tool_execution", "completed", "完成", 100, f"发现 {aggregated['total_vulnerabilities']} 个漏洞")
        state.add_execution_step("vulnerability_scan", {"plugins_used": state.vuln_scan_plugins_loaded, "vulnerabilities_found": aggregated["total_vulnerabilities"], "scan_duration": aggregated["scan_summary"]["total_duration"]}, "success")


# ============================================================================
# 信息收集子图节点
# ============================================================================

class InfoTaskPlanningNode(BasePlanningNode):
    """
    信息收集任务规划节点
    
    规划信息收集阶段的任务，根据目标上下文动态调整任务列表。
    """
    
    def __init__(self):
        super().__init__(stage=NodeStage.INFO_COLLECTION)
    
    async def _plan_tasks(self, state: AgentState) -> List[str]:
        """规划信息收集任务"""
        tasks = ["baseinfo", "portscan", "cms_identify", "waf_detect", "cdn_detect"]
        
        if state.target_context:
            cms = state.target_context.get("cms", "").lower()
            if cms:
                tasks.append("subdomain_scan")
        
        return tasks
    
    def _get_fallback_tasks(self) -> List[str]:
        return ["baseinfo", "portscan", "cms_identify"]
    
    def _get_valid_tools(self) -> List[str]:
        return ToolCategoryHelper.get_info_collection_tools()


class InfoToolExecutionNode(BaseToolExecutionNode):
    """
    信息收集工具执行节点
    
    执行信息收集工具，更新目标上下文。
    """
    
    def __init__(self):
        super().__init__(stage=NodeStage.INFO_COLLECTION)
    
    async def _execute_tool(self, state: AgentState, tool_name: str):
        """执行信息收集工具"""
        tool_wrapper = registry.get_tool(tool_name)
        if tool_wrapper is None:
            raise ValueError(f"工具未注册: {tool_name}")
        return await tool_wrapper.execute(state.target)
    
    async def _handle_success(self, state: AgentState, tool_name: str, result, step_number: int):
        """处理执行成功"""
        state.tool_results[tool_name] = result.data
        
        if result.data:
            TargetContextUpdater.update_context(state, tool_name, result.data)
        
        self._mark_task_completed(state, tool_name)
        logger.info(f"[{state.task_id}] ✅ 工具执行成功: {tool_name}")
        
        state.update_execution_step(step_number, result=result.data, status="success", state_transitions=["completed"])
        self._update_progress(state, f"完成 {tool_name}")
    
    async def _handle_failure(self, state: AgentState, tool_name: str, result, step_number: int):
        """处理执行失败"""
        error_msg = result.error if hasattr(result, 'error') else "未知错误"
        logger.warning(f"[{state.task_id}] ⚠️ 工具执行失败: {tool_name} - {error_msg}")
        state.add_error(f"工具执行失败: {tool_name} - {error_msg}")
        
        state.update_execution_step(step_number, result={"error": error_msg}, status="failed", state_transitions=["failed"])
        self._mark_task_completed(state, tool_name)


class InfoResultVerificationNode(BaseResultVerificationNode):
    """
    信息收集结果验证节点
    
    验证信息收集结果，补充必要的POC任务。
    """
    
    def __init__(self):
        super().__init__(stage=NodeStage.INFO_COLLECTION)
    
    async def _verify_results(self, state: AgentState) -> None:
        """验证信息收集结果并补充POC任务"""
        supplement_tasks = POCTaskHelper.supplement_poc_tasks(state)
        for task in supplement_tasks:
            state.planned_tasks.append(task)


# ============================================================================
# 漏洞扫描子图节点
# ============================================================================

class VulnScanPlanningNode(BasePlanningNode):
    """
    漏洞扫描任务规划节点
    
    规划漏洞扫描阶段的任务，根据CMS类型选择合适的扫描策略。
    """
    
    def __init__(self):
        super().__init__(stage=NodeStage.VULN_SCAN)
    
    async def _plan_tasks(self, state: AgentState) -> List[str]:
        """规划漏洞扫描任务"""
        tasks = ["sqli_scan", "xss_scan", "csrf_scan", "vuln_infoleak_scan"]
        
        cms = state.target_context.get("cms", "").lower()
        cms_task_map = {
            "wordpress": ["sqli_scan", "xss_scan"],
            "drupal": ["sqli_scan", "xss_scan"],
            "joomla": ["sqli_scan", "xss_scan"]
        }
        
        if cms in cms_task_map:
            tasks = cms_task_map[cms]
        
        return tasks
    
    def _get_fallback_tasks(self) -> List[str]:
        return ToolCategoryHelper.get_vuln_scan_tools()
    
    def _get_valid_tools(self) -> List[str]:
        return ToolCategoryHelper.get_vuln_scan_tools()


class VulnToolExecutionNode(BaseToolExecutionNode):
    """
    漏洞扫描工具执行节点
    
    执行漏洞扫描工具，记录发现的漏洞。
    """
    
    def __init__(self):
        super().__init__(stage=NodeStage.VULN_SCAN)
    
    async def _execute_tool(self, state: AgentState, tool_name: str):
        """执行漏洞扫描工具"""
        if tool_name not in registry.tools:
            raise ValueError(f"工具未注册: {tool_name}")
        
        tool_wrapper = registry.tools[tool_name]
        return await tool_wrapper.execute(state.target)
    
    async def _handle_success(self, state: AgentState, tool_name: str, result, step_number: int):
        """处理执行成功"""
        state.tool_results[tool_name] = result.data
        
        self._extract_vulnerabilities(state, tool_name, result.data)
        
        self._mark_task_completed(state, tool_name)
        logger.info(f"[{state.task_id}] ✅ 漏洞扫描工具执行成功: {tool_name}")
        
        state.update_execution_step(step_number, result=result.data, status="success", state_transitions=["completed"])
        self._update_progress(state, f"完成 {tool_name}")
    
    async def _handle_failure(self, state: AgentState, tool_name: str, result, step_number: int):
        """处理执行失败"""
        error_msg = result.error if hasattr(result, 'error') else "未知错误"
        logger.warning(f"[{state.task_id}] ⚠️ 漏洞扫描工具执行失败: {tool_name}")
        state.add_error(f"漏洞扫描工具执行失败: {tool_name}")
        
        state.update_execution_step(step_number, result={"error": error_msg}, status="failed", state_transitions=["failed"])
        self._mark_task_completed(state, tool_name)
    
    def _extract_vulnerabilities(self, state: AgentState, tool_name: str, vuln_data: Dict) -> None:
        """
        从扫描结果中提取漏洞信息
        
        Args:
            state: Agent状态对象
            tool_name: 工具名称
            vuln_data: 漏洞数据
        """
        if not isinstance(vuln_data, dict):
            return
        
        vuln_keys = [
            "vulnerabilities", "fileupload_results", "cmdi_results", 
            "weakpass_results", "lfi_results", "ssrf_results"
        ]
        
        for key in vuln_keys:
            if key in vuln_data and vuln_data[key]:
                vulns = vuln_data[key]
                if isinstance(vulns, list):
                    for vuln in vulns:
                        state.add_vulnerability(vuln)
                elif isinstance(vulns, dict):
                    state.add_vulnerability(vulns)


class VulnResultAggregationNode:
    """
    漏洞扫描结果汇总节点
    
    汇总所有漏洞扫描结果，生成汇总报告。
    """
    
    def __init__(self):
        logger.info("📊 漏洞扫描结果汇总节点初始化")
    
    async def __call__(self, state: AgentState) -> AgentState:
        """汇总漏洞扫描结果"""
        logger.info(f"[{state.task_id}] 📊 汇总漏洞扫描结果")
        
        total_vulns = len(state.vulnerabilities)
        vuln_tools = ToolCategoryHelper.get_vuln_scan_tools()
        
        state.vuln_scan_results = {
            "total_vulnerabilities": total_vulns,
            "vulnerabilities": state.vulnerabilities,
            "tools_used": [t for t in state.completed_tasks if t in vuln_tools]
        }
        
        state.update_stage_status("tool_execution", "completed", "完成", 100, f"发现 {total_vulns} 个漏洞")
        logger.info(f"[{state.task_id}] ✅ 漏洞扫描结果汇总完成: 发现 {total_vulns} 个漏洞")
        
        return state


# ============================================================================
# POC验证子图节点
# ============================================================================

class PocTaskPlanningNode(BasePlanningNode):
    """
    POC任务规划节点
    
    根据目标上下文（CMS类型、开放端口）规划POC验证任务。
    """
    
    def __init__(self):
        super().__init__(stage=NodeStage.POC_VERIFICATION)
    
    async def _plan_tasks(self, state: AgentState) -> List[str]:
        """规划POC验证任务"""
        poc_tasks = POCTaskHelper.get_poc_tasks_from_context(state)
        return [t for t in poc_tasks if t not in state.completed_tasks]
    
    def _get_fallback_tasks(self) -> List[str]:
        return []
    
    def _get_valid_tools(self) -> List[str]:
        return ToolCategoryHelper.get_poc_tools()


class PocExecutionNode(BaseToolExecutionNode):
    """
    POC执行节点
    
    执行POC验证，确认漏洞可利用性。
    """
    
    def __init__(self):
        super().__init__(stage=NodeStage.POC_VERIFICATION)
    
    async def _execute_tool(self, state: AgentState, tool_name: str):
        """执行POC验证"""
        if tool_name not in registry.tools:
            raise ValueError(f"POC未注册: {tool_name}")
        
        tool_wrapper = registry.tools[tool_name]
        return await tool_wrapper.execute(state.target)
    
    async def _handle_success(self, state: AgentState, tool_name: str, result, step_number: int):
        """处理执行成功"""
        state.tool_results[tool_name] = result.data
        
        if result.data and result.data.get("vulnerabilities"):
            for vuln in result.data["vulnerabilities"]:
                state.add_vulnerability(vuln)
        
        self._mark_task_completed(state, tool_name)
        logger.info(f"[{state.task_id}] ✅ POC验证成功: {tool_name}")
        
        state.update_execution_step(step_number, result=result.data, status="success", state_transitions=["completed"])
        self._update_progress(state, f"完成 {tool_name}")
    
    async def _handle_failure(self, state: AgentState, tool_name: str, result, step_number: int):
        """处理执行失败"""
        error_msg = result.error if hasattr(result, 'error') else "未知错误"
        logger.warning(f"[{state.task_id}] ⚠️ POC验证失败: {tool_name}")
        state.add_error(f"POC验证失败: {tool_name}")
        
        state.update_execution_step(step_number, result={"error": error_msg}, status="failed", state_transitions=["failed"])
        self._mark_task_completed(state, tool_name)


class PocResultVerificationNode(BaseResultVerificationNode):
    """
    POC结果验证节点
    
    验证POC执行结果。
    """
    
    def __init__(self):
        super().__init__(stage=NodeStage.POC_VERIFICATION)
