"""
LangGraph 多子图架构 - 优化版

拆分为三个独立子图：
1. 信息收集子图 - 负责目标信息收集、端口扫描、子域名等
2. 漏洞扫描子图 - 负责SQL注入、XSS、命令注入等漏洞检测
3. 报告生成子图 - 负责漏洞分析、报告生成

优化特性：
- 完整的工作流状态管理
- 超时控制和异常处理
- 进度跟踪和日志记录
- 性能优化（并行执行、缓存）
- 健康检查和监控
"""
import json
import logging
import time
import asyncio
import functools
from typing import Dict, Any, List, Optional, Callable, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from contextlib import asynccontextmanager
from langgraph.graph import StateGraph, END, START

from .state import AgentState
from .nodes import (
    VulnerabilityAnalysisNode,
    ReportGenerationNode,
    EnvironmentAwarenessNode,
    AIDecisionNode as BaseAIDecisionNode,
    UserInteractNode as BaseUserInteractNode,
    ExecuteAnalyzeNode,
    ChatNegotiateNode,
    ScriptToolNode,
    PortScanNode,
    SubdomainEnumNode,
    DirScanNode,
    SSLCertificateNode,
    SensitiveInfoLeakNode,
    SQLInjectionDeepNode,
    XSSDeepScanNode,
    SSRFScanNode,
    FileUploadScanNode
)
from .tools.registry import registry, validate_script_code, load_and_test_script
from .tools.info_tools import INFO_COLLECTION_TOOLS
from .tools.vuln_tools import VULN_SCAN_TOOLS
from .agent_config import agent_config

logger = logging.getLogger(__name__)


class WorkflowStage(Enum):
    INIT = "init"
    ENVIRONMENT_AWARENESS = "environment_awareness"
    INFO_COLLECTION = "info_collection"
    VULN_SCAN = "vuln_scan"
    REPORT_GENERATION = "report_generation"
    COMPLETED = "completed"
    FAILED = "failed"


class WorkflowStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


@dataclass
class WorkflowMetrics:
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    total_nodes_executed: int = 0
    total_tools_executed: int = 0
    total_errors: int = 0
    total_retries: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    
    @property
    def duration(self) -> float:
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        elif self.start_time:
            return time.time() - self.start_time
        return 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.duration,
            "total_nodes_executed": self.total_nodes_executed,
            "total_tools_executed": self.total_tools_executed,
            "total_errors": self.total_errors,
            "total_retries": self.total_retries,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses
        }


@dataclass
class WorkflowCheckpoint:
    stage: WorkflowStage
    state_data: Dict[str, Any]
    timestamp: float
    message: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage": self.stage.value,
            "state_data": self.state_data,
            "timestamp": self.timestamp,
            "message": self.message
        }


class WorkflowStateManager:
    """工作流状态管理器"""
    
    def __init__(self, task_id: str):
        self.task_id = task_id
        self.status = WorkflowStatus.PENDING
        self.current_stage = WorkflowStage.INIT
        self.progress: int = 0
        self.metrics = WorkflowMetrics()
        self.checkpoints: List[WorkflowCheckpoint] = []
        self.errors: List[Dict[str, Any]] = []
        self.warnings: List[Dict[str, Any]] = []
        self._lock = asyncio.Lock()
        self._stage_progress: Dict[WorkflowStage, int] = {
            WorkflowStage.INIT: 0,
            WorkflowStage.ENVIRONMENT_AWARENESS: 5,
            WorkflowStage.INFO_COLLECTION: 35,
            WorkflowStage.VULN_SCAN: 70,
            WorkflowStage.REPORT_GENERATION: 95,
            WorkflowStage.COMPLETED: 100
        }
    
    async def update_status(self, status: WorkflowStatus, message: str = ""):
        async with self._lock:
            old_status = self.status
            self.status = status
            logger.info(f"[{self.task_id}] 工作流状态变更: {old_status.value} -> {status.value} | {message}")
    
    async def update_stage(self, stage: WorkflowStage, message: str = ""):
        async with self._lock:
            self.current_stage = stage
            self.progress = self._stage_progress.get(stage, 0)
            checkpoint = WorkflowCheckpoint(
                stage=stage,
                state_data={},
                timestamp=time.time(),
                message=message
            )
            self.checkpoints.append(checkpoint)
            logger.info(f"[{self.task_id}] 工作流阶段变更: {stage.value} | 进度: {self.progress}% | {message}")
    
    async def record_error(self, error: str, stage: Optional[WorkflowStage] = None, recoverable: bool = True):
        async with self._lock:
            error_record = {
                "timestamp": time.time(),
                "error": error,
                "stage": (stage or self.current_stage).value,
                "recoverable": recoverable
            }
            self.errors.append(error_record)
            self.metrics.total_errors += 1
            logger.error(f"[{self.task_id}] 工作流错误: {error} | 阶段: {self.current_stage.value} | 可恢复: {recoverable}")
    
    async def record_warning(self, warning: str):
        async with self._lock:
            warning_record = {
                "timestamp": time.time(),
                "warning": warning,
                "stage": self.current_stage.value
            }
            self.warnings.append(warning_record)
            logger.warning(f"[{self.task_id}] 工作流警告: {warning}")
    
    async def increment_node_count(self):
        async with self._lock:
            self.metrics.total_nodes_executed += 1
    
    async def increment_tool_count(self):
        async with self._lock:
            self.metrics.total_tools_executed += 1
    
    async def increment_retry_count(self):
        async with self._lock:
            self.metrics.total_retries += 1
    
    async def record_cache_hit(self):
        async with self._lock:
            self.metrics.cache_hits += 1
    
    async def record_cache_miss(self):
        async with self._lock:
            self.metrics.cache_misses += 1
    
    def start(self):
        self.metrics.start_time = time.time()
    
    def end(self):
        self.metrics.end_time = time.time()
    
    def get_summary(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "status": self.status.value,
            "current_stage": self.current_stage.value,
            "progress": self.progress,
            "metrics": self.metrics.to_dict(),
            "errors_count": len(self.errors),
            "warnings_count": len(self.warnings),
            "checkpoints_count": len(self.checkpoints)
        }


class WorkflowTimeoutError(Exception):
    """工作流超时错误"""
    pass


class WorkflowCancelledError(Exception):
    """工作流取消错误"""
    pass


class WorkflowHealthChecker:
    """工作流健康检查器"""
    
    def __init__(self, state_manager: WorkflowStateManager):
        self.state_manager = state_manager
        self._health_status: Dict[str, Any] = {}
        self._last_check_time: Optional[float] = None
    
    async def check_health(self) -> Dict[str, Any]:
        now = time.time()
        self._last_check_time = now
        
        health = {
            "status": "healthy",
            "timestamp": now,
            "task_id": self.state_manager.task_id,
            "current_stage": self.state_manager.current_stage.value,
            "progress": self.state_manager.progress,
            "errors_count": len(self.state_manager.errors),
            "warnings_count": len(self.state_manager.warnings),
            "metrics": self.state_manager.metrics.to_dict(),
            "issues": []
        }
        
        if self.state_manager.status == WorkflowStatus.FAILED:
            health["status"] = "unhealthy"
            health["issues"].append("工作流状态为失败")
        
        if self.state_manager.metrics.total_errors > 5:
            health["status"] = "degraded"
            health["issues"].append(f"错误数量过多: {self.state_manager.metrics.total_errors}")
        
        if self.state_manager.status == WorkflowStatus.RUNNING:
            duration = self.state_manager.metrics.duration
            if duration > 1800:
                health["status"] = "degraded"
                health["issues"].append(f"运行时间过长: {duration:.0f}秒")
        
        self._health_status = health
        return health
    
    async def is_healthy(self) -> bool:
        health = await self.check_health()
        return health["status"] in ["healthy", "degraded"]


class WorkflowCache:
    """工作流缓存"""
    
    def __init__(self, max_size: int = 100, ttl: int = 3600):
        self._cache: Dict[str, Any] = {}
        self._timestamps: Dict[str, float] = {}
        self._max_size = max_size
        self._ttl = ttl
        self._lock = asyncio.Lock()
    
    def _make_key(self, tool_name: str, target: str) -> str:
        return f"{tool_name}:{target}"
    
    async def get(self, tool_name: str, target: str) -> Optional[Any]:
        async with self._lock:
            key = self._make_key(tool_name, target)
            if key in self._cache:
                timestamp = self._timestamps.get(key, 0)
                if time.time() - timestamp < self._ttl:
                    return self._cache[key]
                else:
                    del self._cache[key]
                    del self._timestamps[key]
            return None
    
    async def set(self, tool_name: str, target: str, result: Any):
        async with self._lock:
            if len(self._cache) >= self._max_size:
                oldest_key = min(self._timestamps, key=self._timestamps.get)
                del self._cache[oldest_key]
                del self._timestamps[oldest_key]
            
            key = self._make_key(tool_name, target)
            self._cache[key] = result
            self._timestamps[key] = time.time()
    
    async def clear(self):
        async with self._lock:
            self._cache.clear()
            self._timestamps.clear()


def with_timeout(timeout_seconds: int):
    """超时装饰器"""
    def decorator(func: Callable):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await asyncio.wait_for(func(*args, **kwargs), timeout=timeout_seconds)
            except asyncio.TimeoutError:
                raise WorkflowTimeoutError(f"操作超时: {func.__name__} 超过 {timeout_seconds} 秒")
        return wrapper
    return decorator


def with_retry(max_retries: int = 3, delay: float = 1.0, backoff: float = 2.0):
    """重试装饰器"""
    def decorator(func: Callable):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_retries - 1:
                        wait_time = delay * (backoff ** attempt)
                        logger.warning(f"操作失败，{wait_time}秒后重试 (尝试 {attempt + 1}/{max_retries}): {func.__name__}")
                        await asyncio.sleep(wait_time)
            raise last_exception
        return wrapper
    return decorator


@asynccontextmanager
async def workflow_context(state_manager: WorkflowStateManager, stage: WorkflowStage):
    """工作流上下文管理器"""
    await state_manager.update_stage(stage, f"开始执行 {stage.value}")
    start_time = time.time()
    try:
        yield
        duration = time.time() - start_time
        await state_manager.update_stage(stage, f"完成 {stage.value} (耗时: {duration:.2f}秒)")
    except WorkflowTimeoutError as e:
        await state_manager.record_error(str(e), stage, recoverable=False)
        await state_manager.update_status(WorkflowStatus.TIMEOUT, str(e))
        raise
    except WorkflowCancelledError as e:
        await state_manager.record_error(str(e), stage, recoverable=False)
        await state_manager.update_status(WorkflowStatus.CANCELLED, str(e))
        raise
    except Exception as e:
        await state_manager.record_error(str(e), stage, recoverable=True)
        raise


def stream_print(text: str, delay: float = 0.01):
    for char in str(text):
        print(char, end="", flush=True)
        time.sleep(delay)
    print()


def build_info_collection_subgraph():
    from langgraph.graph import StateGraph
    
    class InfoAIDecisionNode(BaseAIDecisionNode):
        async def _llm_decision(self, state: AgentState) -> Dict[str, Any]:
            available_tools = [t for t in registry.list_tools() if t['name'] in INFO_COLLECTION_TOOLS]
            tools_desc = "\n".join([f"- {t['name']}: {t['description']}" for t in available_tools])
            context_info = f"\n目标上下文: {json.dumps(state.target_context, ensure_ascii=False)}" if state.target_context else ""
            
            system_prompt = """你是Web安全信息收集专家，负责分析当前状态决定下一步行动。
## 可用任务
{tools}
## 规则
1. 如果任务不存在，只输出：need_script
2. 否则只输出任务名
3. 绝对不要输出end/停止
## 输出格式
{{"action": "tool", "tasks": ["task1"], "reason": "决策理由"}}"""
            
            user_prompt = f"目标: {state.target}{context_info}\n已完成任务: {state.completed_tasks}\n聊天历史总结: {state.chat_summary}"
            
            from langchain_core.prompts import ChatPromptTemplate
            from langchain_core.output_parsers import JsonOutputParser
            prompt = ChatPromptTemplate.from_messages([("system", system_prompt), ("human", user_prompt)])
            chain = prompt | self.llm | JsonOutputParser()
            result = await chain.ainvoke({"tools": tools_desc, "target": state.target})
            
            logger.info(f"[信息收集] LLM决策结果: {result}")
            return result
        
        def _rule_based_decision(self, state: AgentState) -> Dict[str, Any]:
            completed = set(state.completed_tasks) & set(INFO_COLLECTION_TOOLS)
            
            if len(completed) < 3:
                remaining = [t for t in INFO_COLLECTION_TOOLS if t not in state.completed_tasks]
                return {"action": "tool", "tasks": remaining[:3], "reason": "继续信息收集"}
            
            return {"action": "end", "reason": "信息收集已完成"}
    
    class InfoUserInteractNode(BaseUserInteractNode):
        async def __call__(self, state: AgentState) -> AgentState:
            print("\n" + "="*60)
            print(f"[信息收集模式] 目标：{state.target}")
            task = state.planned_tasks[0] if state.planned_tasks else "无"
            print(f"AI推荐任务：{task}")
            print("【1】执行扫描 【2】完成信息收集 【3】和AI聊天 【4】上传脚本 【5】生成脚本 【0】切换模式")
            
            choice = input("请输入指令：").strip()
            state.user_choice = choice
            
            logger.info(f"[信息收集] 用户选择: {choice}")
            return state
    
    def info_router(state: AgentState) -> str:
        if state.need_generate_script:
            return "script_tool"
        
        if state.user_choice == "0":
            return "__main_switch__"
        
        c = state.user_choice
        if c == "1": 
            return "execute_analyze"
        if c == "2": 
            return "__end_subgraph__"
        if c == "3": 
            return "chat_negotiate"
        if c in ["4", "5"]: 
            return "script_tool"
        
        return "user_interact"
    
    workflow = StateGraph(AgentState)
    
    workflow.add_node("ai_decide", InfoAIDecisionNode())
    workflow.add_node("user_interact", InfoUserInteractNode())
    workflow.add_node("execute_analyze", ExecuteAnalyzeNode())
    workflow.add_node("chat_negotiate", ChatNegotiateNode())
    workflow.add_node("script_tool", ScriptToolNode())
    
    workflow.set_entry_point("ai_decide")
    workflow.add_edge("ai_decide", "user_interact")
    workflow.add_conditional_edges("user_interact", info_router, {
        "execute_analyze": "execute_analyze",
        "chat_negotiate": "chat_negotiate",
        "script_tool": "script_tool",
        "__end_subgraph__": END,
        "__main_switch__": END
    })
    
    workflow.add_edge("execute_analyze", "ai_decide")
    workflow.add_edge("chat_negotiate", "ai_decide")
    workflow.add_edge("script_tool", "ai_decide")
    
    return workflow.compile()


def build_vulnerability_scan_subgraph():
    from langgraph.graph import StateGraph
    
    class VulnAIDecisionNode(BaseAIDecisionNode):
        async def _llm_decision(self, state: AgentState) -> Dict[str, Any]:
            available_tools = [t for t in registry.list_tools() if t['name'] in VULN_SCAN_TOOLS]
            tools_desc = "\n".join([f"- {t['name']}: {t['description']}" for t in available_tools])
            context_info = f"\n目标上下文: {json.dumps(state.target_context, ensure_ascii=False)}" if state.target_context else ""
            
            system_prompt = """你是Web安全漏洞扫描专家，负责分析当前状态决定下一步行动。
## 可用任务
{tools}
## 规则
1. 如果任务不存在，只输出：need_script
2. 否则只输出任务名
3. 绝对不要输出end/停止
## 输出格式
{{"action": "tool", "tasks": ["task1"], "reason": "决策理由"}}"""
            
            user_prompt = f"目标: {state.target}{context_info}\n已完成任务: {state.completed_tasks}\n已发现漏洞: {len(state.vulnerabilities)}个\n聊天历史总结: {state.chat_summary}"
            
            from langchain_core.prompts import ChatPromptTemplate
            from langchain_core.output_parsers import JsonOutputParser
            prompt = ChatPromptTemplate.from_messages([("system", system_prompt), ("human", user_prompt)])
            chain = prompt | self.llm | JsonOutputParser()
            result = await chain.ainvoke({"tools": tools_desc, "target": state.target})
            
            logger.info(f"[漏洞扫描] LLM决策结果: {result}")
            return result
        
        def _rule_based_decision(self, state: AgentState) -> Dict[str, Any]:
            completed = set(state.completed_tasks) & set(VULN_SCAN_TOOLS)
            
            if len(completed) < 3:
                remaining = [t for t in VULN_SCAN_TOOLS if t not in state.completed_tasks]
                return {"action": "tool", "tasks": remaining[:3], "reason": "继续漏洞扫描"}
            
            return {"action": "end", "reason": "漏洞扫描已完成"}
    
    class VulnUserInteractNode(BaseUserInteractNode):
        async def __call__(self, state: AgentState) -> AgentState:
            print("\n" + "="*60)
            print(f"[漏洞扫描模式] 目标：{state.target}")
            task = state.planned_tasks[0] if state.planned_tasks else "无"
            print(f"AI推荐任务：{task}")
            print(f"已发现漏洞：{len(state.vulnerabilities)} 个")
            print("【1】执行扫描 【2】完成漏洞扫描 【3】和AI聊天 【4】上传脚本 【5】生成脚本 【0】切换模式")
            
            choice = input("请输入指令：").strip()
            state.user_choice = choice
            
            logger.info(f"[漏洞扫描] 用户选择: {choice}")
            return state
    
    def vuln_router(state: AgentState) -> str:
        if state.need_generate_script:
            return "script_tool"
        
        if state.user_choice == "0":
            return "__main_switch__"
        
        c = state.user_choice
        if c == "1": 
            return "execute_analyze"
        if c == "2": 
            return "__end_subgraph__"
        if c == "3": 
            return "chat_negotiate"
        if c in ["4", "5"]: 
            return "script_tool"
        
        return "user_interact"
    
    workflow = StateGraph(AgentState)
    
    workflow.add_node("ai_decide", VulnAIDecisionNode())
    workflow.add_node("user_interact", VulnUserInteractNode())
    workflow.add_node("execute_analyze", ExecuteAnalyzeNode())
    workflow.add_node("chat_negotiate", ChatNegotiateNode())
    workflow.add_node("script_tool", ScriptToolNode())
    
    workflow.set_entry_point("ai_decide")
    workflow.add_edge("ai_decide", "user_interact")
    workflow.add_conditional_edges("user_interact", vuln_router, {
        "execute_analyze": "execute_analyze",
        "chat_negotiate": "chat_negotiate",
        "script_tool": "script_tool",
        "__end_subgraph__": END,
        "__main_switch__": END
    })
    
    workflow.add_edge("execute_analyze", "ai_decide")
    workflow.add_edge("chat_negotiate", "ai_decide")
    workflow.add_edge("script_tool", "ai_decide")
    
    return workflow.compile()


def build_report_subgraph():
    from langgraph.graph import StateGraph
    
    workflow = StateGraph(AgentState)
    
    workflow.add_node("vulnerability_analysis", VulnerabilityAnalysisNode())
    workflow.add_node("report_generation", ReportGenerationNode())
    
    workflow.set_entry_point("vulnerability_analysis")
    workflow.add_edge("vulnerability_analysis", "report_generation")
    workflow.add_edge("report_generation", END)
    
    return workflow.compile()


class ScanAgentGraph:
    """主扫描Agent图 - 优化版"""
    
    WORKFLOW_TIMEOUT = 3600
    NODE_TIMEOUT = 300
    MAX_RETRIES = 3
    
    def __init__(self):
        logger.info("初始化多子图扫描Agent (优化版)")
        
        initialize_tools()
        
        self.info_subgraph = build_info_collection_subgraph()
        self.vuln_subgraph = build_vulnerability_scan_subgraph()
        self.report_subgraph = build_report_subgraph()
        
        self.graph = self._build_main_graph()
        
        self._state_managers: Dict[str, WorkflowStateManager] = {}
        self._health_checkers: Dict[str, WorkflowHealthChecker] = {}
        self._cache = WorkflowCache()
        
        logger.info("多子图Agent构建完成 (优化版)")
    
    def _build_main_graph(self) -> StateGraph:
        workflow = StateGraph(AgentState)
        
        workflow.add_node("environment_awareness", EnvironmentAwarenessNode())
        workflow.add_node("main_decision", self._main_decision_node)
        
        workflow.add_node("info_collection", self.info_subgraph)
        workflow.add_node("vulnerability_scan", self.vuln_subgraph)
        workflow.add_node("report_generation", self.report_subgraph)
        
        workflow.set_entry_point("environment_awareness")
        workflow.add_edge("environment_awareness", "main_decision")
        
        workflow.add_edge("info_collection", "main_decision")
        workflow.add_edge("vulnerability_scan", "main_decision")
        
        workflow.add_edge("report_generation", END)
        
        workflow.add_conditional_edges("main_decision", self._main_router, {
            "info": "info_collection",
            "vuln": "vulnerability_scan",
            "report": "report_generation"
        })
        
        return workflow
    
    def _main_decision_node(self, state: AgentState) -> AgentState:
        stream_print("\n" + "="*60)
        stream_print("主模式选择")
        print("请选择扫描模式：")
        print("【1】信息收集模式")
        print("【2】漏洞扫描模式")
        print("【3】生成扫描报告")
        
        choice = input("请输入模式编号：").strip()
        
        if choice == "1":
            state.next_mode = "info"
            stream_print("已切换到：信息收集模式")
        elif choice == "2":
            state.next_mode = "vuln"
            stream_print("已切换到：漏洞扫描模式")
        elif choice == "3":
            state.next_mode = "report"
            stream_print("开始生成报告...")
        else:
            state.next_mode = "info"
            stream_print("输入错误，默认进入信息收集模式")
        
        return state
    
    def _main_router(self, state: AgentState) -> str:
        mode = getattr(state, 'next_mode', 'info')
        if mode == "info":
            return "info"
        elif mode == "vuln":
            return "vuln"
        elif mode == "report":
            return "report"
        return "info"
    
    def compile(self):
        return self.graph.compile()
    
    def get_state_manager(self, task_id: str) -> WorkflowStateManager:
        if task_id not in self._state_managers:
            self._state_managers[task_id] = WorkflowStateManager(task_id)
            self._health_checkers[task_id] = WorkflowHealthChecker(self._state_managers[task_id])
        return self._state_managers[task_id]
    
    def get_health_checker(self, task_id: str) -> WorkflowHealthChecker:
        if task_id not in self._health_checkers:
            self.get_state_manager(task_id)
        return self._health_checkers[task_id]
    
    @with_timeout(WORKFLOW_TIMEOUT)
    async def invoke(self, initial_state: AgentState) -> AgentState:
        task_id = initial_state.task_id
        state_manager = self.get_state_manager(task_id)
        
        logger.info(f"开始执行多子图Agent工作流: {task_id}")
        
        state_manager.start()
        await state_manager.update_status(WorkflowStatus.RUNNING, "工作流开始执行")
        
        try:
            async with workflow_context(state_manager, WorkflowStage.INIT):
                await state_manager.increment_node_count()
            
            async with workflow_context(state_manager, WorkflowStage.ENVIRONMENT_AWARENESS):
                await state_manager.increment_node_count()
            
            compiled_graph = self.compile()
            config = {
                "recursion_limit": 200,
                "configurable": {
                    "thread_id": task_id
                }
            }
            
            final_state = await compiled_graph.ainvoke(initial_state, config=config)
            
            if isinstance(final_state, dict):
                final_state = AgentState.from_dict(final_state)
            
            state_manager.end()
            await state_manager.update_status(WorkflowStatus.COMPLETED, "工作流执行完成")
            await state_manager.update_stage(WorkflowStage.COMPLETED, "工作流完成")
            
            logger.info(
                f"工作流执行完成: {task_id} | "
                f"完成任务: {len(final_state.completed_tasks)} | "
                f"发现漏洞: {len(final_state.vulnerabilities)} | "
                f"耗时: {state_manager.metrics.duration:.2f}秒"
            )
            
            return final_state
            
        except WorkflowTimeoutError as e:
            state_manager.end()
            await state_manager.update_status(WorkflowStatus.TIMEOUT, str(e))
            logger.error(f"工作流超时: {task_id}, 错误: {str(e)}")
            raise
            
        except WorkflowCancelledError as e:
            state_manager.end()
            await state_manager.update_status(WorkflowStatus.CANCELLED, str(e))
            logger.error(f"工作流取消: {task_id}, 错误: {str(e)}")
            raise
            
        except Exception as e:
            state_manager.end()
            await state_manager.record_error(str(e), recoverable=False)
            await state_manager.update_status(WorkflowStatus.FAILED, str(e))
            logger.error(f"工作流执行失败: {task_id}, 错误: {str(e)}")
            raise
    
    async def get_workflow_status(self, task_id: str) -> Dict[str, Any]:
        state_manager = self.get_state_manager(task_id)
        return state_manager.get_summary()
    
    async def get_workflow_health(self, task_id: str) -> Dict[str, Any]:
        health_checker = self.get_health_checker(task_id)
        return await health_checker.check_health()
    
    async def cancel_workflow(self, task_id: str) -> bool:
        if task_id in self._state_managers:
            state_manager = self._state_managers[task_id]
            if state_manager.status == WorkflowStatus.RUNNING:
                await state_manager.update_status(WorkflowStatus.CANCELLED, "用户取消")
                return True
        return False
    
    async def cleanup_workflow(self, task_id: str):
        if task_id in self._state_managers:
            del self._state_managers[task_id]
        if task_id in self._health_checkers:
            del self._health_checkers[task_id]
        logger.info(f"清理工作流资源: {task_id}")


def create_agent_graph() -> ScanAgentGraph:
    return ScanAgentGraph()


def initialize_tools():
    from ..tools.registry import registry
    from ..tools.adapters import PluginAdapter, POCAdapter
    
    logger.info("开始初始化全局工具...")
    
    if len(registry.tools) > 0:
        logger.info("工具已初始化，跳过")
        return
    
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
    
    logger.info(f"插件工具初始化完成,共注册 {len([t for t in registry.tools.values() if t.category == 'plugin'])} 个")
    
    logger.info("开始注册POC工具...")
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
    
    logger.info(f"POC工具初始化完成,共注册 {len(pocs)} 个POC工具")
    
    registry.register(
        name="sqli_scan",
        func=PluginAdapter.adapt_sqli_scan,
        description="SQL注入漏洞扫描",
        category="vuln_scan",
        timeout=120,
        priority=7,
        tags=["vulnerability", "sqli"]
    )
    
    registry.register(
        name="xss_scan",
        func=PluginAdapter.adapt_xss_scan,
        description="XSS漏洞扫描",
        category="vuln_scan",
        timeout=120,
        priority=7,
        tags=["vulnerability", "xss"]
    )
    
    registry.register(
        name="csrf_scan",
        func=PluginAdapter.adapt_csrf_scan,
        description="CSRF漏洞扫描",
        category="vuln_scan",
        timeout=60,
        priority=6,
        tags=["vulnerability", "csrf"]
    )
    
    registry.register(
        name="vuln_infoleak_scan",
        func=PluginAdapter.adapt_vuln_infoleak_scan,
        description="敏感信息泄露扫描",
        category="vuln_scan",
        timeout=60,
        priority=5,
        tags=["vulnerability", "infoleak"]
    )
    
    registry.register(
        name="crawler",
        func=PluginAdapter.adapt_crawler,
        description="Web爬虫(自动发现页面)",
        category="plugin",
        timeout=300,
        priority=1,
        tags=["crawler", "spider"]
    )
    
    registry.register(
        name="fileupload_scan",
        func=PluginAdapter.adapt_fileupload_scan,
        description="文件上传漏洞扫描",
        category="vuln_scan",
        timeout=120,
        priority=8,
        tags=["vulnerability", "fileupload"]
    )
    
    registry.register(
        name="cmdi_scan",
        func=PluginAdapter.adapt_cmdi_scan,
        description="命令注入漏洞扫描",
        category="vuln_scan",
        timeout=180,
        priority=9,
        tags=["vulnerability", "cmdi"]
    )
    
    registry.register(
        name="weakpass_scan",
        func=PluginAdapter.adapt_weakpass_scan,
        description="弱口令扫描",
        category="vuln_scan",
        timeout=300,
        priority=7,
        tags=["vulnerability", "weakpass"]
    )
    
    registry.register(
        name="lfi_scan",
        func=PluginAdapter.adapt_lfi_scan,
        description="文件包含漏洞扫描",
        category="vuln_scan",
        timeout=180,
        priority=8,
        tags=["vulnerability", "lfi"]
    )
    
    registry.register(
        name="ssrf_scan",
        func=PluginAdapter.adapt_ssrf_scan,
        description="SSRF漏洞扫描",
        category="vuln_scan",
        timeout=180,
        priority=8,
        tags=["vulnerability", "ssrf"]
    )
    
    logger.info(f"漏洞扫描工具初始化完成,共注册 10 个漏洞扫描工具")
    logger.info(f"全局工具初始化完成，总工具数: {len(registry.tools)}")
