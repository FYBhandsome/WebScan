"""
工作流数据标准化模块

提供统一的工作流数据格式定义和转换工具，用于标准化 AI Agent 工作流的执行数据。

模块功能:
1. 工作流数据标准化
   - StandardizedNodeExecution: 标准化节点执行记录
   - StandardizedSubgraph: 标准化子图数据
   - StandardizedGraphFlow: 标准化图流数据
   - StandardizedWorkflowData: 标准化工作流数据

2. 数据转换器
   - WorkflowDataConverter: 工作流数据转换器，支持从多种数据源转换

3. 执行优化功能（从 execution_optimizer.py 合并）
   - NodeExecutionMetrics: 节点执行指标数据类
   - ExecutionMetricsCollector: 执行指标收集器
   - NodeExecutionOptimizer: 节点执行优化器
   - optimized_node: 节点优化装饰器
   - get_execution_optimizer: 获取全局优化器实例

合并说明:
- 本模块合并了原 backend.ai_agents.core.execution_optimizer.py 的全部功能
- 统一了工作流数据的格式定义和转换逻辑
- 提供了执行性能监控和优化能力

使用示例:
    from backend.api.workflow_schemas import (
        WorkflowDataConverter,
        StandardizedWorkflowData,
        get_execution_optimizer
    )
    
    # 转换工作流数据
    converter = WorkflowDataConverter()
    workflow_data = converter.from_agent_state(agent_state)
    
    # 使用执行优化器
    optimizer = get_execution_optimizer()
    result, success = await optimizer.execute_with_optimization(
        node_func, "node_name", "task_id"
    )
"""
from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
import time
import json
import logging
import asyncio
from functools import wraps

logger = logging.getLogger(__name__)


class WorkflowStatus(Enum):
    """
    工作流状态枚举
    
    定义工作流的生命周期状态:
    - PENDING: 等待执行
    - RUNNING: 正在执行
    - COMPLETED: 执行完成
    - FAILED: 执行失败
    - CANCELLED: 已取消
    """
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class NodeStatus(Enum):
    """
    节点状态枚举
    
    定义单个节点的执行状态:
    - PENDING: 等待执行
    - RUNNING: 正在执行
    - SUCCESS: 执行成功
    - FAILED: 执行失败
    - SKIPP: 跳过执行
    """
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class StandardizedNodeExecution:
    """
    标准化节点执行记录
    
    用于记录单个节点的执行信息，包括执行状态、时间、输入输出等。
    
    属性:
        node_id: 节点唯一标识
        node_name: 节点名称
        node_type: 节点类型
        status: 执行状态
        step_number: 步骤序号
        start_time: 开始时间戳
        end_time: 结束时间戳
        duration_ms: 执行耗时（毫秒）
        execution_time: 执行时间（秒）
        input_params: 输入参数
        output_data: 输出数据
        error: 错误信息
        error_message: 错误消息
        task: 任务名称
        tool_name: 工具名称
        timestamp: 时间戳
        timestamp_iso: ISO格式时间戳
        metadata: 元数据
    
    使用示例:
        node_exec = StandardizedNodeExecution(
            node_id="node_001",
            node_name="端口扫描",
            node_type="scan",
            status="completed"
        )
        data = node_exec.to_dict()
    """
    node_id: str
    node_name: str
    node_type: str
    status: str = "pending"
    step_number: int = 0
    
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    duration_ms: Optional[float] = None
    execution_time: Optional[float] = None
    
    input_params: Dict[str, Any] = field(default_factory=dict)
    output_data: Dict[str, Any] = field(default_factory=dict)
    
    error: Optional[str] = None
    error_message: Optional[str] = None
    
    task: Optional[str] = None
    tool_name: Optional[str] = None
    
    timestamp: Optional[float] = None
    timestamp_iso: Optional[str] = None
    
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data.pop('metadata', None)
        if self.metadata:
            data.update(self.metadata)
        return data


@dataclass
class StandardizedSubgraph:
    """
    标准化子图数据
    
    用于表示工作流中的子图结构，包含多个节点和依赖关系。
    
    属性:
        subgraph_id: 子图唯一标识
        subgraph_name: 子图名称
        status: 子图状态
        start_time: 开始时间
        end_time: 结束时间
        nodes: 节点列表
        dependencies: 依赖列表
        metadata: 元数据
    
    使用示例:
        subgraph = StandardizedSubgraph(
            subgraph_id="sg_001",
            subgraph_name="信息收集阶段",
            nodes=[node1.to_dict(), node2.to_dict()]
        )
    """
    subgraph_id: str
    subgraph_name: str
    status: str = "pending"
    
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    
    nodes: List[Dict[str, Any]] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "subgraph_id": self.subgraph_id,
            "subgraph_name": self.subgraph_name,
            "status": self.status,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "nodes": self.nodes,
            "dependencies": self.dependencies,
            **self.metadata
        }


@dataclass
class StandardizedGraphFlow:
    """
    标准化图流数据
    
    用于表示完整的工作流图结构，包含多个子图和执行顺序。
    
    属性:
        subgraphs: 子图列表
        dependencies: 子图依赖关系
        execution_order: 执行顺序
    
    使用示例:
        graph_flow = StandardizedGraphFlow(
            subgraphs=[subgraph1.to_dict()],
            execution_order=["sg_001", "sg_002"]
        )
    """
    subgraphs: List[Dict[str, Any]] = field(default_factory=list)
    dependencies: List[Dict[str, str]] = field(default_factory=list)
    execution_order: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "subgraphs": self.subgraphs,
            "dependencies": self.dependencies,
            "execution_order": self.execution_order
        }


@dataclass
class StandardizedWorkflowData:
    """
    标准化工作流数据
    
    完整的工作流执行数据，包含任务信息、执行历史、漏洞发现等。
    
    属性:
        task_id: 任务唯一标识
        target: 扫描目标
        status: 工作流状态
        progress: 进度百分比
        start_time: 开始时间戳
        end_time: 结束时间戳
        duration: 执行时长
        execution_history: 执行历史记录
        graph_flow: 图流数据
        current_step: 当前步骤
        total_steps: 总步骤数
        completed_steps: 已完成步骤数
        vulnerabilities: 发现的漏洞列表
        tool_results: 工具执行结果
        metadata: 元数据
    
    使用示例:
        workflow = StandardizedWorkflowData(
            task_id="task_001",
            target="http://example.com",
            status="running",
            progress=50
        )
        api_response = workflow.to_dict()
    """
    task_id: str
    target: str
    status: str = "pending"
    progress: int = 0
    
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    duration: Optional[float] = None
    
    execution_history: List[Dict[str, Any]] = field(default_factory=list)
    graph_flow: Optional[Dict[str, Any]] = None
    
    current_step: Optional[str] = None
    total_steps: int = 0
    completed_steps: int = 0
    
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    tool_results: Dict[str, Any] = field(default_factory=dict)
    
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        data = {
            "task_id": self.task_id,
            "target": self.target,
            "status": self.status,
            "progress": self.progress,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.duration,
            "execution_history": self.execution_history,
            "graph_flow": self.graph_flow,
            "current_step": self.current_step,
            "total_steps": self.total_steps,
            "completed_steps": self.completed_steps,
            "vulnerabilities": self.vulnerabilities,
            "tool_results": self.tool_results,
            **self.metadata
        }
        return data


class WorkflowDataConverter:
    """
    工作流数据转换器
    
    提供多种数据源到标准化工作流数据的转换功能。
    
    主要方法:
        normalize_execution_history: 标准化执行历史
        from_agent_state: 从 AgentState 转换
        from_task_result: 从任务结果转换
        normalize_execution_record: 标准化单条执行记录
        normalize_graph_flow: 标准化图流数据
        normalize_status: 标准化状态值
    
    使用示例:
        converter = WorkflowDataConverter()
        
        # 从 AgentState 转换
        workflow_data = converter.from_agent_state(agent_state)
        
        # 从任务结果转换
        workflow_data = converter.from_task_result(
            task_result, task_id="task_001", target="http://example.com"
        )
    """
    
    @staticmethod
    def normalize_execution_history(history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not history or not isinstance(history, list):
            return []
        
        normalized = []
        for idx, record in enumerate(history):
            if isinstance(record, dict):
                normalized_record = WorkflowDataConverter.normalize_execution_record(record, idx)
                normalized.append(normalized_record)
        
        return normalized
    
    @staticmethod
    def from_agent_state(state) -> StandardizedWorkflowData:
        from backend.ai_agents.core.state import AgentState, NodeExecutionRecord
        
        if not hasattr(state, 'task_id'):
            raise ValueError("Invalid state object: missing task_id")
        
        execution_history = []
        if hasattr(state, 'execution_history') and state.execution_history:
            for idx, record in enumerate(state.execution_history):
                if isinstance(record, NodeExecutionRecord):
                    execution_history.append(record.to_dict())
                elif isinstance(record, dict):
                    normalized = WorkflowDataConverter.normalize_execution_record(record, idx)
                    execution_history.append(normalized)
        
        graph_flow = None
        if hasattr(state, 'graph_flow') and state.graph_flow:
            graph_flow = WorkflowDataConverter.normalize_graph_flow(state.graph_flow)
        
        duration = None
        if hasattr(state, 'start_time') and state.start_time:
            duration = time.time() - state.start_time
        
        workflow_data = StandardizedWorkflowData(
            task_id=str(state.task_id) if hasattr(state, 'task_id') else '',
            target=state.target if hasattr(state, 'target') else '',
            status=WorkflowDataConverter.normalize_status(state.status) if hasattr(state, 'status') else 'pending',
            progress=state.progress if hasattr(state, 'progress') else 0,
            start_time=state.start_time if hasattr(state, 'start_time') else None,
            end_time=state.end_time if hasattr(state, 'end_time') else None,
            duration=duration,
            execution_history=execution_history,
            graph_flow=graph_flow,
            vulnerabilities=state.vulnerabilities if hasattr(state, 'vulnerabilities') else [],
            tool_results=state.tool_results if hasattr(state, 'tool_results') else {},
            metadata={
                "target_context": state.target_context if hasattr(state, 'target_context') else {},
                "planned_tasks": state.planned_tasks if hasattr(state, 'planned_tasks') else []
            }
        )
        
        return workflow_data
    
    @staticmethod
    def normalize_execution_record(record: Dict[str, Any], index: int = 0) -> Dict[str, Any]:
        normalized = {
            "step_number": record.get("step_number", index + 1),
            "node_id": record.get("node_id", record.get("node_name", f"node-{index}")),
            "node_name": record.get("node_name", record.get("task", "Unknown")),
            "node_type": record.get("node_type", "unknown"),
            "status": WorkflowDataConverter.normalize_status(record.get("status", "pending")),
            "task": record.get("task", record.get("node_name")),
            "tool_name": record.get("tool_name", record.get("task")),
            "timestamp": record.get("timestamp", record.get("start_time")),
            "timestamp_iso": record.get("timestamp_iso", record.get("start_time_iso")),
            "execution_time": record.get("execution_time", record.get("duration_ms", 0) / 1000 if record.get("duration_ms") else 0),
            "duration_ms": record.get("duration_ms"),
            "input_params": record.get("input_params", record.get("input_data", {})),
            "output_data": record.get("output_data", {}),
            "error": record.get("error", record.get("error_message")),
            "error_message": record.get("error_message", record.get("error"))
        }
        
        return {k: v for k, v in normalized.items() if v is not None}
    
    @staticmethod
    def normalize_graph_flow(graph_flow: Any) -> Dict[str, Any]:
        if isinstance(graph_flow, dict):
            return graph_flow
        
        if hasattr(graph_flow, 'to_dict'):
            return graph_flow.to_dict()
        
        if hasattr(graph_flow, 'subgraphs'):
            subgraphs = []
            for sg in graph_flow.subgraphs:
                if hasattr(sg, 'to_dict'):
                    subgraphs.append(sg.to_dict())
                elif isinstance(sg, dict):
                    subgraphs.append(sg)
            
            return {
                "subgraphs": subgraphs,
                "dependencies": getattr(graph_flow, 'dependencies', []),
                "execution_order": getattr(graph_flow, 'execution_order', [])
            }
        
        return {"subgraphs": [], "dependencies": [], "execution_order": []}
    
    @staticmethod
    def normalize_status(status: Any) -> str:
        if isinstance(status, str):
            status_lower = status.lower()
            status_map = {
                "success": "completed",
                "completed": "completed",
                "running": "running",
                "pending": "pending",
                "failed": "failed",
                "error": "failed",
                "cancelled": "cancelled",
                "skipped": "skipped"
            }
            return status_map.get(status_lower, status_lower)
        
        if hasattr(status, 'value'):
            return status.value
        
        return "pending"
    
    @staticmethod
    def from_task_result(task_result: Dict[str, Any], task_id: str, target: str) -> StandardizedWorkflowData:
        execution_history = []
        raw_history = task_result.get("execution_history", [])
        
        for idx, record in enumerate(raw_history):
            normalized = WorkflowDataConverter.normalize_execution_record(record, idx)
            execution_history.append(normalized)
        
        graph_flow = None
        if "graph_flow" in task_result:
            graph_flow = WorkflowDataConverter.normalize_graph_flow(task_result["graph_flow"])
        
        duration = None
        if "start_time" in task_result:
            end_time = task_result.get("end_time", time.time())
            duration = end_time - task_result["start_time"]
        
        workflow_data = StandardizedWorkflowData(
            task_id=str(task_id),
            target=target,
            status=WorkflowDataConverter.normalize_status(task_result.get("status", "pending")),
            progress=task_result.get("progress", 0),
            start_time=task_result.get("start_time"),
            end_time=task_result.get("end_time"),
            duration=duration,
            execution_history=execution_history,
            graph_flow=graph_flow,
            vulnerabilities=task_result.get("vulnerabilities", []),
            tool_results=task_result.get("tool_results", {}),
            metadata={
                "raw_result": task_result.get("raw_result"),
                "scan_id": task_result.get("scan_id"),
                "target_id": task_result.get("target_id")
            }
        )
        
        return workflow_data


def create_workflow_response(
    task_id: str,
    target: str,
    status: str = "pending",
    progress: int = 0,
    execution_history: List[Dict] = None,
    graph_flow: Dict = None,
    **kwargs
) -> Dict[str, Any]:
    converter = WorkflowDataConverter()
    
    workflow_data = StandardizedWorkflowData(
        task_id=str(task_id),
        target=target,
        status=converter.normalize_status(status),
        progress=progress,
        execution_history=execution_history or [],
        graph_flow=graph_flow,
        **kwargs
    )
    
    return workflow_data.to_dict()


# ============ 以下内容从 backend.ai_agents.core.execution_optimizer.py 合并 ============


@dataclass
class NodeExecutionMetrics:
    """
    节点执行指标数据类
    
    用于记录单个节点的执行性能指标。
    
    属性:
        node_name: 节点名称
        task_id: 任务ID
        start_time: 开始时间戳
        end_time: 结束时间戳
        duration: 执行时长（秒）
        success: 是否成功
        retries: 重试次数
        skipped: 是否跳过
        error: 错误信息
        timestamp: 记录时间戳
    
    使用示例:
        metrics = NodeExecutionMetrics(
            node_name="端口扫描",
            task_id="task_001",
            start_time=time.time()
        )
    """
    node_name: str
    task_id: str
    start_time: float
    end_time: Optional[float] = None
    duration: Optional[float] = None
    success: bool = False
    retries: int = 0
    skipped: bool = False
    error: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class ExecutionMetricsCollector:
    """
    执行指标收集器
    
    收集和管理节点执行的性能指标，支持并发安全操作。
    
    主要方法:
        start_execution: 开始执行记录
        end_execution: 结束执行记录
        record_retry: 记录重试
        mark_skipped: 标记跳过
        get_metrics: 获取指标列表
        get_summary: 获取执行摘要
    
    使用示例:
        collector = ExecutionMetricsCollector()
        metrics_id = await collector.start_execution("节点名称", "任务ID")
        # ... 执行节点 ...
        await collector.end_execution(metrics_id, success=True)
        summary = collector.get_summary("任务ID")
    """
    
    def __init__(self):
        self.metrics: Dict[str, NodeExecutionMetrics] = {}
        self._lock = asyncio.Lock()
    
    async def start_execution(self, node_name: str, task_id: str) -> str:
        """开始执行记录"""
        metrics_id = f"{task_id}_{node_name}_{int(time.time())}"
        metrics = NodeExecutionMetrics(
            node_name=node_name,
            task_id=task_id,
            start_time=time.time()
        )
        
        async with self._lock:
            self.metrics[metrics_id] = metrics
        
        logger.debug(f"[Metrics] 开始执行: {node_name}, 任务ID: {task_id}")
        return metrics_id
    
    async def end_execution(self, metrics_id: str, success: bool, error: Optional[str] = None):
        """结束执行记录"""
        async with self._lock:
            if metrics_id in self.metrics:
                metrics = self.metrics[metrics_id]
                metrics.end_time = time.time()
                metrics.duration = metrics.end_time - metrics.start_time
                metrics.success = success
                metrics.error = error
                
                logger.debug(
                    f"[Metrics] 执行完成: {metrics.node_name}, "
                    f"任务ID: {metrics.task_id}, "
                    f"耗时: {metrics.duration:.2f}s, "
                    f"成功: {success}"
                )
    
    async def record_retry(self, metrics_id: str):
        """记录重试"""
        async with self._lock:
            if metrics_id in self.metrics:
                self.metrics[metrics_id].retries += 1
                logger.debug(
                    f"[Metrics] 重试: {self.metrics[metrics_id].node_name}, "
                    f"重试次数: {self.metrics[metrics_id].retries}"
                )
    
    async def mark_skipped(self, metrics_id: str, reason: str):
        """标记为跳过"""
        async with self._lock:
            if metrics_id in self.metrics:
                self.metrics[metrics_id].skipped = True
                self.metrics[metrics_id].error = reason
                logger.warning(
                    f"[Metrics] 节点跳过: {self.metrics[metrics_id].node_name}, "
                    f"原因: {reason}"
                )
    
    def get_metrics(self, task_id: Optional[str] = None) -> list:
        """获取指标"""
        if task_id:
            return [m for m in self.metrics.values() if m.task_id == task_id]
        return list(self.metrics.values())
    
    def get_summary(self, task_id: Optional[str] = None) -> Dict[str, Any]:
        """获取摘要"""
        metrics_list = self.get_metrics(task_id)
        if not metrics_list:
            return {}
        
        total = len(metrics_list)
        successful = sum(1 for m in metrics_list if m.success and not m.skipped)
        skipped = sum(1 for m in metrics_list if m.skipped)
        failed = total - successful - skipped
        
        durations = [m.duration for m in metrics_list if m.duration is not None]
        avg_duration = sum(durations) / len(durations) if durations else 0
        max_duration = max(durations) if durations else 0
        total_duration = sum(durations) if durations else 0
        
        return {
            "total_nodes": total,
            "successful": successful,
            "skipped": skipped,
            "failed": failed,
            "avg_duration": avg_duration,
            "max_duration": max_duration,
            "total_duration": total_duration
        }


class NodeExecutionOptimizer:
    """
    节点执行优化器
    
    提供节点执行的优化机制，包括超时控制、重试机制、性能监控等。
    
    主要功能:
    - 超时控制：自动检测并处理执行超时
    - 重试机制：支持指数退避重试策略
    - 性能监控：记录执行时间和成功率
    - 节点跳过：失败后可选择跳过而非中断
    
    主要方法:
        execute_with_optimization: 带优化机制的节点执行
        get_execution_summary: 获取执行摘要
        get_execution_metrics: 获取执行指标
    
    使用示例:
        optimizer = NodeExecutionOptimizer()
        result, success = await optimizer.execute_with_optimization(
            node_func=my_async_function,
            node_name="扫描节点",
            task_id="task_001",
            arg1, arg2, kwarg1=value1
        )
    """
    
    def __init__(self):
        self.metrics_collector = ExecutionMetricsCollector()
    
    async def execute_with_optimization(
        self,
        node_func: Callable,
        node_name: str,
        task_id: str,
        *args,
        **kwargs
    ) -> Tuple[Any, bool]:
        """
        带优化机制的节点执行
        
        Args:
            node_func: 节点函数
            node_name: 节点名称
            task_id: 任务ID
            *args, **kwargs: 节点函数参数
            
        Returns:
            (结果, 是否成功)
        """
        try:
            from backend.ai_agents.agent_config import agent_config
        except ImportError:
            class MockConfig:
                ENABLE_RESPONSE_TIME_MONITORING = False
                NODE_MAX_RETRIES = 3
                NODE_RESPONSE_TIME_THRESHOLD = 60
                ENABLE_NODE_SKIPPING = True
            agent_config = MockConfig()
        
        if not agent_config.ENABLE_RESPONSE_TIME_MONITORING:
            try:
                result = await node_func(*args, **kwargs)
                return result, True
            except Exception as e:
                logger.error(f"节点执行失败: {node_name}, 错误: {str(e)}")
                return None, False
        
        metrics_id = await self.metrics_collector.start_execution(node_name, task_id)
        
        max_retries = agent_config.NODE_MAX_RETRIES
        threshold = agent_config.NODE_RESPONSE_TIME_THRESHOLD
        
        last_error = None
        
        for attempt in range(max_retries + 1):
            try:
                start_time = time.time()
                
                if asyncio.iscoroutinefunction(node_func):
                    result = await asyncio.wait_for(
                        node_func(*args, **kwargs),
                        timeout=threshold
                    )
                else:
                    result = node_func(*args, **kwargs)
                
                duration = time.time() - start_time
                
                await self.metrics_collector.end_execution(metrics_id, success=True)
                
                logger.info(
                    f"✅ 节点执行成功: {node_name}, "
                    f"任务ID: {task_id}, "
                    f"耗时: {duration:.2f}s"
                )
                
                return result, True
                
            except asyncio.TimeoutError:
                last_error = f"执行超时 (>{threshold}s)"
                logger.warning(
                    f"⏱️ 节点执行超时: {node_name}, "
                    f"任务ID: {task_id}, "
                    f"尝试: {attempt + 1}/{max_retries + 1}"
                )
                
            except Exception as e:
                last_error = str(e)
                logger.warning(
                    f"⚠️ 节点执行异常: {node_name}, "
                    f"任务ID: {task_id}, "
                    f"尝试: {attempt + 1}/{max_retries + 1}, "
                    f"错误: {last_error}"
                )
            
            if attempt < max_retries:
                await self.metrics_collector.record_retry(metrics_id)
                wait_time = min(2 ** attempt, 10)
                logger.info(f"🔄 {wait_time}秒后重试...")
                await asyncio.sleep(wait_time)
        
        await self.metrics_collector.end_execution(
            metrics_id,
            success=False,
            error=last_error
        )
        
        if agent_config.ENABLE_NODE_SKIPPING:
            await self.metrics_collector.mark_skipped(metrics_id, last_error)
            logger.warning(
                f"⏭️ 节点已跳过: {node_name}, "
                f"任务ID: {task_id}, "
                f"原因: {last_error}"
            )
            return None, True
        
        logger.error(
            f"❌ 节点执行最终失败: {node_name}, "
            f"任务ID: {task_id}, "
            f"错误: {last_error}"
        )
        return None, False
    
    def get_execution_summary(self, task_id: Optional[str] = None) -> Dict[str, Any]:
        """获取执行摘要"""
        return self.metrics_collector.get_summary(task_id)
    
    def get_execution_metrics(self, task_id: Optional[str] = None) -> list:
        """获取执行指标"""
        return self.metrics_collector.get_metrics(task_id)


def optimized_node(node_name: str):
    """
    节点优化装饰器
    
    用于装饰异步节点函数，自动添加执行优化机制。
    装饰后的函数将自动获得：
    - 超时控制
    - 自动重试
    - 性能监控
    - 错误处理
    
    参数:
        node_name: 节点名称，用于日志和监控
    
    使用示例:
        @optimized_node("端口扫描")
        async def port_scan(state):
            # 扫描逻辑
            return result
        
        # 调用时会自动应用优化机制
        result = await port_scan(state)
    """
    def decorator(func):
        optimizer = NodeExecutionOptimizer()
        
        @wraps(func)
        async def wrapper(*args, **kwargs):
            task_id = None
            for arg in args:
                if hasattr(arg, 'task_id'):
                    task_id = arg.task_id
                    break
            
            if task_id is None:
                task_id = kwargs.get('task_id', f'unknown-{int(time.time())}')
            
            result, success = await optimizer.execute_with_optimization(
                func,
                node_name,
                task_id,
                *args,
                **kwargs
            )
            
            return result
        
        return wrapper
    return decorator


_execution_optimizer = NodeExecutionOptimizer()


def get_execution_optimizer() -> NodeExecutionOptimizer:
    """
    获取全局执行优化器实例
    
    返回单例模式的 NodeExecutionOptimizer 实例，
    用于在整个应用中共享执行优化配置和指标。
    
    返回:
        NodeExecutionOptimizer: 全局优化器实例
    
    使用示例:
        optimizer = get_execution_optimizer()
        summary = optimizer.get_execution_summary("task_001")
    """
    return _execution_optimizer
