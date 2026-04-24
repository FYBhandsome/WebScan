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

4. 数据持久化功能
   - WorkflowDataValidator: 工作流数据验证器
   - WorkflowPersistence: 工作流数据持久化管理器
   - get_workflow_persistence: 获取全局持久化实例

合并说明:
- 本模块合并了原 backend.ai_agents.core.execution_optimizer.py 的全部功能
- 统一了工作流数据的格式定义和转换逻辑
- 提供了执行性能监控和优化能力
- 提供了完整的数据持久化和验证功能

使用示例:
    from backend.api.workflow_schemas import (
        WorkflowDataConverter,
        StandardizedWorkflowData,
        get_execution_optimizer,
        get_workflow_persistence
    )
    
    # 转换工作流数据
    converter = WorkflowDataConverter()
    workflow_data = converter.from_agent_state(agent_state)
    
    # 使用执行优化器
    optimizer = get_execution_optimizer()
    result, success = await optimizer.execute_with_optimization(
        node_func, "node_name", "task_id"
    )
    
    # 保存工作流数据到数据库
    persistence = get_workflow_persistence()
    workflow_id = await persistence.save_workflow(workflow_data)
    
    # 保存完整工作流（包括执行历史和任务规划）
    result = await persistence.save_complete_workflow(
        workflow_data,
        task_id="task_001",
        task_plans=[{"plan_id": "p1", "plan_name": "端口扫描", "priority": 1}]
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


class WorkflowDataValidator:
    """
    工作流数据验证器
    
    提供数据完整性验证功能，确保数据符合预期格式和约束。
    
    主要方法:
        validate_workflow_data: 验证工作流数据
        validate_node_execution: 验证节点执行数据
        validate_task_plan: 验证任务规划数据
        validate_status: 验证状态值
        validate_progress: 验证进度值
    
    使用示例:
        validator = WorkflowDataValidator()
        is_valid, errors = validator.validate_workflow_data(workflow_dict)
        if not is_valid:
            print(f"验证失败: {errors}")
    """
    
    VALID_WORKFLOW_STATUSES = ["pending", "running", "completed", "failed", "cancelled"]
    VALID_NODE_STATUSES = ["pending", "running", "success", "failed", "skipped"]
    VALID_PLAN_STATUSES = ["pending", "running", "completed", "failed", "skipped"]
    
    @staticmethod
    def validate_workflow_data(data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        验证工作流数据完整性
        
        Args:
            data: 工作流数据字典
            
        Returns:
            (是否有效, 错误列表)
        """
        errors = []
        
        if not isinstance(data, dict):
            return False, ["数据必须是字典类型"]
        
        if "task_id" not in data or not data["task_id"]:
            errors.append("task_id 是必填字段")
        
        if "target" not in data or not data["target"]:
            errors.append("target 是必填字段")
        
        if "status" in data:
            is_valid, status_errors = WorkflowDataValidator.validate_status(
                data["status"], "workflow"
            )
            if not is_valid:
                errors.extend(status_errors)
        
        if "progress" in data:
            is_valid, progress_errors = WorkflowDataValidator.validate_progress(data["progress"])
            if not is_valid:
                errors.extend(progress_errors)
        
        if "execution_history" in data:
            if not isinstance(data["execution_history"], list):
                errors.append("execution_history 必须是列表类型")
        
        if "vulnerabilities" in data:
            if not isinstance(data["vulnerabilities"], list):
                errors.append("vulnerabilities 必须是列表类型")
        
        if "tool_results" in data:
            if not isinstance(data["tool_results"], dict):
                errors.append("tool_results 必须是字典类型")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def validate_node_execution(data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        验证节点执行数据完整性
        
        Args:
            data: 节点执行数据字典
            
        Returns:
            (是否有效, 错误列表)
        """
        errors = []
        
        if not isinstance(data, dict):
            return False, ["数据必须是字典类型"]
        
        if "node_id" not in data or not data["node_id"]:
            errors.append("node_id 是必填字段")
        
        if "node_name" not in data or not data["node_name"]:
            errors.append("node_name 是必填字段")
        
        if "status" in data:
            is_valid, status_errors = WorkflowDataValidator.validate_status(
                data["status"], "node"
            )
            if not is_valid:
                errors.extend(status_errors)
        
        if "step_number" in data:
            if not isinstance(data["step_number"], int) or data["step_number"] < 0:
                errors.append("step_number 必须是非负整数")
        
        if "duration_ms" in data:
            if not isinstance(data["duration_ms"], (int, float)) or data["duration_ms"] < 0:
                errors.append("duration_ms 必须是非负数值")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def validate_task_plan(data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        验证任务规划数据完整性
        
        Args:
            data: 任务规划数据字典
            
        Returns:
            (是否有效, 错误列表)
        """
        errors = []
        
        if not isinstance(data, dict):
            return False, ["数据必须是字典类型"]
        
        if "plan_id" not in data or not data["plan_id"]:
            errors.append("plan_id 是必填字段")
        
        if "plan_name" not in data or not data["plan_name"]:
            errors.append("plan_name 是必填字段")
        
        if "status" in data:
            is_valid, status_errors = WorkflowDataValidator.validate_status(
                data["status"], "plan"
            )
            if not is_valid:
                errors.extend(status_errors)
        
        if "priority" in data:
            if not isinstance(data["priority"], int) or not (1 <= data["priority"] <= 10):
                errors.append("priority 必须是1-10之间的整数")
        
        if "dependencies" in data:
            if not isinstance(data["dependencies"], list):
                errors.append("dependencies 必须是列表类型")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def validate_status(status: str, status_type: str = "workflow") -> Tuple[bool, List[str]]:
        """
        验证状态值
        
        Args:
            status: 状态值
            status_type: 状态类型 (workflow/node/plan)
            
        Returns:
            (是否有效, 错误列表)
        """
        errors = []
        
        if not isinstance(status, str):
            return False, ["状态必须是字符串类型"]
        
        status_lower = status.lower()
        
        if status_type == "workflow":
            valid_statuses = WorkflowDataValidator.VALID_WORKFLOW_STATUSES
        elif status_type == "node":
            valid_statuses = WorkflowDataValidator.VALID_NODE_STATUSES
        elif status_type == "plan":
            valid_statuses = WorkflowDataValidator.VALID_PLAN_STATUSES
        else:
            valid_statuses = WorkflowDataValidator.VALID_WORKFLOW_STATUSES
        
        if status_lower not in valid_statuses:
            errors.append(f"无效的{status_type}状态: {status}, 有效值: {valid_statuses}")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def validate_progress(progress: int) -> Tuple[bool, List[str]]:
        """
        验证进度值
        
        Args:
            progress: 进度值
            
        Returns:
            (是否有效, 错误列表)
        """
        errors = []
        
        if not isinstance(progress, int):
            return False, ["进度必须是整数类型"]
        
        if not (0 <= progress <= 100):
            errors.append("进度必须在0-100之间")
        
        return len(errors) == 0, errors


class WorkflowPersistence:
    """
    工作流数据持久化管理器
    
    提供工作流数据的数据库持久化功能，包括保存、更新、查询等操作。
    
    主要功能:
    - 工作流数据保存和更新
    - 执行历史保存
    - 任务规划数据保存
    - 执行结果保存
    - 数据完整性验证
    
    使用示例:
        persistence = WorkflowPersistence()
        
        # 保存工作流数据
        workflow_id = await persistence.save_workflow(workflow_data)
        
        # 保存执行历史
        await persistence.save_execution_history(workflow_id, execution_history)
        
        # 保存任务规划
        await persistence.save_task_plans(workflow_id, task_plans)
    """
    
    def __init__(self):
        self.validator = WorkflowDataValidator()
        self._initialized = False
    
    async def _ensure_db_initialized(self):
        """确保数据库已初始化"""
        if not self._initialized:
            try:
                from tortoise import Tortoise
                if not Tortoise._inited:
                    from backend.database import init_db
                    await init_db()
                self._initialized = True
            except Exception as e:
                logger.warning(f"数据库初始化检查: {e}")
                self._initialized = True
    
    async def save_workflow(
        self,
        workflow_data: StandardizedWorkflowData,
        task_id: Optional[str] = None,
        workflow_name: str = "AI Security Scan"
    ) -> str:
        """
        保存工作流数据到数据库
        
        Args:
            workflow_data: 标准化工作流数据
            task_id: 关联的任务ID
            workflow_name: 工作流名称
            
        Returns:
            工作流ID
            
        Raises:
            ValueError: 数据验证失败
        """
        await self._ensure_db_initialized()
        
        from backend.models import WorkflowExecution
        from uuid import uuid4
        
        data_dict = workflow_data.to_dict()
        
        is_valid, errors = self.validator.validate_workflow_data(data_dict)
        if not is_valid:
            raise ValueError(f"工作流数据验证失败: {', '.join(errors)}")
        
        workflow_id = str(uuid4())
        
        try:
            workflow = await WorkflowExecution.create(
                id=workflow_id,
                task_id=task_id or data_dict.get("task_id"),
                workflow_name=workflow_name,
                target=data_dict.get("target", ""),
                status=data_dict.get("status", "pending"),
                progress=data_dict.get("progress", 0),
                start_time=data_dict.get("start_time"),
                end_time=data_dict.get("end_time"),
                duration=data_dict.get("duration"),
                current_step=data_dict.get("current_step"),
                total_steps=data_dict.get("total_steps", 0),
                completed_steps=data_dict.get("completed_steps", 0),
                graph_flow=data_dict.get("graph_flow", {}),
                vulnerabilities=data_dict.get("vulnerabilities", []),
                tool_results=data_dict.get("tool_results", {}),
                metadata=data_dict.get("metadata", {})
            )
            
            logger.info(f"工作流数据已保存: {workflow_id}")
            return workflow_id
            
        except Exception as e:
            logger.error(f"保存工作流数据失败: {e}")
            raise
    
    async def update_workflow(
        self,
        workflow_id: str,
        workflow_data: StandardizedWorkflowData
    ) -> bool:
        """
        更新工作流数据
        
        Args:
            workflow_id: 工作流ID
            workflow_data: 标准化工作流数据
            
        Returns:
            是否更新成功
        """
        await self._ensure_db_initialized()
        
        from backend.models import WorkflowExecution
        
        data_dict = workflow_data.to_dict()
        
        is_valid, errors = self.validator.validate_workflow_data(data_dict)
        if not is_valid:
            raise ValueError(f"工作流数据验证失败: {', '.join(errors)}")
        
        try:
            workflow = await WorkflowExecution.get_or_none(id=workflow_id)
            if not workflow:
                logger.warning(f"工作流不存在: {workflow_id}")
                return False
            
            workflow.status = data_dict.get("status", workflow.status)
            workflow.progress = data_dict.get("progress", workflow.progress)
            workflow.end_time = data_dict.get("end_time", workflow.end_time)
            workflow.duration = data_dict.get("duration", workflow.duration)
            workflow.current_step = data_dict.get("current_step", workflow.current_step)
            workflow.total_steps = data_dict.get("total_steps", workflow.total_steps)
            workflow.completed_steps = data_dict.get("completed_steps", workflow.completed_steps)
            workflow.graph_flow = data_dict.get("graph_flow", workflow.graph_flow)
            workflow.vulnerabilities = data_dict.get("vulnerabilities", workflow.vulnerabilities)
            workflow.tool_results = data_dict.get("tool_results", workflow.tool_results)
            workflow.metadata = data_dict.get("metadata", workflow.metadata)
            
            if workflow.status == "failed":
                workflow.error_message = data_dict.get("error_message", "")
            
            await workflow.save()
            
            logger.info(f"工作流数据已更新: {workflow_id}")
            return True
            
        except Exception as e:
            logger.error(f"更新工作流数据失败: {e}")
            raise
    
    async def save_execution_history(
        self,
        workflow_id: str,
        execution_history: List[Dict[str, Any]]
    ) -> int:
        """
        保存执行历史到数据库
        
        Args:
            workflow_id: 工作流ID
            execution_history: 执行历史列表
            
        Returns:
            保存的记录数量
        """
        await self._ensure_db_initialized()
        
        from backend.models import WorkflowExecution, WorkflowNodeExecution
        
        if not execution_history:
            return 0
        
        try:
            workflow = await WorkflowExecution.get_or_none(id=workflow_id)
            if not workflow:
                raise ValueError(f"工作流不存在: {workflow_id}")
            
            saved_count = 0
            for idx, record in enumerate(execution_history):
                is_valid, errors = self.validator.validate_node_execution(record)
                if not is_valid:
                    logger.warning(f"节点执行数据验证失败，跳过: {errors}")
                    continue
                
                node_execution = await WorkflowNodeExecution.create(
                    workflow=workflow,
                    node_id=record.get("node_id", f"node-{idx}"),
                    node_name=record.get("node_name", "Unknown"),
                    node_type=record.get("node_type", "unknown"),
                    status=record.get("status", "pending"),
                    step_number=record.get("step_number", idx + 1),
                    start_time=record.get("start_time"),
                    end_time=record.get("end_time"),
                    duration_ms=record.get("duration_ms"),
                    execution_time=record.get("execution_time"),
                    input_params=record.get("input_params", {}),
                    output_data=record.get("output_data", {}),
                    error=record.get("error"),
                    error_message=record.get("error_message"),
                    task=record.get("task"),
                    tool_name=record.get("tool_name"),
                    timestamp=record.get("timestamp"),
                    timestamp_iso=record.get("timestamp_iso"),
                    metadata=record.get("metadata", {})
                )
                saved_count += 1
            
            logger.info(f"执行历史已保存: {saved_count} 条记录")
            return saved_count
            
        except Exception as e:
            logger.error(f"保存执行历史失败: {e}")
            raise
    
    async def save_task_plans(
        self,
        workflow_id: str,
        task_plans: List[Dict[str, Any]]
    ) -> int:
        """
        保存任务规划数据到数据库
        
        Args:
            workflow_id: 工作流ID
            task_plans: 任务规划列表
            
        Returns:
            保存的记录数量
        """
        await self._ensure_db_initialized()
        
        from backend.models import WorkflowExecution, WorkflowTaskPlan
        
        if not task_plans:
            return 0
        
        try:
            workflow = await WorkflowExecution.get_or_none(id=workflow_id)
            if not workflow:
                raise ValueError(f"工作流不存在: {workflow_id}")
            
            saved_count = 0
            for idx, plan in enumerate(task_plans):
                is_valid, errors = self.validator.validate_task_plan(plan)
                if not is_valid:
                    logger.warning(f"任务规划数据验证失败，跳过: {errors}")
                    continue
                
                task_plan = await WorkflowTaskPlan.create(
                    workflow=workflow,
                    plan_id=plan.get("plan_id", f"plan-{idx}"),
                    plan_name=plan.get("plan_name", "Unknown Task"),
                    plan_type=plan.get("plan_type", "scan"),
                    priority=plan.get("priority", 5),
                    status=plan.get("status", "pending"),
                    dependencies=plan.get("dependencies", []),
                    estimated_time=plan.get("estimated_time"),
                    actual_time=plan.get("actual_time"),
                    parameters=plan.get("parameters", {}),
                    result=plan.get("result", {}),
                    error_message=plan.get("error_message")
                )
                saved_count += 1
            
            logger.info(f"任务规划已保存: {saved_count} 条记录")
            return saved_count
            
        except Exception as e:
            logger.error(f"保存任务规划失败: {e}")
            raise
    
    async def save_execution_result(
        self,
        workflow_id: str,
        result_type: str,
        result_data: Dict[str, Any]
    ) -> bool:
        """
        保存执行结果
        
        Args:
            workflow_id: 工作流ID
            result_type: 结果类型 (vulnerability/scan/tool)
            result_data: 结果数据
            
        Returns:
            是否保存成功
        """
        await self._ensure_db_initialized()
        
        from backend.models import WorkflowExecution
        
        try:
            workflow = await WorkflowExecution.get_or_none(id=workflow_id)
            if not workflow:
                raise ValueError(f"工作流不存在: {workflow_id}")
            
            if result_type == "vulnerability":
                vulnerabilities = workflow.vulnerabilities or []
                vulnerabilities.append(result_data)
                workflow.vulnerabilities = vulnerabilities
            elif result_type == "scan":
                tool_results = workflow.tool_results or {}
                scan_results = tool_results.get("scan_results", [])
                scan_results.append(result_data)
                tool_results["scan_results"] = scan_results
                workflow.tool_results = tool_results
            elif result_type == "tool":
                tool_results = workflow.tool_results or {}
                tool_name = result_data.get("tool_name", "unknown")
                tool_results[tool_name] = result_data
                workflow.tool_results = tool_results
            else:
                metadata = workflow.metadata or {}
                if "results" not in metadata:
                    metadata["results"] = {}
                if result_type not in metadata["results"]:
                    metadata["results"][result_type] = []
                metadata["results"][result_type].append(result_data)
                workflow.metadata = metadata
            
            await workflow.save()
            
            logger.info(f"执行结果已保存: {result_type}")
            return True
            
        except Exception as e:
            logger.error(f"保存执行结果失败: {e}")
            raise
    
    async def get_workflow(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        """
        获取工作流数据
        
        Args:
            workflow_id: 工作流ID
            
        Returns:
            工作流数据字典，不存在返回None
        """
        await self._ensure_db_initialized()
        
        from backend.models import WorkflowExecution
        
        try:
            workflow = await WorkflowExecution.get_or_none(id=workflow_id)
            if not workflow:
                return None
            
            return {
                "id": str(workflow.id),
                "task_id": workflow.task_id,
                "workflow_name": workflow.workflow_name,
                "target": workflow.target,
                "status": workflow.status,
                "progress": workflow.progress,
                "start_time": workflow.start_time,
                "end_time": workflow.end_time,
                "duration": workflow.duration,
                "current_step": workflow.current_step,
                "total_steps": workflow.total_steps,
                "completed_steps": workflow.completed_steps,
                "graph_flow": workflow.graph_flow,
                "vulnerabilities": workflow.vulnerabilities,
                "tool_results": workflow.tool_results,
                "metadata": workflow.metadata,
                "error_message": workflow.error_message,
                "created_at": workflow.created_at.isoformat() if workflow.created_at else None,
                "updated_at": workflow.updated_at.isoformat() if workflow.updated_at else None
            }
            
        except Exception as e:
            logger.error(f"获取工作流数据失败: {e}")
            raise
    
    async def get_execution_history(
        self,
        workflow_id: str,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        获取执行历史
        
        Args:
            workflow_id: 工作流ID
            limit: 返回记录数量限制
            
        Returns:
            执行历史列表
        """
        await self._ensure_db_initialized()
        
        from backend.models import WorkflowNodeExecution
        
        try:
            node_executions = await WorkflowNodeExecution.filter(
                workflow_id=workflow_id
            ).order_by("step_number").limit(limit)
            
            return [
                {
                    "id": ne.id,
                    "node_id": ne.node_id,
                    "node_name": ne.node_name,
                    "node_type": ne.node_type,
                    "status": ne.status,
                    "step_number": ne.step_number,
                    "start_time": ne.start_time,
                    "end_time": ne.end_time,
                    "duration_ms": ne.duration_ms,
                    "execution_time": ne.execution_time,
                    "input_params": ne.input_params,
                    "output_data": ne.output_data,
                    "error": ne.error,
                    "error_message": ne.error_message,
                    "task": ne.task,
                    "tool_name": ne.tool_name,
                    "timestamp": ne.timestamp,
                    "timestamp_iso": ne.timestamp_iso,
                    "metadata": ne.metadata,
                    "created_at": ne.created_at.isoformat() if ne.created_at else None
                }
                for ne in node_executions
            ]
            
        except Exception as e:
            logger.error(f"获取执行历史失败: {e}")
            raise
    
    async def get_task_plans(
        self,
        workflow_id: str
    ) -> List[Dict[str, Any]]:
        """
        获取任务规划
        
        Args:
            workflow_id: 工作流ID
            
        Returns:
            任务规划列表
        """
        await self._ensure_db_initialized()
        
        from backend.models import WorkflowTaskPlan
        
        try:
            task_plans = await WorkflowTaskPlan.filter(
                workflow_id=workflow_id
            ).order_by("priority")
            
            return [
                {
                    "id": tp.id,
                    "plan_id": tp.plan_id,
                    "plan_name": tp.plan_name,
                    "plan_type": tp.plan_type,
                    "priority": tp.priority,
                    "status": tp.status,
                    "dependencies": tp.dependencies,
                    "estimated_time": tp.estimated_time,
                    "actual_time": tp.actual_time,
                    "parameters": tp.parameters,
                    "result": tp.result,
                    "error_message": tp.error_message,
                    "created_at": tp.created_at.isoformat() if tp.created_at else None,
                    "updated_at": tp.updated_at.isoformat() if tp.updated_at else None
                }
                for tp in task_plans
            ]
            
        except Exception as e:
            logger.error(f"获取任务规划失败: {e}")
            raise
    
    async def delete_workflow(self, workflow_id: str) -> bool:
        """
        删除工作流及相关数据
        
        Args:
            workflow_id: 工作流ID
            
        Returns:
            是否删除成功
        """
        await self._ensure_db_initialized()
        
        from backend.models import WorkflowExecution, WorkflowNodeExecution, WorkflowTaskPlan
        
        try:
            workflow = await WorkflowExecution.get_or_none(id=workflow_id)
            if not workflow:
                return False
            
            await WorkflowNodeExecution.filter(workflow_id=workflow_id).delete()
            await WorkflowTaskPlan.filter(workflow_id=workflow_id).delete()
            await workflow.delete()
            
            logger.info(f"工作流已删除: {workflow_id}")
            return True
            
        except Exception as e:
            logger.error(f"删除工作流失败: {e}")
            raise
    
    async def save_complete_workflow(
        self,
        workflow_data: StandardizedWorkflowData,
        task_id: Optional[str] = None,
        workflow_name: str = "AI Security Scan",
        task_plans: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        保存完整的工作流数据（包括执行历史和任务规划）
        
        Args:
            workflow_data: 标准化工作流数据
            task_id: 关联的任务ID
            workflow_name: 工作流名称
            task_plans: 任务规划列表
            
        Returns:
            保存结果信息
        """
        result = {
            "workflow_id": None,
            "execution_history_count": 0,
            "task_plans_count": 0,
            "success": False,
            "errors": []
        }
        
        try:
            workflow_id = await self.save_workflow(
                workflow_data,
                task_id=task_id,
                workflow_name=workflow_name
            )
            result["workflow_id"] = workflow_id
            
            if workflow_data.execution_history:
                count = await self.save_execution_history(
                    workflow_id,
                    workflow_data.execution_history
                )
                result["execution_history_count"] = count
            
            if task_plans:
                count = await self.save_task_plans(workflow_id, task_plans)
                result["task_plans_count"] = count
            
            result["success"] = True
            logger.info(f"完整工作流数据已保存: {workflow_id}")
            
        except Exception as e:
            result["errors"].append(str(e))
            logger.error(f"保存完整工作流数据失败: {e}")
        
        return result


_workflow_persistence: Optional[WorkflowPersistence] = None


def get_workflow_persistence() -> WorkflowPersistence:
    """
    获取全局工作流持久化实例
    
    返回单例模式的 WorkflowPersistence 实例，
    用于在整个应用中共享数据持久化功能。
    
    返回:
        WorkflowPersistence: 全局持久化实例
    
    使用示例:
        persistence = get_workflow_persistence()
        workflow_id = await persistence.save_workflow(workflow_data)
    """
    global _workflow_persistence
    if _workflow_persistence is None:
        _workflow_persistence = WorkflowPersistence()
    return _workflow_persistence
