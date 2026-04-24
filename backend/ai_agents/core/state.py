"""
Agent 状态管理

定义Agent的状态结构,用于LangGraph的状态传递。
"""
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import asyncio
import logging
import json
import time
from enum import Enum

logger = logging.getLogger(__name__)


class NodeStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class NodeExecutionRecord:
    node_name: str
    node_type: str
    status: NodeStatus = NodeStatus.PENDING
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    duration_ms: Optional[float] = None
    input_data: Dict[str, Any] = field(default_factory=dict)
    output_data: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def start(self, input_data: Dict[str, Any] = None):
        self.status = NodeStatus.RUNNING
        self.start_time = time.time()
        if input_data:
            self.input_data = input_data
    
    def complete(self, output_data: Dict[str, Any] = None, metadata: Dict[str, Any] = None):
        self.status = NodeStatus.SUCCESS
        self.end_time = time.time()
        self.duration_ms = (self.end_time - self.start_time) * 1000 if self.start_time else None
        if output_data:
            self.output_data = output_data
        if metadata:
            self.metadata.update(metadata)
    
    def fail(self, error_message: str, output_data: Dict[str, Any] = None):
        self.status = NodeStatus.FAILED
        self.end_time = time.time()
        self.duration_ms = (self.end_time - self.start_time) * 1000 if self.start_time else None
        self.error_message = error_message
        if output_data:
            self.output_data = output_data
    
    def skip(self, reason: str = None):
        self.status = NodeStatus.SKIPPED
        self.end_time = time.time()
        self.duration_ms = 0
        if reason:
            self.metadata["skip_reason"] = reason
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_name": self.node_name,
            "node_type": self.node_type,
            "status": self.status.value,
            "start_time": self.start_time,
            "start_time_iso": datetime.fromtimestamp(self.start_time).isoformat() if self.start_time else None,
            "end_time": self.end_time,
            "end_time_iso": datetime.fromtimestamp(self.end_time).isoformat() if self.end_time else None,
            "duration_ms": self.duration_ms,
            "input_data": self.input_data,
            "output_data": self.output_data,
            "error_message": self.error_message,
            "metadata": self.metadata
        }


@dataclass
class WorkflowTrace:
    workflow_id: str
    task_id: str
    target: str
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    total_duration_ms: Optional[float] = None
    nodes: List[NodeExecutionRecord] = field(default_factory=list)
    current_node_index: int = -1
    workflow_status: NodeStatus = NodeStatus.PENDING
    summary: Dict[str, Any] = field(default_factory=dict)
    
    def start_workflow(self):
        self.workflow_status = NodeStatus.RUNNING
        self.start_time = time.time()
    
    def start_node(self, node_name: str, node_type: str, input_data: Dict[str, Any] = None) -> int:
        node = NodeExecutionRecord(node_name=node_name, node_type=node_type)
        node.start(input_data)
        self.nodes.append(node)
        self.current_node_index = len(self.nodes) - 1
        return self.current_node_index
    
    def complete_node(self, node_index: int, output_data: Dict[str, Any] = None, metadata: Dict[str, Any] = None):
        if 0 <= node_index < len(self.nodes):
            self.nodes[node_index].complete(output_data, metadata)
    
    def fail_node(self, node_index: int, error_message: str, output_data: Dict[str, Any] = None):
        if 0 <= node_index < len(self.nodes):
            self.nodes[node_index].fail(error_message, output_data)
    
    def skip_node(self, node_index: int, reason: str = None):
        if 0 <= node_index < len(self.nodes):
            self.nodes[node_index].skip(reason)
    
    def complete_workflow(self, summary: Dict[str, Any] = None):
        self.workflow_status = NodeStatus.SUCCESS
        self.end_time = time.time()
        self.total_duration_ms = (self.end_time - self.start_time) * 1000
        if summary:
            self.summary = summary
    
    def fail_workflow(self, error_message: str):
        self.workflow_status = NodeStatus.FAILED
        self.end_time = time.time()
        self.total_duration_ms = (self.end_time - self.start_time) * 1000
        self.summary["error"] = error_message
    
    def get_node_by_name(self, node_name: str) -> Optional[NodeExecutionRecord]:
        for node in self.nodes:
            if node.node_name == node_name:
                return node
        return None
    
    def get_nodes_by_status(self, status: NodeStatus) -> List[NodeExecutionRecord]:
        return [node for node in self.nodes if node.status == status]
    
    def get_statistics(self) -> Dict[str, Any]:
        total = len(self.nodes)
        success = len(self.get_nodes_by_status(NodeStatus.SUCCESS))
        failed = len(self.get_nodes_by_status(NodeStatus.FAILED))
        skipped = len(self.get_nodes_by_status(NodeStatus.SKIPPED))
        running = len(self.get_nodes_by_status(NodeStatus.RUNNING))
        
        total_duration = sum(node.duration_ms or 0 for node in self.nodes)
        avg_duration = total_duration / success if success > 0 else 0
        
        return {
            "total_nodes": total,
            "success_count": success,
            "failed_count": failed,
            "skipped_count": skipped,
            "running_count": running,
            "total_duration_ms": total_duration,
            "average_duration_ms": avg_duration,
            "success_rate": (success / total * 100) if total > 0 else 0
        }
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "workflow_id": self.workflow_id,
            "task_id": self.task_id,
            "target": self.target,
            "start_time": self.start_time,
            "start_time_iso": datetime.fromtimestamp(self.start_time).isoformat() if self.start_time else None,
            "end_time": self.end_time,
            "end_time_iso": datetime.fromtimestamp(self.end_time).isoformat() if self.end_time else None,
            "total_duration_ms": self.total_duration_ms,
            "workflow_status": self.workflow_status.value,
            "nodes": [node.to_dict() for node in self.nodes],
            "current_node_index": self.current_node_index,
            "summary": self.summary,
            "statistics": self.get_statistics()
        }


class WorkflowRecorder:
    _instance = None
    _workflows: Dict[str, WorkflowTrace] = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    @classmethod
    def create_workflow(cls, task_id: str, target: str) -> WorkflowTrace:
        workflow_id = f"wf_{task_id}_{int(time.time() * 1000)}"
        workflow = WorkflowTrace(
            workflow_id=workflow_id,
            task_id=task_id,
            target=target
        )
        cls._workflows[workflow_id] = workflow
        return workflow
    
    @classmethod
    def get_workflow(cls, workflow_id: str) -> Optional[WorkflowTrace]:
        return cls._workflows.get(workflow_id)
    
    @classmethod
    def get_workflow_by_task(cls, task_id: str) -> Optional[WorkflowTrace]:
        for workflow in cls._workflows.values():
            if workflow.task_id == task_id:
                return workflow
        return None
    
    @classmethod
    def remove_workflow(cls, workflow_id: str):
        if workflow_id in cls._workflows:
            del cls._workflows[workflow_id]
    
    @classmethod
    def get_all_workflows(cls) -> Dict[str, WorkflowTrace]:
        return cls._workflows.copy()
    
    @classmethod
    def clear_all(cls):
        cls._workflows.clear()

try:
    from backend.utils.serializers import sanitize_json_data
except ImportError:
    from utils.serializers import sanitize_json_data


async def persist_task_state(task_id: str, state_data: Dict[str, Any], progress: int = None):
    """
    持久化完整的任务状态到数据库
    
    Args:
        task_id: 任务ID
        state_data: 完整的状态数据字典，包含所有需要持久化的字段
        progress: 可选的进度值，如果不提供则从state_data中获取
    
    持久化的数据包括：
        - stages: 阶段状态
        - tool_results: 工具执行结果
        - vulnerabilities: 发现的漏洞
        - execution_history: 执行历史
        - target_context: 目标上下文
        - scan_summary: 扫描摘要
        - report: 分析报告
        - planned_tasks: 规划的任务
        - completed_tasks: 已完成的任务
        - errors: 错误信息
        - seebug_pocs: Seebug POC列表
        - generated_pocs: 生成的POC列表
        - workflow_trace: 工作流追踪记录
    """
    try:
        try:
            from backend.models import Task
        except ImportError:
            from models import Task
        
        try:
            tid = int(task_id)
        except ValueError:
            logger.error(f"Invalid task_id format: {task_id}")
            return
            
        task = await Task.get(id=tid)
        
        if progress is not None:
            task.progress = progress
        elif 'progress' in state_data:
            task.progress = state_data['progress']
        
        try:
            current_result = json.loads(task.result) if task.result else {}
        except:
            current_result = {}
        
        current_result['stages'] = state_data.get('stage_status', {})
        
        if 'tool_results' in state_data and state_data['tool_results']:
            current_result['tool_results'] = state_data['tool_results']
        
        if 'vulnerabilities' in state_data and state_data['vulnerabilities']:
            current_result['vulnerabilities'] = state_data['vulnerabilities']
        
        if 'execution_history' in state_data and state_data['execution_history']:
            current_result['execution_history'] = state_data['execution_history']
        
        if 'target_context' in state_data and state_data['target_context']:
            current_result['target_context'] = state_data['target_context']
        
        if 'scan_summary' in state_data and state_data['scan_summary']:
            current_result['scan_summary'] = state_data['scan_summary']
        
        if 'report' in state_data and state_data['report']:
            current_result['report'] = state_data['report']
        
        if 'planned_tasks' in state_data:
            current_result['planned_tasks'] = state_data['planned_tasks']
        
        if 'completed_tasks' in state_data:
            current_result['completed_tasks'] = state_data['completed_tasks']
        
        if 'errors' in state_data and state_data['errors']:
            current_result['errors'] = state_data['errors']
        
        if 'seebug_pocs' in state_data and state_data['seebug_pocs']:
            current_result['seebug_pocs'] = state_data['seebug_pocs']
        
        if 'generated_pocs' in state_data and state_data['generated_pocs']:
            current_result['generated_pocs'] = state_data['generated_pocs']
        
        if 'current_task' in state_data:
            current_result['current_task'] = state_data['current_task']
        
        if 'vuln_scan_results' in state_data and state_data['vuln_scan_results']:
            current_result['vuln_scan_results'] = state_data['vuln_scan_results']
        
        if 'vuln_scan_plugins_loaded' in state_data:
            current_result['vuln_scan_plugins_loaded'] = state_data['vuln_scan_plugins_loaded']
        
        if 'vuln_scan_progress' in state_data:
            current_result['vuln_scan_progress'] = state_data['vuln_scan_progress']
        
        if 'workflow_trace' in state_data and state_data['workflow_trace']:
            current_result['workflow_trace'] = state_data['workflow_trace']
        
        if 'scan_summary' not in current_result:
            current_result['scan_summary'] = {}
        if 'vulnerabilities' not in current_result:
            current_result['vulnerabilities'] = []
        if 'report' not in current_result:
            current_result['report'] = ""
        if 'execution_history' not in current_result:
            current_result['execution_history'] = []
        if 'tool_results' not in current_result:
            current_result['tool_results'] = {}
        if 'target_context' not in current_result:
            current_result['target_context'] = {}
        if 'workflow_trace' not in current_result:
            current_result['workflow_trace'] = {}
        
        current_result = sanitize_json_data(current_result)
        task.result = json.dumps(current_result, default=str)
        
        await task.save()
        
        logger.info(
            f"Successfully persisted task state for {task_id}: "
            f"{len(current_result.get('vulnerabilities', []))} vulnerabilities, "
            f"{len(current_result.get('execution_history', []))} history items, "
            f"{len(current_result.get('tool_results', {}))} tool results, "
            f"workflow nodes: {len(current_result.get('workflow_trace', {}).get('nodes', []))}"
        )
        
    except Exception as e:
        logger.error(f"Failed to persist task state for {task_id}: {e}", exc_info=True)


@dataclass
class AgentState:
    """
    Agent状态类
    
    管理Agent执行过程中的所有状态信息,包括:
    - 基础信息:目标、任务ID
    - 任务规划:规划任务列表、当前任务、已完成任务
    - 执行结果:工具结果、发现的漏洞
    - 记忆与上下文:目标上下文、执行历史
    - 异常处理:错误列表、重试次数
    - 控制开关:完成标志、继续执行标志
    - 工作流追踪:工作流执行记录、节点状态追踪
    
    Attributes:
        target: 扫描目标(URL/IP)
        task_id: 任务ID
        planned_tasks: 规划的子任务列表
        current_task: 当前执行的子任务
        completed_tasks: 已完成子任务列表
        tool_results: 工具执行结果字典
        vulnerabilities: 发现的漏洞列表
        target_context: 目标上下文(CMS、端口、WAF等)
        execution_history: 执行历史记录
        errors: 执行错误列表
        retry_count: 重试次数
        is_complete: 任务是否完成
        should_continue: 是否继续执行
        workflow_trace: 工作流执行追踪记录
    """
    
    # = 基础信息 =
    target: str
    """
    扫描目标
    
    可以是URL、IP地址或域名。
    """
    
    task_id: str
    """
    任务ID
    
    用于标识和跟踪Agent任务。
    """
    
    # = 工作流追踪 =
    workflow_trace: Optional[WorkflowTrace] = None
    """
    工作流执行追踪记录
    
    记录整个工作流的执行过程，包括：
    - 各节点的执行状态
    - 执行时间戳
    - 输入输出数据
    - 执行统计信息
    """
    
    _current_node_index: int = field(default=-1, repr=False)
    """
    当前正在执行的节点索引（内部使用）
    """
    
    # = 任务规划 =
    planned_tasks: List[str] = field(default_factory=list)
    """
    规划的子任务列表
    
    包含待执行的任务名称,如["baseinfo", "portscan", "poc_weblogic_2020_2551"]。
    """
    
    current_task: Optional[str] = None
    """
    当前执行的子任务
    
    表示Agent当前正在执行的任务。
    """
    
    completed_tasks: List[str] = field(default_factory=list)
    """
    已完成子任务列表
    
    记录已成功执行的任务。
    """
    
    # = 执行结果 =
    tool_results: Dict[str, Any] = field(default_factory=dict)
    """
    工具执行结果字典
    
    存储每个工具的执行结果,键为工具名称,值为结果数据。
    """
    
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    """
    发现的漏洞列表
    
    每个漏洞包含CVE、严重度、详情等信息。
    """
    
    # = 记忆与上下文 =
    target_context: Dict[str, Any] = field(default_factory=dict)
    """
    目标上下文

    存储目标的关键特征,如:
    - cms: CMS类型(WordPress、Drupal等)
    - open_ports: 开放端口列表
    - waf: WAF类型
    - cdn: 是否使用CDN
    - server: 服务器类型
    - os: 操作系统
    """
    
    user_tools: List[Dict[str, Any]] = field(default_factory=list)
    """
    用户提供的工具列表

    存储用户请求中提供的可用工具。
    """
    
    user_requirement: str = ""
    """
    用户需求描述

    用户的具体需求和目标描述。
    """
    
    memory_info: str = ""
    """
    记忆信息

    用于上下文传递的记忆信息。
    """
    
    plan_data: Optional[str] = None
    """
    规划数据

    存储规划节点的输出数据。
    """
    
    execution_results: List[Dict[str, Any]] = field(default_factory=list)
    """
    执行结果列表

    存储工具执行的结果列表。
    """
    
    execution_history: List[Dict[str, Any]] = field(default_factory=list)
    """
    执行历史记录
    
    记录Agent的执行步骤,用于追溯和调试。
    每条记录包含:task、result、timestamp等。
    """
    
    # = 异常处理 =
    errors: List[str] = field(default_factory=list)
    """
    执行错误列表
    
    记录执行过程中发生的错误信息。
    """
    
    retry_count: int = 0
    """
    重试次数
    
    记录当前任务的重试次数。
    """
    
    enhancement_retry_count: int = 0
    """
    功能增强重试次数
    
    记录功能增强的重试次数,防止无限循环。
    """
    
    # = 控制开关 =
    is_complete: bool = False
    """
    任务是否完成
    
    设置为True时,Agent将结束执行。
    """
    
    should_continue: bool = True
    """
    是否继续执行
    
    用于条件分支控制,决定是否继续执行工具还是进入下一阶段。
    """
    
    # = Seebug Agent =
    seebug_pocs: List[Dict[str, Any]] = field(default_factory=list)
    """
    Seebug POC 搜索结果列表
    
    存储从Seebug搜索到的POC列表,每个POC包含:
    - ssvid: POC ID
    - name: POC 名称
    - type: POC 类型
    - description: POC 描述
    """
    
    generated_pocs: List[Dict[str, Any]] = field(default_factory=list)
    """
    生成的 POC 列表
    
    存储生成的POC代码,每个POC包含:
    - poc_id: POC ID
    - name: POC 名称
    - code: POC 代码
    - source: 来源
    """
    
    # = Stage Tracking =
    stage_status: Dict[str, Dict[str, Any]] = field(default_factory=lambda: {
        "planning": {"status": "pending", "sub_status": "pending", "progress": 0, "logs": [], "start_time": None, "end_time": None},
        "tool_execution": {"status": "pending", "sub_status": "pending", "progress": 0, "logs": [], "start_time": None, "end_time": None},
        "poc_verification": {"status": "pending", "sub_status": "pending", "progress": 0, "logs": [], "start_time": None, "end_time": None},
        "report": {"status": "pending", "sub_status": "pending", "progress": 0, "logs": [], "start_time": None, "end_time": None}
    })
    
    def __post_init__(self):
        if self.workflow_trace is None:
            self.workflow_trace = WorkflowRecorder.create_workflow(self.task_id, self.target)
    
    def start_workflow_recording(self):
        if self.workflow_trace:
            self.workflow_trace.start_workflow()
            logger.info(f"[{self.task_id}] 🚀 工作流开始记录 | Workflow ID: {self.workflow_trace.workflow_id}")
    
    def start_node_recording(self, node_name: str, node_type: str, input_data: Dict[str, Any] = None) -> int:
        if self.workflow_trace:
            node_index = self.workflow_trace.start_node(node_name, node_type, input_data)
            self._current_node_index = node_index
            logger.debug(f"[{self.task_id}] 📍 节点开始 | 节点: {node_name} | 类型: {node_type} | 索引: {node_index}")
            return node_index
        return -1
    
    def complete_node_recording(self, node_index: int = None, output_data: Dict[str, Any] = None, metadata: Dict[str, Any] = None):
        if self.workflow_trace:
            idx = node_index if node_index is not None else self._current_node_index
            if idx >= 0:
                self.workflow_trace.complete_node(idx, output_data, metadata)
                node = self.workflow_trace.nodes[idx] if idx < len(self.workflow_trace.nodes) else None
                if node:
                    logger.debug(f"[{self.task_id}] ✅ 节点完成 | 节点: {node.node_name} | 耗时: {node.duration_ms:.2f}ms")
    
    def fail_node_recording(self, error_message: str, node_index: int = None, output_data: Dict[str, Any] = None):
        if self.workflow_trace:
            idx = node_index if node_index is not None else self._current_node_index
            if idx >= 0:
                self.workflow_trace.fail_node(idx, error_message, output_data)
                node = self.workflow_trace.nodes[idx] if idx < len(self.workflow_trace.nodes) else None
                if node:
                    logger.debug(f"[{self.task_id}] ❌ 节点失败 | 节点: {node.node_name} | 错误: {error_message}")
    
    def skip_node_recording(self, reason: str = None, node_index: int = None):
        if self.workflow_trace:
            idx = node_index if node_index is not None else self._current_node_index
            if idx >= 0:
                self.workflow_trace.skip_node(idx, reason)
                node = self.workflow_trace.nodes[idx] if idx < len(self.workflow_trace.nodes) else None
                if node:
                    logger.debug(f"[{self.task_id}] ⏭️ 节点跳过 | 节点: {node.node_name} | 原因: {reason}")
    
    def complete_workflow_recording(self, summary: Dict[str, Any] = None):
        if self.workflow_trace:
            self.workflow_trace.complete_workflow(summary)
            stats = self.workflow_trace.get_statistics()
            logger.info(
                f"[{self.task_id}] 🏁 工作流完成 | "
                f"总节点: {stats['total_nodes']} | "
                f"成功: {stats['success_count']} | "
                f"失败: {stats['failed_count']} | "
                f"总耗时: {stats['total_duration_ms']:.2f}ms | "
                f"成功率: {stats['success_rate']:.1f}%"
            )
    
    def fail_workflow_recording(self, error_message: str):
        if self.workflow_trace:
            self.workflow_trace.fail_workflow(error_message)
            logger.error(f"[{self.task_id}] 💥 工作流失败 | 错误: {error_message}")
    
    def get_workflow_statistics(self) -> Dict[str, Any]:
        if self.workflow_trace:
            return self.workflow_trace.get_statistics()
        return {}
    
    def get_workflow_report(self) -> Dict[str, Any]:
        if self.workflow_trace:
            return self.workflow_trace.to_dict()
        return {}
    
    # = Vulnerability Scan =
    vuln_scan_results: Dict[str, Any] = field(default_factory=dict)
    vuln_scan_plugins_loaded: List[str] = field(default_factory=list)
    vuln_scan_progress: int = 0
    vuln_scan_metadata: Dict[str, Any] = field(default_factory=dict)
    """
    Stage Tracking
    
    Track the progress of 4 stages: openai, plugins, awvs, pocsuite3.
    """
    
    # = AI Analysis Results =
    scan_summary: Dict[str, Any] = field(default_factory=dict)
    """
    扫描摘要
    
    存储AI分析的扫描摘要结果。
    """
    
    report: str = ""
    """
    分析报告
    
    存储AI生成的完整分析报告。
    """
    
    def update_stage_status(self, stage: str, status: str = None, sub_status: str = None, progress: int = None, log: str = None):
        """
        Update stage status and broadcast via WebSocket
        
        更新阶段状态并通过WebSocket广播，同时持久化完整的任务状态到数据库
        
        Args:
            stage: 阶段名称 (planning, tool_execution, poc_verification, report)
            status: 阶段状态 (pending, running, completed, failed)
            sub_status: 子状态描述
            progress: 进度值 (0-100)
            log: 日志消息
        """
        try:
            from backend.api.websocket import manager
        except ImportError:
            from api.websocket import manager

        if stage in self.stage_status:
            if status:
                self.stage_status[stage]["status"] = status
            if sub_status:
                self.stage_status[stage]["sub_status"] = sub_status
            if progress is not None:
                self.stage_status[stage]["progress"] = progress
            if log:
                entry = {
                    "timestamp": datetime.now().isoformat(),
                    "message": log,
                    "sub_status": sub_status or self.stage_status[stage]["sub_status"]
                }
                self.stage_status[stage]["logs"].append(entry)
            
            try:
                try:
                    loop = asyncio.get_running_loop()
                    if loop.is_running():
                        asyncio.create_task(manager.broadcast({
                            "type": "stage_update",
                            "payload": {
                                "task_id": self.task_id,
                                "stage": stage,
                                "data": self.stage_status[stage]
                            }
                        }))
                        
                        state_data = self.to_dict()
                        
                        asyncio.create_task(persist_task_state(
                            self.task_id, 
                            state_data,
                            self.get_progress()
                        ))
                except RuntimeError:
                    pass
            except Exception as e:
                logger.error(f"Failed to broadcast stage update: {e}")

    def get_progress(self) -> int:
        """
        Get total progress
        """
        total = 0
        count = 0
        for stage in self.stage_status.values():
            total += stage["progress"]
            count += 1
        return int(total / count) if count > 0 else 0

    def add_execution_step(
        self,
        task: str,
        result: Any,
        status: str = "success",
        step_type: str = "tool_execution",
        input_params: Dict[str, Any] = None,
        processing_logic: str = "",
        intermediate_results: List[Dict[str, Any]] = None,
        output_data: Dict[str, Any] = None,
        data_changes: Dict[str, Any] = None,
        state_transitions: List[str] = None,
        execution_time: float = None
    ):
        """
        添加执行步骤到历史记录（增强版）
        
        Args:
            task: 任务名称
            result: 执行结果
            status: 执行状态(success/failed/pending/running)
            step_type: 步骤类型(tool_execution/code_generation/code_execution/capability_enhancement/verification/analysis)
            input_params: 输入参数
            processing_logic: 处理逻辑描述
            intermediate_results: 中间结果列表
            output_data: 输出数据
            data_changes: 关键数据变化
            state_transitions: 状态转换列表
            execution_time: 执行时间（秒）
        """
        import time
        current_time = time.time()
        
        # 自动生成步骤编号
        step_number = len(self.execution_history) + 1
        
        # 记录当前状态快照
        current_state_snapshot = {
            "target": self.target,
            "current_task": self.current_task,
            "progress": self.get_progress(),
            "is_complete": self.is_complete,
            "should_continue": self.should_continue,
            "retry_count": self.retry_count
        }
        
        execution_step = {
            "step_number": step_number,
            "task": task,
            "step_type": step_type,
            "status": status,
            "timestamp": current_time,
            "timestamp_iso": datetime.fromtimestamp(current_time).isoformat(),
            "input_params": input_params or {},
            "processing_logic": processing_logic,
            "result": result,
            "intermediate_results": intermediate_results or [],
            "output_data": output_data or {},
            "data_changes": data_changes or {},
            "state_transitions": state_transitions or [],
            "execution_time": execution_time,
            "state_snapshot": current_state_snapshot
        }
        
        self.execution_history.append(execution_step)
    
    def add_execution_step_start(
        self,
        task: str,
        step_type: str = "tool_execution",
        input_params: Dict[str, Any] = None,
        processing_logic: str = ""
    ):
        """
        记录执行步骤开始
        
        Args:
            task: 任务名称
            step_type: 步骤类型
            input_params: 输入参数
            processing_logic: 处理逻辑描述
        """
        import time
        current_time = time.time()
        
        step_number = len(self.execution_history) + 1
        
        execution_step = {
            "step_number": step_number,
            "task": task,
            "step_type": step_type,
            "status": "running",
            "timestamp": current_time,
            "timestamp_iso": datetime.fromtimestamp(current_time).isoformat(),
            "input_params": input_params or {},
            "processing_logic": processing_logic,
            "start_time": current_time,
            "intermediate_results": [],
            "output_data": {},
            "data_changes": {},
            "state_transitions": ["started"]
        }
        
        self.execution_history.append(execution_step)
        return step_number
    
    def update_execution_step(
        self,
        step_number: int,
        result: Any = None,
        status: str = None,
        intermediate_results: List[Dict[str, Any]] = None,
        output_data: Dict[str, Any] = None,
        data_changes: Dict[str, Any] = None,
        state_transitions: List[str] = None
    ):
        """
        更新执行步骤
        
        Args:
            step_number: 步骤编号
            result: 执行结果
            status: 执行状态
            intermediate_results: 中间结果
            output_data: 输出数据
            data_changes: 数据变化
            state_transitions: 状态转换
        """
        import time
        
        if step_number <= len(self.execution_history):
            step = self.execution_history[step_number - 1]
            
            if result is not None:
                step["result"] = result
            
            if status is not None:
                step["status"] = status
                if status in ["success", "failed"]:
                    if "start_time" in step:
                        step["execution_time"] = time.time() - step["start_time"]
                    step["timestamp"] = time.time()
                    step["timestamp_iso"] = datetime.fromtimestamp(time.time()).isoformat()
            
            if intermediate_results is not None:
                step["intermediate_results"].extend(intermediate_results)
            
            if output_data is not None:
                step["output_data"].update(output_data)
            
            if data_changes is not None:
                step["data_changes"].update(data_changes)
            
            if state_transitions is not None:
                step["state_transitions"].extend(state_transitions)
    
    def update_context(self, key: str, value: Any):
        """
        更新目标上下文
        
        Args:
            key: 上下文键名
            value: 上下文值
        """
        self.target_context[key] = value
    
    def add_vulnerability(self, vuln: Dict[str, Any]):
        """
        添加漏洞到漏洞列表
        
        Args:
            vuln: 漏洞信息字典
        """
        self.vulnerabilities.append(vuln)
    
    async def add_vulnerability_with_persist(self, vuln: Dict[str, Any]):
        """
        添加漏洞到漏洞列表并立即持久化
        
        Args:
            vuln: 漏洞信息字典
        """
        self.vulnerabilities.append(vuln)
        await self.persist_state()
    
    async def persist_state(self):
        """
        强制持久化当前状态到数据库
        
        这是一个异步方法，用于在关键操作后立即保存状态，
        而不是等待下一次 update_stage_status 调用。
        """
        try:
            state_data = self.to_dict()
            await persist_task_state(self.task_id, state_data, self.get_progress())
            logger.debug(f"State persisted for task {self.task_id}")
        except Exception as e:
            logger.error(f"Failed to persist state for task {self.task_id}: {e}", exc_info=True)
    
    def add_tool_result(self, tool_name: str, result: Any):
        """
        添加工具执行结果
        
        Args:
            tool_name: 工具名称
            result: 执行结果
        """
        self.tool_results[tool_name] = result
    
    async def add_tool_result_with_persist(self, tool_name: str, result: Any):
        """
        添加工具执行结果并立即持久化
        
        Args:
            tool_name: 工具名称
            result: 执行结果
        """
        self.tool_results[tool_name] = result
        await self.persist_state()
    
    def add_error(self, error: str):
        """
        添加错误到错误列表
        
        Args:
            error: 错误信息
        """
        self.errors.append(error)
    
    def increment_retry(self):
        """
        增加重试次数
        """
        self.retry_count += 1
    
    def reset_retry(self):
        """
        重置重试次数
        """
        self.retry_count = 0
    
    def increment_enhancement_retry(self):
        """
        增加功能增强重试次数
        """
        self.enhancement_retry_count += 1
        
    def reset_enhancement_retry(self):
        """
        重置功能增强重试次数
        """
        self.enhancement_retry_count = 0
    
    def mark_complete(self):
        """
        标记任务为完成
        """
        self.is_complete = True
        self.should_continue = False
    
    def to_dict(self) -> Dict[str, Any]:
        """
        转换为字典格式 - 用于子图间数据传递
        
        确保所有字段完整序列化，支持子图间无缝数据传递。
        
        Returns:
            Dict: 包含所有状态信息的字典
        """
        return {
            "target": self.target,
            "task_id": self.task_id,
            "workflow_trace": self.workflow_trace.to_dict() if self.workflow_trace else None,
            "planned_tasks": self.planned_tasks,
            "current_task": self.current_task,
            "completed_tasks": self.completed_tasks,
            "tool_results": self.tool_results,
            "vulnerabilities": self.vulnerabilities,
            "target_context": self.target_context,
            "user_tools": self.user_tools,
            "user_requirement": self.user_requirement,
            "memory_info": self.memory_info,
            "plan_data": self.plan_data,
            "execution_results": self.execution_results,
            "execution_history": self.execution_history,
            "errors": self.errors,
            "retry_count": self.retry_count,
            "enhancement_retry_count": self.enhancement_retry_count,
            "is_complete": self.is_complete,
            "should_continue": self.should_continue,
            "seebug_pocs": self.seebug_pocs,
            "generated_pocs": self.generated_pocs,
            "stage_status": self.stage_status,
            "vuln_scan_results": self.vuln_scan_results,
            "vuln_scan_plugins_loaded": self.vuln_scan_plugins_loaded,
            "vuln_scan_progress": self.vuln_scan_progress,
            "vuln_scan_metadata": self.vuln_scan_metadata,
            "scan_summary": self.scan_summary,
            "report": self.report,
            "progress": self.get_progress()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentState":
        """
        从字典创建AgentState实例 - 用于子图间数据传递
        
        确保所有字段完整反序列化，支持子图间无缝数据传递。
        
        Args:
            data: 包含状态信息的字典
            
        Returns:
            AgentState: 新的AgentState实例
        """
        default_stage_status = {
            "planning": {"status": "pending", "sub_status": "pending", "progress": 0, "logs": [], "start_time": None, "end_time": None},
            "tool_execution": {"status": "pending", "sub_status": "pending", "progress": 0, "logs": [], "start_time": None, "end_time": None},
            "poc_verification": {"status": "pending", "sub_status": "pending", "progress": 0, "logs": [], "start_time": None, "end_time": None},
            "report": {"status": "pending", "sub_status": "pending", "progress": 0, "logs": [], "start_time": None, "end_time": None}
        }
        
        workflow_trace_data = data.get("workflow_trace")
        workflow_trace = None
        if workflow_trace_data:
            workflow_trace = cls._reconstruct_workflow_trace(workflow_trace_data)
        
        instance = cls(
            target=data.get("target", ""),
            task_id=data.get("task_id", ""),
            workflow_trace=workflow_trace,
            planned_tasks=data.get("planned_tasks", []),
            current_task=data.get("current_task"),
            completed_tasks=data.get("completed_tasks", []),
            tool_results=data.get("tool_results", {}),
            vulnerabilities=data.get("vulnerabilities", []),
            target_context=data.get("target_context", {}),
            user_tools=data.get("user_tools", []),
            user_requirement=data.get("user_requirement", ""),
            memory_info=data.get("memory_info", ""),
            plan_data=data.get("plan_data"),
            execution_results=data.get("execution_results", []),
            execution_history=data.get("execution_history", []),
            errors=data.get("errors", []),
            retry_count=data.get("retry_count", 0),
            enhancement_retry_count=data.get("enhancement_retry_count", 0),
            is_complete=data.get("is_complete", False),
            should_continue=data.get("should_continue", True),
            seebug_pocs=data.get("seebug_pocs", []),
            generated_pocs=data.get("generated_pocs", []),
            stage_status=data.get("stage_status", default_stage_status),
            vuln_scan_results=data.get("vuln_scan_results", {}),
            vuln_scan_plugins_loaded=data.get("vuln_scan_plugins_loaded", []),
            vuln_scan_progress=data.get("vuln_scan_progress", 0),
            vuln_scan_metadata=data.get("vuln_scan_metadata", {}),
            scan_summary=data.get("scan_summary", {}),
            report=data.get("report", "")
        )
        
        return instance
    
    @classmethod
    def _reconstruct_workflow_trace(cls, data: Dict[str, Any]) -> Optional[WorkflowTrace]:
        """
        从字典重建 WorkflowTrace 对象
        
        Args:
            data: 工作流追踪数据字典
            
        Returns:
            WorkflowTrace: 重建的工作流追踪对象
        """
        if not data:
            return None
        
        workflow_trace = WorkflowTrace(
            workflow_id=data.get("workflow_id", ""),
            task_id=data.get("task_id", ""),
            target=data.get("target", ""),
            start_time=data.get("start_time", time.time()),
            end_time=data.get("end_time"),
            total_duration_ms=data.get("total_duration_ms"),
            workflow_status=NodeStatus(data.get("workflow_status", "pending")),
            summary=data.get("summary", {})
        )
        
        for node_data in data.get("nodes", []):
            node = NodeExecutionRecord(
                node_name=node_data.get("node_name", ""),
                node_type=node_data.get("node_type", ""),
                status=NodeStatus(node_data.get("status", "pending")),
                start_time=node_data.get("start_time"),
                end_time=node_data.get("end_time"),
                duration_ms=node_data.get("duration_ms"),
                input_data=node_data.get("input_data", {}),
                output_data=node_data.get("output_data", {}),
                error_message=node_data.get("error_message"),
                metadata=node_data.get("metadata", {})
            )
            workflow_trace.nodes.append(node)
        
        return workflow_trace
    
    @classmethod
    def get_all_fields(cls) -> List[str]:
        """
        获取所有字段名称列表
        
        Returns:
            List[str]: 所有字段名称
        """
        return [
            "target", "task_id", "workflow_trace",
            "planned_tasks", "current_task", "completed_tasks",
            "tool_results", "vulnerabilities", "target_context", "user_tools",
            "user_requirement", "memory_info", "plan_data", "execution_results",
            "execution_history", "errors", "retry_count", "enhancement_retry_count",
            "is_complete", "should_continue", "seebug_pocs", "generated_pocs",
            "stage_status", "vuln_scan_results", "vuln_scan_plugins_loaded",
            "vuln_scan_progress", "vuln_scan_metadata", "scan_summary", "report"
        ]
    
    def validate_data_integrity(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        验证数据完整性
        
        检查序列化数据是否包含所有必需字段，用于子图间数据传递验证。
        
        Args:
            data: 要验证的数据字典
            
        Returns:
            Dict: 包含验证结果的字典
                - is_valid: 是否有效
                - missing_fields: 缺失字段列表
                - extra_fields: 多余字段列表
                - field_count: 字段总数
        """
        all_fields = set(self.get_all_fields())
        data_fields = set(data.keys())
        
        missing_fields = all_fields - data_fields
        extra_fields = data_fields - all_fields
        
        return {
            "is_valid": len(missing_fields) == 0,
            "missing_fields": list(missing_fields),
            "extra_fields": list(extra_fields),
            "field_count": len(data_fields),
            "expected_count": len(all_fields)
        }
    
    def serialize_for_transfer(self) -> Dict[str, Any]:
        """
        为子图传递序列化数据（带完整性验证）
        
        序列化当前状态并验证数据完整性，确保子图间数据传递的可靠性。
        
        Returns:
            Dict: 包含状态数据和验证信息的字典
        """
        data = self.to_dict()
        validation = self.validate_data_integrity(data)
        
        if not validation["is_valid"]:
            logger.warning(
                f"Data serialization incomplete. Missing fields: {validation['missing_fields']}"
            )
        
        return {
            "state_data": data,
            "validation": validation,
            "timestamp": datetime.now().isoformat()
        }
    
    @classmethod
    def deserialize_from_transfer(cls, transfer_data: Dict[str, Any]) -> "AgentState":
        """
        从子图传递反序列化数据（带完整性验证）
        
        反序列化数据并验证完整性，确保子图间数据传递的可靠性。
        
        Args:
            transfer_data: 包含状态数据和验证信息的字典
            
        Returns:
            AgentState: 新的AgentState实例
            
        Raises:
            ValueError: 如果数据格式无效或缺少关键字段
        """
        if "state_data" not in transfer_data:
            raise ValueError("Invalid transfer data: missing 'state_data' field")
        
        data = transfer_data["state_data"]
        
        if "validation" in transfer_data:
            validation = transfer_data["validation"]
            if not validation["is_valid"]:
                logger.warning(
                    f"Data deserialization with missing fields: {validation['missing_fields']}"
                )
        
        return cls.from_dict(data)
    
    def merge_from_dict(self, data: Dict[str, Any]) -> "AgentState":
        """
        合并字典数据到当前状态
        
        用于子图间增量数据传递，只更新提供的字段。
        
        Args:
            data: 要合并的数据字典
            
        Returns:
            AgentState: 更新后的状态实例（self）
        """
        for key, value in data.items():
            if hasattr(self, key):
                setattr(self, key, value)
            else:
                logger.warning(f"Unknown field '{key}' ignored during merge")
        
        return self
    
    def clone(self) -> "AgentState":
        """
        克隆当前状态
        
        创建当前状态的深拷贝，用于子图间数据隔离。
        
        Returns:
            AgentState: 新的AgentState实例
        """
        return self.from_dict(self.to_dict())
