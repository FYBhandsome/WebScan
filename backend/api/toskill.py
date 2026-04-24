"""
TOSKill 业务层 API 接口

提供 TOSKill 扫描系统的统一调用入口，包括：
- 任务创建 API - 创建新的 TOSKill 扫描任务
- 任务执行 API - 执行 TOSKill 扫描工作流
- 任务查询 API - 查询任务状态和结果
- 报告生成 API - 生成扫描报告
- 健康检查 API - 检查 TOSKill 系统状态

特性：
- 统一的响应格式
- 完整的 API 文档和注释
- 异步执行支持
- 错误处理和日志记录
- 任务状态查询和进度跟踪
- 任务取消和清理
"""
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
import logging
import asyncio
import json
import uuid
import time
from enum import Enum

from backend.api.common import APIResponse

logger = logging.getLogger(__name__)

router = APIRouter()


class TOSKillTaskStatus(str, Enum):
    """TOSKill 任务状态枚举"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class TOSKillWorkflowStage(str, Enum):
    """TOSKill 工作流阶段枚举"""
    INIT = "init"
    ENVIRONMENT_AWARENESS = "environment_awareness"
    INFO_COLLECTION = "info_collection"
    VULN_SCAN = "vuln_scan"
    REPORT_GENERATION = "report_generation"
    COMPLETED = "completed"


class TOSKillScanMode(str, Enum):
    """TOSKill 扫描模式枚举"""
    INFO = "info"
    VULN = "vuln"
    FULL = "full"


class CreateTOSKillTaskRequest(BaseModel):
    """
    创建 TOSKill 扫描任务的请求模型
    
    Attributes:
        task_name: 任务名称
        target: 扫描目标（URL、IP 或域名）
        scan_mode: 扫描模式，可选值: 'info'(信息收集), 'vuln'(漏洞扫描), 'full'(完整扫描)
        config: 任务配置参数
        timeout: 任务超时时间（秒），默认 3600 秒
        auto_report: 是否自动生成报告，默认 True
    """
    task_name: str = Field(..., description="任务名称", min_length=1, max_length=200)
    target: str = Field(..., description="扫描目标（URL、IP 或域名）", min_length=1)
    scan_mode: TOSKillScanMode = Field(default=TOSKillScanMode.FULL, description="扫描模式")
    config: Dict[str, Any] = Field(default_factory=dict, description="任务配置参数")
    timeout: int = Field(default=3600, description="任务超时时间（秒）", ge=60, le=7200)
    auto_report: bool = Field(default=True, description="是否自动生成报告")


class TOSKillTaskResponse(BaseModel):
    """
    TOSKill 任务响应模型
    
    Attributes:
        task_id: 任务 ID
        task_name: 任务名称
        target: 扫描目标
        status: 任务状态
        progress: 任务进度（0-100）
        current_stage: 当前工作流阶段
        created_at: 创建时间
        updated_at: 更新时间
    """
    task_id: str
    task_name: str
    target: str
    status: TOSKillTaskStatus
    progress: int
    current_stage: TOSKillWorkflowStage
    created_at: str
    updated_at: str


class TOSKillTaskDetail(BaseModel):
    """
    TOSKill 任务详情模型
    
    Attributes:
        task_id: 任务 ID
        task_name: 任务名称
        target: 扫描目标
        scan_mode: 扫描模式
        status: 任务状态
        progress: 任务进度
        current_stage: 当前工作流阶段
        completed_tasks: 已完成的任务列表
        vulnerabilities: 发现的漏洞列表
        target_context: 目标上下文信息
        execution_history: 执行历史
        errors: 错误列表
        config: 任务配置
        created_at: 创建时间
        updated_at: 更新时间
        started_at: 开始时间
        finished_at: 结束时间
        duration: 执行时长（秒）
    """
    task_id: str
    task_name: str
    target: str
    scan_mode: str
    status: TOSKillTaskStatus
    progress: int
    current_stage: TOSKillWorkflowStage
    completed_tasks: List[str]
    vulnerabilities: List[Dict[str, Any]]
    target_context: Dict[str, Any]
    execution_history: List[Dict[str, Any]]
    errors: List[str]
    config: Dict[str, Any]
    created_at: str
    updated_at: str
    started_at: Optional[str]
    finished_at: Optional[str]
    duration: Optional[float]


class TOSKillReportRequest(BaseModel):
    """
    TOSKill 报告生成请求模型
    
    Attributes:
        task_id: 任务 ID
        report_format: 报告格式，可选值: 'json', 'html', 'markdown'
        include_evidence: 是否包含漏洞证据
        include_remediation: 是否包含修复建议
    """
    task_id: str = Field(..., description="任务 ID")
    report_format: str = Field(default="json", description="报告格式")
    include_evidence: bool = Field(default=True, description="是否包含漏洞证据")
    include_remediation: bool = Field(default=True, description="是否包含修复建议")


class TOSKillHealthStatus(BaseModel):
    """
    TOSKill 健康状态模型
    
    Attributes:
        status: 健康状态
        components: 组件状态
        active_tasks: 活跃任务数
        total_tasks: 总任务数
        uptime: 运行时间（秒）
        version: 系统版本
    """
    status: str
    components: Dict[str, Any]
    active_tasks: int
    total_tasks: int
    uptime: float
    version: str


class TOSKillTaskManager:
    """
    TOSKill 任务管理器
    
    管理所有 TOSKill 任务的生命周期，包括创建、执行、查询、取消和清理。
    """
    
    def __init__(self):
        self._tasks: Dict[str, Dict[str, Any]] = {}
        self._running_tasks: Dict[str, asyncio.Task] = {}
        self._start_time = time.time()
        self._lock = asyncio.Lock()
    
    async def create_task(
        self,
        task_name: str,
        target: str,
        scan_mode: str = "full",
        config: Dict[str, Any] = None,
        timeout: int = 3600,
        auto_report: bool = True
    ) -> str:
        """
        创建新的 TOSKill 扫描任务
        
        Args:
            task_name: 任务名称
            target: 扫描目标
            scan_mode: 扫描模式
            config: 任务配置
            timeout: 超时时间
            auto_report: 是否自动生成报告
            
        Returns:
            str: 任务 ID
        """
        task_id = str(uuid.uuid4())
        now = datetime.now()
        
        task_data = {
            "task_id": task_id,
            "task_name": task_name,
            "target": target,
            "scan_mode": scan_mode,
            "status": TOSKillTaskStatus.PENDING,
            "progress": 0,
            "current_stage": TOSKillWorkflowStage.INIT,
            "completed_tasks": [],
            "vulnerabilities": [],
            "target_context": {},
            "execution_history": [],
            "errors": [],
            "config": config or {},
            "timeout": timeout,
            "auto_report": auto_report,
            "created_at": now,
            "updated_at": now,
            "started_at": None,
            "finished_at": None,
            "result": None
        }
        
        async with self._lock:
            self._tasks[task_id] = task_data
        
        logger.info(f"[TOSKill] 任务创建成功 | 任务ID: {task_id} | 目标: {target} | 模式: {scan_mode}")
        return task_id
    
    async def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """
        获取任务信息
        
        Args:
            task_id: 任务 ID
            
        Returns:
            Optional[Dict[str, Any]]: 任务数据，不存在则返回 None
        """
        async with self._lock:
            return self._tasks.get(task_id)
    
    async def update_task(
        self,
        task_id: str,
        status: TOSKillTaskStatus = None,
        progress: int = None,
        current_stage: TOSKillWorkflowStage = None,
        completed_tasks: List[str] = None,
        vulnerabilities: List[Dict] = None,
        target_context: Dict[str, Any] = None,
        execution_history: List[Dict] = None,
        errors: List[str] = None,
        result: Any = None
    ) -> bool:
        """
        更新任务状态
        
        Args:
            task_id: 任务 ID
            status: 任务状态
            progress: 进度
            current_stage: 当前阶段
            completed_tasks: 已完成任务
            vulnerabilities: 漏洞列表
            target_context: 目标上下文
            execution_history: 执行历史
            errors: 错误列表
            result: 结果数据
            
        Returns:
            bool: 更新是否成功
        """
        async with self._lock:
            if task_id not in self._tasks:
                return False
            
            task = self._tasks[task_id]
            
            if status is not None:
                task["status"] = status
            if progress is not None:
                task["progress"] = min(100, max(0, progress))
            if current_stage is not None:
                task["current_stage"] = current_stage
            if completed_tasks is not None:
                task["completed_tasks"] = completed_tasks
            if vulnerabilities is not None:
                task["vulnerabilities"] = vulnerabilities
            if target_context is not None:
                task["target_context"] = target_context
            if execution_history is not None:
                task["execution_history"] = execution_history
            if errors is not None:
                task["errors"] = errors
            if result is not None:
                task["result"] = result
            
            task["updated_at"] = datetime.now()
            
            return True
    
    async def start_task(self, task_id: str) -> bool:
        """
        标记任务开始执行
        
        Args:
            task_id: 任务 ID
            
        Returns:
            bool: 是否成功
        """
        async with self._lock:
            if task_id not in self._tasks:
                return False
            
            task = self._tasks[task_id]
            task["status"] = TOSKillTaskStatus.RUNNING
            task["started_at"] = datetime.now()
            task["updated_at"] = datetime.now()
            
            return True
    
    async def finish_task(
        self,
        task_id: str,
        status: TOSKillTaskStatus,
        result: Any = None
    ) -> bool:
        """
        标记任务完成
        
        Args:
            task_id: 任务 ID
            status: 最终状态
            result: 结果数据
            
        Returns:
            bool: 是否成功
        """
        async with self._lock:
            if task_id not in self._tasks:
                return False
            
            task = self._tasks[task_id]
            task["status"] = status
            task["finished_at"] = datetime.now()
            task["updated_at"] = datetime.now()
            task["progress"] = 100 if status == TOSKillTaskStatus.COMPLETED else task["progress"]
            
            if result is not None:
                task["result"] = result
            
            return True
    
    async def cancel_task(self, task_id: str) -> bool:
        """
        取消任务
        
        Args:
            task_id: 任务 ID
            
        Returns:
            bool: 是否成功
        """
        async with self._lock:
            if task_id not in self._tasks:
                return False
            
            task = self._tasks[task_id]
            
            if task["status"] not in [TOSKillTaskStatus.PENDING, TOSKillTaskStatus.RUNNING]:
                return False
            
            task["status"] = TOSKillTaskStatus.CANCELLED
            task["finished_at"] = datetime.now()
            task["updated_at"] = datetime.now()
            
            if task_id in self._running_tasks:
                self._running_tasks[task_id].cancel()
                del self._running_tasks[task_id]
            
            logger.info(f"[TOSKill] 任务已取消 | 任务ID: {task_id}")
            return True
    
    async def delete_task(self, task_id: str) -> bool:
        """
        删除任务
        
        Args:
            task_id: 任务 ID
            
        Returns:
            bool: 是否成功
        """
        async with self._lock:
            if task_id not in self._tasks:
                return False
            
            if task_id in self._running_tasks:
                self._running_tasks[task_id].cancel()
                del self._running_tasks[task_id]
            
            del self._tasks[task_id]
            
            logger.info(f"[TOSKill] 任务已删除 | 任务ID: {task_id}")
            return True
    
    async def list_tasks(
        self,
        status: TOSKillTaskStatus = None,
        skip: int = 0,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        获取任务列表
        
        Args:
            status: 按状态过滤
            skip: 跳过数量
            limit: 返回数量
            
        Returns:
            List[Dict[str, Any]]: 任务列表
        """
        async with self._lock:
            tasks = list(self._tasks.values())
            
            if status:
                tasks = [t for t in tasks if t["status"] == status]
            
            tasks.sort(key=lambda x: x["created_at"], reverse=True)
            
            return tasks[skip:skip + limit]
    
    async def get_statistics(self) -> Dict[str, Any]:
        """
        获取统计信息
        
        Returns:
            Dict[str, Any]: 统计信息
        """
        async with self._lock:
            total = len(self._tasks)
            active = sum(1 for t in self._tasks.values() if t["status"] == TOSKillTaskStatus.RUNNING)
            completed = sum(1 for t in self._tasks.values() if t["status"] == TOSKillTaskStatus.COMPLETED)
            failed = sum(1 for t in self._tasks.values() if t["status"] == TOSKillTaskStatus.FAILED)
            
            return {
                "total": total,
                "active": active,
                "completed": completed,
                "failed": failed,
                "uptime": time.time() - self._start_time
            }
    
    def register_running_task(self, task_id: str, async_task: asyncio.Task):
        """
        注册正在运行的异步任务
        
        Args:
            task_id: 任务 ID
            async_task: 异步任务对象
        """
        self._running_tasks[task_id] = async_task


task_manager = TOSKillTaskManager()


async def execute_toskill_workflow(
    task_id: str,
    target: str,
    scan_mode: str,
    config: Dict[str, Any],
    timeout: int,
    auto_report: bool
):
    """
    执行 TOSKill 扫描工作流
    
    Args:
        task_id: 任务 ID
        target: 扫描目标
        scan_mode: 扫描模式
        config: 任务配置
        timeout: 超时时间
        auto_report: 是否自动生成报告
    """
    try:
        await task_manager.start_task(task_id)
        logger.info(f"[TOSKill] 开始执行工作流 | 任务ID: {task_id} | 目标: {target}")
        
        try:
            from TOSKill.AI.graph import ScanAgentGraph, WorkflowStage, WorkflowStatus
            from TOSKill.AI.state import AgentState
            
            agent_graph = ScanAgentGraph()
            
            initial_state = AgentState(
                target=target,
                task_id=task_id
            )
            
            final_state = await asyncio.wait_for(
                agent_graph.invoke(initial_state),
                timeout=timeout
            )
            
            vulnerabilities = []
            if hasattr(final_state, 'vulnerabilities'):
                vulnerabilities = final_state.vulnerabilities
            
            completed_tasks = []
            if hasattr(final_state, 'completed_tasks'):
                completed_tasks = final_state.completed_tasks
            
            target_context = {}
            if hasattr(final_state, 'target_context'):
                target_context = final_state.target_context
            
            execution_history = []
            if hasattr(final_state, 'execution_history'):
                execution_history = final_state.execution_history
            
            errors = []
            if hasattr(final_state, 'errors'):
                errors = final_state.errors
            
            result = {
                "vulnerabilities": vulnerabilities,
                "completed_tasks": completed_tasks,
                "target_context": target_context,
                "execution_history": execution_history,
                "errors": errors,
                "scan_summary": {
                    "total_vulnerabilities": len(vulnerabilities),
                    "severity_distribution": _count_severity(vulnerabilities),
                    "completed_tasks_count": len(completed_tasks)
                }
            }
            
            await task_manager.update_task(
                task_id=task_id,
                progress=100,
                current_stage=TOSKillWorkflowStage.COMPLETED,
                completed_tasks=completed_tasks,
                vulnerabilities=vulnerabilities,
                target_context=target_context,
                execution_history=execution_history,
                errors=errors,
                result=result
            )
            
            await task_manager.finish_task(
                task_id=task_id,
                status=TOSKillTaskStatus.COMPLETED,
                result=result
            )
            
            logger.info(f"[TOSKill] 工作流执行完成 | 任务ID: {task_id} | 漏洞数: {len(vulnerabilities)}")
            
        except asyncio.TimeoutError:
            logger.error(f"[TOSKill] 工作流执行超时 | 任务ID: {task_id}")
            await task_manager.finish_task(
                task_id=task_id,
                status=TOSKillTaskStatus.TIMEOUT,
                result={"error": "工作流执行超时"}
            )
            
        except Exception as e:
            logger.error(f"[TOSKill] 工作流执行失败 | 任务ID: {task_id} | 错误: {str(e)}", exc_info=True)
            await task_manager.finish_task(
                task_id=task_id,
                status=TOSKillTaskStatus.FAILED,
                result={"error": str(e)}
            )
            
    except Exception as e:
        logger.error(f"[TOSKill] 任务执行异常 | 任务ID: {task_id} | 错误: {str(e)}", exc_info=True)
        await task_manager.finish_task(
            task_id=task_id,
            status=TOSKillTaskStatus.FAILED,
            result={"error": str(e)}
        )


def _count_severity(vulnerabilities: List[Dict]) -> Dict[str, int]:
    """
    统计漏洞严重程度分布
    
    Args:
        vulnerabilities: 漏洞列表
        
    Returns:
        Dict[str, int]: 严重程度分布
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for vuln in vulnerabilities:
        severity = str(vuln.get("severity", "info")).lower()
        if severity in counts:
            counts[severity] += 1
    return counts


def _format_datetime(dt: datetime) -> str:
    """
    格式化日期时间
    
    Args:
        dt: datetime 对象
        
    Returns:
        str: 格式化后的字符串
    """
    if dt is None:
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


@router.post("/tasks", response_model=APIResponse)
async def create_task(request: CreateTOSKillTaskRequest, background_tasks: BackgroundTasks):
    """
    创建 TOSKill 扫描任务
    
    创建新的 TOSKill 扫描任务并启动异步执行。
    
    Args:
        request: 创建任务请求
        background_tasks: FastAPI 后台任务
        
    Returns:
        APIResponse: 包含任务 ID 的响应
        
    Examples:
        >>> 创建完整扫描任务
        >>> POST /api/toskill/tasks
        >>> {
        ...     "task_name": "扫描 example.com",
        ...     "target": "https://example.com",
        ...     "scan_mode": "full",
        ...     "timeout": 3600
        ... }
    """
    try:
        logger.info(f"[TOSKill] 收到创建任务请求 | 名称: {request.task_name} | 目标: {request.target}")
        
        if not request.target:
            raise HTTPException(status_code=400, detail="扫描目标不能为空")
        
        task_id = await task_manager.create_task(
            task_name=request.task_name,
            target=request.target,
            scan_mode=request.scan_mode.value,
            config=request.config,
            timeout=request.timeout,
            auto_report=request.auto_report
        )
        
        async_task = asyncio.create_task(
            execute_toskill_workflow(
                task_id=task_id,
                target=request.target,
                scan_mode=request.scan_mode.value,
                config=request.config,
                timeout=request.timeout,
                auto_report=request.auto_report
            )
        )
        
        task_manager.register_running_task(task_id, async_task)
        
        logger.info(f"[TOSKill] 任务已启动 | 任务ID: {task_id}")
        
        return APIResponse(
            code=200,
            message="任务创建成功",
            data={
                "task_id": task_id,
                "status": TOSKillTaskStatus.PENDING.value,
                "target": request.target
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[TOSKill] 创建任务失败 | 错误: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/tasks/{task_id}/execute", response_model=APIResponse)
async def execute_task(task_id: str, background_tasks: BackgroundTasks):
    """
    执行 TOSKill 扫描任务
    
    启动或重新执行指定的 TOSKill 扫描任务。
    
    Args:
        task_id: 任务 ID
        background_tasks: FastAPI 后台任务
        
    Returns:
        APIResponse: 执行状态响应
        
    Examples:
        >>> 执行任务
        >>> POST /api/toskill/tasks/{task_id}/execute
    """
    try:
        logger.info(f"[TOSKill] 收到执行任务请求 | 任务ID: {task_id}")
        
        task = await task_manager.get_task(task_id)
        if not task:
            raise HTTPException(status_code=404, detail="任务不存在")
        
        if task["status"] == TOSKillTaskStatus.RUNNING:
            return APIResponse(
                code=200,
                message="任务正在执行中",
                data={"task_id": task_id, "status": task["status"].value}
            )
        
        if task["status"] not in [TOSKillTaskStatus.PENDING, TOSKillTaskStatus.FAILED, TOSKillTaskStatus.TIMEOUT]:
            raise HTTPException(status_code=400, detail=f"任务状态不允许执行: {task['status'].value}")
        
        await task_manager.update_task(
            task_id=task_id,
            status=TOSKillTaskStatus.PENDING,
            progress=0,
            current_stage=TOSKillWorkflowStage.INIT
        )
        
        async_task = asyncio.create_task(
            execute_toskill_workflow(
                task_id=task_id,
                target=task["target"],
                scan_mode=task["scan_mode"],
                config=task["config"],
                timeout=task["timeout"],
                auto_report=task["auto_report"]
            )
        )
        
        task_manager.register_running_task(task_id, async_task)
        
        logger.info(f"[TOSKill] 任务执行已启动 | 任务ID: {task_id}")
        
        return APIResponse(
            code=200,
            message="任务执行已启动",
            data={"task_id": task_id, "status": TOSKillTaskStatus.RUNNING.value}
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[TOSKill] 执行任务失败 | 任务ID: {task_id} | 错误: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tasks/{task_id}", response_model=APIResponse)
async def get_task(task_id: str):
    """
    查询 TOSKill 任务状态
    
    获取指定任务的详细状态信息，包括进度、阶段、漏洞等。
    
    Args:
        task_id: 任务 ID
        
    Returns:
        APIResponse: 包含任务详情的响应
        
    Examples:
        >>> 查询任务状态
        >>> GET /api/toskill/tasks/{task_id}
    """
    try:
        task = await task_manager.get_task(task_id)
        
        if not task:
            raise HTTPException(status_code=404, detail="任务不存在")
        
        duration = None
        if task["started_at"]:
            end_time = task["finished_at"] or datetime.now()
            duration = (end_time - task["started_at"]).total_seconds()
        
        response_data = {
            "task_id": task["task_id"],
            "task_name": task["task_name"],
            "target": task["target"],
            "scan_mode": task["scan_mode"],
            "status": task["status"].value,
            "progress": task["progress"],
            "current_stage": task["current_stage"].value,
            "completed_tasks": task["completed_tasks"],
            "vulnerabilities": task["vulnerabilities"],
            "target_context": task["target_context"],
            "execution_history": task["execution_history"][-20:],
            "errors": task["errors"],
            "config": task["config"],
            "created_at": _format_datetime(task["created_at"]),
            "updated_at": _format_datetime(task["updated_at"]),
            "started_at": _format_datetime(task["started_at"]),
            "finished_at": _format_datetime(task["finished_at"]),
            "duration": duration
        }
        
        return APIResponse(
            code=200,
            message="获取成功",
            data=response_data
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[TOSKill] 查询任务失败 | 任务ID: {task_id} | 错误: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tasks", response_model=APIResponse)
async def list_tasks(
    status: Optional[TOSKillTaskStatus] = None,
    skip: int = 0,
    limit: int = 100
):
    """
    获取 TOSKill 任务列表
    
    获取所有任务列表，支持按状态过滤和分页。
    
    Args:
        status: 按状态过滤
        skip: 跳过数量
        limit: 返回数量
        
    Returns:
        APIResponse: 包含任务列表的响应
        
    Examples:
        >>> 获取所有运行中的任务
        >>> GET /api/toskill/tasks?status=running
    """
    try:
        tasks = await task_manager.list_tasks(status=status, skip=skip, limit=limit)
        
        task_list = []
        for task in tasks:
            task_list.append({
                "task_id": task["task_id"],
                "task_name": task["task_name"],
                "target": task["target"],
                "scan_mode": task["scan_mode"],
                "status": task["status"].value,
                "progress": task["progress"],
                "current_stage": task["current_stage"].value,
                "created_at": _format_datetime(task["created_at"]),
                "updated_at": _format_datetime(task["updated_at"])
            })
        
        return APIResponse(
            code=200,
            message="获取成功",
            data={
                "tasks": task_list,
                "total": len(task_list),
                "skip": skip,
                "limit": limit
            }
        )
        
    except Exception as e:
        logger.error(f"[TOSKill] 获取任务列表失败 | 错误: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/tasks/{task_id}/cancel", response_model=APIResponse)
async def cancel_task(task_id: str):
    """
    取消 TOSKill 任务
    
    取消正在运行或等待中的任务。
    
    Args:
        task_id: 任务 ID
        
    Returns:
        APIResponse: 取消结果响应
        
    Examples:
        >>> 取消任务
        >>> POST /api/toskill/tasks/{task_id}/cancel
    """
    try:
        logger.info(f"[TOSKill] 收到取消任务请求 | 任务ID: {task_id}")
        
        success = await task_manager.cancel_task(task_id)
        
        if not success:
            task = await task_manager.get_task(task_id)
            if not task:
                raise HTTPException(status_code=404, detail="任务不存在")
            raise HTTPException(status_code=400, detail="任务无法取消")
        
        return APIResponse(
            code=200,
            message="任务已取消",
            data={"task_id": task_id, "status": TOSKillTaskStatus.CANCELLED.value}
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[TOSKill] 取消任务失败 | 任务ID: {task_id} | 错误: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/tasks/{task_id}", response_model=APIResponse)
async def delete_task(task_id: str):
    """
    删除 TOSKill 任务
    
    删除指定的任务及其相关数据。
    
    Args:
        task_id: 任务 ID
        
    Returns:
        APIResponse: 删除结果响应
        
    Examples:
        >>> 删除任务
        >>> DELETE /api/toskill/tasks/{task_id}
    """
    try:
        logger.info(f"[TOSKill] 收到删除任务请求 | 任务ID: {task_id}")
        
        success = await task_manager.delete_task(task_id)
        
        if not success:
            raise HTTPException(status_code=404, detail="任务不存在")
        
        return APIResponse(
            code=200,
            message="任务已删除",
            data={"task_id": task_id}
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[TOSKill] 删除任务失败 | 任务ID: {task_id} | 错误: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tasks/{task_id}/results", response_model=APIResponse)
async def get_task_results(task_id: str):
    """
    获取 TOSKill 任务结果
    
    获取任务的完整扫描结果，包括漏洞详情、执行历史等。
    
    Args:
        task_id: 任务 ID
        
    Returns:
        APIResponse: 包含任务结果的响应
        
    Examples:
        >>> 获取任务结果
        >>> GET /api/toskill/tasks/{task_id}/results
    """
    try:
        task = await task_manager.get_task(task_id)
        
        if not task:
            raise HTTPException(status_code=404, detail="任务不存在")
        
        if task["status"] not in [TOSKillTaskStatus.COMPLETED, TOSKillTaskStatus.FAILED, TOSKillTaskStatus.TIMEOUT]:
            return APIResponse(
                code=200,
                message="任务尚未完成",
                data={
                    "task_id": task_id,
                    "status": task["status"].value,
                    "progress": task["progress"],
                    "current_stage": task["current_stage"].value
                }
            )
        
        result = task.get("result", {})
        
        return APIResponse(
            code=200,
            message="获取成功",
            data={
                "task_id": task_id,
                "task_name": task["task_name"],
                "target": task["target"],
                "scan_mode": task["scan_mode"],
                "status": task["status"].value,
                "vulnerabilities": result.get("vulnerabilities", []),
                "completed_tasks": result.get("completed_tasks", []),
                "target_context": result.get("target_context", {}),
                "scan_summary": result.get("scan_summary", {}),
                "errors": task["errors"],
                "execution_history": task["execution_history"]
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[TOSKill] 获取任务结果失败 | 任务ID: {task_id} | 错误: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/reports", response_model=APIResponse)
async def generate_report(request: TOSKillReportRequest):
    """
    生成 TOSKill 扫描报告
    
    根据任务结果生成指定格式的扫描报告。
    
    Args:
        request: 报告生成请求
        
    Returns:
        APIResponse: 包含报告内容的响应
        
    Examples:
        >>> 生成 JSON 格式报告
        >>> POST /api/toskill/reports
        >>> {
        ...     "task_id": "xxx-xxx-xxx",
        ...     "report_format": "json",
        ...     "include_evidence": true,
        ...     "include_remediation": true
        ... }
    """
    try:
        logger.info(f"[TOSKill] 收到生成报告请求 | 任务ID: {request.task_id} | 格式: {request.report_format}")
        
        task = await task_manager.get_task(request.task_id)
        
        if not task:
            raise HTTPException(status_code=404, detail="任务不存在")
        
        if task["status"] != TOSKillTaskStatus.COMPLETED:
            raise HTTPException(status_code=400, detail="任务尚未完成，无法生成报告")
        
        result = task.get("result", {})
        vulnerabilities = result.get("vulnerabilities", [])
        
        report = {
            "report_id": str(uuid.uuid4()),
            "task_id": request.task_id,
            "task_name": task["task_name"],
            "target": task["target"],
            "scan_mode": task["scan_mode"],
            "generated_at": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "summary": {
                "total_vulnerabilities": len(vulnerabilities),
                "severity_distribution": _count_severity(vulnerabilities),
                "scan_duration": None,
                "completed_tasks": len(result.get("completed_tasks", []))
            },
            "vulnerabilities": vulnerabilities if request.include_evidence else [
                {k: v for k, v in vuln.items() if k != "evidence"}
                for vuln in vulnerabilities
            ],
            "target_context": result.get("target_context", {}),
            "execution_summary": {
                "total_steps": len(task["execution_history"]),
                "errors_count": len(task["errors"])
            }
        }
        
        if request.include_remediation:
            report["remediation_recommendations"] = _generate_remediation_recommendations(vulnerabilities)
        
        if request.report_format == "json":
            return APIResponse(
                code=200,
                message="报告生成成功",
                data=report
            )
        elif request.report_format == "markdown":
            markdown_report = _generate_markdown_report(report)
            return APIResponse(
                code=200,
                message="报告生成成功",
                data={"report": markdown_report, "format": "markdown"}
            )
        elif request.report_format == "html":
            html_report = _generate_html_report(report)
            return APIResponse(
                code=200,
                message="报告生成成功",
                data={"report": html_report, "format": "html"}
            )
        else:
            raise HTTPException(status_code=400, detail=f"不支持的报告格式: {request.report_format}")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[TOSKill] 生成报告失败 | 任务ID: {request.task_id} | 错误: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


def _generate_remediation_recommendations(vulnerabilities: List[Dict]) -> List[Dict]:
    """
    生成修复建议
    
    Args:
        vulnerabilities: 漏洞列表
        
    Returns:
        List[Dict]: 修复建议列表
    """
    recommendations = []
    
    for vuln in vulnerabilities:
        vuln_type = vuln.get("type", "").lower()
        recommendation = {
            "vulnerability_id": vuln.get("id"),
            "title": vuln.get("title"),
            "recommendation": ""
        }
        
        if "sql" in vuln_type or "sqli" in vuln_type:
            recommendation["recommendation"] = "使用参数化查询或预编译语句，避免直接拼接用户输入到SQL语句中。"
        elif "xss" in vuln_type:
            recommendation["recommendation"] = "对所有用户输入进行HTML编码，使用内容安全策略(CSP)限制脚本执行。"
        elif "csrf" in vuln_type:
            recommendation["recommendation"] = "实现CSRF令牌验证，检查Referer头，使用SameSite Cookie属性。"
        elif "ssrf" in vuln_type:
            recommendation["recommendation"] = "验证和限制用户提供的URL，使用白名单机制，禁用不必要的协议。"
        elif "lfi" in vuln_type or "rfi" in vuln_type:
            recommendation["recommendation"] = "避免使用用户输入构建文件路径，使用白名单验证文件名，禁用远程文件包含。"
        elif "rce" in vuln_type or "cmd" in vuln_type:
            recommendation["recommendation"] = "避免直接执行用户输入，使用安全的API替代系统命令，严格过滤特殊字符。"
        else:
            recommendation["recommendation"] = "请根据漏洞详情进行针对性修复，建议进行安全代码审计。"
        
        recommendations.append(recommendation)
    
    return recommendations


def _generate_markdown_report(report: Dict) -> str:
    """
    生成 Markdown 格式报告
    
    Args:
        report: 报告数据
        
    Returns:
        str: Markdown 格式的报告
    """
    md = f"""# TOSKill 安全扫描报告

## 基本信息

- **任务名称**: {report['task_name']}
- **扫描目标**: {report['target']}
- **扫描模式**: {report['scan_mode']}
- **生成时间**: {report['generated_at']}

## 扫描摘要

- **漏洞总数**: {report['summary']['total_vulnerabilities']}
- **严重程度分布**:
  - Critical: {report['summary']['severity_distribution']['critical']}
  - High: {report['summary']['severity_distribution']['high']}
  - Medium: {report['summary']['severity_distribution']['medium']}
  - Low: {report['summary']['severity_distribution']['low']}
  - Info: {report['summary']['severity_distribution']['info']}

## 漏洞详情

"""
    for i, vuln in enumerate(report['vulnerabilities'], 1):
        md += f"""### {i}. {vuln.get('title', 'Unknown')}

- **严重程度**: {vuln.get('severity', 'Unknown')}
- **类型**: {vuln.get('type', 'Unknown')}
- **URL**: {vuln.get('url', 'N/A')}

"""
        if vuln.get('description'):
            md += f"**描述**: {vuln['description']}\n\n"
        if vuln.get('evidence'):
            md += f"**证据**: `{vuln['evidence']}`\n\n"
    
    if report.get('remediation_recommendations'):
        md += """## 修复建议

"""
        for rec in report['remediation_recommendations']:
            md += f"""### {rec['title']}

{rec['recommendation']}

"""
    
    return md


def _generate_html_report(report: Dict) -> str:
    """
    生成 HTML 格式报告
    
    Args:
        report: 报告数据
        
    Returns:
        str: HTML 格式的报告
    """
    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TOSKill 安全扫描报告</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #007bff; margin-top: 30px; }}
        .info-box {{ background: #f8f9fa; padding: 15px; border-radius: 4px; margin: 10px 0; }}
        .vuln-item {{ border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 4px; }}
        .severity-critical {{ background: #f8d7da; border-left: 4px solid #dc3545; }}
        .severity-high {{ background: #fff3cd; border-left: 4px solid #ffc107; }}
        .severity-medium {{ background: #fff3cd; border-left: 4px solid #fd7e14; }}
        .severity-low {{ background: #d1ecf1; border-left: 4px solid #17a2b8; }}
        .severity-info {{ background: #d4edda; border-left: 4px solid #28a745; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>TOSKill 安全扫描报告</h1>
        
        <div class="info-box">
            <h2>基本信息</h2>
            <p><strong>任务名称:</strong> {report['task_name']}</p>
            <p><strong>扫描目标:</strong> {report['target']}</p>
            <p><strong>扫描模式:</strong> {report['scan_mode']}</p>
            <p><strong>生成时间:</strong> {report['generated_at']}</p>
        </div>
        
        <div class="info-box">
            <h2>扫描摘要</h2>
            <p><strong>漏洞总数:</strong> {report['summary']['total_vulnerabilities']}</p>
            <p>
                <span class="badge" style="background:#dc3545;color:white;">Critical: {report['summary']['severity_distribution']['critical']}</span>
                <span class="badge" style="background:#ffc107;color:black;">High: {report['summary']['severity_distribution']['high']}</span>
                <span class="badge" style="background:#fd7e14;color:white;">Medium: {report['summary']['severity_distribution']['medium']}</span>
                <span class="badge" style="background:#17a2b8;color:white;">Low: {report['summary']['severity_distribution']['low']}</span>
                <span class="badge" style="background:#28a745;color:white;">Info: {report['summary']['severity_distribution']['info']}</span>
            </p>
        </div>
        
        <h2>漏洞详情</h2>
"""
    for i, vuln in enumerate(report['vulnerabilities'], 1):
        severity = vuln.get('severity', 'info').lower()
        html += f"""
        <div class="vuln-item severity-{severity}">
            <h3>{i}. {vuln.get('title', 'Unknown')}</h3>
            <p><strong>严重程度:</strong> {vuln.get('severity', 'Unknown')}</p>
            <p><strong>类型:</strong> {vuln.get('type', 'Unknown')}</p>
            <p><strong>URL:</strong> {vuln.get('url', 'N/A')}</p>
            {f'<p><strong>描述:</strong> {vuln["description"]}</p>' if vuln.get('description') else ''}
        </div>
"""
    
    html += """
    </div>
</body>
</html>
"""
    return html


@router.get("/health", response_model=APIResponse)
async def health_check():
    """
    TOSKill 系统健康检查
    
    检查 TOSKill 系统的运行状态，包括组件状态、任务统计等。
    
    Returns:
        APIResponse: 包含健康状态的响应
        
    Examples:
        >>> 健康检查
        >>> GET /api/toskill/health
    """
    try:
        stats = await task_manager.get_statistics()
        
        components = {
            "task_manager": {
                "status": "healthy",
                "total_tasks": stats["total"],
                "active_tasks": stats["active"]
            },
            "agent_graph": {
                "status": "healthy",
                "message": "Agent graph initialized"
            },
            "tools_registry": {
                "status": "healthy",
                "message": "Tools registry ready"
            }
        }
        
        try:
            from TOSKill.AI.graph import ScanAgentGraph
            components["agent_graph"]["status"] = "healthy"
        except Exception as e:
            components["agent_graph"]["status"] = "degraded"
            components["agent_graph"]["message"] = str(e)
        
        try:
            from TOSKill.AI.tools.registry import registry
            components["tools_registry"]["tools_count"] = len(registry.tools)
        except Exception as e:
            components["tools_registry"]["status"] = "degraded"
            components["tools_registry"]["message"] = str(e)
        
        overall_status = "healthy"
        for comp in components.values():
            if comp.get("status") == "degraded":
                overall_status = "degraded"
                break
            elif comp.get("status") == "unhealthy":
                overall_status = "unhealthy"
                break
        
        return APIResponse(
            code=200,
            message="健康检查完成",
            data={
                "status": overall_status,
                "components": components,
                "active_tasks": stats["active"],
                "total_tasks": stats["total"],
                "uptime": stats["uptime"],
                "version": "1.0.0"
            }
        )
        
    except Exception as e:
        logger.error(f"[TOSKill] 健康检查失败 | 错误: {str(e)}", exc_info=True)
        return APIResponse(
            code=500,
            message="健康检查失败",
            data={
                "status": "unhealthy",
                "error": str(e)
            }
        )


@router.get("/statistics", response_model=APIResponse)
async def get_statistics():
    """
    获取 TOSKill 统计信息
    
    获取任务执行统计信息，包括总数、活跃数、完成数、失败数等。
    
    Returns:
        APIResponse: 包含统计信息的响应
        
    Examples:
        >>> 获取统计信息
        >>> GET /api/toskill/statistics
    """
    try:
        stats = await task_manager.get_statistics()
        
        return APIResponse(
            code=200,
            message="获取成功",
            data=stats
        )
        
    except Exception as e:
        logger.error(f"[TOSKill] 获取统计信息失败 | 错误: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tasks/{task_id}/vulnerabilities", response_model=APIResponse)
async def get_task_vulnerabilities(
    task_id: str,
    severity: Optional[str] = None,
    skip: int = 0,
    limit: int = 100
):
    """
    获取任务的漏洞列表
    
    获取指定任务发现的所有漏洞，支持按严重程度过滤。
    
    Args:
        task_id: 任务 ID
        severity: 按严重程度过滤 (critical/high/medium/low/info)
        skip: 跳过数量
        limit: 返回数量
        
    Returns:
        APIResponse: 包含漏洞列表的响应
        
    Examples:
        >>> 获取高危漏洞
        >>> GET /api/toskill/tasks/{task_id}/vulnerabilities?severity=high
    """
    try:
        task = await task_manager.get_task(task_id)
        
        if not task:
            raise HTTPException(status_code=404, detail="任务不存在")
        
        result = task.get("result", {})
        vulnerabilities = result.get("vulnerabilities", [])
        
        if severity:
            vulnerabilities = [
                v for v in vulnerabilities
                if str(v.get("severity", "")).lower() == severity.lower()
            ]
        
        total = len(vulnerabilities)
        vulnerabilities = vulnerabilities[skip:skip + limit]
        
        return APIResponse(
            code=200,
            message="获取成功",
            data={
                "vulnerabilities": vulnerabilities,
                "total": total,
                "skip": skip,
                "limit": limit
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[TOSKill] 获取漏洞列表失败 | 任务ID: {task_id} | 错误: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
