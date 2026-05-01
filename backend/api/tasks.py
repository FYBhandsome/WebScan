"""
任务管理相关的 API 路由
已迁移至数据库存储(Tortoise-ORM)

本模块提供任务管理的完整 API 接口,包括:
- 任务创建、查询、更新、删除
- 任务结果获取和聚合
- 漏洞数据管理和统计
- POC 扫描结果管理
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta, timezone
import logging
from tortoise.functions import Count
import json
import asyncio
from backend.models import Task, Vulnerability, POCScanResult, Report
from backend.config import settings
from backend.api.common import APIResponse

logger = logging.getLogger(__name__)

router = APIRouter()

# ====== 辅助函数 ======

def standardize_severity(severity_val) -> str:
    """
    标准化严重程度为统一格式 (Title Case)
    
    支持整数和字符串两种输入格式,统一转换为标准字符串格式。
    
    Args:
        severity_val: 严重程度值,可以是整数 (0-4) 或字符串
        
    Returns:
        str: 标准化后的严重程度字符串,可选值: 'Critical', 'High', 'Medium', 'Low', 'Info'
        
    Examples:
        >>> standardize_severity(4)
        'Critical'
        >>> standardize_severity('high')
        'High'
    """
    if isinstance(severity_val, int):
        if severity_val >= 4: return 'Critical'
        if severity_val == 3: return 'High'
        if severity_val == 2: return 'Medium'
        if severity_val == 1: return 'Low'
        return 'Info'
    
    if isinstance(severity_val, str):
        s = severity_val.lower()
        if s == 'critical': return 'Critical'
        if s == 'high': return 'High'
        if s == 'medium': return 'Medium'
        if s == 'low': return 'Low'
        if s == 'info': return 'Info'
        return severity_val.capitalize()
    
    return 'Info'

# ====== 业务规则常量 ======

VALID_TASK_STATUSES = ['pending', 'running', 'completed', 'failed', 'cancelled']

VALID_STATUS_TRANSITIONS = {
    'pending': ['running', 'cancelled', 'failed'],
    'running': ['completed', 'failed', 'cancelled'],
    'completed': [],
    'failed': ['pending'],
    'cancelled': ['pending']
}

def validate_status_transition(current_status: str, new_status: str) -> tuple:
    """
    验证任务状态转换是否合法
    
    Args:
        current_status: 当前状态
        new_status: 目标状态
        
    Returns:
        tuple: (is_valid: bool, error_message: str)
    """
    if current_status == new_status:
        return True, None
    
    if new_status not in VALID_TASK_STATUSES:
        logger.warning(f"[状态转换验证] 无效的目标状态: {new_status}")
        return False, f"Invalid target status: {new_status}"
    
    allowed_transitions = VALID_STATUS_TRANSITIONS.get(current_status, [])
    if new_status not in allowed_transitions:
        logger.warning(f"[状态转换验证] 非法状态转换: {current_status} -> {new_status}")
        return False, f"Invalid state transition: {current_status} -> {new_status}"
    
    return True, None

# ====== 请求模型 ======

class CreateTaskRequest(BaseModel):
    """
    创建任务的请求模型
    
    Attributes:
        task_name: 任务名称
        target: 扫描目标 (URL、IP 或目录路径)
        task_type: 任务类型,可选值: 'awvs_scan', 'poc_scan', 'scan_dir', 'scan_webside', 'scan_port', 'scan_cms', 'scan_comprehensive'
        config: 任务配置参数,字典格式
    """
    task_name: str
    target: str
    task_type: str
    config: Dict[str, Any] = {}

class TaskUpdate(BaseModel):
    """
    更新任务的请求模型
    
    Attributes:
        status: 任务状态,可选值: 'pending', 'running', 'completed', 'failed', 'cancelled'
        progress: 任务进度,0-100
        result: 任务结果数据
    """
    status: Optional[str] = None
    progress: Optional[int] = None
    result: Optional[Any] = None

# ====== 任务管理接口 ======

@router.post("/create", response_model=APIResponse)
async def create_task(request: CreateTaskRequest):
    """
    统一任务创建接口
    
    创建新的扫描任务并启动异步执行。支持多种任务类型,包括 AWVS 扫描、POC 扫描、目录扫描等。
    
    Args:
        request: 创建任务的请求参数
        
    Returns:
        APIResponse: 包含任务 ID 和状态的响应
        
    Raises:
        HTTPException: 当参数无效或数据库操作失败时抛出
        
    Examples:
        >>> 创建 AWVS 扫描任务
        >>> {
        ...     "task_name": "扫描 www.baidu.com",
        ...     "target": "https://www.baidu.com",
        ...     "task_type": "awvs_scan",
        ...     "config": {"profile_id": "11111111-1111-1111-1111-111111111111"}
        ... }
    """
    try:
        from backend.task_executor import task_executor

        # 1. 验证参数
        if not request.target:
             raise HTTPException(status_code=400, detail="Target cannot be empty")

        # 验证任务类型
        valid_types = ['awvs_scan', 'poc_scan', 'scan_dir', 'scan_webside', 'scan_port', 'scan_cms', 'scan_comprehensive']
        if request.task_type not in valid_types:
            logger.warning(f"无效的任务类型: {request.task_type}")
            # 暂时不强制验证,允许插件扩展
            # TODO: 未来考虑添加任务类型验证
            pass

        # 1.1 POC 任务参数校验
        if request.task_type == 'poc_scan':
            poc_types = request.config.get('poc_types', [])
            if not poc_types:
                 logger.warning("POC扫描未指定POC类型,默认扫描所有")

            # 简单的 POC 类型验证
            # 这里不强制失败,只是记录日志
            # TODO: 未来考虑添加更严格的 POC 类型验证
            pass

        # 2. 创建 Task 记录
        try:
            task = await Task.create(
                task_name=request.task_name,
                task_type=request.task_type,
                target=request.target,
                status='pending',
                progress=0,
                config=json.dumps(request.config)
            )
        except Exception as db_err:
            logger.error(f"创建任务数据库记录失败: {str(db_err)}")
            raise HTTPException(status_code=500, detail=f"Database error: {str(db_err)}")

        # 3. 启动异步任务执行
        try:
            # 确保 task_executor 已初始化
            if not task_executor:
                 raise Exception("Task executor not initialized")

            asyncio.create_task(task_executor.start_task(
                task_id=task.id,
                target=request.target,
                scan_config=request.config
            ))
        except Exception as exec_err:
            logger.error(f"启动异步任务失败: {str(exec_err)}")
            # 更新任务状态为失败
            task.status = 'failed'
            task.error_message = f"Failed to start task: {str(exec_err)}"
            await task.save()
            # 注意:这里我们返回成功,因为任务已创建,只是执行失败。
            # 前端可以通过查询任务状态获知失败。
            # 或者也可以返回 500,取决于前端逻辑。
            # 为了让用户看到任务已创建但失败,我们返回成功。
            return APIResponse(code=200, message="任务创建成功,但启动失败", data={"task_id": task.id, "status": "failed"})
        
        return APIResponse(code=200, message="任务创建成功", data={"task_id": task.id, "status": "pending"})
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"创建任务失败 (未捕获异常): {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/", response_model=APIResponse)
async def list_tasks(
    status: Optional[str] = None,
    task_type: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    search: Optional[str] = None,
    skip: int = 0,
    limit: int = 1000
):
    """
    获取任务列表(使用数据库)
    
    支持按状态、类型、时间范围、关键词过滤,并包含漏洞统计信息。
    
    Args:
        status: 按任务状态过滤,可选值: 'pending', 'running', 'completed', 'failed', 'cancelled'
        task_type: 按任务类型过滤
        start_date: 起始日期,格式: YYYY-MM-DD
        end_date: 结束日期,格式: YYYY-MM-DD
        search: 搜索关键词,匹配任务名称或目标
        skip: 跳过的记录数,用于分页
        limit: 返回的最大记录数
        
    Returns:
        APIResponse: 包含任务列表、总数和分页信息的响应
        
    Examples:
        >>> 获取所有运行中的任务
        >>> GET /tasks/?status=running
    """
    try:
        from tortoise.expressions import Q
        
        # 构建查询条件
        query = Task.all()
        
        # 过滤条件
        if status:
            query = query.filter(status=status)
        if task_type:
            query = query.filter(task_type=task_type)
        if search:
            query = query.filter(Q(task_name__icontains=search) | Q(target__icontains=search))
        if start_date:
            try:
                start_dt = datetime.strptime(start_date, "%Y-%m-%d")
                # 处理时区: 假设前端传入的是北京时间(UTC+8), 转换为UTC时间进行查询
                cn_tz = timezone(timedelta(hours=8))
                start_dt = start_dt.replace(tzinfo=cn_tz)
                start_dt_utc = start_dt.astimezone(timezone.utc)
                query = query.filter(created_at__gte=start_dt_utc)
            except ValueError:
                pass
        if end_date:
            try:
                end_dt = datetime.strptime(end_date, "%Y-%m-%d")
                # 加一天以包含结束日期当天
                end_dt = end_dt + timedelta(days=1)
                # 处理时区: 假设前端传入的是北京时间(UTC+8), 转换为UTC时间进行查询
                cn_tz = timezone(timedelta(hours=8))
                end_dt = end_dt.replace(tzinfo=cn_tz)
                end_dt_utc = end_dt.astimezone(timezone.utc)
                query = query.filter(created_at__lt=end_dt_utc)
            except ValueError:
                pass
        
        # 排序(最新的在前)
        query = query.order_by('-created_at')
        
        # 获取总数
        total = await query.count()
        
        # 分页查询
        tasks = await query.offset(skip).limit(limit)
        
        # 转换为字典格式
        task_list = []
        for task in tasks:
            res = {}
            if task.result:
                try:
                    parsed = json.loads(task.result)
                    if isinstance(parsed, dict):
                        res = parsed
                    else:
                        res = {'raw_result': parsed}
                except:
                    res = {'raw_result': task.result}

            task_dict = {
                "id": task.id,
                "task_name": task.task_name,
                "task_type": task.task_type,
                "target": task.target,
                "status": task.status,
                "progress": task.progress,
                "config": json.loads(task.config) if task.config else {},
                "result": res,
            "created_at": task.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "updated_at": task.updated_at.strftime("%Y-%m-%dT%H:%M:%SZ")
        }
        
        # 计算漏洞统计 (从数据库)
            # 这确保了 Dashboard 显示的数字与详情页一致 (包括 Critical)
            try:
                vuln_counts = await Vulnerability.filter(task_id=task.id).group_by('severity').annotate(count=Count('id')).values('severity', 'count')
                
                counts_map = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
                total_db_count = 0
                for item in vuln_counts:
                    s = str(item['severity']).lower()
                    if s in counts_map:
                        counts_map[s] = item['count']
                        total_db_count += item['count']
                
                # 只有当数据库有数据时才覆盖,否则保留原始 result 中的数据 (如果存在)
                # 这样即使数据库同步失败,也能显示 AWVS 原始统计 (虽然可能没有 Critical)
                if total_db_count > 0:
                    if 'vulnerabilities' not in task_dict['result']:
                         task_dict['result']['vulnerabilities'] = {}
                    task_dict['result']['vulnerabilities'] = counts_map
                elif 'vulnerabilities' not in task_dict['result'] or not task_dict['result']['vulnerabilities']:
                    # 如果数据库没数据且 result 也没数据,默认全 0
                    task_dict['result']['vulnerabilities'] = counts_map
            except Exception as e:
                logger.warning(f"Failed to get vulnerability counts for task {task.id}: {e}")

            task_list.append(task_dict)
        
        return APIResponse(
            code=200,
            message="获取成功",
            data={
                "tasks": task_list,
                "total": total,
                "skip": skip,
                "limit": limit
            }
        )
    except Exception as e:
        logger.error(f"获取任务列表失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/frozen", response_model=APIResponse)
async def get_frozen_tasks():
    """
    获取冻结任务列表
    
    获取运行时间超过预设阈值的80%的任务，这些任务可能已卡死。
    
    Returns:
        APIResponse: 包含冻结任务列表的响应
        
    Examples:
        >>> 获取冻结任务
        >>> GET /tasks/frozen
    """
    try:
        # 获取所有运行中的任务
        running_tasks = await Task.filter(status='running').all()
        
        frozen_tasks = []
        for task in running_tasks:
            # 计算运行时长（分钟）
            if task.created_at:
                now = datetime.now(timezone.utc)
                created_at = task.created_at
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=timezone.utc)
                duration = (now - created_at).total_seconds() / 60
                
                # 预设阈值（默认30分钟）
                threshold = 30
                
                # 如果运行时长超过阈值的80%，视为可能冻结
                if duration > threshold * 0.8:
                    frozen_tasks.append({
                        "id": task.id,
                        "task_name": task.task_name,
                        "task_type": task.task_type,
                        "duration": round(duration, 1),
                        "threshold": threshold,
                        "progress": task.progress or 0
                    })
        
        return APIResponse(
            code=200,
            message="获取成功",
            data=frozen_tasks
        )
    except Exception as e:
        logger.error(f"获取冻结任务失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/statistics/overview", response_model=APIResponse)
async def get_statistics_overview():
    """
    获取任务统计概览
    
    获取所有任务的统计信息,包括:
    - 总任务数
    - 各状态任务数
    - 各类型任务数
    - 总漏洞数
    - 各严重程度漏洞数
    
    Returns:
        APIResponse: 包含统计概览数据的响应
        
    Examples:
        >>> 获取统计概览
        >>> GET /tasks/statistics/overview
    """
    try:
        from backend.models import Task, Vulnerability
        from tortoise.functions import Count
        
        # 任务统计
        total_tasks = await Task.all().count()
        
        # 按状态统计
        status_stats = await Task.all().group_by('status').annotate(count=Count('id')).values('status', 'count')
        status_counts = {item['status']: item['count'] for item in status_stats}
        
        # 按类型统计
        type_stats = await Task.all().group_by('task_type').annotate(count=Count('id')).values('task_type', 'count')
        type_counts = {item['task_type']: item['count'] for item in type_stats}
        
        # 漏洞统计
        total_vulns = await Vulnerability.all().count()
        
        # 按严重程度统计
        severity_stats = await Vulnerability.all().group_by('severity').annotate(count=Count('id')).values('severity', 'count')
        severity_counts = {item['severity']: item['count'] for item in severity_stats}
        
        return APIResponse(
            code=200,
            message="获取成功",
            data={
                "tasks": {
                    "total": total_tasks,
                    "by_status": status_counts,
                    "by_type": type_counts
                },
                "vulnerabilities": {
                    "total": total_vulns,
                    "by_severity": severity_counts
                }
            }
        )
    except Exception as e:
        logger.error(f"获取统计概览失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{task_id}", response_model=APIResponse)
async def get_task(task_id: int):
    """
    获取任务详情(使用数据库)
    
    根据任务 ID 获取单个任务的详细信息。
    
    Args:
        task_id: 任务 ID
        
    Returns:
        APIResponse: 包含任务详细信息的响应
        
    Raises:
        HTTPException: 当任务不存在时抛出 404 错误
        
    Examples:
        >>> 获取 ID 为 1 的任务详情
        >>> GET /tasks/1
    """
    try:
        task = await Task.get_or_none(id=task_id)
        
        if not task:
            raise HTTPException(status_code=404, detail="任务不存在")
        
        # 转换为字典格式
        task_dict = {
            "id": task.id,
            "task_name": task.task_name,
            "task_type": task.task_type,
            "target": task.target,
            "status": task.status,
            "progress": task.progress,
            "config": json.loads(task.config) if task.config else {},
            "result": json.loads(task.result) if task.result else None,
            "created_at": task.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "updated_at": task.updated_at.strftime("%Y-%m-%dT%H:%M:%SZ")
        }
        
        return APIResponse(code=200, message="获取成功", data=task_dict)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"获取任务详情失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{task_id}", response_model=APIResponse)
async def update_task(task_id: int, task_update: TaskUpdate):
    """
    更新任务状态
    
    更新任务的状态、进度或结果信息。包含完整的状态转换验证和业务流程日志。
    
    Args:
        task_id: 任务 ID
        task_update: 更新数据
        
    Returns:
        APIResponse: 更新成功的响应
        
    Raises:
        HTTPException: 当任务不存在或状态转换非法时抛出错误
        
    Business Rules:
        - pending -> running, cancelled, failed
        - running -> completed, failed, cancelled
        - completed -> (no transitions allowed)
        - failed -> pending
        - cancelled -> pending
    """
    try:
        task = await Task.get_or_none(id=task_id)
        if not task:
            logger.warning(f"[任务更新] 任务不存在 | 任务ID: {task_id}")
            raise HTTPException(status_code=404, detail="任务不存在")
        
        current_status = task.status
        current_progress = task.progress
        
        if task_update.status:
            is_valid, error_msg = validate_status_transition(current_status, task_update.status)
            if not is_valid:
                logger.warning(f"[任务更新] 状态转换验证失败 | {error_msg}")
                raise HTTPException(status_code=400, detail=error_msg)
            task.status = task_update.status
        
        if task_update.progress is not None:
            if not (0 <= task_update.progress <= 100):
                logger.warning(f"[任务更新] 进度值无效: {task_update.progress}")
                raise HTTPException(status_code=400, detail="Progress must be between 0 and 100")
            task.progress = task_update.progress
        
        if task_update.result:
            task.result = json.dumps(task_update.result)
            
        await task.save()
        
        return APIResponse(code=200, message="更新成功")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[任务更新] 更新任务失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{task_id}", response_model=APIResponse)
async def delete_task(task_id: int):
    """
    删除任务
    
    根据任务 ID 删除任务及其相关数据。
    
    Args:
        task_id: 任务 ID
        
    Returns:
        APIResponse: 删除成功的响应
        
    Raises:
        HTTPException: 当任务不存在时抛出 404 错误
        
    Examples:
        >>> 删除 ID 为 1 的任务
        >>> DELETE /tasks/1
    """
    try:
        from backend.models import Task
        
        task = await Task.get_or_none(id=task_id)
        if not task:
            raise HTTPException(status_code=404, detail="任务不存在")
            
        await task.delete()
        
        return APIResponse(code=200, message="删除成功")
    except Exception as e:
        logger.error(f"删除任务失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{task_id}/results", response_model=APIResponse)
async def get_task_results(task_id: int):
    """
    获取任务的详细结果(智能聚合)
    
    获取任务的完整扫描结果,包括:
    - 任务基本信息
    - AWVS 漏洞列表
    - POC 扫描结果
    - 插件扫描结果
    
    支持从数据库和 AWVS API 双向获取数据,并自动同步到数据库。
    
    Args:
        task_id: 任务 ID
        
    Returns:
        APIResponse: 包含任务详细结果的响应,结构如下:
            {
                "task_info": {...},
                "vulnerabilities": [...],
                "basic_info": [...],
                "poc_results": [...]
            }
        
    Raises:
        HTTPException: 当任务不存在或获取失败时抛出错误
        
    Examples:
        >>> 获取 ID 为 1 的任务结果
        >>> GET /tasks/1/results
    """
    try:
        task = await Task.get_or_none(id=task_id)
        if not task:
            raise HTTPException(status_code=404, detail="任务不存在")

        response_data = {
            "task_info": {
                "id": task.id,
                "name": task.task_name,
                "type": task.task_type,
                "target": task.target,
                "status": task.status,
                "created_at": task.created_at,
                "updated_at": task.updated_at
            },
            "vulnerabilities": [],
            "basic_info": [],
            "poc_results": []
        }

        # 1. 获取 POC 结果
        poc_results = await POCScanResult.filter(task=task).all()
        for poc in poc_results:
            response_data["poc_results"].append({
                "id": poc.id,
                "poc_type": poc.poc_type,
                "target": poc.target,
                "vulnerable": poc.vulnerable,
                "message": poc.message,
                "severity": standardize_severity(poc.severity),  # 强制标准化
                "cve_id": poc.cve_id,
                "created_at": poc.created_at,
                "source": "poc"
            })

        # 2. 获取 AWVS 漏洞
        # 优先从数据库获取
        db_vulns = await Vulnerability.filter(task=task).all()
        if db_vulns:
            for v in db_vulns:
                 response_data["vulnerabilities"].append({
                    "id": v.source_id or str(v.id), # 优先使用 source_id (AWVS GUID), 否则使用 DB ID
                    "title": v.title,
                    "severity": standardize_severity(v.severity),
                    "status": v.status,
                    "cvss_score": None, # 数据库暂未存储
                    "discovered_at": str(v.created_at),
                    "description": f"Found on {v.url}", 
                    "type": v.vuln_type,
                    "target": v.url,
                    "source": "awvs"
                })
        # 如果数据库没有且是 AWVS 任务,尝试从 API 获取 (并同步到数据库)
        elif task.task_type == 'awvs_scan':
            config = json.loads(task.config) if task.config else {}
            target_id = config.get('target_id')
            
            # 尝试从 AWVS API 获取最新漏洞
            if target_id and settings.AWVS_API_KEY:
                try:
                    client = {'api_url': settings.AWVS_API_URL, 'api_key': settings.AWVS_API_KEY}
                    v_api = Vuln(client['api_url'], client['api_key'])
                    result_text = v_api.search(status='open', target_id=target_id)
                    if result_text:
                        result_json = json.loads(result_text)
                        vulns = result_json.get('vulnerabilities', [])
                        
                        for val in vulns:
                            # 数据一致性检查与清洗
                            severity_val = val.get('severity')
                            severity_str = standardize_severity(severity_val)
                            
                            vt_name = val.get('vt_name', 'Unknown Vulnerability')
                            title = standardize_title(vt_name)

                            # 数据一致性检查机制
                            validation_errors = validate_vulnerability_consistency(val)
                            if validation_errors:
                                logger.warning(f"Task {task_id} Vulnerability Consistency Warning: {validation_errors} - Data: {val.get('vuln_id', 'Unknown')}")
                                if "Missing vuln_id" in validation_errors:
                                     continue # Skip items without ID
                            
                            # 保存到数据库 (Sync)
                            try:
                                await Vulnerability.create(
                                    task=task,
                                    vuln_type=val.get('vt_name'),
                                    severity=severity_str,
                                    title=title,
                                    description=val.get('description', ''),
                                    url=val.get('affects_url', ''),
                                    status=val.get('status', 'open'),
                                    source_id=val.get('vuln_id')
                                )
                            except Exception as db_e:
                                logger.error(f"Sync vulnerability to DB failed: {db_e}")

                            response_data["vulnerabilities"].append({
                                "id": val.get('vuln_id'),
                                "title": title,
                                "severity": severity_str,
                                "status": val.get('status'),
                                "cvss_score": val.get('cvss_score'),
                                "discovered_at": val.get('last_seen'),
                                "description": f"Found on {val.get('affects_url')}", 
                                "type": val.get('vt_name'),
                                "target": val.get('affects_url'),
                                "source": "awvs",
                                "consistency_errors": validation_errors # 返回一致性检查结果
                            })
                except Exception as e:
                    logger.warning(f"从 AWVS 获取漏洞失败: {e}")
            
        # 3. 获取插件扫描结果 (非 AWVS/POC 任务,或者混合任务)
        # 始终尝试提取 basic_info,无论任务类型如何
        if task.result:
            try:
                res = json.loads(task.result)
                # 尝试提取结构化基础信息
                if isinstance(res, dict):
                    # 如果是 AWVS 任务,result 主要是统计信息,基础信息可能在 details 里
                    # 但如果是插件任务,result 本身就是信息
                    
                    # 排除掉已知的大字段
                    ignored_keys = ['vulnerabilities', 'scan_id', 'target_id', 'scan_status', 'start_time', 'end_time', 'requests_count', 'vulnerabilities_count']
                    
                    for k, v in res.items():
                        if k not in ignored_keys:
                            # 格式化 value
                            val_str = str(v)
                            # 如果是列表或字典,转换为 JSON 字符串
                            if isinstance(v, (list, dict)):
                                try:
                                    val_str = json.dumps(v, ensure_ascii=False)
                                except:
                                    pass
                            # 限制长度
                            if len(val_str) > 500:
                                val_str = val_str[:500] + "..."
                            response_data["basic_info"].append({
                                "key": k,
                                "value": val_str
                            })
            except Exception as e:
                logger.warning(f"解析任务结果失败: {e}")
        
        return APIResponse(code=200, message="获取成功", data=response_data)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"获取任务结果失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{task_id}/cancel", response_model=APIResponse)
async def cancel_task(task_id: int):
    """
    取消任务
    
    取消正在运行或等待中的任务。
    
    Args:
        task_id: 任务 ID
        
    Returns:
        APIResponse: 取消成功的响应
        
    Raises:
        HTTPException: 当任务不存在或无法取消时抛出错误
        
    Examples:
        >>> 取消 ID 为 1 的任务
        >>> POST /tasks/1/cancel
    """
    try:
        from backend.task_executor import task_executor

        task = await Task.get_or_none(id=task_id)
        if not task:
            raise HTTPException(status_code=404, detail="任务不存在")
        
        if task.status not in ['pending', 'running']:
            raise HTTPException(status_code=400, detail="只能取消等待中或运行中的任务")
        
        # 更新任务状态
        task.status = 'cancelled'
        await task.save()
        
        # 通知任务执行器停止任务
        if task_executor:
            try:
                await task_executor.cancel_task(task_id)
            except Exception as e:
                logger.warning(f"通知任务执行器取消任务失败: {e}")
        
        return APIResponse(code=200, message="任务已取消")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"取消任务失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{task_id}/logs", response_model=APIResponse)
async def get_task_logs(
    task_id: int,
    skip: int = 0,
    limit: int = 100
):
    """
    获取任务日志
    
    获取指定任务的执行日志记录。
    
    Args:
        task_id: 任务 ID
        skip: 跳过的记录数,用于分页
        limit: 返回的最大记录数
        
    Returns:
        APIResponse: 包含日志列表的响应
        
    Raises:
        HTTPException: 当任务不存在时抛出 404 错误
        
    Examples:
        >>> 获取任务 1 的日志
        >>> GET /tasks/1/logs
    """
    try:
        task = await Task.get_or_none(id=task_id)
        if not task:
            raise HTTPException(status_code=404, detail="任务不存在")
        
        logs = []
        if task.result:
            try:
                result = json.loads(task.result)
                if isinstance(result, dict):
                    execution_history = result.get('execution_history', [])
                    if isinstance(execution_history, list):
                        logs = execution_history[skip:skip+limit]
            except:
                pass
        
        return APIResponse(
            code=200,
            message="获取成功",
            data={
                "logs": logs,
                "total": len(logs),
                "skip": skip,
                "limit": limit
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"获取任务日志失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{task_id}/vulnerabilities", response_model=APIResponse)
async def get_task_vulnerabilities(
    task_id: str,
    severity: Optional[str] = None,
    type: Optional[str] = None,
    source: Optional[str] = None,
    status: Optional[str] = None,
    skip: int = 0,
    limit: int = 100
):
    """
    获取任务的漏洞列表
    
    获取指定任务的所有漏洞,支持按严重程度、类型、来源和状态过滤。
    支持整数ID和UUID格式的task_id。
    
    Args:
        task_id: 任务 ID (整数或UUID字符串)
        severity: 按严重程度过滤,可选值: 'critical', 'high', 'medium', 'low', 'info'
        type: 按漏洞类型过滤
        source: 按漏洞来源过滤,可选值: 'awvs', 'poc', 'ai_agent'
        status: 按漏洞状态过滤,可选值: 'open', 'fixed', 'reopened'
        skip: 跳过的记录数
        limit: 返回的记录数
        
    Returns:
        APIResponse: 包含漏洞列表的响应
    """
    try:
        import uuid
        
        is_uuid = False
        try:
            uuid.UUID(str(task_id))
            is_uuid = True
        except (ValueError, AttributeError):
            pass
        
        if is_uuid:
            from backend.models import AgentTask, AgentResult
            
            agent_task = await AgentTask.get_or_none(task_id=task_id)
            if agent_task:
                agent_result = await AgentResult.get_or_none(task=agent_task)
                if not agent_result or not agent_result.final_output:
                    return APIResponse(
                        code=200,
                        message="获取成功",
                        data={
                            "vulnerabilities": [],
                            "total": 0,
                            "skip": skip,
                            "limit": limit
                        }
                    )
                
                try:
                    result_data = json.loads(agent_result.final_output)
                except json.JSONDecodeError:
                    result_data = {}
                
                vulnerabilities = result_data.get('vulnerabilities', [])
                if not isinstance(vulnerabilities, list):
                    vulnerabilities = []
                
                vuln_list = []
                for idx, vuln in enumerate(vulnerabilities):
                    vuln_severity = vuln.get('severity', 'Info')
                    if severity and vuln_severity.lower() != severity.lower():
                        continue
                    if type and vuln.get('type', '').lower() != type.lower():
                        continue
                    if source and vuln.get('source', 'ai_agent').lower() != source.lower():
                        continue
                    if status and vuln.get('status', 'open').lower() != status.lower():
                        continue
                    
                    vuln_list.append({
                        "id": vuln.get('id') or f"agent-{task_id[:8]}-{idx}",
                        "title": vuln.get('title', 'Unknown Vulnerability'),
                        "severity": standardize_severity(vuln_severity),
                        "status": vuln.get('status', 'open'),
                        "type": vuln.get('type', vuln.get('vuln_type', 'Unknown')),
                        "url": vuln.get('url', ''),
                        "description": vuln.get('description', ''),
                        "payload": vuln.get('payload', ''),
                        "evidence": vuln.get('evidence', ''),
                        "remediation": vuln.get('remediation', ''),
                        "created_at": agent_task.created_at.strftime("%Y-%m-%dT%H:%M:%SZ") if agent_task.created_at else None,
                        "updated_at": agent_task.updated_at.strftime("%Y-%m-%dT%H:%M:%SZ") if agent_task.updated_at else None,
                        "source": vuln.get('source', 'ai_agent')
                    })
                
                total = len(vuln_list)
                vuln_list = vuln_list[skip:skip + limit]
                
                return APIResponse(
                    code=200,
                    message="获取成功",
                    data={
                        "vulnerabilities": vuln_list,
                        "total": total,
                        "skip": skip,
                        "limit": limit
                    }
                )
            
            awvs_task = await Task.filter(config__contains=str(task_id)).first()
            if awvs_task:
                task = awvs_task
            else:
                raise HTTPException(status_code=404, detail="任务不存在")
        else:
            try:
                task_id_int = int(task_id)
                task = await Task.get_or_none(id=task_id_int)
            except ValueError:
                task = None
            
            if not task:
                raise HTTPException(status_code=404, detail="任务不存在")
        
        if task:
            query = Vulnerability.filter(task=task)
            
            if severity:
                query = query.filter(severity=severity.lower())
            if type:
                query = query.filter(vuln_type=type)
            if source:
                query = query.filter(source=source.lower())
            if status:
                query = query.filter(status=status.lower())
            
            query = query.order_by('-created_at')
            
            total = await query.count()
            vulns = await query.offset(skip).limit(limit)
            
            vuln_list = []
            for vuln in vulns:
                vuln_list.append({
                    "id": vuln.source_id or str(vuln.id),
                    "title": vuln.title,
                    "severity": standardize_severity(vuln.severity),
                    "status": vuln.status,
                    "type": vuln.vuln_type,
                    "url": vuln.url,
                    "description": vuln.description,
                    "created_at": vuln.created_at.strftime("%Y-%m-%dT%H:%M:%SZ") if vuln.created_at else None,
                    "updated_at": vuln.updated_at.strftime("%Y-%m-%dT%H:%M:%SZ") if vuln.updated_at else None,
                    "source": vuln.source
                })
            
            return APIResponse(
                code=200,
                message="获取成功",
                data={
                    "vulnerabilities": vuln_list,
                    "total": total,
                    "skip": skip,
                    "limit": limit
                }
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"获取任务漏洞列表失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

