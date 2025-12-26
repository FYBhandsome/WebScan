"""
任务管理相关的 API 路由
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

router = APIRouter()


# 请求模型
class TaskCreate(BaseModel):
    task_name: str
    task_type: str  # scan, vulnerability, etc.
    target: str
    config: Optional[Dict[str, Any]] = {}


class TaskUpdate(BaseModel):
    status: Optional[str] = None
    result: Optional[Dict[str, Any]] = None


# 响应模型
class TaskResponse(BaseModel):
    id: int
    task_name: str
    task_type: str
    target: str
    status: str
    progress: int
    config: Dict[str, Any]
    result: Optional[Dict[str, Any]]
    created_at: datetime
    updated_at: datetime


class APIResponse(BaseModel):
    code: int
    message: str
    data: Optional[Any] = None


# 模拟任务存储（实际应该使用数据库）
tasks_store = {}
task_id_counter = 0


@router.get("/", response_model=APIResponse)
async def list_tasks(
    status: Optional[str] = None,
    task_type: Optional[str] = None,
    skip: int = 0,
    limit: int = 20
):
    """
    获取任务列表
    """
    try:
        tasks = list(tasks_store.values())
        
        # 过滤
        if status:
            tasks = [t for t in tasks if t['status'] == status]
        if task_type:
            tasks = [t for t in tasks if t['task_type'] == task_type]
        
        # 排序（最新的在前）
        tasks = sorted(tasks, key=lambda x: x['created_at'], reverse=True)
        
        # 分页
        total = len(tasks)
        tasks = tasks[skip:skip + limit]
        
        return APIResponse(
            code=200,
            message="获取成功",
            data={
                "tasks": tasks,
                "total": total,
                "skip": skip,
                "limit": limit
            }
        )
    except Exception as e:
        logger.error(f"获取任务列表失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/", response_model=APIResponse)
async def create_task(task: TaskCreate):
    """
    创建新任务
    """
    global task_id_counter
    try:
        task_id_counter += 1
        
        new_task = {
            "id": task_id_counter,
            "task_name": task.task_name,
            "task_type": task.task_type,
            "target": task.target,
            "status": "pending",
            "progress": 0,
            "config": task.config or {},
            "result": None,
            "created_at": datetime.now(),
            "updated_at": datetime.now()
        }
        
        tasks_store[task_id_counter] = new_task
        logger.info(f"创建任务: {task.task_name} (ID: {task_id_counter})")
        
        # TODO: 启动异步任务执行
        # asyncio.create_task(execute_task(task_id_counter))
        
        return APIResponse(code=200, message="任务创建成功", data=new_task)
    except Exception as e:
        logger.error(f"创建任务失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{task_id}", response_model=APIResponse)
async def get_task(task_id: int):
    """
    获取任务详情
    """
    try:
        if task_id not in tasks_store:
            raise HTTPException(status_code=404, detail="任务不存在")
        
        return APIResponse(code=200, message="获取成功", data=tasks_store[task_id])
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"获取任务详情失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{task_id}", response_model=APIResponse)
async def update_task(task_id: int, task_update: TaskUpdate):
    """
    更新任务状态
    """
    try:
        if task_id not in tasks_store:
            raise HTTPException(status_code=404, detail="任务不存在")
        
        task = tasks_store[task_id]
        
        if task_update.status:
            task['status'] = task_update.status
        if task_update.result is not None:
            task['result'] = task_update.result
        
        task['updated_at'] = datetime.now()
        
        logger.info(f"更新任务: {task_id}")
        return APIResponse(code=200, message="更新成功", data=task)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"更新任务失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{task_id}", response_model=APIResponse)
async def delete_task(task_id: int):
    """
    删除任务
    """
    try:
        if task_id not in tasks_store:
            raise HTTPException(status_code=404, detail="任务不存在")
        
        task_name = tasks_store[task_id]['task_name']
        del tasks_store[task_id]
        
        logger.info(f"删除任务: {task_name} (ID: {task_id})")
        return APIResponse(code=200, message="删除成功", data=None)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"删除任务失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{task_id}/cancel", response_model=APIResponse)
async def cancel_task(task_id: int):
    """
    取消任务
    """
    try:
        if task_id not in tasks_store:
            raise HTTPException(status_code=404, detail="任务不存在")
        
        task = tasks_store[task_id]
        
        if task['status'] in ['completed', 'failed', 'cancelled']:
            return APIResponse(code=400, message=f"任务已{task['status']}，无法取消", data=None)
        
        task['status'] = 'cancelled'
        task['updated_at'] = datetime.now()
        
        # TODO: 停止正在执行的任务
        
        logger.info(f"取消任务: {task_id}")
        return APIResponse(code=200, message="任务已取消", data=task)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"取消任务失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
