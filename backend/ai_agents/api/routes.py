"""
AI Agents API 路由

提供Agent扫描任务的API接口。

优化内容:
- 集成POC搜索、执行和批量执行API
- 集成工作流执行指标API
- 添加统一的错误处理和响应格式
- 增强错误处理和日志记录
"""
import json
import logging
from typing import Dict, Any, Optional, List
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from enum import Enum

from backend.models import Task
from backend.api.common import APIResponse
from backend.task_executor import task_executor
from ..core.state import AgentState
from ..agent_config import agent_config

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ai_agents", tags=["AI Agents"])


class AgentScanRequest(BaseModel):
    """
    Agent扫描请求模型
    
    Attributes:
        target: 扫描目标(URL/IP)
        enable_llm_planning: 是否启用LLM增强规划
        custom_tasks: 自定义任务列表(可选)
        need_custom_scan: 是否需要自定义扫描
        custom_scan_type: 自定义扫描类型
        custom_scan_requirements: 自定义扫描需求
        custom_scan_language: 自定义扫描语言
        need_capability_enhancement: 是否需要功能补充
        capability_requirement: 功能补充需求
        strategy: 扫描策略 (quick/standard/deep)
        concurrency: 并发数
        timeout: 超时时间(秒)
        selected_tools: 选定的工具列表
    """
    target: str
    enable_llm_planning: Optional[bool] = None
    custom_tasks: Optional[list] = None
    need_custom_scan: Optional[bool] = False
    custom_scan_type: Optional[str] = None
    custom_scan_requirements: Optional[str] = None
    custom_scan_language: Optional[str] = "python"
    need_capability_enhancement: Optional[bool] = False
    capability_requirement: Optional[str] = None
    strategy: Optional[str] = "standard"
    concurrency: Optional[int] = 5
    timeout: Optional[int] = 300
    selected_tools: Optional[list] = None


class AgentScanResponse(BaseModel):
    """
    Agent扫描响应模型
    
    Attributes:
        task_id: 任务ID
        status: 任务状态
        message: 响应消息
    """
    task_id: str
    status: str
    message: str


@router.post("/scan", response_model=AgentScanResponse)
async def start_agent_scan(
    request: AgentScanRequest
):
    """
    启动Agent扫描任务
    
    创建Agent任务并在后台执行扫描工作流。
    """
    try:
        # 1. 构造扫描配置
        scan_config = request.model_dump()
        logger.info(f"[AI_AGENT] [INIT] 构造扫描配置 - 模块: API, 变量: scan_config, 值: {scan_config}")
        
        # 2. 更新全局配置 (如果需要)
        if request.enable_llm_planning is not None:
            old_value = agent_config.ENABLE_LLM_PLANNING
            agent_config.ENABLE_LLM_PLANNING = request.enable_llm_planning
            logger.info(f"[AI_AGENT] [CONFIG] 更新LLM规划配置 - 模块: API, 变量: ENABLE_LLM_PLANNING, 旧值: {old_value}, 新值: {request.enable_llm_planning}, 状态: updated")
            
        # 3. 创建任务记录 (Unified Task Model)
        task_obj = await Task.create(
            task_name=f"AI Agent Scan {request.target}",
            task_type="ai_agent_scan",
            target=request.target,
            status="pending",
            progress=0,
            config=json.dumps(scan_config, ensure_ascii=False)
        )
        
        task_id = task_obj.id
        logger.info(f"[AI_AGENT] [TASK_CREATE] 创建任务记录 - 模块: API, 变量: task_id, 值: {task_id}, 状态: created")
        
        # 4. 提交到任务执行器 (串行队列)
        await task_executor.start_task(
            task_id=task_id,
            target=request.target,
            scan_config=scan_config
        )
        
        logger.info(f"[AI_AGENT] [TASK_SUBMIT] 任务已提交到队列 - 模块: API, 变量: task_id, 值: {task_id}, 目标: {request.target}, 状态: queued")
        
        return AgentScanResponse(
            task_id=str(task_id),
            status="pending",
            message="Agent扫描任务已提交到队列"
        )
        
    except Exception as e:
        logger.error(f"[AI_AGENT] [ERROR] 启动Agent任务失败 - 模块: API, 错误: {str(e)}, 堆栈: {type(e).__name__}")
        raise HTTPException(
            status_code=500,
            detail=f"启动Agent任务失败: {str(e)}"
        )


@router.get("/tasks/{task_id}", response_model=APIResponse)
async def get_agent_task(task_id: str):
    """
    获取Agent任务详情
    """
    try:
        logger.info(f"[AI_AGENT] [TASK_DETAIL_START] 获取Agent任务详情 - 模块: API, 变量: task_id, 值: {task_id}")
        
        db_task_id = None
        if task_id.isdigit():
            db_task_id = int(task_id)
            logger.info(f"[AI_AGENT] [TASK_DETAIL_CONVERT] Task ID转换 - 模块: API, 变量: task_id, 旧值: {task_id}, 新值: {db_task_id}")
        
        task = None
        if db_task_id:
            logger.info(f"[AI_AGENT] [TASK_DETAIL_DB] 从数据库获取任务 - 模块: API, 变量: db_task_id, 状态: querying")
            task = await Task.get_or_none(id=db_task_id)
        
        if not task:
            logger.error(f"[AI_AGENT] [TASK_DETAIL_NOT_FOUND] 任务不存在 - 模块: API, 变量: task_id, 值: {task_id}, 状态: error")
            raise HTTPException(status_code=404, detail="任务不存在")
        
        logger.info(f"[AI_AGENT] [TASK_DETAIL_FOUND] 找到任务 - 模块: API, 变量: task_id, 值: {task.id}, 状态: {task.status}")
        
        execution_history = []
        stages = {}
        graph_flow = None
        final_output = None
        
        if task.result:
            try:
                if isinstance(task.result, str):
                    result_data = json.loads(task.result)
                else:
                    result_data = task.result
                
                execution_history = result_data.get('execution_history', [])
                raw_stages = result_data.get('stages', {})
                graph_flow = result_data.get('graph_flow')
                final_output = result_data.get('final_output', result_data)
                target_context = result_data.get('target_context', {})
                scan_summary = result_data.get('scan_summary', {})
                
                if raw_stages:
                    for stage_name in ['planning', 'tool_execution', 'poc_verification', 'report']:
                        if stage_name in raw_stages:
                            stages[stage_name] = raw_stages[stage_name]
                        elif stage_name not in stages:
                            stages[stage_name] = {'status': 'pending', 'progress': 0}
            except Exception as parse_err:
                logger.warning(f"[AI_AGENT] [TASK_DETAIL_PARSE] 解析任务结果失败: {parse_err}")
                final_output = task.result
        
        all_pending = all(
            s.get('status') == 'pending' for s in stages.values()
        ) if stages else True
        
        if (not stages or all_pending) and task.status == 'completed':
            stages = {
                'planning': {'status': 'completed', 'progress': 100},
                'tool_execution': {'status': 'completed', 'progress': 100},
                'poc_verification': {'status': 'completed', 'progress': 100},
                'report': {'status': 'completed', 'progress': 100}
            }
        elif (not stages or all_pending) and task.status == 'running':
            progress = task.progress or 0
            stages = {
                'planning': {
                    'status': 'running' if progress < 25 else 'completed',
                    'progress': min(progress, 25)
                },
                'tool_execution': {
                    'status': 'running' if 25 <= progress < 50 else ('completed' if progress >= 50 else 'pending'),
                    'progress': max(0, min(25, progress - 25))
                },
                'poc_verification': {
                    'status': 'running' if 50 <= progress < 75 else ('completed' if progress >= 75 else 'pending'),
                    'progress': max(0, min(25, progress - 50))
                },
                'report': {
                    'status': 'running' if 75 <= progress < 100 else ('completed' if progress >= 100 else 'pending'),
                    'progress': max(0, min(25, progress - 75))
                }
            }
        elif not stages:
            stages = {
                'planning': {'status': 'pending', 'progress': 0},
                'tool_execution': {'status': 'pending', 'progress': 0},
                'poc_verification': {'status': 'pending', 'progress': 0},
                'report': {'status': 'pending', 'progress': 0}
            }
        
        return APIResponse(
            code=200,
            message="获取成功",
            data={
                "task_id": str(task.id),
                "task_type": task.task_type,
                "target": task.target,
                "status": task.status,
                "progress": task.progress,
                "config": task.config,
                "stages": stages,
                "execution_history": execution_history,
                "graph_flow": graph_flow,
                "target_context": target_context,
                "scan_summary": scan_summary,
                "created_at": task.created_at,
                "updated_at": task.updated_at,
                "final_output": final_output,
                "error_message": task.error_message
            }
        )
        
    except HTTPException as http_ex:
        logger.error(f"[AI_AGENT] [ERROR] 获取Agent任务详情HTTP异常 - 模块: API, 错误: {str(http_ex)}")
        raise
    except Exception as e:
        logger.error(f"[AI_AGENT] [ERROR] 获取Agent任务详情失败 - 模块: API, 错误: {str(e)}, 堆栈: {type(e).__name__}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tasks")
async def list_agent_tasks(
    status: Optional[str] = None,
    task_type: Optional[str] = None,
    page: int = 1,
    page_size: int = 20
):
    """
    获取Agent任务列表
    """
    try:
        logger.info(f"[AI_AGENT] [TASK_LIST_START] 获取Agent任务列表 - 模块: API, 参数: status={status}, task_type={task_type}, page={page}, page_size={page_size}")
        
        # 查询 Unified Task Model, 过滤 ai_agent_scan 类型
        query = Task.filter(task_type="ai_agent_scan")
        
        if status:
            query = query.filter(status=status)
            logger.info(f"[AI_AGENT] [TASK_LIST_FILTER] 应用状态过滤 - 模块: API, 过滤条件: status={status}")
        # 如果指定了 task_type (如 code_generation)，可以在 config 中查找或扩展 Task 字段
        # 目前简单处理: 如果 task_type 不是 ai_agent_scan，可能无法通过 Task.task_type 过滤准确
        # 但 Task.task_type 记录的是 "ai_agent_scan"。
        # 实际 Agent 的具体类型 (code/vuln) 可能存在 config 中。
        
        total = await query.count()
        logger.info(f"[AI_AGENT] [TASK_LIST_COUNT] 查询结果 - 模块: API, 总数: {total}")
        
        tasks = await query \
            .order_by("-created_at") \
            .offset((page - 1) * page_size) \
            .limit(page_size)
        
        task_list = []
        for task in tasks:
            task_list.append({
                "task_id": str(task.id),
                "task_type": task.task_type,
                "target": task.target,
                "status": task.status,
                "progress": task.progress,
                "created_at": task.created_at,
                "updated_at": task.updated_at
            })
        
        logger.info(f"[AI_AGENT] [TASK_LIST_RESULT] 返回任务列表 - 模块: API, 任务数: {len(task_list)}, 页码: {page}")
        
        response_data = {
            "tasks": task_list,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size
        }
        
        logger.info(f"[AI_AGENT] [TASK_LIST_RETURN] 返回响应数据 - 模块: API, 数据: {response_data}")
        
        return APIResponse(
            code=200,
            message="获取成功",
            data=response_data
        )
        
    except Exception as e:
        logger.error(f"[AI_AGENT] [ERROR] 获取Agent任务列表失败 - 模块: API, 错误: {str(e)}, 堆栈: {type(e).__name__}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/tasks/{task_id}/cancel", response_model=APIResponse)
async def cancel_agent_task(task_id: str):
    """
    取消Agent任务
    """
    try:
        logger.info(f"[AI_AGENT] [TASK_CANCEL_START] 取消Agent任务 - 模块: API, 变量: task_id, 值: {task_id}")
        
        # 尝试转换为int
        db_task_id = None
        if task_id.isdigit():
            db_task_id = int(task_id)
            logger.info(f"[AI_AGENT] [TASK_CANCEL_CONVERT] Task ID转换 - 模块: API, 变量: task_id, 旧值: {task_id}, 新值: {db_task_id}")
        
        # 数据库状态更新 & 任务终止
        if db_task_id:
            logger.info(f"[AI_AGENT] [TASK_CANCEL_DB] 从数据库获取任务 - 模块: API, 变量: db_task_id, 状态: querying")
            task = await Task.get_or_none(id=db_task_id)
            if task:
                logger.info(f"[AI_AGENT] [TASK_CANCEL_FOUND] 找到任务 - 模块: API, 变量: task_id, 当前状态: {task.status}")
                # 调用任务执行器取消任务
                if task_executor:
                    logger.info(f"[AI_AGENT] [TASK_CANCEL_STOP] 通知执行器停止任务 - 模块: API, 变量: task_id, 状态: stopping")
                    await task_executor.cancel_task(db_task_id)
                
                # 确保数据库状态更新
                if task.status == "running" or task.status == "pending":
                    task.status = "cancelled"
                    await task.save()
                
                logger.info(f"[AI_AGENT] [TASK_CANCEL_SUCCESS] 任务已取消 - 模块: API, 变量: task_id, 新状态: {task.status}")
                
                return APIResponse(
                    code=200,
                    message="任务已取消",
                    data={
                        "task_id": str(task.id),
                        "status": "cancelled"
                    }
                )

        logger.error(f"[AI_AGENT] [TASK_CANCEL_NOT_FOUND] 任务不存在 - 模块: API, 变量: task_id, 值: {task_id}, 状态: error")
        raise HTTPException(status_code=404, detail="任务不存在")
        
    except HTTPException as http_ex:
        logger.error(f"[AI_AGENT] [ERROR] 取消Agent任务HTTP异常 - 模块: API, 错误: {str(http_ex)}")
        raise
    except Exception as e:
        logger.error(f"[AI_AGENT] [ERROR] 取消Agent任务失败 - 模块: API, 错误: {str(e)}, 堆栈: {type(e).__name__}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/tasks/{task_id}", response_model=APIResponse)
async def delete_agent_task(task_id: str):
    """
    删除Agent任务
    
    删除任务记录。如果任务正在运行，会先取消任务。
    """
    try:
        logger.info(f"[AI_AGENT] [TASK_DELETE_START] 删除Agent任务 - 模块: API, 变量: task_id, 值: {task_id}")
        
        # 尝试转换为int
        db_task_id = None
        if task_id.isdigit():
            db_task_id = int(task_id)
            logger.info(f"[AI_AGENT] [TASK_DELETE_CONVERT] Task ID转换 - 模块: API, 变量: task_id, 旧值: {task_id}, 新值: {db_task_id}")
        
        # 删除 Unified Task
        if db_task_id:
            logger.info(f"[AI_AGENT] [TASK_DELETE_DB] 从数据库获取任务 - 模块: API, 变量: db_task_id, 状态: querying")
            task = await Task.get_or_none(id=db_task_id)
            if task:
                logger.info(f"[AI_AGENT] [TASK_DELETE_FOUND] 找到任务 - 模块: API, 变量: task_id, 当前状态: {task.status}")
                # 如果正在运行，先取消
                if task.status == "running" or task.status == "pending":
                    if task_executor:
                        logger.info(f"[AI_AGENT] [TASK_DELETE_STOP] 任务正在运行，先取消 - 模块: API, 变量: task_id, 状态: cancelling")
                        await task_executor.cancel_task(db_task_id)
                
                # 删除数据库记录
                await task.delete()
                
                logger.info(f"[AI_AGENT] [TASK_DELETE_SUCCESS] 任务已删除 - 模块: API, 变量: task_id, 状态: deleted")
                
                return APIResponse(
                    code=200,
                    message="任务已删除",
                    data={
                        "task_id": str(db_task_id),
                        "status": "deleted"
                    }
                )

        logger.error(f"[AI_AGENT] [TASK_DELETE_NOT_FOUND] 任务不存在 - 模块: API, 变量: task_id, 值: {task_id}, 状态: error")
        raise HTTPException(status_code=404, detail="任务不存在")

    except HTTPException as http_ex:
        logger.error(f"[AI_AGENT] [ERROR] 删除Agent任务HTTP异常 - 模块: API, 错误: {str(http_ex)}")
        raise
    except Exception as e:
        logger.error(f"[AI_AGENT] [ERROR] 删除Agent任务失败 - 模块: API, 错误: {str(e)}, 堆栈: {type(e).__name__}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tools", response_model=APIResponse)
async def list_tools(category: Optional[str] = None) -> APIResponse:
    """
    获取可用工具列表
    
    列出所有已注册的扫描工具。
    
    Args:
        category: 按分类过滤(plugin/poc/general)
        
    Returns:
        APIResponse: 工具列表
        
    Examples:
        >>> 获取所有插件
        >>> GET /ai_agents/tools?category=plugin
    """
    try:
        from ..tools.registry import registry
        
        tools = registry.list_tools(category=category)
        
        return APIResponse(
            code=200,
            message="获取成功",
            data={
                "total": len(tools),
                "tools": tools
            }
        )
        
    except Exception as e:
        logger.error(f"❌ 获取工具列表失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/config", response_model=APIResponse)
async def get_config() -> APIResponse:
    """
    获取Agent配置
    
    返回当前的Agent配置参数。
    
    Returns:
        APIResponse: 配置信息
    """
    return APIResponse(
        code=200,
        message="获取成功",
        data={
            "max_execution_time": agent_config.MAX_EXECUTION_TIME,
            "max_retries": agent_config.MAX_RETRIES,
            "max_concurrent_tools": agent_config.MAX_CONCURRENT_TOOLS,
            "tool_timeout": agent_config.TOOL_TIMEOUT,
            "enable_llm_planning": agent_config.ENABLE_LLM_PLANNING,
            "default_scan_tasks": agent_config.DEFAULT_SCAN_TASKS,
            "enable_memory": agent_config.ENABLE_MEMORY,
            "enable_kb_integration": agent_config.ENABLE_KB_INTEGRATION
        }
    )


@router.post("/config", response_model=APIResponse)
async def update_config(
    max_execution_time: Optional[int] = None,
    max_retries: Optional[int] = None,
    max_concurrent_tools: Optional[int] = None,
    tool_timeout: Optional[int] = None,
    enable_llm_planning: Optional[bool] = None,
    enable_memory: Optional[bool] = None,
    enable_kb_integration: Optional[bool] = None
) -> APIResponse:
    """
    更新Agent配置
    
    动态更新Agent的配置参数。
    
    Returns:
        APIResponse: 更新后的配置
    """
    if max_execution_time is not None:
        agent_config.MAX_EXECUTION_TIME = max_execution_time
    if max_retries is not None:
        agent_config.MAX_RETRIES = max_retries
    if max_concurrent_tools is not None:
        agent_config.MAX_CONCURRENT_TOOLS = max_concurrent_tools
    if tool_timeout is not None:
        agent_config.TOOL_TIMEOUT = tool_timeout
    if enable_llm_planning is not None:
        agent_config.ENABLE_LLM_PLANNING = enable_llm_planning
    if enable_memory is not None:
        agent_config.ENABLE_MEMORY = enable_memory
    if enable_kb_integration is not None:
        agent_config.ENABLE_KB_INTEGRATION = enable_kb_integration
    
    logger.info("✅ Agent配置已更新")
    
    return APIResponse(
        code=200,
        message="配置更新成功",
        data={
            "max_execution_time": agent_config.MAX_EXECUTION_TIME,
            "max_retries": agent_config.MAX_RETRIES,
            "max_concurrent_tools": agent_config.MAX_CONCURRENT_TOOLS,
            "tool_timeout": agent_config.TOOL_TIMEOUT,
            "enable_llm_planning": agent_config.ENABLE_LLM_PLANNING,
            "default_scan_tasks": agent_config.DEFAULT_SCAN_TASKS,
            "enable_memory": agent_config.ENABLE_MEMORY,
            "enable_kb_integration": agent_config.ENABLE_KB_INTEGRATION
        }
    )


@router.get("/resources/usage", response_model=APIResponse)
async def get_resource_usage():
    """
    获取资源使用情况
    
    Returns:
        APIResponse: 资源使用情况
    """
    try:
        from ..utils.resource_limiter import get_default_limiter
        
        limiter = get_default_limiter()
        usage = await limiter.get_current_usage()
        
        return APIResponse(
            code=200,
            message="获取成功",
            data=usage.to_dict()
        )
        
    except Exception as e:
        logger.error(f"❌ 获取资源使用情况失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/resources/statistics", response_model=APIResponse)
async def get_resource_statistics():
    """
    获取资源统计信息
    
    Returns:
        APIResponse: 资源统计信息
    """
    try:
        from ..utils.resource_limiter import get_default_limiter
        
        limiter = get_default_limiter()
        stats = limiter.get_statistics()
        
        return APIResponse(
            code=200,
            message="获取成功",
            data=stats
        )
        
    except Exception as e:
        logger.error(f"❌ 获取资源统计信息失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ============ 从 agent.py 合并的端点 ============

class HeartbeatRequest(BaseModel):
    """插件心跳请求模型"""
    timestamp: float


class FinishRequest(BaseModel):
    """插件完成请求模型"""
    exitCode: int
    stdout: str
    stderr: str


@router.put("/tasks/{task_id}/plugin/{plugin_id}/heartbeat", response_model=APIResponse)
async def plugin_heartbeat(task_id: int, plugin_id: str, request: HeartbeatRequest):
    """
    插件心跳上报
    
    Args:
        task_id: 任务ID
        plugin_id: 插件ID
        request: 心跳请求
        
    Returns:
        APIResponse: 心跳处理结果
    """
    try:
        task_executor.update_heartbeat(task_id)
        return APIResponse(code=200, message="Heartbeat received")
    except Exception as e:
        logger.warning(f"Heartbeat update failed: {e}")
        return APIResponse(code=500, message="Heartbeat failed")


@router.post("/tasks/{task_id}/plugin/{plugin_id}/finish", response_model=APIResponse)
async def plugin_finish(task_id: int, plugin_id: str, request: FinishRequest):
    """
    插件执行完成回调
    
    Args:
        task_id: 任务ID
        plugin_id: 插件ID
        request: 完成请求
        
    Returns:
        APIResponse: 完成处理结果
    """
    try:
        logger.info(f"[插件完成] 收到完成回调 | 任务ID: {task_id} | 插件: {plugin_id} | 退出码: {request.exitCode}")
        task = await Task.get_or_none(id=task_id)
        if not task:
            logger.warning(f"[插件完成] 任务不存在 | 任务ID: {task_id}")
            return APIResponse(code=404, message="Task not found")
        
        if request.exitCode == 0:
            logger.info(f"[插件完成] 执行成功 | 任务ID: {task_id} | 插件: {plugin_id}")
            task.status = 'completed'
            task.progress = 100
            try:
                task.result = request.stdout
            except:
                task.result = json.dumps({"raw_output": request.stdout})
        else:
            logger.warning(f"[插件完成] 执行失败 | 任务ID: {task_id} | 插件: {plugin_id} | 退出码: {request.exitCode} | 错误: {request.stderr}")
            task.status = 'failed'
            task.result = json.dumps({"error": request.stderr or "Unknown error", "exit_code": request.exitCode})
            
        await task.save()
        logger.info(f"[插件完成] 任务状态已更新 | 任务ID: {task_id} | 状态: {task.status}")
        return APIResponse(code=200, message="Finish processed")
    except Exception as e:
        logger.error(f"Finish callback failed: {e}")
        return APIResponse(code=500, message=f"Finish callback failed: {str(e)}")


@router.get("/tasks/{task_id}/logs", response_model=APIResponse)
async def get_task_logs(task_id: int, tail: int = 500, keyword: str = ""):
    """
    获取任务的插件日志
    
    Args:
        task_id: 任务ID
        tail: 返回最后N行日志
        keyword: 关键词过滤
        
    Returns:
        APIResponse: 日志内容
    """
    from pathlib import Path
    
    try:
        task = await Task.get_or_none(id=task_id)
        if not task:
            return APIResponse(code=404, message="Task not found")
        
        log_date = task.created_at.strftime("%Y-%m-%d")
        log_file = Path("logs") / "plugins" / log_date / f"{task_id}.log"
        
        if not log_file.exists():
            files = list(Path("logs").glob(f"plugins/*/{task_id}.log"))
            if files:
                log_file = files[0]
            else:
                return APIResponse(code=200, message="暂无日志", data="")

        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            if keyword:
                lines = [l for l in lines if keyword.lower() in l.lower()]
                
            if len(lines) > tail:
                lines = lines[-tail:]
                
            return APIResponse(code=200, message="获取成功", data="".join(lines))
        except Exception as e:
            return APIResponse(code=500, message=f"读取日志失败: {e}")
            
    except Exception as e:
        return APIResponse(code=500, message=f"获取日志失败: {str(e)}")


@router.get("/tasks/frozen", response_model=APIResponse)
async def get_frozen_tasks():
    """
    获取冻结任务列表
    
    冻结定义: 运行中 且 运行时长 > 80% 阈值
        
    Returns:
        APIResponse: 冻结任务列表
    """
    import datetime
    
    try:
        running_tasks = await Task.filter(status='running').all()
        frozen_tasks = []
        now = datetime.datetime.now(datetime.timezone.utc)
        
        TIMEOUTS = {
            'scan_port': 15,
            'scan_waf': 5,
            'awvs_scan': 60,
            'default': 30
        }
        
        for task in running_tasks:
            if not task.created_at: continue
            
            created_at = task.created_at
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=datetime.timezone.utc)
                
            duration_minutes = (now - created_at).total_seconds() / 60
            threshold = TIMEOUTS.get(task.task_type, TIMEOUTS['default'])
            
            if duration_minutes > (threshold * 0.8):
                frozen_tasks.append({
                    "id": task.id,
                    "task_name": task.task_name,
                    "task_type": task.task_type,
                    "duration": f"{duration_minutes:.1f}",
                    "threshold": threshold,
                    "progress": task.progress
                })
                
        return APIResponse(code=200, message="获取成功", data=frozen_tasks)
    except Exception as e:
        logger.error(f"Get frozen tasks error: {e}")
        return APIResponse(code=500, message=f"获取冻结任务失败: {str(e)}")


# ============ POC API 端点 ============

class POCSearchRequest(BaseModel):
    """POC搜索请求模型"""
    cve_id: str


class POCExecuteRequest(BaseModel):
    """POC执行请求模型"""
    target: str
    cve_id: Optional[str] = None
    poc_name: Optional[str] = None
    timeout: Optional[float] = 300.0


class POCBatchExecuteRequest(BaseModel):
    """批量POC执行请求模型"""
    targets: List[str]
    cve_ids: List[str]


@router.post("/poc/search", response_model=APIResponse)
async def search_poc(request: POCSearchRequest):
    """
    搜索POC
    
    通过CVE编号搜索可用的POC。
    
    Args:
        request: 包含CVE编号的搜索请求
        
    Returns:
        APIResponse: POC搜索结果
    """
    try:
        logger.info(f"[POC_SEARCH] 搜索POC - CVE: {request.cve_id}")
        
        from backend.ai_agents.poc_system.poc_manager import poc_manager
        
        poc_infos = await poc_manager.sync_from_seebug(keyword=request.cve_id, limit=10)
        
        data = {
            "cve_id": request.cve_id,
            "count": len(poc_infos),
            "results": [
                {
                    "title": poc.poc_name,
                    "description": poc.description,
                    "severity": poc.severity,
                    "poc_id": poc.poc_id,
                    "source": poc.source
                }
                for poc in poc_infos
            ]
        }
        
        logger.info(f"[POC_SEARCH] 搜索完成 - 找到 {len(poc_infos)} 个POC")
        return APIResponse(code=200, message=f"找到 {len(poc_infos)} 个POC", data=data)
        
    except Exception as e:
        logger.error(f"[POC_SEARCH_ERROR] 搜索POC失败 - 错误: {str(e)}")
        return APIResponse(code=500, message=f"搜索POC失败: {str(e)}")


@router.post("/poc/execute", response_model=APIResponse)
async def execute_poc(request: POCExecuteRequest):
    """
    执行POC检测
    
    执行单个POC漏洞检测。
    
    Args:
        request: 包含目标、CVE编号或POC名称的执行请求
        
    Returns:
        APIResponse: POC执行结果
    """
    try:
        logger.info(f"[POC_EXECUTE] 执行POC - 目标: {request.target}, CVE: {request.cve_id}, POC: {request.poc_name}")
        
        from backend.ai_agents.poc_system.poc_manager import poc_manager
        from backend.ai_agents.poc_system.verification_engine import verification_engine
        
        poc_id = request.poc_name or request.cve_id
        if not poc_id:
            return APIResponse(code=400, message="必须提供 cve_id 或 poc_name")
        
        verification_task = await poc_manager.create_verification_task(
            poc_id=poc_id,
            target=request.target
        )
        
        result = await verification_engine.execute_verification_task(verification_task)
        
        data = {
            "cve_id": request.cve_id,
            "target": result.target,
            "success": result.error is None,
            "vulnerable": result.vulnerable,
            "poc_name": result.poc_name,
            "execution_time": result.execution_time,
            "error": result.error,
            "message": result.message
        }
        
        message = "POC执行完成" if result.vulnerable else "POC执行完成，未发现漏洞"
        logger.info(f"[POC_EXECUTE] 执行完成 - 成功: {result.error is None}, 有漏洞: {result.vulnerable}")
        
        return APIResponse(code=200, message=message, data=data)
        
    except Exception as e:
        logger.error(f"[POC_EXECUTE_ERROR] 执行POC失败 - 错误: {str(e)}")
        return APIResponse(code=500, message=f"执行POC失败: {str(e)}")


@router.post("/poc/batch-execute", response_model=APIResponse)
async def batch_execute_poc(request: POCBatchExecuteRequest):
    """
    批量执行POC检测
    
    对多个目标执行多个CVE的POC检测。
    
    Args:
        request: 包含目标列表和CVE编号列表的批量执行请求
        
    Returns:
        APIResponse: 批量执行结果
    """
    try:
        logger.info(f"[POC_BATCH] 批量执行POC - 目标数: {len(request.targets)}, CVE数: {len(request.cve_ids)}")
        
        from backend.ai_agents.poc_system.poc_manager import poc_manager
        from backend.ai_agents.poc_system.verification_engine import verification_engine
        
        verification_tasks = []
        for target in request.targets:
            for cve_id in request.cve_ids:
                try:
                    task = await poc_manager.create_verification_task(
                        poc_id=cve_id,
                        target=target
                    )
                    verification_tasks.append(task)
                except Exception as e:
                    logger.warning(f"[POC_BATCH] 创建任务失败: {cve_id} -> {target}, 错误: {str(e)}")
        
        results = await verification_engine.execute_batch_verification(verification_tasks)
        
        data = {
            "total": len(results),
            "successful": sum(1 for r in results if r.error is None),
            "vulnerable": sum(1 for r in results if r.vulnerable),
            "results": [
                {
                    "cve_id": r.poc_id,
                    "target": r.target,
                    "success": r.error is None,
                    "vulnerable": r.vulnerable,
                    "execution_time": r.execution_time
                }
                for r in results
            ]
        }
        
        logger.info(f"[POC_BATCH] 批量执行完成 - 总任务: {len(results)}")
        return APIResponse(code=200, message=f"批量POC执行完成: {len(results)} 个任务", data=data)
        
    except Exception as e:
        logger.error(f"[POC_BATCH_ERROR] 批量执行POC失败 - 错误: {str(e)}")
        return APIResponse(code=500, message=f"批量执行POC失败: {str(e)}")


# ============ 工作流指标 API 端点 ============

@router.get("/workflow/metrics", response_model=APIResponse)
async def get_execution_metrics(task_id: Optional[str] = None):
    """
    获取工作流执行指标
    
    获取节点执行时间、重试次数、跳过状态等指标。
    
    Args:
        task_id: 可选的任务ID，用于过滤特定任务的指标
        
    Returns:
        APIResponse: 执行指标数据
    """
    try:
        logger.info(f"[WORKFLOW_METRICS] 获取执行指标 - 任务ID: {task_id}")
        
        from backend.api.workflow_schemas import get_execution_optimizer
        
        optimizer = get_execution_optimizer()
        summary = optimizer.get_execution_summary(task_id)
        metrics = optimizer.get_execution_metrics(task_id)
        
        data = {
            "summary": summary,
            "metrics": [
                {
                    "node_name": m.node_name,
                    "task_id": m.task_id,
                    "duration": m.duration,
                    "success": m.success,
                    "retries": m.retries,
                    "skipped": m.skipped,
                    "error": m.error,
                    "timestamp": m.timestamp
                }
                for m in metrics
            ]
        }
        
        logger.info(f"[WORKFLOW_METRICS] 获取完成 - 指标数: {len(metrics)}")
        return APIResponse(code=200, message="获取执行指标成功", data=data)
        
    except Exception as e:
        logger.error(f"[WORKFLOW_METRICS_ERROR] 获取执行指标失败 - 错误: {str(e)}")
        return APIResponse(code=500, message=f"获取执行指标失败: {str(e)}")


# ============ 报告生成 API 端点 ============

class ReportGenerateRequest(BaseModel):
    """报告生成请求模型"""
    task_id: int
    format: str = Field(default="json", description="报告格式: json, html, pdf")
    include_ai_analysis: bool = Field(default=True, description="是否包含AI分析结果")


class AIAnalysisRequest(BaseModel):
    """AI分析请求模型"""
    task_id: int


@router.post("/reports/generate", response_model=APIResponse)
async def generate_report(request: ReportGenerateRequest):
    """
    生成扫描报告
    
    根据任务ID生成指定格式的报告，支持JSON、HTML、PDF格式。
    报告包含完整的子图/节点执行信息和AI分析结果。
    
    Args:
        request: 报告生成请求
        
    Returns:
        APIResponse: 报告生成结果
    """
    try:
        logger.info(f"[REPORT_GENERATE] 生成报告 - 任务ID: {request.task_id}, 格式: {request.format}")
        
        from ..analyzers.enhanced_report_gen import EnhancedReportGenerator, ReportFormat
        
        task = await Task.get_or_none(id=request.task_id)
        if not task:
            return APIResponse(code=404, message="任务不存在")
        
        from ..core.state import AgentState
        state = AgentState(target=task.target, task_id=str(task.id))
        
        if task.config:
            try:
                config = json.loads(task.config) if isinstance(task.config, str) else task.config
                state.tool_results = config.get("tool_results", {})
                state.vulnerabilities = config.get("vulnerabilities", [])
                state.target_context = config.get("target_context", {})
                state.execution_history = config.get("execution_history", [])
            except:
                pass
        
        if task.result:
            try:
                result = json.loads(task.result) if isinstance(task.result, str) else task.result
                if isinstance(result, dict):
                    state.tool_results.update(result.get("tool_results", {}))
                    if result.get("vulnerabilities"):
                        state.vulnerabilities = result["vulnerabilities"]
            except:
                pass
        
        generator = EnhancedReportGenerator(auto_ai_analysis=request.include_ai_analysis)
        report_data = generator.generate_from_state_sync(state, task_name=task.task_name)
        
        format_map = {
            "json": ReportFormat.JSON,
            "html": ReportFormat.HTML,
            "pdf": ReportFormat.PDF
        }
        report_format = format_map.get(request.format.lower(), ReportFormat.JSON)
        
        content = ""
        if report_format == ReportFormat.JSON:
            content = generator.generate_json_report(report_data)
        elif report_format == ReportFormat.HTML:
            content = generator.generate_html_report(report_data)
        else:
            content = generator.generate_json_report(report_data)
        
        from backend.models import Report
        report = await Report.create(
            task_id=task.id,
            report_name=f"{task.task_name}_report_{request.format}",
            report_type=request.format,
            content=json.loads(content) if request.format == "json" else {"raw": content}
        )
        
        logger.info(f"[REPORT_GENERATE] 报告生成完成 - 报告ID: {report.id}")
        
        return APIResponse(
            code=200,
            message="报告生成成功",
            data={
                "report_id": report.id,
                "task_id": task.id,
                "format": request.format,
                "content": json.loads(content) if request.format == "json" else None,
                "ai_analysis_included": request.include_ai_analysis
            }
        )
        
    except Exception as e:
        logger.error(f"[REPORT_GENERATE_ERROR] 生成报告失败 - 错误: {str(e)}")
        return APIResponse(code=500, message=f"生成报告失败: {str(e)}")


@router.get("/reports", response_model=APIResponse)
async def list_reports(
    task_id: Optional[int] = None,
    page: int = 1,
    page_size: int = 20
):
    """
    获取报告列表
    
    获取所有报告或指定任务的报告列表。
    
    Args:
        task_id: 可选的任务ID，用于过滤特定任务的报告
        page: 页码
        page_size: 每页数量
        
    Returns:
        APIResponse: 报告列表
    """
    try:
        from backend.models import Report
        
        query = Report.all()
        if task_id:
            query = query.filter(task_id=task_id)
        
        total = await query.count()
        reports = await query.order_by("-created_at").offset((page - 1) * page_size).limit(page_size)
        
        report_list = []
        for report in reports:
            report_list.append({
                "id": report.id,
                "task_id": report.task_id,
                "report_name": report.report_name,
                "report_type": report.report_type,
                "created_at": report.created_at,
                "updated_at": report.updated_at
            })
        
        return APIResponse(
            code=200,
            message="获取成功",
            data={
                "reports": report_list,
                "total": total,
                "page": page,
                "page_size": page_size
            }
        )
        
    except Exception as e:
        logger.error(f"[REPORT_LIST_ERROR] 获取报告列表失败 - 错误: {str(e)}")
        return APIResponse(code=500, message=f"获取报告列表失败: {str(e)}")


@router.get("/reports/{report_id}", response_model=APIResponse)
async def get_report(report_id: int):
    """
    获取报告详情
    
    根据报告ID获取完整的报告内容。
    
    Args:
        report_id: 报告ID
        
    Returns:
        APIResponse: 报告详情
    """
    try:
        from backend.models import Report
        
        report = await Report.get_or_none(id=report_id)
        if not report:
            return APIResponse(code=404, message="报告不存在")
        
        return APIResponse(
            code=200,
            message="获取成功",
            data={
                "id": report.id,
                "task_id": report.task_id,
                "report_name": report.report_name,
                "report_type": report.report_type,
                "content": report.content,
                "created_at": report.created_at,
                "updated_at": report.updated_at
            }
        )
        
    except Exception as e:
        logger.error(f"[REPORT_DETAIL_ERROR] 获取报告详情失败 - 错误: {str(e)}")
        return APIResponse(code=500, message=f"获取报告详情失败: {str(e)}")


@router.delete("/reports/{report_id}", response_model=APIResponse)
async def delete_report(report_id: int):
    """
    删除报告
    
    根据报告ID删除报告。
    
    Args:
        report_id: 报告ID
        
    Returns:
        APIResponse: 删除结果
    """
    try:
        from backend.models import Report
        
        report = await Report.get_or_none(id=report_id)
        if not report:
            return APIResponse(code=404, message="报告不存在")
        
        await report.delete()
        
        logger.info(f"[REPORT_DELETE] 报告已删除 - 报告ID: {report_id}")
        return APIResponse(code=200, message="报告已删除")
        
    except Exception as e:
        logger.error(f"[REPORT_DELETE_ERROR] 删除报告失败 - 错误: {str(e)}")
        return APIResponse(code=500, message=f"删除报告失败: {str(e)}")


@router.get("/tasks/{task_id}/ai-analysis", response_model=APIResponse)
async def get_ai_analysis(task_id: int):
    """
    获取AI分析结果
    
    根据任务ID获取AI分析结果，包括漏洞成因、利用风险、修复优先级、业务影响等。
    
    Args:
        task_id: 任务ID
        
    Returns:
        APIResponse: AI分析结果
    """
    try:
        logger.info(f"[AI_ANALYSIS] 获取AI分析结果 - 任务ID: {task_id}")
        
        from ..analyzers.ai_analyzer import AIAnalyzer
        
        task = await Task.get_or_none(id=task_id)
        if not task:
            return APIResponse(code=404, message="任务不存在")
        
        from ..core.state import AgentState
        state = AgentState(target=task.target, task_id=str(task.id))
        
        if task.config:
            try:
                config = json.loads(task.config) if isinstance(task.config, str) else task.config
                state.vulnerabilities = config.get("vulnerabilities", [])
                state.tool_results = config.get("tool_results", {})
                state.target_context = config.get("target_context", {})
            except:
                pass
        
        if task.result:
            try:
                result = json.loads(task.result) if isinstance(task.result, str) else task.result
                if isinstance(result, dict):
                    if result.get("vulnerabilities"):
                        state.vulnerabilities = result["vulnerabilities"]
                    if result.get("tool_results"):
                        state.tool_results.update(result["tool_results"])
            except:
                pass
        
        ai_analyzer = AIAnalyzer()
        ai_result = ai_analyzer._analyze_with_rules(
            state.vulnerabilities,
            state.tool_results,
            state.target_context
        )
        
        logger.info(f"[AI_ANALYSIS] AI分析完成 - 任务ID: {task_id}")
        
        return APIResponse(
            code=200,
            message="AI分析完成",
            data={
                "task_id": task_id,
                "ai_analysis": ai_result.to_dict()
            }
        )
        
    except Exception as e:
        logger.error(f"[AI_ANALYSIS_ERROR] AI分析失败 - 错误: {str(e)}")
        return APIResponse(code=500, message=f"AI分析失败: {str(e)}")


@router.get("/tasks/{task_id}/execution-details", response_model=APIResponse)
async def get_execution_details(task_id: int):
    """
    获取任务执行详情
    
    获取任务的子图和节点执行详情，包括执行时间、状态、结果等。
    使用标准化工作流数据格式返回。
    
    Args:
        task_id: 任务ID
        
    Returns:
        APIResponse: 标准化的执行详情数据
    """
    try:
        logger.info(f"[EXEC_DETAILS] 获取执行详情 - 任务ID: {task_id}")
        
        task = await Task.get_or_none(id=task_id)
        if not task:
            return APIResponse(code=404, message="任务不存在")
        
        from backend.api.workflow_schemas import WorkflowDataConverter
        
        execution_history = []
        graph_flow = None
        tool_results = {}
        vulnerabilities = []
        start_time = None
        end_time = None
        duration = None
        
        if task.config:
            try:
                config = json.loads(task.config) if isinstance(task.config, str) else task.config
                execution_history = config.get("execution_history", [])
                graph_flow = config.get("graph_flow")
                tool_results = config.get("tool_results", {})
                vulnerabilities = config.get("vulnerabilities", [])
                start_time = config.get("start_time")
                end_time = config.get("end_time")
            except Exception as e:
                logger.warning(f"[EXEC_DETAILS] 解析任务配置失败: {e}")
        
        if task.result:
            try:
                result = json.loads(task.result) if isinstance(task.result, str) else task.result
                if isinstance(result, dict):
                    if result.get("execution_history"):
                        execution_history = result["execution_history"]
                    if result.get("graph_flow"):
                        graph_flow = result["graph_flow"]
                    if result.get("tool_results"):
                        tool_results.update(result["tool_results"])
                    if result.get("vulnerabilities"):
                        vulnerabilities = result["vulnerabilities"]
                    if result.get("start_time"):
                        start_time = result["start_time"]
                    if result.get("end_time"):
                        end_time = result["end_time"]
            except Exception as e:
                logger.warning(f"[EXEC_DETAILS] 解析任务结果失败: {e}")
        
        normalized_history = []
        for idx, record in enumerate(execution_history):
            normalized = WorkflowDataConverter.normalize_execution_record(record, idx)
            normalized_history.append(normalized)
        
        normalized_graph_flow = None
        if graph_flow:
            normalized_graph_flow = WorkflowDataConverter.normalize_graph_flow(graph_flow)
        
        if start_time:
            if end_time:
                duration = end_time - start_time
            else:
                import time
                duration = time.time() - start_time
        
        workflow_data = {
            "task_id": str(task_id),
            "target": task.target,
            "status": WorkflowDataConverter.normalize_status(task.status),
            "progress": task.progress or 0,
            "start_time": start_time,
            "end_time": end_time,
            "duration": duration,
            "execution_history": normalized_history,
            "graph_flow": normalized_graph_flow,
            "vulnerabilities": vulnerabilities,
            "tool_results": tool_results,
            "created_at": task.created_at.strftime("%Y-%m-%dT%H:%M:%SZ") if task.created_at else None,
            "updated_at": task.updated_at.strftime("%Y-%m-%dT%H:%M:%SZ") if task.updated_at else None
        }
        
        logger.info(f"[EXEC_DETAILS] 获取成功 - 任务ID: {task_id}, 执行步骤: {len(normalized_history)}")
        
        return APIResponse(
            code=200,
            message="获取成功",
            data=workflow_data
        )
        
    except Exception as e:
        logger.error(f"[EXEC_DETAILS_ERROR] 获取执行详情失败 - 错误: {str(e)}", exc_info=True)
        return APIResponse(code=500, message=f"获取执行详情失败: {str(e)}")
