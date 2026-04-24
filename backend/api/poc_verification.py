"""
POC 验证 API 路由

提供 POC 验证相关的核心 API 接口:
- 创建/查询/控制验证任务
- 生成验证报告
- 系统健康检查

注意: POC 注册表和同步功能请使用 /poc 或 /seebug API

API 端点:
    POST /poc/verification/tasks          - 创建 POC 验证任务
    POST /poc/verification/tasks/batch    - 批量创建验证任务
    GET  /poc/verification/tasks          - 列出验证任务
    GET  /poc/verification/tasks/{task_id} - 获取任务详情
    POST /poc/verification/tasks/{task_id}/pause   - 暂停任务
    POST /poc/verification/tasks/{task_id}/resume  - 继续任务
    POST /poc/verification/tasks/{task_id}/cancel  - 取消任务
    POST /poc/verification/tasks/{task_id}/report  - 生成报告
    GET  /poc/verification/health         - 健康检查

响应格式:
    所有接口返回统一格式:
    {
        "code": 200,           # 状态码
        "data": {...},         # 响应数据
        "message": "操作成功"   # 响应消息
    }
"""
import json
import logging
from typing import Dict, Any, List, Optional
from uuid import UUID

from fastapi import APIRouter, Query, HTTPException
from pydantic import BaseModel, Field

from backend.models import POCVerificationTask, POCVerificationResult, Report, Task
from backend.ai_agents.poc_system import (
    poc_manager,
    verification_engine,
    result_analyzer,
    report_generator
)
from backend.config import settings
from backend.api.common import APIResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/poc/verification", tags=["POC验证"])


class CreateVerificationTaskRequest(BaseModel):
    """创建验证任务请求模型"""
    poc_id: str = Field(..., description="POC ID")
    target: str = Field(..., description="验证目标URL")
    priority: int = Field(default=5, ge=1, le=10, description="优先级(1-10)")
    task_id: Optional[str] = Field(None, description="关联的任务ID")


class CreateBatchVerificationTaskRequest(BaseModel):
    """批量创建验证任务请求模型"""
    poc_tasks: List[Dict[str, Any]] = Field(..., description="POC任务列表")
    target: str = Field(..., description="验证目标URL")
    task_id: Optional[str] = Field(None, description="关联的任务ID")


def _build_task_response(task: POCVerificationTask, result: Optional[POCVerificationResult] = None) -> Dict[str, Any]:
    return {
        "task_id": str(task.id),
        "poc_name": task.poc_name,
        "poc_id": task.poc_id,
        "target": task.target,
        "status": task.status,
        "progress": task.progress,
        "priority": task.priority,
        "created_at": task.created_at.isoformat(),
        "updated_at": task.updated_at.isoformat()
    }


def _build_result_response(result: POCVerificationResult) -> Dict[str, Any]:
    return {
        "result_id": result.id,
        "poc_name": result.poc_name,
        "poc_id": result.poc_id,
        "target": result.target,
        "vulnerable": result.vulnerable,
        "message": result.message,
        "output": result.output,
        "error": result.error,
        "execution_time": result.execution_time,
        "confidence": result.confidence,
        "severity": result.severity,
        "cvss_score": result.cvss_score,
        "created_at": result.created_at.isoformat()
    }


@router.post("/tasks", response_model=APIResponse)
async def create_verification_task(request: CreateVerificationTaskRequest):
    """
    创建 POC 验证任务
    
    创建单个 POC 验证任务并立即执行，返回任务信息和验证结果。
    
    请求参数:
        - poc_id (str, 必填): POC 标识符
        - target (str, 必填): 验证目标 URL，必须以 http:// 或 https:// 开头
        - priority (int, 可选): 优先级，范围 1-10，默认为 5
        - task_id (str, 可选): 关联的任务 ID
    
    请求示例:
        POST /api/poc/verification/tasks
        {
            "poc_id": "CVE-2024-1234",
            "target": "https://example.com",
            "priority": 8,
            "task_id": "task-uuid-123"
        }
    
    响应示例:
        {
            "code": 200,
            "message": "POC 验证任务创建成功",
            "data": {
                "task": {
                    "task_id": "uuid-123",
                    "poc_name": "Apache RCE",
                    "poc_id": "CVE-2024-1234",
                    "target": "https://example.com",
                    "status": "completed",
                    "progress": 100
                },
                "result": {
                    "result_id": "result-uuid",
                    "vulnerable": true,
                    "message": "目标存在漏洞",
                    "confidence": 0.95,
                    "severity": "high",
                    "cvss_score": 9.8,
                    "execution_time": 2.5
                },
                "analysis": {
                    "is_false_positive": false,
                    "risk_level": "high",
                    "recommendations": ["立即修复漏洞", "更新到最新版本"]
                }
            }
        }
    
    状态码:
        - 200: 任务创建成功
        - 400: 请求参数错误
        - 403: POC 验证功能已禁用
        - 404: POC 不存在
        - 500: 任务执行失败
    """
    try:
        if not request.poc_id or not request.poc_id.strip():
            raise HTTPException(status_code=400, detail="POC ID 不能为空")
        
        if not request.target or not request.target.strip():
            raise HTTPException(status_code=400, detail="验证目标不能为空")
        
        if not request.target.startswith(('http://', 'https://')):
            raise HTTPException(status_code=400, detail="验证目标必须是有效的URL格式")
        
        if not settings.POC_VERIFICATION_ENABLED:
            raise HTTPException(status_code=403, detail="POC 验证功能已禁用")
        
        logger.info(f"创建 POC 验证任务: {request.poc_id} -> {request.target}")
        
        verification_task = await poc_manager.create_verification_task(
            poc_id=request.poc_id,
            target=request.target,
            priority=request.priority,
            task_id=request.task_id
        )
        
        if not verification_task:
            raise HTTPException(status_code=404, detail=f"POC 不存在: {request.poc_id}")
        
        result = await verification_engine.execute_verification_task(verification_task)
        if not result:
            raise HTTPException(status_code=500, detail="POC 验证执行失败")
        
        analysis = await result_analyzer.analyze_single_result(result)
        
        analysis_data = {
            "is_false_positive": analysis.is_false_positive,
            "risk_level": analysis.risk_level,
            "recommendations": analysis.recommendations,
            "false_positive_score": analysis.false_positive_score,
            "confidence": analysis.confidence,
            "cvss_score": analysis.cvss_score,
            "severity": analysis.severity,
            "analysis_details": analysis.analysis_details
        }
        
        try:
            result.analysis = analysis_data
            await result.save()
            logger.info(f"AI分析结果已保存到数据库: result_id={result.id}")
        except Exception as e:
            logger.error(f"保存AI分析结果失败: result_id={result.id}, error={str(e)}")
        
        logger.info(f"POC 验证任务完成: {verification_task.id}")
        
        return APIResponse(
            code=200,
            message="POC 验证任务创建成功",
            data={
                "task": _build_task_response(verification_task),
                "result": {
                    "result_id": result.id,
                    "vulnerable": result.vulnerable,
                    "message": result.message,
                    "confidence": result.confidence,
                    "severity": result.severity,
                    "cvss_score": result.cvss_score,
                    "execution_time": result.execution_time
                },
                "analysis": {
                    "is_false_positive": analysis.is_false_positive,
                    "risk_level": analysis.risk_level,
                    "recommendations": analysis.recommendations
                }
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"创建 POC 验证任务失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"创建任务失败: {str(e)}")


@router.post("/tasks/batch", response_model=APIResponse)
async def create_batch_verification_tasks(request: CreateBatchVerificationTaskRequest):
    """
    批量创建 POC 验证任务
    
    批量创建多个 POC 验证任务并并发执行，返回任务列表和分析摘要。
    
    请求参数:
        - poc_tasks (list, 必填): POC 任务列表，每项包含:
            - poc_id (str): POC 标识符
            - priority (int, 可选): 优先级
        - target (str, 必填): 验证目标 URL
        - task_id (str, 可选): 关联的任务 ID
    
    请求示例:
        POST /api/poc/verification/tasks/batch
        {
            "poc_tasks": [
                {"poc_id": "CVE-2024-1234", "priority": 8},
                {"poc_id": "CVE-2024-5678", "priority": 5}
            ],
            "target": "https://example.com",
            "task_id": "task-uuid-123"
        }
    
    响应示例:
        {
            "code": 200,
            "message": "批量 POC 验证任务创建成功",
            "data": {
                "tasks": [...],
                "results_count": 2,
                "analysis": {
                    "total_results": 2,
                    "vulnerable_count": 1,
                    "false_positive_count": 0,
                    "true_positive_count": 1,
                    "severity_distribution": {"high": 1, "medium": 0, "low": 0},
                    "average_confidence": 0.92,
                    "high_risk_targets": ["https://example.com"],
                    "recommendations": ["修复高危漏洞"]
                }
            }
        }
    
    状态码:
        - 200: 任务创建成功
        - 400: 没有有效的 POC 任务
        - 403: POC 验证功能已禁用
        - 500: 任务执行失败
    """
    try:
        if not settings.POC_VERIFICATION_ENABLED:
            raise HTTPException(status_code=403, detail="POC 验证功能已禁用")
        
        logger.info(f"批量创建 POC 验证任务,数量: {len(request.poc_tasks)}")
        
        verification_tasks = []
        for poc_task in request.poc_tasks:
            task = await poc_manager.create_verification_task(
                poc_id=poc_task.get("poc_id"),
                target=request.target,
                priority=poc_task.get("priority", 5),
                task_id=request.task_id
            )
            if task:
                verification_tasks.append(task)
        
        if not verification_tasks:
            raise HTTPException(status_code=400, detail="没有有效的 POC 任务")
        
        results = await verification_engine.execute_batch_verification(verification_tasks)
        
        for result in results:
            try:
                analysis = await result_analyzer.analyze_single_result(result)
                analysis_data = {
                    "is_false_positive": analysis.is_false_positive,
                    "risk_level": analysis.risk_level,
                    "recommendations": analysis.recommendations,
                    "false_positive_score": analysis.false_positive_score,
                    "confidence": analysis.confidence,
                    "cvss_score": analysis.cvss_score,
                    "severity": analysis.severity,
                    "analysis_details": analysis.analysis_details
                }
                result.analysis = analysis_data
                await result.save()
                logger.debug(f"批量验证 - AI分析结果已保存: result_id={result.id}")
            except Exception as e:
                logger.error(f"批量验证 - 保存分析结果失败: result_id={result.id}, error={str(e)}")
        
        analysis_summary = await result_analyzer.analyze_batch_results(results)
        
        batch_analysis_data = {
            "total_results": analysis_summary.total_results,
            "vulnerable_count": analysis_summary.vulnerable_count,
            "false_positive_count": analysis_summary.false_positive_count,
            "true_positive_count": analysis_summary.true_positive_count,
            "severity_distribution": analysis_summary.severity_distribution,
            "average_confidence": analysis_summary.average_confidence,
            "high_risk_targets": analysis_summary.high_risk_targets,
            "recommendations": analysis_summary.recommendations
        }
        
        for task in verification_tasks:
            try:
                if task.config is None:
                    task.config = {}
                task.config["batch_analysis"] = batch_analysis_data
                await task.save()
            except Exception as e:
                logger.error(f"保存批量分析摘要到任务失败: task_id={task.id}, error={str(e)}")
        
        logger.info(f"批量验证完成: {len(results)}个结果, {analysis_summary.vulnerable_count}个漏洞")
        
        return APIResponse(
            code=200,
            message="批量 POC 验证任务创建成功",
            data={
                "tasks": [_build_task_response(t) for t in verification_tasks],
                "results_count": len(results),
                "analysis": {
                    "total_results": analysis_summary.total_results,
                    "vulnerable_count": analysis_summary.vulnerable_count,
                    "false_positive_count": analysis_summary.false_positive_count,
                    "true_positive_count": analysis_summary.true_positive_count,
                    "severity_distribution": analysis_summary.severity_distribution,
                    "average_confidence": analysis_summary.average_confidence,
                    "high_risk_targets": analysis_summary.high_risk_targets,
                    "recommendations": analysis_summary.recommendations
                }
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"批量创建 POC 验证任务失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"批量创建任务失败: {str(e)}")


@router.get("/tasks", response_model=APIResponse)
async def list_verification_tasks(
    status: Optional[str] = Query(None, description="任务状态过滤"),
    page: int = Query(1, ge=1, description="页码"),
    page_size: int = Query(20, ge=1, le=100, description="每页数量")
):
    """
    列出 POC 验证任务
    
    获取 POC 验证任务列表，支持按状态过滤和分页查询。
    
    查询参数:
        - status (str, 可选): 任务状态过滤，可选值: pending, running, completed, failed, cancelled
        - page (int, 可选): 页码，默认为 1
        - page_size (int, 可选): 每页数量，默认为 20，范围 1-100
    
    请求示例:
        GET /api/poc/verification/tasks?status=completed&page=1&page_size=20
    
    响应示例:
        {
            "code": 200,
            "message": "查询验证任务成功",
            "data": {
                "items": [
                    {
                        "task_id": "uuid-123",
                        "poc_name": "Apache RCE",
                        "poc_id": "CVE-2024-1234",
                        "target": "https://example.com",
                        "status": "completed",
                        "progress": 100,
                        "priority": 8,
                        "created_at": "2024-01-01T12:00:00Z",
                        "updated_at": "2024-01-01T12:00:05Z",
                        "latest_result": {
                            "vulnerable": true,
                            "message": "目标存在漏洞",
                            "confidence": 0.95
                        }
                    }
                ],
                "total": 100,
                "page": 1,
                "page_size": 20,
                "total_pages": 5
            }
        }
    
    状态码:
        - 200: 查询成功
        - 500: 查询失败
    """
    try:
        query = POCVerificationTask.all()
        
        if status:
            query = query.filter(status=status)
        
        total = await query.count()
        tasks = await query.order_by("-created_at").offset(
            (page - 1) * page_size
        ).limit(page_size)
        
        task_list = []
        for task in tasks:
            latest_result = await POCVerificationResult.filter(
                verification_task=task.id
            ).order_by("-created_at").first()
            
            task_data = _build_task_response(task)
            if latest_result:
                task_data["latest_result"] = {
                    "vulnerable": latest_result.vulnerable,
                    "message": latest_result.message,
                    "confidence": latest_result.confidence
                }
            task_list.append(task_data)
        
        return APIResponse(
            code=200,
            message="查询验证任务成功",
            data={
                "items": task_list,
                "total": total,
                "page": page,
                "page_size": page_size,
                "total_pages": (total + page_size - 1) // page_size
            }
        )
    except Exception as e:
        logger.error(f"查询验证任务失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"查询任务失败: {str(e)}")


@router.get("/tasks/{task_id}", response_model=APIResponse)
async def get_verification_task(task_id: UUID):
    """
    获取 POC 验证任务详情
    
    获取指定任务的详细信息，包括所有验证结果。
    
    路径参数:
        - task_id (UUID, 必填): 任务 ID
    
    请求示例:
        GET /api/poc/verification/tasks/uuid-123
    
    响应示例:
        {
            "code": 200,
            "message": "查询验证任务成功",
            "data": {
                "task": {
                    "task_id": "uuid-123",
                    "poc_name": "Apache RCE",
                    "poc_id": "CVE-2024-1234",
                    "target": "https://example.com",
                    "status": "completed",
                    "progress": 100,
                    "priority": 8,
                    "config": {...}
                },
                "results": [
                    {
                        "result_id": "result-uuid",
                        "poc_name": "Apache RCE",
                        "poc_id": "CVE-2024-1234",
                        "target": "https://example.com",
                        "vulnerable": true,
                        "message": "目标存在漏洞",
                        "output": "...",
                        "error": null,
                        "execution_time": 2.5,
                        "confidence": 0.95,
                        "severity": "high",
                        "cvss_score": 9.8
                    }
                ],
                "results_count": 1,
                "vulnerable_count": 1
            }
        }
    
    状态码:
        - 200: 查询成功
        - 404: 任务不存在
        - 500: 查询失败
    """
    try:
        task = await POCVerificationTask.get_or_none(id=task_id)
        if not task:
            raise HTTPException(status_code=404, detail="验证任务不存在")
        
        results = await POCVerificationResult.filter(
            verification_task=task.id
        ).order_by("-created_at")
        
        result_list = [_build_result_response(r) for r in results]
        
        return APIResponse(
            code=200,
            message="查询验证任务成功",
            data={
                "task": {
                    **_build_task_response(task),
                    "config": task.config
                },
                "results": result_list,
                "results_count": len(result_list),
                "vulnerable_count": sum(1 for r in result_list if r["vulnerable"])
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"查询验证任务详情失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"查询任务详情失败: {str(e)}")


@router.post("/tasks/{task_id}/pause", response_model=APIResponse)
async def pause_verification_task(task_id: UUID):
    """
    暂停 POC 验证任务
    
    暂停正在执行的 POC 验证任务。
    
    路径参数:
        - task_id (UUID, 必填): 任务 ID
    
    请求示例:
        POST /api/poc/verification/tasks/uuid-123/pause
    
    响应示例:
        {
            "code": 200,
            "message": "验证任务已暂停",
            "data": null
        }
    
    状态码:
        - 200: 暂停成功
        - 400: 任务状态不允许暂停
        - 500: 暂停失败
    """
    try:
        success = await verification_engine.pause_verification_task(str(task_id))
        if success:
            return APIResponse(code=200, message="验证任务已暂停")
        raise HTTPException(status_code=400, detail="任务状态不允许暂停")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"暂停验证任务失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"暂停任务失败: {str(e)}")


@router.post("/tasks/{task_id}/resume", response_model=APIResponse)
async def resume_verification_task(task_id: UUID):
    """
    继续 POC 验证任务
    
    继续执行已暂停的 POC 验证任务。
    
    路径参数:
        - task_id (UUID, 必填): 任务 ID
    
    请求示例:
        POST /api/poc/verification/tasks/uuid-123/resume
    
    响应示例:
        {
            "code": 200,
            "message": "验证任务已继续",
            "data": null
        }
    
    状态码:
        - 200: 继续成功
        - 400: 任务状态不允许继续
        - 500: 继续失败
    """
    try:
        success = await verification_engine.resume_verification_task(str(task_id))
        if success:
            return APIResponse(code=200, message="验证任务已继续")
        raise HTTPException(status_code=400, detail="任务状态不允许继续")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"继续验证任务失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"继续任务失败: {str(e)}")


@router.post("/tasks/{task_id}/cancel", response_model=APIResponse)
async def cancel_verification_task(task_id: UUID):
    """
    取消 POC 验证任务
    
    取消正在执行或暂停的 POC 验证任务。
    
    路径参数:
        - task_id (UUID, 必填): 任务 ID
    
    请求示例:
        POST /api/poc/verification/tasks/uuid-123/cancel
    
    响应示例:
        {
            "code": 200,
            "message": "验证任务已取消",
            "data": null
        }
    
    状态码:
        - 200: 取消成功
        - 400: 任务状态不允许取消
        - 500: 取消失败
    """
    try:
        success = await verification_engine.cancel_verification_task(str(task_id))
        if success:
            return APIResponse(code=200, message="验证任务已取消")
        raise HTTPException(status_code=400, detail="任务状态不允许取消")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"取消验证任务失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"取消任务失败: {str(e)}")


@router.post("/tasks/{task_id}/report", response_model=APIResponse)
async def generate_verification_report(
    task_id: UUID,
    format: str = Query("html", description="报告格式: html, json, pdf"),
    output_path: Optional[str] = Query(None, description="输出文件路径")
):
    """
    生成 POC 验证报告
    
    生成指定任务的验证报告，支持 HTML、JSON、PDF 格式。
    
    路径参数:
        - task_id (UUID, 必填): 任务 ID
    
    查询参数:
        - format (str, 可选): 报告格式，可选值: html, json, pdf，默认为 html
        - output_path (str, 可选): 输出文件路径，不指定则返回报告内容
    
    请求示例:
        POST /api/poc/verification/tasks/uuid-123/report?format=html
    
    响应示例:
        {
            "code": 200,
            "message": "报告生成成功",
            "data": {
                "task_id": "uuid-123",
                "format": "html",
                "report": "<html>...</html>",
                "generated_at": "2024-01-01T12:00:00Z"
            }
        }
    
    状态码:
        - 200: 报告生成成功
        - 404: 任务不存在
        - 500: 报告生成失败
    """
    try:
        poc_task = await POCVerificationTask.get_or_none(id=task_id)
        if not poc_task:
            raise HTTPException(status_code=404, detail="验证任务不存在")
        
        report = await report_generator.generate_report(
            verification_task=poc_task,
            format=format,
            output_path=output_path
        )
        
        results = await POCVerificationResult.filter(verification_task=poc_task.id)
        
        report_content = {
            "task_id": str(task_id),
            "poc_name": poc_task.poc_name,
            "poc_id": poc_task.poc_id,
            "target": poc_task.target,
            "status": poc_task.status,
            "format": format,
            "report": report if not output_path else f"报告已保存到: {output_path}",
            "results_count": len(results),
            "vulnerable_count": sum(1 for r in results if r.vulnerable),
            "generated_at": poc_task.updated_at.isoformat()
        }
        
        analysis_summary = None
        if poc_task.config and "batch_analysis" in poc_task.config:
            analysis_summary = poc_task.config["batch_analysis"]
        elif results:
            analysis_summary = {
                "total_results": len(results),
                "vulnerable_count": sum(1 for r in results if r.vulnerable),
                "results_with_analysis": sum(1 for r in results if r.analysis)
            }
        
        try:
            parent_task = None
            if poc_task.config and poc_task.config.get("task_id"):
                parent_task = await Task.get_or_none(id=int(poc_task.config["task_id"]))
            
            report_record = Report(
                task=parent_task if parent_task else None,
                report_name=f"POC验证报告-{poc_task.poc_name}-{poc_task.target}",
                report_type=format,
                content=json.dumps(report_content, ensure_ascii=False),
                file_path=output_path,
                ai_analysis=json.dumps(analysis_summary, ensure_ascii=False) if analysis_summary else None
            )
            await report_record.save()
            logger.info(f"报告已保存到数据库: report_id={report_record.id}, task_id={task_id}")
        except Exception as e:
            logger.error(f"保存报告到数据库失败: {str(e)}")
        
        return APIResponse(
            code=200,
            message="报告生成成功",
            data={
                "task_id": str(task_id),
                "format": format,
                "report": report if not output_path else f"报告已保存到: {output_path}",
                "generated_at": poc_task.updated_at.isoformat()
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"生成验证报告失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"生成报告失败: {str(e)}")


@router.get("/health", response_model=APIResponse)
async def health_check():
    """
    健康检查
    
    检查 POC 验证系统的健康状态，包含统计信息。
    
    请求示例:
        GET /api/poc/verification/health
    
    响应示例:
        {
            "code": 200,
            "message": "POC 验证系统运行正常",
            "data": {
                "status": "healthy",
                "enabled": true,
                "config": {
                    "max_concurrent_executions": 5,
                    "execution_timeout": 300,
                    "max_retries": 3,
                    "result_accuracy_threshold": 0.8,
                    "cache_enabled": true,
                    "cache_ttl": 3600
                },
                "statistics": {
                    "total_tasks": 100,
                    "completed_tasks": 95,
                    "failed_tasks": 5,
                    "active_tasks": 0
                }
            }
        }
    
    状态码:
        - 200: 系统正常
        - 500: 系统异常
    """
    try:
        stats = await verification_engine.get_engine_statistics()
        
        return APIResponse(
            code=200,
            message="POC 验证系统运行正常",
            data={
                "status": "healthy",
                "enabled": settings.POC_VERIFICATION_ENABLED,
                "config": {
                    "max_concurrent_executions": settings.POC_MAX_CONCURRENT_EXECUTIONS,
                    "execution_timeout": settings.POC_EXECUTION_TIMEOUT,
                    "max_retries": settings.POC_RETRY_MAX_COUNT,
                    "result_accuracy_threshold": settings.POC_RESULT_ACCURACY_THRESHOLD,
                    "cache_enabled": settings.POC_CACHE_ENABLED,
                    "cache_ttl": settings.POC_CACHE_TTL
                },
                "statistics": stats
            }
        )
    except Exception as e:
        logger.error(f"健康检查失败: {str(e)}")
        return APIResponse(
            code=500,
            message="POC 验证系统异常",
            data={"status": "unhealthy", "error": str(e)}
        )
