"""
报告管理 API 路由

提供统一的报告管理接口：
- 报告创建、查询、更新、删除
- 多格式导出（HTML、PDF、JSON、Markdown）
- AI 分析集成
"""
from fastapi import APIRouter, HTTPException, Response, Query, BackgroundTasks
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
import logging
import json
from urllib.parse import quote

from backend.models import Report, Task, Vulnerability
from backend.api.common import APIResponse
from backend.services.report_service import report_service, ReportFormat

logger = logging.getLogger(__name__)

router = APIRouter()


class ReportCreate(BaseModel):
    """创建报告请求模型"""
    task_id: int
    name: str = Field(..., description="报告名称")
    format: str = Field(default="json", description="报告格式")
    include_ai_analysis: bool = Field(default=True, description="是否包含AI分析")


class ReportUpdate(BaseModel):
    """更新报告请求模型"""
    report_name: Optional[str] = None
    content: Optional[Dict[str, Any]] = None


@router.get("/", response_model=APIResponse)
async def list_reports(
    task_id: Optional[int] = None,
    skip: int = Query(0, ge=0, description="跳过数量"),
    limit: int = Query(20, ge=1, le=100, description="返回数量")
):
    """
    获取报告列表
    
    Args:
        task_id: 可选，按任务ID过滤
        skip: 跳过数量
        limit: 返回数量
        
    Returns:
        APIResponse: 报告列表
    """
    try:
        query = Report.all()
        
        if task_id:
            query = query.filter(task_id=task_id)
        
        query = query.order_by('-created_at')
        total = await query.count()
        reports = await query.prefetch_related('task').offset(skip).limit(limit)
        
        report_list = []
        for report in reports:
            content_str = report.content or ""
            size_bytes = len(content_str.encode('utf-8'))
            size = f"{size_bytes} B" if size_bytes < 1024 else f"{size_bytes / 1024:.1f} KB" if size_bytes < 1024 * 1024 else f"{size_bytes / (1024 * 1024):.1f} MB"

            report_list.append({
                "id": report.id,
                "task_id": report.task_id,
                "task_name": report.task.task_name if report.task else "Unknown Task",
                "report_name": report.report_name,
                "report_type": report.report_type,
                "size": size,
                "created_at": report.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "updated_at": report.updated_at.strftime("%Y-%m-%dT%H:%M:%SZ")
            })
        
        return APIResponse(
            code=200,
            message="获取成功",
            data={"reports": report_list, "total": total, "skip": skip, "limit": limit}
        )
    except Exception as e:
        logger.error(f"获取报告列表失败: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"获取报告列表失败: {str(e)}")


@router.post("/", response_model=APIResponse)
async def create_report(report: ReportCreate):
    """
    创建新报告
    
    Args:
        report: 报告创建请求
        
    Returns:
        APIResponse: 创建的报告信息
    """
    try:
        task = await Task.get_or_none(id=report.task_id)
        if not task:
            logger.error(f"任务不存在 | 任务ID: {report.task_id}")
            raise HTTPException(status_code=400, detail="任务不存在")
        
        vulns = await Vulnerability.filter(task_id=task.id).all()
        
        vuln_list = [{
            "id": v.id,
            "title": v.title,
            "name": v.title,
            "severity": v.severity,
            "url": v.url,
            "description": v.description,
            "remediation": v.remediation
        } for v in vulns]
        
        report_data = await report_service.generate_report(
            task_id=str(task.id),
            task_name=task.task_name,
            target=task.target,
            vulnerabilities=vuln_list,
            include_ai_analysis=report.include_ai_analysis,
            scan_time=str(task.created_at)
        )
        
        ai_analysis_json = None
        analyzed_at = None
        analysis_model = None
        
        if report_data.ai_analysis:
            ai_analysis_json = json.dumps(report_data.ai_analysis.to_dict())
            analyzed_at = datetime.now()
            analysis_model = "AI_Analyzer_v1"
        
        new_report = await Report.create(
            task_id=report.task_id,
            report_name=report.name,
            report_type=report.format,
            content=json.dumps(report_data.to_dict()),
            ai_analysis=ai_analysis_json,
            analyzed_at=analyzed_at,
            analysis_model=analysis_model
        )
        
        response_data = {
            "id": new_report.id,
            "task_id": new_report.task_id,
            "report_name": new_report.report_name,
            "report_type": new_report.report_type,
            "created_at": new_report.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "total_vulnerabilities": report_data.summary.total_vulnerabilities,
            "risk_assessment": report_data.risk_assessment.to_dict(),
            "has_ai_analysis": report_data.ai_analysis is not None
        }
        
        if report_data.ai_analysis:
            response_data["ai_analysis"] = report_data.ai_analysis.to_dict()
        
        return APIResponse(
            code=200,
            message="报告创建成功",
            data=response_data
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"创建报告失败: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"创建报告失败: {str(e)}")


@router.get("/{report_id}", response_model=APIResponse)
async def get_report(report_id: int):
    """
    获取报告详情
    
    Args:
        report_id: 报告ID
        
    Returns:
        APIResponse: 报告详情
    """
    try:
        report = await Report.filter(id=report_id).prefetch_related('task').first()
        
        if not report:
            logger.error(f"报告不存在 | 报告ID: {report_id}")
            raise HTTPException(status_code=404, detail="报告不存在")
        
        content_data = json.loads(report.content) if report.content else {}
        
        ai_analysis_data = None
        if report.ai_analysis:
            try:
                ai_analysis_data = json.loads(report.ai_analysis)
            except json.JSONDecodeError:
                logger.warning(f"AI分析结果JSON解析失败 | 报告ID: {report_id}")
        
        if not ai_analysis_data and "ai_analysis" in content_data:
            ai_analysis_data = content_data.get("ai_analysis")
        
        response_data = {
            "id": report.id,
            "task_id": report.task_id,
            "task_type": report.task.task_type if report.task else None,
            "target_url": report.task.target if report.task else None,
            "report_name": report.report_name,
            "report_type": report.report_type,
            "content": content_data,
            "file_path": report.file_path,
            "created_at": report.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "updated_at": report.updated_at.strftime("%Y-%m-%dT%H:%M:%SZ")
        }
        
        if ai_analysis_data:
            response_data["ai_analysis"] = ai_analysis_data
            response_data["has_ai_analysis"] = True
            response_data["analyzed_at"] = report.analyzed_at.strftime("%Y-%m-%dT%H:%M:%SZ") if report.analyzed_at else None
            response_data["analysis_model"] = report.analysis_model
        else:
            response_data["has_ai_analysis"] = False
        
        return APIResponse(
            code=200,
            message="获取成功",
            data=response_data
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"获取报告详情失败: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"获取报告详情失败: {str(e)}")


@router.put("/{report_id}", response_model=APIResponse)
async def update_report(report_id: int, report_update: ReportUpdate):
    """
    更新报告
    
    Args:
        report_id: 报告ID
        report_update: 更新请求
        
    Returns:
        APIResponse: 更新后的报告信息
    """
    try:
        report = await Report.get_or_none(id=report_id)
        if not report:
            logger.error(f"报告不存在 | 报告ID: {report_id}")
            raise HTTPException(status_code=404, detail="报告不存在")

        if report_update.report_name:
            report.report_name = report_update.report_name
        if report_update.content is not None:
            report.content = json.dumps(report_update.content)
        
        await report.save()
        
        return APIResponse(code=200, message="更新成功", data={"id": report.id})
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"更新报告失败: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"更新报告失败: {str(e)}")


@router.delete("/{report_id}", response_model=APIResponse)
async def delete_report(report_id: int):
    """
    删除报告
    
    Args:
        report_id: 报告ID
        
    Returns:
        APIResponse: 删除结果
    """
    try:
        report = await Report.get_or_none(id=report_id)
        if not report:
            logger.error(f"报告不存在 | 报告ID: {report_id}")
            raise HTTPException(status_code=404, detail="报告不存在")

        await report.delete()
        return APIResponse(code=200, message="删除成功", data=None)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"删除报告失败: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"删除报告失败: {str(e)}")


@router.get("/{report_id}/export")
async def export_report(
    report_id: int, 
    format: str = Query("json", description="导出格式: json, html, markdown, pdf")
):
    """
    导出报告
    
    Args:
        report_id: 报告ID
        format: 导出格式 (json, html, markdown, pdf)
        
    Returns:
        Response: 导出的报告文件
    """
    try:
        report = await Report.get_or_none(id=report_id)
        if not report:
            logger.error(f"报告不存在 | 报告ID: {report_id}")
            raise HTTPException(status_code=404, detail="报告不存在")
        
        content = json.loads(report.content) if report.content else {}
        
        from backend.services.report_service import ReportData, Language
        
        report_data = ReportData(
            task_id=content.get("task_id", ""),
            task_name=content.get("task_name", report.report_name),
            target=content.get("target", ""),
            scan_time=content.get("scan_time", ""),
            generated_at=content.get("generated_at", datetime.now().isoformat()),
            vulnerabilities=content.get("vulnerabilities", [])
        )
        
        if "summary" in content:
            from backend.services.report_service import ReportSummary
            report_data.summary = ReportSummary(**content["summary"])
        
        if "risk_assessment" in content:
            from backend.services.report_service import RiskAssessment
            report_data.risk_assessment = RiskAssessment(**content["risk_assessment"])
        
        if "ai_analysis" in content:
            from backend.services.report_service import AIAnalysisData
            report_data.ai_analysis = AIAnalysisData(**content["ai_analysis"])
        
        format_lower = format.lower()
        
        if format_lower == "html":
            html_content = report_service.generate_html_report(report_data)
            file_path = report_service.save_report(report_data, ReportFormat.HTML, f"{report.report_name}.html")
            filename = quote(f"{report.report_name}.html")
            
            report.file_path = file_path
            await report.save()
            
            return Response(
                content=html_content,
                media_type="text/html",
                headers={"Content-Disposition": f"attachment; filename={filename}; filename*=utf-8''{filename}"}
            )
        elif format_lower == "json":
            json_content = report_service.generate_json_report(report_data)
            file_path = report_service.save_report(report_data, ReportFormat.JSON, f"{report.report_name}.json")
            filename = quote(f"{report.report_name}.json")
            
            report.file_path = file_path
            await report.save()
            
            return JSONResponse(
                content=content,
                headers={"Content-Disposition": f"attachment; filename={filename}; filename*=utf-8''{filename}"}
            )
        elif format_lower in ["markdown", "md"]:
            md_content = report_service.generate_markdown_report(report_data)
            file_path = report_service.save_report(report_data, ReportFormat.MARKDOWN, f"{report.report_name}.md")
            filename = quote(f"{report.report_name}.md")
            
            report.file_path = file_path
            await report.save()
            
            return PlainTextResponse(
                content=md_content,
                media_type="text/markdown",
                headers={"Content-Disposition": f"attachment; filename={filename}; filename*=utf-8''{filename}"}
            )
        elif format_lower == "pdf":
            pdf_content = report_service.generate_pdf_report(report_data)
            file_path = report_service.save_report(report_data, ReportFormat.PDF, f"{report.report_name}.pdf")
            filename = quote(f"{report.report_name}.pdf")
            
            report.file_path = file_path
            await report.save()
            
            return Response(
                content=pdf_content,
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename={filename}; filename*=utf-8''{filename}"}
            )
        else:
            logger.error(f"不支持的导出格式 | 格式: {format}")
            raise HTTPException(status_code=400, detail=f"不支持的导出格式: {format}")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"导出报告失败: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"导出报告失败: {str(e)}")


@router.get("/{report_id}/preview", response_model=APIResponse)
async def preview_report(report_id: int):
    """
    预览报告
    
    Args:
        report_id: 报告ID
        
    Returns:
        APIResponse: 报告预览数据
    """
    try:
        report = await Report.filter(id=report_id).prefetch_related('task').first()
        if not report:
            logger.error(f"报告不存在 | 报告ID: {report_id}")
            raise HTTPException(status_code=404, detail="报告不存在")
        
        content_data = json.loads(report.content) if report.content else {}
        summary = content_data.get('summary', {})
        vulnerabilities = content_data.get('vulnerabilities', [])
        
        ai_analysis_data = None
        if report.ai_analysis:
            try:
                ai_analysis_data = json.loads(report.ai_analysis)
            except json.JSONDecodeError:
                ai_analysis_data = content_data.get('ai_analysis')
        elif 'ai_analysis' in content_data:
            ai_analysis_data = content_data.get('ai_analysis')
        
        preview_data = {
            "id": report.id,
            "report_name": report.report_name,
            "task_name": content_data.get('task_name'),
            "target": content_data.get('target'),
            "scan_time": content_data.get('scan_time'),
            "summary": summary,
            "risk_assessment": content_data.get('risk_assessment'),
            "vulnerabilities_preview": vulnerabilities[:5],
            "total_vulnerabilities": len(vulnerabilities),
            "has_more": len(vulnerabilities) > 5,
            "export_formats": ["json", "html", "markdown", "pdf"],
            "has_ai_analysis": ai_analysis_data is not None
        }
        
        if ai_analysis_data:
            preview_data["ai_analysis"] = ai_analysis_data
        
        return APIResponse(code=200, message="获取预览成功", data=preview_data)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"预览报告失败: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"预览报告失败: {str(e)}")


@router.get("/task/{task_id}/latest", response_model=APIResponse)
async def get_latest_report_by_task(task_id: int):
    """
    获取指定任务的最新报告
    
    Args:
        task_id: 任务ID
        
    Returns:
        APIResponse: 最新报告信息
    """
    try:
        task = await Task.get_or_none(id=task_id)
        if not task:
            logger.error(f"任务不存在 | 任务ID: {task_id}")
            raise HTTPException(status_code=404, detail="任务不存在")
        
        report = await Report.filter(task_id=task_id).order_by('-created_at').first()
        if not report:
            return APIResponse(code=404, message="该任务暂无报告", data=None)
        
        content_data = json.loads(report.content) if report.content else {}
        
        ai_analysis_data = None
        if report.ai_analysis:
            try:
                ai_analysis_data = json.loads(report.ai_analysis)
            except json.JSONDecodeError:
                ai_analysis_data = content_data.get('ai_analysis')
        elif 'ai_analysis' in content_data:
            ai_analysis_data = content_data.get('ai_analysis')
        
        response_data = {
            "id": report.id,
            "task_id": report.task_id,
            "report_name": report.report_name,
            "report_type": report.report_type,
            "content": content_data,
            "file_path": report.file_path,
            "created_at": report.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "updated_at": report.updated_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "has_ai_analysis": ai_analysis_data is not None
        }
        
        if ai_analysis_data:
            response_data["ai_analysis"] = ai_analysis_data
        
        return APIResponse(
            code=200,
            message="获取成功",
            data=response_data
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"获取最新报告失败: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"获取最新报告失败: {str(e)}")


@router.post("/{report_id}/regenerate", response_model=APIResponse)
async def regenerate_report(report_id: int, background_tasks: BackgroundTasks):
    """
    重新生成报告
    
    Args:
        report_id: 报告ID
        background_tasks: 后台任务
        
    Returns:
        APIResponse: 重新生成结果
    """
    try:
        report = await Report.get_or_none(id=report_id).prefetch_related('task')
        if not report:
            logger.error(f"报告不存在 | 报告ID: {report_id}")
            raise HTTPException(status_code=404, detail="报告不存在")
        
        task = report.task
        if not task:
            logger.error(f"关联任务不存在 | 报告ID: {report_id}")
            raise HTTPException(status_code=400, detail="关联任务不存在")
        
        vulns = await Vulnerability.filter(task_id=task.id).all()
        
        vuln_list = [{
            "id": v.id,
            "title": v.title,
            "severity": v.severity,
            "url": v.url,
            "description": v.description,
            "remediation": v.remediation
        } for v in vulns]
        
        existing_content = json.loads(report.content) if report.content else {}
        
        report_data = await report_service.generate_report(
            task_id=str(task.id),
            task_name=task.task_name,
            target=task.target,
            vulnerabilities=vuln_list,
            execution_history=existing_content.get('execution_history', []),
            tool_results=existing_content.get('tool_results', {}),
            target_context=existing_content.get('target_context', {}),
            include_ai_analysis=True,
            scan_time=str(task.created_at)
        )
        
        ai_analysis_json = None
        analyzed_at = None
        analysis_model = None
        
        if report_data.ai_analysis:
            ai_analysis_json = json.dumps(report_data.ai_analysis.to_dict())
            analyzed_at = datetime.now()
            analysis_model = "AI_Analyzer_v1"
        
        report.content = json.dumps(report_data.to_dict())
        report.ai_analysis = ai_analysis_json
        report.analyzed_at = analyzed_at
        report.analysis_model = analysis_model
        await report.save()
        
        return APIResponse(
            code=200,
            message="报告重新生成成功",
            data={
                "report_id": report.id,
                "total_vulnerabilities": report_data.summary.total_vulnerabilities,
                "risk_assessment": report_data.risk_assessment.to_dict(),
                "has_ai_analysis": report_data.ai_analysis is not None,
                "ai_analysis": report_data.ai_analysis.to_dict() if report_data.ai_analysis else None
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"重新生成报告失败: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"重新生成报告失败: {str(e)}")
