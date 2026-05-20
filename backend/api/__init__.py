"""
API 路由总入口

统一管理所有 API 路由,包括扫描、任务、报告、POC、AWVS、AI 对话、AI Agents 等模块。

"""
from fastapi import APIRouter, HTTPException
from . import tasks, reports, poc, awvs, settings, ai, kb, user, notifications, websocket, seebug
from backend.ai_agents.api import router as ai_agents_router
from TOSKill.api import ai_chat_router, report_router, scan_router, chat_router
from backend.models import Vulnerability
from backend.api.common import APIResponse
import json

api_router = APIRouter()

api_router.include_router(tasks.router, prefix="/tasks", tags=["任务管理"])
api_router.include_router(reports.router, prefix="/reports", tags=["报告管理"])
api_router.include_router(awvs.router, prefix="/awvs", tags=["AWVS漏洞扫描"])
api_router.include_router(settings.router, prefix="/settings", tags=["系统设置"])
api_router.include_router(ai.router, prefix="/ai", tags=["AI对话"])
api_router.include_router(kb.router, prefix="/kb", tags=["漏洞知识库"])
api_router.include_router(user.router, tags=["用户管理"])
api_router.include_router(notifications.router, tags=["通知管理"])
api_router.include_router(ai_agents_router, tags=["AI Agents"])
api_router.include_router(websocket.router, tags=["WebSocket"])
api_router.include_router(seebug.router, prefix="/seebug", tags=["Seebug"])
api_router.include_router(report_router, tags=["报告下载"])
api_router.include_router(ai_chat_router, tags=["AI对话WebSocket"])
api_router.include_router(scan_router, tags=["TOSKill扫描API"])
api_router.include_router(chat_router, tags=["TOSKill聊天API"])

api_router.include_router(poc.router, tags=["POC扫描"])


@api_router.get("/vulnerabilities/{vuln_id}", response_model=APIResponse)
async def get_vulnerability_by_id(vuln_id: int):
    try:
        vuln = await Vulnerability.filter(id=vuln_id).prefetch_related('task').first()
        if not vuln:
            raise HTTPException(status_code=404, detail="漏洞不存在")
        
        task_data = None
        if vuln.task:
            task_data = {
                "id": vuln.task.id,
                "task_name": vuln.task.task_name,
                "target": vuln.task.target,
                "status": vuln.task.status,
                "created_at": vuln.task.created_at.strftime("%Y-%m-%dT%H:%M:%SZ") if vuln.task.created_at else None
            }
        
        vuln_data = {
            "id": vuln.id,
            "title": vuln.title,
            "type": vuln.vuln_type,
            "severity": vuln.severity,
            "status": vuln.status,
            "url": vuln.url,
            "description": vuln.description,
            "payload": vuln.payload,
            "evidence": vuln.evidence,
            "remediation": vuln.remediation,
            "source": vuln.source or "awvs",
            "source_id": vuln.source_id,
            "task_id": vuln.task_id,
            "task": task_data,
            "risk_score": vuln.risk_score,
            "fix_priority": vuln.fix_priority,
            "cvss_score": vuln.cvss_score,
            "affected_product": vuln.affected_product,
            "created_at": vuln.created_at.strftime("%Y-%m-%dT%H:%M:%SZ") if vuln.created_at else None,
            "updated_at": vuln.updated_at.strftime("%Y-%m-%dT%H:%M:%SZ") if vuln.updated_at else None
        }
        
        return APIResponse(code=200, message="获取成功", data=vuln_data)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
