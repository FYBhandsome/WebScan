"""
API 路由总入口

统一管理所有 API 路由,包括扫描、任务、报告、POC、AWVS、AI 对话、AI Agents 等模块。

"""
from fastapi import APIRouter
from . import tasks, reports, poc, awvs, settings, ai, kb, user, notifications, websocket, seebug
from backend.ai_agents.api import router as ai_agents_router
from TOSKill.api import ai_chat_router, report_router, scan_router, chat_router

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
