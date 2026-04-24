"""
API 路由总入口

统一管理所有 API 路由,包括扫描、任务、报告、POC、AWVS、AI 对话、AI Agents、TOSKill、AI对话TOSKill 等模块。
"""
from fastapi import APIRouter
from . import scan, tasks, reports, poc, awvs, settings, ai, kb, user, notifications, poc_verification, websocket, seebug, toskill, ai_chat
from backend.ai_agents.api import router as ai_agents_router

api_router = APIRouter()

# 注册各个模块的路由
api_router.include_router(scan.router, prefix="/scan", tags=["扫描功能"])
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
api_router.include_router(toskill.router, prefix="/toskill", tags=["TOSKill扫描"])
api_router.include_router(ai_chat.router, prefix="/ai-chat", tags=["AI对话TOSKill"])

api_router.include_router(poc_verification.router, tags=["POC验证"])
api_router.include_router(poc.router, tags=["POC扫描"])
