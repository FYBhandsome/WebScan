"""
TOSKill API 模块

提供 WebSocket 和 REST API 接口。
"""
from TOSKill.api.ai_chat_websocket import router as ai_chat_router
from TOSKill.api.report import router as report_router

__all__ = [
    'ai_chat_router',
    'report_router'
]
