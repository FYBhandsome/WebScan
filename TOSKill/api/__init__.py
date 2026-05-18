"""
TOSKill API 模块

提供 WebSocket 和 REST API 接口。
"""
from TOSKill.api.ai_chat_websocket import router as ai_chat_router
from TOSKill.api.report import router as report_router
from TOSKill.api.scan_api import router as scan_router, chat_router
from TOSKill.api.log_websocket import router as log_ws_router

__all__ = [
    'ai_chat_router',
    'chat_router',
    'log_ws_router',
    'report_router',
    'scan_router'
]
