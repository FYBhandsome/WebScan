"""将扫描线程中的结构化日志安全桥接到主事件循环。"""
import asyncio
import contextvars
import logging
import re
import threading
import time
from contextlib import contextmanager
from datetime import datetime
from typing import Callable, Dict, Optional


logger = logging.getLogger(__name__)
_progress_context: contextvars.ContextVar[Optional[Dict]] = contextvars.ContextVar(
    "scanner_progress_context", default=None
)
_install_lock = threading.Lock()
_handler_installed = False

_VISIBLE_KEYWORDS = (
    "初始化", "开始", "扫描", "检测", "测试", "分析", "请求", "参数",
    "进度", "完成", "发现", "失败", "错误", "警告", "payload",
)
_TERMINAL_KEYWORDS = ("完成", "失败", "错误", "警告", "发现")
_SECRET_PATTERN = re.compile(
    r"(?i)(authorization|cookie|token|password|passwd|secret)\s*[:=]\s*([^\s,;]+)"
)


def _sanitize_message(message: str) -> str:
    message = _SECRET_PATTERN.sub(r"\1=[已隐藏]", message)
    return message[:400]


class ScannerProgressHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        context = _progress_context.get()
        if not context:
            return

        try:
            message = _sanitize_message(record.getMessage())
            level = record.levelname.lower()
            if record.levelno < logging.WARNING and not any(key in message for key in _VISIBLE_KEYWORDS):
                return

            now = time.monotonic()
            is_terminal = record.levelno >= logging.WARNING or any(key in message for key in _TERMINAL_KEYWORDS)
            if not is_terminal and now - context["last_emit"] < context["min_interval"]:
                return
            context["last_emit"] = now

            payload = {
                "type": "tool_progress",
                "payload": {
                    "tool": context["tool"],
                    "target": context["target"],
                    "node": "scanner",
                    "level": level,
                    "message": message,
                    "timestamp": datetime.now().isoformat(),
                    "logger": record.name,
                },
            }
            callback = context["callback"]
            context["loop"].call_soon_threadsafe(
                lambda: asyncio.create_task(callback(payload))
            )
        except Exception as exc:
            logger.warning(f"扫描进度日志桥接失败: {exc}")


def _install_handler() -> None:
    global _handler_installed
    if _handler_installed:
        return
    with _install_lock:
        if _handler_installed:
            return
        scanner_logger = logging.getLogger("backend.vulnerability_scan_plugins")
        if scanner_logger.getEffectiveLevel() > logging.INFO:
            scanner_logger.setLevel(logging.INFO)
        scanner_logger.addHandler(ScannerProgressHandler(level=logging.INFO))
        _handler_installed = True


@contextmanager
def scanner_progress_context(
    session_id: str,
    tool: str,
    target: str,
    callback: Optional[Callable],
    min_interval: float = 0.2,
):
    """为 asyncio.to_thread 调用设置可传播的扫描进度上下文。"""
    if callback is None:
        yield
        return

    _install_handler()
    context = {
        "session_id": session_id,
        "tool": tool,
        "target": target,
        "callback": callback,
        "loop": asyncio.get_running_loop(),
        "last_emit": 0.0,
        "min_interval": min_interval,
    }
    token = _progress_context.set(context)
    try:
        yield
    finally:
        _progress_context.reset(token)
