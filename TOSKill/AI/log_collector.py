import logging
import asyncio
from datetime import datetime
from typing import Dict, List, Optional
from uuid import uuid4

logger = logging.getLogger(__name__)

LOG_LEVEL_DEBUG = "debug"
LOG_LEVEL_INFO = "info"
LOG_LEVEL_WARNING = "warning"
LOG_LEVEL_ERROR = "error"
LOG_LEVEL_SUCCESS = "success"

LOG_CATEGORY_API = "api"
LOG_CATEGORY_WORKFLOW = "workflow"
LOG_CATEGORY_SYSTEM = "system"
LOG_CATEGORY_SCAN = "scan"
LOG_CATEGORY_REPORT = "report"

LEVEL_COLORS = {
    LOG_LEVEL_DEBUG: "#888888",
    LOG_LEVEL_INFO: "#cccccc",
    LOG_LEVEL_WARNING: "#ffcc00",
    LOG_LEVEL_ERROR: "#ff4444",
    LOG_LEVEL_SUCCESS: "#00ff66",
}

MAX_LOGS_PER_SESSION = 2000
MAX_SYSTEM_LOGS = 5000


class LogCollector:
    _instance: Optional["LogCollector"] = None

    def __init__(self):
        self._logs: Dict[str, List[Dict]] = {}
        self._system_logs: List[Dict] = []
        self._last_id = 0

    @classmethod
    def get_instance(cls) -> "LogCollector":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _next_id(self) -> str:
        self._last_id += 1
        return f"log_{self._last_id}_{uuid4().hex[:6]}"

    def _make_entry(self, session_id, node, level, category, message,
                    details=None):
        return {
            "id": self._next_id(),
            "session_id": session_id or "global",
            "node": node or "-",
            "level": level,
            "category": category or LOG_CATEGORY_SYSTEM,
            "message": message,
            "details": details or {},
            "timestamp": datetime.now().isoformat(),
            "color": LEVEL_COLORS.get(level, "#cccccc"),
        }

    def add_log(self, session_id: str, node: str, level: str, message: str,
                category: str = None, details: Dict = None) -> Dict:
        log_entry = self._make_entry(session_id, node, level,
                                     category or LOG_CATEGORY_WORKFLOW,
                                     message, details)

        if session_id not in self._logs:
            self._logs[session_id] = []
        self._logs[session_id].append(log_entry)
        if len(self._logs[session_id]) > MAX_LOGS_PER_SESSION:
            self._logs[session_id] = self._logs[session_id][-MAX_LOGS_PER_SESSION:]

        logger.info(f"[{session_id}][{node}][{level}] {message}")

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.ensure_future(self.push_to_websocket(session_id, log_entry))
        except RuntimeError:
            pass

        return log_entry

    def add_system_log(self, level: str, message: str,
                       category: str = None, details: Dict = None) -> Dict:
        log_entry = self._make_entry(
            "global", "system", level,
            category or LOG_CATEGORY_SYSTEM, message, details
        )
        self._system_logs.append(log_entry)
        if len(self._system_logs) > MAX_SYSTEM_LOGS:
            self._system_logs = self._system_logs[-MAX_SYSTEM_LOGS:]

        logger.info(f"[system][{level}] {message}")

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.ensure_future(self.push_to_all(log_entry))
        except RuntimeError:
            pass

        return log_entry

    async def push_to_all(self, log_entry: Dict):
        try:
            from TOSKill.api.log_websocket import log_ws_manager as _mgr
            await _mgr.broadcast(log_entry)
        except Exception as e:
            logger.debug(f"广播 system_log 失败: {e}")

    async def push_to_websocket(self, session_id: str, log_entry: Dict):
        try:
            from TOSKill.api.log_websocket import log_ws_manager as _mgr
            await _mgr.push_to_session(session_id, log_entry)
        except Exception:
            pass

        try:
            from .graph import memory_store as _ms
            ws_callback = _ms.get_websocket_callback(session_id)
            if ws_callback:
                await ws_callback({
                    "type": "workflow_log",
                    "payload": log_entry
                })
        except Exception as e:
            logger.debug(f"[{session_id}] 推送 workflow_log 失败: {e}")

    def get_logs(self, session_id: str) -> List[Dict]:
        if session_id in self._logs:
            return list(self._logs[session_id])
        return []

    def get_system_logs(self) -> List[Dict]:
        return list(self._system_logs)

    def get_all_logs(self) -> List[Dict]:
        result = list(self._system_logs)
        for sid_logs in self._logs.values():
            result.extend(sid_logs)
        result.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return result[:MAX_SYSTEM_LOGS]

    def get_stats(self, session_id: str = None) -> Dict:
        target = self._logs.get(session_id, []) if session_id else self.get_all_logs()
        stats = {"total": len(target)}
        for lv in [LOG_LEVEL_DEBUG, LOG_LEVEL_INFO, LOG_LEVEL_WARNING,
                   LOG_LEVEL_ERROR, LOG_LEVEL_SUCCESS]:
            stats[lv] = sum(1 for e in target if e.get("level") == lv)
        return stats


log_collector = LogCollector.get_instance()