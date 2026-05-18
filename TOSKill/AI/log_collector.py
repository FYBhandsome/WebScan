import logging
import asyncio
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class LogCollector:
    _instance: Optional["LogCollector"] = None

    def __init__(self):
        self._logs: Dict[str, List[Dict]] = {}

    @classmethod
    def get_instance(cls) -> "LogCollector":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def add_log(self, session_id: str, node: str, level: str, message: str) -> Dict:
        log_entry = {
            "session_id": session_id,
            "node": node,
            "level": level,
            "message": message,
            "timestamp": datetime.now().isoformat()
        }

        if session_id not in self._logs:
            self._logs[session_id] = []
        self._logs[session_id].append(log_entry)

        logger.info(f"[{session_id}][{node}][{level}] {message}")

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.ensure_future(self.push_to_websocket(session_id, log_entry))
        except RuntimeError:
            pass

        return log_entry

    async def push_to_websocket(self, session_id: str, log_entry: Dict):
        from .graph import memory_store as _ms
        ws_callback = _ms.get_websocket_callback(session_id)
        if ws_callback is None:
            return
        try:
            await ws_callback({
                "type": "workflow_log",
                "payload": log_entry
            })
        except Exception as e:
            logger.warning(f"[{session_id}] 推送 workflow_log 失败: {e}")

    def get_logs(self, session_id: str) -> List[Dict]:
        return self._logs.get(session_id, [])


log_collector = LogCollector.get_instance()