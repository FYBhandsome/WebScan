"""
统一日志收集器

整合内存日志和文件日志，支持：
1. 内存存储 - 快速访问最近日志
2. 文件持久化 - 长期保存日志
3. WebSocket推送 - 实时推送到前端
"""
import logging
import asyncio
import json
import os
import threading
from datetime import datetime
from typing import Dict, List, Optional
from uuid import uuid4
from pathlib import Path

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

LEVEL_PREFIX = {
    LOG_LEVEL_DEBUG: "[DEBUG]",
    LOG_LEVEL_INFO: "[INFO]",
    LOG_LEVEL_WARNING: "[WARN]",
    LOG_LEVEL_ERROR: "[ERROR]",
    LOG_LEVEL_SUCCESS: "[SUCCESS]",
}

MAX_LOGS_PER_SESSION = 2000
MAX_SYSTEM_LOGS = 5000
MAX_FILE_SIZE = 10 * 1024 * 1024
MAX_BACKUP_FILES = 5


class LogCollector:
    _instance: Optional["LogCollector"] = None
    
    def __init__(self):
        self._logs: Dict[str, List[Dict]] = {}
        self._system_logs: List[Dict] = []
        self._last_id = 0
        self._write_lock = threading.Lock()
        self._log_file: Optional[Path] = None
        self._initialized = False
    
    @classmethod
    def get_instance(cls) -> "LogCollector":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    def initialize(self, log_file: str = None, max_size: int = None, max_backups: int = None):
        if self._initialized:
            return
        
        try:
            from TOSKill.config import settings
            self._log_file = Path(log_file) if log_file else settings.RUNTIME_LOG_PATH
            self._max_size = max_size or settings.MAX_LOG_FILE_SIZE
            self._max_backups = max_backups or settings.MAX_LOG_BACKUP_FILES
        except Exception:
            self._log_file = Path("TOSKill/logs/runtime.log")
            self._max_size = MAX_FILE_SIZE
            self._max_backups = MAX_BACKUP_FILES
        
        self._ensure_log_dir()
        self._initialized = True
        logger.info(f"日志收集器初始化完成: {self._log_file}")
    
    def _ensure_log_dir(self):
        if self._log_file:
            self._log_file.parent.mkdir(parents=True, exist_ok=True)
            if not self._log_file.exists():
                self._log_file.touch()
    
    def _next_id(self) -> str:
        self._last_id += 1
        return f"log_{self._last_id}_{uuid4().hex[:6]}"
    
    def _make_entry(self, session_id, node, level, category, message, details=None):
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
    
    def _write_to_file(self, log_entry: Dict):
        if not self._log_file:
            return
        
        timestamp = log_entry.get("timestamp", "")
        level = log_entry.get("level", "info")
        category = log_entry.get("category", "system")
        node = log_entry.get("node", "-")
        message = log_entry.get("message", "")
        details = log_entry.get("details", {})
        
        level_prefix = LEVEL_PREFIX.get(level, "[INFO]")
        log_line = f"[{timestamp}] {level_prefix} [{category}] [{node}] {message}"
        if details:
            log_line += f" | {json.dumps(details, ensure_ascii=False)}"
        log_line += "\n"
        
        with self._write_lock:
            self._check_rotation()
            try:
                with open(self._log_file, "a", encoding="utf-8", errors="replace") as f:
                    f.write(log_line)
            except Exception as e:
                logger.error(f"写入日志文件失败: {e}")
    
    def _check_rotation(self):
        if not self._log_file or not self._log_file.exists():
            return
        
        try:
            file_size = self._log_file.stat().st_size
            if file_size >= self._max_size:
                self._rotate_log()
        except Exception:
            pass
    
    def _rotate_log(self):
        try:
            for i in range(self._max_backups - 1, 0, -1):
                old_file = self._log_file.with_suffix(f".log.{i}")
                new_file = self._log_file.with_suffix(f".log.{i + 1}")
                if old_file.exists():
                    old_file.rename(new_file)
            
            backup_file = self._log_file.with_suffix(".log.1")
            self._log_file.rename(backup_file)
            self._log_file.touch()
            logger.info(f"日志文件轮转: {backup_file}")
        except Exception as e:
            logger.error(f"日志轮转失败: {e}")
    
    def add_log(self, session_id: str, node: str, level: str, message: str,
                category: str = None, details: Dict = None) -> Dict:
        if not self._initialized:
            self.initialize()
        
        log_entry = self._make_entry(session_id, node, level,
                                      category or LOG_CATEGORY_WORKFLOW,
                                      message, details)
        
        if session_id not in self._logs:
            self._logs[session_id] = []
        self._logs[session_id].append(log_entry)
        if len(self._logs[session_id]) > MAX_LOGS_PER_SESSION:
            self._logs[session_id] = self._logs[session_id][-MAX_LOGS_PER_SESSION:]
        
        self._write_to_file(log_entry)
        
        logger.info(f"[{session_id}][{node}][{level}] {message}")
        
        try:
            asyncio.get_running_loop()
            asyncio.ensure_future(self.push_to_websocket(session_id, log_entry))
        except RuntimeError:
            pass
        
        return log_entry
    
    def add_system_log(self, level: str, message: str,
                       category: str = None, details: Dict = None) -> Dict:
        if not self._initialized:
            self.initialize()
        
        log_entry = self._make_entry(
            "global", "system", level,
            category or LOG_CATEGORY_SYSTEM, message, details
        )
        self._system_logs.append(log_entry)
        if len(self._system_logs) > MAX_SYSTEM_LOGS:
            self._system_logs = self._system_logs[-MAX_SYSTEM_LOGS:]
        
        self._write_to_file(log_entry)
        
        logger.info(f"[system][{level}] {message}")
        
        try:
            asyncio.get_running_loop()
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
    
    def get_file_logs(self, count: int = 200) -> List[Dict]:
        if not self._log_file or not self._log_file.exists():
            return []
        
        logs = []
        try:
            with open(self._log_file, "r", encoding="utf-8") as f:
                lines = f.readlines()[-count:]
                for line in lines:
                    line = line.strip()
                    if line:
                        parsed = self._parse_line(line)
                        if parsed:
                            logs.append(parsed)
        except Exception as e:
            logger.error(f"读取日志文件失败: {e}")
        return logs
    
    def _parse_line(self, line: str) -> Optional[Dict]:
        import re
        
        pattern = r'\[(\d{4}-\d{2}-\d{2}T[\d:]+)\] \[(\w+)\] \[(\w+)\] \[(\w+)\] (.+)'
        match = re.match(pattern, line)
        
        if match:
            timestamp, level, category, node, rest = match.groups()
            
            details = {}
            if "|" in rest:
                msg_part, details_part = rest.rsplit("|", 1)
                message = msg_part.strip()
                try:
                    details = json.loads(details_part.strip())
                except:
                    details = {"raw": details_part.strip()}
            else:
                message = rest
            
            return {
                "id": f"file_{hash(line) % 100000}",
                "timestamp": timestamp,
                "level": level.lower(),
                "category": category,
                "node": node,
                "message": message,
                "details": details,
                "color": LEVEL_COLORS.get(level.lower(), "#cccccc")
            }
        
        return {
            "id": f"raw_{hash(line) % 100000}",
            "timestamp": datetime.now().isoformat(),
            "level": "info",
            "message": line,
            "color": "#cccccc"
        }
    
    def get_stats(self, session_id: str = None) -> Dict:
        target = self._logs.get(session_id, []) if session_id else self.get_all_logs()
        stats = {"total": len(target)}
        for lv in [LOG_LEVEL_DEBUG, LOG_LEVEL_INFO, LOG_LEVEL_WARNING,
                   LOG_LEVEL_ERROR, LOG_LEVEL_SUCCESS]:
            stats[lv] = sum(1 for e in target if e.get("level") == lv)
        return stats
    
    def clear_logs(self):
        self._logs.clear()
        self._system_logs.clear()
        
        if self._log_file and self._log_file.exists():
            try:
                with open(self._log_file, "w", encoding="utf-8") as f:
                    f.truncate()
                logger.info("日志文件已清空")
            except Exception as e:
                logger.error(f"清空日志文件失败: {e}")


log_collector = LogCollector.get_instance()
