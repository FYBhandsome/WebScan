"""
日志文件写入器 - 将运行日志写入本地文件供前端读取
支持日志级别、文件轮转、大小限制
"""
import os
import time
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
import json
import logging

logger = logging.getLogger(__name__)

LOG_LEVEL_DEBUG = "debug"
LOG_LEVEL_INFO = "info"
LOG_LEVEL_WARNING = "warning"
LOG_LEVEL_ERROR = "error"
LOG_LEVEL_SUCCESS = "success"

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

DEFAULT_LOG_FILE = "runtime.log"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
MAX_BACKUP_FILES = 5


class LogWriter:
    """日志文件写入器"""
    
    _instance: Optional["LogWriter"] = None
    _lock = threading.Lock()
    
    def __init__(self, log_file: str = None, max_size: int = None):
        self.log_file = Path(log_file or DEFAULT_LOG_FILE)
        self.max_size = max_size or MAX_FILE_SIZE
        self._write_lock = threading.Lock()
        self._last_id = 0
        
        self._ensure_file_exists()
    
    @classmethod
    def get_instance(cls, log_file: str = None) -> "LogWriter":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls(log_file)
        return cls._instance
    
    def _ensure_file_exists(self):
        """确保日志文件存在"""
        if not self.log_file.exists():
            self.log_file.touch()
            logger.info(f"创建日志文件: {self.log_file}")
    
    def _next_id(self) -> int:
        """生成日志ID"""
        self._last_id += 1
        return self._last_id
    
    def _check_rotation(self):
        """检查是否需要轮转日志文件"""
        if not self.log_file.exists():
            return
        
        file_size = self.log_file.stat().st_size
        if file_size >= self.max_size:
            self._rotate_log()
    
    def _rotate_log(self):
        """轮转日志文件"""
        try:
            for i in range(MAX_BACKUP_FILES - 1, 0, -1):
                old_file = self.log_file.with_suffix(f".log.{i}")
                new_file = self.log_file.with_suffix(f".log.{i + 1}")
                if old_file.exists():
                    old_file.rename(new_file)
            
            backup_file = self.log_file.with_suffix(".log.1")
            self.log_file.rename(backup_file)
            self.log_file.touch()
            logger.info(f"日志文件轮转: {backup_file}")
        except Exception as e:
            logger.error(f"日志轮转失败: {e}")
    
    def _format_timestamp(self) -> str:
        """格式化时间戳"""
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    
    def write_log(
        self,
        level: str,
        message: str,
        category: str = "system",
        node: str = "-",
        session_id: str = None,
        details: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        写入日志到文件
        
        Args:
            level: 日志级别 (debug/info/warning/error/success)
            message: 日志消息
            category: 日志分类 (system/api/workflow/scan/report)
            node: 节点名称
            session_id: 会话ID
            details: 详细信息
        
        Returns:
            日志条目字典
        """
        timestamp = self._format_timestamp()
        log_id = self._next_id()
        level_prefix = LEVEL_PREFIX.get(level, "[INFO]")
        
        log_entry = {
            "id": f"log_{log_id}",
            "timestamp": timestamp,
            "level": level,
            "category": category,
            "node": node,
            "message": message,
            "session_id": session_id or "global",
            "details": details or {},
            "color": LEVEL_COLORS.get(level, "#cccccc")
        }
        
        log_line = f"[{timestamp}] {level_prefix} [{category}] [{node}] {message}"
        if details:
            log_line += f" | {json.dumps(details, ensure_ascii=False)}"
        log_line += "\n"
        
        with self._write_lock:
            self._check_rotation()
            try:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(log_line)
            except Exception as e:
                logger.error(f"写入日志文件失败: {e}")
        
        return log_entry
    
    def write_log_entry(self, log_entry: Dict[str, Any]):
        """
        写入已格式化的日志条目
        
        Args:
            log_entry: 日志条目字典
        """
        level = log_entry.get("level", "info")
        message = log_entry.get("message", "")
        category = log_entry.get("category", "system")
        node = log_entry.get("node", "-")
        session_id = log_entry.get("session_id")
        details = log_entry.get("details")
        
        self.write_log(level, message, category, node, session_id, details)
    
    def clear_logs(self):
        """清空日志文件"""
        with self._write_lock:
            try:
                with open(self.log_file, "w", encoding="utf-8") as f:
                    f.truncate()
                logger.info("日志文件已清空")
            except Exception as e:
                logger.error(f"清空日志文件失败: {e}")
    
    def get_logs(self, count: int = 100) -> list:
        """
        读取最近的日志
        
        Args:
            count: 读取条数
        
        Returns:
            日志列表
        """
        logs = []
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                lines = f.readlines()[-count:]
                for line in lines:
                    line = line.strip()
                    if line:
                        logs.append(self._parse_line(line))
        except Exception as e:
            logger.error(f"读取日志文件失败: {e}")
        return logs
    
    def _parse_line(self, line: str) -> Dict[str, Any]:
        """解析日志行"""
        import re
        
        pattern = r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\] \[(\w+)\] \[(\w+)\] \[(\w+)\] (.+)'
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
                "timestamp": timestamp,
                "level": level.lower(),
                "category": category,
                "node": node,
                "message": message,
                "details": details,
                "color": LEVEL_COLORS.get(level.lower(), "#cccccc")
            }
        
        return {
            "timestamp": datetime.now().isoformat(),
            "level": "info",
            "message": line,
            "color": "#cccccc"
        }


log_writer = LogWriter.get_instance()


def log_debug(message: str, **kwargs):
    """写入DEBUG级别日志"""
    return log_writer.write_log(LOG_LEVEL_DEBUG, message, **kwargs)


def log_info(message: str, **kwargs):
    """写入INFO级别日志"""
    return log_writer.write_log(LOG_LEVEL_INFO, message, **kwargs)


def log_warn(message: str, **kwargs):
    """写入WARN级别日志"""
    return log_writer.write_log(LOG_LEVEL_WARNING, message, **kwargs)


def log_error(message: str, **kwargs):
    """写入ERROR级别日志"""
    return log_writer.write_log(LOG_LEVEL_ERROR, message, **kwargs)


def log_success(message: str, **kwargs):
    """写入SUCCESS级别日志"""
    return log_writer.write_log(LOG_LEVEL_SUCCESS, message, **kwargs)


def clear_logs():
    """清空日志文件"""
    log_writer.clear_logs()


def get_logs(count: int = 100) -> list:
    """获取最近日志"""
    return log_writer.get_logs(count)
