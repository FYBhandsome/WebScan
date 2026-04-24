"""
日志工具模块

提供结构化日志配置和请求ID追踪功能
"""
import logging
import sys
import json
import uuid
from datetime import datetime
from typing import Optional
from contextvars import ContextVar
from pathlib import Path


request_id_var: ContextVar[Optional[str]] = ContextVar('request_id', default=None)


class JsonFormatter(logging.Formatter):
    """JSON格式日志格式化器"""
    
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        request_id = get_request_id()
        if request_id:
            log_data["request_id"] = request_id
        
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        if hasattr(record, 'extra_data') and record.extra_data:
            log_data["extra"] = record.extra_data
        
        return json.dumps(log_data, ensure_ascii=False)


class ConsoleFormatter(logging.Formatter):
    """控制台格式日志格式化器"""
    
    COLORS = {
        'DEBUG': '\033[36m',
        'INFO': '\033[32m',
        'WARNING': '\033[33m',
        'ERROR': '\033[31m',
        'CRITICAL': '\033[35m'
    }
    RESET = '\033[0m'
    
    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, self.RESET)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        request_id = get_request_id()
        request_id_str = f" [{request_id[:8]}]" if request_id else ""
        
        return f"{timestamp}{request_id_str} {color}{record.levelname:8}{self.RESET} {record.name}: {record.getMessage()}"


def setup_structured_logging(
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    json_format: bool = True,
    console_output: bool = True
) -> None:
    """
    配置结构化日志
    
    Args:
        log_level: 日志级别
        log_file: 日志文件路径
        json_format: 是否使用JSON格式
        console_output: 是否输出到控制台
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    if json_format:
        formatter = JsonFormatter()
    else:
        formatter = ConsoleFormatter()
    
    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
    
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setFormatter(JsonFormatter())
        root_logger.addHandler(file_handler)
    
    logging.getLogger("uvicorn").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)


def set_request_id(request_id: Optional[str] = None) -> str:
    """
    设置当前请求ID
    
    Args:
        request_id: 请求ID，不提供则自动生成
        
    Returns:
        str: 设置的请求ID
    """
    if request_id is None:
        request_id = str(uuid.uuid4())
    request_id_var.set(request_id)
    return request_id


def get_request_id() -> Optional[str]:
    """
    获取当前请求ID
    
    Returns:
        Optional[str]: 当前请求ID
    """
    return request_id_var.get()


def clear_request_id() -> None:
    """清除当前请求ID"""
    request_id_var.set(None)
