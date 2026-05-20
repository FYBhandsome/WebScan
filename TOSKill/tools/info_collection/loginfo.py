# -*- coding:utf-8 -*-
"""
日志处理工具
封装backend.plugins.loginfo模块
"""

from typing import Dict, Any, Optional
import logging


def log_handler(
    name: str,
    level: str = "INFO",
    stream: bool = False,
    file: bool = True
) -> Dict[str, Any]:
    """日志处理工具，创建自定义日志处理器
    
    创建自定义日志处理器：
    - 支持按天自动切割日志文件
    - 支持控制台输出和文件输出
    - 单例模式，避免重复创建handler
    - 支持动态重置日志名称
    
    Args:
        name: 日志器名称
        level: 日志级别(DEBUG/INFO/WARNING/ERROR/CRITICAL)，默认INFO
        stream: 是否输出到控制台，默认False
        file: 是否输出到文件，默认True
        
    Returns:
        包含日志处理器信息的字典，包括：
        - success: 执行状态(True/False)
        - data: 日志处理器配置信息
        - error: 错误信息(成功时为None)
        - metadata: 元数据(工具名称、日志名称等)
    """
    try:
        from backend.plugins.loginfo.loginfo import LogHandler
        
        level_map = {
            "DEBUG": logging.DEBUG,
            "INFO": logging.INFO,
            "WARNING": logging.WARNING,
            "ERROR": logging.ERROR,
            "CRITICAL": logging.CRITICAL
        }
        
        log_level = level_map.get(level.upper(), logging.INFO)
        
        log = LogHandler(name, level=log_level, stream=stream, file=file)
        
        return {
            "success": True,
            "data": {
                "name": name,
                "level": level,
                "stream": stream,
                "file": file,
                "handlers_count": len(log.handlers)
            },
            "error": "",
            "metadata": {
                "tool": "log_handler",
                "log_name": name,
                "log_level": level
            }
        }
    except ImportError as e:
        return {
            "success": False,
            "data": {},
            "error": f"导入loginfo模块失败: {str(e)}",
            "metadata": {"tool": "log_handler", "name": name}
        }
    except Exception as e:
        return {
            "success": False,
            "data": {},
            "error": f"执行log_handler工具异常: {str(e)}",
            "metadata": {"tool": "log_handler", "name": name}
        }


if __name__ == "__main__":
    test_result = log_handler.invoke({"name": "test_log", "level": "INFO", "stream": True})
    print(test_result)
