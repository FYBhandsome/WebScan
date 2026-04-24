"""
序列化工具模块

提供 JSON 数据清理和序列化功能。
"""
import datetime
import decimal
from typing import Any, Dict, List, Set, Union


def sanitize_json_data(data: Any, max_depth: int = 10) -> Any:
    """
    清理数据使其可以安全地 JSON 序列化
    
    Args:
        data: 需要清理的数据
        max_depth: 最大递归深度，防止循环引用
        
    Returns:
        清理后的数据
    """
    if max_depth <= 0:
        return str(data)
    
    if data is None:
        return None
    
    if isinstance(data, (str, int, float, bool)):
        return data
    
    if isinstance(data, bytes):
        try:
            return data.decode('utf-8')
        except UnicodeDecodeError:
            return data.hex()
    
    if isinstance(data, datetime.datetime):
        return data.isoformat()
    
    if isinstance(data, datetime.date):
        return data.isoformat()
    
    if isinstance(data, datetime.time):
        return data.isoformat()
    
    if isinstance(data, decimal.Decimal):
        return float(data)
    
    if isinstance(data, set):
        return [sanitize_json_data(item, max_depth - 1) for item in data]
    
    if isinstance(data, (list, tuple)):
        return [sanitize_json_data(item, max_depth - 1) for item in data]
    
    if isinstance(data, dict):
        return {
            str(k): sanitize_json_data(v, max_depth - 1)
            for k, v in data.items()
        }
    
    if hasattr(data, '__dict__'):
        return sanitize_json_data(data.__dict__, max_depth - 1)
    
    if hasattr(data, 'to_dict'):
        try:
            return sanitize_json_data(data.to_dict(), max_depth - 1)
        except Exception:
            pass
    
    if hasattr(data, 'model_dump'):
        try:
            return sanitize_json_data(data.model_dump(), max_depth - 1)
        except Exception:
            pass
    
    return str(data)


__all__ = ["sanitize_json_data"]
