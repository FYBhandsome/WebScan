# -*- coding:utf-8 -*-
"""
统一错误处理模块

提供标准化的错误信息格式，帮助用户快速定位问题来源。
"""

from enum import Enum
from dataclasses import dataclass
from typing import Optional, Dict, Any


class ErrorSource(Enum):
    """错误来源枚举"""
    FRONTEND = "frontend"
    BACKEND = "backend"
    NETWORK = "network"
    TOOL = "tool"
    AI_MODEL = "ai_model"
    DATABASE = "database"
    WEBSOCKET = "websocket"
    UNKNOWN = "unknown"


class ErrorCategory(Enum):
    """错误类别枚举"""
    CONNECTION = "connection"
    TIMEOUT = "timeout"
    VALIDATION = "validation"
    PERMISSION = "permission"
    RESOURCE = "resource"
    CONFIGURATION = "configuration"
    EXECUTION = "execution"
    DNS = "dns"
    AUTH = "auth"


@dataclass
class ErrorInfo:
    """标准化错误信息"""
    code: str
    message: str
    source: ErrorSource
    category: ErrorCategory
    suggestion: str
    details: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "source": self.source.value,
            "category": self.category.value,
            "suggestion": self.suggestion,
            "details": self.details or {}
        }


ERROR_DEFINITIONS = {
    "DNS_RESOLVE_FAILED": ErrorInfo(
        code="E001",
        message="DNS解析失败",
        source=ErrorSource.NETWORK,
        category=ErrorCategory.DNS,
        suggestion="请检查目标域名是否正确，或尝试使用IP地址"
    ),
    "TARGET_UNREACHABLE": ErrorInfo(
        code="E002",
        message="目标不可达",
        source=ErrorSource.NETWORK,
        category=ErrorCategory.CONNECTION,
        suggestion="请检查目标地址是否正确，或网络连接是否正常"
    ),
    "TOOL_NOT_FOUND": ErrorInfo(
        code="E003",
        message="工具不存在",
        source=ErrorSource.BACKEND,
        category=ErrorCategory.RESOURCE,
        suggestion="请检查工具名称是否正确，或联系管理员添加该工具"
    ),
    "TOOL_EXECUTION_FAILED": ErrorInfo(
        code="E004",
        message="工具执行失败",
        source=ErrorSource.TOOL,
        category=ErrorCategory.EXECUTION,
        suggestion="请查看详细错误信息，或尝试其他工具"
    ),
    "WEBSOCKET_DISCONNECTED": ErrorInfo(
        code="E005",
        message="WebSocket连接断开",
        source=ErrorSource.WEBSOCKET,
        category=ErrorCategory.CONNECTION,
        suggestion="请刷新页面重新连接，或检查网络状态"
    ),
    "AI_MODEL_ERROR": ErrorInfo(
        code="E006",
        message="AI模型响应错误",
        source=ErrorSource.AI_MODEL,
        category=ErrorCategory.EXECUTION,
        suggestion="请稍后重试，或检查AI模型配置"
    ),
    "SESSION_NOT_FOUND": ErrorInfo(
        code="E007",
        message="会话不存在",
        source=ErrorSource.BACKEND,
        category=ErrorCategory.RESOURCE,
        suggestion="请刷新页面创建新会话"
    ),
    "INVALID_TARGET": ErrorInfo(
        code="E008",
        message="无效的目标地址",
        source=ErrorSource.FRONTEND,
        category=ErrorCategory.VALIDATION,
        suggestion="请输入有效的IP地址、域名或URL"
    ),
    "PERMISSION_DENIED": ErrorInfo(
        code="E009",
        message="权限不足",
        source=ErrorSource.BACKEND,
        category=ErrorCategory.PERMISSION,
        suggestion="请联系管理员获取相应权限"
    ),
    "TIMEOUT": ErrorInfo(
        code="E010",
        message="操作超时",
        source=ErrorSource.NETWORK,
        category=ErrorCategory.TIMEOUT,
        suggestion="请检查网络连接，或稍后重试"
    ),
    "SCAN_IN_PROGRESS": ErrorInfo(
        code="E011",
        message="扫描正在进行中",
        source=ErrorSource.BACKEND,
        category=ErrorCategory.RESOURCE,
        suggestion="请等待当前扫描完成，或停止当前扫描后重试"
    ),
    "RATE_LIMITED": ErrorInfo(
        code="E012",
        message="请求频率过高",
        source=ErrorSource.BACKEND,
        category=ErrorCategory.RESOURCE,
        suggestion="请稍后再试"
    ),
}


ERROR_DEFINITIONS.setdefault(
    "INVALID_PROTOCOL_PAYLOAD",
    ErrorInfo(
        code="INVALID_PROTOCOL_PAYLOAD",
        message="pause/resume 协议参数无效",
        source=ErrorSource.BACKEND,
        category=ErrorCategory.VALIDATION,
        suggestion="请检查 protocol_version、request_id 及 pause_id/interaction_id 字段",
    ),
)


def create_error_response(
    error_code: str,
    custom_message: str = None,
    details: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    创建标准化错误响应
    
    Args:
        error_code: 错误代码
        custom_message: 自定义错误消息（覆盖默认消息）
        details: 额外的错误详情
    
    Returns:
        标准化的错误响应字典
    """
    error_info = ERROR_DEFINITIONS.get(error_code)
    
    if not error_info:
        error_info = ErrorInfo(
            code=error_code,
            message=custom_message or "未知错误",
            source=ErrorSource.UNKNOWN,
            category=ErrorCategory.EXECUTION,
            suggestion="请联系技术支持"
        )
    
    response = error_info.to_dict()
    
    if custom_message:
        response["message"] = custom_message
    
    if details:
        response["details"].update(details)
    
    return {
        "type": "error",
        "payload": response
    }


def format_tool_error(tool_name: str, error: Exception) -> Dict[str, Any]:
    """
    格式化工具执行错误
    
    Args:
        tool_name: 工具名称
        error: 异常对象
    
    Returns:
        标准化的错误响应
    """
    error_str = str(error).lower()
    
    if "dns" in error_str or "getaddrinfo" in error_str or "resolve" in error_str:
        return create_error_response(
            "DNS_RESOLVE_FAILED",
            details={"tool": tool_name, "original_error": str(error)}
        )
    
    if "timeout" in error_str:
        return create_error_response(
            "TIMEOUT",
            details={"tool": tool_name, "original_error": str(error)}
        )
    
    if "connection" in error_str or "unreachable" in error_str:
        return create_error_response(
            "TARGET_UNREACHABLE",
            details={"tool": tool_name, "original_error": str(error)}
        )
    
    return create_error_response(
        "TOOL_EXECUTION_FAILED",
        custom_message=f"工具 {tool_name} 执行失败: {str(error)}",
        details={"tool": tool_name, "original_error": str(error)}
    )
