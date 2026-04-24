"""
工具执行结果类型定义

提供统一的工具执行结果格式，包含状态、数据、错误信息、执行时间和元数据。
所有工具执行结果都应使用 PluginResult 类型，确保接口一致性。
"""
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, Optional


class ToolStatus(Enum):
    """
    工具执行状态枚举
    
    Attributes:
        SUCCESS: 执行成功
        FAILED: 执行失败
        TIMEOUT: 执行超时
        SECURITY_BLOCKED: 安全检查未通过
        CANCELLED: 执行被取消
    """
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    SECURITY_BLOCKED = "security_blocked"
    CANCELLED = "cancelled"


@dataclass
class PluginResult:
    """
    插件执行结果数据类
    
    统一所有工具的返回格式，包含执行状态、数据、错误信息、执行时间和元数据。
    所有工具适配器和包装器都应返回此类型。
    
    Attributes:
        status: 执行状态 (success/failed/timeout/security_blocked/cancelled)
        data: 返回的数据，失败时为 None
        error: 错误信息，成功时为 None
        execution_time: 执行时间(秒)
        metadata: 额外的元数据信息，如插件名称、目标地址等
        tool_name: 工具名称
        target: 目标地址
    
    Examples:
        >>> result = PluginResult.success(data={"ports": [80, 443]}, plugin="portscan")
        >>> result.status
        'success'
        >>> result.to_dict()
        {'status': 'success', 'data': {...}, ...}
    """
    status: str
    data: Any = None
    error: Optional[str] = None
    execution_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    tool_name: str = ""
    target: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """
        转换为字典格式
        
        Returns:
            Dict[str, Any]: 包含所有字段的字典
        """
        return asdict(self)
    
    @property
    def is_success(self) -> bool:
        """检查是否执行成功"""
        return self.status == ToolStatus.SUCCESS.value
    
    @property
    def is_failed(self) -> bool:
        """检查是否执行失败"""
        return self.status == ToolStatus.FAILED.value
    
    @property
    def is_timeout(self) -> bool:
        """检查是否执行超时"""
        return self.status == ToolStatus.TIMEOUT.value
    
    @classmethod
    def success(
        cls,
        data: Any = None,
        execution_time: float = 0.0,
        tool_name: str = "",
        target: str = "",
        **metadata
    ) -> 'PluginResult':
        """
        创建成功结果
        
        Args:
            data: 返回的数据
            execution_time: 执行时间(秒)
            tool_name: 工具名称
            target: 目标地址
            **metadata: 额外的元数据信息
        
        Returns:
            PluginResult: 成功状态的结果实例
        """
        return cls(
            status=ToolStatus.SUCCESS.value,
            data=data,
            execution_time=execution_time,
            metadata=metadata,
            tool_name=tool_name,
            target=target
        )
    
    @classmethod
    def failed(
        cls,
        error: str,
        execution_time: float = 0.0,
        tool_name: str = "",
        target: str = "",
        **metadata
    ) -> 'PluginResult':
        """
        创建失败结果
        
        Args:
            error: 错误信息
            execution_time: 执行时间(秒)
            tool_name: 工具名称
            target: 目标地址
            **metadata: 额外的元数据信息
        
        Returns:
            PluginResult: 失败状态的结果实例
        """
        return cls(
            status=ToolStatus.FAILED.value,
            error=error,
            execution_time=execution_time,
            metadata=metadata,
            tool_name=tool_name,
            target=target
        )
    
    @classmethod
    def timeout(
        cls,
        timeout_seconds: float,
        execution_time: float = 0.0,
        tool_name: str = "",
        target: str = "",
        **metadata
    ) -> 'PluginResult':
        """
        创建超时结果
        
        Args:
            timeout_seconds: 超时时间(秒)
            execution_time: 实际执行时间(秒)
            tool_name: 工具名称
            target: 目标地址
            **metadata: 额外的元数据信息
        
        Returns:
            PluginResult: 超时状态的结果实例
        """
        return cls(
            status=ToolStatus.TIMEOUT.value,
            error=f"执行超时，超过 {timeout_seconds} 秒",
            execution_time=execution_time,
            metadata={"timeout_seconds": timeout_seconds, **metadata},
            tool_name=tool_name,
            target=target
        )
    
    @classmethod
    def security_blocked(
        cls,
        error: str,
        security_issues: list,
        tool_name: str = "",
        target: str = "",
        **metadata
    ) -> 'PluginResult':
        """
        创建安全检查未通过结果
        
        Args:
            error: 错误信息
            security_issues: 安全问题列表
            tool_name: 工具名称
            target: 目标地址
            **metadata: 额外的元数据信息
        
        Returns:
            PluginResult: 安全检查未通过状态的结果实例
        """
        return cls(
            status=ToolStatus.SECURITY_BLOCKED.value,
            error=error,
            metadata={"security_issues": security_issues, **metadata},
            tool_name=tool_name,
            target=target
        )
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PluginResult':
        """
        从字典创建结果实例
        
        Args:
            data: 包含结果数据的字典
        
        Returns:
            PluginResult: 结果实例
        """
        return cls(
            status=data.get("status", ToolStatus.FAILED.value),
            data=data.get("data"),
            error=data.get("error"),
            execution_time=data.get("execution_time", 0.0),
            metadata=data.get("metadata", {}),
            tool_name=data.get("tool_name", ""),
            target=data.get("target", "")
        )


@dataclass
class ProgressInfo:
    """
    进度信息数据类
    
    用于在工具执行过程中报告进度。
    
    Attributes:
        tool_name: 工具名称
        target: 目标地址
        stage: 当前阶段名称
        progress: 进度百分比 (0-100)
        message: 进度消息
        elapsed_time: 已用时间(秒)
        extra_data: 额外数据
    """
    tool_name: str
    target: str
    stage: str
    progress: int
    message: str = ""
    elapsed_time: float = 0.0
    extra_data: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return asdict(self)
