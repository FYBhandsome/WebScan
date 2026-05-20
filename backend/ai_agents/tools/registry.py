"""
工具注册表模块

管理所有扫描工具的注册和调用，提供统一的工具接口。

增强功能：
- 丰富的元数据管理（版本、作者、依赖、场景、标签等）
- 执行安全检查（危险模式检测、权限检查）
- 结果缓存（支持TTL过期）
- 统一返回 PluginResult 格式
"""
import asyncio
import logging
import time
import hashlib
import json
from typing import Dict, Callable, Any, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

from .result_types import PluginResult, ToolStatus
from .wrappers import AsyncToolWrapper

logger = logging.getLogger(__name__)


class ToolPermission(Enum):
    """
    工具权限枚举
    
    定义工具执行所需的权限类型。
    """
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    NETWORK = "network"
    FILE = "file"
    ADMIN = "admin"


@dataclass
class CallChainNode:
    """
    调用链节点
    
    记录单次工具调用的详细信息，用于追踪和调试。
    
    Attributes:
        tool_name: 工具名称
        target: 目标地址
        start_time: 开始时间
        end_time: 结束时间
        status: 执行状态
        params: 调用参数
        result: 执行结果
        error: 错误信息
        parent_id: 父节点ID
        node_id: 节点ID
    """
    tool_name: str
    target: str
    start_time: datetime
    end_time: Optional[datetime] = None
    status: str = "pending"
    params: Dict[str, Any] = field(default_factory=dict)
    result: Optional[PluginResult] = None
    error: Optional[str] = None
    parent_id: Optional[str] = None
    node_id: str = field(default_factory=lambda: str(id(object())))


@dataclass
class CacheEntry:
    """
    缓存条目
    
    存储工具执行结果的缓存数据。
    
    Attributes:
        result: 缓存的结果
        created_at: 创建时间
        ttl_seconds: 过期时间(秒)
        cache_key: 缓存键
    """
    result: PluginResult
    created_at: datetime
    ttl_seconds: int
    cache_key: str
    
    def is_expired(self) -> bool:
        """检查缓存是否过期"""
        return datetime.now() > self.created_at + timedelta(seconds=self.ttl_seconds)


class ToolRegistry:
    """
    工具注册表类
    
    负责注册、管理和调用所有扫描工具。
    支持装饰器注册和直接注册两种方式。
    
    增强功能:
        - 丰富的元数据管理
        - 调用链追踪
        - 执行安全检查
        - 结果缓存
        - 统一返回 PluginResult
    
    Attributes:
        tools: 工具字典，键为工具名称，值为工具对象
        tool_metadata: 工具元数据字典
        _call_chain: 调用链记录列表
        _result_cache: 结果缓存字典
        _security_audit_log: 安全审计日志
    """
    
    def __init__(self):
        """初始化工具注册表"""
        self.tools: Dict[str, AsyncToolWrapper] = {}
        self.tool_metadata: Dict[str, Dict[str, Any]] = {}
        
        self._call_chain: List[CallChainNode] = []
        self._call_chain_enabled: bool = True
        self._current_trace_id: Optional[str] = None
        
        self._result_cache: Dict[str, CacheEntry] = {}
        self._cache_enabled: bool = True
        self._default_cache_ttl: int = 300
        
        self._security_audit_log: List[Dict[str, Any]] = []
        self._security_check_enabled: bool = True
        
        self._dangerous_patterns: Set[str] = {
            "rm -rf",
            "del /",
            "format",
            "shutdown",
            "reboot",
            "; rm",
            "| rm",
            "&& rm",
            "drop table",
            "delete from",
            "truncate table",
            "<script>",
            "javascript:",
            "eval(",
            "exec(",
            "system(",
            "subprocess",
            "os.system",
        }

    
    def register(
        self,
        name: str,
        func: Callable,
        description: str = "",
        category: str = "general",
        timeout: int = 60,
        priority: int = 5,
        version: str = "1.0.0",
        author: str = "unknown",
        dependencies: Optional[List[str]] = None,
        applicable_scenarios: Optional[List[str]] = None,
        permissions: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        examples: Optional[List[Dict[str, Any]]] = None,
        cache_ttl: Optional[int] = None,
        enabled: bool = True
    ):
        """
        注册工具（增强版）
        
        Args:
            name: 工具名称，唯一标识符
            func: 工具函数，可以是同步或异步函数
            description: 工具描述，详细说明工具的功能
            category: 工具分类(plugin/poc/general/scanner/exploit)
            timeout: 超时时间(秒)
            priority: 工具优先级(1-10，数字越大优先级越高)
            version: 工具版本号，遵循语义化版本规范
            author: 工具作者
            dependencies: 工具依赖的其他工具名称列表
            applicable_scenarios: 适用场景列表，描述工具的使用场景
            permissions: 工具所需权限列表
            tags: 工具标签，用于分类和搜索
            examples: 使用示例列表
            cache_ttl: 结果缓存时间(秒)，None表示使用默认值
            enabled: 工具是否启用
        """
        if name in self.tools:
            logger.warning(f"工具 {name} 已存在，将被覆盖")
        
        if isinstance(func, AsyncToolWrapper):
            wrapper = func
        else:
            wrapper = AsyncToolWrapper(func, timeout=timeout, tool_name=name)
        
        self.tools[name] = wrapper
        
        self.tool_metadata[name] = {
            "description": description,
            "category": category,
            "timeout": timeout,
            "priority": priority,
            "version": version,
            "author": author,
            "dependencies": dependencies or [],
            "applicable_scenarios": applicable_scenarios or [],
            "permissions": permissions or [],
            "tags": tags or [],
            "examples": examples or [],
            "cache_ttl": cache_ttl if cache_ttl is not None else self._default_cache_ttl,
            "enabled": enabled,
            "registered_at": datetime.now().isoformat(),
            "call_count": 0,
            "last_called_at": None,
            "avg_execution_time": 0.0,
        }

    def _security_check(
        self,
        tool_name: str,
        target: str,
        **kwargs
    ) -> Dict[str, Any]:
        """
        执行安全检查
        
        检查工具权限、参数安全性等。
        
        Args:
            tool_name: 工具名称
            target: 扫描目标
            **kwargs: 工具参数
            
        Returns:
            Dict: 安全检查结果，包含passed、warnings、errors字段
        """
        check_result = {
            "passed": True,
            "warnings": [],
            "errors": [],
            "check_time": datetime.now().isoformat(),
        }
        
        if not self._security_check_enabled:
            return check_result
        
        metadata = self.tool_metadata.get(tool_name, {})
        
        if not metadata.get("enabled", True):
            check_result["passed"] = False
            check_result["errors"].append(f"工具 {tool_name} 已被禁用")
        
        target_check = self._check_dangerous_patterns(target, "target")
        if not target_check["safe"]:
            check_result["passed"] = False
            check_result["errors"].extend(target_check["issues"])
        
        for key, value in kwargs.items():
            if isinstance(value, str):
                param_check = self._check_dangerous_patterns(value, f"参数 {key}")
                if not param_check["safe"]:
                    check_result["warnings"].extend(param_check["issues"])
        
        required_permissions = metadata.get("permissions", [])
        if required_permissions:
            check_result["warnings"].append(
                f"工具 {tool_name} 需要以下权限: {', '.join(required_permissions)}"
            )
        
        dependencies = metadata.get("dependencies", [])
        missing_deps = [dep for dep in dependencies if dep not in self.tools]
        if missing_deps:
            check_result["warnings"].append(
                f"工具依赖缺失: {', '.join(missing_deps)}"
            )
        
        self._log_security_audit(tool_name, target, check_result)
        return check_result
    
    def _check_dangerous_patterns(self, value: str, field_name: str) -> Dict[str, Any]:
        """
        检查危险模式
        
        Args:
            value: 要检查的值
            field_name: 字段名称
            
        Returns:
            Dict: 检查结果，包含safe和issues字段
        """
        result = {"safe": True, "issues": []}
        
        lower_value = value.lower()
        for pattern in self._dangerous_patterns:
            if pattern.lower() in lower_value:
                result["safe"] = False
                result["issues"].append(
                    f"{field_name} 包含危险模式: '{pattern}'"
                )
        
        return result
    
    def _log_security_audit(
        self,
        tool_name: str,
        target: str,
        check_result: Dict[str, Any]
    ):
        """
        记录安全审计日志
        
        Args:
            tool_name: 工具名称
            target: 扫描目标
            check_result: 安全检查结果
        """
        audit_entry = {
            "timestamp": datetime.now().isoformat(),
            "tool_name": tool_name,
            "target": target[:100] if len(target) > 100 else target,
            "passed": check_result["passed"],
            "warnings_count": len(check_result["warnings"]),
            "errors_count": len(check_result["errors"]),
            "warnings": check_result["warnings"],
            "errors": check_result["errors"],
        }
        
        self._security_audit_log.append(audit_entry)
        
        if len(self._security_audit_log) > 1000:
            self._security_audit_log = self._security_audit_log[-500:]

    async def call_tool(
        self,
        tool_name: str,
        target: str,
        use_cache: bool = True,
        **kwargs
    ) -> PluginResult:
        """
        调用工具（增强版）
        
        增强功能:
            - 安全检查
            - 调用链追踪
            - 结果缓存
            - 执行统计
            - 统一返回 PluginResult
        
        Args:
            tool_name: 工具名称
            target: 扫描目标
            use_cache: 是否使用缓存
            **kwargs: 工具参数
            
        Returns:
            PluginResult: 统一格式的执行结果
            
        Raises:
            ValueError: 工具不存在
        """
        if tool_name not in self.tools:
            raise ValueError(f"工具不存在: {tool_name}")
        
        security_result = self._security_check(tool_name, target, **kwargs)
        if not security_result["passed"]:
            return PluginResult.security_blocked(
                error="安全检查未通过",
                security_issues=security_result["errors"],
                tool_name=tool_name,
                target=target
            )
        
        cache_key = self._generate_cache_key(tool_name, target, **kwargs)
        
        if use_cache:
            cached_result = self._get_cached_result(cache_key)
            if cached_result:
                cached_result.metadata["from_cache"] = True
                return cached_result
        
        call_node = CallChainNode(
            tool_name=tool_name,
            target=target,
            start_time=datetime.now(),
            params=kwargs,
            parent_id=self._current_trace_id
        )
        
        if self._call_chain_enabled and self._current_trace_id:
            self._call_chain.append(call_node)
        
        tool = self.tools[tool_name]
        metadata = self.tool_metadata.get(tool_name, {})
        
        start_time = time.time()
        
        try:
            result = await tool.execute(target, **kwargs)
            
            execution_time = time.time() - start_time
            
            call_node.status = "success"
            call_node.end_time = datetime.now()
            call_node.result = result
            
            self._update_tool_stats(tool_name, execution_time)
            
            if not isinstance(result, PluginResult):
                result = PluginResult.success(
                    data=result,
                    execution_time=execution_time,
                    tool_name=tool_name,
                    target=target
                )
            else:
                result.execution_time = execution_time
                result.tool_name = tool_name
                result.target = target
            
            result.metadata["security_warnings"] = security_result.get("warnings", [])
            result.metadata["from_cache"] = False
            
            ttl = metadata.get("cache_ttl", self._default_cache_ttl)
            if use_cache:
                self._cache_result(cache_key, result, ttl)
            
            return result
            
        except asyncio.TimeoutError:
            execution_time = time.time() - start_time
            
            call_node.status = "timeout"
            call_node.end_time = datetime.now()
            call_node.error = f"执行超时({tool.timeout}秒)"
            
            self._update_tool_stats(tool_name, execution_time, success=False)
            
            logger.error(f"⏱️ 工具 {tool_name} 执行超时")
            return PluginResult.timeout(
                timeout_seconds=tool.timeout,
                execution_time=execution_time,
                tool_name=tool_name,
                target=target
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            
            call_node.status = "failed"
            call_node.end_time = datetime.now()
            call_node.error = str(e)
            
            self._update_tool_stats(tool_name, execution_time, success=False)
            
            logger.error(f"❌ 工具 {tool_name} 执行失败: {str(e)}")
            return PluginResult.failed(
                error=str(e),
                execution_time=execution_time,
                tool_name=tool_name,
                target=target
            )
    
    def _update_tool_stats(
        self,
        tool_name: str,
        execution_time: float,
        success: bool = True
    ):
        """
        更新工具执行统计
        
        Args:
            tool_name: 工具名称
            execution_time: 执行时间
            success: 是否成功
        """
        if tool_name not in self.tool_metadata:
            return
        
        metadata = self.tool_metadata[tool_name]
        
        metadata["call_count"] = metadata.get("call_count", 0) + 1
        metadata["last_called_at"] = datetime.now().isoformat()
        
        current_avg = metadata.get("avg_execution_time", 0.0)
        call_count = metadata["call_count"]
        metadata["avg_execution_time"] = (
            (current_avg * (call_count - 1) + execution_time) / call_count
        )

    def list_tools(
        self,
        category: Optional[str] = None,
        tags: Optional[List[str]] = None,
        enabled_only: bool = False
    ) -> List[Dict[str, Any]]:
        """
        列出所有工具（增强版）
        
        Args:
            category: 按分类过滤
            tags: 按标签过滤（满足任一标签即可）
            enabled_only: 只返回启用的工具
            
        Returns:
            List[Dict]: 工具列表，包含名称和元数据
        """
        tools_list = []
        
        for name, wrapper in self.tools.items():
            metadata = self.tool_metadata.get(name, {})
            
            if category is not None and metadata.get("category") != category:
                continue
            
            if tags is not None:
                tool_tags = set(metadata.get("tags", []))
                if not tool_tags.intersection(set(tags)):
                    continue
            
            if enabled_only and not metadata.get("enabled", True):
                continue
            
            tools_list.append({
                "name": name,
                **metadata
            })
        
        return sorted(tools_list, key=lambda x: x.get("priority", 0), reverse=True)
    
    def get_tools_by_category(self, category: str) -> List[str]:
        """
        按分类获取工具名称列表
        
        Args:
            category: 工具分类
            
        Returns:
            List[str]: 工具名称列表
        """
        return [
            name for name, metadata in self.tool_metadata.items()
            if metadata.get("category") == category
        ]
    
    def get_tool(self, name: str) -> Optional[AsyncToolWrapper]:
        """
        获取指定名称的工具
        
        Args:
            name: 工具名称
            
        Returns:
            Optional[AsyncToolWrapper]: 工具包装器对象，不存在则返回None
        """
        return self.tools.get(name)

registry = ToolRegistry()

