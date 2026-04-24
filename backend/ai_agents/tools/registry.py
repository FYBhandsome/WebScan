"""
工具注册表模块

管理所有扫描工具的注册和调用，提供统一的工具接口。

增强功能：
- 丰富的元数据管理（版本、作者、依赖、场景、标签等）
- 调用链追踪（start_trace/end_trace/get_call_chain）
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
        
        logger.info(
            "工具注册表初始化完成 "
            "（增强版：支持元数据管理、调用链追踪、安全检查、结果缓存）"
        )
    
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
        
        logger.info(
            f"✅ 注册工具: {name} "
            f"(分类: {category}, 版本: {version}, 作者: {author}, 优先级: {priority})"
        )
    
    def get_tool_metadata(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """
        获取工具元数据
        
        Args:
            tool_name: 工具名称
            
        Returns:
            Optional[Dict]: 工具元数据字典，不存在则返回None
        """
        if tool_name not in self.tool_metadata:
            logger.warning(f"工具 {tool_name} 不存在")
            return None
        
        metadata = self.tool_metadata[tool_name].copy()
        metadata["tool_name"] = tool_name
        return metadata
    
    def update_metadata(
        self,
        tool_name: str,
        **kwargs
    ) -> bool:
        """
        更新工具元数据
        
        Args:
            tool_name: 工具名称
            **kwargs: 要更新的元数据字段
            
        Returns:
            bool: 更新是否成功
        """
        if tool_name not in self.tool_metadata:
            logger.warning(f"工具 {tool_name} 不存在，无法更新元数据")
            return False
        
        protected_fields = {"registered_at"}
        for key, value in kwargs.items():
            if key in protected_fields:
                logger.warning(f"字段 {key} 是受保护字段，不允许更新")
                continue
            if key in self.tool_metadata[tool_name]:
                self.tool_metadata[tool_name][key] = value
                logger.debug(f"更新工具 {tool_name} 的元数据字段 {key}")
            else:
                logger.warning(f"未知的元数据字段: {key}")
        
        logger.info(f"✅ 更新工具 {tool_name} 的元数据")
        return True
    
    def start_trace(self, trace_id: Optional[str] = None) -> str:
        """
        开始调用链追踪
        
        Args:
            trace_id: 追踪ID，如果不提供则自动生成
            
        Returns:
            str: 追踪ID
        """
        if trace_id is None:
            trace_id = hashlib.md5(f"{time.time()}".encode()).hexdigest()[:12]
        
        self._current_trace_id = trace_id
        self._call_chain = []
        self._call_chain_enabled = True
        
        logger.info(f"🔍 开始调用链追踪: {trace_id}")
        return trace_id
    
    def end_trace(self) -> Dict[str, Any]:
        """
        结束调用链追踪
        
        Returns:
            Dict: 调用链摘要信息
        """
        if not self._current_trace_id:
            logger.warning("没有正在进行的调用链追踪")
            return {"status": "no_active_trace"}
        
        trace_summary = {
            "trace_id": self._current_trace_id,
            "start_time": self._call_chain[0].start_time if self._call_chain else None,
            "end_time": self._call_chain[-1].end_time if self._call_chain else None,
            "total_tools": len(self._call_chain),
            "successful_calls": sum(1 for node in self._call_chain if node.status == "success"),
            "failed_calls": sum(1 for node in self._call_chain if node.status == "failed"),
            "total_duration": self._calculate_total_duration(),
            "call_chain": [
                {
                    "tool_name": node.tool_name,
                    "target": node.target,
                    "status": node.status,
                    "start_time": node.start_time.isoformat() if node.start_time else None,
                    "end_time": node.end_time.isoformat() if node.end_time else None,
                    "error": node.error,
                }
                for node in self._call_chain
            ]
        }
        
        logger.info(
            f"🔍 结束调用链追踪: {self._current_trace_id}, "
            f"共调用 {len(self._call_chain)} 个工具"
        )
        
        self._current_trace_id = None
        return trace_summary
    
    def get_call_chain(self) -> List[Dict[str, Any]]:
        """
        获取当前调用链
        
        Returns:
            List[Dict]: 调用链列表
        """
        return [
            {
                "node_id": node.node_id,
                "tool_name": node.tool_name,
                "target": node.target,
                "status": node.status,
                "start_time": node.start_time.isoformat() if node.start_time else None,
                "end_time": node.end_time.isoformat() if node.end_time else None,
                "params": node.params,
                "error": node.error,
                "parent_id": node.parent_id,
            }
            for node in self._call_chain
        ]
    
    def _calculate_total_duration(self) -> Optional[float]:
        """计算调用链总耗时"""
        if not self._call_chain:
            return None
        
        start = min(node.start_time for node in self._call_chain if node.start_time)
        end = max(node.end_time for node in self._call_chain if node.end_time)
        
        if start and end:
            return (end - start).total_seconds()
        return None
    
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
        
        if not check_result["passed"]:
            logger.warning(f"⚠️ 安全检查未通过: {tool_name} - {check_result['errors']}")
        elif check_result["warnings"]:
            logger.info(f"⚠️ 安全检查警告: {tool_name} - {check_result['warnings']}")
        
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
    
    def get_security_audit_log(
        self,
        tool_name: Optional[str] = None,
        passed_only: Optional[bool] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        获取安全审计日志
        
        Args:
            tool_name: 按工具名称过滤
            passed_only: 只返回通过/未通过的记录
            limit: 返回记录数量限制
            
        Returns:
            List[Dict]: 审计日志列表
        """
        logs = self._security_audit_log
        
        if tool_name:
            logs = [log for log in logs if log["tool_name"] == tool_name]
        
        if passed_only is not None:
            logs = [log for log in logs if log["passed"] == passed_only]
        
        return logs[-limit:]
    
    def _generate_cache_key(
        self,
        tool_name: str,
        target: str,
        **kwargs
    ) -> str:
        """
        生成缓存键
        
        Args:
            tool_name: 工具名称
            target: 扫描目标
            **kwargs: 工具参数
            
        Returns:
            str: 缓存键
        """
        cache_data = {
            "tool_name": tool_name,
            "target": target,
            "kwargs": kwargs
        }
        cache_str = json.dumps(cache_data, sort_keys=True)
        return hashlib.sha256(cache_str.encode()).hexdigest()
    
    def _get_cached_result(
        self,
        cache_key: str
    ) -> Optional[PluginResult]:
        """
        获取缓存结果
        
        Args:
            cache_key: 缓存键
            
        Returns:
            Optional[PluginResult]: 缓存的结果，不存在或已过期则返回None
        """
        if not self._cache_enabled:
            return None
        
        if cache_key not in self._result_cache:
            return None
        
        entry = self._result_cache[cache_key]
        
        if entry.is_expired():
            del self._result_cache[cache_key]
            logger.debug(f"缓存已过期: {cache_key[:16]}...")
            return None
        
        logger.debug(f"命中缓存: {cache_key[:16]}...")
        return entry.result
    
    def _cache_result(
        self,
        cache_key: str,
        result: PluginResult,
        ttl_seconds: int
    ):
        """
        缓存执行结果
        
        Args:
            cache_key: 缓存键
            result: 执行结果
            ttl_seconds: 缓存时间(秒)
        """
        if not self._cache_enabled:
            return
        
        self._result_cache[cache_key] = CacheEntry(
            result=result,
            created_at=datetime.now(),
            ttl_seconds=ttl_seconds,
            cache_key=cache_key
        )
        
        logger.debug(f"缓存结果: {cache_key[:16]}..., TTL: {ttl_seconds}秒")
        
        self._cleanup_expired_cache()
    
    def _cleanup_expired_cache(self):
        """清理过期缓存"""
        expired_keys = [
            key for key, entry in self._result_cache.items()
            if entry.is_expired()
        ]
        
        for key in expired_keys:
            del self._result_cache[key]
        
        if expired_keys:
            logger.debug(f"清理过期缓存: {len(expired_keys)} 条")
    
    def clear_cache(self, tool_name: Optional[str] = None):
        """
        清除缓存
        
        Args:
            tool_name: 指定工具名称，None表示清除所有缓存
        """
        if tool_name is None:
            self._result_cache.clear()
            logger.info("清除所有缓存")
        else:
            keys_to_remove = [
                key for key, entry in self._result_cache.items()
                if entry.result.tool_name == tool_name
            ]
            for key in keys_to_remove:
                del self._result_cache[key]
            logger.info(f"清除工具 {tool_name} 的缓存: {len(keys_to_remove)} 条")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """
        获取缓存统计信息
        
        Returns:
            Dict: 缓存统计信息
        """
        total_entries = len(self._result_cache)
        expired_entries = sum(
            1 for entry in self._result_cache.values()
            if entry.is_expired()
        )
        
        return {
            "enabled": self._cache_enabled,
            "total_entries": total_entries,
            "active_entries": total_entries - expired_entries,
            "expired_entries": expired_entries,
            "default_ttl": self._default_cache_ttl,
        }
    
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
        
        logger.info(f"🔧 调用工具: {tool_name} -> {target}")
        
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
            
            logger.info(f"✅ 工具 {tool_name} 执行成功 (耗时: {execution_time:.2f}秒)")
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
    
    def get_tool(self, tool_name: str) -> Optional[AsyncToolWrapper]:
        """
        获取工具
        
        Args:
            tool_name: 工具名称
            
        Returns:
            Optional[AsyncToolWrapper]: 工具对象，不存在则返回None
        """
        return self.tools.get(tool_name)
    
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
    
    def get_tools_by_tags(self, tags: List[str]) -> List[str]:
        """
        按标签获取工具名称列表
        
        Args:
            tags: 标签列表（满足任一标签即可）
            
        Returns:
            List[str]: 工具名称列表
        """
        return [
            name for name, metadata in self.tool_metadata.items()
            if set(metadata.get("tags", [])).intersection(set(tags))
        ]
    
    def has_tool(self, tool_name: str) -> bool:
        """
        检查工具是否存在
        
        Args:
            tool_name: 工具名称
            
        Returns:
            bool: 工具是否存在
        """
        return tool_name in self.tools
    
    def enable_tool(self, tool_name: str) -> bool:
        """
        启用工具
        
        Args:
            tool_name: 工具名称
            
        Returns:
            bool: 操作是否成功
        """
        return self.update_metadata(tool_name, enabled=True)
    
    def disable_tool(self, tool_name: str) -> bool:
        """
        禁用工具
        
        Args:
            tool_name: 工具名称
            
        Returns:
            bool: 操作是否成功
        """
        return self.update_metadata(tool_name, enabled=False)
    
    def get_registry_stats(self) -> Dict[str, Any]:
        """
        获取注册表统计信息
        
        Returns:
            Dict: 统计信息
        """
        total_calls = sum(
            metadata.get("call_count", 0)
            for metadata in self.tool_metadata.values()
        )
        
        categories = {}
        for metadata in self.tool_metadata.values():
            cat = metadata.get("category", "general")
            categories[cat] = categories.get(cat, 0) + 1
        
        return {
            "total_tools": len(self.tools),
            "enabled_tools": sum(
                1 for m in self.tool_metadata.values() if m.get("enabled", True)
            ),
            "disabled_tools": sum(
                1 for m in self.tool_metadata.values() if not m.get("enabled", True)
            ),
            "total_calls": total_calls,
            "categories": categories,
            "cache_stats": self.get_cache_stats(),
            "security_audit_count": len(self._security_audit_log),
            "trace_enabled": self._call_chain_enabled,
            "cache_enabled": self._cache_enabled,
            "security_check_enabled": self._security_check_enabled,
        }
    
    def set_cache_enabled(self, enabled: bool):
        """设置缓存开关"""
        self._cache_enabled = enabled
        logger.info(f"缓存功能已{'启用' if enabled else '禁用'}")
    
    def set_security_check_enabled(self, enabled: bool):
        """设置安全检查开关"""
        self._security_check_enabled = enabled
        logger.info(f"安全检查功能已{'启用' if enabled else '禁用'}")
    
    def set_trace_enabled(self, enabled: bool):
        """设置调用链追踪开关"""
        self._call_chain_enabled = enabled
        logger.info(f"调用链追踪功能已{'启用' if enabled else '禁用'}")
    
    def add_dangerous_pattern(self, pattern: str):
        """
        添加危险模式
        
        Args:
            pattern: 危险模式字符串
        """
        self._dangerous_patterns.add(pattern.lower())
        logger.info(f"添加危险模式: {pattern}")
    
    def remove_dangerous_pattern(self, pattern: str) -> bool:
        """
        移除危险模式
        
        Args:
            pattern: 危险模式字符串
            
        Returns:
            bool: 是否成功移除
        """
        if pattern.lower() in self._dangerous_patterns:
            self._dangerous_patterns.remove(pattern.lower())
            logger.info(f"移除危险模式: {pattern}")
            return True
        return False


def register_tool(
    name: str,
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
    工具注册装饰器（增强版）
    
    用于简化工具注册，使用装饰器语法:
    
    Examples:
        >>> @register_tool(
        ...     name="my_tool",
        ...     description="我的工具",
        ...     category="plugin",
        ...     timeout=30,
        ...     version="1.0.0",
        ...     author="developer",
        ...     tags=["scanner", "security"],
        ...     applicable_scenarios=["漏洞扫描", "安全检测"]
        ... )
        ... async def my_tool_func(target: str):
        ...     return {"result": "success"}
    """
    def decorator(func: Callable):
        registry.register(
            name=name,
            func=func,
            description=description,
            category=category,
            timeout=timeout,
            priority=priority,
            version=version,
            author=author,
            dependencies=dependencies,
            applicable_scenarios=applicable_scenarios,
            permissions=permissions,
            tags=tags,
            examples=examples,
            cache_ttl=cache_ttl,
            enabled=enabled
        )
        return func
    return decorator


registry = ToolRegistry()
"""
全局工具注册表（增强版）

增强功能:
    - 丰富的元数据管理（版本、作者、依赖、场景、标签等）
    - 调用链追踪（start_trace/end_trace/get_call_chain）
    - 执行安全检查（危险模式检测、权限检查）
    - 结果缓存（支持TTL过期）
    - 统一返回 PluginResult

使用示例:
    from ai_agents.tools import registry, register_tool
    
    @register_tool(
        name="my_tool",
        description="我的工具",
        version="1.0.0",
        author="developer",
        tags=["scanner"]
    )
    async def my_tool(target: str):
        return {"result": "success"}
    
    trace_id = registry.start_trace()
    result = await registry.call_tool("my_tool", "https://example.com")
    trace_summary = registry.end_trace()
"""
