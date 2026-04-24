"""
AI Agents 工具模块

提供统一的工具注册、封装和适配功能。

主要组件：
- ToolRegistry: 工具注册表，管理所有工具的注册和调用
- AsyncToolWrapper: 异步工具包装器，提供超时控制和错误处理
- PluginAdapter: 插件适配器，适配扫描插件
- POCAdapter: POC适配器，适配漏洞验证脚本
- PluginResult: 统一的工具执行结果格式

使用示例：
    from backend.ai_agents.tools import (
        registry, register_tool, PluginResult, run_plugin
    )
    
    @register_tool(
        name="my_tool",
        description="我的工具",
        category="scanner",
        timeout=60
    )
    async def my_tool(target: str):
        return {"result": "success"}
    
    result = await registry.call_tool("my_tool", "https://example.com")
    if result.is_success:
        print(result.data)
"""

from .result_types import PluginResult, ToolStatus, ProgressInfo
from .wrappers import (
    AsyncToolWrapper,
    with_timeout_and_error_handling,
    wrap_async,
    ProgressReporter,
    create_progress_reporter
)
from .registry import (
    ToolRegistry,
    register_tool,
    registry,
    ToolPermission,
    CallChainNode,
    CacheEntry
)
from .adapters import (
    BaseAdapter,
    PluginAdapter,
    POCAdapter,
    DependencyAdapter,
    run_plugin,
    run_multiple_plugins
)

__all__ = [
    "PluginResult",
    "ToolStatus",
    "ProgressInfo",
    "AsyncToolWrapper",
    "with_timeout_and_error_handling",
    "wrap_async",
    "ProgressReporter",
    "create_progress_reporter",
    "ToolRegistry",
    "register_tool",
    "registry",
    "ToolPermission",
    "CallChainNode",
    "CacheEntry",
    "BaseAdapter",
    "PluginAdapter",
    "POCAdapter",
    "DependencyAdapter",
    "run_plugin",
    "run_multiple_plugins",
]
