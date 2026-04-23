"""
工具模块

提供统一的工具注册、管理和调用接口。
"""
import logging
from typing import Dict, Any, List, Optional, Callable

from .wrappers import AsyncToolWrapper, wrap_async
from .info_tools import (
    INFO_COLLECTION_TOOLS,
    INFO_TOOL_METADATA,
    get_info_tools,
    get_info_tool_metadata,
    get_all_info_metadata
)
from .vuln_tools import (
    VULN_SCAN_TOOLS,
    VULN_TOOL_METADATA,
    get_vuln_tools,
    get_vuln_tool_metadata,
    get_all_vuln_metadata
)

logger = logging.getLogger(__name__)

ALL_TOOLS = INFO_COLLECTION_TOOLS + VULN_SCAN_TOOLS


def get_all_tools() -> List[str]:
    """获取所有工具名称"""
    return ALL_TOOLS.copy()


def get_tool_category(tool_name: str) -> str:
    """
    获取工具分类
    
    Args:
        tool_name: 工具名称
        
    Returns:
        str: "info" 或 "vuln_scan" 或 "unknown"
    """
    if tool_name in INFO_COLLECTION_TOOLS:
        return "info"
    elif tool_name in VULN_SCAN_TOOLS:
        return "vuln_scan"
    return "unknown"


def get_tool_metadata(tool_name: str) -> Dict[str, Any]:
    """
    获取工具元数据
    
    Args:
        tool_name: 工具名称
        
    Returns:
        Dict: 工具元数据
    """
    metadata = get_info_tool_metadata(tool_name)
    if not metadata:
        metadata = get_vuln_tool_metadata(tool_name)
    return metadata


def initialize_tools() -> None:
    """
    初始化所有工具
    
    注册所有信息收集和漏洞扫描工具到全局注册表。
    """
    from .registry import registry
    
    logger.info("开始初始化工具...")
    
    info_count = 0
    for tool_name in INFO_COLLECTION_TOOLS:
        metadata = get_info_tool_metadata(tool_name)
        if metadata:
            registry.tool_metadata[tool_name] = metadata
            info_count += 1
    
    vuln_count = 0
    for tool_name in VULN_SCAN_TOOLS:
        metadata = get_vuln_tool_metadata(tool_name)
        if metadata:
            registry.tool_metadata[tool_name] = metadata
            vuln_count += 1
    
    logger.info(f"工具初始化完成: 信息收集 {info_count} 个, 漏洞扫描 {vuln_count} 个")


__all__ = [
    'AsyncToolWrapper',
    'wrap_async',
    'INFO_COLLECTION_TOOLS',
    'VULN_SCAN_TOOLS',
    'ALL_TOOLS',
    'get_all_tools',
    'get_tool_category',
    'get_tool_metadata',
    'initialize_tools',
    'get_info_tools',
    'get_vuln_tools',
]
