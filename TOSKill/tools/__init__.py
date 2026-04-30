# -*- coding:utf-8 -*-
"""
TOSKill工具模块
整合所有安全测试工具，提供统一的工具注册和查找接口
"""

from TOSKill.tools.info_collection import INFO_COLLECTION_TOOLS
from TOSKill.tools.poc import POC_TOOLS
from TOSKill.tools.vuln_scan import VULN_SCAN_TOOLS
from TOSKill.tools.report import REPORT_TOOLS

ALL_TOOLS = INFO_COLLECTION_TOOLS + POC_TOOLS + VULN_SCAN_TOOLS + REPORT_TOOLS

TOOLS_BY_CATEGORY = {
    "info_collection": INFO_COLLECTION_TOOLS,
    "poc": POC_TOOLS,
    "vuln_scan": VULN_SCAN_TOOLS,
    "report": REPORT_TOOLS,
}

TOOL_CATEGORIES = list(TOOLS_BY_CATEGORY.keys())

TOOL_COUNT = {
    "info_collection": len(INFO_COLLECTION_TOOLS),
    "poc": len(POC_TOOLS),
    "vuln_scan": len(VULN_SCAN_TOOLS),
    "report": len(REPORT_TOOLS),
    "total": len(ALL_TOOLS),
}

__all__ = [
    "INFO_COLLECTION_TOOLS",
    "POC_TOOLS",
    "VULN_SCAN_TOOLS",
    "REPORT_TOOLS",
    "ALL_TOOLS",
    "TOOLS_BY_CATEGORY",
    "TOOL_CATEGORIES",
    "TOOL_COUNT",
]
