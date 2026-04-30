# -*- coding:utf-8 -*-
"""
报告生成工具模块

提供AI分析和漏洞分析等报告生成工具。
"""

from typing import List
import logging

from .ai_analyzer import ai_analyzer
from .vuln_analyzer import vuln_analyzer, vuln_analyzer_async

logger = logging.getLogger(__name__)

REPORT_TOOLS: List = [
    ai_analyzer,
    vuln_analyzer,
    vuln_analyzer_async,
]

__all__ = [
    "ai_analyzer",
    "vuln_analyzer",
    "vuln_analyzer_async",
    "REPORT_TOOLS",
]
