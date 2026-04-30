# -*- coding:utf-8 -*-
"""
POC验证工具模块
包含所有POC验证相关的LangChain工具
"""

from .struts2 import struts2_s2_032
from .thinkphp import thinkphp_rce
from .weblogic import weblogic_cve_2020_2551

__all__ = [
    "struts2_s2_032",
    "thinkphp_rce",
    "weblogic_cve_2020_2551",
    "POC_TOOLS"
]

POC_TOOLS = [
    struts2_s2_032,
    thinkphp_rce,
    weblogic_cve_2020_2551,
]
