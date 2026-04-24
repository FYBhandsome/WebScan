# -*- coding:utf-8 -*-
"""
POC验证工具模块
包含所有POC验证相关的LangChain工具
"""

from .drupal import drupal_cve_2018_7600
from .jboss import jboss_cve_2017_12149
from .nexus import nexus_cve_2020_10199
from .struts2 import struts2_s2_009, struts2_s2_032
from .thinkphp import thinkphp_rce, thinkphp_cmd_rce
from .tomcat import tomcat_cve_2017_12615
from .weblogic import (
    weblogic_cve_2018_2628,
    weblogic_cve_2018_2894,
    weblogic_cve_2020_2551,
    weblogic_cve_2023_21839
)

__all__ = [
    "drupal_cve_2018_7600",
    "jboss_cve_2017_12149",
    "nexus_cve_2020_10199",
    "struts2_s2_009",
    "struts2_s2_032",
    "thinkphp_rce",
    "thinkphp_cmd_rce",
    "tomcat_cve_2017_12615",
    "weblogic_cve_2018_2628",
    "weblogic_cve_2018_2894",
    "weblogic_cve_2020_2551",
    "weblogic_cve_2023_21839",
    "POC_TOOLS"
]

POC_TOOLS = [
    drupal_cve_2018_7600,
    jboss_cve_2017_12149,
    nexus_cve_2020_10199,
    struts2_s2_009,
    struts2_s2_032,
    thinkphp_rce,
    thinkphp_cmd_rce,
    tomcat_cve_2017_12615,
    weblogic_cve_2018_2628,
    weblogic_cve_2018_2894,
    weblogic_cve_2020_2551,
    weblogic_cve_2023_21839,
]
