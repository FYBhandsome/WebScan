"""
TOSKill AI 工具注册模块

类比 demo.py，使用 @tool 装饰器注册所有工具。
提供统一的工具调用接口。
"""
from typing import Dict, Any, List
from langchain.tools import tool
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)


def clean_target(target: str) -> str:
    """URL 自动清洗 - 类比 demo.py"""
    parsed = urlparse(target)
    return parsed.netloc.strip() if parsed.netloc else target.strip()


# ==================== 信息收集工具 ====================

@tool
def baseinfo_scan(target: str) -> Dict:
    """基础信息收集 - 获取目标网站的基本信息"""
    from TOSKill.tools.info_collection.baseinfo import baseinfo
    t = clean_target(target)
    logger.info(f"[+] 执行基础信息收集：{t}")
    return baseinfo(t)


@tool
def port_scan(target: str) -> Dict:
    """端口扫描 - 扫描目标开放端口"""
    from TOSKill.tools.info_collection.portscan import portscan
    t = clean_target(target)
    logger.info(f"[+] 执行端口扫描：{t}")
    return portscan(t)


@tool
def subdomain_scan(target: str) -> Dict:
    """子域名扫描 - 发现目标的子域名"""
    from TOSKill.tools.info_collection.subdomain import subdomain
    t = clean_target(target)
    logger.info(f"[+] 执行子域名扫描：{t}")
    return subdomain(t)


@tool
def dir_brute(target: str) -> Dict:
    """目录扫描 - 发现目标的目录结构"""
    from TOSKill.tools.info_collection.dirscan import dirscan
    t = clean_target(target)
    logger.info(f"[+] 执行目录扫描：{t}")
    return dirscan(t)


@tool
def waf_detect_scan(target: str) -> Dict:
    """WAF检测 - 检测目标是否部署WAF"""
    from TOSKill.tools.info_collection.waf import waf_detect
    t = clean_target(target)
    logger.info(f"[+] 执行WAF检测：{t}")
    return waf_detect(t)


@tool
def cdn_detect_scan(target: str) -> Dict:
    """CDN检测 - 检测目标是否使用CDN"""
    from TOSKill.tools.info_collection.cdnexist import cdn_detect
    t = clean_target(target)
    logger.info(f"[+] 执行CDN检测：{t}")
    return cdn_detect(t)


@tool
def cms_detect_scan(target: str) -> Dict:
    """CMS识别 - 识别目标使用的CMS系统"""
    from TOSKill.tools.info_collection.whatcms import cms_detect
    t = clean_target(target)
    logger.info(f"[+] 执行CMS识别：{t}")
    return cms_detect(t)


@tool
def infoleak_scan(target: str) -> Dict:
    """信息泄露扫描 - 检测敏感信息泄露"""
    from TOSKill.tools.info_collection.infoleak import infoleak_scan as infoleak
    t = clean_target(target)
    logger.info(f"[+] 执行信息泄露扫描：{t}")
    return infoleak(t)


@tool
def ip_locate_scan(target: str) -> Dict:
    """IP定位 - 查询IP地理位置"""
    from TOSKill.tools.info_collection.iplocating import ip_locate
    t = clean_target(target)
    logger.info(f"[+] 执行IP定位：{t}")
    return ip_locate(t)


@tool
def webside_query_scan(target: str) -> Dict:
    """备案查询 - 查询网站备案信息"""
    from TOSKill.tools.info_collection.webside import webside_query
    t = clean_target(target)
    logger.info(f"[+] 执行备案查询：{t}")
    return webside_query(t)


@tool
def web_weight_scan(target: str) -> Dict:
    """权重查询 - 查询网站权重"""
    from TOSKill.tools.info_collection.webweight import web_weight
    t = clean_target(target)
    logger.info(f"[+] 执行权重查询：{t}")
    return web_weight(t)


# ==================== 漏洞扫描工具 ====================

@tool
def sqli_scan(target: str) -> Dict:
    """SQL注入扫描 - 检测SQL注入漏洞"""
    from TOSKill.tools.vuln_scan.sqli import sqli_scan as sqli
    t = clean_target(target)
    logger.info(f"[+] 执行SQL注入扫描：{t}")
    return sqli(t)


@tool
def xss_scan(target: str) -> Dict:
    """XSS扫描 - 检测跨站脚本漏洞"""
    from TOSKill.tools.vuln_scan.xss import xss_scan as xss
    t = clean_target(target)
    logger.info(f"[+] 执行XSS扫描：{t}")
    return xss(t)


@tool
def csrf_scan(target: str) -> Dict:
    """CSRF扫描 - 检测跨站请求伪造漏洞"""
    from TOSKill.tools.vuln_scan.csrf import csrf_scan as csrf
    t = clean_target(target)
    logger.info(f"[+] 执行CSRF扫描：{t}")
    return csrf(t)


@tool
def fileupload_scan(target: str) -> Dict:
    """文件上传扫描 - 检测文件上传漏洞"""
    from TOSKill.tools.vuln_scan.fileupload import fileupload_scan as fileupload
    t = clean_target(target)
    logger.info(f"[+] 执行文件上传扫描：{t}")
    return fileupload(t)


@tool
def cmdi_scan(target: str) -> Dict:
    """命令注入扫描 - 检测命令注入漏洞"""
    from TOSKill.tools.vuln_scan.cmdi import cmdi_scan as cmdi
    t = clean_target(target)
    logger.info(f"[+] 执行命令注入扫描：{t}")
    return cmdi(t)


@tool
def ssrf_scan(target: str) -> Dict:
    """SSRF扫描 - 检测服务端请求伪造漏洞"""
    from TOSKill.tools.vuln_scan.ssrf import ssrf_scan as ssrf
    t = clean_target(target)
    logger.info(f"[+] 执行SSRF扫描：{t}")
    return ssrf(t)


@tool
def lfi_scan(target: str) -> Dict:
    """LFI扫描 - 检测本地文件包含漏洞"""
    from TOSKill.tools.vuln_scan.lfi import lfi_scan as lfi
    t = clean_target(target)
    logger.info(f"[+] 执行LFI扫描：{t}")
    return lfi(t)


@tool
def weakpass_scan(target: str) -> Dict:
    """弱口令扫描 - 检测弱口令"""
    from TOSKill.tools.vuln_scan.weakpass import weakpass_scan as weakpass
    t = clean_target(target)
    logger.info(f"[+] 执行弱口令扫描：{t}")
    return weakpass(t)


# ==================== POC工具 ====================

@tool
def thinkphp_rce_scan(target: str) -> Dict:
    """ThinkPHP RCE - ThinkPHP远程代码执行检测"""
    from TOSKill.tools.poc.thinkphp import thinkphp_rce
    t = clean_target(target)
    logger.info(f"[+] 执行ThinkPHP RCE检测：{t}")
    return thinkphp_rce(t)


@tool
def struts2_scan(target: str) -> Dict:
    """Struts2漏洞 - Struts2系列漏洞检测"""
    from TOSKill.tools.poc.struts2 import struts2_s2_032
    t = clean_target(target)
    logger.info(f"[+] 执行Struts2漏洞检测：{t}")
    return struts2_s2_032(t)


@tool
def weblogic_scan(target: str) -> Dict:
    """WebLogic漏洞 - WebLogic系列漏洞检测"""
    from TOSKill.tools.poc.weblogic import weblogic_cve_2020_2551
    t = clean_target(target)
    logger.info(f"[+] 执行WebLogic漏洞检测：{t}")
    return weblogic_cve_2020_2551(t)


# ==================== 工具注册表 ====================

INFO_COLLECTION_TOOLS = [
    baseinfo_scan,
    port_scan,
    subdomain_scan,
    dir_brute,
    waf_detect_scan,
    cdn_detect_scan,
    cms_detect_scan,
    infoleak_scan,
    ip_locate_scan,
    webside_query_scan,
    web_weight_scan,
]

VULN_SCAN_TOOLS = [
    sqli_scan,
    xss_scan,
    csrf_scan,
    fileupload_scan,
    cmdi_scan,
    ssrf_scan,
    lfi_scan,
    weakpass_scan,
]

POC_TOOLS = [
    thinkphp_rce_scan,
    struts2_scan,
    weblogic_scan,
]

ALL_TOOLS = INFO_COLLECTION_TOOLS + VULN_SCAN_TOOLS + POC_TOOLS

TOOL_MAP = {t.name: t for t in ALL_TOOLS}

TOOL_SEQUENCE_INFO = [
    "baseinfo_scan",
    "port_scan",
    "subdomain_scan",
    "dir_brute",
    "waf_detect_scan",
    "cdn_detect_scan",
    "cms_detect_scan",
    "infoleak_scan",
    "ip_locate_scan",
    "webside_query_scan",
    "web_weight_scan",
]

TOOL_SEQUENCE_VULN = [
    "sqli_scan",
    "xss_scan",
    "csrf_scan",
    "fileupload_scan",
    "cmdi_scan",
    "ssrf_scan",
    "lfi_scan",
    "weakpass_scan",
]


def get_tool_by_name(name: str):
    """根据名称获取工具"""
    return TOOL_MAP.get(name)


def get_all_tool_names() -> List[str]:
    """获取所有工具名称"""
    return list(TOOL_MAP.keys())


def get_tools_by_mode(mode: str) -> List:
    """根据模式获取工具列表"""
    if mode == "info_collection":
        return INFO_COLLECTION_TOOLS
    elif mode == "vuln_scan":
        return VULN_SCAN_TOOLS
    elif mode == "full_scan":
        return ALL_TOOLS
    return INFO_COLLECTION_TOOLS


def get_tool_sequence(mode: str) -> List[str]:
    """获取工具执行序列"""
    if mode == "info_collection":
        return TOOL_SEQUENCE_INFO
    elif mode == "vuln_scan":
        return TOOL_SEQUENCE_VULN
    elif mode == "full_scan":
        return TOOL_SEQUENCE_INFO + TOOL_SEQUENCE_VULN
    return TOOL_SEQUENCE_INFO
