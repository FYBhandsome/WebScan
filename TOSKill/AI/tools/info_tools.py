"""
信息收集工具注册

定义和注册所有信息收集工具。
"""
from typing import Dict, Any, List

INFO_COLLECTION_TOOLS = [
    "baseinfo",
    "portscan",
    "waf_detect",
    "cdn_detect",
    "cms_identify",
    "subdomain_scan",
    "webside_scan",
    "webweight_scan",
    "iplocating",
    "infoleak_scan",
    "dirscan",
    "loginfo",
    "randheader",
    "crawler"
]

INFO_TOOL_METADATA: Dict[str, Dict[str, Any]] = {
    "baseinfo": {
        "name": "baseinfo",
        "description": "基础信息收集，获取服务器、IP、域名等信息",
        "category": "info",
        "timeout": 60,
        "priority": 10,
        "tags": ["recon", "info"]
    },
    "portscan": {
        "name": "portscan",
        "description": "端口扫描，检测开放端口和服务",
        "category": "info",
        "timeout": 120,
        "priority": 9,
        "tags": ["recon", "network"]
    },
    "waf_detect": {
        "name": "waf_detect",
        "description": "WAF检测，识别Web应用防火墙",
        "category": "info",
        "timeout": 60,
        "priority": 8,
        "tags": ["recon", "security"]
    },
    "cdn_detect": {
        "name": "cdn_detect",
        "description": "CDN检测，判断是否使用CDN",
        "category": "info",
        "timeout": 30,
        "priority": 7,
        "tags": ["recon", "network"]
    },
    "cms_identify": {
        "name": "cms_identify",
        "description": "CMS识别，检测网站使用的CMS系统",
        "category": "info",
        "timeout": 60,
        "priority": 9,
        "tags": ["recon", "cms"]
    },
    "subdomain_scan": {
        "name": "subdomain_scan",
        "description": "子域名扫描，发现目标的子域名",
        "category": "info",
        "timeout": 120,
        "priority": 7,
        "tags": ["recon", "domain"]
    },
    "webside_scan": {
        "name": "webside_scan",
        "description": "站点信息扫描，获取旁站信息",
        "category": "info",
        "timeout": 60,
        "priority": 6,
        "tags": ["recon", "domain"]
    },
    "webweight_scan": {
        "name": "webweight_scan",
        "description": "网站权重查询，获取百度/谷歌权重",
        "category": "info",
        "timeout": 30,
        "priority": 5,
        "tags": ["recon", "seo"]
    },
    "iplocating": {
        "name": "iplocating",
        "description": "IP定位，查询IP地理位置",
        "category": "info",
        "timeout": 30,
        "priority": 6,
        "tags": ["recon", "geo"]
    },
    "infoleak_scan": {
        "name": "infoleak_scan",
        "description": "信息泄露扫描，检测敏感信息泄露",
        "category": "info",
        "timeout": 60,
        "priority": 7,
        "tags": ["recon", "security"]
    },
    "dirscan": {
        "name": "dirscan",
        "description": "目录扫描，发现隐藏目录和文件",
        "category": "info",
        "timeout": 180,
        "priority": 6,
        "tags": ["recon", "directory"]
    },
    "loginfo": {
        "name": "loginfo",
        "description": "日志处理，配置日志处理器",
        "category": "info",
        "timeout": 30,
        "priority": 3,
        "tags": ["utility", "logging"]
    },
    "randheader": {
        "name": "randheader",
        "description": "随机请求头生成，生成随机HTTP头",
        "category": "info",
        "timeout": 30,
        "priority": 4,
        "tags": ["utility", "http"]
    },
    "crawler": {
        "name": "crawler",
        "description": "Web爬虫，爬取网站页面和链接",
        "category": "info",
        "timeout": 300,
        "priority": 5,
        "tags": ["recon", "crawler"]
    }
}


def get_info_tools() -> List[str]:
    """获取所有信息收集工具名称"""
    return INFO_COLLECTION_TOOLS.copy()


def get_info_tool_metadata(tool_name: str) -> Dict[str, Any]:
    """获取信息收集工具元数据"""
    return INFO_TOOL_METADATA.get(tool_name, {})


def get_all_info_metadata() -> Dict[str, Dict[str, Any]]:
    """获取所有信息收集工具元数据"""
    return INFO_TOOL_METADATA.copy()
