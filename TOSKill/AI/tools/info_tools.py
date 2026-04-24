"""
信息收集工具注册

定义和注册所有信息收集工具。
包含新增的安全检测节点元数据。
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
    "crawler",
    "port_scan",
    "subdomain_enum",
    "dir_scan",
    "ssl_certificate"
]

INFO_TOOL_METADATA: Dict[str, Dict[str, Any]] = {
    "baseinfo": {
        "name": "baseinfo",
        "description": "基础信息收集，获取服务器、IP、域名等信息",
        "category": "info",
        "timeout": 60,
        "priority": 10,
        "tags": ["recon", "info"],
        "input": {"target": "目标域名或IP地址", "context": "可选的上下文信息"},
        "output": {"server": "服务器信息", "ip": "IP地址", "domain": "域名", "headers": "HTTP头"}
    },
    "portscan": {
        "name": "portscan",
        "description": "端口扫描，检测开放端口和服务",
        "category": "info",
        "timeout": 120,
        "priority": 9,
        "tags": ["recon", "network"],
        "input": {"target": "目标域名或IP地址"},
        "output": {"open_ports": "开放端口列表", "services": "服务信息"}
    },
    "waf_detect": {
        "name": "waf_detect",
        "description": "WAF检测，识别Web应用防火墙",
        "category": "info",
        "timeout": 60,
        "priority": 8,
        "tags": ["recon", "security"],
        "input": {"target": "目标URL"},
        "output": {"waf": "WAF类型", "has_waf": "是否存在WAF"}
    },
    "cdn_detect": {
        "name": "cdn_detect",
        "description": "CDN检测，判断是否使用CDN",
        "category": "info",
        "timeout": 30,
        "priority": 7,
        "tags": ["recon", "network"],
        "input": {"target": "目标域名"},
        "output": {"is_cdn": "是否使用CDN", "cdn_provider": "CDN提供商"}
    },
    "cms_identify": {
        "name": "cms_identify",
        "description": "CMS识别，检测网站使用的CMS系统",
        "category": "info",
        "timeout": 60,
        "priority": 9,
        "tags": ["recon", "cms"],
        "input": {"target": "目标URL"},
        "output": {"cms": "CMS类型", "version": "CMS版本"}
    },
    "subdomain_scan": {
        "name": "subdomain_scan",
        "description": "子域名扫描，发现目标的子域名",
        "category": "info",
        "timeout": 120,
        "priority": 7,
        "tags": ["recon", "domain"],
        "input": {"target": "主域名"},
        "output": {"subdomains": "子域名列表"}
    },
    "webside_scan": {
        "name": "webside_scan",
        "description": "站点信息扫描，获取旁站信息",
        "category": "info",
        "timeout": 60,
        "priority": 6,
        "tags": ["recon", "domain"],
        "input": {"target": "目标IP"},
        "output": {"side_domains": "旁站列表"}
    },
    "webweight_scan": {
        "name": "webweight_scan",
        "description": "网站权重查询，获取百度/谷歌权重",
        "category": "info",
        "timeout": 30,
        "priority": 5,
        "tags": ["recon", "seo"],
        "input": {"target": "目标域名"},
        "output": {"baidu_weight": "百度权重", "google_weight": "谷歌权重"}
    },
    "iplocating": {
        "name": "iplocating",
        "description": "IP定位，查询IP地理位置",
        "category": "info",
        "timeout": 30,
        "priority": 6,
        "tags": ["recon", "geo"],
        "input": {"target": "IP地址"},
        "output": {"location": "地理位置"}
    },
    "infoleak_scan": {
        "name": "infoleak_scan",
        "description": "信息泄露扫描，检测敏感信息泄露",
        "category": "info",
        "timeout": 60,
        "priority": 7,
        "tags": ["recon", "security"],
        "input": {"target": "目标URL"},
        "output": {"leaks": "泄露信息列表"}
    },
    "dirscan": {
        "name": "dirscan",
        "description": "目录扫描，发现隐藏目录和文件",
        "category": "info",
        "timeout": 180,
        "priority": 6,
        "tags": ["recon", "directory"],
        "input": {"target": "目标URL"},
        "output": {"directories": "目录列表", "files": "文件列表"}
    },
    "loginfo": {
        "name": "loginfo",
        "description": "日志处理，配置日志处理器",
        "category": "info",
        "timeout": 30,
        "priority": 3,
        "tags": ["utility", "logging"],
        "input": {"config": "日志配置"},
        "output": {"status": "配置状态"}
    },
    "randheader": {
        "name": "randheader",
        "description": "随机请求头生成，生成随机HTTP头",
        "category": "info",
        "timeout": 30,
        "priority": 4,
        "tags": ["utility", "http"],
        "input": {},
        "output": {"headers": "随机HTTP头"}
    },
    "crawler": {
        "name": "crawler",
        "description": "Web爬虫，爬取网站页面和链接",
        "category": "info",
        "timeout": 300,
        "priority": 5,
        "tags": ["recon", "crawler"],
        "input": {"target": "目标URL", "depth": "爬取深度"},
        "output": {"pages": "页面列表", "links": "链接列表"}
    },
    "port_scan": {
        "name": "port_scan",
        "description": "端口扫描节点，检测开放端口和服务版本，支持异步并发扫描",
        "category": "recon",
        "timeout": 180,
        "priority": 9,
        "tags": ["recon", "network", "security"],
        "input": {
            "target": "目标域名或IP地址",
            "context": "可选的上下文信息"
        },
        "output": {
            "open_ports": "开放端口列表",
            "services": "端口服务信息",
            "vulnerabilities": "发现的安全问题"
        },
        "node_class": "PortScanNode"
    },
    "subdomain_enum": {
        "name": "subdomain_enum",
        "description": "子域名枚举节点，通过DNS暴力破解发现子域名",
        "category": "recon",
        "timeout": 300,
        "priority": 7,
        "tags": ["recon", "domain", "security"],
        "input": {
            "target": "主域名",
            "context": "可选的上下文信息"
        },
        "output": {
            "subdomains": "发现的子域名列表",
            "ips": "子域名对应的IP地址",
            "vulnerabilities": "发现的安全问题"
        },
        "node_class": "SubdomainEnumNode"
    },
    "dir_scan": {
        "name": "dir_scan",
        "description": "目录扫描节点，发现隐藏目录和敏感文件",
        "category": "recon",
        "timeout": 300,
        "priority": 6,
        "tags": ["recon", "directory", "security"],
        "input": {
            "target": "目标URL",
            "context": "可选的上下文信息"
        },
        "output": {
            "directories": "发现的目录列表",
            "files": "发现的敏感文件",
            "vulnerabilities": "发现的安全问题"
        },
        "node_class": "DirScanNode"
    },
    "ssl_certificate": {
        "name": "ssl_certificate",
        "description": "SSL证书检测节点，验证证书有效性和安全性",
        "category": "security",
        "timeout": 60,
        "priority": 8,
        "tags": ["security", "ssl", "certificate"],
        "input": {
            "target": "目标域名",
            "context": "可选的上下文信息"
        },
        "output": {
            "certificate": "SSL证书信息",
            "vulnerabilities": "证书相关的安全问题"
        },
        "node_class": "SSLCertificateNode"
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
