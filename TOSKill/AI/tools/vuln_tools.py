"""
漏洞扫描工具注册

定义和注册所有漏洞扫描工具。
"""
from typing import Dict, Any, List

VULN_SCAN_TOOLS = [
    "sqli_scan",
    "xss_scan",
    "csrf_scan",
    "fileupload_scan",
    "cmdi_scan",
    "lfi_scan",
    "ssrf_scan",
    "weakpass_scan",
    "vuln_infoleak_scan"
]

VULN_TOOL_METADATA: Dict[str, Dict[str, Any]] = {
    "sqli_scan": {
        "name": "sqli_scan",
        "description": "SQL注入扫描，检测SQL注入漏洞",
        "category": "vuln_scan",
        "timeout": 120,
        "priority": 9,
        "tags": ["vuln", "injection", "sqli"],
        "vuln_type": "sql_injection"
    },
    "xss_scan": {
        "name": "xss_scan",
        "description": "XSS扫描，检测跨站脚本漏洞",
        "category": "vuln_scan",
        "timeout": 120,
        "priority": 8,
        "tags": ["vuln", "xss"],
        "vuln_type": "xss"
    },
    "csrf_scan": {
        "name": "csrf_scan",
        "description": "CSRF扫描，检测跨站请求伪造漏洞",
        "category": "vuln_scan",
        "timeout": 60,
        "priority": 7,
        "tags": ["vuln", "csrf"],
        "vuln_type": "csrf"
    },
    "fileupload_scan": {
        "name": "fileupload_scan",
        "description": "文件上传漏洞扫描，检测恶意文件上传",
        "category": "vuln_scan",
        "timeout": 120,
        "priority": 8,
        "tags": ["vuln", "upload"],
        "vuln_type": "file_upload"
    },
    "cmdi_scan": {
        "name": "cmdi_scan",
        "description": "命令注入扫描，检测OS命令注入漏洞",
        "category": "vuln_scan",
        "timeout": 180,
        "priority": 9,
        "tags": ["vuln", "injection", "rce"],
        "vuln_type": "command_injection"
    },
    "lfi_scan": {
        "name": "lfi_scan",
        "description": "本地文件包含扫描，检测LFI漏洞",
        "category": "vuln_scan",
        "timeout": 180,
        "priority": 8,
        "tags": ["vuln", "lfi", "inclusion"],
        "vuln_type": "lfi"
    },
    "ssrf_scan": {
        "name": "ssrf_scan",
        "description": "SSRF扫描，检测服务器端请求伪造漏洞",
        "category": "vuln_scan",
        "timeout": 180,
        "priority": 8,
        "tags": ["vuln", "ssrf"],
        "vuln_type": "ssrf"
    },
    "weakpass_scan": {
        "name": "weakpass_scan",
        "description": "弱口令扫描，检测常见弱密码",
        "category": "vuln_scan",
        "timeout": 300,
        "priority": 6,
        "tags": ["vuln", "password"],
        "vuln_type": "weak_password"
    },
    "vuln_infoleak_scan": {
        "name": "vuln_infoleak_scan",
        "description": "敏感信息泄露扫描，检测敏感数据泄露",
        "category": "vuln_scan",
        "timeout": 60,
        "priority": 7,
        "tags": ["vuln", "infoleak"],
        "vuln_type": "sensitive_info"
    }
}


def get_vuln_tools() -> List[str]:
    """获取所有漏洞扫描工具名称"""
    return VULN_SCAN_TOOLS.copy()


def get_vuln_tool_metadata(tool_name: str) -> Dict[str, Any]:
    """获取漏洞扫描工具元数据"""
    return VULN_TOOL_METADATA.get(tool_name, {})


def get_all_vuln_metadata() -> Dict[str, Dict[str, Any]]:
    """获取所有漏洞扫描工具元数据"""
    return VULN_TOOL_METADATA.copy()
