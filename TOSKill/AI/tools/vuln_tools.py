"""
漏洞扫描工具注册

定义和注册所有漏洞扫描工具。
包含新增的深度检测节点元数据。
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
    "vuln_infoleak_scan",
    "sensitive_info_leak",
    "sqli_deep_scan",
    "xss_deep_scan",
    "ssrf_scan_node",
    "file_upload_scan"
]

VULN_TOOL_METADATA: Dict[str, Dict[str, Any]] = {
    "sqli_scan": {
        "name": "sqli_scan",
        "description": "SQL注入扫描，检测SQL注入漏洞",
        "category": "vuln_scan",
        "timeout": 120,
        "priority": 9,
        "tags": ["vuln", "injection", "sqli"],
        "vuln_type": "sql_injection",
        "input": {"target": "目标URL", "params": "可选的参数列表"},
        "output": {"vulnerabilities": "发现的SQL注入漏洞"}
    },
    "xss_scan": {
        "name": "xss_scan",
        "description": "XSS扫描，检测跨站脚本漏洞",
        "category": "vuln_scan",
        "timeout": 120,
        "priority": 8,
        "tags": ["vuln", "xss"],
        "vuln_type": "xss",
        "input": {"target": "目标URL", "params": "可选的参数列表"},
        "output": {"vulnerabilities": "发现的XSS漏洞"}
    },
    "csrf_scan": {
        "name": "csrf_scan",
        "description": "CSRF扫描，检测跨站请求伪造漏洞",
        "category": "vuln_scan",
        "timeout": 60,
        "priority": 7,
        "tags": ["vuln", "csrf"],
        "vuln_type": "csrf",
        "input": {"target": "目标URL"},
        "output": {"vulnerabilities": "发现的CSRF漏洞"}
    },
    "fileupload_scan": {
        "name": "fileupload_scan",
        "description": "文件上传漏洞扫描，检测恶意文件上传",
        "category": "vuln_scan",
        "timeout": 120,
        "priority": 8,
        "tags": ["vuln", "upload"],
        "vuln_type": "file_upload",
        "input": {"target": "目标URL", "endpoints": "可选的上传端点列表"},
        "output": {"vulnerabilities": "发现的文件上传漏洞"}
    },
    "cmdi_scan": {
        "name": "cmdi_scan",
        "description": "命令注入扫描，检测OS命令注入漏洞",
        "category": "vuln_scan",
        "timeout": 180,
        "priority": 9,
        "tags": ["vuln", "injection", "rce"],
        "vuln_type": "command_injection",
        "input": {"target": "目标URL", "params": "可选的参数列表"},
        "output": {"vulnerabilities": "发现的命令注入漏洞"}
    },
    "lfi_scan": {
        "name": "lfi_scan",
        "description": "本地文件包含扫描，检测LFI漏洞",
        "category": "vuln_scan",
        "timeout": 180,
        "priority": 8,
        "tags": ["vuln", "lfi", "inclusion"],
        "vuln_type": "lfi",
        "input": {"target": "目标URL", "params": "可选的参数列表"},
        "output": {"vulnerabilities": "发现的LFI漏洞"}
    },
    "ssrf_scan": {
        "name": "ssrf_scan",
        "description": "SSRF扫描，检测服务器端请求伪造漏洞",
        "category": "vuln_scan",
        "timeout": 180,
        "priority": 8,
        "tags": ["vuln", "ssrf"],
        "vuln_type": "ssrf",
        "input": {"target": "目标URL", "params": "可选的参数列表"},
        "output": {"vulnerabilities": "发现的SSRF漏洞"}
    },
    "weakpass_scan": {
        "name": "weakpass_scan",
        "description": "弱口令扫描，检测常见弱密码",
        "category": "vuln_scan",
        "timeout": 300,
        "priority": 6,
        "tags": ["vuln", "password"],
        "vuln_type": "weak_password",
        "input": {"target": "目标URL", "username": "可选的用户名"},
        "output": {"vulnerabilities": "发现的弱口令"}
    },
    "vuln_infoleak_scan": {
        "name": "vuln_infoleak_scan",
        "description": "敏感信息泄露扫描，检测敏感数据泄露",
        "category": "vuln_scan",
        "timeout": 60,
        "priority": 7,
        "tags": ["vuln", "infoleak"],
        "vuln_type": "sensitive_info",
        "input": {"target": "目标URL"},
        "output": {"vulnerabilities": "发现的信息泄露"}
    },
    "sensitive_info_leak": {
        "name": "sensitive_info_leak",
        "description": "敏感信息泄露检测节点，通过正则匹配发现暴露的敏感数据",
        "category": "vuln_scan",
        "timeout": 120,
        "priority": 8,
        "tags": ["vuln", "infoleak", "security"],
        "vuln_type": "sensitive_info",
        "input": {
            "target": "目标URL",
            "context": "可选的上下文信息"
        },
        "output": {
            "leaks": "发现的敏感信息",
            "vulnerabilities": "安全问题列表"
        },
        "node_class": "SensitiveInfoLeakNode",
        "patterns": ["email", "phone_cn", "id_card_cn", "api_key", "aws_key", "private_key", "password", "jwt", "credit_card", "ip_address"]
    },
    "sqli_deep_scan": {
        "name": "sqli_deep_scan",
        "description": "SQL注入深度检测节点，检测错误注入、时间盲注等多种类型",
        "category": "vuln_scan",
        "timeout": 300,
        "priority": 10,
        "tags": ["vuln", "injection", "sqli", "deep_scan"],
        "vuln_type": "sql_injection",
        "input": {
            "target": "目标URL",
            "context": "可选的上下文信息(包括参数列表)"
        },
        "output": {
            "injection_points": "发现的注入点",
            "vulnerabilities": "SQL注入漏洞列表"
        },
        "node_class": "SQLInjectionDeepNode",
        "injection_types": ["error_based", "time_based", "union_based", "boolean_based"]
    },
    "xss_deep_scan": {
        "name": "xss_deep_scan",
        "description": "XSS深度检测节点，检测反射型、存储型XSS，支持多种上下文检测",
        "category": "vuln_scan",
        "timeout": 300,
        "priority": 9,
        "tags": ["vuln", "xss", "deep_scan"],
        "vuln_type": "xss",
        "input": {
            "target": "目标URL",
            "context": "可选的上下文信息"
        },
        "output": {
            "xss_points": "发现的XSS注入点",
            "vulnerabilities": "XSS漏洞列表"
        },
        "node_class": "XSSDeepScanNode",
        "xss_types": ["reflected", "stored", "dom_based"],
        "contexts": ["html", "attribute", "javascript", "url"]
    },
    "ssrf_scan_node": {
        "name": "ssrf_scan_node",
        "description": "SSRF检测节点，检测云元数据访问、内部服务探测等SSRF漏洞",
        "category": "vuln_scan",
        "timeout": 180,
        "priority": 9,
        "tags": ["vuln", "ssrf", "security"],
        "vuln_type": "ssrf",
        "input": {
            "target": "目标URL",
            "context": "可选的上下文信息"
        },
        "output": {
            "ssrf_points": "发现的SSRF注入点",
            "vulnerabilities": "SSRF漏洞列表"
        },
        "node_class": "SSRFScanNode",
        "protocols": ["http", "file", "dict", "gopher"]
    },
    "file_upload_scan": {
        "name": "file_upload_scan",
        "description": "文件上传漏洞检测节点，检测多种绕过方式的恶意文件上传",
        "category": "vuln_scan",
        "timeout": 180,
        "priority": 10,
        "tags": ["vuln", "upload", "security"],
        "vuln_type": "file_upload",
        "input": {
            "target": "目标URL",
            "context": "可选的上下文信息"
        },
        "output": {
            "upload_points": "发现的上传点",
            "vulnerabilities": "文件上传漏洞列表"
        },
        "node_class": "FileUploadScanNode",
        "bypass_methods": ["double_extension", "null_byte", "content_type", "alternative_extensions"]
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
