# -*- coding:utf-8 -*-
"""
命令注入漏洞扫描工具
使用@tool装饰器封装backend.vulnerability_scan_plugins.cmdi模块
"""

from langchain.tools import tool
from typing import Dict, Any


@tool
def cmdi_scan(
    target: str,
    timeout: int = 30
) -> Dict[str, Any]:
    """命令注入漏洞扫描工具，检测目标URL是否存在命令注入漏洞
    
    检测能力：
    - GET/POST参数命令注入
    - HTTP头命令注入
    - Cookie命令注入
    - 时间盲注检测
    - 回显检测
    
    Args:
        target: 目标URL地址
        timeout: 请求超时时间(秒)，默认30秒
        
    Returns:
        包含扫描结果的字典，包括：
        - success: 执行状态(True/False)
        - data: 扫描结果数据
        - error: 错误信息(成功时为None)
        - metadata: 元数据(工具名称、目标、漏洞数量等)
    """
    try:
        from backend.vulnerability_scan_plugins.cmdi.scanner import CmdiScanner
        
        config = {
            "timeout": timeout
        }
        
        scanner = CmdiScanner(target, config)
        result = scanner.scan()
        
        vulnerabilities = []
        for vuln in result.vulnerabilities:
            vulnerabilities.append({
                "vuln_type": vuln.vuln_type.value,
                "url": vuln.url,
                "severity": vuln.severity.value,
                "title": vuln.title,
                "description": vuln.description,
                "parameter": vuln.parameter,
                "payload": vuln.payload,
                "evidence": vuln.evidence
            })
        
        return {
            "success": result.success,
            "data": {
                "target": result.target,
                "vulnerabilities": vulnerabilities,
                "vulnerability_count": len(vulnerabilities),
                "scan_duration": result.scan_duration,
                "metadata": result.metadata
            },
            "error": result.error_message,
            "metadata": {
                "tool": "cmdi_scan",
                "target": target,
                "plugin_name": result.plugin_name,
                "vulnerability_count": len(vulnerabilities)
            }
        }
    except ImportError as e:
        return {
            "success": False,
            "data": None,
            "error": f"导入cmdi模块失败: {str(e)}",
            "metadata": {"tool": "cmdi_scan", "target": target}
        }
    except Exception as e:
        return {
            "success": False,
            "data": None,
            "error": f"执行cmdi_scan工具异常: {str(e)}",
            "metadata": {"tool": "cmdi_scan", "target": target}
        }


if __name__ == "__main__":
    test_result = cmdi_scan.invoke("http://testphp.vulnweb.com")
    print(test_result)
