# -*- coding:utf-8 -*-
"""
XSS跨站脚本漏洞扫描工具
使用@tool装饰器封装backend.vulnerability_scan_plugins.xss模块
"""

from langchain.tools import tool
from typing import Dict, Any


@tool
def xss_scan(
    target: str,
    timeout: int = 10,
    max_payloads: int = 30,
    delay: float = 0.1
) -> Dict[str, Any]:
    """XSS跨站脚本漏洞扫描工具，检测目标URL是否存在XSS漏洞
    
    检测能力：
    - 反射型XSS检测
    - DOM型XSS检测(基础)
    - 各种编码绕过测试
    
    Args:
        target: 目标URL地址
        timeout: 请求超时时间(秒)，默认10秒
        max_payloads: 最大测试Payload数量，默认30
        delay: 请求间隔时间(秒)，默认0.1秒
        
    Returns:
        包含扫描结果的字典，包括：
        - success: 执行状态(True/False)
        - data: 扫描结果数据
        - error: 错误信息(成功时为None)
        - metadata: 元数据(工具名称、目标、漏洞数量等)
    """
    try:
        from backend.vulnerability_scan_plugins.xss.scanner import XSSScanner
        
        config = {
            "timeout": timeout,
            "max_payloads": max_payloads,
            "delay": delay
        }
        
        scanner = XSSScanner(target, config)
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
                "method": vuln.method,
                "payload": vuln.payload,
                "evidence": vuln.evidence,
                "confidence": vuln.confidence,
                "cwe_id": vuln.cwe_id,
                "solution": vuln.solution
            })
        
        return {
            "success": result.success,
            "data": {
                "target": result.target,
                "vulnerabilities": vulnerabilities,
                "vulnerability_count": len(vulnerabilities),
                "scan_duration": result.scan_duration,
                "requests_made": result.requests_made,
                "metadata": result.metadata
            },
            "error": result.error_message,
            "metadata": {
                "tool": "xss_scan",
                "target": target,
                "plugin_name": result.plugin_name,
                "vulnerability_count": len(vulnerabilities)
            }
        }
    except ImportError as e:
        return {
            "success": False,
            "data": None,
            "error": f"导入xss模块失败: {str(e)}",
            "metadata": {"tool": "xss_scan", "target": target}
        }
    except Exception as e:
        return {
            "success": False,
            "data": None,
            "error": f"执行xss_scan工具异常: {str(e)}",
            "metadata": {"tool": "xss_scan", "target": target}
        }


if __name__ == "__main__":
    test_result = xss_scan.invoke("http://testphp.vulnweb.com/search.php?test=query")
    print(test_result)
