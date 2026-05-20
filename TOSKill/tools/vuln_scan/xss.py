# -*- coding:utf-8 -*-
"""
XSS跨站脚本漏洞扫描工具
封装backend.vulnerability_scan_plugins.xss模块
"""

from typing import Dict, Any, Optional


def xss_scan(
    target: str,
    timeout: int = 10,
    max_payloads: int = 30,
    delay: float = 0.1,
    cookies: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    auth_token: Optional[str] = None
) -> Dict[str, Any]:
    """XSS跨站脚本漏洞扫描工具，检测目标URL是否存在XSS漏洞
    
    检测能力：
    - 反射型XSS检测
    - DOM型XSS检测
    - 各种编码绕过测试（URL、HTML实体、Unicode）
    - 事件处理器payload测试（20+类型）
    - SVG/MathML payload测试
    - 支持认证扫描
    
    Args:
        target: 目标URL地址
        timeout: 请求超时时间(秒)，默认10秒
        max_payloads: 最大测试Payload数量，默认30
        delay: 请求间隔时间(秒)，默认0.1秒
        cookies: 认证Cookie字典
        headers: 自定义请求头字典
        auth_token: Bearer Token认证
        
    Returns:
        包含扫描结果的字典，包括：
        - success: 执行状态(True/False)
        - data: 扫描结果数据（包含完整漏洞信息、请求响应日志）
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
        
        if cookies or headers or auth_token:
            scanner.set_authentication(
                cookies=cookies,
                headers=headers,
                auth_token=auth_token
            )
        
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
                "cvss_score": vuln.cvss_score,
                "solution": vuln.solution,
                "request_data": vuln.request_data,
                "response_data": vuln.response_data,
                "discovered_at": vuln.discovered_at
            })
        
        return {
            "success": result.success,
            "data": {
                "target": result.target,
                "vulnerabilities": vulnerabilities,
                "vulnerability_count": len(vulnerabilities),
                "scan_duration": result.scan_duration,
                "requests_made": result.requests_made,
                "tested_endpoints": result.tested_endpoints,
                "request_response_log": result.request_response_log[-20:] if result.request_response_log else [],
                "detailed_evidence": result.detailed_evidence,
                "metadata": result.metadata
            },
            "error": result.error_message or "",
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
            "data": {},
            "error": f"导入xss模块失败: {str(e)}",
            "metadata": {"tool": "xss_scan", "target": target}
        }
    except Exception as e:
        return {
            "success": False,
            "data": {},
            "error": f"执行xss_scan工具异常: {str(e)}",
            "metadata": {"tool": "xss_scan", "target": target}
        }


if __name__ == "__main__":
    import json
    test_result = xss_scan.invoke({"target": "http://testphp.vulnweb.com/search.php?test=query"})
    print(json.dumps(test_result, indent=2, ensure_ascii=False))
