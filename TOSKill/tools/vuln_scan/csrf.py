# -*- coding:utf-8 -*-
"""
CSRF跨站请求伪造漏洞扫描工具
封装backend.vulnerability_scan_plugins.csrf模块
"""

from typing import Dict, Any


def csrf_scan(
    target: str,
    timeout: int = 10
) -> Dict[str, Any]:
    """CSRF跨站请求伪造漏洞扫描工具，检测目标URL是否存在CSRF漏洞
    
    检测能力：
    - CSRF令牌检测
    - Referer验证检测
    - 表单自动提交检测
    
    Args:
        target: 目标URL地址
        timeout: 请求超时时间(秒)，默认10秒
        
    Returns:
        包含扫描结果的字典，包括：
        - success: 执行状态(True/False)
        - data: 扫描结果数据
        - error: 错误信息(成功时为None)
        - metadata: 元数据(工具名称、目标、漏洞数量等)
    """
    try:
        from backend.vulnerability_scan_plugins.csrf.scanner import CSRFScanner
        
        config = {
            "timeout": timeout
        }
        
        scanner = CSRFScanner(target, config)
        result = scanner.scan()
        
        vulnerabilities = []
        for vuln in result.vulnerabilities:
            vulnerabilities.append({
                "vuln_type": vuln.vuln_type.value,
                "url": vuln.url,
                "severity": vuln.severity.value,
                "title": vuln.title,
                "description": vuln.description,
                "method": vuln.method,
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
                "requests_made": result.requests_made
            },
            "error": result.error_message,
            "metadata": {
                "tool": "csrf_scan",
                "target": target,
                "plugin_name": result.plugin_name,
                "vulnerability_count": len(vulnerabilities)
            }
        }
    except ImportError as e:
        return {
            "success": False,
            "data": None,
            "error": f"导入csrf模块失败: {str(e)}",
            "metadata": {"tool": "csrf_scan", "target": target}
        }
    except Exception as e:
        return {
            "success": False,
            "data": None,
            "error": f"执行csrf_scan工具异常: {str(e)}",
            "metadata": {"tool": "csrf_scan", "target": target}
        }


if __name__ == "__main__":
    test_result = csrf_scan.invoke("http://testphp.vulnweb.com")
    print(test_result)
