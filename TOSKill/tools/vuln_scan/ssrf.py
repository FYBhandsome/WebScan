# -*- coding:utf-8 -*-
"""
SSRF服务端请求伪造漏洞扫描工具
封装backend.vulnerability_scan_plugins.ssrf模块
"""

from typing import Dict, Any


def ssrf_scan(
    target: str,
    timeout: int = 30
) -> Dict[str, Any]:
    """SSRF服务端请求伪造漏洞扫描工具，检测目标URL是否存在SSRF漏洞
    
    检测能力：
    - 检测URL参数中的SSRF
    - 检测内网访问能力
    - 检测云元数据访问
    - 绕过技术检测
    
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
        from backend.vulnerability_scan_plugins.ssrf.scanner import SsrfScanner
        
        config = {
            "timeout": timeout
        }
        
        scanner = SsrfScanner(target, config)
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
                "scan_duration": result.scan_duration
            },
            "error": result.error_message,
            "metadata": {
                "tool": "ssrf_scan",
                "target": target,
                "plugin_name": result.plugin_name,
                "vulnerability_count": len(vulnerabilities)
            }
        }
    except ImportError as e:
        return {
            "success": False,
            "data": None,
            "error": f"导入ssrf模块失败: {str(e)}",
            "metadata": {"tool": "ssrf_scan", "target": target}
        }
    except Exception as e:
        return {
            "success": False,
            "data": None,
            "error": f"执行ssrf_scan工具异常: {str(e)}",
            "metadata": {"tool": "ssrf_scan", "target": target}
        }


if __name__ == "__main__":
    test_result = ssrf_scan.invoke("http://testphp.vulnweb.com")
    print(test_result)
