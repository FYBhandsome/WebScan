# -*- coding:utf-8 -*-
"""
本地文件包含/目录遍历漏洞扫描工具
封装backend.vulnerability_scan_plugins.lfi模块
"""

from typing import Dict, Any


def lfi_scan(
    target: str,
    timeout: int = 30
) -> Dict[str, Any]:
    """本地文件包含/目录遍历漏洞扫描工具，检测目标URL是否存在LFI/RFI漏洞
    
    检测能力：
    - 本地文件包含(LFI)检测
    - 远程文件包含(RFI)检测
    - 目录遍历检测
    - PHP伪协议检测
    
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
        from backend.vulnerability_scan_plugins.lfi.scanner import LfiScanner
        
        config = {
            "timeout": timeout
        }
        
        scanner = LfiScanner(target, config)
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
                "tool": "lfi_scan",
                "target": target,
                "plugin_name": result.plugin_name,
                "vulnerability_count": len(vulnerabilities)
            }
        }
    except ImportError as e:
        return {
            "success": False,
            "data": None,
            "error": f"导入lfi模块失败: {str(e)}",
            "metadata": {"tool": "lfi_scan", "target": target}
        }
    except Exception as e:
        return {
            "success": False,
            "data": None,
            "error": f"执行lfi_scan工具异常: {str(e)}",
            "metadata": {"tool": "lfi_scan", "target": target}
        }


if __name__ == "__main__":
    test_result = lfi_scan.invoke("http://testphp.vulnweb.com")
    print(test_result)
