# -*- coding:utf-8 -*-
"""
弱口令/登录爆破扫描工具
使用@tool装饰器封装backend.vulnerability_scan_plugins.weakpass模块
"""

from langchain.tools import tool
from typing import Dict, Any, List, Optional


@tool
def weakpass_scan(
    target: str,
    usernames: Optional[List[str]] = None,
    passwords: Optional[List[str]] = None,
    max_attempts: int = 50
) -> Dict[str, Any]:
    """弱口令/登录爆破扫描工具，检测目标URL是否存在弱口令漏洞
    
    检测能力：
    - 自动发现登录页面
    - 常见用户名/密码字典
    - 成功/失败判断逻辑
    - 支持多种认证方式
    
    Args:
        target: 目标URL地址
        usernames: 自定义用户名列表，默认使用常见用户名
        passwords: 自定义密码列表，默认使用常见密码
        max_attempts: 最大尝试次数，默认50次
        
    Returns:
        包含扫描结果的字典，包括：
        - success: 执行状态(True/False)
        - data: 扫描结果数据
        - error: 错误信息(成功时为None)
        - metadata: 元数据(工具名称、目标、漏洞数量等)
    """
    try:
        from backend.vulnerability_scan_plugins.weakpass.scanner import WeakPassScanner
        
        config = {
            "max_attempts": max_attempts
        }
        
        if usernames:
            config["usernames"] = usernames
        if passwords:
            config["passwords"] = passwords
        
        scanner = WeakPassScanner(target, config)
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
                "tool": "weakpass_scan",
                "target": target,
                "plugin_name": result.plugin_name,
                "vulnerability_count": len(vulnerabilities)
            }
        }
    except ImportError as e:
        return {
            "success": False,
            "data": None,
            "error": f"导入weakpass模块失败: {str(e)}",
            "metadata": {"tool": "weakpass_scan", "target": target}
        }
    except Exception as e:
        return {
            "success": False,
            "data": None,
            "error": f"执行weakpass_scan工具异常: {str(e)}",
            "metadata": {"tool": "weakpass_scan", "target": target}
        }


if __name__ == "__main__":
    test_result = weakpass_scan.invoke("http://testphp.vulnweb.com")
    print(test_result)
