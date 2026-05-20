from typing import Dict, Any, Optional


def csrf_scan(
    target: str,
    timeout: int = 10,
    cookies: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    auth_token: Optional[str] = None
) -> Dict[str, Any]:
    try:
        from backend.vulnerability_scan_plugins.csrf.scanner import CSRFScanner

        config = {"timeout": timeout}

        scanner = CSRFScanner(target, config)

        if cookies or headers or auth_token:
            scanner.set_authentication(
                cookies=cookies or {},
                headers=headers or {},
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
            "error": result.error_message or "",
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
            "data": {},
            "error": f"导入csrf模块失败: {str(e)}",
            "metadata": {"tool": "csrf_scan", "target": target}
        }
    except Exception as e:
        return {
            "success": False,
            "data": {},
            "error": f"执行csrf_scan工具异常: {str(e)}",
            "metadata": {"tool": "csrf_scan", "target": target}
        }
