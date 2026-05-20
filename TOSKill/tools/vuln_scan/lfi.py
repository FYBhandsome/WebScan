from typing import Dict, Any, Optional


def lfi_scan(
    target: str,
    timeout: int = 30,
    cookies: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    auth_token: Optional[str] = None
) -> Dict[str, Any]:
    try:
        from backend.vulnerability_scan_plugins.lfi.scanner import LfiScanner

        config = {"timeout": timeout}

        scanner = LfiScanner(target, config)

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
            "error": result.error_message or "",
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
            "data": {},
            "error": f"导入lfi模块失败: {str(e)}",
            "metadata": {"tool": "lfi_scan", "target": target}
        }
    except Exception as e:
        return {
            "success": False,
            "data": {},
            "error": f"执行lfi_scan工具异常: {str(e)}",
            "metadata": {"tool": "lfi_scan", "target": target}
        }
