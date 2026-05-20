from typing import Dict, Any, Optional


def fileupload_scan(
    target: str,
    timeout: int = 30,
    cookies: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    auth_token: Optional[str] = None
) -> Dict[str, Any]:
    try:
        from backend.vulnerability_scan_plugins.fileupload.scanner import FileUploadScanner

        config = {"timeout": timeout}

        if cookies:
            config["auth_cookies"] = cookies
        if headers:
            config["auth_headers"] = headers
        if auth_token:
            config["auth_token"] = auth_token

        scanner = FileUploadScanner(target, config)
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
                "tool": "fileupload_scan",
                "target": target,
                "plugin_name": result.plugin_name,
                "vulnerability_count": len(vulnerabilities)
            }
        }
    except ImportError as e:
        return {
            "success": False,
            "data": {},
            "error": f"导入fileupload模块失败: {str(e)}",
            "metadata": {"tool": "fileupload_scan", "target": target}
        }
    except Exception as e:
        return {
            "success": False,
            "data": {},
            "error": f"执行fileupload_scan工具异常: {str(e)}",
            "metadata": {"tool": "fileupload_scan", "target": target}
        }
