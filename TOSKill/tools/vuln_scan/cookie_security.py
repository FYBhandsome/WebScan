"""Inspect security attributes on actual session-like response cookies."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from TOSKill.tools.http_probe import fetch_http, normalize_http_url


SESSION_MARKERS = ("session", "sess", "auth", "token", "sid", "jwt")


def _parse_cookie(value: str) -> Tuple[str, Dict[str, str]]:
    parts = [part.strip() for part in value.split(";") if part.strip()]
    name = parts[0].split("=", 1)[0] if parts else "unknown"
    attributes: Dict[str, str] = {}
    for part in parts[1:]:
        key, separator, attr_value = part.partition("=")
        attributes[key.lower()] = attr_value if separator else "true"
    return name, attributes


def _finding(url: str, name: str, attribute: str, solution: str) -> Dict[str, str]:
    return {
        "vuln_type": "Cookie Security Configuration",
        "severity": "medium" if attribute in {"Secure", "HttpOnly"} else "low",
        "title": f"会话 Cookie 缺少 {attribute} 属性",
        "description": f"检测到会话相关 Cookie “{name}” 未设置 {attribute} 属性。",
        "url": url,
        "evidence": f"Set-Cookie: {name}; 未发现 {attribute}",
        "solution": solution,
        "parameter": name,
    }


def cookie_security_scan(target: str, timeout: float = 8.0) -> Dict[str, Any]:
    url = normalize_http_url(target)
    response = fetch_http(url, timeout=timeout, follow_redirects=True, read_body=False)
    inspected: List[Dict[str, Any]] = []
    findings: List[Dict[str, str]] = []
    for raw_cookie in response.header_values.get("set-cookie", []):
        name, attributes = _parse_cookie(raw_cookie)
        session_like = any(marker in name.lower() for marker in SESSION_MARKERS)
        inspected.append({"name": name, "session_like": session_like, "attributes": sorted(attributes)})
        if not session_like:
            continue
        if "secure" not in attributes:
            findings.append(_finding(response.url, name, "Secure", "为会话 Cookie 设置 Secure，仅通过 HTTPS 传输。"))
        if "httponly" not in attributes:
            findings.append(_finding(response.url, name, "HttpOnly", "为会话 Cookie 设置 HttpOnly，降低脚本读取风险。"))
        if "samesite" not in attributes:
            findings.append(_finding(response.url, name, "SameSite", "按业务兼容性设置 SameSite=Lax 或 SameSite=Strict。"))
    return {
        "success": True,
        "data": {"target_url": response.url, "cookies": inspected, "vulnerabilities": findings, "vulnerability_count": len(findings)},
        "error": None,
        "metadata": {"tool": "cookie_security_scan", "target": target, "vulnerability_count": len(findings)},
    }
