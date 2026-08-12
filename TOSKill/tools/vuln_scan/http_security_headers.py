"""Detect high-confidence missing or unsafe HTTP security response headers."""

from __future__ import annotations

from typing import Any, Dict, List

from TOSKill.tools.http_probe import fetch_http, normalize_http_url


def _finding(url: str, header: str, title: str, description: str, evidence: str, solution: str, severity: str = "low") -> Dict[str, str]:
    return {
        "vuln_type": "HTTP Security Headers",
        "severity": severity,
        "title": title,
        "description": description,
        "url": url,
        "evidence": evidence,
        "solution": solution,
        "parameter": header,
    }


def http_security_headers_scan(target: str, timeout: float = 8.0) -> Dict[str, Any]:
    url = normalize_http_url(target)
    response = fetch_http(url, timeout=timeout, follow_redirects=True, read_body=False)
    headers = response.headers
    findings: List[Dict[str, str]] = []
    required = {
        "content-security-policy": ("Content-Security-Policy", "缺少内容安全策略", "配置严格的 Content-Security-Policy，限制脚本和资源来源。", "medium"),
        "x-content-type-options": ("X-Content-Type-Options", "缺少 MIME 类型保护", "设置 X-Content-Type-Options: nosniff，避免浏览器 MIME 嗅探。", "low"),
        "x-frame-options": ("X-Frame-Options", "缺少点击劫持防护", "设置 X-Frame-Options: DENY/SAMEORIGIN，或以 CSP frame-ancestors 限制嵌入。", "medium"),
        "referrer-policy": ("Referrer-Policy", "缺少 Referrer 信息保护", "设置适当的 Referrer-Policy，例如 strict-origin-when-cross-origin。", "low"),
    }
    for key, (label, title, solution, severity) in required.items():
        if not headers.get(key):
            findings.append(_finding(response.url, label, title, f"响应未返回 {label}。", f"{label}: 缺失", solution, severity))

    if url.startswith("https://") and not headers.get("strict-transport-security"):
        findings.append(_finding(response.url, "Strict-Transport-Security", "缺少 HSTS 传输安全策略", "HTTPS 响应未返回 Strict-Transport-Security。", "Strict-Transport-Security: 缺失", "设置 Strict-Transport-Security，并在评估后逐步增加 max-age。", "medium"))
    if headers.get("x-content-type-options", "").lower() not in {"", "nosniff"}:
        findings.append(_finding(response.url, "X-Content-Type-Options", "MIME 类型保护配置不安全", "X-Content-Type-Options 不是 nosniff。", f"X-Content-Type-Options: {headers['x-content-type-options']}", "将 X-Content-Type-Options 设置为 nosniff。"))

    return {
        "success": True,
        "data": {"target_url": response.url, "response_headers": headers, "vulnerabilities": findings, "vulnerability_count": len(findings)},
        "error": None,
        "metadata": {"tool": "http_security_headers_scan", "target": target, "vulnerability_count": len(findings)},
    }
