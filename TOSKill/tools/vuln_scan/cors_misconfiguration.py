"""Detect only high-confidence credentialed CORS origin reflection."""

from __future__ import annotations

from typing import Any, Dict, List

from TOSKill.tools.http_probe import fetch_http, normalize_http_url


PROBE_ORIGIN = "https://toskill.invalid"


def cors_misconfiguration_scan(target: str, timeout: float = 8.0) -> Dict[str, Any]:
    url = normalize_http_url(target)
    response = fetch_http(
        url,
        headers={"Origin": PROBE_ORIGIN},
        timeout=timeout,
        follow_redirects=False,
        read_body=False,
    )
    allow_origin = response.headers.get("access-control-allow-origin", "")
    allow_credentials = response.headers.get("access-control-allow-credentials", "").lower() == "true"
    reflected = allow_origin == PROBE_ORIGIN
    findings: List[Dict[str, str]] = []
    if reflected and allow_credentials:
        findings.append({
            "vuln_type": "CORS Misconfiguration",
            "severity": "high",
            "title": "CORS 反射任意 Origin 且允许携带凭证",
            "description": "服务端反射了受控 Origin，并允许跨域请求携带凭证，可能导致已认证数据被跨站读取。",
            "url": response.url,
            "evidence": f"Origin: {PROBE_ORIGIN}; Access-Control-Allow-Origin: {allow_origin}; Access-Control-Allow-Credentials: true",
            "solution": "使用严格的可信 Origin 白名单，避免动态反射任意 Origin，并仅在必要时启用凭证跨域。",
            "parameter": "Origin",
        })
    return {
        "success": True,
        "data": {
            "target_url": response.url,
            "probe_origin": PROBE_ORIGIN,
            "allow_origin": allow_origin,
            "allow_credentials": allow_credentials,
            "vulnerabilities": findings,
            "vulnerability_count": len(findings),
        },
        "error": None,
        "metadata": {"tool": "cors_misconfiguration_scan", "target": target, "vulnerability_count": len(findings)},
    }
