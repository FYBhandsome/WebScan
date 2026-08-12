"""Low-impact HTTP method and redirect information collection."""

from __future__ import annotations

from typing import Any, Dict

from TOSKill.tools.http_probe import fetch_http, normalize_http_url, parse_allow_methods


def http_methods_scan(target: str, timeout: float = 8.0) -> Dict[str, Any]:
    url = normalize_http_url(target)
    options = fetch_http(url, method="OPTIONS", timeout=timeout, follow_redirects=False, read_body=False)
    head = fetch_http(url, method="HEAD", timeout=timeout, follow_redirects=False, read_body=False)
    allowed = parse_allow_methods(options.header_values.get("allow", []))
    return {
        "success": True,
        "data": {
            "target_url": url,
            "options_status_code": options.status_code,
            "head_status_code": head.status_code,
            "allowed_methods": allowed,
            "redirect_location": options.headers.get("location") or head.headers.get("location", ""),
            "server": options.headers.get("server") or head.headers.get("server", ""),
        },
        "error": None,
        "metadata": {"tool": "http_methods_scan", "target": target},
    }
