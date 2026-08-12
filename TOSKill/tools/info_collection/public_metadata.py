"""Discover publicly exposed site metadata without directory brute forcing."""

from __future__ import annotations

from typing import Any, Dict, List

from TOSKill.tools.http_probe import build_public_url, fetch_http


PUBLIC_RESOURCES = (
    ("robots_txt", "/robots.txt"),
    ("sitemap_xml", "/sitemap.xml"),
    ("security_txt", "/.well-known/security.txt"),
)


def public_metadata_scan(target: str, timeout: float = 8.0) -> Dict[str, Any]:
    resources: List[Dict[str, Any]] = []
    discovered_paths: List[str] = []
    for name, path in PUBLIC_RESOURCES:
        url = build_public_url(target, path)
        response = fetch_http(url, timeout=timeout, follow_redirects=True, max_body_bytes=128 * 1024)
        found = 200 <= response.status_code < 300 and bool(response.body.strip())
        if found:
            discovered_paths.append(path)
        resources.append({
            "name": name,
            "path": path,
            "url": response.url,
            "status_code": response.status_code,
            "found": found,
            "content_preview": response.body[:500] if found else "",
        })
    return {
        "success": True,
        "data": {
            "public_resources": resources,
            "discovered_paths": discovered_paths,
            "total_count": len(discovered_paths),
        },
        "error": None,
        "metadata": {"tool": "public_metadata_scan", "target": target},
    }
