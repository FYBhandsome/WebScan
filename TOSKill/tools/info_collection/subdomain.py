# -*- coding: utf-8 -*-
"""Certificate-transparency based subdomain discovery for the new backend."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


CERTIFICATE_TRANSPARENCY_URL = "https://crt.sh/?q=%25.{domain}&output=json"
REQUEST_TIMEOUT = 12
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def _normalise_domain(value: str) -> str:
    domain = str(value or "").strip().lower().rstrip(".")
    if not DOMAIN_PATTERN.fullmatch(domain):
        raise ValueError(f"域名格式非法: {value}")
    return domain


def _collect_names(payload: Any, domain: str) -> List[str]:
    names = set()
    for entry in payload if isinstance(payload, list) else []:
        if not isinstance(entry, dict):
            continue
        for name in str(entry.get("name_value") or "").splitlines():
            candidate = name.strip().lower().lstrip("*.").rstrip(".")
            if candidate == domain or candidate.endswith(f".{domain}"):
                names.add(candidate)
    return sorted(names)


def subdomain(domain: str) -> Dict[str, Any]:
    """Discover publicly logged subdomains without depending on legacy plugins.

    An empty certificate-transparency result and an unavailable public data
    source are both valid collection outcomes. The latter is marked in the
    payload so scan workflows do not incorrectly mark the whole task failed.
    """
    try:
        normalized_domain = _normalise_domain(domain)
    except ValueError as exc:
        return {
            "success": False,
            "data": {},
            "error": str(exc),
            "metadata": {"tool": "subdomain", "domain": str(domain or "")},
        }

    request_url = CERTIFICATE_TRANSPARENCY_URL.format(domain=quote(normalized_domain, safe=""))
    request = Request(request_url, headers={"User-Agent": "TOSKill-Security-Assessment/1.0"})
    try:
        with urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
        subdomains = _collect_names(payload, normalized_domain)
        has_results = bool(subdomains)
        return {
            "success": True,
            "data": {
                "subdomains": subdomains,
                "total_count": len(subdomains),
                "collection_status": "completed" if has_results else "no_public_records",
                "status_message": (
                    f"已发现 {len(subdomains)} 个公开证书记录中的子域名"
                    if has_results else "未发现公开证书记录中的子域名"
                ),
                "provider": "crt.sh",
            },
            "error": None,
            "metadata": {
                "tool": "subdomain",
                "domain": normalized_domain,
                "subdomain_count": len(subdomains),
                "provider": "crt.sh",
            },
        }
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        return {
            "success": True,
            "data": {
                "subdomains": [],
                "total_count": 0,
                "collection_status": "provider_unavailable",
                "status_message": "子域名公开数据源暂不可用，本次未获得可展示结果。",
                "provider": "crt.sh",
                "provider_error": str(exc),
            },
            "error": None,
            "metadata": {"tool": "subdomain", "domain": normalized_domain, "provider": "crt.sh"},
        }
