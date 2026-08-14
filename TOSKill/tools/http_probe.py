"""Small, dependency-free helpers for the built-in HTTP/TLS probe tools.

These helpers deliberately use only the Python standard library so the new
tools do not depend on the legacy backend plugin implementations.
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional
from urllib.error import HTTPError
from urllib.parse import urljoin, urlparse, urlunparse
from urllib.request import HTTPRedirectHandler, Request, build_opener


DEFAULT_USER_AGENT = "TOSKill-Security-Assessment/1.0"


@dataclass
class HttpResponse:
    url: str
    status_code: int
    headers: Dict[str, str]
    header_values: Dict[str, List[str]]
    body: str


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def normalize_http_url(target: str) -> str:
    """Normalize a user target into an HTTP(S) URL without discarding its path."""
    value = str(target or "").strip()
    if not value:
        raise ValueError("扫描目标不能为空")
    if "://" not in value:
        value = f"https://{value}"
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("仅支持有效的 HTTP 或 HTTPS 扫描目标")
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))


def origin_url(target: str) -> str:
    parsed = urlparse(normalize_http_url(target))
    return urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))


def build_public_url(target: str, path: str) -> str:
    return urljoin(origin_url(target), path.lstrip("/"))


def _header_maps(headers) -> tuple[Dict[str, str], Dict[str, List[str]]]:
    values: Dict[str, List[str]] = {}
    processed = set()
    for key in headers.keys():
        key_text = str(key).lower()
        if key_text in processed:
            continue
        processed.add(key_text)
        current = headers.get_all(key) if hasattr(headers, "get_all") else None
        if not current:
            current = [headers.get(key)]
        values.setdefault(key_text, []).extend(str(item) for item in current if item is not None)
    flattened = {key: ", ".join(items) for key, items in values.items()}
    return flattened, values


def fetch_http(
    url: str,
    *,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 8.0,
    follow_redirects: bool = True,
    read_body: bool = True,
    max_body_bytes: int = 256 * 1024,
) -> HttpResponse:
    """Send one bounded HTTP request and preserve HTTP error responses as data."""
    request_headers = {"User-Agent": DEFAULT_USER_AGENT, **(headers or {})}
    request = Request(url, headers=request_headers, method=method.upper())
    opener = build_opener() if follow_redirects else build_opener(_NoRedirect())
    try:
        response = opener.open(request, timeout=timeout)
    except HTTPError as exc:
        response = exc

    try:
        body_bytes = response.read(max_body_bytes) if read_body else b""
        body = body_bytes.decode("utf-8", errors="replace")
        response_headers, header_values = _header_maps(response.headers)
        return HttpResponse(
            url=response.geturl(),
            status_code=int(response.getcode()),
            headers=response_headers,
            header_values=header_values,
            body=body,
        )
    finally:
        response.close()


def parse_allow_methods(values: Iterable[str]) -> List[str]:
    methods = set()
    for value in values:
        methods.update(method.strip().upper() for method in value.split(",") if method.strip())
    return sorted(methods)


def tls_target(target: str) -> tuple[str, int]:
    parsed = urlparse(normalize_http_url(target))
    host = parsed.hostname
    if not host:
        raise ValueError("扫描目标缺少主机名")
    return host, parsed.port or 443
