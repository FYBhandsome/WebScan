"""扫描目标规范化与校验工具。"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
_NON_PUBLIC_HOST_SUFFIXES = (".localhost", ".local", ".internal", ".test", ".invalid", ".example")


def normalize_scan_target(value: str) -> str:
    """接受 URL、域名或 IP，并返回工具可直接使用的 URL。

    未携带协议的目标默认使用 ``http://``。端口、路径和查询参数会保留，
    这样漏洞扫描器可以直接访问用户输入的具体入口。
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError("扫描目标不能为空")

    target = value.strip()
    if any(char.isspace() for char in target):
        raise ValueError("扫描目标不能包含空白字符")

    candidate = target if re.match(r"^https?://", target, re.IGNORECASE) else f"http://{target}"
    parsed = urlparse(candidate)

    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise ValueError("扫描目标必须是有效的 URL、域名或 IP 地址")
    if parsed.username or parsed.password:
        raise ValueError("扫描目标不能包含用户名或密码")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("扫描目标缺少主机名")

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        if hostname.lower() != "localhost" and not _HOSTNAME_RE.fullmatch(hostname):
            raise ValueError("扫描目标的域名或 IP 地址格式无效")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("扫描目标端口格式无效") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("扫描目标端口必须在 1-65535 范围内")

    normalized = candidate.rstrip("/")
    return normalized


def target_host(value: str) -> str:
    """Extract the normalized hostname from a scan target."""
    parsed = urlparse(normalize_scan_target(value))
    return (parsed.hostname or "").lower().rstrip(".")


def is_non_public_target(value: str) -> bool:
    """Return whether a target is local, internal, or otherwise non-public."""
    host = target_host(value)
    try:
        return not ipaddress.ip_address(host).is_global
    except ValueError:
        return host == "localhost" or host.endswith(_NON_PUBLIC_HOST_SUFFIXES) or "." not in host


def is_public_domain_target(value: str) -> bool:
    """Return whether public domain data sources can meaningfully query it."""
    host = target_host(value)
    if is_non_public_target(value):
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return "." in host
    return False

