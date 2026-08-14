"""TLS certificate and protocol information collection."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict

from TOSKill.tools.http_probe import tls_target


def _name_parts(entries) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for group in entries or ():
        for key, value in group:
            result[str(key)] = str(value)
    return result


def _iso_expiry(value: str) -> str:
    if not value:
        return ""
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        return value


def tls_certificate_scan(target: str, timeout: float = 8.0) -> Dict[str, Any]:
    host, port = tls_target(target)
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as connection:
                certificate = connection.getpeercert() or {}
                subject_alt_names = [value for kind, value in certificate.get("subjectAltName", ()) if kind == "DNS"]
                return {
                    "success": True,
                    "data": {
                        "tls_available": True,
                        "host": host,
                        "port": port,
                        "tls_version": connection.version() or "未知",
                        "cipher": connection.cipher()[0] if connection.cipher() else "未知",
                        "certificate_subject": _name_parts(certificate.get("subject")),
                        "certificate_issuer": _name_parts(certificate.get("issuer")),
                        "certificate_serial_number": certificate.get("serialNumber", ""),
                        "certificate_not_before": _iso_expiry(certificate.get("notBefore", "")),
                        "certificate_expires_at": _iso_expiry(certificate.get("notAfter", "")),
                        "subject_alt_names": subject_alt_names,
                    },
                    "error": None,
                    "metadata": {"tool": "tls_certificate_scan", "target": target},
                }
    except (socket.timeout, TimeoutError):
        failure_type = "connection_timeout"
        error = f"TLS 服务连接超时: {host}:{port}（目标可能未开放 HTTPS）"
    except ConnectionRefusedError:
        failure_type = "connection_refused"
        error = f"TLS 服务拒绝连接: {host}:{port}（目标可能未开放 HTTPS）"
    except socket.gaierror as exc:
        failure_type = "dns_error"
        error = f"TLS 目标域名解析失败: {host} ({exc})"
    except ssl.SSLCertVerificationError as exc:
        failure_type = "certificate_verification_failed"
        error = f"TLS 证书校验失败: {exc}"
    except ssl.SSLError as exc:
        failure_type = "tls_handshake_failed"
        error = f"TLS 握手失败: {exc}"
    except OSError as exc:
        failure_type = "connection_error"
        error = f"TLS 服务连接失败: {host}:{port} ({exc})"

    return {
        "success": False,
        "data": {
            "tls_available": False,
            "host": host,
            "port": port,
            "failure_type": failure_type,
        },
        "error": error,
        "metadata": {"tool": "tls_certificate_scan", "target": target},
    }
