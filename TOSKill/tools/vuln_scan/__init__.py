# -*- coding:utf-8 -*-
"""
漏洞扫描工具模块
包含所有漏洞扫描相关的LangChain工具
"""

from .sqli import sqli_scan
from .xss import xss_scan
from .csrf import csrf_scan
from .fileupload import fileupload_scan
from .cmdi import cmdi_scan
from .ssrf import ssrf_scan
from .lfi import lfi_scan
from .weakpass import weakpass_scan
from .http_security_headers import http_security_headers_scan
from .cookie_security import cookie_security_scan
from .cors_misconfiguration import cors_misconfiguration_scan

__all__ = [
    "sqli_scan",
    "xss_scan",
    "csrf_scan",
    "fileupload_scan",
    "cmdi_scan",
    "ssrf_scan",
    "lfi_scan",
    "weakpass_scan",
    "http_security_headers_scan",
    "cookie_security_scan",
    "cors_misconfiguration_scan",
]

VULN_SCAN_TOOLS = [
    sqli_scan,
    xss_scan,
    csrf_scan,
    fileupload_scan,
    cmdi_scan,
    ssrf_scan,
    lfi_scan,
    weakpass_scan,
    http_security_headers_scan,
    cookie_security_scan,
    cors_misconfiguration_scan,
]
