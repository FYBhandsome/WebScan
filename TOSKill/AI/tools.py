"""
TOSKill AI 工具注册模块

类比 demo.py，使用 @tool 装饰器注册所有工具。
提供统一的工具调用接口。
支持认证参数传递，实现交互式扫描。

数据接口标准:
    - 所有工具返回统一的 ToolResult 格式
    - 认证参数统一命名: cookies, headers, auth_token
    - 支持 validate_tool_result 进行格式验证

工具返回格式规范:
    ToolResult:
        - success: bool - 执行是否成功
        - data: Dict[str, Any] - 返回数据
        - error: Optional[str] - 错误信息
        - auth_info: Optional[Dict] - 认证信息
        - timestamp: str - 时间戳

认证参数命名规范:
    - cookies: Dict[str, str] - Cookie认证
    - headers: Dict[str, str] - HTTP头认证
    - auth_token: str - Token认证
"""
from typing import Dict, Any, List, Optional, TypedDict, Callable
from langchain.tools import tool
from urllib.parse import urlparse
from datetime import datetime, timedelta
from pathlib import Path
import logging
import re
import ipaddress
import socket
import sqlite3
import threading

# 预先导入所有工具模块，避免并发执行时的模块导入死锁
from TOSKill.tools.info_collection.baseinfo import baseinfo
from TOSKill.tools.info_collection.portscan import portscan
from TOSKill.tools.info_collection.subdomain import subdomain
from TOSKill.tools.info_collection.dirscan import dirscan
from TOSKill.tools.info_collection.waf import waf_detect
from TOSKill.tools.info_collection.cdnexist import cdn_detect
from TOSKill.tools.info_collection.whatcms import cms_detect
from TOSKill.tools.info_collection.infoleak import infoleak_scan as infoleak
from TOSKill.tools.info_collection.iplocating import ip_locate
from TOSKill.tools.info_collection.webside import webside_query
from TOSKill.tools.info_collection.webweight import web_weight
from TOSKill.tools.info_collection.crawler import crawler
from TOSKill.tools.info_collection.tls_certificate import tls_certificate_scan as tls_certificate
from TOSKill.tools.info_collection.http_methods import http_methods_scan as http_methods
from TOSKill.tools.info_collection.public_metadata import public_metadata_scan as public_metadata
from TOSKill.tools.vuln_scan.sqli import sqli_scan as sqli
from TOSKill.tools.vuln_scan.xss import xss_scan as xss
from TOSKill.tools.vuln_scan.csrf import csrf_scan as csrf
from TOSKill.tools.vuln_scan.fileupload import fileupload_scan as fileupload
from TOSKill.tools.vuln_scan.cmdi import cmdi_scan as cmdi
from TOSKill.tools.vuln_scan.ssrf import ssrf_scan as ssrf
from TOSKill.tools.vuln_scan.lfi import lfi_scan as lfi
from TOSKill.tools.vuln_scan.weakpass import weakpass_scan as weakpass
from TOSKill.tools.vuln_scan.http_security_headers import http_security_headers_scan as http_security_headers
from TOSKill.tools.vuln_scan.cookie_security import cookie_security_scan as cookie_security
from TOSKill.tools.vuln_scan.cors_misconfiguration import cors_misconfiguration_scan as cors_misconfiguration
from TOSKill.tools.poc.thinkphp import thinkphp_rce
from TOSKill.tools.poc.struts2 import struts2_s2_032
from TOSKill.tools.poc.weblogic import weblogic_cve_2020_2551
from TOSKill.utils.target import normalize_scan_target

logger = logging.getLogger(__name__)

AUTH_DEFAULT_EXPIRY_MINUTES = 30


def is_auth_expired(state: Dict[str, Any], default_expiry_minutes: int = AUTH_DEFAULT_EXPIRY_MINUTES) -> bool:
    """
    检查认证信息是否过期
    
    Args:
        state: 包含认证信息的状态字典
        default_expiry_minutes: 默认过期时间（分钟），默认30分钟
        
    Returns:
        bool: 认证信息是否已过期
        
    检查逻辑:
        1. 如果没有认证信息，返回 True
        2. 如果有 auth_expires_at 字段，检查是否过期
        3. 如果没有 auth_expires_at，使用 auth_timestamp 和默认过期时间计算
    """
    auth_info = state.get("auth_info", {})
    if not auth_info:
        auth_info = state.get("auth_cookies") or state.get("session_cookies") or state.get("auth_token")
        if not auth_info:
            return True
    
    expires_at = state.get("auth_expires_at")
    if expires_at:
        try:
            if isinstance(expires_at, str):
                expires_dt = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
            elif isinstance(expires_at, datetime):
                expires_dt = expires_at
            else:
                expires_dt = datetime.now() + timedelta(minutes=default_expiry_minutes)
            
            return datetime.now() > expires_dt
        except (ValueError, TypeError) as e:
            logger.warning(f"解析过期时间失败: {e}")
    
    auth_timestamp = state.get("auth_timestamp")
    if auth_timestamp:
        try:
            if isinstance(auth_timestamp, str):
                auth_dt = datetime.fromisoformat(auth_timestamp.replace('Z', '+00:00'))
            elif isinstance(auth_timestamp, datetime):
                auth_dt = auth_timestamp
            else:
                return True
            
            expiry_time = auth_dt + timedelta(minutes=default_expiry_minutes)
            return datetime.now() > expiry_time
        except (ValueError, TypeError) as e:
            logger.warning(f"解析认证时间戳失败: {e}")
            return True
    
    return True


def get_auth_remaining_time(state: Dict[str, Any], default_expiry_minutes: int = AUTH_DEFAULT_EXPIRY_MINUTES) -> int:
    """
    获取认证信息剩余有效时间（秒）
    
    Args:
        state: 包含认证信息的状态字典
        default_expiry_minutes: 默认过期时间（分钟）
        
    Returns:
        int: 剩余有效时间（秒），已过期返回0，无认证信息返回-1
    """
    auth_info = state.get("auth_info", {})
    if not auth_info:
        return -1
    
    expires_at = state.get("auth_expires_at")
    if expires_at:
        try:
            if isinstance(expires_at, str):
                expires_dt = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
            elif isinstance(expires_at, datetime):
                expires_dt = expires_at
            else:
                return 0
            
            remaining = (expires_dt - datetime.now()).total_seconds()
            return max(0, int(remaining))
        except (ValueError, TypeError):
            return 0
    
    auth_timestamp = state.get("auth_timestamp")
    if auth_timestamp:
        try:
            if isinstance(auth_timestamp, str):
                auth_dt = datetime.fromisoformat(auth_timestamp.replace('Z', '+00:00'))
            elif isinstance(auth_timestamp, datetime):
                auth_dt = auth_timestamp
            else:
                return 0
            
            expiry_time = auth_dt + timedelta(minutes=default_expiry_minutes)
            remaining = (expiry_time - datetime.now()).total_seconds()
            return max(0, int(remaining))
        except (ValueError, TypeError):
            return 0
    
    return 0


class ToolResult(TypedDict, total=False):
    """
    工具返回格式标准定义
    
    所有工具应返回此格式的字典，确保接口一致性。
    
    Attributes:
        success: 必需字段，表示工具执行是否成功
        data: 必需字段，包含工具返回的核心数据
        error: 可选字段，执行失败时的错误信息
        auth_info: 可选字段，认证信息（如登录后获取的cookie/token）
        timestamp: 必需字段，结果生成时间戳（ISO格式）
    
    Example:
        >>> result: ToolResult = {
        ...     "success": True,
        ...     "data": {"ports": [80, 443]},
        ...     "error": None,
        ...     "auth_info": None,
        ...     "timestamp": "2024-01-01T12:00:00"
        ... }
    """
    success: bool
    data: Dict[str, Any]
    error: Optional[str]
    auth_info: Optional[Dict[str, Any]]
    timestamp: str


def validate_tool_result(result: Dict) -> bool:
    """
    验证工具返回格式是否符合 ToolResult 标准
    
    Args:
        result: 待验证的字典结果
        
    Returns:
        bool: 格式是否有效
        
    Validation Rules:
        - 必须是字典类型
        - 必须包含 success 字段，且为 bool 类型
        - 必须包含 data 字段，且为 dict 类型
        - 必须包含 timestamp 字段，且为 str 类型
        - error 字段如果存在，必须为 str 或 None
        - auth_info 字段如果存在，必须为 dict 或 None
    
    Example:
        >>> validate_tool_result({"success": True, "data": {}, "timestamp": "2024-01-01"})
        True
        >>> validate_tool_result({"success": "yes"})
        False
    """
    if not isinstance(result, dict):
        return False
    
    if "success" not in result or not isinstance(result["success"], bool):
        return False
    
    if "data" not in result or not isinstance(result["data"], dict):
        return False
    
    if "timestamp" not in result or not isinstance(result["timestamp"], str):
        return False
    
    if "error" in result and result["error"] is not None:
        if not isinstance(result["error"], str):
            return False
    
    if "auth_info" in result and result["auth_info"] is not None:
        if not isinstance(result["auth_info"], dict):
            return False
    
    return True


def wrap_tool_result(
    success: bool,
    data: Dict[str, Any],
    error: Optional[str] = None,
    auth_info: Optional[Dict[str, Any]] = None
) -> ToolResult:
    """
    包装工具返回结果为标准 ToolResult 格式
    
    Args:
        success: 执行是否成功
        data: 返回数据字典
        error: 错误信息（可选）
        auth_info: 认证信息（可选）
        
    Returns:
        ToolResult: 标准格式的工具返回结果
        
    Note:
        自动添加当前时间戳，无需手动传入
        
    Example:
        >>> wrap_tool_result(True, {"ports": [80, 443]})
        {'success': True, 'data': {'ports': [80, 443]}, 'error': None, 'auth_info': None, 'timestamp': '...'}
    """
    return ToolResult(
        success=success,
        data=data,
        error=error,
        auth_info=auth_info,
        timestamp=datetime.now().isoformat()
    )


def normalize_scanner_result(
    raw_result: Any,
    auth_info: Optional[Dict[str, Any]] = None
) -> ToolResult:
    """将底层扫描器结果展开为统一 ToolResult，避免嵌套 success 状态。"""
    if not isinstance(raw_result, dict):
        return wrap_tool_result(True, {"result": raw_result}, auth_info=auth_info)

    success = raw_result.get("success", True)
    data = raw_result.get("data", {})
    error = raw_result.get("error")

    # Compatibility guard for legacy adapters that accidentally wrapped a
    # complete scanner result inside an outer successful ToolResult.
    if isinstance(data, dict) and isinstance(data.get("success"), bool):
        nested = data
        success = nested["success"]
        data = nested.get("data", {})
        error = nested.get("error") or error
        if "metadata" not in raw_result and isinstance(nested.get("metadata"), dict):
            raw_result = {**raw_result, "metadata": nested["metadata"]}

    if not isinstance(success, bool):
        return wrap_tool_result(False, {}, error="扫描器返回的 success 字段不是布尔值")
    if data is None:
        data = {}
    elif not isinstance(data, dict):
        data = {"result": data}

    metadata = raw_result.get("metadata")
    if isinstance(metadata, dict) and "metadata" not in data:
        data = {**data, "metadata": metadata}

    return wrap_tool_result(success, data, error=error, auth_info=auth_info)


def clean_target(target: str) -> str:
    """URL 自动清洗 - 类比 demo.py"""
    import re
    
    target = target.strip()
    
    url_pattern = r'(https?://[a-zA-Z0-9\.-]+(?::\d+)?(?:/[a-zA-Z0-9\./_-]*)?)'
    match = re.search(url_pattern, target)
    if match:
        target = match.group(1)
    
    ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?)'
    match = re.search(ip_pattern, target)
    if match:
        return match.group(1)
    
    domain_pattern = r'([a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]\.[a-zA-Z0-9.-]+(?::\d+)?)'
    match = re.search(domain_pattern, target)
    if match:
        return match.group(1)
    
    parsed = urlparse(target)
    if parsed.netloc:
        return parsed.netloc.strip()
    
    return target


# Tools that perform HTTP(S) requests need the user-supplied scheme, port and
# path intact. Host-only discovery tools continue to receive a cleaned host.
URL_PRESERVING_TOOLS = frozenset({
    "sqli_scan",
    "xss_scan",
    "waf_detect_scan",
    "tls_certificate_scan",
    "http_methods_scan",
    "public_metadata_scan",
    "http_security_headers_scan",
    "cookie_security_scan",
    "cors_misconfiguration_scan",
})


def clean_target_for_tool(tool_name: str, target: str) -> str:
    """Prepare a target using the input shape expected by a specific tool."""
    if tool_name in URL_PRESERVING_TOOLS:
        return normalize_scan_target(target)
    # Uploaded tools define their own target handling contract. Preserve the
    # normalized URL so an HTTP script does not unexpectedly lose scheme,
    # path or query parameters merely because its name is not built in.
    manager = globals().get("script_manager")
    if manager and tool_name in manager.get_registered_scripts():
        return normalize_scan_target(target)
    return clean_target(target)


def resolve_target_ip(target: str) -> str:
    """Extract the host from a scan target and resolve it to an IPv4 address."""
    import ipaddress
    import socket

    value = target.strip()
    parsed = urlparse(value if "://" in value else f"//{value}")
    host = parsed.hostname or clean_target(value).split(":", 1)[0]
    if not host:
        raise ValueError("扫描目标缺少有效主机名或 IP 地址")

    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        try:
            return socket.gethostbyname(host)
        except OSError as exc:
            raise ValueError(f"无法解析目标域名 {host} 的 IP 地址") from exc


def invoke_tool_with_auth(tool, params_or_target, state: Dict[str, Any] = None) -> Any:
    """带认证信息的工具调用辅助函数（非强制性）
    
    认证机制为非强制性要求：
    - 优先使用 state.get("auth_info", {}) 中的认证信息
    - 若无有效认证信息，将以未认证模式继续执行
    - 不会因缺少认证而中断流程或抛出阻断性错误
    
    Args:
        tool: LangChain工具实例
        params_or_target: 扫描目标URL(str)或tool_call参数字典(dict)
        state: 包含认证信息的状态字典（可选，无认证信息时忽略）
        
    Returns:
        工具执行结果（无论是否有认证信息都会返回）
    """
    if isinstance(params_or_target, str):
        params = {"target": params_or_target}
    else:
        params = dict(params_or_target)
    
    if state:
        unified_auth = state.get("auth_info", {})
        
        if unified_auth:
            cookies = unified_auth.get("cookies", {})
            headers = unified_auth.get("headers", {})
            auth_token = unified_auth.get("token", "")
            
            if cookies:
                params["cookies"] = cookies
            if headers:
                params["headers"] = headers
            if auth_token:
                params["auth_token"] = auth_token
        else:
            cookies = state.get("auth_cookies") or state.get("session_cookies")
            headers = state.get("auth_headers")
            auth_token = state.get("auth_token") or state.get("session_token")
            
            if cookies:
                params["cookies"] = cookies
            if headers:
                params["headers"] = headers
            if auth_token:
                params["auth_token"] = auth_token
    
    result = tool.invoke(params)
    if (
        isinstance(result, dict)
        and result.get("success") is True
        and isinstance(result.get("data"), dict)
        and isinstance(result["data"].get("success"), bool)
        and ("data" in result["data"] or "error" in result["data"])
    ):
        result = normalize_scanner_result(result)
    if not validate_tool_result(result):
        logger.error(f"工具 {getattr(tool, 'name', 'unknown')} 返回格式不符合 ToolResult 规范")
        return wrap_tool_result(
            success=False,
            data={},
            error="工具返回格式不符合 ToolResult 规范"
        )
    return result


def extract_auth_from_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """从工具结果中提取认证信息
    
    统一提取 cookies、headers、token，返回标准化的 auth_info 字典
    
    Args:
        result: 工具执行结果
        
    Returns:
        包含提取的认证信息的字典，包括:
        - auth_info: 统一认证信息存储
        - auth_timestamp: 认证信息获取时间
        - auth_expires_at: 认证过期时间（如果提供）
        - 兼容旧字段: session_cookies, session_token, authentication_used
    """
    from datetime import datetime
    
    auth_info = {}
    
    if not isinstance(result, dict):
        return auth_info
    
    unified_auth = {
        "cookies": {},
        "headers": {},
        "token": "",
        "type": "",
        "source": ""
    }
    
    if result.get("cookies_obtained"):
        cookies = result["cookies_obtained"]
        if isinstance(cookies, dict):
            unified_auth["cookies"] = cookies
        elif isinstance(cookies, str):
            unified_auth["cookies"] = {"cookie": cookies}
        auth_info["session_cookies"] = cookies
    
    if result.get("headers_obtained"):
        headers = result["headers_obtained"]
        if isinstance(headers, dict):
            unified_auth["headers"] = headers
        auth_info["auth_headers"] = headers
    
    if result.get("tokens_obtained"):
        token = result["tokens_obtained"]
        unified_auth["token"] = token
        auth_info["session_token"] = token
    
    if result.get("auth_token"):
        unified_auth["token"] = result["auth_token"]
        auth_info["auth_token"] = result["auth_token"]
    
    if result.get("auth_type"):
        unified_auth["type"] = result["auth_type"]
    
    if result.get("auth_source"):
        unified_auth["source"] = result["auth_source"]
    
    if result.get("authentication_used"):
        auth_info["authentication_used"] = True
    
    if result.get("auth_expires_at"):
        auth_info["auth_expires_at"] = result["auth_expires_at"]
    
    if unified_auth["cookies"] or unified_auth["token"] or unified_auth["headers"]:
        auth_info["auth_info"] = unified_auth
        auth_info["auth_timestamp"] = datetime.now().isoformat()
        auth_info["credentials_obtained"] = True
    
    return auth_info


# ==================== 信息收集工具 ====================

@tool
def baseinfo_scan(target: str) -> ToolResult:
    """
    基础信息收集工具
    
    获取目标网站的基本信息，包括服务器类型、响应头、标题等。
    
    Args:
        target: 扫描目标URL或域名
        
    Returns:
        ToolResult: 标准返回格式
            - success: 执行是否成功
            - data: 包含基础信息的字典
                - server: 服务器类型
                - title: 网页标题
                - headers: 响应头信息
            - error: 错误信息（如有）
            - timestamp: 执行时间戳
    
    Example:
        >>> result = baseinfo_scan("https://example.com")
        >>> result["success"]
        True
    """
    t = clean_target(target)
    logger.info(f"[+] 执行基础信息收集：{t}")
    try:
        raw_result = baseinfo(t)
        return wrap_tool_result(
            success=True,
            data=raw_result if isinstance(raw_result, dict) else {"result": raw_result}
        )
    except Exception as e:
        logger.error(f"基础信息收集失败: {e}")
        return wrap_tool_result(success=False, data={}, error=str(e))


@tool
def port_scan(target: str) -> ToolResult:
    """
    端口扫描工具
    
    扫描目标主机开放的端口及服务信息。
    
    Args:
        target: 扫描目标IP或域名
        
    Returns:
        ToolResult: 标准返回格式
            - success: 执行是否成功
            - data: 包含端口信息的字典
                - ports: 开放端口列表
                - services: 端口服务信息
            - error: 错误信息（如有）
            - timestamp: 执行时间戳
    """
    t = clean_target(target)
    logger.info(f"[+] 执行端口扫描：{t}")
    try:
        from backend.plugins.portscan.portscan import ScanPort
        
        scanner = ScanPort(t)
        
        if not scanner.run_scan():
            error_msg = scanner.get_last_error() or "端口扫描执行失败，可能是目标不可达"
            logger.warning(f"端口扫描失败: {error_msg}")
            return wrap_tool_result(success=False, data={}, error=error_msg)
        
        raw_result = scanner.get_results()
        logger.info(f"端口扫描完成，发现 {len(raw_result)} 个开放端口")
        
        return wrap_tool_result(
            success=True,
            data={
                "open_ports": raw_result,
                "total_count": len(raw_result),
                "portspoof_detected": "Portspoof:0" in raw_result
            }
        )
    except Exception as e:
        logger.error(f"端口扫描失败: {e}")
        return wrap_tool_result(success=False, data={}, error=str(e))


@tool
def subdomain_scan(target: str) -> ToolResult:
    """
    子域名扫描工具
    
    发现目标域名的子域名信息。
    
    Args:
        target: 目标域名
        
    Returns:
        ToolResult: 标准返回格式
            - success: 执行是否成功
            - data: 包含子域名列表的字典
                - subdomains: 发现的子域名列表
            - error: 错误信息（如有）
            - timestamp: 执行时间戳
    """
    t = clean_target(target)
    logger.info(f"[+] 执行子域名扫描：{t}")
    try:
        raw_result = subdomain(t)
        return normalize_scanner_result(raw_result)
    except Exception as e:
        logger.error(f"子域名扫描失败: {e}")
        return wrap_tool_result(success=False, data={}, error=str(e))


@tool
def dir_brute(target: str) -> ToolResult:
    """
    目录扫描工具
    
    发现目标网站的目录结构和敏感路径。
    
    Args:
        target: 目标URL
        
    Returns:
        ToolResult: 标准返回格式
            - success: 执行是否成功
            - data: 包含目录信息的字典
                - directories: 发现的目录列表
                - files: 发现的文件列表
            - error: 错误信息（如有）
            - timestamp: 执行时间戳
    """
    t = clean_target(target)
    logger.info(f"[+] 执行目录扫描：{t}")
    try:
        raw_result = dirscan(t)
        return wrap_tool_result(
            success=True,
            data=raw_result if isinstance(raw_result, dict) else {"result": raw_result}
        )
    except Exception as e:
        logger.error(f"目录扫描失败: {e}")
        return wrap_tool_result(success=False, data={}, error=str(e))


@tool
def waf_detect_scan(target: str) -> ToolResult:
    """
    WAF检测工具
    
    检测目标网站是否部署Web应用防火墙(WAF)。
    
    Args:
        target: 目标URL
        
    Returns:
        ToolResult: 标准返回格式
            - success: 执行是否成功
            - data: 包含WAF信息的字典
                - waf_detected: 是否检测到WAF
                - waf_type: WAF类型（如检测到）
            - error: 错误信息（如有）
            - timestamp: 执行时间戳
    """
    t = normalize_scan_target(target)
    logger.info(f"[+] 执行WAF检测：{t}")
    try:
        raw_result = waf_detect(t)
        return normalize_scanner_result(raw_result)
    except Exception as e:
        logger.error(f"WAF检测失败: {e}")
        return wrap_tool_result(success=False, data={}, error=str(e))


@tool
def cdn_detect_scan(target: str) -> ToolResult:
    """
    CDN检测工具
    
    检测目标网站是否使用CDN服务。
    
    Args:
        target: 目标URL或域名
        
    Returns:
        ToolResult: 标准返回格式
            - success: 执行是否成功
            - data: 包含CDN信息的字典
                - cdn_detected: 是否检测到CDN
                - cdn_provider: CDN提供商（如检测到）
            - error: 错误信息（如有）
            - timestamp: 执行时间戳
    """
    t = clean_target(target)
    logger.info(f"[+] 执行CDN检测：{t}")
    try:
        raw_result = cdn_detect(t)
        return wrap_tool_result(
            success=True,
            data=raw_result if isinstance(raw_result, dict) else {"result": raw_result}
        )
    except Exception as e:
        logger.error(f"CDN检测失败: {e}")
        return wrap_tool_result(success=False, data={}, error=str(e))


@tool
def cms_detect_scan(target: str) -> ToolResult:
    """
    CMS识别工具
    
    识别目标网站使用的CMS系统类型和版本。
    
    Args:
        target: 目标URL
        
    Returns:
        ToolResult: 标准返回格式
            - success: 执行是否成功
            - data: 包含CMS信息的字典
                - cms_name: CMS名称
                - cms_version: CMS版本
            - error: 错误信息（如有）
            - timestamp: 执行时间戳
    """
    t = target.strip()
    logger.info(f"[+] 执行CMS识别：{t}")
    try:
        raw_result = cms_detect(t)
        raw_success = raw_result.get("success", False) if isinstance(raw_result, dict) else True
        raw_data = raw_result.get("data") if isinstance(raw_result, dict) else {"result": raw_result}
        raw_error = raw_result.get("error") if isinstance(raw_result, dict) else None
        return wrap_tool_result(
            success=raw_success,
            data=raw_data if isinstance(raw_data, dict) else {},
            error=raw_error
        )
    except Exception as e:
        logger.error(f"CMS识别失败: {e}")
        return wrap_tool_result(success=False, data={}, error=str(e))


@tool
def infoleak_scan(target: str) -> ToolResult:
    """
    信息泄露扫描工具
    
    检测目标网站的敏感信息泄露风险。
    
    Args:
        target: 目标URL
        
    Returns:
        ToolResult: 标准返回格式
            - success: 执行是否成功
            - data: 包含泄露信息的字典
                - leaks_found: 是否发现泄露
                - leak_details: 泄露详情列表
            - error: 错误信息（如有）
            - timestamp: 执行时间戳
    """
    t = clean_target(target)
    logger.info(f"[+] 执行信息泄露扫描：{t}")
    try:
        raw_result = infoleak(t)
        return wrap_tool_result(
            success=True,
            data=raw_result if isinstance(raw_result, dict) else {"result": raw_result}
        )
    except Exception as e:
        logger.error(f"信息泄露扫描失败: {e}")
        return wrap_tool_result(success=False, data={}, error=str(e))


@tool
def ip_locate_scan(target: str) -> ToolResult:
    """
    IP地理位置查询工具
    
    查询目标IP的地理位置信息。
    
    Args:
        target: 目标IP地址
        
    Returns:
        ToolResult: 标准返回格式
            - success: 执行是否成功
            - data: 包含位置信息的字典
                - country: 国家
                - province: 省份
                - city: 城市
                - isp: 运营商
            - error: 错误信息（如有）
            - timestamp: 执行时间戳
    """
    try:
        t = resolve_target_ip(target)
    except (TypeError, ValueError) as e:
        logger.error(f"IP定位目标解析失败: {e}")
        return wrap_tool_result(success=False, data={}, error=str(e))
    logger.info(f"[+] 执行IP定位：{t}")
    try:
        raw_result = ip_locate(t)
        return normalize_scanner_result(raw_result)
    except Exception as e:
        logger.error(f"IP定位失败: {e}")
        return wrap_tool_result(success=False, data={}, error=str(e))


@tool
def webside_query_scan(target: str) -> ToolResult:
    """
    网站备案查询工具
    
    查询目标网站的ICP备案信息。
    
    Args:
        target: 目标域名或IP
        
    Returns:
        ToolResult: 标准返回格式
            - success: 执行是否成功
            - data: 包含备案信息的字典
                - icp_number: 备案号
                - owner: 备案主体
                - site_name: 网站名称
            - error: 错误信息（如有）
            - timestamp: 执行时间戳
    """
    t = clean_target(target)
    logger.info(f"[+] 执行备案查询：{t}")
    try:
        target_ip = resolve_target_ip(target)
        raw_result = webside_query.invoke({"ip": target_ip})
        raw_success = raw_result.get("success", False) if isinstance(raw_result, dict) else True
        raw_data = raw_result.get("data") if isinstance(raw_result, dict) else {"result": raw_result}
        raw_error = raw_result.get("error") if isinstance(raw_result, dict) else None
        if not raw_success:
            neutral_message = "旁站查询数据源暂不可用，本次未获得可展示结果。"
            return wrap_tool_result(
                success=True,
                data={
                    **(raw_data if isinstance(raw_data, dict) else {}),
                    "query_status": "provider_unavailable",
                    "status_message": neutral_message,
                    "provider_error": raw_error or "未知外部服务错误",
                },
            )
        return wrap_tool_result(
            success=raw_success,
            data=raw_data if isinstance(raw_data, dict) else {},
            error=raw_error,
        )
    except Exception as e:
        logger.error(f"备案查询失败: {e}")
        return wrap_tool_result(success=False, data={}, error=str(e))


@tool
def web_weight_scan(target: str) -> ToolResult:
    """
    网站权重查询工具
    
    查询目标网站的搜索引擎权重信息。
    
    Args:
        target: 目标域名
        
    Returns:
        ToolResult: 标准返回格式
            - success: 执行是否成功
            - data: 包含权重信息的字典
                - baidu_weight: 百度权重
                - google_pr: Google PR值
            - error: 错误信息（如有）
            - timestamp: 执行时间戳
    """
    t = clean_target(target)
    logger.info(f"[+] 执行权重查询：{t}")
    try:
        raw_result = web_weight(t)
        return normalize_scanner_result(raw_result)
    except Exception as e:
        logger.error(f"权重查询失败: {e}")
        return wrap_tool_result(success=False, data={}, error=str(e))


# ==================== Web 爬虫工具 ====================

@tool
def crawler_scan(target: str) -> ToolResult:
    """
    Web 站点爬虫工具。

    从目标 URL 开始抓取站内页面，提取链接、表单、参数、脚本和敏感信息，
    并返回站点地图及抓取统计。target 应为目标 URL 或域名。
    """
    t = target.strip()
    logger.info(f"[+] 执行 Web 站点爬虫：{t}")
    try:
        return normalize_scanner_result(crawler(t))
    except Exception as e:
        logger.error(f"Web 站点爬虫执行失败: {e}")
        return wrap_tool_result(success=False, data={}, error=str(e))


@tool
def tls_certificate_scan(target: str) -> ToolResult:
    """收集 HTTPS 服务的 TLS 协议、证书主体、签发者、有效期与 SAN 信息。"""
    logger.info(f"[+] 执行 TLS 证书分析：{target}")
    try:
        raw_result = tls_certificate(target)
        if isinstance(raw_result, dict) and raw_result.get("success") is False:
            raw_data = raw_result.get("data")
            failure_type = raw_data.get("failure_type", "unavailable") if isinstance(raw_data, dict) else "unavailable"
            return wrap_tool_result(
                success=True,
                data={
                    **(raw_data if isinstance(raw_data, dict) else {}),
                    "tls_available": False,
                    "collection_status": failure_type,
                    "status_message": "未检测到可访问的 TLS 服务。",
                    "diagnostic": raw_result.get("error") or "TLS 探测未返回可用结果",
                },
            )
        return normalize_scanner_result(raw_result)
    except Exception as e:
        logger.error(f"TLS 证书分析失败: {e}")
        return wrap_tool_result(success=False, data={}, error=str(e))


@tool
def http_methods_scan(target: str) -> ToolResult:
    """收集目标支持的 HTTP 方法、状态码、重定向与服务标识。"""
    logger.info(f"[+] 执行 HTTP 方法探测：{target}")
    try:
        return normalize_scanner_result(http_methods(target))
    except Exception as e:
        logger.error(f"HTTP 方法探测失败: {e}")
        return wrap_tool_result(success=False, data={}, error=str(e))


@tool
def public_metadata_scan(target: str) -> ToolResult:
    """收集 robots.txt、sitemap.xml 与 security.txt 等公开站点元数据。"""
    logger.info(f"[+] 执行公开元数据发现：{target}")
    try:
        return normalize_scanner_result(public_metadata(target))
    except Exception as e:
        logger.error(f"公开元数据发现失败: {e}")
        return wrap_tool_result(success=False, data={}, error=str(e))


# ==================== 漏洞扫描工具 ====================

@tool
def sqli_scan(
    target: str,
    cookies: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    auth_token: Optional[str] = None
) -> ToolResult:
    """
    SQL注入漏洞扫描工具
    
    检测目标网站是否存在SQL注入漏洞，支持认证扫描。
    
    Args:
        target: 目标URL
        cookies: Cookie认证信息，格式: {"name": "value"}
        headers: 自定义HTTP头认证，格式: {"Header-Name": "value"}
        auth_token: Token认证字符串
        
    Returns:
        ToolResult: 标准返回格式
            - success: 执行是否成功
            - data: 包含漏洞信息的字典
                - vulnerable: 是否存在漏洞
                - injection_type: 注入类型
                - payload: 成功的payload
            - auth_info: 认证信息（如登录成功获取）
            - error: 错误信息（如有）
            - timestamp: 执行时间戳
    
    Note:
        认证参数命名统一: cookies, headers, auth_token
    """
    t = target.strip()
    logger.info(f"[+] 执行SQL注入扫描：{t} (认证: {bool(cookies or auth_token)})")
    params = {"target": t}
    if cookies:
        params["cookies"] = cookies
    if headers:
        params["headers"] = headers
    if auth_token:
        params["auth_token"] = auth_token
    try:
        raw_result = sqli(**params)
        auth_extracted = extract_auth_from_result(raw_result) if isinstance(raw_result, dict) else None
        raw_success = raw_result.get("success", False) if isinstance(raw_result, dict) else True
        raw_data = raw_result.get("data") if isinstance(raw_result, dict) else {"result": raw_result}
        raw_error = raw_result.get("error") if isinstance(raw_result, dict) else None
        return wrap_tool_result(
            success=raw_success,
            data=raw_data if isinstance(raw_data, dict) else {},
            error=raw_error,
            auth_info=auth_extracted.get("auth_info") if auth_extracted else None
        )
    except Exception as e:
        logger.error(f"SQL注入扫描失败: {e}")
        return wrap_tool_result(success=False, data={}, error=str(e))


@tool
def xss_scan(
    target: str,
    cookies: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    auth_token: Optional[str] = None
) -> ToolResult:
    """
    XSS跨站脚本漏洞扫描工具
    
    检测目标网站是否存在XSS漏洞，支持认证扫描。
    
    Args:
        target: 目标URL
        cookies: Cookie认证信息，格式: {"name": "value"}
        headers: 自定义HTTP头认证，格式: {"Header-Name": "value"}
        auth_token: Token认证字符串
        
    Returns:
        ToolResult: 标准返回格式
            - success: 执行是否成功
            - data: 包含漏洞信息的字典
                - vulnerable: 是否存在漏洞
                - xss_type: XSS类型（反射型/存储型/DOM型）
                - payload: 成功的payload
            - error: 错误信息（如有）
            - timestamp: 执行时间戳
    
    Note:
        认证参数命名统一: cookies, headers, auth_token
    """
    t = target.strip()
    logger.info(f"[+] 执行XSS扫描：{t} (认证: {bool(cookies or auth_token)})")
    params = {"target": t}
    if cookies:
        params["cookies"] = cookies
    if headers:
        params["headers"] = headers
    if auth_token:
        params["auth_token"] = auth_token
    try:
        raw_result = xss(**params)
        return normalize_scanner_result(raw_result)
    except Exception as e:
        logger.error(f"XSS扫描失败: {e}")
        return wrap_tool_result(success=False, data={}, error=str(e))


@tool
def csrf_scan(
    target: str,
    cookies: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    auth_token: Optional[str] = None
) -> ToolResult:
    """
    CSRF跨站请求伪造漏洞扫描工具
    
    检测目标网站是否存在CSRF漏洞，支持认证扫描。
    
    Args:
        target: 目标URL
        cookies: Cookie认证信息，格式: {"name": "value"}
        headers: 自定义HTTP头认证，格式: {"Header-Name": "value"}
        auth_token: Token认证字符串
        
    Returns:
        ToolResult: 标准返回格式
            - success: 执行是否成功
            - data: 包含漏洞信息的字典
                - vulnerable: 是否存在漏洞
                - form_url: 存在漏洞的表单URL
            - error: 错误信息（如有）
            - timestamp: 执行时间戳
    
    Note:
        认证参数命名统一: cookies, headers, auth_token
    """
    t = target.strip()
    logger.info(f"[+] 执行CSRF扫描：{t} (认证: {bool(cookies or auth_token)})")
    params = {"target": t}
    if cookies:
        params["cookies"] = cookies
    if headers:
        params["headers"] = headers
    if auth_token:
        params["auth_token"] = auth_token
    try:
        raw_result = csrf(**params)
        return normalize_scanner_result(raw_result)
    except Exception as e:
        logger.error(f"CSRF扫描失败: {e}")
        return wrap_tool_result(success=False, data={}, error=str(e))


@tool
def fileupload_scan(
    target: str,
    cookies: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    auth_token: Optional[str] = None
) -> ToolResult:
    """
    文件上传漏洞扫描工具
    
    检测目标网站是否存在文件上传漏洞，支持认证扫描。
    
    Args:
        target: 目标URL
        cookies: Cookie认证信息，格式: {"name": "value"}
        headers: 自定义HTTP头认证，格式: {"Header-Name": "value"}
        auth_token: Token认证字符串
        
    Returns:
        ToolResult: 标准返回格式
            - success: 执行是否成功
            - data: 包含漏洞信息的字典
                - vulnerable: 是否存在漏洞
                - upload_path: 上传路径
                - bypass_method: 绕过方法
            - error: 错误信息（如有）
            - timestamp: 执行时间戳
    
    Note:
        认证参数命名统一: cookies, headers, auth_token
    """
    t = target.strip()
    logger.info(f"[+] 执行文件上传扫描：{t} (认证: {bool(cookies or auth_token)})")
    params = {"target": t}
    if cookies:
        params["cookies"] = cookies
    if headers:
        params["headers"] = headers
    if auth_token:
        params["auth_token"] = auth_token
    try:
        raw_result = fileupload(**params)
        return normalize_scanner_result(raw_result)
    except Exception as e:
        logger.error(f"文件上传扫描失败: {e}")
        return wrap_tool_result(success=False, data={}, error=str(e))


@tool
def cmdi_scan(
    target: str,
    cookies: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    auth_token: Optional[str] = None
) -> ToolResult:
    """
    命令注入漏洞扫描工具
    
    检测目标网站是否存在命令注入漏洞，支持认证扫描。
    
    Args:
        target: 目标URL
        cookies: Cookie认证信息，格式: {"name": "value"}
        headers: 自定义HTTP头认证，格式: {"Header-Name": "value"}
        auth_token: Token认证字符串
        
    Returns:
        ToolResult: 标准返回格式
            - success: 执行是否成功
            - data: 包含漏洞信息的字典
                - vulnerable: 是否存在漏洞
                - injection_point: 注入点
                - payload: 成功的payload
            - error: 错误信息（如有）
            - timestamp: 执行时间戳
    
    Note:
        认证参数命名统一: cookies, headers, auth_token
    """
    t = target.strip()
    logger.info(f"[+] 执行命令注入扫描：{t} (认证: {bool(cookies or auth_token)})")
    params = {"target": t}
    if cookies:
        params["cookies"] = cookies
    if headers:
        params["headers"] = headers
    if auth_token:
        params["auth_token"] = auth_token
    try:
        raw_result = cmdi(**params)
        return normalize_scanner_result(raw_result)
    except Exception as e:
        logger.error(f"命令注入扫描失败: {e}")
        return wrap_tool_result(success=False, data={}, error=str(e))


@tool
def ssrf_scan(
    target: str,
    cookies: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    auth_token: Optional[str] = None
) -> ToolResult:
    """
    SSRF服务端请求伪造漏洞扫描工具
    
    检测目标网站是否存在SSRF漏洞，支持认证扫描。
    
    Args:
        target: 目标URL
        cookies: Cookie认证信息，格式: {"name": "value"}
        headers: 自定义HTTP头认证，格式: {"Header-Name": "value"}
        auth_token: Token认证字符串
        
    Returns:
        ToolResult: 标准返回格式
            - success: 执行是否成功
            - data: 包含漏洞信息的字典
                - vulnerable: 是否存在漏洞
                - injection_point: 注入点
                - internal_access: 可访问的内部资源
            - error: 错误信息（如有）
            - timestamp: 执行时间戳
    
    Note:
        认证参数命名统一: cookies, headers, auth_token
    """
    t = target.strip()
    logger.info(f"[+] 执行SSRF扫描：{t} (认证: {bool(cookies or auth_token)})")
    params = {"target": t}
    if cookies:
        params["cookies"] = cookies
    if headers:
        params["headers"] = headers
    if auth_token:
        params["auth_token"] = auth_token
    try:
        raw_result = ssrf(**params)
        return normalize_scanner_result(raw_result)
    except Exception as e:
        logger.error(f"SSRF扫描失败: {e}")
        return wrap_tool_result(success=False, data={}, error=str(e))


@tool
def lfi_scan(
    target: str,
    cookies: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    auth_token: Optional[str] = None
) -> ToolResult:
    """
    LFI本地文件包含漏洞扫描工具
    
    检测目标网站是否存在本地文件包含漏洞，支持认证扫描。
    
    Args:
        target: 目标URL
        cookies: Cookie认证信息，格式: {"name": "value"}
        headers: 自定义HTTP头认证，格式: {"Header-Name": "value"}
        auth_token: Token认证字符串
        
    Returns:
        ToolResult: 标准返回格式
            - success: 执行是否成功
            - data: 包含漏洞信息的字典
                - vulnerable: 是否存在漏洞
                - readable_files: 可读取的文件列表
                - payload: 成功的payload
            - error: 错误信息（如有）
            - timestamp: 执行时间戳
    
    Note:
        认证参数命名统一: cookies, headers, auth_token
    """
    t = target.strip()
    logger.info(f"[+] 执行LFI扫描：{t} (认证: {bool(cookies or auth_token)})")
    params = {"target": t}
    if cookies:
        params["cookies"] = cookies
    if headers:
        params["headers"] = headers
    if auth_token:
        params["auth_token"] = auth_token
    try:
        raw_result = lfi(**params)
        return normalize_scanner_result(raw_result)
    except Exception as e:
        logger.error(f"LFI扫描失败: {e}")
        return wrap_tool_result(success=False, data={}, error=str(e))


@tool
def weakpass_scan(
    target: str,
    cookies: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    auth_token: Optional[str] = None
) -> ToolResult:
    """
    弱口令扫描工具
    
    检测目标登录页面是否存在弱口令，成功后返回认证信息供其他扫描器使用。
    
    Args:
        target: 目标登录页面URL
        cookies: Cookie认证信息，格式: {"name": "value"}
        headers: 自定义HTTP头认证，格式: {"Header-Name": "value"}
        auth_token: Token认证字符串
        
    Returns:
        ToolResult: 标准返回格式
            - success: 执行是否成功
            - data: 包含扫描结果的字典
                - login_success: 是否登录成功
                - username: 成功的用户名
                - password: 成功的密码
            - auth_info: 认证信息（登录成功后获取的cookies/token）
                - cookies: 获取的cookies
                - token: 获取的token
            - error: 错误信息（如有）
            - timestamp: 执行时间戳
    
    Note:
        认证参数命名统一: cookies, headers, auth_token
        此工具返回的auth_info可用于后续认证扫描
    """
    t = target.strip()
    logger.info(f"[+] 执行弱口令扫描：{t}")
    params = {"target": t}
    if cookies:
        params["cookies"] = cookies
    if headers:
        params["headers"] = headers
    if auth_token:
        params["auth_token"] = auth_token
    try:
        raw_result = weakpass(**params)
        auth_extracted = extract_auth_from_result(raw_result) if isinstance(raw_result, dict) else None
        return normalize_scanner_result(
            raw_result,
            auth_info=auth_extracted.get("auth_info") if auth_extracted else None
        )
    except Exception as e:
        logger.error(f"弱口令扫描失败: {e}")
        return wrap_tool_result(success=False, data={}, error=str(e))


@tool
def http_security_headers_scan(target: str) -> ToolResult:
    """检测 HTTP 安全响应头缺失或不安全配置。"""
    logger.info(f"[+] 执行 HTTP 安全响应头检测：{target}")
    try:
        return normalize_scanner_result(http_security_headers(target))
    except Exception as e:
        logger.error(f"HTTP 安全响应头检测失败: {e}")
        return wrap_tool_result(success=False, data={}, error=str(e))


@tool
def cookie_security_scan(target: str) -> ToolResult:
    """检测响应中会话 Cookie 的 Secure、HttpOnly、SameSite 安全属性。"""
    logger.info(f"[+] 执行 Cookie 安全属性检测：{target}")
    try:
        return normalize_scanner_result(cookie_security(target))
    except Exception as e:
        logger.error(f"Cookie 安全属性检测失败: {e}")
        return wrap_tool_result(success=False, data={}, error=str(e))


@tool
def cors_misconfiguration_scan(target: str) -> ToolResult:
    """检测高置信度的凭证型 CORS 任意 Origin 反射配置。"""
    logger.info(f"[+] 执行 CORS 配置检测：{target}")
    try:
        return normalize_scanner_result(cors_misconfiguration(target))
    except Exception as e:
        logger.error(f"CORS 配置检测失败: {e}")
        return wrap_tool_result(success=False, data={}, error=str(e))


# ==================== POC工具 ====================

@tool
def thinkphp_rce_scan(target: str) -> ToolResult:
    """
    ThinkPHP远程代码执行漏洞检测工具
    
    检测目标是否存在ThinkPHP远程代码执行漏洞。
    
    Args:
        target: 目标URL
        
    Returns:
        ToolResult: 标准返回格式
            - success: 执行是否成功
            - data: 包含漏洞信息的字典
                - vulnerable: 是否存在漏洞
                - version: ThinkPHP版本
                - exploit_url: 利用URL
            - error: 错误信息（如有）
            - timestamp: 执行时间戳
    """
    t = clean_target(target)
    logger.info(f"[+] 执行ThinkPHP RCE检测：{t}")
    try:
        raw_result = thinkphp_rce(t)
        return wrap_tool_result(
            success=True,
            data=raw_result if isinstance(raw_result, dict) else {"result": raw_result}
        )
    except Exception as e:
        logger.error(f"ThinkPHP RCE检测失败: {e}")
        return wrap_tool_result(success=False, data={}, error=str(e))


@tool
def struts2_scan(target: str) -> ToolResult:
    """
    Struts2系列漏洞检测工具
    
    检测目标是否存在Struts2系列漏洞（S2-032等）。
    
    Args:
        target: 目标URL
        
    Returns:
        ToolResult: 标准返回格式
            - success: 执行是否成功
            - data: 包含漏洞信息的字典
                - vulnerable: 是否存在漏洞
                - cve_id: CVE编号
                - exploit_url: 利用URL
            - error: 错误信息（如有）
            - timestamp: 执行时间戳
    """
    t = clean_target(target)
    logger.info(f"[+] 执行Struts2漏洞检测：{t}")
    try:
        raw_result = struts2_s2_032(t)
        return wrap_tool_result(
            success=True,
            data=raw_result if isinstance(raw_result, dict) else {"result": raw_result}
        )
    except Exception as e:
        logger.error(f"Struts2漏洞检测失败: {e}")
        return wrap_tool_result(success=False, data={}, error=str(e))


@tool
def weblogic_scan(target: str) -> ToolResult:
    """
    WebLogic系列漏洞检测工具
    
    检测目标是否存在WebLogic系列漏洞（CVE-2020-2551等）。
    
    Args:
        target: 目标URL
        
    Returns:
        ToolResult: 标准返回格式
            - success: 执行是否成功
            - data: 包含漏洞信息的字典
                - vulnerable: 是否存在漏洞
                - cve_id: CVE编号
                - port: 受影响端口
            - error: 错误信息（如有）
            - timestamp: 执行时间戳
    """
    t = clean_target(target)
    logger.info(f"[+] 执行WebLogic漏洞检测：{t}")
    try:
        raw_result = weblogic_cve_2020_2551(t)
        return wrap_tool_result(
            success=True,
            data=raw_result if isinstance(raw_result, dict) else {"result": raw_result}
        )
    except Exception as e:
        logger.error(f"WebLogic漏洞检测失败: {e}")
        return wrap_tool_result(success=False, data={}, error=str(e))


# ==================== 工具注册表 ====================

INFO_COLLECTION_TOOLS = [
    baseinfo_scan,
    port_scan,
    subdomain_scan,
    dir_brute,
    waf_detect_scan,
    cdn_detect_scan,
    cms_detect_scan,
    infoleak_scan,
    ip_locate_scan,
    webside_query_scan,
    web_weight_scan,
    crawler_scan,
    tls_certificate_scan,
    http_methods_scan,
    public_metadata_scan,
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

POC_TOOLS = [
    thinkphp_rce_scan,
    struts2_scan,
    weblogic_scan,
]

ALL_TOOLS = INFO_COLLECTION_TOOLS + VULN_SCAN_TOOLS + POC_TOOLS

TOOL_MAP = {t.name: t for t in ALL_TOOLS}

# Keep the built-in registry immutable from the perspective of custom tools.
# Dynamic tools remain directly executable through TOOL_MAP, but are not added
# to these collections so they cannot silently change default scan plans.
SYSTEM_INFO_TOOL_NAMES = frozenset(t.name for t in INFO_COLLECTION_TOOLS)
SYSTEM_VULN_TOOL_NAMES = frozenset(t.name for t in VULN_SCAN_TOOLS)
SYSTEM_POC_TOOL_NAMES = frozenset(t.name for t in POC_TOOLS)
SYSTEM_TOOL_NAMES = SYSTEM_INFO_TOOL_NAMES | SYSTEM_VULN_TOOL_NAMES | SYSTEM_POC_TOOL_NAMES

TOOL_SEQUENCE_INFO = [
    "baseinfo_scan",
    "port_scan",
    "subdomain_scan",
    "dir_brute",
    "waf_detect_scan",
    "cdn_detect_scan",
    "cms_detect_scan",
    "infoleak_scan",
    "ip_locate_scan",
    "webside_query_scan",
    "web_weight_scan",
    "crawler_scan",
    "tls_certificate_scan",
    "http_methods_scan",
    "public_metadata_scan",
]

TOOL_SEQUENCE_VULN = [
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


def get_tool_by_name(name: str):
    """根据名称获取工具"""
    if name not in TOOL_MAP:
        try:
            script_manager.restore_registered_tools()
        except (NameError, sqlite3.Error, OSError):
            pass
    return TOOL_MAP.get(name)


def get_all_tool_names() -> List[str]:
    """获取所有工具名称"""
    return list(TOOL_MAP.keys())


def is_tool_exists(tool_name: str) -> bool:
    """检查工具是否存在"""
    return get_tool_by_name(tool_name) is not None


def get_tools_by_mode(mode: str) -> List:
    """根据模式获取工具列表"""
    if mode == "info_collection":
        return INFO_COLLECTION_TOOLS
    elif mode == "vuln_scan":
        return VULN_SCAN_TOOLS
    elif mode == "full_scan":
        return ALL_TOOLS
    return INFO_COLLECTION_TOOLS


def get_tool_sequence(mode: str) -> List[str]:
    """获取工具执行序列"""
    if mode == "info_collection":
        return TOOL_SEQUENCE_INFO
    elif mode == "vuln_scan":
        return TOOL_SEQUENCE_VULN
    elif mode == "full_scan":
        return TOOL_SEQUENCE_INFO + TOOL_SEQUENCE_VULN
    return TOOL_SEQUENCE_INFO


def get_custom_tool_names() -> List[str]:
    """获取自定义工具名称列表"""
    return list(script_manager.get_registered_scripts().keys())


def get_tool_metadata(tool_name: str) -> Optional[Dict[str, Any]]:
    """Return the canonical metadata used by API, workflow and UI."""
    if tool_name in SYSTEM_INFO_TOOL_NAMES:
        category = "info_collection"
    elif tool_name in SYSTEM_VULN_TOOL_NAMES:
        category = "vuln_scan"
    elif tool_name in SYSTEM_POC_TOOL_NAMES:
        category = "poc"
    else:
        custom = script_manager.get_registered_scripts().get(tool_name)
        if not custom:
            return None
        return {
            "name": tool_name,
            "description": custom.get("description", ""),
            "category": custom.get("category", "other"),
            "source": "custom",
            "creation_method": custom.get("creation_method", "upload"),
            "script_path": custom.get("script_path") or custom.get("path", ""),
            "enabled": bool(custom.get("enabled", True)),
            "include_in_default_scan": bool(custom.get("include_in_default_scan", False)),
            "created_at": custom.get("created_at") or custom.get("registered_at"),
            "updated_at": custom.get("updated_at") or custom.get("registered_at"),
            "is_custom": True,
        }

    tool = TOOL_MAP.get(tool_name)
    return {
        "name": tool_name,
        "description": getattr(tool, "description", "") if tool else "",
        "category": category,
        "source": "system",
        "creation_method": "builtin",
        "script_path": "",
        "enabled": True,
        "include_in_default_scan": True,
        "created_at": None,
        "updated_at": None,
        "is_custom": False,
    }


def list_tool_metadata(
    category: Optional[str] = None,
    source: Optional[str] = None,
    synchronize: bool = True,
) -> List[Dict[str, Any]]:
    """List system and custom tools using one stable response model."""
    if synchronize:
        script_manager.restore_registered_tools()
    records = []
    for name in TOOL_MAP:
        metadata = get_tool_metadata(name)
        if not metadata:
            continue
        if category and metadata["category"] != category:
            continue
        if source and metadata["source"] != source:
            continue
        records.append(metadata)
    return records


@tool
def _script_analysis_result(tool_name: str, description: str, category: str, input_type: str, output_type: str) -> str:
    """上报脚本分析结果。请根据提供的脚本内容填充各字段：
    tool_name: 英文下划线分隔的工具名称，如custom_port_check
    description: 工具功能描述（一句话）
    category: 工具类别，可选 info_collection、vuln_scan、poc 或 custom
    input_type: 输入类型，可选 url、ip、domain
    output_type: 输出类型，如 漏洞信息、端口列表、其他
    """
    return ""

class ScriptManager:
    """脚本管理器 - 处理上传/生成脚本的注册"""
    
    _instance = None
    _scripts_dir = None
    _db_path = None
    _registered_scripts: Dict[str, Dict] = {}
    _registry_lock = threading.RLock()
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
            from TOSKill.config import settings
            cls._scripts_dir = settings.CUSTOM_SCRIPTS_PATH
            cls._scripts_dir.mkdir(parents=True, exist_ok=True)
            cls._instance._ensure_registry_schema()
        return cls._instance

    def _get_db_path(self) -> Path:
        if self._db_path:
            return Path(self._db_path)
        from TOSKill.config import settings
        return Path(settings.DB_PATH)

    def _connect_registry(self) -> sqlite3.Connection:
        db_path = self._get_db_path()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_registry_schema(self) -> None:
        with self._registry_lock, self._connect_registry() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS custom_tools (
                    tool_name TEXT PRIMARY KEY,
                    script_content TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    category TEXT NOT NULL,
                    creation_method TEXT NOT NULL DEFAULT 'upload',
                    script_path TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    include_in_default_scan INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_custom_tools_category "
                "ON custom_tools(category, enabled)"
            )

    @staticmethod
    def _normalize_category(category: str) -> str:
        normalized = str(category or "").strip().lower()
        if normalized == "poc":
            return "vuln_scan"
        if normalized in {"info_collection", "vuln_scan"}:
            return normalized
        # Transitional compatibility for clients that do not yet send the new
        # category field. New REST registrations reject this value explicitly.
        return "other"

    @staticmethod
    def _normalize_creation_method(creation_method: str) -> str:
        normalized = str(creation_method or "upload").strip().lower()
        return normalized if normalized in {"upload", "ai_generate"} else "upload"

    def _metadata_from_row(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "name": row["tool_name"],
            "description": row["description"],
            "category": row["category"],
            "source": "custom",
            "creation_method": row["creation_method"],
            "script_path": row["script_path"],
            "enabled": bool(row["enabled"]),
            "include_in_default_scan": bool(row["include_in_default_scan"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "is_custom": True,
        }

    def _load_persisted_rows(self, enabled_only: bool = True) -> List[sqlite3.Row]:
        self._ensure_registry_schema()
        sql = "SELECT * FROM custom_tools"
        if enabled_only:
            sql += " WHERE enabled = 1"
        sql += " ORDER BY created_at ASC"
        with self._registry_lock, self._connect_registry() as conn:
            return list(conn.execute(sql).fetchall())

    def _build_runtime_tool(self, script_path: Path, script_name: str, description: str):
        import importlib.util

        try:
            from langchain_core.tools import Tool
        except ImportError:
            from langchain.tools import Tool

        def tool_func(target: str):
            try:
                spec = importlib.util.spec_from_file_location(
                    f"toskill_custom_{script_name}", str(script_path)
                )
                if not spec or not spec.loader:
                    return {"success": False, "error": "无法加载脚本"}

                module = importlib.util.module_from_spec(spec)
                safe_builtins = {
                    'print': print, 'len': len, 'range': range,
                    'str': str, 'int': int, 'float': float, 'bool': bool,
                    'list': list, 'dict': dict, 'set': set, 'tuple': tuple,
                    'True': True, 'False': False, 'None': None,
                    'isinstance': isinstance, 'type': type,
                    'Exception': Exception, 'ValueError': ValueError,
                    'TypeError': TypeError, 'KeyError': KeyError,
                    'ImportError': ImportError, 'AttributeError': AttributeError,
                    'min': min, 'max': max, 'sum': sum, 'sorted': sorted,
                    'abs': abs, 'round': round, 'enumerate': enumerate,
                    'zip': zip, 'map': map, 'filter': filter, 'any': any, 'all': all,
                    'hasattr': hasattr, 'getattr': getattr, 'setattr': setattr,
                    '__import__': lambda name, *args, **kwargs: __import__(name, *args, **kwargs)
                }
                module.__builtins__ = safe_builtins
                spec.loader.exec_module(module)

                logger.info(f"自定义脚本执行: {script_name} -> {target}")
                if hasattr(module, 'run'):
                    return module.run(target)
                if hasattr(module, 'scan'):
                    return module.scan(target)
                return {"success": False, "error": "脚本缺少run或scan函数"}
            except Exception as exc:
                logger.error(f"自定义脚本 {script_name} 执行失败: {exc}")
                return {"success": False, "error": str(exc)}

        return Tool(name=script_name, description=description, func=tool_func)

    def restore_registered_tools(self) -> Dict[str, Any]:
        """Restore enabled custom tools and synchronize this worker's registry."""
        restored = []
        removed = []
        failed = []
        with self._registry_lock:
            rows = self._load_persisted_rows(enabled_only=True)
            persisted_names = {row["tool_name"] for row in rows}
            for name in set(self._registered_scripts) - persisted_names:
                tool = TOOL_MAP.pop(name, None)
                while tool in ALL_TOOLS:
                    ALL_TOOLS.remove(tool)
                self._registered_scripts.pop(name, None)
                removed.append(name)

            for row in rows:
                name = row["tool_name"]
                if name in SYSTEM_TOOL_NAMES:
                    failed.append({"tool_name": name, "error": "与系统工具重名"})
                    continue
                metadata = self._metadata_from_row(row)
                script_path = Path(row["script_path"])
                try:
                    if not script_path.exists():
                        script_path.parent.mkdir(parents=True, exist_ok=True)
                        script_path.write_text(row["script_content"], encoding="utf-8")
                    if name not in TOOL_MAP:
                        TOOL_MAP[name] = self._build_runtime_tool(
                            script_path, name, row["description"]
                        )
                        restored.append(name)
                    self._registered_scripts[name] = metadata
                except Exception as exc:
                    logger.error(f"恢复自定义工具 {name} 失败: {exc}")
                    failed.append({"tool_name": name, "error": str(exc)})
        return {"restored": restored, "removed": removed, "failed": failed}
    
    def _get_llm(self):
        """获取LLM实例 - 使用统一客户端"""
        from TOSKill.AI.llm_client import get_llm
        return get_llm()
    
    async def analyze_script_with_ai(self, script_content: str) -> Dict:
        """使用AI分析脚本，生成工具描述"""
        from langchain_core.messages import SystemMessage, HumanMessage
        
        llm = self._get_llm().bind_tools([_script_analysis_result])
        messages = [
            SystemMessage(content="请分析以下安全扫描脚本，调用script_analysis_result工具上报分析结果。"),
            HumanMessage(content=f"```python\n{script_content[:2000]}\n```")
        ]
        try:
            response = llm.invoke(messages)
            tool_calls = getattr(response, 'tool_calls', [])
            
            if tool_calls:
                args = tool_calls[0].get('args', {})
                tool_name = args.get("tool_name", f"custom_{hash(script_content) % 10000}")
                if not tool_name.startswith("custom_") and not tool_name.startswith("ai_gen_"):
                    tool_name = f"custom_{tool_name}"
                return {
                    "tool_name": tool_name,
                    "description": args.get("description", "自定义扫描脚本"),
                    "category": args.get("category", "custom"),
                    "input_type": args.get("input_type", "url"),
                    "output_type": args.get("output_type", "其他"),
                }
        except Exception as e:
            logger.error(f"AI分析脚本失败: {e}")
        
        return {
            "tool_name": f"custom_{hash(script_content) % 10000}",
            "description": "自定义扫描脚本",
            "category": "custom",
            "input_type": "url",
            "output_type": "其他"
        }
    
    def register_script_as_tool(
        self,
        script_content: str,
        script_name: str,
        description: str,
        category: str = "custom",
        creation_method: str = "upload",
        include_in_default_scan: bool = False,
    ) -> Dict:
        """Persist and register one custom tool without changing default scans."""
        try:
            from ..AI.script_safety import sanitize_script_name, validate_script_safety
            safe_name, name_error = sanitize_script_name(script_name)
            if name_error:
                return {
                    "success": False,
                    "error": f"脚本名称不合法: {name_error}",
                    "error_code": "INVALID_SCRIPT_NAME",
                }
            script_name = safe_name
            is_safe, safety_err = validate_script_safety(script_content)
            if not is_safe:
                return {
                    "success": False,
                    "error": f"脚本安全审查未通过: {safety_err}",
                    "error_code": "SCRIPT_SAFETY_REJECTED",
                }
        except ImportError as exc:
            return {
                "success": False,
                "error": f"脚本安全校验依赖不可用: {exc}",
                "error_code": "SCRIPT_VALIDATOR_IMPORT_FAILED",
            }

        normalized_category = self._normalize_category(category)
        normalized_method = self._normalize_creation_method(creation_method)
        if include_in_default_scan:
            return {
                "success": False,
                "error": "自定义工具不能直接加入默认扫描计划",
                "error_code": "DEFAULT_SCAN_MUTATION_FORBIDDEN",
            }
        if script_name in SYSTEM_TOOL_NAMES:
            return {
                "success": False,
                "error": f"工具名称 '{script_name}' 与系统工具冲突",
                "error_code": "SYSTEM_TOOL_NAME_CONFLICT",
            }

        script_path = Path(self._scripts_dir) / f"{script_name}.py"
        now = datetime.now().isoformat()
        with self._registry_lock:
            self._ensure_registry_schema()
            with self._connect_registry() as conn:
                exists = conn.execute(
                    "SELECT 1 FROM custom_tools WHERE tool_name = ?", (script_name,)
                ).fetchone()
            if exists or script_name in TOOL_MAP or script_path.exists():
                return {
                    "success": False,
                    "error": f"自定义工具 '{script_name}' 已存在",
                    "error_code": "CUSTOM_TOOL_NAME_CONFLICT",
                }

            try:
                script_path.parent.mkdir(parents=True, exist_ok=True)
                script_path.write_text(script_content, encoding="utf-8")
                tool = self._build_runtime_tool(script_path, script_name, description)
                with self._connect_registry() as conn:
                    conn.execute(
                        """
                        INSERT INTO custom_tools (
                            tool_name, script_content, description, category,
                            creation_method, script_path, enabled,
                            include_in_default_scan, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, 1, 0, ?, ?)
                        """,
                        (
                            script_name, script_content, description,
                            normalized_category, normalized_method,
                            str(script_path.resolve()), now, now,
                        ),
                    )
                metadata = {
                    "name": script_name,
                    "description": description,
                    "category": normalized_category,
                    "source": "custom",
                    "creation_method": normalized_method,
                    "script_path": str(script_path.resolve()),
                    "enabled": True,
                    "include_in_default_scan": False,
                    "created_at": now,
                    "updated_at": now,
                    "is_custom": True,
                }
                TOOL_MAP[script_name] = tool
                self._registered_scripts[script_name] = metadata
                logger.info(f"动态注册并持久化工具: {script_name}")
                return {
                    "success": True,
                    "tool_name": script_name,
                    "tool": tool,
                    "metadata": metadata,
                }
            except Exception as exc:
                TOOL_MAP.pop(script_name, None)
                self._registered_scripts.pop(script_name, None)
                try:
                    with self._connect_registry() as conn:
                        conn.execute("DELETE FROM custom_tools WHERE tool_name = ?", (script_name,))
                except Exception:
                    pass
                script_path.unlink(missing_ok=True)
                logger.error(f"注册脚本工具失败: {exc}")
                return {
                    "success": False,
                    "error": str(exc),
                    "error_code": "SCRIPT_REGISTER_FAILED",
                }

    def unregister_custom_tool(self, tool_name: str, delete_script: bool = True) -> Dict[str, Any]:
        """Remove a custom tool from persistence and this worker's runtime."""
        if tool_name in SYSTEM_TOOL_NAMES:
            return {
                "success": False,
                "error": "系统工具不允许删除",
                "error_code": "SYSTEM_TOOL_DELETE_FORBIDDEN",
            }
        self._ensure_registry_schema()
        with self._registry_lock, self._connect_registry() as conn:
            row = conn.execute(
                "SELECT * FROM custom_tools WHERE tool_name = ?", (tool_name,)
            ).fetchone()
            if not row:
                return {
                    "success": False,
                    "error": f"自定义工具 '{tool_name}' 不存在",
                    "error_code": "CUSTOM_TOOL_NOT_FOUND",
                }
            conn.execute("DELETE FROM custom_tools WHERE tool_name = ?", (tool_name,))

        tool = TOOL_MAP.pop(tool_name, None)
        while tool in ALL_TOOLS:
            ALL_TOOLS.remove(tool)
        self._registered_scripts.pop(tool_name, None)
        if delete_script:
            Path(row["script_path"]).unlink(missing_ok=True)
        logger.info(f"自定义工具已注销: {tool_name}")
        return {"success": True, "tool_name": tool_name}

    def get_custom_tool_record(
        self, tool_name: str, include_script: bool = False
    ) -> Optional[Dict[str, Any]]:
        """Read one persisted custom tool, optionally including source code."""
        self._ensure_registry_schema()
        with self._registry_lock, self._connect_registry() as conn:
            row = conn.execute(
                "SELECT * FROM custom_tools WHERE tool_name = ?", (tool_name,)
            ).fetchone()
        if not row:
            return None
        record = self._metadata_from_row(row)
        if include_script:
            record["script_content"] = row["script_content"]
        return record
    
    async def generate_script_with_ai(self, description: str) -> str:
        """使用AI生成扫描脚本"""
        from ..AI.script_safety import extract_code_block
        from ..AI.maas_client import get_maas_client
        from ..config import settings
        
        prompt = f"""根据以下需求生成一个Python安全扫描脚本：

需求：{description}

要求：
1. 必须包含 run(target: str) 函数
2. 返回完整 ToolResult 字典：success 必须是 bool，data 必须是 dict，
   error 必须是字符串或 None，auth_info 必须是字典或 None，timestamp 必须是字符串
3. 包含错误处理
4. 使用 requests 库进行HTTP请求
5. 代码简洁高效

安全约束（必须严格遵守）：
- 禁止导入 os, subprocess, shutil, socket, ctypes, signal, multiprocessing 模块
- 禁止使用 eval(), exec(), compile(), __import__() 函数
- 禁止执行系统命令或访问文件系统
- 仅使用 requests, json, re, urllib, base64, hashlib, time 等安全库

只输出Python代码，使用```python包裹代码。
"""
        response = await get_maas_client().complete(
            messages=[
                {"role": "system", "content": "你是安全扫描脚本生成助手，只输出符合约束的 Python 代码。"},
                {"role": "user", "content": prompt},
            ],
            max_tokens=settings.SCRIPT_GENERATION_MAX_TOKENS,
            timeout=settings.SCRIPT_GENERATION_TIMEOUT,
            max_retries=settings.SCRIPT_GENERATION_MAX_RETRIES,
            temperature=settings.LLM_TEMPERATURE,
        )
        code = extract_code_block(response)
        return code or response.strip()
    
    def get_registered_scripts(self) -> Dict:
        """获取已注册的脚本列表"""
        # Synchronize additions/deletions made by another API worker before
        # exposing category or source metadata in this process.
        try:
            self.restore_registered_tools()
        except (sqlite3.Error, OSError):
            pass
        return self._registered_scripts.copy()


# ==================== 意图工具集（仅用于 LLM Function Calling 结构化输出） ====================

@tool
def intent_scan(target: str) -> str:
    """当用户请求进行完整安全扫描/漏洞检测/信息收集时调用此工具。target参数为扫描目标URL或域名。"""
    return ""

@tool
def intent_execute_tool(tool_name: str, target: str) -> str:
    """当用户明确指定要调用某个具体扫描工具时调用此工具。tool_name为工具名称，target为扫描目标。"""
    return ""

@tool
def intent_chat(message: str) -> str:
    """当用户进行安全咨询、技术问答、概念询问等对话类请求时调用此工具。"""
    return ""

@tool
def intent_upload_script() -> str:
    """当用户请求上传自定义脚本、导入脚本或添加自定义工具时调用此工具。"""
    return ""

@tool
def intent_generate_script(description: str) -> str:
    """当用户请求让AI生成安全扫描脚本或工具时调用此工具。description为用户的需求描述。"""
    return ""

INTENT_TOOLS = [intent_scan, intent_execute_tool, intent_chat, intent_upload_script, intent_generate_script]

def map_tool_call_to_intent(tool_name: str) -> str:
    """将tool_call名称映射为intent_type"""
    mapping = {
        "intent_scan": "scan",
        "intent_execute_tool": "tool",
        "intent_chat": "chat",
        "intent_upload_script": "upload_script",
        "intent_generate_script": "generate_script",
    }
    return mapping.get(tool_name, "chat")

script_manager = ScriptManager.get_instance()
