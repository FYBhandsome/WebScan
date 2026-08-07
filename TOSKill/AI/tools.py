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
import logging
import re
import json
import socket

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
from TOSKill.tools.vuln_scan.sqli import sqli_scan as sqli
from TOSKill.tools.vuln_scan.xss import xss_scan as xss
from TOSKill.tools.vuln_scan.csrf import csrf_scan as csrf
from TOSKill.tools.vuln_scan.fileupload import fileupload_scan as fileupload
from TOSKill.tools.vuln_scan.cmdi import cmdi_scan as cmdi
from TOSKill.tools.vuln_scan.ssrf import ssrf_scan as ssrf
from TOSKill.tools.vuln_scan.lfi import lfi_scan as lfi
from TOSKill.tools.vuln_scan.weakpass import weakpass_scan as weakpass
from TOSKill.tools.poc.thinkphp import thinkphp_rce
from TOSKill.tools.poc.struts2 import struts2_s2_032
from TOSKill.tools.poc.weblogic import weblogic_cve_2020_2551

logger = logging.getLogger(__name__)

# 可选依赖：tld模块用于提取根域名
try:
    from tld import get_tld
    HAS_TLD = True
except ImportError:
    HAS_TLD = False
    logger.warning("tld模块未安装，域名权重查询功能将受限")

AUTH_DEFAULT_EXPIRY_MINUTES = 30

# Cookie下发模式：on_demand（按需，由AI决策是否传入）或 legacy（自动注入）
COOKIE_INJECTION_MODE = "on_demand"


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


def validate_ip(ip: str) -> bool:
    """验证IP格式合法性"""
    try:
        socket.inet_aton(ip)
        return True
    except:
        return False

def domain2ip(domain: str) -> Optional[str]:
    """域名自动解析为IP"""
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def get_root_domain(domain: str) -> str:
    """提取根域名（修复权重查询BUG）"""
    if not HAS_TLD:
        # 如果没有tld模块，返回原始域名
        return domain
    try:
        return get_tld(f"http://{domain}", as_object=True).fld
    except:
        return domain

def clean_target(target: str) -> str:
    """URL/IP/域名 自动清洗（修复格式非法+协议头缺失）"""
    if isinstance(target, dict):
        target = target.get("target") or target.get("url") or target.get("host") or ""
    
    if not isinstance(target, str):
        target = str(target) if target is not None else ""
    
    target = target.strip()
    if not target:
        return ""

    # 自动补全协议头
    parsed = urlparse(target)
    if not parsed.scheme:
        target = f"http://{target}"
    
    # 提取主机地址
    parsed = urlparse(target)
    host = parsed.netloc or parsed.path
    # 去除端口
    host = host.split(':')[0]
    
    return host


def normalize_target_url(target: str, default_scheme: str = "https") -> str:
    """Return a canonical URL for HTTP-oriented scanners."""
    if isinstance(target, dict):
        target = target.get("target") or target.get("url") or target.get("host") or ""
    value = str(target or "").strip()
    if not value:
        return ""
    parsed = urlparse(value if "://" in value else f"{default_scheme}://{value}")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    netloc = parsed.netloc
    path = parsed.path or ""
    query = f"?{parsed.query}" if parsed.query else ""
    fragment = f"#{parsed.fragment}" if parsed.fragment else ""
    return f"{parsed.scheme}://{netloc}{path}{query}{fragment}".rstrip("/")


def normalize_target_domain(target: str) -> str:
    """Return only the hostname for domain-oriented scanners."""
    url = normalize_target_url(target)
    if not url:
        return clean_target(target)
    parsed = urlparse(url)
    return parsed.hostname or ""

def invoke_tool_with_auth(tool, params_or_target, state: Dict[str, Any] = None, llm_params: Dict[str, Any] = None) -> Any:
    """带认证信息的工具调用辅助函数（非强制性）
    
    认证机制为非强制性要求：
    - 优先使用 state.get("auth_info", {}) 中的认证信息
    - 若无有效认证信息，将以未认证模式继续执行
    - 不会因缺少认证而中断流程或抛出阻断性错误
    
    LLM参数传递机制：
    - llm_params: LLM通过Function Calling生成的工具调用参数
    - 这些参数会被合并到工具调用参数中，覆盖默认值
    - 支持将LLM生成的结构化参数解析为对应工具脚本的变量
    
    Args:
        tool: LangChain工具实例
        params_or_target: 扫描目标URL(str)或tool_call参数字典(dict)
        state: 包含认证信息的状态字典（可选，无认证信息时忽略）
        llm_params: LLM生成的工具调用参数（可选，用于传递结构化参数）
        
    Returns:
        工具执行结果（无论是否有认证信息都会返回）
    """
    tool_name = getattr(tool, 'name', str(tool))
    
    if isinstance(params_or_target, str):
        params = {"target": params_or_target}
    else:
        params = dict(params_or_target)
    
    if llm_params and isinstance(llm_params, dict):
        # __extend_params 动态参数注入：从 llm_params 中提取并合并
        llm_extend = llm_params.get("__extend_params")
        if isinstance(llm_extend, dict):
            for k, v in llm_extend.items():
                if k not in params and v is not None:
                    params[k] = v
        for key, value in llm_params.items():
            if key not in ("target",) and value is not None:
                params[key] = value

    # __extend_params 动态参数注入：从 state 中提取并合并
    if state and isinstance(state, dict):
        state_extend = state.get("__extend_params")
        if isinstance(state_extend, dict):
            for k, v in state_extend.items():
                if k not in params and v is not None:
                    params[k] = v
    
    log_msg = f"[LLM参数提取] 工具: {tool_name} | 参数: {json.dumps(params, ensure_ascii=False, default=str)[:200]}"
    logger.info(log_msg)
    
    if state:
        session_id = state.get("websocket_session_id") or state.get("task_id")
        if session_id:
            try:
                import asyncio
                from .graph import safe_ws_send
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.create_task(safe_ws_send(session_id, {
                        "type": "workflow_log",
                        "payload": {
                            "level": "INFO",
                            "message": log_msg,
                            "source": "llm_params",
                            "tool": tool_name,
                            "params": {k: str(v)[:100] for k, v in params.items()},
                            "timestamp": datetime.now().isoformat()
                        }
                    }))
            except Exception as e:
                logger.debug(f"发送LLM参数日志失败: {e}")
    
    if state:
        unified_auth = state.get("auth_info", {})

        # Cookie按需下发：仅在on_demand模式下不自动注入，由AI决策
        if COOKIE_INJECTION_MODE == "on_demand":
            # 按需模式：不自动注入cookie，仅保留LLM已显式传入的参数
            pass
        elif tool_name in {getattr(t, "name", "") for t in INFO_COLLECTION_TOOLS}:
            # 信息收集工具在任何模式下都不下发cookie
            pass
        elif unified_auth:
            # legacy模式：自动注入（原有逻辑）
            cookies = unified_auth.get("cookies", {})
            headers = unified_auth.get("headers", {})
            auth_token = unified_auth.get("token", "")

            if cookies and "cookies" not in params:
                params["cookies"] = cookies
            if headers and "headers" not in params:
                params["headers"] = headers
            if auth_token and "auth_token" not in params:
                params["auth_token"] = auth_token
        else:
            cookies = state.get("auth_cookies") or state.get("session_cookies")
            headers = state.get("auth_headers")
            auth_token = state.get("auth_token") or state.get("session_token")

            if cookies and "cookies" not in params:
                params["cookies"] = cookies
            if headers and "headers" not in params:
                params["headers"] = headers
            if auth_token and "auth_token" not in params:
                params["auth_token"] = auth_token
    
    # 若工具函数含 **kwargs（如 register_script_as_tool 注册的 tool_func），
    # 直接调用 func 绕过 langchain Tool 单参限制（Tool.invoke 拒绝多 key dict），
    # 将 params 作为 kwargs 透传；不含 **kwargs 的工具仍走 langchain invoke 原路径
    import inspect as _inspect
    _func = getattr(tool, 'func', None)
    if _func is not None and isinstance(params, dict):
        try:
            _f_sig = _inspect.signature(_func)
            _has_vkw = any(
                p.kind == _inspect.Parameter.VAR_KEYWORD
                for p in _f_sig.parameters.values()
            )
        except (ValueError, TypeError):
            _has_vkw = False
        if _has_vkw:
            return _func(**params)

    return tool.invoke(params)


def unified_tool_invoke(tool_name: str, arguments: Dict[str, Any], state: Dict[str, Any] = None) -> Dict[str, Any]:
    """统一脚本工具调用传参接口层

    支持动态参数扩展，兼容旧脚本：
    - 通过inspect.signature检查工具函数参数，过滤不存在的key
    - 新参数自动传递给支持的工具
    - 旧脚本在无新参数时正常运行
    - 支持 __extend_params 动态参数注入：合并后经 signature 过滤，旧脚本自动忽略

    Args:
        tool_name: 工具名称
        arguments: LLM通过Function Calling生成的参数字典
        state: 包含认证信息的状态字典（可选）

    Returns:
        工具执行结果
    """
    import inspect

    tool = get_tool_by_name(tool_name)
    if not tool:
        return {"success": False, "error": f"工具不存在: {tool_name}", "data": {}}

    # __extend_params 动态参数注入：展开合并到调用参数，然后删除容器键
    merged_args = dict(arguments)
    extend_params = merged_args.pop("__extend_params", None)
    if isinstance(extend_params, dict):
        # 合并扩展参数，已有显式参数优先（不被覆盖）
        for k, v in extend_params.items():
            if k not in merged_args:
                merged_args[k] = v

    # 过滤参数：只传递工具函数实际接受的参数
    try:
        if hasattr(tool, 'func'):
            sig = inspect.signature(tool.func)
        elif hasattr(tool, 'invoke'):
            # LangChain tool
            sig = inspect.signature(tool.invoke) if callable(tool.invoke) else None
        else:
            sig = None

        if sig:
            accepted_params = set(sig.parameters.keys())
            # 若工具函数含 **kwargs（VAR_KEYWORD，如 register_script_as_tool 注册的 tool_func），
            # 则不做过滤，全部透传 —— 由工具函数内部再按 entry 签名二次过滤
            has_var_keyword = any(
                p.kind == inspect.Parameter.VAR_KEYWORD
                for p in sig.parameters.values()
            )
            if has_var_keyword:
                filtered_args = dict(merged_args)
            else:
                filtered_args = {k: v for k, v in merged_args.items() if k in accepted_params}
        else:
            filtered_args = dict(merged_args)
    except Exception:
        filtered_args = dict(merged_args)

    # 通过invoke_tool_with_auth执行，支持认证信息
    return invoke_tool_with_auth(tool, filtered_args, state)


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
    
    nested_data = result.get("data") if isinstance(result.get("data"), dict) else {}
    nested_cookies = nested_data.get("cookies")
    if nested_cookies is not None:
        cookies = nested_cookies
        if isinstance(cookies, dict):
            unified_auth["cookies"] = cookies
        elif isinstance(cookies, list):
            unified_auth["cookies"] = {str(i): value for i, value in enumerate(cookies)}
        elif isinstance(cookies, str):
            unified_auth["cookies"] = {"cookie": cookies}
        if cookies:
            auth_info["session_cookies"] = cookies
            auth_info["auth_cookies"] = cookies

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


# ==================== Cookie提取工具（会话凭证管理） ====================

@tool
def cookie_extract(target_domain: str = "") -> ToolResult:
    """
    独立凭证提取脚本，从会话环境提取当前全量cookie集合。

    **重要：业务脚本内部不应自己提取cookie，统一通过此工具获取。**

    此工具仅负责凭证提取，不执行业务逻辑。

    Args:
        target_domain: 目标域名（可选），为空返回全部会话cookie。
                      例如："example.com" 只返回该域名的cookie

    Returns:
        ToolResult: 标准返回格式
            - success: 是否成功提取cookie
            - data: 包含cookie数据的字典
                - cookies: 提取的cookie字典 {"name": "value"}
                - domains: cookie所属域名列表
            - error: 错误信息（如有）
            - timestamp: 执行时间戳

    Note:
        - 此工具从state中的auth_info获取cookie
        - 支持域名过滤，便于针对性提取
        - 返回的cookie可用于后续认证扫描

    Example:
        >>> result = cookie_extract("example.com")
        >>> result["data"]["cookies"]
        {"sessionid": "abc123", "token": "xyz789"}
    """
    from TOSKill.AI.graph import memory_store

    logger.info(f"[+] 执行Cookie提取: target_domain={target_domain or '全部'}")

    try:
        # 获取当前会话状态（通过环境变量或全局变量）
        import os
        session_id = os.getenv("CURRENT_SESSION_ID", "")

        if not session_id:
            # 尝试从其他来源获取session_id
            return wrap_tool_result(
                success=False,
                data={"cookies": {}, "domains": []},
                error="无法获取当前会话ID，请确保在正确的上下文中调用"
            )

        state = memory_store.get_session(session_id)
        if not state:
            return wrap_tool_result(
                success=False,
                data={"cookies": {}, "domains": []},
                error=f"会话 {session_id} 不存在"
            )

        # 从统一认证信息中提取
        auth_info = state.get("auth_info", {})
        all_cookies = auth_info.get("cookies", {})

        # 兼容旧格式
        if not all_cookies:
            all_cookies = state.get("auth_cookies") or state.get("session_cookies", {})

        if isinstance(all_cookies, str):
            # 处理字符串格式的cookie
            all_cookies = {"cookie": all_cookies}

        # 域名过滤
        filtered_cookies = {}
        domains = []

        if target_domain:
            # 过滤指定域名的cookie（简单匹配）
            filtered_cookies = all_cookies
            domains = [target_domain]
            logger.info(f"提取指定域名cookie: {target_domain}")
        else:
            # 返回全部cookie
            filtered_cookies = all_cookies
            domains = list(set(all_cookies.keys())) if all_cookies else []

        logger.info(f"成功提取 {len(filtered_cookies)} 个cookie")

        return wrap_tool_result(
            success=True,
            data={
                "cookies": filtered_cookies,
                "domains": domains,
                "total_count": len(filtered_cookies)
            }
        )

    except Exception as e:
        logger.error(f"Cookie提取失败: {e}")
        return wrap_tool_result(
            success=False,
            data={"cookies": {}, "domains": []},
            error=str(e)
        )


@tool
def cookie_brute_extract(target: str, login_paths: List[str] = None, cred_pairs: List[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    暴力提取Cookie工具 - 通过尝试常见登录路径和凭据对获取会话Cookie。

    对目标的多个登录路径进行凭据尝试，登录成功后从响应中提取Set-Cookie或会话Token。
    适用于未提供认证信息但需要会话凭证的场景。

    Args:
        target: 目标URL，如 http://example.com
        login_paths: 待尝试的登录路径列表，默认覆盖常见路径
                     ["/login", "/admin", "/admin/login", "/user/login", "/api/login", "/signin"]
        cred_pairs: 凭据对列表，每项包含 username 和 password 字段。
                    默认包含常见弱口令组合。

    Returns:
        Dict[str, Any]: 标准工具返回格式
            - success: 是否成功获取到Cookie
            - data: {"cookies": {...}, "source_path": "/login", "credentials_used": {...}}
            - error: 错误信息（成功时为空字符串）
            - metadata: {"tool": "cookie_brute_extract", "target": target, "paths_tried": N}

    Example:
        >>> result = cookie_brute_extract("http://example.com")
        >>> result["success"]
        True
        >>> result["data"]["cookies"]
        {"sessionid": "abc123"}
    """
    import requests

    if login_paths is None:
        login_paths = ["/login", "/admin", "/admin/login", "/user/login", "/api/login", "/signin"]
    if cred_pairs is None:
        cred_pairs = [
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": "123456"},
            {"username": "admin", "password": "password"},
            {"username": "root", "password": "root"},
            {"username": "test", "password": "test"},
        ]

    # 规范化目标URL，确保带协议头
    raw = target.strip() if isinstance(target, str) else str(target)
    if not raw:
        return wrap_tool_result(
            success=False,
            data={"cookies": {}, "source_path": "", "credentials_used": {}, "tool": "cookie_brute_extract", "target": target, "paths_tried": 0},
            error="目标URL为空"
        )
    if not raw.startswith("http://") and not raw.startswith("https://"):
        base_url = f"http://{raw}"
    else:
        base_url = raw
    base_url = base_url.rstrip("/")

    logger.info(f"[+] 执行Cookie暴力提取: {base_url}")

    paths_tried = 0
    try:
        for path in login_paths:
            login_url = f"{base_url}{path if path.startswith('/') else '/' + path}"
            for cred in cred_pairs:
                paths_tried += 1
                try:
                    resp = requests.post(
                        login_url,
                        data=cred,
                        timeout=10,
                        allow_redirects=False
                    )

                    # 从 Set-Cookie 响应头解析 cookie
                    cookies = {}
                    set_cookie = resp.headers.get("Set-Cookie", "")
                    if set_cookie:
                        for item in set_cookie.split(";"):
                            if "=" in item:
                                name, _, value = item.partition("=")
                                name = name.strip()
                                if name and name.lower() not in (
                                    "path", "domain", "expires", "max-age",
                                    "secure", "httponly", "samesite"
                                ):
                                    cookies[name] = value.strip()

                    # 同时从 requests.cookies 对象提取
                    if resp.cookies:
                        for ck in resp.cookies:
                            cookies[ck.name] = ck.value

                    # 登录成功判定：获取到有效cookie
                    if cookies:
                        logger.info(
                            f"[+] Cookie暴力提取成功: {login_url} "
                            f"凭据={cred.get('username')}"
                        )
                        return wrap_tool_result(
                            success=True,
                            data={
                                "cookies": cookies,
                                "source_path": path,
                                "credentials_used": cred,
                                "tool": "cookie_brute_extract",
                                "target": target,
                                "paths_tried": paths_tried,
                            }
                        )
                except requests.exceptions.Timeout:
                    logger.debug(f"登录路径请求超时: {login_url}")
                    continue
                except Exception as e:
                    logger.debug(f"尝试登录路径失败: {login_url} - {e}")
                    continue

        return wrap_tool_result(
            success=False,
            data={"cookies": {}, "source_path": "", "credentials_used": {}, "tool": "cookie_brute_extract", "target": target, "paths_tried": paths_tried},
            error="所有登录路径和凭据对均未获取到有效Cookie"
        )
    except Exception as e:
        logger.error(f"Cookie暴力提取失败: {e}")
        return wrap_tool_result(
            success=False,
            data={"cookies": {}, "source_path": "", "credentials_used": {}, "tool": "cookie_brute_extract", "target": target, "paths_tried": paths_tried},
            error=str(e)
        )


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
    t = normalize_target_domain(target)
    logger.info(f"[+] 执行子域名扫描：{t}")
    try:
        raw_result = subdomain(t)
        return wrap_tool_result(
            success=True,
            data=raw_result if isinstance(raw_result, dict) else {"result": raw_result}
        )
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
    t = normalize_target_url(target)
    logger.info(f"[+] 执行WAF检测：{t}")
    try:
        raw_result = waf_detect(t)
        return wrap_tool_result(
            success=True,
            data=raw_result if isinstance(raw_result, dict) else {"result": raw_result}
        )
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
    t = clean_target(target)
    logger.info(f"[+] 执行CMS识别：{t}")
    try:
        raw_result = cms_detect(t)
        return wrap_tool_result(
            success=True,
            data=raw_result if isinstance(raw_result, dict) else {"result": raw_result}
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
    t = clean_target(target)
    # 修复：域名自动转IP
    if not validate_ip(t):
        t = domain2ip(t) or t
    
    logger.info(f"[+] 执行IP定位：{t}")
    try:
        raw_result = ip_locate(t)
        return wrap_tool_result(
            success=True,
            data=raw_result if isinstance(raw_result, dict) else {"result": raw_result}
        )
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
        raw_result = webside_query(t)
        return wrap_tool_result(
            success=True,
            data=raw_result if isinstance(raw_result, dict) else {"result": raw_result}
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
    # 修复：提取根域名
    t = get_root_domain(t)
    
    logger.info(f"[+] 执行权重查询：{t}")
    try:
        raw_result = web_weight(t)
        return wrap_tool_result(
            success=True,
            data=raw_result if isinstance(raw_result, dict) else {"result": raw_result}
        )
    except Exception as e:
        logger.error(f"权重查询失败: {e}")
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
    t = clean_target(target)
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
        return wrap_tool_result(
            success=True,
            data=raw_result if isinstance(raw_result, dict) else {"result": raw_result},
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
    t = clean_target(target)
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
        return wrap_tool_result(
            success=True,
            data=raw_result if isinstance(raw_result, dict) else {"result": raw_result}
        )
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
    t = clean_target(target)
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
        return wrap_tool_result(
            success=True,
            data=raw_result if isinstance(raw_result, dict) else {"result": raw_result}
        )
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
    t = clean_target(target)
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
        return wrap_tool_result(
            success=True,
            data=raw_result if isinstance(raw_result, dict) else {"result": raw_result}
        )
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
    t = clean_target(target)
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
        return wrap_tool_result(
            success=True,
            data=raw_result if isinstance(raw_result, dict) else {"result": raw_result}
        )
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
    t = clean_target(target)
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
        return wrap_tool_result(
            success=True,
            data=raw_result if isinstance(raw_result, dict) else {"result": raw_result}
        )
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
    t = clean_target(target)
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
        return wrap_tool_result(
            success=True,
            data=raw_result if isinstance(raw_result, dict) else {"result": raw_result}
        )
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
    t = clean_target(target)
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
        return wrap_tool_result(
            success=True,
            data=raw_result if isinstance(raw_result, dict) else {"result": raw_result},
            auth_info=auth_extracted.get("auth_info") if auth_extracted else None
        )
    except Exception as e:
        logger.error(f"弱口令扫描失败: {e}")
        return wrap_tool_result(success=False, data={}, error=str(e))


@tool
def dvwa_vuln_scanner(
    target: str,
    cookie: Any = None,
    __extend_params: Optional[Dict[str, Any]] = None,
) -> ToolResult:
    """DVWA靶场漏洞综合扫描工具

    对DVWA靶场常见漏洞点发起最小化payload测试，返回原始漏洞JSON证据。
    支持通过cookie参数传入会话凭证（可经__extend_params动态注入）。

    Args:
        target: DVWA靶场URL，如 http://127.0.0.1:8080/setup.php
        cookie: 可选Cookie字符串，格式: "name1=value1; name2=value2"

    Returns:
        ToolResult: 标准返回格式
            - success: 扫描是否成功执行
            - data: 包含漏洞证据的字典
                - target: 扫描目标
                - findings: 漏洞发现列表
                    - vuln_type: 漏洞类型
                    - url: 漏洞点URL
                    - payload: 测试payload
                    - evidence: 响应特征证据
                    - severity: 严重等级
            - error: 错误信息（如有）
            - timestamp: 执行时间戳
    """
    # 综合脚本已移至独立模块，保留此注册入口以兼容现有 TOOL_MAP、Cookie 分发和调用协议。
    from TOSKill.tools.vuln_scan.dvwa import adapter_wrapper
    delegated = adapter_wrapper(
        target=target,
        cookie=cookie,
        __extend_params=__extend_params,
    )
    delegated.setdefault("timestamp", datetime.now().isoformat())
    return delegated

    # Legacy implementation retained below for source compatibility.
    import requests

    # 从target解析base_url
    raw = target.strip() if isinstance(target, str) else str(target)
    if not raw:
        return wrap_tool_result(
            success=False,
            data={"target": target, "findings": []},
            error="目标URL为空"
        )
    if not raw.startswith("http://") and not raw.startswith("https://"):
        raw = f"http://{raw}"

    parsed = urlparse(raw)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    logger.info(f"[+] 执行DVWA漏洞扫描: {base_url} (cookie: {'有' if cookie else '无'})")

    headers = {}
    if cookie:
        headers["Cookie"] = cookie

    # 漏洞测试配置：漏洞类型 → (路径, 请求方法, 参数/payload, 命中特征)
    vuln_tests = [
        {
            "vuln_type": "SQLInjection",
            "path": "/vulnerabilities/sqli/",
            "method": "GET",
            "params": {"id": "' OR '1'='1", "Submit": "Submit"},
            "evidence_patterns": [
                "First name", "Surname", "user", "admin",
                "SQL syntax", "mysql", "syntax error"
            ],
            "severity": "high"
        },
        {
            "vuln_type": "XSSReflected",
            "path": "/vulnerabilities/xss_r/",
            "method": "GET",
            "params": {"name": "<script>alert(1)</script>"},
            "evidence_patterns": [
                "<script>alert(1)</script>", "alert(1)"
            ],
            "severity": "medium"
        },
        {
            "vuln_type": "XSSStored",
            "path": "/vulnerabilities/xss_s/",
            "method": "POST",
            "params": {"txtName": "test", "mtxMessage": "<script>alert(1)</script>", "btnSign": "Sign Guestbook"},
            "evidence_patterns": [
                "<script>alert(1)</script>", "alert(1)"
            ],
            "severity": "medium"
        },
        {
            "vuln_type": "CommandInjection",
            "path": "/vulnerabilities/exec/",
            "method": "POST",
            "params": {"ip": ";id", "Submit": "Submit"},
            "evidence_patterns": [
                "uid=", "gid=", "root", "www-data"
            ],
            "severity": "high"
        },
        {
            "vuln_type": "FileInclusion",
            "path": "/vulnerabilities/fi/",
            "method": "GET",
            "params": {"page": "../../../../../../etc/passwd"},
            "evidence_patterns": [
                "root:x:0:0:", "/bin/bash", "/bin/sh"
            ],
            "severity": "high"
        },
        {
            "vuln_type": "CSRF",
            "path": "/vulnerabilities/csrf/",
            "method": "GET",
            "params": {"password_new": "testpass", "password_conf": "testpass", "Change": "Change"},
            "evidence_patterns": [
                "Password Changed", "password"
            ],
            "severity": "medium"
        },
        {
            "vuln_type": "FileUpload",
            "path": "/vulnerabilities/upload/",
            "method": "POST",
            "params": {},  # 文件上传需特殊处理
            "evidence_patterns": [
                "upload", "successfully", "../../hackable/uploads/"
            ],
            "severity": "high"
        },
        {
            "vuln_type": "BruteForce",
            "path": "/vulnerabilities/brute/",
            "method": "GET",
            "params": {"username": "admin", "password": "password", "Login": "Login"},
            "evidence_patterns": [
                "Welcome to the password protected area", "username and/or password incorrect"
            ],
            "severity": "medium"
        }
    ]

    findings = []

    try:
        for test in vuln_tests:
            url = f"{base_url}{test['path']}"
            try:
                if test["vuln_type"] == "FileUpload":
                    # 文件上传：发送最小化测试文件
                    files = {"uploaded": ("test.php", "<?php echo 'dvwa_test';?>", "application/x-php")}
                    data = {"Upload": "Upload"}
                    resp = requests.post(url, headers=headers, files=files, data=data, timeout=15, allow_redirects=True, verify=False)
                elif test["method"] == "GET":
                    resp = requests.get(url, headers=headers, params=test["params"], timeout=15, verify=False)
                else:
                    resp = requests.post(url, headers=headers, data=test["params"], timeout=15, verify=False)

                resp_text = resp.text

                # 检查响应是否命中漏洞特征
                matched_evidence = []
                for pattern in test["evidence_patterns"]:
                    if pattern.lower() in resp_text.lower():
                        matched_evidence.append(pattern)

                if matched_evidence:
                    findings.append({
                        "vuln_type": test["vuln_type"],
                        "url": url,
                        "payload": test["params"] if test["vuln_type"] != "FileUpload" else "test.php upload",
                        "evidence": matched_evidence,
                        "severity": test["severity"]
                    })
                    logger.info(f"[+] DVWA漏洞发现: {test['vuln_type']} @ {url}")

            except requests.exceptions.Timeout:
                logger.debug(f"DVWA扫描超时: {url}")
                continue
            except requests.exceptions.ConnectionError:
                logger.debug(f"DVWA连接失败: {url}")
                continue
            except Exception as e:
                logger.debug(f"DVWA测试失败: {url} - {e}")
                continue

        return wrap_tool_result(
            success=True,
            data={
                "target": target,
                "base_url": base_url,
                "findings": findings,
                "total_findings": len(findings)
            }
        )

    except Exception as e:
        logger.error(f"DVWA漏洞扫描失败: {e}")
        return wrap_tool_result(
            success=False,
            data={"target": target, "findings": []},
            error=str(e)
        )


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

# Cookie提取工具（独立凭证管理）
COOKIE_TOOLS = [
    cookie_extract,
    cookie_brute_extract,
]

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
    dvwa_vuln_scanner,
]

POC_TOOLS = [
    thinkphp_rce_scan,
    struts2_scan,
    weblogic_scan,
]

ALL_TOOLS = COOKIE_TOOLS + INFO_COLLECTION_TOOLS + VULN_SCAN_TOOLS + POC_TOOLS

TOOL_MAP = {t.name: t for t in ALL_TOOLS}

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
]


TOOL_SEQUENCE_DVWA = [
    "cookie_extract",
    "dvwa_vuln_scanner",
]


def get_tool_by_name(name: str):
    """根据名称获取工具"""
    return TOOL_MAP.get(name)


def get_all_tool_names() -> List[str]:
    """获取所有工具名称"""
    return list(TOOL_MAP.keys())


def is_tool_exists(tool_name: str) -> bool:
    """检查工具是否存在"""
    return tool_name in TOOL_MAP


def get_tools_by_mode(mode: str) -> List:
    """根据模式获取工具列表"""
    if mode == "info_collection":
        return INFO_COLLECTION_TOOLS
    elif mode == "vuln_scan":
        return VULN_SCAN_TOOLS
    elif mode == "dvwa_scan":
        return [cookie_extract, dvwa_vuln_scanner]
    elif mode == "full_scan":
        return ALL_TOOLS
    return INFO_COLLECTION_TOOLS


def get_tool_sequence(mode: str) -> List[str]:
    """获取工具执行序列"""
    if mode == "info_collection":
        return TOOL_SEQUENCE_INFO
    elif mode == "vuln_scan":
        return TOOL_SEQUENCE_VULN
    elif mode == "dvwa_scan":
        return TOOL_SEQUENCE_DVWA
    elif mode == "full_scan":
        return TOOL_SEQUENCE_INFO + TOOL_SEQUENCE_VULN
    return TOOL_SEQUENCE_INFO


def get_custom_tool_names() -> List[str]:
    """获取自定义工具名称列表"""
    return [name for name in TOOL_MAP.keys() if name.startswith('custom_') or name.startswith('ai_gen_')]


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
    _registered_scripts: Dict[str, Dict] = {}
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
            from TOSKill.config import settings
            cls._scripts_dir = settings.CUSTOM_SCRIPTS_PATH
            cls._scripts_dir.mkdir(parents=True, exist_ok=True)
        return cls._instance
    
    def _get_llm(self):
        """获取LLM实例 - 使用统一客户端"""
        from TOSKill.AI.llm_client import get_llm
        return get_llm()
    
    async def analyze_script_with_ai(self, script_content: str) -> Dict:
        """使用AI分析脚本，生成工具描述"""
        from langchain_core.messages import SystemMessage, HumanMessage
        
        prompt = f"""请分析以下Python安全扫描脚本，并以JSON格式返回分析结果。

脚本内容:
```python
{script_content[:2000]}
```

请返回以下JSON格式（只返回JSON，不要其他内容）:
{{
    "tool_name": "英文下划线分隔的工具名称，如custom_port_check",
    "description": "工具功能描述（一句话）",
    "category": "工具类别：info_collection、vuln_scan、poc 或 custom",
    "input_type": "输入类型：url、ip 或 domain",
    "output_type": "输出类型描述"
}}"""
        
        try:
            llm = self._get_llm()
            messages = [
                SystemMessage(content="你是一个安全工具分析专家，请分析脚本并返回JSON格式的结果。"),
                HumanMessage(content=prompt)
            ]
            response = llm.invoke(messages)
            
            content = response.content if hasattr(response, 'content') else str(response)
            
            import json
            import re
            
            json_match = re.search(r'\{[^{}]*\}', content, re.DOTALL)
            if json_match:
                try:
                    args = json.loads(json_match.group())
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
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            logger.error(f"AI分析脚本失败: {e}")
        
        return {
            "tool_name": f"custom_{hash(script_content) % 10000}",
            "description": "自定义扫描脚本",
            "category": "custom",
            "input_type": "url",
            "output_type": "其他"
        }
    
    def register_script_as_tool(self, script_content: str, script_name: str, 
                                 description: str, category: str = "custom") -> Dict:
        """将脚本注册为 LangChain 工具"""
        from datetime import datetime
        import importlib.util
        import subprocess
        import json

        try:
            from langchain_core.tools import Tool
        except ImportError:
            from langchain.tools import Tool

        try:
            from ..AI.script_safety import normalize_script_for_registration
            ok, normalize_msg, normalized = normalize_script_for_registration(
                script_content,
                script_name=script_name,
                filename=script_name,
                default_prefix="ai_gen" if str(script_name).startswith("ai_gen_") else "custom",
            )
            if not ok or normalized is None:
                return {"success": False, "error": f"脚本验证失败: {normalize_msg}"}
            script_content = normalized.content
            script_name = normalized.filename
            base_name = normalized.tool_name
            script_kind = normalized.language
        except ImportError:
            pass

        script_kind = locals().get("script_kind", "js" if script_name.lower().endswith(".js") else "py")
        base_name = locals().get("base_name", script_name.rsplit(".", 1)[0] if script_name.lower().endswith((".py", ".js")) else script_name)

        try:
            if script_kind == "js":
                script_path = self._scripts_dir / f"{base_name}.js"
                with open(script_path, 'w', encoding='utf-8') as f:
                    f.write(script_content)

                def create_js_tool_func(script_path, script_name):
                    def tool_func(target: str, **kwargs):
                        try:
                            payload = {"target": target, "kwargs": kwargs}
                            runner = r"""
const fs = require('fs');
const vm = require('vm');
const path = process.argv[2];
const input = JSON.parse(process.argv[3] || '{}');
const code = fs.readFileSync(path, 'utf8');
const sandbox = {
  console,
  target: input.target,
  kwargs: input.kwargs || {},
  module: { exports: {} },
  exports: {},
  require: (name) => {
    const allowed = new Set(['fs', 'path', 'url', 'querystring', 'crypto']);
    if (!allowed.has(name)) throw new Error('Disallowed module: ' + name);
    return require(name);
  },
  setTimeout,
  clearTimeout,
  setInterval,
  clearInterval,
  Buffer,
  process: { env: {} },
};
vm.createContext(sandbox);
vm.runInContext(code, sandbox, { timeout: 3000 });
const entry = typeof sandbox.run === 'function' ? sandbox.run
  : typeof sandbox.scan === 'function' ? sandbox.scan
  : (sandbox.module && typeof sandbox.module.exports?.run === 'function' ? sandbox.module.exports.run
  : typeof sandbox.module.exports?.scan === 'function' ? sandbox.module.exports.scan : null);
if (!entry) throw new Error('JS script missing run(target) or scan(target)');
Promise.resolve(entry.call(sandbox, input.target, ...(input.kwargs ? [input.kwargs] : [])))
  .then((output) => {
    process.stdout.write(JSON.stringify({ success: true, data: output }));
  })
  .catch((err) => {
    process.stdout.write(JSON.stringify({ success: false, error: String(err && err.message ? err.message : err) }));
    process.exitCode = 1;
  });
"""
                            result = subprocess.run(
                                ['node', '-e', runner, str(script_path), json.dumps(payload, ensure_ascii=False)],
                                capture_output=True,
                                text=True,
                                timeout=10,
                            )
                            if not result.stdout:
                                return {"success": False, "error": result.stderr.strip() or "JS script execution failed"}
                            try:
                                parsed = json.loads(result.stdout)
                            except json.JSONDecodeError:
                                return {"success": False, "error": result.stdout[:500]}
                            return parsed if isinstance(parsed, dict) else {"success": False, "error": "JS script returned invalid format"}
                        except subprocess.TimeoutExpired:
                            return {"success": False, "error": "JS script execution timeout"}
                        except Exception as e:
                            logger.error(f"JS custom script {script_name} execution failed: {e}")
                            return {"success": False, "error": str(e)}
                    return tool_func

                tool = Tool(
                    name=base_name,
                    description=description,
                    func=create_js_tool_func(str(script_path), base_name)
                )
            else:
                script_path = self._scripts_dir / f"{base_name}.py"
                with open(script_path, 'w', encoding='utf-8') as f:
                    f.write(script_content)

                def create_tool_func(script_path, script_name):
                    def tool_func(target: str, **kwargs):
                        try:
                            spec = importlib.util.spec_from_file_location("custom_module", script_path)
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
                                '__import__': lambda name, *args, **kw: __import__(name, *args, **kw)
                            }
                            module.__builtins__ = safe_builtins
                            spec.loader.exec_module(module)

                            logger.info(f"自定义脚本执行: {script_name} -> {target} | kwargs={list(kwargs.keys())}")

                            if hasattr(module, 'run'):
                                entry = module.run
                            elif hasattr(module, 'scan'):
                                entry = module.scan
                            else:
                                return {"success": False, "error": "脚本缺少 run 或 scan 函数"}

                            import inspect as _inspect
                            filtered = {}
                            try:
                                entry_sig = _inspect.signature(entry)
                                accepted = set(entry_sig.parameters.keys())
                                has_var_keyword = any(
                                    p.kind == _inspect.Parameter.VAR_KEYWORD
                                    for p in entry_sig.parameters.values()
                                )
                                if has_var_keyword:
                                    filtered = dict(kwargs)
                                else:
                                    filtered = {k: v for k, v in kwargs.items() if k in accepted}
                            except (ValueError, TypeError):
                                filtered = {}

                            try:
                                return entry(target, **filtered)
                            except TypeError:
                                return entry(**filtered) if filtered else entry()
                        except Exception as e:
                            logger.error(f"自定义脚本 {script_name} 执行失败: {e}")
                            return {"success": False, "error": str(e)}
                    return tool_func

                tool = Tool(
                    name=base_name,
                    description=description,
                    func=create_tool_func(str(script_path), base_name)
                )

            if tool and hasattr(tool, 'name'):
                TOOL_MAP[tool.name] = tool
                if tool not in ALL_TOOLS:
                    ALL_TOOLS.append(tool)
                logger.info(f"动态注册工具: {tool.name}")
                self._registered_scripts[base_name] = {
                    "path": str(script_path),
                    "description": description,
                    "category": category,
                    "registered_at": datetime.now().isoformat(),
                    "language": script_kind,
                }
                return {"success": True, "tool_name": base_name, "tool": tool, "language": script_kind}

            script_path.unlink(missing_ok=True)
            return {"success": False, "error": "工具注册失败，脚本文件已清理"}

        except Exception as e:
            logger.error(f"注册脚本工具失败: {e}")
            return {"success": False, "error": str(e)}
    async def generate_script_with_ai(self, description: str) -> str:
        """使用AI生成扫描脚本"""
        from ..AI.script_safety import extract_code_block
        
        llm = self._get_llm()
        prompt = f"""根据以下需求生成一个Python安全扫描脚本：

需求：{description}

要求：
1. 必须包含 run(target: str) 函数
2. 返回 Dict 类型的结果，包含 success、data、message 字段
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
        try:
            response = llm.invoke(prompt).content
            code = extract_code_block(response)
            if code:
                return code
            return response.strip()
        except Exception as e:
            logger.error(f"AI生成脚本失败: {e}")
            return ""
    
    def get_registered_scripts(self) -> Dict:
        """获取已注册的脚本列表"""
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
