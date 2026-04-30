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
from typing import Dict, Any, List, Optional, TypedDict, Callable, Awaitable
from langchain.tools import tool
from urllib.parse import urlparse
from datetime import datetime, timedelta
import logging
import base64
import json
import re
import asyncio

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


class MultiStepAuthManager:
    """多步骤认证管理器
    
    支持:
    - CSRF Token 获取
    - 登录表单提交
    - 验证码处理（预留接口）
    """
    
    def __init__(self):
        self._captcha_handlers: Dict[str, Callable] = {}
        self._auth_sessions: Dict[str, Dict] = {}
    
    def register_captcha_handler(self, captcha_type: str, handler: Callable):
        """
        注册验证码处理器
        
        Args:
            captcha_type: 验证码类型（如 'image', 'recaptcha', 'geetest' 等）
            handler: 处理函数，接收验证码数据，返回验证码答案
        """
        self._captcha_handlers[captcha_type] = handler
        logger.info(f"已注册验证码处理器: {captcha_type}")
    
    async def fetch_csrf_token(
        self, 
        login_url: str, 
        session: Any = None,
        token_name: str = "csrf_token",
        token_input_name: str = "_token"
    ) -> Dict[str, Any]:
        """
        获取 CSRF Token
        
        Args:
            login_url: 登录页面URL
            session: requests Session 对象（可选）
            token_name: Token 在响应中的名称
            token_input_name: Token 在表单中的 input name
            
        Returns:
            Dict: 包含 csrf_token, cookies, headers 等信息
        """
        import requests
        
        result = {
            "success": False,
            "csrf_token": None,
            "cookies": {},
            "headers": {},
            "form_data": {},
            "error": None
        }
        
        try:
            if session is None:
                session = requests.Session()
            
            response = session.get(login_url, timeout=10, allow_redirects=True)
            response.raise_for_status()
            
            result["cookies"] = dict(session.cookies)
            result["headers"] = {"Referer": login_url}
            
            csrf_patterns = [
                rf'<input[^>]*name=["\']?{token_input_name}["\']?[^>]*value=["\']?([^"\'>\s]+)["\']?',
                rf'<meta[^>]*name=["\']?csrf-token["\']?[^>]*content=["\']?([^"\'>\s]+)["\']',
                rf'var\s+{token_name}\s*=\s*["\']([^"\']+)["\']',
                rf'"csrf[_-]?token"\s*:\s*"([^"]+)"',
            ]
            
            for pattern in csrf_patterns:
                match = re.search(pattern, response.text, re.IGNORECASE)
                if match:
                    result["csrf_token"] = match.group(1)
                    break
            
            form_data_pattern = r'<form[^>]*action=["\']?([^"\'>\s]*)["\']?[^>]*>(.*?)</form>'
            form_match = re.search(form_data_pattern, response.text, re.DOTALL | re.IGNORECASE)
            
            if form_match:
                form_action = form_match.group(1)
                form_content = form_match.group(2)
                
                if form_action:
                    if form_action.startswith('/'):
                        from urllib.parse import urljoin
                        result["form_data"]["action"] = urljoin(login_url, form_action)
                    else:
                        result["form_data"]["action"] = form_action
                
                hidden_inputs = re.findall(
                    r'<input[^>]*type=["\']?hidden["\']?[^>]*name=["\']?([^"\'>\s]+)["\']?[^>]*value=["\']?([^"\'>\s]*)["\']?',
                    form_content,
                    re.IGNORECASE
                )
                
                for name, value in hidden_inputs:
                    result["form_data"][name] = value
            
            result["success"] = True
            logger.info(f"CSRF Token 获取成功: {result['csrf_token']}")
            
        except Exception as e:
            result["error"] = str(e)
            logger.error(f"CSRF Token 获取失败: {e}")
        
        return result
    
    async def submit_login_form(
        self,
        login_url: str,
        username: str,
        password: str,
        csrf_token: str = None,
        form_data: Dict[str, str] = None,
        cookies: Dict[str, str] = None,
        headers: Dict[str, str] = None,
        session: Any = None,
        username_field: str = "username",
        password_field: str = "password",
        csrf_field: str = "_token"
    ) -> Dict[str, Any]:
        """
        提交登录表单
        
        Args:
            login_url: 登录提交URL
            username: 用户名
            password: 密码
            csrf_token: CSRF Token（可选）
            form_data: 额外的表单数据
            cookies: Cookie
            headers: 请求头
            session: requests Session 对象
            username_field: 用户名字段名
            password_field: 密码字段名
            csrf_field: CSRF Token 字段名
            
        Returns:
            Dict: 包含登录结果、cookies、token等信息
        """
        import requests
        
        result = {
            "success": False,
            "logged_in": False,
            "cookies": {},
            "token": None,
            "headers": {},
            "redirect_url": None,
            "error": None
        }
        
        try:
            if session is None:
                session = requests.Session()
            
            data = form_data.copy() if form_data else {}
            data[username_field] = username
            data[password_field] = password
            
            if csrf_token:
                data[csrf_field] = csrf_token
            
            req_headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
            if headers:
                req_headers.update(headers)
            
            response = session.post(
                login_url,
                data=data,
                headers=req_headers,
                cookies=cookies,
                timeout=15,
                allow_redirects=True
            )
            
            result["cookies"] = dict(session.cookies)
            result["redirect_url"] = response.url
            
            if response.status_code in [200, 302, 303, 307]:
                login_indicators = [
                    "dashboard", "welcome", "logout", "profile", "account",
                    "success", "logged in", "登录成功"
                ]
                
                logout_indicators = [
                    "login", "signin", "error", "invalid", "incorrect",
                    "wrong", "failed", "登录失败", "用户名或密码错误"
                ]
                
                content_lower = response.text.lower()
                
                if any(ind in content_lower for ind in login_indicators):
                    if not any(ind in content_lower for ind in logout_indicators):
                        result["logged_in"] = True
                        result["success"] = True
                
                token_patterns = [
                    r'"token"\s*:\s*"([^"]+)"',
                    r'"access_token"\s*:\s*"([^"]+)"',
                    r'"auth_token"\s*:\s*"([^"]+)"',
                    r'Authorization:\s*Bearer\s+([^\s<]+)',
                ]
                
                for pattern in token_patterns:
                    match = re.search(pattern, response.text, re.IGNORECASE)
                    if match:
                        result["token"] = match.group(1)
                        break
                
                if result["logged_in"]:
                    logger.info(f"登录成功: {username}")
                else:
                    result["error"] = "登录失败，请检查用户名和密码"
                    logger.warning(f"登录失败: {username}")
            else:
                result["error"] = f"HTTP错误: {response.status_code}"
                
        except Exception as e:
            result["error"] = str(e)
            logger.error(f"登录表单提交失败: {e}")
        
        return result
    
    async def handle_captcha(
        self,
        captcha_type: str,
        captcha_data: Any,
        session_id: str = None
    ) -> Dict[str, Any]:
        """
        处理验证码（预留接口）
        
        Args:
            captcha_type: 验证码类型
            captcha_data: 验证码数据（图片base64、验证码ID等）
            session_id: 会话ID
            
        Returns:
            Dict: 包含验证码答案
        """
        result = {
            "success": False,
            "answer": None,
            "error": None
        }
        
        handler = self._captcha_handlers.get(captcha_type)
        if handler:
            try:
                if asyncio.iscoroutinefunction(handler):
                    answer = await handler(captcha_data, session_id)
                else:
                    answer = handler(captcha_data, session_id)
                
                result["success"] = True
                result["answer"] = answer
                logger.info(f"验证码处理成功: {captcha_type}")
            except Exception as e:
                result["error"] = str(e)
                logger.error(f"验证码处理失败: {e}")
        else:
            result["error"] = f"未注册验证码处理器: {captcha_type}"
            logger.warning(result["error"])
        
        return result
    
    def create_auth_session(self, session_id: str, config: Dict[str, Any]) -> str:
        """
        创建认证会话
        
        Args:
            session_id: 会话ID
            config: 认证配置
            
        Returns:
            str: 认证会话ID
        """
        auth_session_id = f"auth_{session_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        self._auth_sessions[auth_session_id] = {
            "session_id": session_id,
            "config": config,
            "step": 0,
            "created_at": datetime.now().isoformat(),
            "status": "pending"
        }
        return auth_session_id
    
    def get_auth_session(self, auth_session_id: str) -> Optional[Dict]:
        """获取认证会话"""
        return self._auth_sessions.get(auth_session_id)
    
    def update_auth_session(self, auth_session_id: str, **kwargs):
        """更新认证会话"""
        if auth_session_id in self._auth_sessions:
            self._auth_sessions[auth_session_id].update(kwargs)
    
    def delete_auth_session(self, auth_session_id: str):
        """删除认证会话"""
        self._auth_sessions.pop(auth_session_id, None)


multi_step_auth_manager = MultiStepAuthManager()


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


def clean_target(target: str) -> str:
    """URL 自动清洗 - 类比 demo.py"""
    parsed = urlparse(target)
    return parsed.netloc.strip() if parsed.netloc else target.strip()


def invoke_tool_with_auth(tool, target: str, state: Dict[str, Any] = None) -> Any:
    """带认证信息的工具调用辅助函数
    
    优先使用 state.get("auth_info", {})，支持向后兼容旧字段
    
    Args:
        tool: LangChain工具实例
        target: 扫描目标
        state: 包含认证信息的状态字典
        
    Returns:
        工具执行结果
    """
    params = {"target": target}
    
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
    
    return tool.invoke(params)


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
        raw_result = baseinfo.invoke({"target": t})
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
        raw_result = portscan.invoke({"target": t})
        return wrap_tool_result(
            success=True,
            data=raw_result if isinstance(raw_result, dict) else {"result": raw_result}
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
        raw_result = subdomain.invoke({"domain": t})
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
        raw_result = dirscan.invoke({"target": t})
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
    t = clean_target(target)
    logger.info(f"[+] 执行WAF检测：{t}")
    try:
        raw_result = waf_detect.invoke({"target": t})
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
        raw_result = cdn_detect.invoke({"target": t})
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
        raw_result = cms_detect.invoke({"target": t})
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
        raw_result = infoleak.invoke({"target": t})
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
    logger.info(f"[+] 执行IP定位：{t}")
    try:
        raw_result = ip_locate.invoke({"ip": t})
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
        raw_result = webside_query.invoke({"ip": t})
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
    logger.info(f"[+] 执行权重查询：{t}")
    try:
        raw_result = web_weight.invoke({"domain": t})
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
        raw_result = sqli.invoke(params)
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
        raw_result = xss.invoke(params)
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
        raw_result = csrf.invoke(params)
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
        raw_result = fileupload.invoke(params)
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
        raw_result = cmdi.invoke(params)
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
        raw_result = ssrf.invoke(params)
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
        raw_result = lfi.invoke(params)
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
        raw_result = weakpass.invoke(params)
        auth_extracted = extract_auth_from_result(raw_result) if isinstance(raw_result, dict) else None
        return wrap_tool_result(
            success=True,
            data=raw_result if isinstance(raw_result, dict) else {"result": raw_result},
            auth_info=auth_extracted.get("auth_info") if auth_extracted else None
        )
    except Exception as e:
        logger.error(f"弱口令扫描失败: {e}")
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
        raw_result = thinkphp_rce.invoke({"target": t})
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
        raw_result = struts2_s2_032.invoke({"target": t})
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
        raw_result = weblogic_cve_2020_2551.invoke({"target": t})
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
]

POC_TOOLS = [
    thinkphp_rce_scan,
    struts2_scan,
    weblogic_scan,
]

ALL_TOOLS = INFO_COLLECTION_TOOLS + VULN_SCAN_TOOLS + POC_TOOLS

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


def get_tool_by_name(name: str):
    """根据名称获取工具"""
    return TOOL_MAP.get(name)


def get_all_tool_names() -> List[str]:
    """获取所有工具名称"""
    return list(TOOL_MAP.keys())


def get_tools_description() -> str:
    """获取所有工具的描述信息，用于AI提示词"""
    descriptions = []
    for name, tool in TOOL_MAP.items():
        desc = tool.description if hasattr(tool, 'description') else "无描述"
        descriptions.append(f"- {name}: {desc}")
    return "\n".join(descriptions)


def is_tool_exists(tool_name: str) -> bool:
    """检查工具是否存在"""
    return tool_name in TOOL_MAP


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


def register_custom_tool(tool, category: str = "custom"):
    """动态注册自定义工具到工具映射表"""
    global TOOL_MAP, ALL_TOOLS
    
    if tool and hasattr(tool, 'name'):
        TOOL_MAP[tool.name] = tool
        if tool not in ALL_TOOLS:
            ALL_TOOLS.append(tool)
        logger.info(f"动态注册工具: {tool.name}")
        return True
    return False


def get_custom_tool_names() -> List[str]:
    """获取自定义工具名称列表"""
    return [name for name in TOOL_MAP.keys() if name.startswith('custom_') or name.startswith('ai_gen_')]


class ScriptManager:
    """脚本管理器 - 处理上传/生成脚本的注册"""
    
    _instance = None
    _scripts_dir = None
    _registered_scripts: Dict[str, Dict] = {}
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
            from pathlib import Path
            cls._scripts_dir = Path("scripts/custom")
            cls._scripts_dir.mkdir(parents=True, exist_ok=True)
        return cls._instance
    
    def _get_llm(self):
        """获取LLM实例"""
        from langchain_openai import ChatOpenAI
        from TOSKill.config import settings
        return ChatOpenAI(
            model=settings.MODEL_ID,
            temperature=0.3,
            api_key=settings.OPENAI_API_KEY,
            base_url=settings.OPENAI_BASE_URL
        )
    
    async def analyze_script_with_ai(self, script_content: str) -> Dict:
        """使用AI分析脚本，生成工具描述"""
        import json
        import re
        
        llm = self._get_llm()
        prompt = f"""分析以下安全扫描脚本，生成工具描述：

```python
{script_content[:2000]}
```

请严格按以下JSON格式回复，不要添加其他内容：
{{
    "tool_name": "工具名称（英文，下划线分隔，如custom_port_check）",
    "description": "工具功能描述（一句话）",
    "category": "info_collection或vuln_scan或poc",
    "input_type": "url或ip或domain",
    "output_type": "漏洞信息或端口列表或其他"
}}
"""
        try:
            response = llm.invoke(prompt).content
            json_match = re.search(r'\{[^{}]*\}', response, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
                tool_name = result.get("tool_name", f"custom_{hash(script_content) % 10000}")
                if not tool_name.startswith("custom_") and not tool_name.startswith("ai_gen_"):
                    tool_name = f"custom_{tool_name}"
                result["tool_name"] = tool_name
                return result
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
        """将脚本注册为LangChain工具"""
        from pathlib import Path
        from datetime import datetime
        from langchain.tools import Tool
        import importlib.util
        
        try:
            script_path = self._scripts_dir / f"{script_name}.py"
            with open(script_path, 'w', encoding='utf-8') as f:
                f.write(script_content)
            
            def create_tool_func(script_path):
                def tool_func(target: str):
                    try:
                        spec = importlib.util.spec_from_file_location("custom_module", script_path)
                        if not spec or not spec.loader:
                            return {"success": False, "error": "无法加载脚本"}
                        
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)
                        
                        if hasattr(module, 'run'):
                            return module.run(target)
                        elif hasattr(module, 'scan'):
                            return module.scan(target)
                        else:
                            return {"success": False, "error": "脚本缺少run或scan函数"}
                    except Exception as e:
                        return {"success": False, "error": str(e)}
                return tool_func
            
            tool = Tool(
                name=script_name,
                description=description,
                func=create_tool_func(str(script_path))
            )
            
            if register_custom_tool(tool, category):
                self._registered_scripts[script_name] = {
                    "path": str(script_path),
                    "description": description,
                    "category": category,
                    "registered_at": datetime.now().isoformat()
                }
                return {"success": True, "tool_name": script_name, "tool": tool}
            
            return {"success": False, "error": "工具注册失败"}
            
        except Exception as e:
            logger.error(f"注册脚本工具失败: {e}")
            return {"success": False, "error": str(e)}
    
    async def generate_script_with_ai(self, description: str) -> str:
        """使用AI生成扫描脚本"""
        import re
        
        llm = self._get_llm()
        prompt = f"""根据以下需求生成一个Python安全扫描脚本：

需求：{description}

要求：
1. 必须包含 run(target: str) 函数
2. 返回 Dict 类型的结果，包含 success、data、message 字段
3. 包含错误处理
4. 使用 requests 库进行HTTP请求
5. 代码简洁高效

只输出Python代码，不要其他内容。使用```python包裹代码。
"""
        try:
            response = llm.invoke(prompt).content
            code_match = re.search(r'```python\s*([\s\S]*?)\s*```', response)
            if code_match:
                return code_match.group(1).strip()
            code_match = re.search(r'```\s*([\s\S]*?)\s*```', response)
            if code_match:
                return code_match.group(1).strip()
            return response.strip()
        except Exception as e:
            logger.error(f"AI生成脚本失败: {e}")
            return ""
    
    def get_registered_scripts(self) -> Dict:
        """获取已注册的脚本列表"""
        return self._registered_scripts.copy()


script_manager = ScriptManager.get_instance()
