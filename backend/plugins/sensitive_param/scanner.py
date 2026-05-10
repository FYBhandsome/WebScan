"""
敏感参数发现模块

功能:
- URL参数分析
- 表单参数提取
- JS变量分析
- API参数发现
- 敏感参数识别
- 参数值模式分析
"""

import re
import json
import logging
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError

logger = logging.getLogger(__name__)


@dataclass
class SensitiveParam:
    name: str
    location: str
    value: str
    source: str
    category: str
    severity: str
    description: str
    is_sensitive: bool
    evidence: str


SENSITIVE_PARAM_CATEGORIES = {
    "authentication": {
        "params": [
            "password", "passwd", "pwd", "pass", "secret", "token",
            "auth", "api_key", "apikey", "api_secret", "apisecret",
            "access_token", "accesstoken", "refresh_token", "refreshtoken",
            "session", "session_id", "sessionid", "session_key",
            "credential", "credentials", "login", "signin", "sign_in",
            "private_key", "privatekey", "secret_key", "secretkey",
        ],
        "severity": "critical",
        "description": "认证相关参数",
    },
    "user_identity": {
        "params": [
            "user", "username", "user_id", "userid", "uid", "user_name",
            "account", "account_id", "accountid", "member", "member_id",
            "email", "mail", "phone", "mobile", "tel", "telephone",
            "id_card", "idcard", "ssn", "social_security",
        ],
        "severity": "high",
        "description": "用户身份参数",
    },
    "financial": {
        "params": [
            "card", "card_number", "cardnumber", "credit_card", "creditcard",
            "cvv", "cvc", "card_code", "expiry", "expire", "expiration",
            "payment", "amount", "price", "total", "money", "balance",
            "bank", "bank_account", "account_number", "iban", "swift",
            "transaction", "order_id", "orderid", "invoice", "receipt",
        ],
        "severity": "critical",
        "description": "金融相关参数",
    },
    "admin": {
        "params": [
            "admin", "administrator", "root", "super", "superuser",
            "manage", "manager", "management", "control", "master",
            "privilege", "permission", "role", "group", "level",
            "is_admin", "isadmin", "is_root", "isroot", "is_super", "issuper",
        ],
        "severity": "high",
        "description": "管理权限参数",
    },
    "file_operations": {
        "params": [
            "file", "filename", "filepath", "path", "dir", "directory",
            "folder", "document", "doc", "upload", "download",
            "read", "write", "delete", "copy", "move", "rename",
            "source", "target", "dest", "destination", "output", "input",
        ],
        "severity": "high",
        "description": "文件操作参数",
    },
    "command_execution": {
        "params": [
            "cmd", "command", "exec", "execute", "system", "shell",
            "bash", "sh", "powershell", "ps", "script", "code",
            "eval", "expression", "expr", "query", "sql", "statement",
        ],
        "severity": "critical",
        "description": "命令执行参数",
    },
    "url_redirect": {
        "params": [
            "url", "uri", "link", "redirect", "redirect_url", "redirecturl",
            "return", "return_url", "returnurl", "next", "next_url", "nexturl",
            "goto", "goto_url", "gotourl", "target", "target_url", "targeturl",
            "callback", "forward", "continue", "dest", "destination",
        ],
        "severity": "high",
        "description": "URL重定向参数",
    },
    "configuration": {
        "params": [
            "config", "configuration", "setting", "settings", "option",
            "options", "param", "parameter", "args", "arguments",
            "env", "environment", "var", "variable", "property",
            "debug", "test", "dev", "development", "production", "prod",
        ],
        "severity": "medium",
        "description": "配置相关参数",
    },
    "sensitive_data": {
        "params": [
            "data", "content", "body", "payload", "message", "text",
            "info", "information", "detail", "details", "result", "response",
            "key", "value", "val", "json", "xml", "html", "raw",
        ],
        "severity": "medium",
        "description": "敏感数据参数",
    },
}

SENSITIVE_VALUE_PATTERNS = {
    "email": {
        "pattern": r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
        "description": "邮箱地址",
        "severity": "medium",
    },
    "phone": {
        "pattern": r"^(\+?86)?1[3-9]\d{9}$",
        "description": "手机号码",
        "severity": "medium",
    },
    "id_card": {
        "pattern": r"^\d{17}[\dXx]$",
        "description": "身份证号",
        "severity": "high",
    },
    "credit_card": {
        "pattern": r"^\d{13,19}$",
        "description": "银行卡号",
        "severity": "critical",
    },
    "ip_address": {
        "pattern": r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
        "description": "IP地址",
        "severity": "low",
    },
    "jwt_token": {
        "pattern": r"^eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$",
        "description": "JWT Token",
        "severity": "high",
    },
    "base64": {
        "pattern": r"^[A-Za-z0-9+/]+=*$",
        "description": "Base64编码数据",
        "severity": "low",
    },
    "uuid": {
        "pattern": r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$",
        "description": "UUID",
        "severity": "low",
    },
}

FORM_PATTERN = re.compile(
    r'<form[^>]*>(.*?)</form>',
    re.IGNORECASE | re.DOTALL
)

INPUT_PATTERN = re.compile(
    r'<input[^>]*(?:name|id)\s*=\s*["\']([^"\']+)["\'][^>]*>',
    re.IGNORECASE
)

TEXTAREA_PATTERN = re.compile(
    r'<textarea[^>]*name\s*=\s*["\']([^"\']+)["\'][^>]*>',
    re.IGNORECASE
)

SELECT_PATTERN = re.compile(
    r'<select[^>]*name\s*=\s*["\']([^"\']+)["\'][^>]*>',
    re.IGNORECASE
)

JS_VAR_PATTERN = re.compile(
    r'(?:var|let|const)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*["\']?([^"\';\n]+)["\']?',
    re.IGNORECASE
)

JS_OBJECT_PATTERN = re.compile(
    r'["\']?([a-zA-Z_][a-zA-Z0-9_]*)["\']?\s*:\s*["\']?([^"\';,\n}]+)["\']?',
    re.IGNORECASE
)

URL_PARAM_PATTERN = re.compile(
    r'["\']([^"\']*\?[^"\']*=)[^"\']*["\']',
    re.IGNORECASE
)


class SensitiveParamDiscovery:
    """
    敏感参数发现
    
    功能:
    - URL参数分析
    - 表单参数提取
    - JS变量分析
    - API参数发现
    - 敏感参数识别
    """
    
    def __init__(self, target: str, config: Optional[Dict[str, Any]] = None):
        self.target = self._normalize_url(target)
        self.config = config or {}
        
        self.timeout = self.config.get("timeout", 15)
        self.verify_ssl = self.config.get("verify_ssl", False)
        self.max_results = self.config.get("max_results", 100)
        
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive"
        })
        
        self._results: List[SensitiveParam] = []
        self._discovered_params: Set[str] = set()
        self._response_text = ""
    
    def _normalize_url(self, url: str) -> str:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        return url.rstrip("/")
    
    def scan(self) -> Dict[str, Any]:
        logger.info(f"[SensitiveParam] 发现敏感参数: {self.target}")
        
        self._analyze_url_params()
        self._fetch_and_analyze_page()
        self._analyze_js_files()
        
        return {
            "success": True,
            "target": self.target,
            "total_params": len(self._results),
            "sensitive_params": [self._param_to_dict(p) for p in self._results if p.is_sensitive],
            "all_params": [self._param_to_dict(p) for p in self._results[:self.max_results]],
            "statistics": self._generate_statistics(),
        }
    
    def _analyze_url_params(self) -> None:
        parsed = urlparse(self.target)
        query_params = parse_qs(parsed.query)
        
        for param_name, param_values in query_params.items():
            value = param_values[0] if param_values else ""
            self._analyze_param(param_name, value, "URL", "Query String")
    
    def _fetch_and_analyze_page(self) -> None:
        try:
            response = self.session.get(
                self.target + "/",
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            self._response_text = response.text
            self._analyze_forms()
            self._analyze_js_variables()
            
        except (Timeout, ConnectionError, RequestException) as e:
            logger.debug(f"[SensitiveParam] 页面获取失败: {e}")
    
    def _analyze_forms(self) -> None:
        for form_match in FORM_PATTERN.finditer(self._response_text):
            form_content = form_match.group(1)
            
            for pattern, location in [
                (INPUT_PATTERN, "Form Input"),
                (TEXTAREA_PATTERN, "Form Textarea"),
                (SELECT_PATTERN, "Form Select"),
            ]:
                for match in pattern.finditer(form_content):
                    param_name = match.group(1)
                    self._analyze_param(param_name, "", "Form", location)
    
    def _analyze_js_variables(self) -> None:
        for pattern in [JS_VAR_PATTERN, JS_OBJECT_PATTERN]:
            for match in pattern.finditer(self._response_text):
                param_name = match.group(1)
                value = match.group(2) if len(match.groups()) > 1 else ""
                
                if len(param_name) > 2 and not param_name.startswith("_"):
                    self._analyze_param(param_name, value, "JavaScript", "JS Variable")
    
    def _analyze_js_files(self) -> None:
        js_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)
        
        for match in js_pattern.finditer(self._response_text):
            js_url = match.group(1)
            
            if js_url.startswith("//"):
                js_url = "https:" + js_url
            elif js_url.startswith("/"):
                js_url = self.target + js_url
            elif not js_url.startswith("http"):
                continue
            
            self._fetch_and_analyze_js(js_url)
    
    def _fetch_and_analyze_js(self, js_url: str) -> None:
        try:
            response = self.session.get(
                js_url,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            for pattern in [JS_VAR_PATTERN, JS_OBJECT_PATTERN, URL_PARAM_PATTERN]:
                for match in pattern.finditer(response.text):
                    param_name = match.group(1)
                    value = match.group(2) if len(match.groups()) > 1 else ""
                    
                    if len(param_name) > 2:
                        self._analyze_param(param_name, value, "JavaScript", "JS File")
                        
        except (Timeout, ConnectionError, RequestException):
            pass
    
    def _analyze_param(self, name: str, value: str, location: str, source: str) -> None:
        param_key = f"{name}:{location}"
        if param_key in self._discovered_params:
            return
        self._discovered_params.add(param_key)
        
        name_lower = name.lower()
        
        category = ""
        severity = "low"
        description = ""
        is_sensitive = False
        
        for cat_name, cat_info in SENSITIVE_PARAM_CATEGORIES.items():
            if name_lower in [p.lower() for p in cat_info["params"]]:
                category = cat_name
                severity = cat_info["severity"]
                description = cat_info["description"]
                is_sensitive = True
                break
        
        if value:
            for value_type, value_info in SENSITIVE_VALUE_PATTERNS.items():
                if re.match(value_info["pattern"], value):
                    if not is_sensitive:
                        severity = max(severity, value_info["severity"], key=lambda s: ["low", "medium", "high", "critical"].index(s))
                    description = f"{description}; 包含{value_info['description']}" if description else value_info["description"]
                    break
        
        self._results.append(SensitiveParam(
            name=name,
            location=location,
            value=value[:100] if value else "",
            source=source,
            category=category,
            severity=severity,
            description=description,
            is_sensitive=is_sensitive,
            evidence=f"Found in {source}"
        ))
    
    def _generate_statistics(self) -> Dict[str, Any]:
        stats = {
            "total_params": len(self._results),
            "sensitive_count": sum(1 for p in self._results if p.is_sensitive),
            "by_severity": {},
            "by_category": {},
            "by_location": {},
        }
        
        for param in self._results:
            stats["by_severity"][param.severity] = stats["by_severity"].get(param.severity, 0) + 1
            if param.category:
                stats["by_category"][param.category] = stats["by_category"].get(param.category, 0) + 1
            stats["by_location"][param.location] = stats["by_location"].get(param.location, 0) + 1
        
        return stats
    
    def _param_to_dict(self, param: SensitiveParam) -> Dict[str, Any]:
        return {
            "name": param.name,
            "location": param.location,
            "value": param.value,
            "source": param.source,
            "category": param.category,
            "severity": param.severity,
            "description": param.description,
            "is_sensitive": param.is_sensitive,
        }


def discover_sensitive_params(target: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    敏感参数发现便捷函数
    
    Args:
        target: 目标URL
        config: 配置选项
        
    Returns:
        发现结果
    """
    discovery = SensitiveParamDiscovery(target, config)
    return discovery.scan()
