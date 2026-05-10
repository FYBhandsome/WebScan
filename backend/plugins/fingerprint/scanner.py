"""
指纹识别增强模块

功能:
- Web服务器识别
- 编程语言检测
- 框架/CMS识别
- 中间件检测
- 前端技术栈识别
- 安全设备检测
- CDN/WAF识别
"""

import re
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError

logger = logging.getLogger(__name__)


@dataclass
class FingerprintResult:
    name: str
    category: str
    version: str
    confidence: float
    evidence: List[str] = field(default_factory=list)
    cpe: str = ""
    description: str = ""


SERVER_FINGERPRINTS = {
    "nginx": {
        "patterns": [r"nginx[/\s]?([\d.]+)?"],
        "headers": ["Server"],
        "category": "Web Server",
    },
    "apache": {
        "patterns": [r"Apache[/\s]?([\d.]+)?", r"Apache-Coyote"],
        "headers": ["Server"],
        "category": "Web Server",
    },
    "iis": {
        "patterns": [r"Microsoft-IIS[/\s]?([\d.]+)?"],
        "headers": ["Server"],
        "category": "Web Server",
    },
    "tomcat": {
        "patterns": [r"Apache-Coyote[/\s]?([\d.]+)?"],
        "headers": ["Server"],
        "category": "Application Server",
    },
    "jetty": {
        "patterns": [r"Jetty[/\s]?([\d.]+)?"],
        "headers": ["Server"],
        "category": "Application Server",
    },
    "lighttpd": {
        "patterns": [r"lighttpd[/\s]?([\d.]+)?"],
        "headers": ["Server"],
        "category": "Web Server",
    },
    "openresty": {
        "patterns": [r"openresty[/\s]?([\d.]+)?"],
        "headers": ["Server"],
        "category": "Web Server",
    },
    "caddy": {
        "patterns": [r"Caddy"],
        "headers": ["Server"],
        "category": "Web Server",
    },
}

LANGUAGE_FINGERPRINTS = {
    "php": {
        "patterns": [
            r"\.php",
            r"X-Powered-By:\s*PHP[/\s]?([\d.]+)?",
            r"Set-Cookie:\s*PHPSESSID",
            r"<\?php",
        ],
        "headers": ["X-Powered-By"],
        "category": "Programming Language",
    },
    "asp.net": {
        "patterns": [
            r"\.aspx?",
            r"X-AspNet-Version:\s*([\d.]+)",
            r"X-Powered-By:\s*ASP\.NET",
            r"__VIEWSTATE",
            r"__EVENTVALIDATION",
        ],
        "headers": ["X-AspNet-Version", "X-Powered-By"],
        "category": "Programming Language",
    },
    "jsp": {
        "patterns": [
            r"\.jsp",
            r"JSESSIONID",
            r"Set-Cookie:\s*JSESSIONID",
        ],
        "headers": ["Set-Cookie"],
        "category": "Programming Language",
    },
    "python": {
        "patterns": [
            r"X-Powered-By:\s*(Python|WSGI|gunicorn|uWSGI)",
            r"__pycache__",
            r"csrfmiddlewaretoken",
            r"csrftoken",
        ],
        "headers": ["X-Powered-By"],
        "category": "Programming Language",
    },
    "ruby": {
        "patterns": [
            r"X-Powered-By:\s*(Phusion Passenger|Rack|Ruby)",
            r"_rails_session",
            r"csrf-token",
        ],
        "headers": ["X-Powered-By"],
        "category": "Programming Language",
    },
    "nodejs": {
        "patterns": [
            r"X-Powered-By:\s*Express",
            r"X-Powered-By:\s*Node\.js",
            r"connect\.sid",
        ],
        "headers": ["X-Powered-By"],
        "category": "Programming Language",
    },
    "java": {
        "patterns": [
            r"JSESSIONID",
            r"Set-Cookie:\s*JSESSIONID",
            r"\.do\b",
            r"\.action\b",
        ],
        "headers": ["Set-Cookie"],
        "category": "Programming Language",
    },
    "go": {
        "patterns": [
            r"X-Powered-By:\s*Go",
            r"Gin-",
        ],
        "headers": ["X-Powered-By"],
        "category": "Programming Language",
    },
}

FRAMEWORK_FINGERPRINTS = {
    "wordpress": {
        "patterns": [
            r"wp-content",
            r"wp-includes",
            r"wp-admin",
            r"WordPress(?:/([\d.]+))?",
            r"/xmlrpc\.php",
        ],
        "meta": ["generator"],
        "category": "CMS",
    },
    "drupal": {
        "patterns": [
            r"Drupal(?:\.settings)?",
            r"/sites/default/files",
            r"Drupal\.js",
            r"X-Drupal-Cache",
            r"X-Generator:\s*Drupal",
        ],
        "headers": ["X-Drupal-Cache", "X-Generator"],
        "meta": ["generator"],
        "category": "CMS",
    },
    "joomla": {
        "patterns": [
            r"Joomla!",
            r"/media/jui/",
            r"/administrator/",
            r"option=com_",
        ],
        "meta": ["generator"],
        "category": "CMS",
    },
    "django": {
        "patterns": [
            r"csrfmiddlewaretoken",
            r"__admin_media_prefix__",
            r"django",
        ],
        "category": "Framework",
    },
    "flask": {
        "patterns": [
            r"flask",
            r"werkzeug",
        ],
        "category": "Framework",
    },
    "spring": {
        "patterns": [
            r"Spring(?:-Framework)?",
            r"/spring/",
            r"JSESSIONID",
            r"\.do\b",
            r"\.action\b",
        ],
        "category": "Framework",
    },
    "struts": {
        "patterns": [
            r"Struts",
            r"\.action\b",
            r"struts\.token",
        ],
        "category": "Framework",
    },
    "laravel": {
        "patterns": [
            r"laravel_session",
            r"XSRF-TOKEN",
            r"Laravel",
        ],
        "headers": ["Set-Cookie"],
        "category": "Framework",
    },
    "symfony": {
        "patterns": [
            r"sf2_locale",
            r"symfony",
            r"sf-toolbar",
        ],
        "category": "Framework",
    },
    "rails": {
        "patterns": [
            r"csrf-token",
            r"_rails_session",
            r"Ruby on Rails",
        ],
        "category": "Framework",
    },
    "express": {
        "patterns": [
            r"X-Powered-By:\s*Express",
        ],
        "headers": ["X-Powered-By"],
        "category": "Framework",
    },
    "vue": {
        "patterns": [
            r"Vue\.js",
            r"vue-app",
            r"data-v-[a-f0-9]+",
            r"__VUE__",
        ],
        "category": "Frontend Framework",
    },
    "react": {
        "patterns": [
            r"react(?:-root|-app)?",
            r"data-reactroot",
            r"__REACT_DEVTOOLS_GLOBAL_HOOK__",
            r"_jsx",
        ],
        "category": "Frontend Framework",
    },
    "angular": {
        "patterns": [
            r"ng-[a-z]+",
            r"angular(?:\.module)?",
            r"ng-version",
            r"_ng[a-z]+_",
        ],
        "category": "Frontend Framework",
    },
    "jquery": {
        "patterns": [
            r"jquery(?:-[\d.]+)?\.js",
            r"\$\(document\)",
            r"jQuery",
        ],
        "category": "Frontend Library",
    },
    "bootstrap": {
        "patterns": [
            r"bootstrap(?:-[\d.]+)?\.css",
            r"bootstrap(?:-[\d.]+)?\.js",
            r"container-fluid",
            r"row-fluid",
        ],
        "category": "Frontend Framework",
    },
}

WAF_FINGERPRINTS = {
    "cloudflare": {
        "patterns": [
            r"cloudflare",
            r"cf-ray",
            r"__cfduid",
            r"cf-cache-status",
        ],
        "headers": ["CF-Ray", "Server"],
        "cookies": ["__cfduid"],
        "category": "WAF/CDN",
    },
    "akamai": {
        "patterns": [
            r"akamai",
            r"X-Akamai-Transformed",
        ],
        "headers": ["X-Akamai-Transformed", "Server"],
        "category": "WAF/CDN",
    },
    "aws_waf": {
        "patterns": [
            r"X-AMZ-CF-ID",
            r"aws",
            r"amazon",
        ],
        "headers": ["X-AMZ-CF-ID", "Server"],
        "category": "WAF/CDN",
    },
    "modsecurity": {
        "patterns": [
            r"ModSecurity",
            r"mod_security",
        ],
        "headers": ["Server"],
        "category": "WAF",
    },
    "incapsula": {
        "patterns": [
            r"incap_ses_",
            r"visid_incap_",
            r"X-CDN:\s*Incapsula",
        ],
        "headers": ["X-CDN"],
        "cookies": ["incap_ses_", "visid_incap_"],
        "category": "WAF/CDN",
    },
    "sucuri": {
        "patterns": [
            r"sucuri",
            r"X-Sucuri-ID",
            r"X-Sucuri-Cache",
        ],
        "headers": ["X-Sucuri-ID", "X-Sucuri-Cache", "Server"],
        "category": "WAF/CDN",
    },
    "barracuda": {
        "patterns": [
            r"barracuda",
            r"barra_counter_session",
        ],
        "headers": ["Server"],
        "cookies": ["barra_counter_session"],
        "category": "WAF",
    },
    "f5_bigip": {
        "patterns": [
            r"BigIP",
            r"F5",
            r"X-WA-Info",
        ],
        "headers": ["Server", "Set-Cookie"],
        "cookies": ["BIGipServer"],
        "category": "WAF/Load Balancer",
    },
    "fortinet": {
        "patterns": [
            r"FortiWeb",
            r"FortiGate",
            r"FORTIWAFSID",
        ],
        "headers": ["Server"],
        "cookies": ["FORTIWAFSID"],
        "category": "WAF",
    },
}

DATABASE_FINGERPRINTS = {
    "mysql": {
        "patterns": [
            r"MySQL",
            r"mysql_connect",
            r"mysqli_",
        ],
        "category": "Database",
    },
    "postgresql": {
        "patterns": [
            r"PostgreSQL",
            r"pg_connect",
            r"psql",
        ],
        "category": "Database",
    },
    "mongodb": {
        "patterns": [
            r"MongoDB",
            r"mongo_connect",
            r"mongoose",
        ],
        "category": "Database",
    },
    "redis": {
        "patterns": [
            r"Redis",
            r"redis-cli",
        ],
        "category": "Database",
    },
    "elasticsearch": {
        "patterns": [
            r"elasticsearch",
            r"Elasticsearch[/\s]?([\d.]+)?",
        ],
        "category": "Database",
    },
}

CMS_VERSION_PATTERNS = {
    "wordpress": [
        r'<meta name="generator" content="WordPress\s*([\d.]+)?"',
        r'wp-includes/js/wp-embed\.min\.js\?ver=([\d.]+)',
        r'/wp-content/themes/[^/]+/style\.css\?ver=([\d.]+)',
    ],
    "drupal": [
        r'<meta name="generator" content="Drupal\s*([\d.]+)',
        r'Drupal\.settings[^}]*"version"\s*:\s*"([\d.]+)"',
    ],
    "joomla": [
        r'<meta name="generator" content="Joomla!\s*([\d.]+)?"',
        r'/media/jui/js/jquery\.min\.js\?([\d.]+)',
    ],
}


class FingerprintScanner:
    """
    指纹识别增强扫描器
    
    功能:
    - Web服务器识别
    - 编程语言检测
    - 框架/CMS识别
    - WAF/CDN检测
    - 数据库指纹
    - 前端技术栈
    """
    
    def __init__(self, target: str, config: Optional[Dict[str, Any]] = None):
        self.target = self._normalize_url(target)
        self.config = config or {}
        
        self.timeout = self.config.get("timeout", 15)
        self.verify_ssl = self.config.get("verify_ssl", False)
        
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive"
        })
        
        self._response: Optional[requests.Response] = None
        self._results: List[FingerprintResult] = []
        self._detected: Set[str] = set()
    
    def _normalize_url(self, url: str) -> str:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        return url.rstrip("/")
    
    def scan(self) -> Dict[str, Any]:
        try:
            self._response = self.session.get(
                self.target + "/",
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True
            )
        except (Timeout, ConnectionError, RequestException) as e:
            logger.error(f"[FingerprintScanner] 请求失败: {e}")
            return {"success": False, "error": str(e), "fingerprints": []}
        
        self._detect_servers()
        self._detect_languages()
        self._detect_frameworks()
        self._detect_waf()
        self._detect_databases()
        self._detect_cms_version()
        
        return {
            "success": True,
            "target": self.target,
            "fingerprints": [self._result_to_dict(r) for r in self._results],
            "summary": self._generate_summary(),
            "headers": dict(self._response.headers),
            "cookies": dict(self._response.cookies),
        }
    
    def _detect_servers(self) -> None:
        self._detect_from_rules(SERVER_FINGERPRINTS, "Server")
    
    def _detect_languages(self) -> None:
        self._detect_from_rules(LANGUAGE_FINGERPRINTS, "Language")
    
    def _detect_frameworks(self) -> None:
        self._detect_from_rules(FRAMEWORK_FINGERPRINTS, "Framework")
    
    def _detect_waf(self) -> None:
        self._detect_from_rules(WAF_FINGERPRINTS, "WAF/CDN")
    
    def _detect_databases(self) -> None:
        self._detect_from_rules(DATABASE_FINGERPRINTS, "Database")
    
    def _detect_from_rules(self, rules: Dict, default_category: str) -> None:
        if not self._response:
            return
        
        headers = dict(self._response.headers)
        cookies = dict(self._response.cookies)
        body = self._response.text
        
        for name, rule in rules.items():
            if name in self._detected:
                continue
            
            evidence_list = []
            version = ""
            
            patterns = rule.get("patterns", [])
            for pattern in patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    evidence_list.append(f"Pattern: {pattern}")
                    if match.groups():
                        version = match.group(1) or ""
            
            header_names = rule.get("headers", [])
            for header in header_names:
                if header in headers:
                    value = headers[header]
                    evidence_list.append(f"Header: {header}={value}")
                    for pattern in patterns:
                        match = re.search(pattern, value, re.IGNORECASE)
                        if match and match.groups():
                            version = match.group(1) or ""
            
            cookie_names = rule.get("cookies", [])
            for cookie_pattern in cookie_names:
                for cookie_name in cookies:
                    if cookie_pattern.lower() in cookie_name.lower():
                        evidence_list.append(f"Cookie: {cookie_name}")
            
            if evidence_list:
                category = rule.get("category", default_category)
                self._results.append(FingerprintResult(
                    name=name,
                    category=category,
                    version=version,
                    confidence=0.85 if version else 0.7,
                    evidence=evidence_list,
                    description=f"Detected {name}"
                ))
                self._detected.add(name)
    
    def _detect_cms_version(self) -> None:
        if not self._response:
            return
        
        body = self._response.text
        
        for cms, patterns in CMS_VERSION_PATTERNS.items():
            if cms not in self._detected:
                continue
            
            for pattern in patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match and match.groups():
                    version = match.group(1)
                    for result in self._results:
                        if result.name == cms:
                            result.version = version
                            result.confidence = 0.95
                            result.evidence.append(f"Version pattern: {pattern}")
                    break
    
    def _generate_summary(self) -> Dict[str, List[str]]:
        summary = {
            "web_servers": [],
            "languages": [],
            "frameworks": [],
            "cms": [],
            "waf_cdn": [],
            "databases": [],
            "frontend": [],
        }
        
        for result in self._results:
            if result.category == "Web Server":
                summary["web_servers"].append(result.name)
            elif result.category == "Programming Language":
                summary["languages"].append(result.name)
            elif result.category in ["Framework", "CMS"]:
                summary["frameworks"].append(result.name)
                if result.category == "CMS":
                    summary["cms"].append(result.name)
            elif result.category in ["WAF", "WAF/CDN", "WAF/Load Balancer"]:
                summary["waf_cdn"].append(result.name)
            elif result.category == "Database":
                summary["databases"].append(result.name)
            elif result.category in ["Frontend Framework", "Frontend Library"]:
                summary["frontend"].append(result.name)
        
        return {k: v for k, v in summary.items() if v}
    
    def _result_to_dict(self, result: FingerprintResult) -> Dict[str, Any]:
        return {
            "name": result.name,
            "category": result.category,
            "version": result.version,
            "confidence": round(result.confidence, 2),
            "evidence": result.evidence[:5],
            "description": result.description,
        }


def scan_fingerprint(target: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    指纹识别便捷函数
    
    Args:
        target: 目标URL
        config: 配置选项
        
    Returns:
        识别结果
    """
    scanner = FingerprintScanner(target, config)
    return scanner.scan()
