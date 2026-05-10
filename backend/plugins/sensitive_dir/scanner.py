"""
敏感目录扫描增强模块

功能:
- 多字典源支持
- 智能路径发现
- 备份文件检测
- 敏感文件检测
- Git/SVN信息泄露
- 配置文件暴露
"""

import re
import time
import logging
import hashlib
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError

logger = logging.getLogger(__name__)


@dataclass
class DirResult:
    path: str
    url: str
    status_code: int
    content_length: int
    content_type: str
    redirect_url: str
    title: str
    is_sensitive: bool
    sensitive_type: str
    confidence: float


SENSITIVE_PATHS = {
    "admin_panels": [
        "/admin", "/administrator", "/admin.php", "/admin.html",
        "/wp-admin", "/wp-login.php", "/phpmyadmin", "/pma",
        "/adminer.php", "/manage", "/manager", "/backend",
        "/console", "/control", "/cpanel", "/webadmin",
        "/admincp", "/moderator", "/adm", "/admin_area",
        "/admin-login", "/admin_login", "/adminpanel",
    ],
    "backup_files": [
        "/backup", "/backups", "/backup.zip", "/backup.tar.gz",
        "/backup.sql", "/backup.tar", "/backup.rar", "/backup.7z",
        "/db.sql", "/database.sql", "/dump.sql", "/db_backup.sql",
        "/backup/", "/old/", "/bak/", "/temp/", "/tmp/",
        "/www.zip", "/web.zip", "/site.zip", "/1.zip", "/www.tar.gz",
        "/www.rar", "/web.rar", "/site.rar", "/www.7z",
    ],
    "config_files": [
        "/config.php", "/configuration.php", "/config.inc.php",
        "/settings.php", "/wp-config.php", "/database.yml",
        "/database.yaml", "/config.yml", "/config.yaml",
        "/config.json", "/settings.json", "/app.config",
        "/web.config", "/.env", "/.env.local", "/.env.production",
        "/.env.development", "/config.ini", "/config.xml",
        "/application.properties", "/application.yml",
    ],
    "git_svn": [
        "/.git", "/.git/config", "/.git/HEAD", "/.git/index",
        "/.git/objects", "/.git/refs", "/.gitignore",
        "/.svn", "/.svn/entries", "/.svn/wc.db",
        "/.hg", "/.hg/hgrc", "/.bzr", "/.bzr/branch",
        "/.gitattributes", "/.gitmodules",
    ],
    "sensitive_files": [
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
        "/.htaccess", "/.htpasswd", "/server-status",
        "/server-info", "/phpinfo.php", "/info.php",
        "/test.php", "/debug.php", "/shell.php",
        "/cmd.php", "/c99.php", "/r57.php", "/webshell.php",
        "/.DS_Store", "/Thumbs.db", "/desktop.ini",
        "/README.md", "/readme.txt", "/CHANGELOG.md",
        "/LICENSE", "/INSTALL", "/install.php", "/install/",
        "/error.log", "/access.log", "/debug.log",
    ],
    "api_docs": [
        "/api", "/api-docs", "/api-docs/", "/swagger",
        "/swagger-ui", "/swagger-ui.html", "/swagger-resources",
        "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
        "/api/swagger", "/api/v1", "/api/v2", "/graphql",
        "/graphiql", "/docs", "/redoc", "/openapi.json",
        "/swagger.json", "/api.json", "/rest-api",
    ],
    "upload_dirs": [
        "/upload", "/uploads", "/uploadfiles", "/files",
        "/attachments", "/media", "/images", "/img",
        "/static", "/assets", "/public", "/userfiles",
        "/file", "/download", "/downloads", "/res",
    ],
    "sensitive_dirs": [
        "/cgi-bin", "/scripts", "/bin", "/sbin",
        "/logs", "/log", "/data", "/database",
        "/db", "/cache", "/session", "/sessions",
        "/private", "/secret", "/conf", "/config",
        "/includes", "/include", "/inc", "/lib",
        "/vendor", "/node_modules", "/bower_components",
    ],
}

COMMON_EXTENSIONS = [
    "", ".php", ".asp", ".aspx", ".jsp", ".do", ".action",
    ".html", ".htm", ".js", ".json", ".xml", ".txt",
    ".bak", ".backup", ".old", ".copy", ".orig",
    ".zip", ".tar", ".tar.gz", ".rar", ".7z", ".gz",
    ".sql", ".db", ".sqlite", ".mdb",
    ".log", ".conf", ".cfg", ".ini", ".yaml", ".yml",
    ".swp", ".swo", ".save",
]

STATUS_CODE_MEANING = {
    200: "OK",
    201: "Created",
    204: "No Content",
    301: "Moved Permanently",
    302: "Found",
    303: "See Other",
    304: "Not Modified",
    307: "Temporary Redirect",
    308: "Permanent Redirect",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
}

TITLE_PATTERN = re.compile(r"<title[^>]*>([^<]+)</title>", re.IGNORECASE | re.DOTALL)


class SensitiveDirScanner:
    """
    敏感目录扫描器
    
    功能:
    - 多类别敏感路径检测
    - 智能响应分析
    - 备份文件发现
    - 配置文件暴露检测
    - Git/SVN信息泄露检测
    """
    
    def __init__(self, target: str, config: Optional[Dict[str, Any]] = None):
        self.target = self._normalize_url(target)
        self.config = config or {}
        
        self.timeout = self.config.get("timeout", 10)
        self.max_workers = self.config.get("max_workers", 10)
        self.delay = self.config.get("delay", 0.1)
        self.verify_ssl = self.config.get("verify_ssl", False)
        self.max_results = self.config.get("max_results", 200)
        
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive"
        })
        
        self._results: List[DirResult] = []
        self._scanned_paths: Set[str] = set()
        self._baseline_length = 0
        self._baseline_content = ""
    
    def _normalize_url(self, url: str) -> str:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        return url.rstrip("/")
    
    def _get_baseline(self) -> None:
        try:
            response = self.session.get(
                self.target + "/",
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False
            )
            self._baseline_length = len(response.content)
            self._baseline_content = hashlib.md5(response.content).hexdigest()[:8]
        except (Timeout, ConnectionError, RequestException):
            pass
    
    def scan(self) -> List[Dict[str, Any]]:
        self._get_baseline()
        
        all_paths = []
        for category, paths in SENSITIVE_PATHS.items():
            for path in paths:
                if path not in self._scanned_paths:
                    all_paths.append((path, category))
                    self._scanned_paths.add(path)
        
        logger.info(f"[SensitiveDirScanner] 开始扫描 {len(all_paths)} 个敏感路径")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._scan_path, path, category): path
                for path, category in all_paths
            }
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self._results.append(result)
                except Exception as e:
                    logger.debug(f"扫描异常: {e}")
        
        self._results.sort(key=lambda x: (not x.is_sensitive, x.status_code))
        
        return [self._result_to_dict(r) for r in self._results[:self.max_results]]
    
    def _scan_path(self, path: str, category: str) -> Optional[DirResult]:
        url = self.target + path
        
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False
            )
            
            if response.status_code == 404:
                return None
            
            content_length = len(response.content)
            if content_length == 0:
                return None
            
            content_hash = hashlib.md5(response.content).hexdigest()[:8]
            if content_hash == self._baseline_content and response.status_code in [200, 301, 302]:
                return None
            
            content_type = response.headers.get("Content-Type", "").split(";")[0].strip()
            redirect_url = response.headers.get("Location", "")
            
            title = ""
            if "text/html" in content_type:
                title_match = TITLE_PATTERN.search(response.text)
                if title_match:
                    title = title_match.group(1).strip()[:100]
            
            is_sensitive = self._is_sensitive(response, path, category)
            sensitive_type = category if is_sensitive else ""
            confidence = self._calculate_confidence(response, path, category)
            
            return DirResult(
                path=path,
                url=url,
                status_code=response.status_code,
                content_length=content_length,
                content_type=content_type,
                redirect_url=redirect_url,
                title=title,
                is_sensitive=is_sensitive,
                sensitive_type=sensitive_type,
                confidence=confidence
            )
            
        except (Timeout, ConnectionError, RequestException):
            return None
    
    def _is_sensitive(self, response: requests.Response, path: str, category: str) -> bool:
        sensitive_categories = [
            "backup_files", "config_files", "git_svn",
            "sensitive_files", "api_docs"
        ]
        
        if category in sensitive_categories and response.status_code in [200, 301, 302]:
            return True
        
        if category == "admin_panels":
            if response.status_code in [200, 301, 302, 401, 403]:
                return True
        
        body = response.text.lower()
        
        sensitive_keywords = [
            "password", "secret", "api_key", "apikey",
            "private_key", "access_token", "auth",
            "database", "mysql", "postgres", "mongodb",
            "backup", "dump", "sql", "credentials"
        ]
        
        for keyword in sensitive_keywords:
            if keyword in body:
                return True
        
        return False
    
    def _calculate_confidence(self, response: requests.Response, path: str, category: str) -> float:
        confidence = 0.5
        
        if response.status_code == 200:
            confidence += 0.2
        elif response.status_code in [301, 302]:
            confidence += 0.1
        elif response.status_code in [401, 403]:
            confidence += 0.15
        
        content_type = response.headers.get("Content-Type", "")
        if "application/json" in content_type:
            confidence += 0.1
        elif "application/xml" in content_type:
            confidence += 0.1
        
        if category in ["backup_files", "config_files", "git_svn"]:
            confidence += 0.2
        
        return min(confidence, 1.0)
    
    def _result_to_dict(self, result: DirResult) -> Dict[str, Any]:
        return {
            "path": result.path,
            "url": result.url,
            "status_code": result.status_code,
            "status_meaning": STATUS_CODE_MEANING.get(result.status_code, "Unknown"),
            "content_length": result.content_length,
            "content_type": result.content_type,
            "redirect_url": result.redirect_url,
            "title": result.title,
            "is_sensitive": result.is_sensitive,
            "sensitive_type": result.sensitive_type,
            "confidence": round(result.confidence, 2)
        }


def scan_sensitive_dirs(target: str, config: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    敏感目录扫描便捷函数
    
    Args:
        target: 目标URL
        config: 配置选项
        
    Returns:
        扫描结果列表
    """
    scanner = SensitiveDirScanner(target, config)
    return scanner.scan()
