# -*- coding:utf-8 -*-

"""
信息泄露扫描模块（增强版）

功能:
1. 扫描目标URL的敏感文件和目录
2. 检测潜在的信息泄露风险
3. 智能判断有效响应（排除误报）
4. 内容验证（检查备份文件是否有效）
5. 支持多线程并发扫描

特性:
- 内置扩展字典，无需外部文件
- 智能404页面检测
- 内容类型验证
- 文件大小验证
- 线程安全的结果存储
- 详细的泄露信息分类

依赖:
- requests: 用于HTTP请求
- concurrent.futures: 用于多线程

使用示例:
    >>> from backend.plugins.infoleak.infoleak import scan_infoleak
    >>> result = scan_infoleak('https://example.com/')
    >>> print(result)
"""

import re
import logging
import hashlib
from typing import List, Dict, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError

logger = logging.getLogger(__name__)


@dataclass
class LeakResult:
    path: str
    url: str
    category: str
    status_code: int
    content_length: int
    content_type: str
    title: str
    is_valid: bool
    confidence: float
    evidence: str
    severity: str


INFOLEAK_PATHS = {
    "backup_files": {
        "paths": [
            "/backup", "/backup.zip", "/backup.tar.gz", "/backup.tar", "/backup.rar",
            "/backup.sql", "/backup.7z", "/backup/", "/backups/", "/bak/",
            "/db.sql", "/database.sql", "/dump.sql", "/db_backup.sql",
            "/www.zip", "/web.zip", "/site.zip", "/www.tar.gz", "/www.rar",
            "/1.zip", "/2.zip", "/www.7z", "/web.tar.gz", "/site.tar.gz",
            "/old.zip", "/temp.zip", "/tmp.zip", "/test.zip",
            "/backup_db.sql", "/db_backup.zip", "/database_backup.sql",
            "/backup_2020.zip", "/backup_2021.zip", "/backup_2022.zip",
            "/backup_2023.zip", "/backup_2024.zip", "/backup_2025.zip",
            "/data.zip", "/data.tar.gz", "/data.sql", "/sql.zip",
            "/archive.zip", "/archive.tar.gz", "/archives/",
        ],
        "severity": "critical",
        "description": "备份文件泄露",
    },
    "config_files": {
        "paths": [
            "/config.php", "/configuration.php", "/config.inc.php", "/settings.php",
            "/database.yml", "/database.yaml", "/config.yml", "/config.yaml",
            "/config.json", "/settings.json", "/app.config", "/web.config",
            "/.env", "/.env.local", "/.env.production", "/.env.development",
            "/.env.backup", "/.env.old", "/.env.save", "/.env.bak",
            "/config.ini", "/config.xml", "/configuration.xml",
            "/application.properties", "/application.yml", "/application.yaml",
            "/wp-config.php", "/wp-config.php.bak", "/wp-config.php~",
            "/config.php.bak", "/config.php~", "/config.php.old",
            "/settings.php.bak", "/settings.php~", "/database.yml.bak",
            "/.htaccess", "/.htpasswd", "/.htaccess.bak",
            "/server.xml", "/context.xml", "/web.xml",
            "/php.ini", "/my.cnf", "/my.ini",
        ],
        "severity": "critical",
        "description": "配置文件泄露",
    },
    "git_svn": {
        "paths": [
            "/.git", "/.git/", "/.git/config", "/.git/HEAD", "/.git/index",
            "/.git/objects", "/.git/refs", "/.git/logs", "/.git/hooks",
            "/.gitignore", "/.gitattributes", "/.gitmodules",
            "/.svn", "/.svn/", "/.svn/entries", "/.svn/wc.db", "/.svn/pristine",
            "/.hg", "/.hg/", "/.hg/hgrc", "/.hg/store",
            "/.bzr", "/.bzr/", "/.bzr/branch", "/.bzr/repository",
            "/.cvs", "/.cvs/", "/CVS/", "/CVS/Root",
            "/.DS_Store", "/.svn/text-base", "/.svn/prop-base",
        ],
        "severity": "high",
        "description": "版本控制信息泄露",
    },
    "sensitive_files": {
        "paths": [
            "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
            "/server-status", "/server-status/", "/server-info", "/server-info/",
            "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
            "/phpmyadmin/", "/pma/", "/mysql/", "/adminer.php",
            "/.well-known/", "/.well-known/security.txt",
            "/security.txt", "/humans.txt", "/README.md", "/readme.md",
            "/CHANGELOG.md", "/changelog.md", "/LICENSE", "/license.txt",
            "/composer.json", "/package.json", "/Gemfile", "/requirements.txt",
            "/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
            "/.dockerignore", "/.editorconfig", "/.eslintrc", "/.prettierrc",
            "/Makefile", "/Vagrantfile", "/.travis.yml", "/.gitlab-ci.yml",
            "/Jenkinsfile", "/.github/", "/.gitlab/",
        ],
        "severity": "medium",
        "description": "敏感文件泄露",
    },
    "admin_panels": {
        "paths": [
            "/admin", "/admin/", "/administrator", "/administrator/",
            "/admin.php", "/admin.html", "/admin/login.php",
            "/wp-admin", "/wp-admin/", "/wp-login.php",
            "/manage", "/manage/", "/manager", "/manager/",
            "/backend", "/backend/", "/console", "/console/",
            "/control", "/control/", "/cpanel", "/cpanel/",
            "/admincp", "/admincp/", "/moderator", "/moderator/",
            "/adm", "/adm/", "/admin_area", "/admin_area/",
            "/admin-login", "/admin_login", "/adminpanel",
            "/user/login", "/user/login.php", "/account/login",
            "/system/login", "/sysadmin", "/webadmin",
        ],
        "severity": "medium",
        "description": "管理后台暴露",
    },
    "log_files": {
        "paths": [
            "/error.log", "/error_log", "/errors.log",
            "/access.log", "/access_log", "/accesslog",
            "/debug.log", "/debug_log", "/debuglog",
            "/system.log", "/systemlog", "/syslog",
            "/application.log", "/app.log", "/app_log",
            "/logs/", "/log/", "/logging/",
            "/var/log/", "/var/log/apache2/", "/var/log/nginx/",
            "/apache/logs/", "/nginx/logs/",
            "/error_log.txt", "/error.txt", "/log.txt",
            "/php_errors.log", "/slow.log", "/mysql.log",
        ],
        "severity": "medium",
        "description": "日志文件泄露",
    },
    "api_docs": {
        "paths": [
            "/api-docs", "/api-docs/", "/swagger", "/swagger/",
            "/swagger-ui", "/swagger-ui/", "/swagger-ui.html",
            "/swagger-resources", "/swagger-resources/",
            "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
            "/openapi.json", "/swagger.json", "/api.json",
            "/docs", "/docs/", "/redoc", "/redoc/",
            "/api/reference", "/api/explorer", "/api/console",
            "/graphiql", "/graphql", "/playground",
            "/api/test", "/api/debug", "/api/sandbox",
        ],
        "severity": "medium",
        "description": "API文档暴露",
    },
    "upload_dirs": {
        "paths": [
            "/upload", "/upload/", "/uploads", "/uploads/",
            "/files", "/files/", "/attachments", "/attachments/",
            "/media", "/media/", "/static", "/static/",
            "/assets", "/assets/", "/public", "/public/",
            "/tmp", "/tmp/", "/temp", "/temp/",
            "/cache", "/cache/", "/storage", "/storage/",
            "/userfiles", "/userfiles/", "/user_files",
            "/download", "/download/", "/downloads", "/downloads/",
        ],
        "severity": "low",
        "description": "上传目录暴露",
    },
    "sensitive_pages": {
        "paths": [
            "/install", "/install/", "/install.php", "/install/index.php",
            "/setup", "/setup/", "/setup.php",
            "/upgrade", "/upgrade/", "/upgrade.php",
            "/update", "/update/", "/update.php",
            "/reset", "/reset/", "/reset.php",
            "/forgot", "/forgot/", "/forgot.php",
            "/password", "/password/", "/change_password.php",
            "/register", "/register/", "/signup", "/signup/",
            "/profile", "/profile/", "/account", "/account/",
            "/user", "/user/", "/member", "/member/",
            "/api", "/api/", "/rest", "/rest/",
            "/service", "/service/", "/services", "/services/",
        ],
        "severity": "low",
        "description": "敏感页面暴露",
    },
}

SENSITIVE_CONTENT_PATTERNS = {
    "database_credentials": {
        "patterns": [
            r"(?i)(mysql|postgres|mongodb|redis|oracle|sqlite)://[^\s]+",
            r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]+['\"]",
            r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"][^'\"]+['\"]",
            r"(?i)(secret[_-]?key|secretkey)\s*[=:]\s*['\"][^'\"]+['\"]",
            r"(?i)(access[_-]?token|accesstoken)\s*[=:]\s*['\"][^'\"]+['\"]",
        ],
        "severity": "critical",
    },
    "private_keys": {
        "patterns": [
            r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
            r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----",
            r"-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----",
        ],
        "severity": "critical",
    },
    "aws_credentials": {
        "patterns": [
            r"(?i)AKIA[0-9A-Z]{16}",
            r"(?i)aws_access_key_id\s*=\s*[A-Z0-9]{20}",
            r"(?i)aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}",
        ],
        "severity": "critical",
    },
    "php_info": {
        "patterns": [
            r"PHP\s+Version",
            r"phpinfo\(\)",
            r"Configuration\s+File\s+\(php\.ini\)\s+Path",
        ],
        "severity": "high",
    },
    "git_content": {
        "patterns": [
            r"\[core\]",
            r"\[remote\s+\"origin\"\]",
            r"repositoryformatversion",
        ],
        "severity": "high",
    },
}

VALID_STATUS_CODES = {200, 201, 202, 203, 204, 206, 301, 302, 303, 307, 308, 401, 403}


class InfoLeakScanner:
    """
    信息泄露扫描器（增强版）
    
    功能:
    - 多类别敏感路径检测
    - 智能响应分析
    - 内容验证
    - 404页面检测
    """
    
    def __init__(self, target: str, config: Optional[Dict[str, Any]] = None):
        self.target = self._normalize_url(target)
        self.config = config or {}
        
        self.timeout = self.config.get("timeout", 10)
        self.max_workers = self.config.get("max_workers", 20)
        self.verify_ssl = self.config.get("verify_ssl", False)
        self.max_results = self.config.get("max_results", 200)
        
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive"
        })
        
        self._results: List[LeakResult] = []
        self._scanned_paths: Set[str] = set()
        self._baseline_404_content = ""
        self._baseline_404_length = 0
        self._baseline_404_hash = ""
        self._lock = Lock()
    
    def _normalize_url(self, url: str) -> str:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url.rstrip("/")
    
    def _get_baseline_404(self) -> None:
        random_path = f"/{hashlib.md5(self.target.encode()).hexdigest()[:16]}.html"
        try:
            response = self.session.get(
                self.target + random_path,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False
            )
            if response.status_code == 404:
                self._baseline_404_content = response.text[:500]
                self._baseline_404_length = len(response.content)
                self._baseline_404_hash = hashlib.md5(response.content).hexdigest()[:8]
        except Exception:
            pass
    
    def _is_custom_404(self, response: requests.Response) -> bool:
        if response.status_code == 404:
            return True
        
        content_hash = hashlib.md5(response.content).hexdigest()[:8]
        if content_hash == self._baseline_404_hash:
            return True
        
        content_length = len(response.content)
        if self._baseline_404_length > 0:
            if abs(content_length - self._baseline_404_length) < 100:
                if self._baseline_404_content and self._baseline_404_content[:100] in response.text:
                    return True
        
        content_type = response.headers.get("Content-Type", "").lower()
        if "text/html" in content_type:
            text = response.text.lower()
            if any(x in text for x in ["404", "not found", "页面不存在", "找不到页面"]):
                title_match = re.search(r"<title>([^<]+)</title>", text, re.IGNORECASE)
                if title_match and any(x in title_match.group(1).lower() for x in ["404", "not found", "错误", "error"]):
                    return True
        
        return False
    
    def _extract_title(self, text: str) -> str:
        match = re.search(r"<title>([^<]+)</title>", text, re.IGNORECASE)
        return match.group(1).strip()[:100] if match else ""
    
    def _check_sensitive_content(self, content: str) -> Tuple[bool, str, str]:
        for category, config in SENSITIVE_CONTENT_PATTERNS.items():
            for pattern in config["patterns"]:
                if re.search(pattern, content):
                    return True, category, config["severity"]
        return False, "", ""
    
    def _scan_path(self, path: str, category: str, severity: str) -> Optional[LeakResult]:
        if path in self._scanned_paths:
            return None
        self._scanned_paths.add(path)
        
        url = self.target + path
        
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False
            )
            
            if response.status_code not in VALID_STATUS_CODES:
                return None
            
            if self._is_custom_404(response):
                return None
            
            content_length = len(response.content)
            content_type = response.headers.get("Content-Type", "")
            
            if content_length < 10:
                return None
            
            title = self._extract_title(response.text) if "text/html" in content_type else ""
            
            has_sensitive, sensitive_type, sensitive_severity = self._check_sensitive_content(response.text[:5000])
            
            if has_sensitive:
                severity = sensitive_severity
                evidence = f"检测到敏感内容: {sensitive_type}"
            else:
                evidence = f"HTTP {response.status_code}, 大小: {content_length} bytes"
            
            confidence = 0.5
            if response.status_code == 200:
                confidence = 0.8
            if has_sensitive:
                confidence = 0.95
            if any(x in path for x in [".git", ".svn", ".env", "backup", "config"]):
                confidence = min(confidence + 0.1, 1.0)
            
            return LeakResult(
                path=path,
                url=url,
                category=category,
                status_code=response.status_code,
                content_length=content_length,
                content_type=content_type,
                title=title,
                is_valid=True,
                confidence=confidence,
                evidence=evidence,
                severity=severity,
            )
        
        except Timeout:
            logger.debug(f"[InfoLeak] 超时: {url}")
        except ConnectionError:
            logger.debug(f"[InfoLeak] 连接失败: {url}")
        except RequestException as e:
            logger.debug(f"[InfoLeak] 请求异常: {url} - {e}")
        except Exception as e:
            logger.debug(f"[InfoLeak] 未知异常: {url} - {e}")
        
        return None
    
    def scan(self) -> Dict[str, Any]:
        logger.info(f"[InfoLeak] 开始扫描: {self.target}")
        
        self._get_baseline_404()
        
        all_paths = []
        for category, config in INFOLEAK_PATHS.items():
            for path in config["paths"]:
                all_paths.append((path, category, config["severity"]))
        
        logger.info(f"[InfoLeak] 待扫描路径数: {len(all_paths)}")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._scan_path, path, category, severity): path
                for path, category, severity in all_paths
            }
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        with self._lock:
                            if len(self._results) < self.max_results:
                                self._results.append(result)
                except Exception as e:
                    logger.debug(f"[InfoLeak] 任务异常: {e}")
        
        self._results.sort(key=lambda x: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.severity, 4),
            -x.confidence
        ))
        
        return {
            "success": True,
            "target": self.target,
            "total_found": len(self._results),
            "results": [self._result_to_dict(r) for r in self._results[:self.max_results]],
            "statistics": self._generate_statistics(),
        }
    
    def _result_to_dict(self, result: LeakResult) -> Dict[str, Any]:
        return {
            "path": result.path,
            "url": result.url,
            "category": result.category,
            "status_code": result.status_code,
            "content_length": result.content_length,
            "content_type": result.content_type,
            "title": result.title,
            "is_valid": result.is_valid,
            "confidence": result.confidence,
            "evidence": result.evidence,
            "severity": result.severity,
        }
    
    def _generate_statistics(self) -> Dict[str, Any]:
        stats = {
            "total": len(self._results),
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "by_category": {},
        }
        
        for result in self._results:
            stats["by_severity"][result.severity] = stats["by_severity"].get(result.severity, 0) + 1
            stats["by_category"][result.category] = stats["by_category"].get(result.category, 0) + 1
        
        return stats


def scan_infoleak(target: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    扫描目标URL的信息泄露风险
    
    :param target: 目标URL
    :param config: 配置选项
    :return: 扫描结果
    """
    scanner = InfoLeakScanner(target, config)
    return scanner.scan()


def get_infoleak(target_url: Optional[str]) -> List[Tuple[str, str]]:
    """
    兼容函数: 扫描目标URL的信息泄露风险链接
    
    :param target_url: 目标URL
    :return: 风险链接列表 [(风险类型key, 风险URL), ...]
    """
    if not target_url or not isinstance(target_url, str):
        return []
    
    result = scan_infoleak(target_url)
    
    return [
        (r["category"], r["url"])
        for r in result.get("results", [])
    ]


if __name__ == '__main__':
    test_url = "https://example.com"
    result = scan_infoleak(test_url)
    
    print(f"\n目标: {result['target']}")
    print(f"发现数量: {result['total_found']}")
    print(f"\n统计信息:")
    for severity, count in result['statistics']['by_severity'].items():
        if count > 0:
            print(f"  {severity}: {count}")
    
    print(f"\n详细结果:")
    for r in result['results'][:10]:
        print(f"  [{r['severity']}] {r['category']}: {r['url']}")
        print(f"    状态码: {r['status_code']}, 大小: {r['content_length']}, 置信度: {r['confidence']:.2f}")
