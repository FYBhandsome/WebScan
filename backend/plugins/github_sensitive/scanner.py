"""
GitHub敏感信息检测模块

功能:
- GitHub代码搜索
- 敏感信息模式匹配
- API密钥检测
- 数据库凭证检测
- 私钥证书检测
- 配置文件泄露检测
"""

import re
import json
import logging
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError

logger = logging.getLogger(__name__)


@dataclass
class SensitiveFinding:
    file_url: str
    file_path: str
    repository: str
    line_number: int
    matched_content: str
    finding_type: str
    severity: str
    description: str
    pattern_name: str
    confidence: float


SENSITIVE_PATTERNS = {
    "aws_access_key": {
        "pattern": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "description": "AWS Access Key ID",
        "severity": "critical",
    },
    "aws_secret_key": {
        "pattern": r"(?:aws)?_?secret_?(?:access)?_?key['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}",
        "description": "AWS Secret Access Key",
        "severity": "critical",
    },
    "github_token": {
        "pattern": r"ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|ghr_[A-Za-z0-9]{36}",
        "description": "GitHub Personal Access Token",
        "severity": "critical",
    },
    "github_oauth": {
        "pattern": r"github_oauth_token['\"]?\s*[:=]\s*['\"]?[a-f0-9]{40}",
        "description": "GitHub OAuth Token",
        "severity": "high",
    },
    "google_api_key": {
        "pattern": r"AIza[A-Za-z0-9_-]{35}",
        "description": "Google API Key",
        "severity": "high",
    },
    "google_oauth": {
        "pattern": r"[0-9]+-[A-Za-z0-9_]{32}\.apps\.googleusercontent\.com",
        "description": "Google OAuth Client ID",
        "severity": "medium",
    },
    "slack_token": {
        "pattern": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}",
        "description": "Slack Token",
        "severity": "high",
    },
    "slack_webhook": {
        "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,11}/B[A-Z0-9]{8,11}/[A-Za-z0-9]{24}",
        "description": "Slack Webhook URL",
        "severity": "high",
    },
    "stripe_api_key": {
        "pattern": r"sk_live_[0-9a-zA-Z]{24}|rk_live_[0-9a-zA-Z]{24}",
        "description": "Stripe API Key",
        "severity": "critical",
    },
    "stripe_publishable": {
        "pattern": r"pk_live_[0-9a-zA-Z]{24}",
        "description": "Stripe Publishable Key",
        "severity": "medium",
    },
    "twilio_api_key": {
        "pattern": r"SK[a-f0-9]{32}",
        "description": "Twilio API Key",
        "severity": "high",
    },
    "mailchimp_api_key": {
        "pattern": r"[a-f0-9]{32}-us[0-9]{1,2}",
        "description": "Mailchimp API Key",
        "severity": "high",
    },
    "sendgrid_api_key": {
        "pattern": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        "description": "SendGrid API Key",
        "severity": "high",
    },
    "mailgun_api_key": {
        "pattern": r"key-[a-f0-9]{32}",
        "description": "Mailgun API Key",
        "severity": "high",
    },
    "jwt_secret": {
        "pattern": r"(?:jwt|token)_?secret['\"]?\s*[:=]\s*['\"]?[^'\"]{16,}",
        "description": "JWT Secret",
        "severity": "high",
    },
    "private_key": {
        "pattern": r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
        "description": "Private Key",
        "severity": "critical",
    },
    "ssh_private_key": {
        "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----",
        "description": "SSH Private Key",
        "severity": "critical",
    },
    "pg_private_key": {
        "pattern": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "description": "PGP Private Key",
        "severity": "critical",
    },
    "database_url": {
        "pattern": r"(?:mysql|postgres|mongodb|redis)://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+",
        "description": "Database Connection URL",
        "severity": "critical",
    },
    "mysql_connection": {
        "pattern": r"mysql://[^:]+:[^@]+@[^/]+/[^\s'\"]*",
        "description": "MySQL Connection String",
        "severity": "critical",
    },
    "postgres_connection": {
        "pattern": r"postgres(?:ql)?://[^:]+:[^@]+@[^/]+/[^\s'\"]*",
        "description": "PostgreSQL Connection String",
        "severity": "critical",
    },
    "mongodb_connection": {
        "pattern": r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s'\"]+",
        "description": "MongoDB Connection String",
        "severity": "critical",
    },
    "redis_connection": {
        "pattern": r"redis://(?::[^@]+@)?[^\s'\"]+",
        "description": "Redis Connection String",
        "severity": "high",
    },
    "password_in_code": {
        "pattern": r"(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?[^'\"]{4,}['\"]?",
        "description": "Password in Code",
        "severity": "high",
    },
    "api_key_generic": {
        "pattern": r"(?:api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_-]{20,}['\"]?",
        "description": "Generic API Key",
        "severity": "high",
    },
    "secret_key_generic": {
        "pattern": r"(?:secret[_-]?key|secretkey)['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_-]{16,}['\"]?",
        "description": "Generic Secret Key",
        "severity": "high",
    },
    "auth_token": {
        "pattern": r"(?:auth[_-]?token|bearer)['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_-]{20,}['\"]?",
        "description": "Authentication Token",
        "severity": "high",
    },
    "oauth_token": {
        "pattern": r"oauth[_-]?token['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_-]{20,}['\"]?",
        "description": "OAuth Token",
        "severity": "high",
    },
    "firebase_url": {
        "pattern": r"https://[a-z0-9-]+\.firebaseio\.com",
        "description": "Firebase URL",
        "severity": "medium",
    },
    "heroku_api_key": {
        "pattern": r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
        "description": "Heroku API Key (UUID format)",
        "severity": "high",
    },
    "generic_secret": {
        "pattern": r"(?:secret|private|credential)['\"]?\s*[:=]\s*['\"]?[^'\"]{8,}['\"]?",
        "description": "Generic Secret",
        "severity": "medium",
    },
}

FILE_EXTENSIONS = [
    ".env", ".env.local", ".env.production", ".env.development",
    ".config", ".conf", ".cfg", ".ini", ".yaml", ".yml",
    ".json", ".xml", ".properties",
    ".pem", ".key", ".crt", ".p12", ".pfx",
    ".sql", ".db", ".sqlite",
    ".sh", ".bash", ".zsh",
    ".py", ".rb", ".php", ".js", ".ts", ".java", ".go",
]

IGNORE_PATTERNS = [
    r"example",
    r"sample",
    r"test",
    r"dummy",
    r"fake",
    r"placeholder",
    r"your[_-]?key",
    r"xxx+",
    r"abc+",
    r"123+",
]


class GitHubSensitiveScanner:
    """
    GitHub敏感信息检测
    
    功能:
    - GitHub代码搜索
    - 敏感信息模式匹配
    - API密钥检测
    - 数据库凭证检测
    - 私钥证书检测
    """
    
    def __init__(self, domain: str, config: Optional[Dict[str, Any]] = None):
        self.domain = self._normalize_domain(domain)
        self.config = config or {}
        
        self.timeout = self.config.get("timeout", 30)
        self.github_token = self.config.get("github_token", "")
        self.max_results = self.config.get("max_results", 50)
        
        self.session = requests.Session()
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/vnd.github.v3+json",
        }
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"
        self.session.headers.update(headers)
        
        self._findings: List[SensitiveFinding] = []
        self._scanned_repos: Set[str] = set()
    
    def _normalize_domain(self, domain: str) -> str:
        domain = domain.strip().lower()
        if domain.startswith(("http://", "https://")):
            domain = urlparse(domain).netloc
        domain = domain.split(":")[0]
        return domain
    
    def scan(self) -> Dict[str, Any]:
        logger.info(f"[GitHubScanner] 扫描GitHub敏感信息: {self.domain}")
        
        self._search_code()
        
        return {
            "success": True,
            "domain": self.domain,
            "total_findings": len(self._findings),
            "findings": [self._finding_to_dict(f) for f in self._findings[:self.max_results]],
            "statistics": self._generate_statistics(),
        }
    
    def _search_code(self) -> None:
        queries = [
            f'"{self.domain}"',
            f'"{self.domain}" password',
            f'"{self.domain}" api_key',
            f'"{self.domain}" secret',
            f'"{self.domain}" token',
            f'"{self.domain}" credential',
            f'"{self.domain}" private_key',
            f'"{self.domain}" database',
        ]
        
        for query in queries:
            self._execute_search(query)
    
    def _execute_search(self, query: str) -> None:
        url = "https://api.github.com/search/code"
        params = {
            "q": query,
            "per_page": 30,
        }
        
        try:
            response = self.session.get(
                url,
                params=params,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                items = data.get("items", [])
                
                for item in items:
                    self._process_search_item(item)
                    
            elif response.status_code == 403:
                logger.warning("[GitHubScanner] API速率限制，请稍后重试或配置GitHub Token")
            elif response.status_code == 401:
                logger.warning("[GitHubScanner] GitHub Token无效")
                
        except (Timeout, ConnectionError, RequestException) as e:
            logger.debug(f"[GitHubScanner] 搜索失败: {e}")
    
    def _process_search_item(self, item: Dict) -> None:
        repo_name = item.get("repository", {}).get("full_name", "")
        file_path = item.get("path", "")
        file_url = item.get("html_url", "")
        
        if self._should_ignore_file(file_path):
            return
        
        repo_key = f"{repo_name}:{file_path}"
        if repo_key in self._scanned_repos:
            return
        self._scanned_repos.add(repo_key)
        
        content_url = item.get("url", "")
        if content_url:
            self._fetch_and_analyze(content_url, file_url, file_path, repo_name)
    
    def _fetch_and_analyze(self, content_url: str, file_url: str, file_path: str, repo_name: str) -> None:
        try:
            response = self.session.get(
                content_url,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                content_encoded = data.get("content", "")
                
                try:
                    content = __import__("base64").b64decode(content_encoded).decode("utf-8", errors="ignore")
                except Exception:
                    return
                
                self._analyze_content(content, file_url, file_path, repo_name)
                
        except (Timeout, ConnectionError, RequestException):
            pass
    
    def _analyze_content(self, content: str, file_url: str, file_path: str, repo_name: str) -> None:
        lines = content.split("\n")
        
        for pattern_name, pattern_info in SENSITIVE_PATTERNS.items():
            pattern = pattern_info["pattern"]
            
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    if self._should_ignore_match(line):
                        continue
                    
                    self._findings.append(SensitiveFinding(
                        file_url=file_url,
                        file_path=file_path,
                        repository=repo_name,
                        line_number=i,
                        matched_content=self._sanitize_content(line),
                        finding_type=pattern_name,
                        severity=pattern_info["severity"],
                        description=pattern_info["description"],
                        pattern_name=pattern_name,
                        confidence=0.8
                    ))
    
    def _should_ignore_file(self, file_path: str) -> bool:
        ignore_dirs = ["node_modules", "vendor", ".git", "dist", "build", "__pycache__"]
        for dir_name in ignore_dirs:
            if f"/{dir_name}/" in file_path:
                return True
        return False
    
    def _should_ignore_match(self, content: str) -> bool:
        content_lower = content.lower()
        for pattern in IGNORE_PATTERNS:
            if re.search(pattern, content_lower):
                return True
        return False
    
    def _sanitize_content(self, content: str) -> str:
        content = content.strip()
        if len(content) > 200:
            content = content[:200] + "..."
        return content
    
    def _generate_statistics(self) -> Dict[str, Any]:
        stats = {
            "total_findings": len(self._findings),
            "by_severity": {},
            "by_type": {},
            "by_repository": {},
        }
        
        for finding in self._findings:
            stats["by_severity"][finding.severity] = stats["by_severity"].get(finding.severity, 0) + 1
            stats["by_type"][finding.finding_type] = stats["by_type"].get(finding.finding_type, 0) + 1
            stats["by_repository"][finding.repository] = stats["by_repository"].get(finding.repository, 0) + 1
        
        return stats
    
    def _finding_to_dict(self, finding: SensitiveFinding) -> Dict[str, Any]:
        return {
            "file_url": finding.file_url,
            "file_path": finding.file_path,
            "repository": finding.repository,
            "line_number": finding.line_number,
            "matched_content": finding.matched_content,
            "finding_type": finding.finding_type,
            "severity": finding.severity,
            "description": finding.description,
            "confidence": finding.confidence,
        }


def scan_github_sensitive(domain: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    GitHub敏感信息检测便捷函数
    
    Args:
        domain: 目标域名
        config: 配置选项
        
    Returns:
        检测结果
    """
    scanner = GitHubSensitiveScanner(domain, config)
    return scanner.scan()
