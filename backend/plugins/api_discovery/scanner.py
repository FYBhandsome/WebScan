"""
API接口发现模块

功能:
- JS文件分析提取API
- HTML页面分析提取API
- 常见API路径探测
- GraphQL端点检测
- REST API发现
- API文档发现
"""

import re
import json
import logging
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError

logger = logging.getLogger(__name__)


@dataclass
class APIEndpoint:
    url: str
    method: str
    path: str
    source: str
    content_type: str
    parameters: List[str] = field(default_factory=list)
    description: str = ""
    is_sensitive: bool = False


API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/api/v1.0", "/api/v2.0", "/api/rest",
    "/rest", "/restful", "/service",
    "/services", "/ws", "/wsdl",
    "/graphql", "/graphiql", "/graphql/console",
    "/api-docs", "/api-docs/", "/swagger",
    "/swagger-ui", "/swagger-ui.html", "/swagger-resources",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/openapi.json", "/swagger.json", "/api.json",
    "/docs", "/redoc", "/api/reference",
    "/api/users", "/api/user", "/api/auth",
    "/api/login", "/api/logout", "/api/register",
    "/api/account", "/api/accounts", "/api/profile",
    "/api/admin", "/api/config", "/api/settings",
    "/api/data", "/api/search", "/api/query",
    "/api/upload", "/api/download", "/api/file",
    "/api/posts", "/api/comments", "/api/articles",
    "/api/products", "/api/orders", "/api/items",
    "/api/health", "/api/status", "/api/ping",
    "/api/metrics", "/api/info", "/api/version",
    "/internal/api", "/private/api", "/public/api",
    "/mobile/api", "/app/api", "/web/api",
]

API_URL_PATTERNS = [
    re.compile(r'["\']([^"\']*?/api/[^"\']*?)["\']', re.IGNORECASE),
    re.compile(r'["\']([^"\']*?/v\d+/[^"\']*?)["\']', re.IGNORECASE),
    re.compile(r'["\']([^"\']*?/rest/[^"\']*?)["\']', re.IGNORECASE),
    re.compile(r'["\']([^"\']*?/graphql[^"\']*?)["\']', re.IGNORECASE),
    re.compile(r'["\']([^"\']*?/service/[^"\']*?)["\']', re.IGNORECASE),
    re.compile(r'["\']([^"\']*?\.(?:json|xml)[^"\']*?)["\']', re.IGNORECASE),
    re.compile(r'(?:fetch|axios|http|request)\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'\.(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'url\s*:\s*["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'href\s*=\s*["\']([^"\']*api[^"\']*)["\']', re.IGNORECASE),
    re.compile(r'action\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
]

JS_FILE_PATTERNS = [
    re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE),
    re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE),
]

SENSITIVE_API_KEYWORDS = [
    "admin", "user", "password", "token", "auth", "login",
    "secret", "key", "api_key", "apikey", "private",
    "config", "setting", "account", "profile", "credit",
    "payment", "order", "transaction", "database", "db",
    "backup", "export", "import", "upload", "delete",
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]


class APIDiscovery:
    """
    API接口发现扫描器
    
    功能:
    - JS文件分析提取API
    - HTML页面分析提取API
    - 常见API路径探测
    - GraphQL端点检测
    - API文档发现
    """
    
    def __init__(self, target: str, config: Optional[Dict[str, Any]] = None):
        self.target = self._normalize_url(target)
        self.config = config or {}
        
        self.timeout = self.config.get("timeout", 15)
        self.max_workers = self.config.get("max_workers", 10)
        self.delay = self.config.get("delay", 0.1)
        self.verify_ssl = self.config.get("verify_ssl", False)
        self.max_results = self.config.get("max_results", 100)
        
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive"
        })
        
        self._results: List[APIEndpoint] = []
        self._discovered_urls: Set[str] = set()
        self._base_domain = urlparse(self.target).netloc
    
    def _normalize_url(self, url: str) -> str:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        return url.rstrip("/")
    
    def scan(self) -> Dict[str, Any]:
        logger.info(f"[APIDiscovery] 开始扫描: {self.target}")
        
        self._analyze_html_page()
        self._analyze_js_files()
        self._probe_api_paths()
        self._detect_graphql()
        self._detect_api_docs()
        
        results = [self._endpoint_to_dict(e) for e in self._results[:self.max_results]]
        
        return {
            "success": True,
            "target": self.target,
            "total_found": len(self._results),
            "endpoints": results,
            "statistics": self._generate_statistics(),
        }
    
    def _analyze_html_page(self) -> None:
        try:
            response = self.session.get(
                self.target + "/",
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            self._extract_apis_from_content(response.text, "HTML")
            
        except (Timeout, ConnectionError, RequestException) as e:
            logger.debug(f"[APIDiscovery] HTML分析失败: {e}")
    
    def _analyze_js_files(self) -> None:
        try:
            response = self.session.get(
                self.target + "/",
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            js_files = set()
            for pattern in JS_FILE_PATTERNS:
                for match in pattern.finditer(response.text):
                    js_url = match.group(1)
                    if js_url.startswith("//"):
                        js_url = "https:" + js_url
                    elif js_url.startswith("/"):
                        js_url = urljoin(self.target, js_url)
                    elif not js_url.startswith("http"):
                        js_url = urljoin(self.target, js_url)
                    js_files.add(js_url)
            
            logger.info(f"[APIDiscovery] 发现 {len(js_files)} 个JS文件")
            
            for js_url in list(js_files)[:20]:
                self._fetch_and_analyze_js(js_url)
                
        except (Timeout, ConnectionError, RequestException) as e:
            logger.debug(f"[APIDiscovery] JS分析失败: {e}")
    
    def _fetch_and_analyze_js(self, js_url: str) -> None:
        try:
            response = self.session.get(
                js_url,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            self._extract_apis_from_content(response.text, "JS")
            
        except (Timeout, ConnectionError, RequestException):
            pass
    
    def _extract_apis_from_content(self, content: str, source: str) -> None:
        for pattern in API_URL_PATTERNS:
            for match in pattern.finditer(content):
                api_url = match.group(1)
                
                if api_url.startswith("//"):
                    api_url = "https:" + api_url
                elif api_url.startswith("/"):
                    api_url = self.target + api_url
                elif not api_url.startswith("http"):
                    api_url = urljoin(self.target, api_url)
                
                if self._is_valid_api_url(api_url):
                    self._add_endpoint(api_url, source)
    
    def _is_valid_api_url(self, url: str) -> bool:
        if url in self._discovered_urls:
            return False
        
        parsed = urlparse(url)
        
        if parsed.netloc and parsed.netloc != self._base_domain:
            if not parsed.netloc.endswith(self._base_domain):
                return False
        
        ignore_extensions = ['.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.css', '.woff', '.woff2', '.ttf', '.eot']
        for ext in ignore_extensions:
            if url.lower().endswith(ext):
                return False
        
        return True
    
    def _add_endpoint(self, url: str, source: str, method: str = "GET") -> None:
        if url in self._discovered_urls:
            return
        
        self._discovered_urls.add(url)
        
        parsed = urlparse(url)
        path = parsed.path
        params = list(parse_qs(parsed.query).keys())
        
        is_sensitive = any(kw in url.lower() for kw in SENSITIVE_API_KEYWORDS)
        
        self._results.append(APIEndpoint(
            url=url,
            method=method,
            path=path,
            source=source,
            content_type="",
            parameters=params,
            is_sensitive=is_sensitive
        ))
    
    def _probe_api_paths(self) -> None:
        logger.info(f"[APIDiscovery] 探测常见API路径...")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._probe_path, path): path
                for path in API_PATHS[:50]
            }
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass
    
    def _probe_path(self, path: str) -> None:
        url = self.target + path
        
        if url in self._discovered_urls:
            return
        
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False
            )
            
            if response.status_code in [200, 201, 301, 302, 401, 403, 405]:
                content_type = response.headers.get("Content-Type", "")
                
                if "application/json" in content_type or "application/xml" in content_type:
                    self._discovered_urls.add(url)
                    self._results.append(APIEndpoint(
                        url=url,
                        method="GET",
                        path=path,
                        source="Probe",
                        content_type=content_type,
                        is_sensitive=self._is_sensitive_api(path, response.text)
                    ))
                    
        except (Timeout, ConnectionError, RequestException):
            pass
    
    def _detect_graphql(self) -> None:
        graphql_url = self.target + "/graphql"
        
        try:
            response = self.session.post(
                graphql_url,
                json={"query": "{ __schema { types { name } } }"},
                timeout=self.timeout,
                verify=self.verify_ssl,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if "data" in data or "errors" in data:
                        self._discovered_urls.add(graphql_url)
                        self._results.append(APIEndpoint(
                            url=graphql_url,
                            method="POST",
                            path="/graphql",
                            source="GraphQL Detection",
                            content_type="application/json",
                            description="GraphQL endpoint detected",
                            is_sensitive=True
                        ))
                except json.JSONDecodeError:
                    pass
                    
        except (Timeout, ConnectionError, RequestException):
            pass
    
    def _detect_api_docs(self) -> None:
        doc_paths = [
            "/swagger-ui.html", "/api-docs", "/docs",
            "/redoc", "/openapi.json", "/swagger.json"
        ]
        
        for path in doc_paths:
            url = self.target + path
            
            if url in self._discovered_urls:
                continue
            
            try:
                response = self.session.get(
                    url,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                
                if response.status_code == 200:
                    content_type = response.headers.get("Content-Type", "")
                    
                    if "swagger" in response.text.lower() or "openapi" in response.text.lower():
                        self._discovered_urls.add(url)
                        self._results.append(APIEndpoint(
                            url=url,
                            method="GET",
                            path=path,
                            source="API Docs",
                            content_type=content_type,
                            description="API documentation detected",
                            is_sensitive=True
                        ))
                        
            except (Timeout, ConnectionError, RequestException):
                pass
    
    def _is_sensitive_api(self, path: str, content: str) -> bool:
        path_lower = path.lower()
        content_lower = content.lower()
        
        for keyword in SENSITIVE_API_KEYWORDS:
            if keyword in path_lower or keyword in content_lower:
                return True
        
        return False
    
    def _generate_statistics(self) -> Dict[str, Any]:
        stats = {
            "total_endpoints": len(self._results),
            "sensitive_endpoints": sum(1 for e in self._results if e.is_sensitive),
            "by_source": {},
            "by_method": {},
        }
        
        for endpoint in self._results:
            stats["by_source"][endpoint.source] = stats["by_source"].get(endpoint.source, 0) + 1
            stats["by_method"][endpoint.method] = stats["by_method"].get(endpoint.method, 0) + 1
        
        return stats
    
    def _endpoint_to_dict(self, endpoint: APIEndpoint) -> Dict[str, Any]:
        return {
            "url": endpoint.url,
            "method": endpoint.method,
            "path": endpoint.path,
            "source": endpoint.source,
            "content_type": endpoint.content_type,
            "parameters": endpoint.parameters,
            "description": endpoint.description,
            "is_sensitive": endpoint.is_sensitive,
        }


def discover_apis(target: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    API接口发现便捷函数
    
    Args:
        target: 目标URL
        config: 配置选项
        
    Returns:
        发现结果
    """
    discovery = APIDiscovery(target, config)
    return discovery.scan()
