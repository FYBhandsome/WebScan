# -*- coding:utf-8 -*-

"""
搜索引擎发现模块
功能:
1. 多搜索引擎聚合查询
2. 相关页面发现
3. 敏感信息搜索
4. 搜索结果解析
5. Google Dork支持
6. 结果去重
"""

import logging
import re
import time
import random
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from urllib.parse import quote, urlparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("SearchEngine")

@dataclass
class SearchResult:
    title: str = ""
    url: str = ""
    snippet: str = ""
    engine: str = ""

@dataclass
class SearchEngineResult:
    query: str = ""
    results: List[SearchResult] = field(default_factory=list)
    total_results: int = 0
    engines_used: List[str] = field(default_factory=list)
    has_result: bool = False
    error: str = ""

class SearchEngineAPI:
    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retry_strategy = Retry(
            total=2,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"]
        )
        session.mount("http://", HTTPAdapter(max_retries=retry_strategy))
        session.mount("https://", HTTPAdapter(max_retries=retry_strategy))
        
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        ]
        
        session.headers.update({
            "User-Agent": random.choice(user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        })
        return session
    
    def search_bing(self, query: str, count: int = 10) -> List[SearchResult]:
        results = []
        try:
            url = f"https://www.bing.com/search?q={quote(query)}&count={count}"
            response = self.session.get(url, timeout=self.timeout)
            response.encoding = "utf-8"
            
            pattern = re.compile(r'<li class="b_algo"[^>]*>.*?<h2><a href="([^"]+)"[^>]*>([^<]+)</a></h2>.*?<p[^>]*>([^<]+)</p>', re.DOTALL)
            matches = pattern.findall(response.text)
            
            for match in matches[:count]:
                results.append(SearchResult(
                    title=re.sub(r'<[^>]+>', '', match[1]).strip(),
                    url=match[0],
                    snippet=re.sub(r'<[^>]+>', '', match[2]).strip(),
                    engine="Bing"
                ))
                
        except Exception as e:
            logger.warning(f"Bing搜索异常: {str(e)[:50]}")
        
        return results
    
    def search_duckduckgo(self, query: str, count: int = 10) -> List[SearchResult]:
        results = []
        try:
            url = f"https://html.duckduckgo.com/html/?q={quote(query)}"
            response = self.session.get(url, timeout=self.timeout)
            response.encoding = "utf-8"
            
            pattern = re.compile(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>([^<]+)</a>.*?<a[^>]+class="result__snippet"[^>]*>([^<]*)</a>', re.DOTALL)
            matches = pattern.findall(response.text)
            
            for match in matches[:count]:
                results.append(SearchResult(
                    title=re.sub(r'<[^>]+>', '', match[1]).strip(),
                    url=match[0],
                    snippet=re.sub(r'<[^>]+>', '', match[2]).strip(),
                    engine="DuckDuckGo"
                ))
                
        except Exception as e:
            logger.warning(f"DuckDuckGo搜索异常: {str(e)[:50]}")
        
        return results
    
    def search_searx(self, query: str, count: int = 10) -> List[SearchResult]:
        results = []
        searx_instances = [
            "https://searx.be",
            "https://search.bus-hit.me",
            "https://searx.fmac.xyz",
        ]
        
        for instance in searx_instances:
            try:
                url = f"{instance}/search?q={quote(query)}&format=json"
                response = self.session.get(url, timeout=self.timeout)
                
                if response.status_code == 200:
                    data = response.json()
                    for item in data.get("results", [])[:count]:
                        results.append(SearchResult(
                            title=item.get("title", ""),
                            url=item.get("url", ""),
                            snippet=item.get("content", ""),
                            engine="Searx"
                        ))
                    if results:
                        break
                        
            except Exception as e:
                logger.warning(f"Searx({instance})搜索异常: {str(e)[:50]}")
                continue
        
        return results
    
    def search_google_custom(self, query: str, api_key: str = "", cx: str = "", count: int = 10) -> List[SearchResult]:
        results = []
        
        if not api_key or not cx:
            return results
        
        try:
            url = "https://www.googleapis.com/customsearch/v1"
            params = {
                "key": api_key,
                "cx": cx,
                "q": query,
                "num": count,
            }
            response = self.session.get(url, params=params, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                for item in data.get("items", []):
                    results.append(SearchResult(
                        title=item.get("title", ""),
                        url=item.get("link", ""),
                        snippet=item.get("snippet", ""),
                        engine="Google"
                    ))
                    
        except Exception as e:
            logger.warning(f"Google搜索异常: {str(e)[:50]}")
        
        return results

class SearchEngineDiscovery:
    DORK_TEMPLATES = {
        "site": "site:{target}",
        "related": "related:{target}",
        "info": "info:{target}",
        "inurl": "inurl:{target}",
        "intitle": 'intitle:"{target}"',
        "filetype": "site:{domain} filetype:{ext}",
        "admin": "site:{target} admin",
        "login": "site:{target} login",
        "password": "site:{target} password",
        "config": "site:{target} config",
        "backup": "site:{target} backup",
        "database": "site:{target} database OR db OR sql",
        "sensitive": 'site:{target} "password" OR "secret" OR "key" OR "token"',
        "directory_listing": 'site:{target} intitle:"index of"',
        "error_pages": 'site:{target} intitle:"error" OR intitle:"exception"',
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 15)
        self.google_api_key = self.config.get("google_api_key", "")
        self.google_cx = self.config.get("google_cx", "")
        
        self._api = SearchEngineAPI(timeout=self.timeout)
    
    def search(self, query: str, engines: List[str] = None, count: int = 10) -> SearchEngineResult:
        result = SearchEngineResult(query=query)
        
        if engines is None:
            engines = ["bing", "duckduckgo", "searx"]
        
        all_results = []
        seen_urls = set()
        
        for engine in engines:
            try:
                logger.info(f"使用 {engine} 搜索: {query}")
                
                if engine == "bing":
                    results = self._api.search_bing(query, count)
                elif engine == "duckduckgo":
                    results = self._api.search_duckduckgo(query, count)
                elif engine == "searx":
                    results = self._api.search_searx(query, count)
                elif engine == "google":
                    results = self._api.search_google_custom(query, self.google_api_key, self.google_cx, count)
                else:
                    continue
                
                for r in results:
                    if r.url not in seen_urls:
                        seen_urls.add(r.url)
                        all_results.append(r)
                
                result.engines_used.append(engine)
                time.sleep(random.uniform(0.5, 1.5))
                
            except Exception as e:
                logger.warning(f"{engine} 搜索异常: {str(e)[:50]}")
                continue
        
        result.results = all_results
        result.total_results = len(all_results)
        result.has_result = bool(all_results)
        
        return result
    
    def dork_search(self, target: str, dork_types: List[str] = None) -> Dict[str, SearchEngineResult]:
        domain = target.strip().lower()
        if domain.startswith(("http://", "https://")):
            domain = urlparse(domain).netloc
        
        if dork_types is None:
            dork_types = ["site", "admin", "login", "sensitive", "directory_listing"]
        
        results = {}
        
        for dork_type in dork_types:
            if dork_type in self.DORK_TEMPLATES:
                query = self.DORK_TEMPLATES[dork_type].format(target=domain, domain=domain, ext="pdf")
                results[dork_type] = self.search(query, count=5)
                time.sleep(random.uniform(1, 2))
        
        return results
    
    def find_related_pages(self, url: str) -> SearchEngineResult:
        domain = urlparse(url).netloc if "://" in url else url
        query = f"related:{domain}"
        return self.search(query)
    
    def find_sensitive_info(self, domain: str) -> SearchEngineResult:
        queries = [
            f'site:{domain} "password" OR "secret" OR "api_key" OR "token"',
            f'site:{domain} filetype:env OR filetype:config OR filetype:ini',
            f'site:{domain} intitle:"index of" "parent directory"',
        ]
        
        all_results = []
        seen_urls = set()
        
        for query in queries:
            result = self.search(query, count=5)
            for r in result.results:
                if r.url not in seen_urls:
                    seen_urls.add(r.url)
                    all_results.append(r)
            time.sleep(random.uniform(1, 2))
        
        final_result = SearchEngineResult(query=f"sensitive:{domain}")
        final_result.results = all_results
        final_result.total_results = len(all_results)
        final_result.has_result = bool(all_results)
        
        return final_result

def search(query: str, engines: List[str] = None) -> Dict[str, Any]:
    discovery = SearchEngineDiscovery()
    result = discovery.search(query, engines)
    
    return {
        "success": result.has_result,
        "query": result.query,
        "total_results": result.total_results,
        "engines_used": result.engines_used,
        "results": [
            {
                "title": r.title,
                "url": r.url,
                "snippet": r.snippet[:100] + "..." if len(r.snippet) > 100 else r.snippet,
                "engine": r.engine
            }
            for r in result.results
        ],
        "error": result.error
    }

def dork_search(target: str, dork_types: List[str] = None) -> Dict[str, Any]:
    discovery = SearchEngineDiscovery()
    results = discovery.dork_search(target, dork_types)
    
    return {
        "success": True,
        "target": target,
        "results": {
            dork_type: {
                "total": result.total_results,
                "items": [{"title": r.title, "url": r.url} for r in result.results[:5]]
            }
            for dork_type, result in results.items()
        }
    }

if __name__ == '__main__':
    test_queries = ["python web scraping", "security vulnerability"]
    for query in test_queries:
        print(f"\n{'='*60}")
        print(f"搜索: {query}")
        result = search(query)
        if result["success"]:
            print(f"找到 {result['total_results']} 条结果")
            print(f"使用的引擎: {', '.join(result['engines_used'])}")
            for r in result['results'][:5]:
                print(f"  - {r['title']}")
                print(f"    {r['url']}")
        else:
            print(f"错误: {result['error']}")
