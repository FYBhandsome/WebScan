# -*- coding:utf-8 -*-
"""
Web爬虫核心实现

功能：
1. 从种子URL开始爬取
2. 解析HTML提取链接、表单、脚本
3. 自动跟踪链接构建站点地图
4. 支持深度限制、范围限制
5. 支持登录态爬取
"""

import asyncio
import logging
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any
from collections import deque
from concurrent.futures import ThreadPoolExecutor

import httpx
from bs4 import BeautifulSoup

from .config import CRAWLER_CONFIG, DEFAULT_HEADERS, SENSITIVE_PATTERNS, LOGIN_PATHS
from .parser import HTMLParser
from .form_extractor import FormExtractor
from .url_filter import URLFilter

logger = logging.getLogger(__name__)


@dataclass
class InputInfo:
    """输入字段信息"""
    name: str
    type: str
    value: str = ""
    required: bool = False
    placeholder: str = ""


@dataclass
class FormInfo:
    """表单信息"""
    url: str
    action: str
    method: str
    inputs: List[InputInfo] = field(default_factory=list)
    has_file_upload: bool = False
    has_password: bool = False
    has_hidden: bool = False


@dataclass
class PageInfo:
    """页面信息"""
    url: str
    depth: int
    status_code: int
    title: str = ""
    content_type: str = ""
    content_length: int = 0
    links: List[str] = field(default_factory=list)
    forms: List[FormInfo] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)
    params: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    response_time: float = 0.0


@dataclass
class CrawlResult:
    """爬取结果"""
    target: str
    pages: List[PageInfo] = field(default_factory=list)
    forms: List[FormInfo] = field(default_factory=list)
    params: List[Dict] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    site_map: Dict = field(default_factory=dict)
    sensitive_info: List[Dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    duration: float = 0.0
    total_pages: int = 0
    total_links: int = 0
    total_forms: int = 0


class WebCrawler:
    """
    Web爬虫核心类
    
    功能：
    1. 从种子URL开始爬取
    2. 解析HTML提取链接、表单、脚本
    3. 自动跟踪链接构建站点地图
    4. 支持深度限制、范围限制
    5. 支持登录态爬取
    """
    
    def __init__(self, target: str, config: Dict = None):
        self.target = self._normalize_target(target)
        self.config = {**CRAWLER_CONFIG, **(config or {})}
        
        self.visited_urls: Set[str] = set()
        self.pending_urls: deque = deque()
        self.pages: List[PageInfo] = []
        self.forms: List[FormInfo] = []
        self.params: List[Dict] = []
        self.urls: List[str] = []
        self.site_map: Dict = {}
        self.sensitive_info: List[Dict] = []
        self.errors: List[str] = []
        
        self.url_filter = URLFilter(self.target, self.config)
        self.html_parser = HTMLParser()
        self.form_extractor = FormExtractor()
        
        self._stop_flag = False
        self._start_time = 0.0
        
        logger.info(f"🕷️ 爬虫初始化: {self.target}")
    
    def _normalize_target(self, target: str) -> str:
        """标准化目标URL"""
        target = target.strip()
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
        return target.rstrip("/")
    
    def crawl(self) -> Dict:
        """
        执行爬取（同步入口）
        
        Returns:
            Dict: 爬取结果
        """
        return asyncio.run(self.crawl_async())
    
    async def crawl_async(self) -> Dict:
        """
        执行爬取（异步入口）
        
        Returns:
            Dict: 爬取结果
        """
        self._start_time = time.time()
        logger.info(f"🕷️ 开始爬取: {self.target}")
        
        self.pending_urls.append((self.target, 0))
        
        robots_rules = self._get_robots_rules()
        
        async with httpx.AsyncClient(
            timeout=self.config["timeout"],
            follow_redirects=self.config["follow_redirects"],
            verify=self.config["verify_ssl"],
            headers=DEFAULT_HEADERS
        ) as client:
            while self.pending_urls and not self._stop_flag:
                if len(self.visited_urls) >= self.config["max_pages"]:
                    logger.info(f"达到最大页面数限制: {self.config['max_pages']}")
                    break
                
                batch_size = min(self.config["max_concurrent"], len(self.pending_urls))
                tasks = []
                
                for _ in range(batch_size):
                    if not self.pending_urls:
                        break
                    url, depth = self.pending_urls.popleft()
                    
                    if url in self.visited_urls:
                        continue
                    if depth > self.config["max_depth"]:
                        continue
                    if not self._respect_robots(url, robots_rules):
                        continue
                    
                    self.visited_urls.add(url)
                    tasks.append(self._crawl_page(client, url, depth))
                
                if tasks:
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    
                    for result in results:
                        if isinstance(result, Exception):
                            self.errors.append(str(result))
                        elif result:
                            self._process_page_result(result)
        
        duration = time.time() - self._start_time
        
        result = CrawlResult(
            target=self.target,
            pages=self.pages,
            forms=self.forms,
            params=self.params,
            urls=list(self.visited_urls),
            site_map=self.site_map,
            sensitive_info=self.sensitive_info,
            errors=self.errors,
            duration=duration,
            total_pages=len(self.pages),
            total_links=len(self.urls),
            total_forms=len(self.forms)
        )
        
        logger.info(f"🕷️ 爬取完成: {len(self.pages)} 页面, {len(self.forms)} 表单, 耗时 {duration:.2f}s")
        
        return self._result_to_dict(result)
    
    async def _crawl_page(self, client: httpx.AsyncClient, url: str, depth: int) -> Optional[PageInfo]:
        """爬取单个页面"""
        try:
            logger.debug(f"爬取: {url} (深度: {depth})")
            
            response = await client.get(url)
            
            if response.status_code >= 400:
                logger.debug(f"跳过错误页面: {url} (状态码: {response.status_code})")
                return None
            
            content_type = response.headers.get("content-type", "")
            if not content_type.startswith("text/html"):
                logger.debug(f"跳过非HTML页面: {url} (类型: {content_type})")
                return None
            
            html = response.text
            soup = BeautifulSoup(html, "html.parser")
            
            title = soup.title.string.strip() if soup.title else ""
            
            links = self.html_parser.extract_links(soup, url)
            forms = self.form_extractor.extract_forms(soup, url)
            scripts = self.html_parser.extract_scripts(soup)
            comments = self.html_parser.extract_comments(html)
            params = self.html_parser.extract_params(url)
            
            sensitive = self._find_sensitive_info(html, url)
            if sensitive:
                self.sensitive_info.extend(sensitive)
            
            for link in links:
                normalized = self.url_filter.normalize_url(link)
                if normalized and normalized not in self.visited_urls:
                    if self.url_filter.should_crawl(normalized):
                        self.pending_urls.append((normalized, depth + 1))
                        self.urls.append(normalized)
            
            self.forms.extend(forms)
            self.params.append({"url": url, "params": params})
            
            self._update_site_map(url, links)
            
            page_info = PageInfo(
                url=url,
                depth=depth,
                status_code=response.status_code,
                title=title,
                content_type=content_type,
                content_length=len(response.content),
                links=links[:20],
                forms=forms,
                scripts=scripts[:10],
                comments=comments[:10],
                params=params,
                headers=dict(response.headers),
                response_time=response.elapsed.total_seconds
            )
            
            self.pages.append(page_info)
            
            await asyncio.sleep(self.config["delay"])
            
            return page_info
            
        except httpx.TimeoutException:
            self.errors.append(f"超时: {url}")
            return None
        except Exception as e:
            self.errors.append(f"错误 {url}: {str(e)}")
            return None
    
    def _process_page_result(self, page_info: PageInfo) -> None:
        """处理页面结果"""
        if page_info:
            logger.debug(f"处理页面: {page_info.url}")
    
    def _find_sensitive_info(self, html: str, url: str) -> List[Dict]:
        """查找敏感信息"""
        sensitive = []
        
        for pattern in SENSITIVE_PATTERNS:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                sensitive.append({
                    "url": url,
                    "type": "sensitive_data",
                    "pattern": pattern.pattern if hasattr(pattern, 'pattern') else str(pattern),
                    "match": match[:100] if isinstance(match, str) else str(match)[:100]
                })
        
        return sensitive
    
    def _get_robots_rules(self) -> Dict:
        """获取robots.txt规则"""
        robots_url = f"{self.target}/robots.txt"
        rules = {"disallow": [], "allow": []}
        
        try:
            import requests
            response = requests.get(robots_url, timeout=5, verify=False)
            if response.status_code == 200:
                for line in response.text.split("\n"):
                    line = line.strip().lower()
                    if line.startswith("disallow:"):
                        rules["disallow"].append(line.split(":", 1)[1].strip())
                    elif line.startswith("allow:"):
                        rules["allow"].append(line.split(":", 1)[1].strip())
        except Exception:
            pass
        
        return rules
    
    def _respect_robots(self, url: str, rules: Dict) -> bool:
        """检查是否遵守robots.txt"""
        if not self.config["respect_robots"]:
            return True
        
        parsed = urllib.parse.urlparse(url)
        path = parsed.path
        
        for disallow in rules.get("disallow", []):
            if disallow and path.startswith(disallow):
                for allow in rules.get("allow", []):
                    if allow and path.startswith(allow):
                        return True
                return False
        
        return True
    
    def _update_site_map(self, url: str, links: List[str]) -> None:
        """更新站点地图"""
        parsed = urllib.parse.urlparse(url)
        path = parsed.path or "/"
        
        if path not in self.site_map:
            self.site_map[path] = {
                "url": url,
                "links": [],
                "linked_from": []
            }
        
        for link in links[:10]:
            link_parsed = urllib.parse.urlparse(link)
            link_path = link_parsed.path or "/"
            if link_path not in self.site_map[path]["links"]:
                self.site_map[path]["links"].append(link_path)
    
    def _result_to_dict(self, result: CrawlResult) -> Dict:
        """将结果转换为字典"""
        return {
            "target": result.target,
            "total_pages": result.total_pages,
            "total_links": result.total_links,
            "total_forms": result.total_forms,
            "duration": result.duration,
            "pages": [
                {
                    "url": p.url,
                    "depth": p.depth,
                    "status_code": p.status_code,
                    "title": p.title,
                    "content_type": p.content_type,
                    "links_count": len(p.links),
                    "forms_count": len(p.forms),
                    "scripts_count": len(p.scripts),
                    "params": p.params
                }
                for p in result.pages
            ],
            "forms": [
                {
                    "url": f.url,
                    "action": f.action,
                    "method": f.method,
                    "has_file_upload": f.has_file_upload,
                    "has_password": f.has_password,
                    "inputs_count": len(f.inputs)
                }
                for f in result.forms
            ],
            "urls": result.urls,
            "site_map": result.site_map,
            "sensitive_info": result.sensitive_info[:20],
            "errors": result.errors[:10]
        }


def crawl(target: str, config: Dict = None) -> Dict:
    """
    爬取入口函数
    
    Args:
        target: 目标URL
        config: 可选配置
        
    Returns:
        Dict: 爬取结果
    """
    crawler = WebCrawler(target, config)
    return crawler.crawl()
