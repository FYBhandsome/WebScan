# -*- coding:utf-8 -*-
"""
URL过滤器和去重器

功能：
1. URL标准化
2. URL去重
3. URL范围限制
4. 扩展名过滤
"""

import re
import urllib.parse
from typing import Set, Dict, Optional, List
from urllib.parse import urlparse, urlunparse

from .config import CRAWLER_CONFIG


class URLFilter:
    """
    URL过滤器
    
    功能：
    1. URL标准化
    2. URL去重
    3. URL范围限制
    4. 扩展名过滤
    """
    
    def __init__(self, target: str, config: Dict = None):
        self.target = target
        self.config = {**CRAWLER_CONFIG, **(config or {})}
        
        self.target_domain = self._extract_domain(target)
        self.target_netloc = self._extract_netloc(target)
        
        self.visited: Set[str] = set()
        self.seen_hashes: Set[str] = set()
        
        self.exclude_extensions = set(self.config.get("exclude_extensions", []))
        self.exclude_patterns = self.config.get("exclude_patterns", [])
        
        self._compile_patterns()
    
    def _compile_patterns(self):
        """编译正则表达式模式"""
        self.compiled_exclude = []
        for pattern in self.exclude_patterns:
            try:
                self.compiled_exclude.append(re.compile(pattern, re.IGNORECASE))
            except re.error:
                pass
    
    def should_crawl(self, url: str) -> bool:
        """
        判断URL是否应该被爬取
        
        Args:
            url: URL字符串
            
        Returns:
            bool: 是否应该爬取
        """
        if not url:
            return False
        
        if url in self.visited:
            return False
        
        normalized = self.normalize_url(url)
        if not normalized:
            return False
        
        if normalized in self.visited:
            return False
        
        if not self._is_same_domain(normalized):
            return False
        
        if self._is_excluded_extension(normalized):
            return False
        
        if self._matches_exclude_pattern(normalized):
            return False
        
        return True
    
    def normalize_url(self, url: str) -> Optional[str]:
        """
        标准化URL
        
        Args:
            url: 原始URL
            
        Returns:
            Optional[str]: 标准化后的URL，无效返回None
        """
        if not url:
            return None
        
        url = url.strip()
        
        if url.startswith(('javascript:', 'mailto:', 'tel:', 'data:', 'ftp:', 'file:')):
            return None
        
        if url.startswith('#'):
            return None
        
        try:
            if url.startswith('//'):
                url = 'http:' + url
            
            parsed = urlparse(url)
            
            if not parsed.scheme:
                base_parsed = urlparse(self.target)
                url = urlunparse((
                    base_parsed.scheme,
                    base_parsed.netloc,
                    parsed.path or '/',
                    parsed.params,
                    parsed.query,
                    ''
                ))
            elif not parsed.netloc:
                base_parsed = urlparse(self.target)
                url = urlunparse((
                    parsed.scheme or base_parsed.scheme,
                    base_parsed.netloc,
                    parsed.path or '/',
                    parsed.params,
                    parsed.query,
                    ''
                ))
            
            parsed = urlparse(url)
            
            path = parsed.path
            if not path:
                path = '/'
            
            path = re.sub(r'/+', '/', path)
            
            if parsed.query:
                query = self._normalize_query(parsed.query)
            else:
                query = ''
            
            url = urlunparse((
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                path,
                parsed.params,
                query,
                ''
            ))
            
            return url
            
        except Exception:
            return None
    
    def _normalize_query(self, query: str) -> str:
        """标准化查询参数"""
        try:
            params = urllib.parse.parse_qs(query, keep_blank_values=True)
            
            sorted_params = sorted(params.items())
            
            normalized_query = urllib.parse.urlencode(sorted_params, doseq=True)
            
            return normalized_query
        except Exception:
            return query
    
    def _is_same_domain(self, url: str) -> bool:
        """检查是否为同一域名"""
        try:
            parsed = urlparse(url)
            url_netloc = parsed.netloc.lower()
            
            if url_netloc == self.target_netloc.lower():
                return True
            
            if url_netloc.endswith('.' + self.target_domain.lower()):
                return True
            
            if self.target_domain.lower().endswith('.' + url_netloc):
                return True
            
            return False
            
        except Exception:
            return False
    
    def _is_excluded_extension(self, url: str) -> bool:
        """检查是否为排除的扩展名"""
        try:
            parsed = urlparse(url)
            path = parsed.path.lower()
            
            for ext in self.exclude_extensions:
                if path.endswith(ext.lower()):
                    return True
            
            return False
            
        except Exception:
            return False
    
    def _matches_exclude_pattern(self, url: str) -> bool:
        """检查是否匹配排除模式"""
        for pattern in self.compiled_exclude:
            if pattern.search(url):
                return True
        
        return False
    
    def _extract_domain(self, url: str) -> str:
        """提取域名"""
        try:
            parsed = urlparse(url)
            netloc = parsed.netloc.lower()
            
            if ':' in netloc:
                netloc = netloc.split(':')[0]
            
            parts = netloc.split('.')
            if len(parts) >= 2:
                return '.'.join(parts[-2:])
            
            return netloc
            
        except Exception:
            return ""
    
    def _extract_netloc(self, url: str) -> str:
        """提取netloc"""
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except Exception:
            return ""
    
    def add_visited(self, url: str) -> None:
        """添加到已访问集合"""
        normalized = self.normalize_url(url)
        if normalized:
            self.visited.add(normalized)
    
    def is_visited(self, url: str) -> bool:
        """检查是否已访问"""
        normalized = self.normalize_url(url)
        return normalized in self.visited if normalized else False
    
    def get_visited_count(self) -> int:
        """获取已访问URL数量"""
        return len(self.visited)
    
    def get_url_hash(self, url: str) -> str:
        """获取URL哈希值"""
        import hashlib
        
        normalized = self.normalize_url(url)
        if normalized:
            return hashlib.md5(normalized.encode()).hexdigest()
        return ""
    
    def filter_urls(self, urls: List[str]) -> List[str]:
        """
        批量过滤URL
        
        Args:
            urls: URL列表
            
        Returns:
            List[str]: 过滤后的URL列表
        """
        filtered = []
        
        for url in urls:
            if self.should_crawl(url):
                filtered.append(self.normalize_url(url))
        
        return list(set(filtered))
    
    def get_url_info(self, url: str) -> Dict:
        """
        获取URL详细信息
        
        Args:
            url: URL字符串
            
        Returns:
            Dict: URL信息
        """
        try:
            parsed = urlparse(url)
            
            return {
                "url": url,
                "scheme": parsed.scheme,
                "netloc": parsed.netloc,
                "domain": self._extract_domain(url),
                "path": parsed.path,
                "query": parsed.query,
                "params": urllib.parse.parse_qs(parsed.query) if parsed.query else {},
                "is_same_domain": self._is_same_domain(url),
                "is_excluded": self._is_excluded_extension(url) or self._matches_exclude_pattern(url),
                "is_visited": self.is_visited(url)
            }
            
        except Exception:
            return {"url": url, "error": "解析失败"}
