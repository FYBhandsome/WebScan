# -*- coding:utf-8 -*-
"""
HTML解析器

功能：
1. 提取链接
2. 提取脚本
3. 提取注释
4. 提取参数
"""

import re
import urllib.parse
from typing import List, Dict, Set
from bs4 import BeautifulSoup, Comment

try:
    from .config import CRAWLER_CONFIG
except ImportError:
    from config import CRAWLER_CONFIG


class HTMLParser:
    """
    HTML解析器
    
    提取内容：
    - 链接：<a>, <link>, <area>, <iframe>, <frame>
    - 表单：<form>
    - 脚本：<script>
    - 图片：<img>
    - 注释中的敏感信息
    """
    
    def __init__(self, config: Dict = None):
        self.config = {**CRAWLER_CONFIG, **(config or {})}
        
        self.link_tags = {
            'a': 'href',
            'link': 'href',
            'area': 'href',
            'iframe': 'src',
            'frame': 'src',
            'embed': 'src',
            'source': 'src',
        }
        
        self.script_tags = ['script']
        self.style_tags = ['style', 'link']
    
    def extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """
        提取页面中的所有链接
        
        Args:
            soup: BeautifulSoup对象
            base_url: 基础URL用于解析相对路径
            
        Returns:
            List[str]: 链接列表
        """
        links = set()
        
        for tag_name, attr_name in self.link_tags.items():
            for tag in soup.find_all(tag_name):
                href = tag.get(attr_name)
                if href:
                    normalized = self._normalize_url(href, base_url)
                    if normalized:
                        links.add(normalized)
        
        for tag in soup.find_all(attrs={"onclick": True}):
            onclick = tag.get("onclick", "")
            js_links = self._extract_js_links(onclick, base_url)
            links.update(js_links)
        
        for tag in soup.find_all('form'):
            action = tag.get('action')
            if action:
                normalized = self._normalize_url(action, base_url)
                if normalized:
                    links.add(normalized)
        
        return list(links)
    
    def extract_scripts(self, soup: BeautifulSoup) -> List[str]:
        """
        提取页面中的脚本
        
        Args:
            soup: BeautifulSoup对象
            
        Returns:
            List[str]: 脚本URL列表
        """
        scripts = []
        
        for tag in soup.find_all('script'):
            src = tag.get('src')
            if src:
                scripts.append(src)
            
            content = tag.string
            if content and len(content) > 50:
                if self.config.get("extract_scripts"):
                    scripts.append({
                        "type": "inline",
                        "content": content[:500],
                        "has_ajax": "ajax" in content.lower() or "fetch" in content.lower() or "xhr" in content.lower(),
                        "has_eval": "eval" in content.lower(),
                        "has_document_write": "document.write" in content.lower()
                    })
        
        return scripts
    
    def extract_comments(self, html: str) -> List[str]:
        """
        提取HTML注释
        
        Args:
            html: HTML字符串
            
        Returns:
            List[str]: 注释列表
        """
        comments = []
        
        soup = BeautifulSoup(html, "html.parser")
        
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            comment_text = comment.strip()
            if comment_text and len(comment_text) > 3:
                comments.append(comment_text)
        
        html_comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
        for comment in html_comments:
            comment_text = comment.strip()
            if comment_text and comment_text not in comments:
                comments.append(comment_text)
        
        return comments
    
    def extract_params(self, url: str) -> Dict[str, str]:
        """
        提取URL参数
        
        Args:
            url: URL字符串
            
        Returns:
            Dict[str, str]: 参数字典
        """
        params = {}
        
        try:
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query)
            
            for key, values in query_params.items():
                params[key] = values[0] if values else ""
                
        except Exception:
            pass
        
        return params
    
    def extract_meta_info(self, soup: BeautifulSoup) -> Dict[str, str]:
        """
        提取meta标签信息
        
        Args:
            soup: BeautifulSoup对象
            
        Returns:
            Dict[str, str]: meta信息
        """
        meta_info = {}
        
        for tag in soup.find_all('meta'):
            name = tag.get('name') or tag.get('property') or tag.get('http-equiv')
            content = tag.get('content')
            
            if name and content:
                meta_info[name] = content
        
        return meta_info
    
    def extract_base_url(self, soup: BeautifulSoup, original_url: str) -> str:
        """
        提取base标签中的URL
        
        Args:
            soup: BeautifulSoup对象
            original_url: 原始URL
            
        Returns:
            str: base URL
        """
        base_tag = soup.find('base')
        if base_tag:
            href = base_tag.get('href')
            if href:
                return self._normalize_url(href, original_url)
        
        return original_url
    
    def _normalize_url(self, url: str, base_url: str) -> str:
        """
        标准化URL
        
        Args:
            url: 原始URL
            base_url: 基础URL
            
        Returns:
            str: 标准化后的URL
        """
        if not url:
            return ""
        
        url = url.strip()
        
        if url.startswith(('javascript:', 'mailto:', 'tel:', 'data:', '#')):
            return ""
        
        if url.startswith('//'):
            parsed = urllib.parse.urlparse(base_url)
            url = f"{parsed.scheme}:{url}"
        elif url.startswith('/'):
            parsed = urllib.parse.urlparse(base_url)
            url = f"{parsed.scheme}://{parsed.netloc}{url}"
        elif not url.startswith(('http://', 'https://')):
            url = urllib.parse.urljoin(base_url, url)
        
        try:
            parsed = urllib.parse.urlparse(url)
            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                url += f"?{parsed.query}"
            if parsed.fragment and self.config.get("include_fragments"):
                url += f"#{parsed.fragment}"
        except Exception:
            return ""
        
        return url
    
    def _extract_js_links(self, js_code: str, base_url: str) -> Set[str]:
        """
        从JavaScript代码中提取链接
        
        Args:
            js_code: JavaScript代码
            base_url: 基础URL
            
        Returns:
            Set[str]: 链接集合
        """
        links = set()
        
        url_patterns = [
            r'["\']([^"\\\'\s]+\.(?:php|asp|aspx|jsp|html?|json|xml))["\']',
            r'["\']([^"\\\'\s]+/[^"\\\'\s]*)["\']',
            r'location\.href\s*=\s*["\']([^"\']+)["\']',
            r'window\.location\s*=\s*["\']([^"\']+)["\']',
            r'window\.open\s*\(\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in url_patterns:
            matches = re.findall(pattern, js_code, re.IGNORECASE)
            for match in matches:
                normalized = self._normalize_url(match, base_url)
                if normalized:
                    links.add(normalized)
        
        return links
    
    def extract_api_endpoints(self, soup: BeautifulSoup, html: str) -> List[Dict]:
        """
        提取API端点信息
        
        Args:
            soup: BeautifulSoup对象
            html: HTML字符串
            
        Returns:
            List[Dict]: API端点列表
        """
        endpoints = []
        
        ajax_patterns = [
            r'\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
            r'\$\.get\s*\(\s*["\']([^"\']+)["\']',
            r'\$\.post\s*\(\s*["\']([^"\']+)["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in ajax_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                endpoints.append({
                    "url": match,
                    "type": "ajax",
                    "method": "GET" if "get" in pattern.lower() else "POST" if "post" in pattern.lower() else "UNKNOWN"
                })
        
        return endpoints
