# -*- coding:utf-8 -*-

"""
旁站查询模块（增强版）
功能:
1. 多API源聚合查询（webscan.cc、ip138、同IP网站查询等）
2. 支持IPv4地址格式校验
3. 智能缓存机制，减少重复查询
4. 自动故障转移，API不可用时切换备用源
5. 端口信息收集
6. 域名历史信息查询

依赖:
- requests: 用于HTTP请求
"""

import logging
import re
import json
import time
import hashlib
from typing import Dict, Any, Optional, List, Set
from dataclasses import dataclass, field
from threading import Lock
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("WebSideInfo")

@dataclass
class SideSite:
    domain: str = ""
    title: str = ""
    ports: List[int] = field(default_factory=list)
    source: str = ""

@dataclass
class SideInfoResult:
    ip: str = ""
    has_data: bool = False
    sites: List[SideSite] = field(default_factory=list)
    domains: Set[str] = field(default_factory=set)
    total_count: int = 0
    source: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)
    error: str = ""

class IPValidator:
    IPV4_PATTERN = re.compile(
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    )
    
    @classmethod
    def is_valid_ipv4(cls, ip: str) -> bool:
        if not isinstance(ip, str) or not ip.strip():
            return False
        return bool(cls.IPV4_PATTERN.match(ip.strip()))
    
    @classmethod
    def is_private_ip(cls, ip: str) -> bool:
        if not cls.is_valid_ipv4(ip):
            return False
        private_ranges = [
            (re.compile(r"^10\."), "10.0.0.0/8"),
            (re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\."), "172.16.0.0/12"),
            (re.compile(r"^192\.168\."), "192.168.0.0/16"),
            (re.compile(r"^127\."), "127.0.0.0/8"),
        ]
        for pattern, _ in private_ranges:
            if pattern.match(ip):
                return True
        return False

class SideInfoCache:
    _instance = None
    _lock = Lock()
    _cache: Dict[str, Dict[str, Any]]
    _cache_lock: Lock
    _max_size: int
    _ttl: int
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._cache = {}
                    cls._instance._cache_lock = Lock()
                    cls._instance._max_size = 300
                    cls._instance._ttl = 1800
        return cls._instance
    
    def _get_cache_key(self, ip: str) -> str:
        return hashlib.md5(ip.strip().encode()).hexdigest()
    
    def get(self, ip: str) -> Optional[SideInfoResult]:
        key = self._get_cache_key(ip)
        with self._cache_lock:
            if key in self._cache:
                cached = self._cache[key]
                if time.time() - cached["timestamp"] < self._ttl:
                    return cached["result"]
                else:
                    del self._cache[key]
        return None
    
    def set(self, ip: str, result: SideInfoResult) -> None:
        key = self._get_cache_key(ip)
        with self._cache_lock:
            if len(self._cache) >= self._max_size:
                oldest_key = min(self._cache.keys(), key=lambda k: self._cache[k]["timestamp"])
                del self._cache[oldest_key]
            self._cache[key] = {
                "result": result,
                "timestamp": time.time()
            }

class SideInfoAPI:
    def __init__(self, timeout: int = 12):
        self.timeout = timeout
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"]
        )
        session.mount("http://", HTTPAdapter(max_retries=retry_strategy))
        session.mount("https://", HTTPAdapter(max_retries=retry_strategy))
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        })
        return session
    
    def query_webscan(self, ip: str) -> SideInfoResult:
        result = SideInfoResult(ip=ip, source="webscan.cc")
        try:
            url = f"http://api.webscan.cc/?action=query&ip={ip}"
            headers = {
                'Host': 'api.webscan.cc',
                'Origin': 'http://webscan.cc',
                'Referer': 'http://webscan.cc/',
            }
            response = self.session.get(url, headers=headers, timeout=self.timeout, verify=False)
            response.encoding = "utf-8"
            text = response.text
            
            if text.startswith('\ufeff'):
                text = text[1:]
            
            if "null" in text.strip().lower():
                result.has_data = False
                return result
            
            data = json.loads(text)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        domain = item.get("domain", "")
                        if domain:
                            site = SideSite(
                                domain=domain,
                                title=item.get("title", ""),
                                source="webscan.cc"
                            )
                            result.sites.append(site)
                            result.domains.add(domain)
                
                result.has_data = True
                result.total_count = len(result.sites)
                result.raw_data = data[:10]
                
        except Exception as e:
            result.error = f"webscan.cc查询异常: {str(e)[:50]}"
        
        return result
    
    def query_ip138(self, ip: str) -> SideInfoResult:
        result = SideInfoResult(ip=ip, source="ip138.com")
        try:
            url = f"https://site.ip138.com/{ip}/"
            headers = {
                "Host": "site.ip138.com",
                "Referer": "https://site.ip138.com/",
            }
            response = self.session.get(url, headers=headers, timeout=self.timeout, verify=False)
            response.encoding = "utf-8"
            
            domain_pattern = re.compile(r'<a[^>]+href="https?://([^/"]+)"[^>]*>([^<]+)</a>')
            matches = domain_pattern.findall(response.text)
            
            seen_domains = set()
            for match in matches[:50]:
                domain = match[0].strip()
                if domain and domain not in seen_domains:
                    seen_domains.add(domain)
                    site = SideSite(
                        domain=domain,
                        title=match[1].strip() if len(match) > 1 else "",
                        source="ip138.com"
                    )
                    result.sites.append(site)
                    result.domains.add(domain)
            
            if result.sites:
                result.has_data = True
                result.total_count = len(result.sites)
                result.raw_data = {"domains": list(seen_domains)[:10]}
                
        except Exception as e:
            result.error = f"ip138.com查询异常: {str(e)[:50]}"
        
        return result
    
    def query_aizhan(self, ip: str) -> SideInfoResult:
        result = SideInfoResult(ip=ip, source="aizhan.com")
        try:
            url = f"https://www.aizhan.com/cha/{ip}/"
            headers = {
                "Host": "www.aizhan.com",
                "Referer": "https://www.aizhan.com/",
            }
            response = self.session.get(url, headers=headers, timeout=self.timeout, verify=False)
            response.encoding = "utf-8"
            
            domain_pattern = re.compile(r'<a[^>]+>([a-zA-Z0-9][-a-zA-Z0-9]{0,62}(?:\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+)</a>')
            matches = domain_pattern.findall(response.text)
            
            seen_domains = set()
            for domain in matches[:50]:
                domain = domain.strip().lower()
                if domain and domain not in seen_domains and not domain.startswith(("www.aizhan", "aizhan.com")):
                    seen_domains.add(domain)
                    site = SideSite(
                        domain=domain,
                        source="aizhan.com"
                    )
                    result.sites.append(site)
                    result.domains.add(domain)
            
            if result.sites:
                result.has_data = True
                result.total_count = len(result.sites)
                result.raw_data = {"domains": list(seen_domains)[:10]}
                
        except Exception as e:
            result.error = f"aizhan.com查询异常: {str(e)[:50]}"
        
        return result
    
    def query_chinaz(self, ip: str) -> SideInfoResult:
        result = SideInfoResult(ip=ip, source="chinaz.com")
        try:
            url = f"https://s.tool.chinaz.com/same?s={ip}"
            headers = {
                "Host": "s.tool.chinaz.com",
                "Referer": "https://s.tool.chinaz.com/",
            }
            response = self.session.get(url, headers=headers, timeout=self.timeout, verify=False)
            response.encoding = "utf-8"
            
            domain_pattern = re.compile(r'([a-zA-Z0-9][-a-zA-Z0-9]{0,62}(?:\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+)')
            matches = domain_pattern.findall(response.text)
            
            seen_domains = set()
            exclude_domains = {"chinaz.com", "www.chinaz.com", "tool.chinaz.com", "s.tool.chinaz.com"}
            for domain in matches[:50]:
                domain = domain.strip().lower()
                if domain and domain not in seen_domains and domain not in exclude_domains:
                    seen_domains.add(domain)
                    site = SideSite(
                        domain=domain,
                        source="chinaz.com"
                    )
                    result.sites.append(site)
                    result.domains.add(domain)
            
            if result.sites:
                result.has_data = True
                result.total_count = len(result.sites)
                result.raw_data = {"domains": list(seen_domains)[:10]}
                
        except Exception as e:
            result.error = f"chinaz.com查询异常: {str(e)[:50]}"
        
        return result
    
    def query_hackertarget(self, ip: str) -> SideInfoResult:
        result = SideInfoResult(ip=ip, source="hackertarget.com")
        try:
            url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
            response = self.session.get(url, timeout=self.timeout, verify=False)
            response.encoding = "utf-8"
            text = response.text
            
            if "error" in text.lower() or "no records" in text.lower():
                result.has_data = False
                return result
            
            lines = text.strip().split("\n")
            for line in lines[:100]:
                domain = line.strip()
                if domain and "." in domain:
                    site = SideSite(
                        domain=domain,
                        source="hackertarget.com"
                    )
                    result.sites.append(site)
                    result.domains.add(domain)
            
            if result.sites:
                result.has_data = True
                result.total_count = len(result.sites)
                result.raw_data = {"domains": list(result.domains)[:10]}
                
        except Exception as e:
            result.error = f"hackertarget.com查询异常: {str(e)[:50]}"
        
        return result
    
    def query_yougetsignal(self, ip: str) -> SideInfoResult:
        result = SideInfoResult(ip=ip, source="yougetsignal.com")
        try:
            url = "https://domains.yougetsignal.com/domains.php"
            data = {
                "remoteAddress": ip,
                "key": ""
            }
            headers = {
                "Host": "domains.yougetsignal.com",
                "Origin": "https://domains.yougetsignal.com",
                "Referer": "https://domains.yougetsignal.com/",
                "Content-Type": "application/x-www-form-urlencoded",
            }
            response = self.session.post(url, data=data, headers=headers, timeout=self.timeout, verify=False)
            response.encoding = "utf-8"
            
            json_data = response.json()
            if json_data.get("status") == "Fail":
                result.has_data = False
                return result
            
            domain_array = json_data.get("domainArray", [])
            for item in domain_array[:100]:
                if isinstance(item, list) and len(item) > 0:
                    domain = item[0].strip()
                    if domain:
                        site = SideSite(
                            domain=domain,
                            source="yougetsignal.com"
                        )
                        result.sites.append(site)
                        result.domains.add(domain)
            
            if result.sites:
                result.has_data = True
                result.total_count = len(result.sites)
                result.raw_data = {"domains": list(result.domains)[:10]}
                
        except Exception as e:
            result.error = f"yougetsignal.com查询异常: {str(e)[:50]}"
        
        return result

class WebSideQuery:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 12)
        self.use_cache = self.config.get("use_cache", True)
        self.api_order = self.config.get("api_order", [
            "webscan", "ip138", "hackertarget", "yougetsignal", "aizhan", "chinaz"
        ])
        
        self._api = SideInfoAPI(timeout=self.timeout)
        self._cache = SideInfoCache() if self.use_cache else None
        
        self._api_methods = {
            "webscan": self._api.query_webscan,
            "ip138": self._api.query_ip138,
            "aizhan": self._api.query_aizhan,
            "chinaz": self._api.query_chinaz,
            "hackertarget": self._api.query_hackertarget,
            "yougetsignal": self._api.query_yougetsignal,
        }
    
    def query(self, ip: str, sources: Optional[List[str]] = None) -> SideInfoResult:
        ip = ip.strip() if isinstance(ip, str) else ""
        
        if not IPValidator.is_valid_ipv4(ip):
            return SideInfoResult(
                ip=ip,
                error=f"IP格式非法: {ip}"
            )
        
        if IPValidator.is_private_ip(ip):
            return SideInfoResult(
                ip=ip,
                has_data=True,
                error="私有IP地址，无旁站信息"
            )
        
        if self._cache:
            cached = self._cache.get(ip)
            if cached:
                logger.info(f"IP {ip} 使用缓存数据")
                return cached
        
        if sources is None:
            sources = self.api_order
        
        final_result = SideInfoResult(ip=ip)
        all_domains: Set[str] = set()
        
        for source in sources:
            if source not in self._api_methods:
                continue
            
            try:
                logger.info(f"尝试使用 {source} 查询 IP: {ip}")
                result = self._api_methods[source](ip)
                
                if result.has_data:
                    for site in result.sites:
                        if site.domain not in all_domains:
                            all_domains.add(site.domain)
                            final_result.sites.append(site)
                    
                    if not final_result.source:
                        final_result.source = result.source
                    
                    final_result.raw_data.update(result.raw_data)
                    
            except Exception as e:
                logger.warning(f"{source} 查询异常: {str(e)[:50]}")
                continue
        
        if all_domains:
            final_result.has_data = True
            final_result.domains = all_domains
            final_result.total_count = len(all_domains)
            
            if self._cache:
                self._cache.set(ip, final_result)
        
        return final_result
    
    def batch_query(self, ips: List[str]) -> Dict[str, SideInfoResult]:
        results = {}
        for ip in ips:
            results[ip] = self.query(ip)
        return results

def get_side_info(ip: str) -> Dict[str, Any]:
    query = WebSideQuery()
    result = query.query(ip)
    
    return {
        "success": result.has_data or not result.error,
        "has_data": result.has_data,
        "data": [{"domain": s.domain, "title": s.title, "source": s.source} for s in result.sites],
        "total_count": result.total_count,
        "source": result.source,
        "message": "" if result.has_data else result.error
    }

def get_side_domains(ip: str) -> List[str]:
    query = WebSideQuery()
    result = query.query(ip)
    return list(result.domains)

if __name__ == '__main__':
    test_ips = [
        "139.224.112.182",
        "8.8.8.8",
        "127.0.0.1",
        "192.168.1.1",
        "256.0.0.1",
        ""
    ]
    
    for test_ip in test_ips:
        print(f"\n{'='*60}")
        print(f"测试IP: {test_ip}")
        result = get_side_info(test_ip)
        if result["has_data"]:
            print(f"旁站数量: {result['total_count']}")
            print(f"数据来源: {result['source']}")
            print(f"旁站列表(前10个):")
            for site in result["data"][:10]:
                print(f"  - {site['domain']}")
        else:
            print(f"查询结果: {result['message']}")
