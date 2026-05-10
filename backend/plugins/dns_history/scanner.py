# -*- coding:utf-8 -*-

"""
被动DNS历史查询模块
功能:
1. 历史DNS记录查询
2. 域名历史IP记录
3. 子域名历史记录
4. DNS变更历史
5. 多数据源聚合
6. 结果缓存
"""

import logging
import re
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
logger = logging.getLogger("DNSHistory")

@dataclass
class DNSHistoryRecord:
    domain: str = ""
    record_type: str = ""
    value: str = ""
    first_seen: str = ""
    last_seen: str = ""
    source: str = ""

@dataclass
class DNSHistoryResult:
    query: str = ""
    records: List[DNSHistoryRecord] = field(default_factory=list)
    historical_ips: List[str] = field(default_factory=list)
    historical_domains: Set[str] = field(default_factory=set)
    total_records: int = 0
    has_result: bool = False
    source: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)
    error: str = ""

class DNSHistoryCache:
    _instance = None
    _lock = Lock()
    _cache: Dict[str, Dict[str, Any]] = {}
    _cache_lock = Lock()
    _max_size: int = 300
    _ttl: int = 3600
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def _get_cache_key(self, query: str) -> str:
        return hashlib.md5(query.strip().lower().encode()).hexdigest()
    
    def get(self, query: str) -> Optional[DNSHistoryResult]:
        key = self._get_cache_key(query)
        with self._cache_lock:
            if key in self._cache:
                cached = self._cache[key]
                if time.time() - cached["timestamp"] < self._ttl:
                    return cached["result"]
                else:
                    del self._cache[key]
        return None
    
    def set(self, query: str, result: DNSHistoryResult) -> None:
        key = self._get_cache_key(query)
        with self._cache_lock:
            if len(self._cache) >= self._max_size:
                oldest_key = min(self._cache.keys(), key=lambda k: self._cache[k]["timestamp"])
                del self._cache[oldest_key]
            self._cache[key] = {
                "result": result,
                "timestamp": time.time()
            }

class DNSHistoryAPI:
    def __init__(self, timeout: int = 15):
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
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json",
        })
        return session
    
    def query_securitytrails(self, domain: str, api_key: str = "") -> DNSHistoryResult:
        result = DNSHistoryResult(query=domain, source="securitytrails.com")
        
        try:
            if api_key:
                url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
                headers = {"APIKEY": api_key}
                response = self.session.get(url, headers=headers, timeout=self.timeout)
            else:
                url = f"https://securitytrails.com/domain/{domain}/history"
                response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                if api_key:
                    data = response.json()
                    for record in data.get("records", []):
                        for ip in record.get("values", []):
                            result.records.append(DNSHistoryRecord(
                                domain=domain,
                                record_type="A",
                                value=ip.get("ip", ""),
                                first_seen=record.get("first_seen", ""),
                                last_seen=record.get("last_seen", ""),
                                source="securitytrails"
                            ))
                            result.historical_ips.append(ip.get("ip", ""))
                else:
                    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
                    ips = ip_pattern.findall(response.text)
                    for ip in set(ips):
                        result.records.append(DNSHistoryRecord(
                            domain=domain,
                            record_type="A",
                            value=ip,
                            source="securitytrails"
                        ))
                        result.historical_ips.append(ip)
                
                result.has_result = bool(result.records)
                result.total_records = len(result.records)
                
        except Exception as e:
            result.error = f"SecurityTrails查询异常: {str(e)[:50]}"
        
        return result
    
    def query_viewdns(self, domain: str) -> DNSHistoryResult:
        result = DNSHistoryResult(query=domain, source="viewdns.info")
        
        try:
            url = f"https://viewdns.info/iphistory/?domain={domain}"
            response = self.session.get(url, timeout=self.timeout)
            response.encoding = "utf-8"
            
            row_pattern = re.compile(r'<tr[^>]*>.*?<td[^>]*>([\d.]+)</td>.*?<td[^>]*>([^<]+)</td>.*?<td[^>]*>([^<]+)</td>.*?</tr>', re.DOTALL)
            matches = row_pattern.findall(response.text)
            
            for match in matches:
                ip = match[0].strip()
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                    result.records.append(DNSHistoryRecord(
                        domain=domain,
                        record_type="A",
                        value=ip,
                        first_seen=match[1].strip(),
                        last_seen=match[2].strip(),
                        source="viewdns"
                    ))
                    result.historical_ips.append(ip)
            
            result.has_result = bool(result.records)
            result.total_records = len(result.records)
            
        except Exception as e:
            result.error = f"ViewDNS查询异常: {str(e)[:50]}"
        
        return result
    
    def query_dnslytics(self, domain: str) -> DNSHistoryResult:
        result = DNSHistoryResult(query=domain, source="dnslytics.com")
        
        try:
            url = f"https://dnslytics.com/domain/{domain}"
            response = self.session.get(url, timeout=self.timeout)
            response.encoding = "utf-8"
            
            ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
            ips = set(ip_pattern.findall(response.text))
            
            for ip in ips:
                result.records.append(DNSHistoryRecord(
                    domain=domain,
                    record_type="A",
                    value=ip,
                    source="dnslytics"
                ))
                result.historical_ips.append(ip)
            
            result.has_result = bool(result.records)
            result.total_records = len(result.records)
            
        except Exception as e:
            result.error = f"DNSlytics查询异常: {str(e)[:50]}"
        
        return result
    
    def query_netcraft(self, domain: str) -> DNSHistoryResult:
        result = DNSHistoryResult(query=domain, source="netcraft.com")
        
        try:
            url = f"https://sitereport.netcraft.com/?url={domain}"
            response = self.session.get(url, timeout=self.timeout)
            response.encoding = "utf-8"
            
            ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
            ips = set(ip_pattern.findall(response.text))
            
            for ip in ips:
                result.records.append(DNSHistoryRecord(
                    domain=domain,
                    record_type="A",
                    value=ip,
                    source="netcraft"
                ))
                result.historical_ips.append(ip)
            
            result.has_result = bool(result.records)
            result.total_records = len(result.records)
            
        except Exception as e:
            result.error = f"Netcraft查询异常: {str(e)[:50]}"
        
        return result
    
    def query_hackertarget(self, domain: str) -> DNSHistoryResult:
        result = DNSHistoryResult(query=domain, source="hackertarget.com")
        
        try:
            url = f"https://api.hackertarget.com/dnshistory/?q={domain}"
            response = self.session.get(url, timeout=self.timeout)
            
            if "error" not in response.text.lower():
                lines = response.text.strip().split("\n")
                for line in lines[1:]:
                    parts = line.split(",")
                    if len(parts) >= 3:
                        result.records.append(DNSHistoryRecord(
                            domain=domain,
                            record_type=parts[0].strip(),
                            value=parts[1].strip(),
                            last_seen=parts[2].strip() if len(parts) > 2 else "",
                            source="hackertarget"
                        ))
                        if parts[0].strip() == "A":
                            result.historical_ips.append(parts[1].strip())
            
            result.has_result = bool(result.records)
            result.total_records = len(result.records)
            
        except Exception as e:
            result.error = f"HackerTarget查询异常: {str(e)[:50]}"
        
        return result

class DNSHistoryQuery:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 15)
        self.use_cache = self.config.get("use_cache", True)
        self.securitytrails_key = self.config.get("securitytrails_key", "")
        
        self._api = DNSHistoryAPI(timeout=self.timeout)
        self._cache = DNSHistoryCache() if self.use_cache else None
    
    def query(self, domain: str) -> DNSHistoryResult:
        domain = domain.strip().lower()
        if domain.startswith(("http://", "https://")):
            domain = domain.split("//")[-1].split("/")[0]
        
        if self._cache:
            cached = self._cache.get(domain)
            if cached:
                return cached
        
        final_result = DNSHistoryResult(query=domain)
        all_ips: Set[str] = set()
        
        apis = [
            ("viewdns", self._api.query_viewdns),
            ("hackertarget", self._api.query_hackertarget),
            ("dnslytics", self._api.query_dnslytics),
            ("netcraft", self._api.query_netcraft),
        ]
        
        if self.securitytrails_key:
            apis.insert(0, ("securitytrails", lambda d: self._api.query_securitytrails(d, self.securitytrails_key)))
        
        for api_name, api_func in apis:
            try:
                logger.info(f"尝试使用 {api_name} 查询DNS历史: {domain}")
                result = api_func(domain)
                
                if result.has_result:
                    for record in result.records:
                        if record.value not in all_ips:
                            all_ips.add(record.value)
                            final_result.records.append(record)
                    
                    if not final_result.source:
                        final_result.source = result.source
                    
            except Exception as e:
                logger.warning(f"{api_name} 查询异常: {str(e)[:50]}")
                continue
        
        if all_ips:
            final_result.has_result = True
            final_result.historical_ips = list(all_ips)
            final_result.total_records = len(final_result.records)
            
            if self._cache:
                self._cache.set(domain, final_result)
        
        return final_result

def query_dns_history(domain: str) -> Dict[str, Any]:
    query = DNSHistoryQuery()
    result = query.query(domain)
    
    return {
        "success": result.has_result,
        "query": result.query,
        "historical_ips": result.historical_ips,
        "total_records": result.total_records,
        "source": result.source,
        "records": [
            {
                "domain": r.domain,
                "record_type": r.record_type,
                "value": r.value,
                "first_seen": r.first_seen,
                "last_seen": r.last_seen,
                "source": r.source
            }
            for r in result.records[:20]
        ],
        "error": result.error
    }

if __name__ == '__main__':
    test_domains = ["github.com", "google.com", "baidu.com"]
    for domain in test_domains:
        print(f"\n{'='*60}")
        print(f"查询域名: {domain}")
        result = query_dns_history(domain)
        if result["success"]:
            print(f"历史IP数量: {len(result['historical_ips'])}")
            print(f"历史IP列表:")
            for ip in result['historical_ips'][:10]:
                print(f"  - {ip}")
        else:
            print(f"错误: {result['error']}")
