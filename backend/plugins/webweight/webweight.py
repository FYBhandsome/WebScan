# -*- coding:utf-8 -*-

"""
网站权重查询模块（增强版）
功能:
1. 多平台权重聚合查询（爱站、站长之家、5118等）
2. 百度/搜狗/360权重查询
3. 百度收录/索引量查询
4. 预估流量查询
5. 智能缓存机制，减少重复查询
6. 自动故障转移

依赖:
- requests: 用于HTTP请求
"""

import os
import logging
import json
import re
import time
import hashlib
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from threading import Lock
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("WebWeight")

@dataclass
class WeightResult:
    domain: str = ""
    baidu_pc_weight: int = 0
    baidu_mobile_weight: int = 0
    baidu收录: int = 0
    baidu_index: int = 0
    sogou_weight: int = 0
    sogou_index: int = 0
    weight_360: int = 0
    index_360: int = 0
    estimated_traffic: int = 0
    source: str = ""
    has_result: bool = False
    raw_data: Dict[str, Any] = field(default_factory=dict)
    error: str = ""

class DomainValidator:
    DOMAIN_PATTERN = re.compile(
        r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$'
    )
    
    @classmethod
    def extract_domain(cls, url: str) -> str:
        if not isinstance(url, str) or not url.strip():
            return ""
        domain = url.strip()
        if domain.startswith(("http://", "https://")):
            domain = domain.split("//")[-1]
        domain = domain.split("/")[0].split(":")[0]
        domain = domain.lower()
        if domain.startswith("www."):
            domain = domain[4:]
        return domain
    
    @classmethod
    def is_valid_domain(cls, domain: str) -> bool:
        if not domain or "." not in domain:
            return False
        return bool(cls.DOMAIN_PATTERN.match(domain))

class WeightCache:
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
                    cls._instance._max_size = 500
                    cls._instance._ttl = 7200
        return cls._instance
    
    def _get_cache_key(self, domain: str) -> str:
        return hashlib.md5(domain.strip().lower().encode()).hexdigest()
    
    def get(self, domain: str) -> Optional[WeightResult]:
        key = self._get_cache_key(domain)
        with self._cache_lock:
            if key in self._cache:
                cached = self._cache[key]
                if time.time() - cached["timestamp"] < self._ttl:
                    return cached["result"]
                else:
                    del self._cache[key]
        return None
    
    def set(self, domain: str, result: WeightResult) -> None:
        key = self._get_cache_key(domain)
        with self._cache_lock:
            if len(self._cache) >= self._max_size:
                oldest_key = min(self._cache.keys(), key=lambda k: self._cache[k]["timestamp"])
                del self._cache[oldest_key]
            self._cache[key] = {
                "result": result,
                "timestamp": time.time()
            }

class WeightAPI:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )
        session.mount("http://", HTTPAdapter(max_retries=retry_strategy))
        session.mount("https://", HTTPAdapter(max_retries=retry_strategy))
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        })
        return session
    
    def query_aizhan(self, domain: str, api_key: str = "") -> WeightResult:
        result = WeightResult(domain=domain, source="aizhan.com")
        try:
            if api_key:
                url = f"https://apistore.aizhan.com/baidurank/siteinfos/{api_key}?domains={domain}"
            else:
                url = f"https://www.aizhan.com/cha/{domain}/"
            
            response = self.session.get(url, timeout=self.timeout, verify=False)
            response.encoding = "utf-8"
            
            if api_key:
                data = response.json()
                success_list = data.get("data", {}).get("success", [])
                if success_list:
                    weight_data = success_list[0]
                    result.baidu_pc_weight = int(weight_data.get("pc_br", 0) or 0)
                    result.baidu_mobile_weight = int(weight_data.get("m_br", 0) or 0)
                    result.estimated_traffic = int(weight_data.get("ip", 0) or 0)
                    result.has_result = True
                    result.raw_data = weight_data
            else:
                pc_match = re.search(r'百度权重[：:]\s*(\d+)', response.text)
                mobile_match = re.search(r'移动权重[：:]\s*(\d+)', response.text)
                traffic_match = re.search(r'预估流量[：:]\s*([\d,]+)', response.text)
                
                if pc_match:
                    result.baidu_pc_weight = int(pc_match.group(1))
                if mobile_match:
                    result.baidu_mobile_weight = int(mobile_match.group(1))
                if traffic_match:
                    result.estimated_traffic = int(traffic_match.group(1).replace(",", ""))
                
                if pc_match or mobile_match:
                    result.has_result = True
                    result.raw_data = {"html": response.text[:500]}
                    
        except Exception as e:
            result.error = f"爱站查询异常: {str(e)[:50]}"
        
        return result
    
    def query_chinaz(self, domain: str) -> WeightResult:
        result = WeightResult(domain=domain, source="chinaz.com")
        try:
            url = f"https://mtool.chinaz.com/baidurank?host={domain}"
            response = self.session.get(url, timeout=self.timeout, verify=False)
            response.encoding = "utf-8"
            
            br_match = re.search(r'百度权重[：:]\s*(\d+)', response.text)
            mobile_match = re.search(r'移动权重[：:]\s*(\d+)', response.text)
            index_match = re.search(r'收录[：:]\s*([\d,]+)', response.text)
            
            if br_match:
                result.baidu_pc_weight = int(br_match.group(1))
            if mobile_match:
                result.baidu_mobile_weight = int(mobile_match.group(1))
            if index_match:
                result.baidu收录 = int(index_match.group(1).replace(",", ""))
            
            if br_match or mobile_match or index_match:
                result.has_result = True
                result.raw_data = {"html": response.text[:500]}
                
        except Exception as e:
            result.error = f"站长之家查询异常: {str(e)[:50]}"
        
        return result
    
    def query_sitebaidu(self, domain: str) -> WeightResult:
        result = WeightResult(domain=domain, source="site.baidu.com")
        try:
            url = f"https://www.baidu.com/s?wd=site:{domain}"
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
            response = self.session.get(url, headers=headers, timeout=self.timeout, verify=False)
            response.encoding = "utf-8"
            
            index_match = re.search(r'找到相关结果[约]?([\d,]+)个', response.text)
            if not index_match:
                index_match = re.search(r'该网站共有\s*([\d,]+)\s*个页面被百度收录', response.text)
            
            if index_match:
                result.baidu收录 = int(index_match.group(1).replace(",", ""))
                result.has_result = True
                result.raw_data = {"index": result.baidu收录}
            else:
                no_result = re.search(r'没有找到|未找到', response.text)
                if no_result:
                    result.baidu收录 = 0
                    result.has_result = True
                    
        except Exception as e:
            result.error = f"百度收录查询异常: {str(e)[:50]}"
        
        return result
    
    def query_sogou(self, domain: str) -> WeightResult:
        result = WeightResult(domain=domain, source="sogou.com")
        try:
            url = f"https://www.sogou.com/web?query=site:{domain}"
            response = self.session.get(url, timeout=self.timeout, verify=False)
            response.encoding = "utf-8"
            
            index_match = re.search(r'找到\s*([\d,]+)\s*个结果', response.text)
            if index_match:
                result.sogou_index = int(index_match.group(1).replace(",", ""))
                result.has_result = True
                result.raw_data = {"sogou_index": result.sogou_index}
                    
        except Exception as e:
            result.error = f"搜狗收录查询异常: {str(e)[:50]}"
        
        return result
    
    def query_360(self, domain: str) -> WeightResult:
        result = WeightResult(domain=domain, source="so.com")
        try:
            url = f"https://www.so.com/s?q=site:{domain}"
            response = self.session.get(url, timeout=self.timeout, verify=False)
            response.encoding = "utf-8"
            
            index_match = re.search(r'找到相关结果[约]?\s*([\d,]+)\s*个', response.text)
            if index_match:
                result.index_360 = int(index_match.group(1).replace(",", ""))
                result.has_result = True
                result.raw_data = {"360_index": result.index_360}
                    
        except Exception as e:
            result.error = f"360收录查询异常: {str(e)[:50]}"
        
        return result
    
    def query_bing(self, domain: str) -> WeightResult:
        result = WeightResult(domain=domain, source="bing.com")
        try:
            url = f"https://www.bing.com/search?q=site:{domain}"
            response = self.session.get(url, timeout=self.timeout, verify=False)
            response.encoding = "utf-8"
            
            index_match = re.search(r'([\d,]+)\s*条结果', response.text)
            if index_match:
                result.raw_data = {"bing_index": int(index_match.group(1).replace(",", ""))}
                result.has_result = True
                    
        except Exception as e:
            result.error = f"Bing收录查询异常: {str(e)[:50]}"
        
        return result
    
    def query_alexa(self, domain: str) -> WeightResult:
        result = WeightResult(domain=domain, source="alexa.com")
        try:
            url = f"https://www.alexa.com/siteinfo/{domain}"
            response = self.session.get(url, timeout=self.timeout, verify=False)
            response.encoding = "utf-8"
            
            rank_match = re.search(r'Global rank[：:]\s*([\d,]+)', response.text, re.IGNORECASE)
            if not rank_match:
                rank_match = re.search(r'rank[：:]\s*#?([\d,]+)', response.text, re.IGNORECASE)
            
            if rank_match:
                result.raw_data = {"alexa_rank": int(rank_match.group(1).replace(",", ""))}
                result.has_result = True
                    
        except Exception as e:
            result.error = f"Alexa排名查询异常: {str(e)[:50]}"
        
        return result

class WebWeightQuery:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 10)
        self.use_cache = self.config.get("use_cache", True)
        self.aizhan_api_key = self.config.get("aizhan_api_key", os.environ.get("AIZHAN_API_KEY", ""))
        
        self._api = WeightAPI(timeout=self.timeout)
        self._cache = WeightCache() if self.use_cache else None
    
    def query(self, domain: str, sources: Optional[List[str]] = None) -> WeightResult:
        pure_domain = DomainValidator.extract_domain(domain)
        
        if not DomainValidator.is_valid_domain(pure_domain):
            return WeightResult(
                domain=domain,
                error=f"域名格式非法: {domain}"
            )
        
        if self._cache:
            cached = self._cache.get(pure_domain)
            if cached:
                logger.info(f"域名 {pure_domain} 使用缓存数据")
                return cached
        
        if sources is None:
            sources = ["aizhan", "chinaz", "baidu", "sogou", "360"]
        
        final_result = WeightResult(domain=pure_domain)
        
        for source in sources:
            try:
                logger.info(f"尝试使用 {source} 查询域名: {pure_domain}")
                
                if source == "aizhan":
                    result = self._api.query_aizhan(pure_domain, self.aizhan_api_key)
                    if result.has_result:
                        final_result.baidu_pc_weight = max(final_result.baidu_pc_weight, result.baidu_pc_weight)
                        final_result.baidu_mobile_weight = max(final_result.baidu_mobile_weight, result.baidu_mobile_weight)
                        final_result.estimated_traffic = max(final_result.estimated_traffic, result.estimated_traffic)
                        final_result.source = result.source
                        
                elif source == "chinaz":
                    result = self._api.query_chinaz(pure_domain)
                    if result.has_result:
                        final_result.baidu_pc_weight = max(final_result.baidu_pc_weight, result.baidu_pc_weight)
                        final_result.baidu_mobile_weight = max(final_result.baidu_mobile_weight, result.baidu_mobile_weight)
                        final_result.baidu收录 = max(final_result.baidu收录, result.baidu收录)
                        if not final_result.source:
                            final_result.source = result.source
                            
                elif source == "baidu":
                    result = self._api.query_sitebaidu(pure_domain)
                    if result.has_result:
                        final_result.baidu收录 = max(final_result.baidu收录, result.baidu收录)
                        if not final_result.source:
                            final_result.source = result.source
                            
                elif source == "sogou":
                    result = self._api.query_sogou(pure_domain)
                    if result.has_result:
                        final_result.sogou_index = result.sogou_index
                        if not final_result.source:
                            final_result.source = result.source
                            
                elif source == "360":
                    result = self._api.query_360(pure_domain)
                    if result.has_result:
                        final_result.index_360 = result.index_360
                        if not final_result.source:
                            final_result.source = result.source
                            
                elif source == "bing":
                    result = self._api.query_bing(pure_domain)
                    if result.has_result:
                        if not final_result.source:
                            final_result.source = result.source
                            
                elif source == "alexa":
                    result = self._api.query_alexa(pure_domain)
                    if result.has_result:
                        if not final_result.source:
                            final_result.source = result.source
                
                final_result.has_result = True
                final_result.raw_data.update(result.raw_data)
                
            except Exception as e:
                logger.warning(f"{source} 查询异常: {str(e)[:50]}")
                continue
        
        if final_result.has_result and self._cache:
            self._cache.set(pure_domain, final_result)
        
        return final_result
    
    def batch_query(self, domains: List[str]) -> Dict[str, WeightResult]:
        results = {}
        for domain in domains:
            results[domain] = self.query(domain)
        return results

def get_web_weight(domain: str) -> Dict[str, Any]:
    query = WebWeightQuery()
    result = query.query(domain)
    
    return {
        "success": result.has_result,
        "result": format_weight_result(result),
        "raw_data": result.raw_data,
        "message": "" if result.has_result else result.error
    }

def format_weight_result(result: WeightResult) -> str:
    if not result.has_result:
        return f"获取数据失败: {result.error}"
    
    parts = []
    if result.baidu_pc_weight > 0:
        parts.append(f"百度PC权重({result.baidu_pc_weight})")
    if result.baidu_mobile_weight > 0:
        parts.append(f"百度移动权重({result.baidu_mobile_weight})")
    if result.baidu收录 > 0:
        parts.append(f"百度收录({result.baidu收录})")
    if result.sogou_index > 0:
        parts.append(f"搜狗收录({result.sogou_index})")
    if result.index_360 > 0:
        parts.append(f"360收录({result.index_360})")
    if result.estimated_traffic > 0:
        parts.append(f"预估流量({result.estimated_traffic})")
    
    if not parts:
        return f"域名 {result.domain} 暂无权重数据"
    
    return f"{', '.join(parts)} --数据来源于{result.source}"

def get_web_weight_compat(domain: str) -> str:
    result = get_web_weight(domain)
    return result["result"]

if __name__ == '__main__':
    test_domains = [
        "https://jwt1399.top/",
        "baidu.com",
        "qq.com",
        "invalid_domain"
    ]
    
    for test_domain in test_domains:
        print(f"\n{'='*60}")
        print(f"测试域名: {test_domain}")
        result = get_web_weight(test_domain)
        print(f"结果: {result['result']}")
        if result['success']:
            print(f"原始数据: {json.dumps(result['raw_data'], ensure_ascii=False, indent=2)}")
