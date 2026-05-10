# -*- coding:utf-8 -*-

"""
IP归属地查询模块（增强版）
功能:
1. 多API源聚合查询（ip-api、ipinfo、ipgeolocation等）
2. 支持IPv4和IPv6地址
3. 智能缓存机制，减少重复查询
4. 详细的地理位置信息（国家、省份、城市、ISP、ASN、时区等）
5. 自动故障转移，API不可用时切换备用源

依赖:
- requests: 用于HTTP请求
"""

import logging
import re
import time
import hashlib
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from threading import Lock
import requests
from requests.exceptions import ConnectTimeout, ReadTimeout, RequestException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("IPLocating")

@dataclass
class IPLocationResult:
    has_result: bool = False
    ip: str = ""
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    isp: str = ""
    org: str = ""
    asn: str = ""
    timezone: str = ""
    lat: float = 0.0
    lon: float = 0.0
    ip_version: int = 4
    source: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)
    error: str = ""

class IPValidator:
    IPV4_PATTERN = re.compile(
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    )
    IPV6_PATTERN = re.compile(
        r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|"
        r"^(?:[0-9a-fA-F]{1,4}:){1,7}:$|"
        r"^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|"
        r"^(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}$|"
        r"^(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}$|"
        r"^(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}$|"
        r"^(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}$|"
        r"^[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}$|"
        r"^:(?::[0-9a-fA-F]{1,4}){1,7}$|"
        r"^::(?:[fF]{4}:)?(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|"
        r"^(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    )
    
    PRIVATE_IPV4_RANGES = [
        (re.compile(r"^10\."), "私有地址(10.0.0.0/8)"),
        (re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\."), "私有地址(172.16.0.0/12)"),
        (re.compile(r"^192\.168\."), "私有地址(192.168.0.0/16)"),
        (re.compile(r"^127\."), "本地回环地址(127.0.0.0/8)"),
        (re.compile(r"^169\.254\."), "链路本地地址(169.254.0.0/16)"),
        (re.compile(r"^224\."), "组播地址(224.0.0.0/4)"),
        (re.compile(r"^240\."), "保留地址(240.0.0.0/4)"),
    ]
    
    @classmethod
    def is_valid_ipv4(cls, ip: str) -> bool:
        if not isinstance(ip, str) or not ip.strip():
            return False
        return bool(cls.IPV4_PATTERN.match(ip.strip()))
    
    @classmethod
    def is_valid_ipv6(cls, ip: str) -> bool:
        if not isinstance(ip, str) or not ip.strip():
            return False
        return bool(cls.IPV6_PATTERN.match(ip.strip()))
    
    @classmethod
    def is_valid_ip(cls, ip: str) -> bool:
        return cls.is_valid_ipv4(ip) or cls.is_valid_ipv6(ip)
    
    @classmethod
    def get_ip_version(cls, ip: str) -> int:
        if cls.is_valid_ipv4(ip):
            return 4
        elif cls.is_valid_ipv6(ip):
            return 6
        return 0
    
    @classmethod
    def is_private_ip(cls, ip: str) -> tuple:
        if not cls.is_valid_ipv4(ip):
            return False, ""
        for pattern, desc in cls.PRIVATE_IPV4_RANGES:
            if pattern.match(ip):
                return True, desc
        return False, ""

class IPGeolocationCache:
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
                    cls._instance._max_size = 1000
                    cls._instance._ttl = 3600
        return cls._instance
    
    def _get_cache_key(self, ip: str) -> str:
        return hashlib.md5(ip.strip().encode()).hexdigest()
    
    def get(self, ip: str) -> Optional[IPLocationResult]:
        key = self._get_cache_key(ip)
        with self._cache_lock:
            if key in self._cache:
                cached = self._cache[key]
                if time.time() - cached["timestamp"] < self._ttl:
                    return cached["result"]
                else:
                    del self._cache[key]
        return None
    
    def set(self, ip: str, result: IPLocationResult) -> None:
        key = self._get_cache_key(ip)
        with self._cache_lock:
            if len(self._cache) >= self._max_size:
                oldest_key = min(self._cache.keys(), key=lambda k: self._cache[k]["timestamp"])
                del self._cache[oldest_key]
            self._cache[key] = {
                "result": result,
                "timestamp": time.time()
            }
    
    def clear(self) -> None:
        with self._cache_lock:
            self._cache.clear()

class IPLocationAPI:
    def __init__(self, timeout: int = 8):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json",
        })
    
    def query_ipapi(self, ip: str) -> IPLocationResult:
        result = IPLocationResult(ip=ip, source="ip-api.com")
        try:
            url = f"http://ip-api.com/json/{ip}?lang=zh-CN&fields=status,message,country,countryCode,region,regionName,city,isp,org,as,timezone,lat,lon,query"
            response = self.session.get(url, timeout=self.timeout)
            response.encoding = "utf-8"
            data = response.json()
            
            if data.get("status") != "success":
                result.error = data.get("message", "查询失败")
                return result
            
            result.has_result = True
            result.country = data.get("country", "")
            result.country_code = data.get("countryCode", "")
            result.region = data.get("regionName", "")
            result.city = data.get("city", "")
            result.isp = data.get("isp", "")
            result.org = data.get("org", "")
            result.asn = data.get("as", "")
            result.timezone = data.get("timezone", "")
            result.lat = float(data.get("lat", 0))
            result.lon = float(data.get("lon", 0))
            result.raw_data = data
            result.ip_version = IPValidator.get_ip_version(ip)
            
        except Exception as e:
            result.error = f"ip-api查询异常: {str(e)[:50]}"
        
        return result
    
    def query_ipapi_pro(self, ip: str) -> IPLocationResult:
        result = IPLocationResult(ip=ip, source="ip-api.com(pro)")
        try:
            url = f"http://pro.ip-api.com/json/{ip}?lang=zh-CN"
            response = self.session.get(url, timeout=self.timeout)
            response.encoding = "utf-8"
            data = response.json()
            
            if data.get("status") != "success":
                result.error = data.get("message", "查询失败")
                return result
            
            result.has_result = True
            result.country = data.get("country", "")
            result.country_code = data.get("countryCode", "")
            result.region = data.get("regionName", "")
            result.city = data.get("city", "")
            result.isp = data.get("isp", "")
            result.org = data.get("org", "")
            result.asn = data.get("as", "")
            result.timezone = data.get("timezone", "")
            result.lat = float(data.get("lat", 0))
            result.lon = float(data.get("lon", 0))
            result.raw_data = data
            result.ip_version = IPValidator.get_ip_version(ip)
            
        except Exception as e:
            result.error = f"ip-api(pro)查询异常: {str(e)[:50]}"
        
        return result
    
    def query_ipinfo(self, ip: str) -> IPLocationResult:
        result = IPLocationResult(ip=ip, source="ipinfo.io")
        try:
            url = f"https://ipinfo.io/{ip}/json"
            response = self.session.get(url, timeout=self.timeout)
            response.encoding = "utf-8"
            data = response.json()
            
            if "bogon" in data and data["bogon"]:
                result.error = "保留/私有IP地址"
                return result
            
            if "error" in data:
                result.error = data.get("error", {}).get("message", "查询失败")
                return result
            
            result.has_result = True
            result.country = data.get("country", "")
            result.country_code = data.get("country", "")
            result.region = data.get("region", "")
            result.city = data.get("city", "")
            result.isp = data.get("org", "")
            result.org = data.get("org", "")
            
            if "loc" in data:
                try:
                    lat, lon = data["loc"].split(",")
                    result.lat = float(lat)
                    result.lon = float(lon)
                except:
                    pass
            
            result.timezone = data.get("timezone", "")
            result.raw_data = data
            result.ip_version = IPValidator.get_ip_version(ip)
            
        except Exception as e:
            result.error = f"ipinfo.io查询异常: {str(e)[:50]}"
        
        return result
    
    def query_ipgeolocation(self, ip: str, api_key: str = "") -> IPLocationResult:
        result = IPLocationResult(ip=ip, source="ipgeolocation.io")
        try:
            base_url = "https://api.ipgeolocation.io/ipgeo"
            if api_key:
                url = f"{base_url}?apiKey={api_key}&ip={ip}&lang=zh"
            else:
                url = f"{base_url}?ip={ip}"
            
            response = self.session.get(url, timeout=self.timeout)
            response.encoding = "utf-8"
            data = response.json()
            
            if "message" in data and "error" in str(data.get("message", "")).lower():
                result.error = data.get("message", "查询失败")
                return result
            
            result.has_result = True
            result.country = data.get("country_name", "")
            result.country_code = data.get("country_code2", "")
            result.region = data.get("state_prov", "")
            result.city = data.get("city", "")
            result.isp = data.get("isp", "")
            result.org = data.get("organization", "")
            result.asn = data.get("asn", "")
            result.timezone = data.get("time_zone", {}).get("name", "")
            result.lat = float(data.get("latitude", 0) or 0)
            result.lon = float(data.get("longitude", 0) or 0)
            result.raw_data = data
            result.ip_version = IPValidator.get_ip_version(ip)
            
        except Exception as e:
            result.error = f"ipgeolocation.io查询异常: {str(e)[:50]}"
        
        return result
    
    def query_ipapi_com(self, ip: str) -> IPLocationResult:
        result = IPLocationResult(ip=ip, source="ipapi.com")
        try:
            url = f"https://ipapi.co/{ip}/json/"
            response = self.session.get(url, timeout=self.timeout)
            response.encoding = "utf-8"
            data = response.json()
            
            if "error" in data:
                result.error = data.get("reason", "查询失败")
                return result
            
            result.has_result = True
            result.country = data.get("country_name", "")
            result.country_code = data.get("country_code", "")
            result.region = data.get("region", "")
            result.city = data.get("city", "")
            result.isp = data.get("org", "")
            result.org = data.get("org", "")
            result.asn = data.get("asn", "")
            result.timezone = data.get("timezone", "")
            result.lat = float(data.get("latitude", 0) or 0)
            result.lon = float(data.get("longitude", 0) or 0)
            result.raw_data = data
            result.ip_version = IPValidator.get_ip_version(ip)
            
        except Exception as e:
            result.error = f"ipapi.com查询异常: {str(e)[:50]}"
        
        return result
    
    def query_ipwhois(self, ip: str) -> IPLocationResult:
        result = IPLocationResult(ip=ip, source="ipwhois.app")
        try:
            url = f"https://ipwhois.app/json/{ip}"
            response = self.session.get(url, timeout=self.timeout)
            response.encoding = "utf-8"
            data = response.json()
            
            if not data.get("success", True):
                result.error = data.get("message", "查询失败")
                return result
            
            result.has_result = True
            result.country = data.get("country", "")
            result.country_code = data.get("country_code", "")
            result.region = data.get("region", "")
            result.city = data.get("city", "")
            result.isp = data.get("isp", "")
            result.org = data.get("org", "")
            result.asn = data.get("asn", "")
            result.timezone = data.get("timezone", {}).get("id", "")
            result.lat = float(data.get("latitude", 0) or 0)
            result.lon = float(data.get("longitude", 0) or 0)
            result.raw_data = data
            result.ip_version = IPValidator.get_ip_version(ip)
            
        except Exception as e:
            result.error = f"ipwhois.app查询异常: {str(e)[:50]}"
        
        return result
    
    def query_ip2location(self, ip: str) -> IPLocationResult:
        result = IPLocationResult(ip=ip, source="ip2location.io")
        try:
            url = f"https://api.ip2location.io/?key=demo&ip={ip}"
            response = self.session.get(url, timeout=self.timeout)
            response.encoding = "utf-8"
            data = response.json()
            
            if "error" in data:
                result.error = data.get("error", {}).get("message", "查询失败")
                return result
            
            result.has_result = True
            result.country = data.get("country_name", "")
            result.country_code = data.get("country_code", "")
            result.region = data.get("region_name", "")
            result.city = data.get("city_name", "")
            result.isp = data.get("isp", "")
            result.org = data.get("as", "")
            result.asn = data.get("asn", "")
            result.raw_data = data
            result.ip_version = IPValidator.get_ip_version(ip)
            
        except Exception as e:
            result.error = f"ip2location.io查询异常: {str(e)[:50]}"
        
        return result

class IPLocator:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 8)
        self.use_cache = self.config.get("use_cache", True)
        self.api_order = self.config.get("api_order", [
            "ipapi", "ipinfo", "ipapi_com", "ipwhois", "ip2location"
        ])
        
        self._api = IPLocationAPI(timeout=self.timeout)
        self._cache = IPGeolocationCache() if self.use_cache else None
        
        self._api_methods = {
            "ipapi": self._api.query_ipapi,
            "ipapi_pro": self._api.query_ipapi_pro,
            "ipinfo": self._api.query_ipinfo,
            "ipgeolocation": lambda ip: self._api.query_ipgeolocation(ip, self.config.get("ipgeolocation_key", "")),
            "ipapi_com": self._api.query_ipapi_com,
            "ipwhois": self._api.query_ipwhois,
            "ip2location": self._api.query_ip2location,
        }
    
    def locate(self, ip: str) -> IPLocationResult:
        ip = ip.strip() if isinstance(ip, str) else ""
        
        if not IPValidator.is_valid_ip(ip):
            return IPLocationResult(
                ip=ip,
                error=f"IP格式非法: {ip}"
            )
        
        is_private, private_desc = IPValidator.is_private_ip(ip)
        if is_private:
            return IPLocationResult(
                ip=ip,
                has_result=True,
                country="本地网络",
                region=private_desc,
                city="内网地址",
                ip_version=4,
                source="local",
                error=""
            )
        
        if self._cache:
            cached = self._cache.get(ip)
            if cached:
                logger.info(f"IP {ip} 使用缓存数据")
                return cached
        
        for api_name in self.api_order:
            if api_name not in self._api_methods:
                continue
            
            try:
                logger.info(f"尝试使用 {api_name} 查询 IP: {ip}")
                result = self._api_methods[api_name](ip)
                
                if result.has_result:
                    if self._cache:
                        self._cache.set(ip, result)
                    logger.info(f"IP {ip} 查询成功，来源: {api_name}")
                    return result
                    
            except Exception as e:
                logger.warning(f"{api_name} 查询异常: {str(e)[:50]}")
                continue
        
        return IPLocationResult(
            ip=ip,
            error="所有API查询均失败"
        )
    
    def batch_locate(self, ips: List[str]) -> Dict[str, IPLocationResult]:
        results = {}
        for ip in ips:
            results[ip] = self.locate(ip)
        return results

def get_locating(ip: str) -> str:
    locator = IPLocator()
    result = locator.locate(ip)
    
    if not result.has_result:
        return f"IP {ip} 查询失败: {result.error}"
    
    parts = []
    if result.country:
        parts.append(f"国家({result.country})")
    if result.region:
        parts.append(f"省份({result.region})")
    if result.city:
        parts.append(f"城市({result.city})")
    if result.isp:
        parts.append(f"ISP({result.isp})")
    if result.asn:
        parts.append(f"ASN({result.asn})")
    
    location_str = ", ".join(parts) if parts else "未知位置"
    return f"{location_str} --数据来源于{result.source}"

def get_locating_detail(ip: str) -> IPLocationResult:
    locator = IPLocator()
    return locator.locate(ip)

if __name__ == '__main__':
    test_ips = [
        "139.224.112.182",
        "8.8.8.8",
        "2001:4860:4860::8888",
        "127.0.0.1",
        "192.168.1.1",
        "256.0.0.1",
        ""
    ]
    
    for test_ip in test_ips:
        print(f"\n{'='*60}")
        print(f"测试IP: {test_ip}")
        result = get_locating_detail(test_ip)
        if result.has_result:
            print(f"国家: {result.country}")
            print(f"省份: {result.region}")
            print(f"城市: {result.city}")
            print(f"ISP: {result.isp}")
            print(f"ASN: {result.asn}")
            print(f"时区: {result.timezone}")
            print(f"坐标: {result.lat}, {result.lon}")
            print(f"IP版本: IPv{result.ip_version}")
            print(f"数据来源: {result.source}")
        else:
            print(f"查询失败: {result.error}")
