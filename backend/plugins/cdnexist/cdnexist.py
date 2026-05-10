# -*- coding:utf-8 -*-

"""
CDN检测模块（增强版）

功能:
1. IP段匹配检测
2. ASN匹配检测
3. CNAME记录检测
4. HTTP响应头特征检测
5. 多DNS服务器解析对比检测
6. 支持URL、域名、IP地址作为输入

特性:
- 多维度检测，提高准确率
- 预编译CDN网段，提升性能
- 支持多种CDN厂商识别
- 返回详细的CDN信息

依赖:
- geoip2: 用于查询IP的ASN信息（可选）
- ipaddress: 用于IP地址和网段处理
- dnspython: 用于DNS查询（可选）

使用示例:
    >>> from backend.plugins.cdnexist.cdnexist import detect_cdn
    >>> result = detect_cdn("https://www.baidu.com")
    >>> print(result)
    {
        "has_cdn": True,
        "cdn_name": "CloudFlare",
        "detection_methods": ["ip_range", "cname", "header"],
        "confidence": 0.95
    }
"""

import logging
import socket
import ipaddress
import re
from typing import Union, Optional, Dict, List, Any, Set
from pathlib import Path
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError

logger = logging.getLogger(__name__)

DNS_AVAILABLE = False
try:
    import dns.resolver
    import dns.rdatatype
    DNS_AVAILABLE = True
except ImportError:
    logger.warning("[CDN] dnspython未安装，CNAME检测功能受限")

GEOIP2_AVAILABLE = False
try:
    import geoip2.database
    from geoip2.errors import AddressNotFoundError, GeoIP2Error
    GEOIP2_AVAILABLE = True
except ImportError:
    logger.warning("[CDN] geoip2未安装，ASN检测功能受限")


@dataclass
class CDNResult:
    has_cdn: bool
    cdn_name: str
    detection_methods: List[str] = field(default_factory=list)
    confidence: float = 0.0
    ip_addresses: List[str] = field(default_factory=list)
    cname_records: List[str] = field(default_factory=list)
    headers_matched: List[str] = field(default_factory=list)
    asn_info: str = ""
    details: Dict[str, Any] = field(default_factory=dict)


CDN_CIDR_LIST = [
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18',
    '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17',
    '162.158.0.0/15', '104.16.0.0/12', '172.64.0.0/13', '131.0.72.0/22', '13.124.199.0/24',
    '144.220.0.0/16', '34.226.14.0/24', '52.124.128.0/17', '54.230.0.0/16', '54.239.128.0/18',
    '52.82.128.0/19', '99.84.0.0/16', '52.15.127.128/26', '35.158.136.0/24', '52.57.254.0/24',
    '18.216.170.128/25', '13.54.63.128/26', '13.59.250.0/26', '13.210.67.128/26', '35.167.191.128/26',
    '52.47.139.0/24', '52.199.127.192/26', '52.212.248.0/26', '205.251.192.0/19', '52.66.194.128/26',
    '54.239.192.0/19', '70.132.0.0/18', '13.32.0.0/15', '13.224.0.0/14', '13.113.203.0/24',
    '34.195.252.0/24', '35.162.63.192/26', '34.223.12.224/27', '13.35.0.0/16', '204.246.172.0/23',
    '204.246.164.0/22', '52.56.127.0/25', '204.246.168.0/22', '13.228.69.0/24', '34.216.51.0/25',
    '71.152.0.0/17', '216.137.32.0/19', '205.251.249.0/24', '99.86.0.0/16', '52.46.0.0/18',
    '52.84.0.0/15', '54.233.255.128/26', '130.176.0.0/16', '64.252.64.0/18', '52.52.191.128/26',
    '204.246.174.0/23', '64.252.128.0/18', '205.251.254.0/24', '143.204.0.0/16', '205.251.252.0/23',
    '52.78.247.128/26', '204.246.176.0/20', '52.220.191.0/26', '13.249.0.0/16', '54.240.128.0/18',
    '205.251.250.0/23', '52.222.128.0/17', '54.182.0.0/16', '54.192.0.0/16', '34.232.163.208/29',
    '58.250.143.0/24', '58.251.121.0/24', '59.36.120.0/24', '61.151.163.0/24', '101.227.163.0/24',
    '111.161.109.0/24', '116.128.128.0/24', '123.151.76.0/24', '125.39.46.0/24', '140.207.120.0/24',
    '180.163.22.0/24', '183.3.254.0/24', '223.166.151.0/24', '113.107.238.0/24', '106.42.25.0/24',
    '183.222.96.0/24', '117.21.219.0/24', '116.55.250.0/24', '111.202.98.0/24', '111.13.147.0/24',
    '122.228.238.0/24', '58.58.81.0/24', '1.31.128.0/24', '123.155.158.0/24', '106.119.182.0/24',
    '180.97.158.0/24', '113.207.76.0/24', '117.23.61.0/24', '118.212.233.0/24', '111.47.226.0/24',
    '219.153.73.0/24', '113.200.91.0/24', '1.32.240.0/24', '203.90.247.0/24', '183.110.242.0/24',
    '202.162.109.0/24', '182.23.211.0/24', '1.32.242.0/24', '1.32.241.0/24', '202.162.108.0/24',
    '185.254.242.0/24', '109.94.168.0/24', '109.94.169.0/24', '1.32.243.0/24', '61.120.154.0/24',
    '1.255.41.0/24', '112.90.216.0/24', '61.213.176.0/24', '1.32.238.0/24', '1.32.239.0/24',
    '1.32.244.0/24', '111.32.135.0/24', '111.32.136.0/24', '125.39.174.0/24', '125.39.239.0/24',
    '112.65.73.0/24', '112.65.74.0/24', '112.65.75.0/24', '119.84.92.0/24', '119.84.93.0/24',
    '113.207.100.0/24', '113.207.101.0/24', '113.207.102.0/24', '180.163.188.0/24', '180.163.189.0/24',
    '163.53.89.0/24', '101.227.206.0/24', '101.227.207.0/24', '119.188.97.0/24', '119.188.9.0/24',
    '61.155.149.0/24', '61.156.149.0/24', '61.155.165.0/24', '61.182.137.0/24', '61.182.136.0/24',
    '120.52.29.0/24', '120.52.113.0/24', '222.216.190.0/24', '219.159.84.0/24', '183.60.235.0/24',
    '116.31.126.0/24', '116.31.127.0/24', '117.34.13.0/24', '117.34.14.0/24', '42.236.93.0/24',
    '42.236.94.0/24', '119.167.246.0/24', '150.138.149.0/24', '150.138.150.0/24', '150.138.151.0/24',
    '117.27.149.0/24', '59.51.81.0/24', '220.170.185.0/24', '220.170.186.0/24', '183.61.236.0/24',
    '14.17.71.0/24', '119.147.134.0/24', '124.95.168.0/24', '124.95.188.0/24', '61.54.46.0/24',
    '61.54.47.0/24', '101.71.55.0/24', '101.71.56.0/24', '183.232.51.0/24', '183.232.53.0/24',
    '157.255.25.0/24', '157.255.26.0/24', '112.25.90.0/24', '112.25.91.0/24', '58.211.2.0/24',
    '58.211.137.0/24', '122.190.2.0/24', '122.190.3.0/24', '183.61.177.0/24', '183.61.190.0/24',
    '117.148.160.0/24', '117.148.161.0/24', '115.231.186.0/24', '115.231.187.0/24', '113.31.27.0/24',
]

CDN_ASN_LIST = {
    '13335': 'CloudFlare',
    '16509': 'Amazon CloudFront',
    '14618': 'Amazon CloudFront',
    '54113': 'Fastly',
    '15133': 'Edgecast',
    '19551': 'Incapsula',
    '55770': 'Baidu Cloud CDN',
    '38365': 'Aliyun CDN',
    '45062': 'Tencent Cloud CDN',
    '24139': 'Cloudflare',
    '20940': 'Akamai',
    '12222': 'Akamai',
    '16625': 'Akamai',
    '34164': 'Akamai',
    '55805': 'ChinaCache',
    '23903': 'ChinaCache',
    '4808': 'ChinaNetCenter',
    '38365': 'WangSu',
    '55990': 'Huawei Cloud CDN',
    '61107': 'Kingsoft Cloud CDN',
    '49689': 'Qiniu Cloud CDN',
    '45062': 'Tencent Cloud',
}

CDN_CNAME_PATTERNS = {
    'cloudflare': {
        'patterns': [
            r'\.cloudflare\.com$', r'\.cdn\.cloudflare\.net$',
            r'\.cf\.cdn\.cloudflare\.net$', r'-provisioned\.cdn\.cloudflare\.net$',
        ],
        'name': 'CloudFlare',
    },
    'akamai': {
        'patterns': [
            r'\.akamaiedge\.net$', r'\.akamai\.net$',
            r'\.akamaized\.net$', r'\.edgesuite\.net$',
            r'\.edgekey\.net$', r'\.cdn\.akamai\.net$',
        ],
        'name': 'Akamai',
    },
    'cloudfront': {
        'patterns': [
            r'\.cloudfront\.net$', r'\.cloudfront\.com$',
        ],
        'name': 'Amazon CloudFront',
    },
    'fastly': {
        'patterns': [
            r'\.fastly\.net$', r'\.fastly\.com$',
            r'\.fastlylb\.net$',
        ],
        'name': 'Fastly',
    },
    'aliyun': {
        'patterns': [
            r'\.kunlun\w*\.com$', r'\.cdn\.aliyun\.com$',
            r'\.alicdn\.com$', r'\.aliyuncs\.com$',
            r'\.w\.cdn\.aliyun\.com$', r'\.kunlun\.com$',
        ],
        'name': 'Aliyun CDN',
    },
    'tencent': {
        'patterns': [
            r'\.cdn\.dnsv1\.com$', r'\.cdn\.qq\.com$',
            r'\.cdn\.dnsv[0-9]+\.com$', r'\.dnsv[0-9]+\.com$',
            r'\.cdn\.myqcloud\.com$', r'\.idc\.qq\.com$',
        ],
        'name': 'Tencent Cloud CDN',
    },
    'baidu': {
        'patterns': [
            r'\.bce\.baidu\.com$', r'\.cdn\.baidu\.com$',
            r'\.bcecdn\.com$', r'\.bdstatic\.com$',
        ],
        'name': 'Baidu Cloud CDN',
    },
    'wangsu': {
        'patterns': [
            r'\.wangsu\.com$', r'\.wscdns\.com$',
            r'\.wscloudcdn\.com$', r'\.chinanetcenter\.com$',
        ],
        'name': 'WangSu CDN',
    },
    'chinacache': {
        'patterns': [
            r'\.chinacache\.com$', r'\.ccgslb\.com$',
            r'\.cdn\.chinacache\.com$',
        ],
        'name': 'ChinaCache',
    },
    'huawei': {
        'patterns': [
            r'\.cdn\.huawei\.com$', r'\.cdn\.myhuaweicloud\.com$',
            r'\.hwcdn\.net$',
        ],
        'name': 'Huawei Cloud CDN',
    },
    'qiniu': {
        'patterns': [
            r'\.qiniudn\.com$', r'\.qiniu\.com$',
            r'\.clouddn\.com$', r'\.qiniucdn\.com$',
        ],
        'name': 'Qiniu Cloud CDN',
    },
    'kingsoft': {
        'patterns': [
            r'\.ks-cdn\.com$', r'\.ksyun\.com$',
            r'\.kingsoft\.com$',
        ],
        'name': 'Kingsoft Cloud CDN',
    },
    'incapsula': {
        'patterns': [
            r'\.incapdns\.net$', r'\.incapsula\.com$',
        ],
        'name': 'Incapsula',
    },
    'stackpath': {
        'patterns': [
            r'\.stackpathdns\.com$', r'\.stackpath\.com$',
        ],
        'name': 'StackPath',
    },
    'sucuri': {
        'patterns': [
            r'\.sucuri\.net$', r'\.cdn\.sucuri\.net$',
        ],
        'name': 'Sucuri',
    },
    'keycdn': {
        'patterns': [
            r'\.kxcdn\.com$', r'\.keycdn\.com$',
        ],
        'name': 'KeyCDN',
    },
    'cdn77': {
        'patterns': [
            r'\.cdn77\.org$', r'\.cdn77\.com$',
        ],
        'name': 'CDN77',
    },
}

CDN_HEADER_SIGNATURES = {
    'cloudflare': {
        'headers': {
            'Server': [r'cloudflare', r'cloudflare-nginx'],
            'CF-RAY': [r'.*'],
            'CF-Cache-Status': [r'.*'],
            'Expect-CT': [r'.*cloudflare.*'],
        },
        'name': 'CloudFlare',
    },
    'akamai': {
        'headers': {
            'Server': [r'AkamaiGHost', r'Akamai'],
            'X-Akamai-Transformed': [r'.*'],
            'X-Akamai-Staging': [r'.*'],
        },
        'name': 'Akamai',
    },
    'cloudfront': {
        'headers': {
            'Server': [r'CloudFront'],
            'X-Cache': [r'.*cloudfront.*', r'Hit from cloudfront', r'Miss from cloudfront'],
            'X-Amz-Cf-Id': [r'.*'],
            'Via': [r'.*cloudfront.*'],
        },
        'name': 'Amazon CloudFront',
    },
    'fastly': {
        'headers': {
            'X-Served-By': [r'.*'],
            'X-Fastly-Request-Id': [r'.*'],
            'X-Cache': [r'.*fastly.*'],
        },
        'name': 'Fastly',
    },
    'aliyun': {
        'headers': {
            'Server': [r'Tengine', r'AliyunOSS'],
            'X-Swift-CacheTime': [r'.*'],
            'X-Swift-SaveTime': [r'.*'],
            'Via': [r'.*Aliyun.*', r'.*Tengine.*'],
        },
        'name': 'Aliyun CDN',
    },
    'tencent': {
        'headers': {
            'Server': [r'nginx', r'Tencent'],
            'X-Cache-Lookup': [r'.*'],
            'X-NWS-LOG-UUID': [r'.*'],
        },
        'name': 'Tencent Cloud CDN',
    },
    'baidu': {
        'headers': {
            'Server': [r'JSP3', r'Apache', r'nginx'],
            'X-Server': [r'.*baidu.*'],
        },
        'name': 'Baidu Cloud CDN',
    },
    'wangsu': {
        'headers': {
            'Server': [r'WangSu', r'chinanetcenter'],
            'X-Cache': [r'.*WangSu.*'],
            'Via': [r'.*WangSu.*'],
        },
        'name': 'WangSu CDN',
    },
    'incapsula': {
        'headers': {
            'X-CDN': [r'Incapsula'],
            'X-Iinfo': [r'.*'],
            'Set-Cookie': [r'.*incap_ses.*', r'.*visid_incap.*'],
        },
        'name': 'Incapsula',
    },
    'sucuri': {
        'headers': {
            'Server': [r'Sucuri'],
            'X-Sucuri-ID': [r'.*'],
            'X-Sucuri-Cache': [r'.*'],
        },
        'name': 'Sucuri',
    },
}

DNS_SERVERS = [
    '8.8.8.8',
    '8.8.4.4',
    '1.1.1.1',
    '1.0.0.1',
    '114.114.114.114',
    '223.5.5.5',
]

GEOIP2_ASN_DB_PATH = Path(__file__).parent.parent.parent / "geoip" / "GeoLite2-ASN.mmdb"

try:
    CDN_NETWORKS = [ipaddress.ip_network(cidr, strict=False) for cidr in CDN_CIDR_LIST]
except ValueError as e:
    logger.error(f"[CDN] CDN网段解析失败: {e}")
    CDN_NETWORKS = []

for cdn_name, config in CDN_CNAME_PATTERNS.items():
    config['compiled_patterns'] = [re.compile(p, re.IGNORECASE) for p in config['patterns']]

for cdn_name, config in CDN_HEADER_SIGNATURES.items():
    for header_name, patterns in config['headers'].items():
        config['headers'][header_name] = [re.compile(p, re.IGNORECASE) for p in patterns]


class CDNDetector:
    """
    CDN检测器（增强版）
    
    检测方式:
    1. IP段匹配 - 检查IP是否在已知CDN网段
    2. ASN匹配 - 检查IP的ASN是否属于CDN厂商
    3. CNAME检测 - 检查域名的CNAME记录
    4. HTTP响应头检测 - 检查响应头特征
    5. 多DNS解析对比 - 检查不同DNS解析结果是否一致
    """
    
    def __init__(self, target: str, config: Optional[Dict[str, Any]] = None):
        self.target = target.strip() if isinstance(target, str) else ""
        self.config = config or {}
        
        self.timeout = self.config.get("timeout", 10)
        self.verify_ssl = self.config.get("verify_ssl", False)
        
        self._domain = ""
        self._ip_addresses: Set[str] = set()
        self._cname_records: List[str] = []
        self._http_headers: Dict[str, str] = {}
        
        self._result = CDNResult(has_cdn=False, cdn_name="")
        
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })
    
    def _extract_domain(self) -> str:
        if not self.target:
            return ""
        
        target = self.target.strip()
        
        if target.startswith(("http://", "https://")):
            parsed = urlparse(target)
            return parsed.netloc.split(":")[0]
        
        target = target.split("/")[0].split(":")[0]
        
        try:
            ipaddress.ip_address(target)
            return ""
        except ValueError:
            pass
        
        return target
    
    def _resolve_domain(self, domain: str) -> Set[str]:
        ips = set()
        
        if DNS_AVAILABLE:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = DNS_SERVERS[:2]
                resolver.timeout = 5
                resolver.lifetime = 5
                
                answers = resolver.resolve(domain, 'A')
                for rdata in answers:
                    ips.add(str(rdata))
                
                answers = resolver.resolve(domain, 'AAAA')
                for rdata in answers:
                    ips.add(str(rdata))
            except Exception as e:
                logger.debug(f"[CDN] DNS解析失败: {e}")
        
        if not ips:
            try:
                socket.setdefaulttimeout(5)
                addrs = socket.getaddrinfo(domain, None)
                for addr in addrs:
                    ips.add(addr[4][0])
            except Exception as e:
                logger.debug(f"[CDN] socket解析失败: {e}")
        
        return ips
    
    def _get_cname_records(self, domain: str) -> List[str]:
        cnames = []
        
        if DNS_AVAILABLE:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = DNS_SERVERS[:2]
                resolver.timeout = 5
                resolver.lifetime = 5
                
                answers = resolver.resolve(domain, 'CNAME')
                for rdata in answers:
                    cnames.append(str(rdata).rstrip('.'))
            except dns.resolver.NoAnswer:
                pass
            except Exception as e:
                logger.debug(f"[CDN] CNAME查询失败: {e}")
        
        return cnames
    
    def _check_ip_in_cdn_networks(self, ip: str) -> Optional[str]:
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in CDN_NETWORKS:
                if ip_obj in network:
                    return "ip_range"
        except ValueError:
            pass
        return None
    
    def _check_ip_asn(self, ip: str) -> Optional[str]:
        if not GEOIP2_AVAILABLE or not GEOIP2_ASN_DB_PATH.exists():
            return None
        
        try:
            with geoip2.database.Reader(str(GEOIP2_ASN_DB_PATH)) as reader:
                response = reader.asn(ip)
                asn = str(response.autonomous_system_number)
                if asn in CDN_ASN_LIST:
                    self._result.asn_info = f"AS{asn} ({CDN_ASN_LIST[asn]})"
                    return "asn"
        except Exception as e:
            logger.debug(f"[CDN] ASN查询失败: {e}")
        
        return None
    
    def _check_cname(self, cname: str) -> Optional[str]:
        for cdn_name, config in CDN_CNAME_PATTERNS.items():
            for pattern in config.get('compiled_patterns', []):
                if pattern.search(cname):
                    if self._result.cdn_name:
                        pass
                    else:
                        self._result.cdn_name = config['name']
                    return "cname"
        return None
    
    def _check_headers(self, headers: Dict[str, str]) -> Optional[str]:
        for cdn_name, config in CDN_HEADER_SIGNATURES.items():
            for header_name, patterns in config['headers'].items():
                header_value = headers.get(header_name, "")
                if header_value:
                    for pattern in patterns:
                        if pattern.search(header_value):
                            if not self._result.cdn_name:
                                self._result.cdn_name = config['name']
                            self._result.headers_matched.append(header_name)
                            return "header"
        return None
    
    def _multi_dns_check(self, domain: str) -> Optional[str]:
        if not DNS_AVAILABLE:
            return None
        
        all_ips = []
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        for dns_server in DNS_SERVERS[:3]:
            try:
                resolver.nameservers = [dns_server]
                answers = resolver.resolve(domain, 'A')
                ips = set(str(rdata) for rdata in answers)
                all_ips.append(ips)
            except Exception:
                pass
        
        if len(all_ips) >= 2:
            first_ips = all_ips[0]
            for ips in all_ips[1:]:
                if first_ips != ips:
                    return "multi_dns"
        
        return None
    
    def detect(self) -> CDNResult:
        self._domain = self._extract_domain()
        
        if not self._domain:
            ip = self.target
            try:
                ipaddress.ip_address(ip)
                self._ip_addresses.add(ip)
            except ValueError:
                self._result.details["error"] = "无效的目标"
                return self._result
        else:
            self._ip_addresses = self._resolve_domain(self._domain)
            self._cname_records = self._get_cname_records(self._domain)
        
        self._result.ip_addresses = list(self._ip_addresses)
        self._result.cname_records = self._cname_records
        
        detection_methods = []
        
        for ip in self._ip_addresses:
            method = self._check_ip_in_cdn_networks(ip)
            if method:
                detection_methods.append(method)
                self._result.has_cdn = True
                if not self._result.cdn_name:
                    self._result.cdn_name = "Unknown CDN"
                break
        
        for ip in self._ip_addresses:
            method = self._check_ip_asn(ip)
            if method:
                detection_methods.append(method)
                self._result.has_cdn = True
                break
        
        for cname in self._cname_records:
            method = self._check_cname(cname)
            if method:
                detection_methods.append(method)
                self._result.has_cdn = True
                break
        
        if self._domain:
            try:
                response = self.session.get(
                    f"https://{self._domain}" if not self.target.startswith("http") else self.target,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=True
                )
                self._http_headers = dict(response.headers)
                
                method = self._check_headers(self._http_headers)
                if method:
                    detection_methods.append(method)
                    self._result.has_cdn = True
            except Exception as e:
                logger.debug(f"[CDN] HTTP请求失败: {e}")
        
        if self._domain and not self._result.has_cdn:
            method = self._multi_dns_check(self._domain)
            if method:
                detection_methods.append(method)
                self._result.has_cdn = True
                if not self._result.cdn_name:
                    self._result.cdn_name = "Unknown CDN"
        
        self._result.detection_methods = list(set(detection_methods))
        
        if self._result.has_cdn:
            method_count = len(self._result.detection_methods)
            self._result.confidence = min(0.5 + method_count * 0.15, 1.0)
        
        self._result.details = {
            "domain": self._domain,
            "ip_count": len(self._ip_addresses),
            "cname_count": len(self._cname_records),
            "headers": self._http_headers,
        }
        
        return self._result


def detect_cdn(target: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    检测目标是否使用CDN
    
    :param target: URL/域名/IP地址
    :param config: 配置选项
    :return: 检测结果字典
    """
    detector = CDNDetector(target, config)
    result = detector.detect()
    
    return {
        "has_cdn": result.has_cdn,
        "cdn_name": result.cdn_name,
        "detection_methods": result.detection_methods,
        "confidence": result.confidence,
        "ip_addresses": result.ip_addresses,
        "cname_records": result.cname_records,
        "headers_matched": result.headers_matched,
        "asn_info": result.asn_info,
        "details": result.details,
    }


def is_cdn(host: Union[str, None]) -> Union[bool, str]:
    """
    兼容函数: 判断目标主机是否使用CDN
    
    :param host: URL/域名/IPv4地址
    :return: True(有CDN)| False(无CDN)| 错误信息字符串
    """
    if not host or not isinstance(host, str):
        return "输入为空或非字符串类型"
    
    host = host.strip()
    if not host:
        return "输入为空字符串"
    
    try:
        result = detect_cdn(host)
        return result["has_cdn"]
    except Exception as e:
        return f"检测异常: {str(e)}"


def iscdn(host: Union[str, None]) -> Union[bool, str]:
    """兼容函数"""
    return is_cdn(host)


if __name__ == '__main__':
    test_hosts = [
        "https://www.baidu.com",
        "https://www.cloudflare.com",
        "https://www.taobao.com",
        "https://jwt1399.top",
    ]
    
    for host in test_hosts:
        result = detect_cdn(host)
        print(f"\n目标: {host}")
        print(f"  CDN: {result['has_cdn']}")
        print(f"  厂商: {result['cdn_name']}")
        print(f"  方法: {result['detection_methods']}")
        print(f"  置信度: {result['confidence']:.2f}")
