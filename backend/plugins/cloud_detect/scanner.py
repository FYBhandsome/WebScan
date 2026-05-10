# -*- coding:utf-8 -*-

"""
云服务识别模块
功能:
1. 云服务商识别（AWS、Azure、GCP、阿里云等）
2. 云服务类型检测
3. CDN检测
4. 云资源发现
5. 区域识别
6. 多维度检测
"""

import logging
import re
import socket
import dns.resolver
from typing import Dict, Any, Optional, List, Set
from dataclasses import dataclass, field
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("CloudDetect")

@dataclass
class CloudProvider:
    name: str
    service_type: str
    region: str = ""
    confidence: int = 100
    evidence: str = ""

@dataclass
class CloudDetectResult:
    target: str = ""
    ip: str = ""
    providers: List[CloudProvider] = field(default_factory=list)
    is_cloud: bool = False
    is_cdn: bool = False
    cdn_provider: str = ""
    cloud_services: List[str] = field(default_factory=list)
    regions: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    error: str = ""

class CloudPatterns:
    AWS_PATTERNS = {
        "domains": [
            r"\.amazonaws\.com$",
            r"\.cloudfront\.net$",
            r"\.s3\.amazonaws\.com$",
            r"\.s3-website.*\.amazonaws\.com$",
            r"\.elasticbeanstalk\.com$",
            r"\.ec2.*\.amazonaws\.com$",
            r"\.rds.*\.amazonaws\.com$",
            r"\.lambda.*\.amazonaws\.com$",
            r"\.execute-api\..*\.amazonaws\.com$",
        ],
        "headers": [
            ("X-Amz-Cf-Id", "CloudFront"),
            ("X-Amz-Bucket-Region", "S3"),
            ("Server", "AmazonS3"),
        ],
        "ip_ranges": [
            "3.0.0.0/8", "13.0.0.0/8", "15.0.0.0/8", "18.0.0.0/8", "34.0.0.0/8",
            "35.0.0.0/8", "52.0.0.0/8", "54.0.0.0/8", "99.0.0.0/8", "100.0.0.0/8",
        ],
    }
    
    AZURE_PATTERNS = {
        "domains": [
            r"\.azurewebsites\.net$",
            r"\.cloudapp\.net$",
            r"\.azureedge\.net$",
            r"\.blob\.core\.windows\.net$",
            r"\.table\.core\.windows\.net$",
            r"\.queue\.core\.windows\.net$",
            r"\.azurecontainer\.io$",
            r"\.azurefd\.net$",
        ],
        "headers": [
            ("X-Azure-Ref", "Azure CDN"),
            ("X-Azure-Request-Id", "Azure"),
        ],
    }
    
    GCP_PATTERNS = {
        "domains": [
            r"\.appspot\.com$",
            r"\.googleusercontent\.com$",
            r"\.cloudfunctions\.net$",
            r"\.run\.app$",
            r"\.firebaseapp\.com$",
            r"\.firebaseio\.com$",
            r"\.gstatic\.com$",
        ],
        "headers": [
            ("Server", "Google Frontend"),
            ("Server", "gunicorn"),
        ],
    }
    
    ALIYUN_PATTERNS = {
        "domains": [
            r"\.aliyuncs\.com$",
            r"\.alicdn\.com$",
            r"\.oss-cn-.*\.aliyuncs\.com$",
            r"\.slb\.aliyuncs\.com$",
            r"\.ecs\.aliyuncs\.com$",
        ],
        "headers": [
            ("Server", "Tengine"),
            ("Via", "Aliyun"),
        ],
    }
    
    TENCENT_PATTERNS = {
        "domains": [
            r"\.myqcloud\.com$",
            r"\.cloudbase\.net$",
            r"\.cdn\.dnsv1\.com$",
            r"\.cdn\.dnsv2\.com$",
            r"\.cos\..*\.myqcloud\.com$",
        ],
        "headers": [
            ("Server", "tencent"),
            ("X-Cache-Lookup", "Cache Hit"),
        ],
    }
    
    HUAWEI_PATTERNS = {
        "domains": [
            r"\.huaweicloud\.com$",
            r"\.obs\..*\.myhuaweicloud\.com$",
            r"\.cdn\.myhuaweicloud\.com$",
        ],
    }
    
    CDN_PATTERNS = {
        "Cloudflare": {
            "domains": [r"\.cloudflare\.com$", r"\.cloudflare-dns\.com$"],
            "headers": [("CF-Ray", ""), ("Server", "cloudflare")],
        },
        "Akamai": {
            "domains": [r"\.akamaized\.net$", r"\.akamai\.net$", r"\.akamaiedge\.net$"],
            "headers": [("X-Akamai-Transformed", "")],
        },
        "Fastly": {
            "domains": [r"\.fastly\.net$", r"\.fastlylb\.net$"],
            "headers": [("X-Served-By", "cache-"), ("X-Fastly-Request-Id", "")],
        },
        "CloudFront": {
            "domains": [r"\.cloudfront\.net$"],
            "headers": [("X-Amz-Cf-Id", "")],
        },
    }

class CloudDetector:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 10)
        self.session = self._create_session()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout
    
    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retry_strategy = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"]
        )
        session.mount("http://", HTTPAdapter(max_retries=retry_strategy))
        session.mount("https://", HTTPAdapter(max_retries=retry_strategy))
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        })
        return session
    
    def _normalize_target(self, target: str) -> str:
        target = target.strip().lower()
        if target.startswith(("http://", "https://")):
            target = target.split("//")[-1].split("/")[0]
        return target
    
    def _get_ip(self, domain: str) -> str:
        try:
            answers = self.resolver.resolve(domain, 'A')
            if answers:
                return str(answers[0])
        except:
            pass
        return ""
    
    def _get_cname(self, domain: str) -> str:
        try:
            answers = self.resolver.resolve(domain, 'CNAME')
            if answers:
                return str(answers[0]).rstrip('.')
        except:
            pass
        return ""
    
    def _detect_from_domain(self, domain: str) -> List[CloudProvider]:
        providers = []
        cname = self._get_cname(domain)
        check_domains = [domain, cname] if cname else [domain]
        
        patterns = [
            ("AWS", CloudPatterns.AWS_PATTERNS),
            ("Azure", CloudPatterns.AZURE_PATTERNS),
            ("GCP", CloudPatterns.GCP_PATTERNS),
            ("Aliyun", CloudPatterns.ALIYUN_PATTERNS),
            ("Tencent", CloudPatterns.TENCENT_PATTERNS),
            ("Huawei", CloudPatterns.HUAWEI_PATTERNS),
        ]
        
        for check_domain in check_domains:
            if not check_domain:
                continue
            
            for provider_name, pattern_dict in patterns:
                for pattern in pattern_dict.get("domains", []):
                    if re.search(pattern, check_domain, re.IGNORECASE):
                        providers.append(CloudProvider(
                            name=provider_name,
                            service_type="Cloud Hosting",
                            evidence=f"域名匹配: {check_domain}",
                            confidence=95
                        ))
                        break
        
        return providers
    
    def _detect_from_headers(self, url: str) -> List[CloudProvider]:
        providers = []
        
        try:
            response = self.session.head(url, timeout=self.timeout, verify=False, allow_redirects=True)
            headers = response.headers
            
            patterns = [
                ("AWS", CloudPatterns.AWS_PATTERNS),
                ("Azure", CloudPatterns.AZURE_PATTERNS),
                ("GCP", CloudPatterns.GCP_PATTERNS),
                ("Aliyun", CloudPatterns.ALIYUN_PATTERNS),
                ("Tencent", CloudPatterns.TENCENT_PATTERNS),
            ]
            
            for provider_name, pattern_dict in patterns:
                for header_name, service_hint in pattern_dict.get("headers", []):
                    if header_name in headers:
                        providers.append(CloudProvider(
                            name=provider_name,
                            service_type=service_hint or "Cloud Service",
                            evidence=f"响应头: {header_name}",
                            confidence=90
                        ))
                        break
            
            for cdn_name, cdn_pattern in CloudPatterns.CDN_PATTERNS.items():
                for header_name, _ in cdn_pattern.get("headers", []):
                    if header_name in headers:
                        providers.append(CloudProvider(
                            name=cdn_name,
                            service_type="CDN",
                            evidence=f"CDN响应头: {header_name}",
                            confidence=95
                        ))
                        break
                        
        except Exception as e:
            logger.warning(f"HTTP请求异常: {str(e)[:50]}")
        
        return providers
    
    def _detect_cdn(self, domain: str) -> tuple:
        cname = self._get_cname(domain)
        
        for cdn_name, cdn_pattern in CloudPatterns.CDN_PATTERNS.items():
            for pattern in cdn_pattern.get("domains", []):
                if cname and re.search(pattern, cname, re.IGNORECASE):
                    return True, cdn_name
        
        return False, ""
    
    def detect(self, target: str) -> CloudDetectResult:
        result = CloudDetectResult(target=target)
        
        domain = self._normalize_target(target)
        result.ip = self._get_ip(domain)
        
        providers_from_domain = self._detect_from_domain(domain)
        
        url = f"https://{domain}"
        providers_from_headers = self._detect_from_headers(url)
        
        all_providers = providers_from_domain + providers_from_headers
        
        seen_providers = set()
        for provider in all_providers:
            key = f"{provider.name}:{provider.service_type}"
            if key not in seen_providers:
                seen_providers.add(key)
                result.providers.append(provider)
        
        result.is_cdn, result.cdn_provider = self._detect_cdn(domain)
        
        if result.providers:
            result.is_cloud = True
            result.cloud_services = list(set(p.name for p in result.providers))
            result.regions = list(set(p.region for p in result.providers if p.region))
        
        result.raw_data = {
            "domain": domain,
            "ip": result.ip,
            "cname": self._get_cname(domain),
        }
        
        return result

def detect_cloud(target: str) -> Dict[str, Any]:
    detector = CloudDetector()
    result = detector.detect(target)
    
    return {
        "success": True,
        "target": result.target,
        "ip": result.ip,
        "is_cloud": result.is_cloud,
        "is_cdn": result.is_cdn,
        "cdn_provider": result.cdn_provider,
        "cloud_providers": [
            {
                "name": p.name,
                "service_type": p.service_type,
                "region": p.region,
                "confidence": p.confidence,
                "evidence": p.evidence
            }
            for p in result.providers
        ],
        "cloud_services": result.cloud_services,
        "regions": result.regions,
        "error": result.error
    }

if __name__ == '__main__':
    test_targets = ["github.com", "aws.amazon.com", "portal.azure.com", "cloud.google.com"]
    for target in test_targets:
        print(f"\n{'='*60}")
        print(f"检测目标: {target}")
        result = detect_cloud(target)
        print(f"IP地址: {result['ip']}")
        print(f"是否云服务: {result['is_cloud']}")
        print(f"是否CDN: {result['is_cdn']}")
        if result['cdn_provider']:
            print(f"CDN提供商: {result['cdn_provider']}")
        if result['cloud_providers']:
            print(f"云服务提供商:")
            for p in result['cloud_providers']:
                print(f"  - {p['name']} ({p['service_type']}) - {p['confidence']}%")
