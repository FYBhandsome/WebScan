"""
证书透明度查询模块

功能:
- crt.sh查询
- Censys证书查询
- 子域名提取
- 证书信息解析
- 历史证书分析
"""

import re
import json
import logging
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError

logger = logging.getLogger(__name__)


@dataclass
class CertificateInfo:
    domain: str
    issuer: str
    issuer_cn: str
    subject: str
    subject_cn: str
    serial_number: str
    not_before: str
    not_after: str
    fingerprint_sha256: str
    fingerprint_sha1: str
    is_expired: bool
    is_self_signed: bool
    san_domains: List[str] = field(default_factory=list)
    source: str = ""


@dataclass
class CTLogResult:
    domain: str
    subdomains: List[str]
    certificates: List[CertificateInfo]
    total_certs: int
    sources: List[str]


class CertificateTransparency:
    """
    证书透明度查询
    
    功能:
    - crt.sh查询
    - Censys证书查询
    - 子域名提取
    - 证书信息解析
    """
    
    def __init__(self, domain: str, config: Optional[Dict[str, Any]] = None):
        self.domain = self._normalize_domain(domain)
        self.config = config or {}
        
        self.timeout = self.config.get("timeout", 30)
        self.verify_ssl = self.config.get("verify_ssl", False)
        
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, text/html, */*",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive"
        })
        
        self._subdomains: Set[str] = set()
        self._certificates: List[CertificateInfo] = []
    
    def _normalize_domain(self, domain: str) -> str:
        domain = domain.strip().lower()
        if domain.startswith(("http://", "https://")):
            domain = urlparse(domain).netloc
        domain = domain.split(":")[0]
        return domain
    
    def query(self) -> Dict[str, Any]:
        logger.info(f"[CTLog] 查询证书透明度: {self.domain}")
        
        self._query_crt_sh()
        self._query_censys()
        
        self._subdomains.add(self.domain)
        
        return {
            "success": True,
            "domain": self.domain,
            "subdomains": sorted(list(self._subdomains)),
            "total_subdomains": len(self._subdomains),
            "certificates": [self._cert_to_dict(c) for c in self._certificates[:20]],
            "total_certificates": len(self._certificates),
        }
    
    def _query_crt_sh(self) -> None:
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        
                        for name in name_value.split("\n"):
                            name = name.strip().lower()
                            if name and self._is_subdomain(name):
                                self._subdomains.add(name)
                        
                        cert_info = self._parse_crt_sh_entry(entry)
                        if cert_info:
                            self._certificates.append(cert_info)
                            
                    logger.info(f"[CTLog] crt.sh 发现 {len(self._subdomains)} 个子域名")
                    
                except json.JSONDecodeError:
                    self._parse_crt_sh_html(response.text)
                    
        except (Timeout, ConnectionError, RequestException) as e:
            logger.debug(f"[CTLog] crt.sh 查询失败: {e}")
    
    def _parse_crt_sh_entry(self, entry: Dict) -> Optional[CertificateInfo]:
        try:
            not_before = entry.get("entry_timestamp", "")
            not_after = entry.get("not_after", "")
            
            is_expired = False
            if not_after:
                try:
                    expiry = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
                    is_expired = expiry < datetime.now(expiry.tzinfo)
                except (ValueError, TypeError):
                    pass
            
            return CertificateInfo(
                domain=self.domain,
                issuer=entry.get("issuer_name", ""),
                issuer_cn=self._extract_cn(entry.get("issuer_name", "")),
                subject=entry.get("name_value", ""),
                subject_cn=entry.get("common_name", ""),
                serial_number=str(entry.get("serial_number", "")),
                not_before=not_before,
                not_after=not_after,
                fingerprint_sha256="",
                fingerprint_sha1="",
                is_expired=is_expired,
                is_self_signed=False,
                san_domains=entry.get("name_value", "").split("\n"),
                source="crt.sh"
            )
        except Exception:
            return None
    
    def _parse_crt_sh_html(self, html: str) -> None:
        pattern = r'<TD[^>]*>([^<]+)</TD>\s*<TD[^>]*>([^<]+)</TD>'
        
        for match in re.finditer(pattern, html, re.IGNORECASE):
            domain = match.group(1).strip().lower()
            if self._is_subdomain(domain):
                self._subdomains.add(domain)
    
    def _query_censys(self) -> None:
        url = f"https://search.censys.io/api/v2/certificates/search"
        params = {
            "q": f"names: {self.domain}",
            "per_page": 20
        }
        
        try:
            response = self.session.get(
                url,
                params=params,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                data = response.json()
                
                result = data.get("result", {})
                certificates = result.get("certificates", [])
                
                for cert in certificates:
                    names = cert.get("names", [])
                    for name in names:
                        name = name.lower().strip()
                        if self._is_subdomain(name):
                            self._subdomains.add(name)
                
                logger.info(f"[CTLog] Censys 发现 {len(self._subdomains)} 个子域名")
                
        except (Timeout, ConnectionError, RequestException) as e:
            logger.debug(f"[CTLog] Censys 查询失败: {e}")
    
    def _is_subdomain(self, name: str) -> bool:
        if not name:
            return False
        
        if name.startswith("*."):
            name = name[2:]
        
        if not re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$', name):
            return False
        
        return name.endswith(self.domain) or name == self.domain
    
    def _extract_cn(self, dn: str) -> str:
        match = re.search(r'CN\s*=\s*([^,]+)', dn, re.IGNORECASE)
        return match.group(1).strip() if match else ""
    
    def _cert_to_dict(self, cert: CertificateInfo) -> Dict[str, Any]:
        return {
            "domain": cert.domain,
            "issuer": cert.issuer,
            "issuer_cn": cert.issuer_cn,
            "subject": cert.subject,
            "subject_cn": cert.subject_cn,
            "serial_number": cert.serial_number,
            "not_before": cert.not_before,
            "not_after": cert.not_after,
            "is_expired": cert.is_expired,
            "is_self_signed": cert.is_self_signed,
            "san_domains": cert.san_domains[:10],
            "source": cert.source,
        }


def query_ct_logs(domain: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    证书透明度查询便捷函数
    
    Args:
        domain: 目标域名
        config: 配置选项
        
    Returns:
        查询结果
    """
    ct = CertificateTransparency(domain, config)
    return ct.query()
