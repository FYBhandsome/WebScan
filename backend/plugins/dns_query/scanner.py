"""
DNS记录查询模块

功能:
- A/AAAA记录查询
- MX记录查询
- NS记录查询
- TXT记录查询
- CNAME记录查询
- SOA记录查询
- SPF/DMARC记录分析
- DNSSEC检测
"""

import re
import logging
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError

logger = logging.getLogger(__name__)

DNS_AVAILABLE = False
try:
    import dns.resolver
    import dns.rdatatype
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    logger.warning("[DNS] dnspython未安装，部分功能受限")


@dataclass
class DNSRecord:
    record_type: str
    name: str
    value: str
    ttl: int
    description: str = ""


@dataclass
class DNSResult:
    domain: str
    a_records: List[DNSRecord] = field(default_factory=list)
    aaaa_records: List[DNSRecord] = field(default_factory=list)
    mx_records: List[DNSRecord] = field(default_factory=list)
    ns_records: List[DNSRecord] = field(default_factory=list)
    txt_records: List[DNSRecord] = field(default_factory=list)
    cname_records: List[DNSRecord] = field(default_factory=list)
    soa_record: Optional[DNSRecord] = None
    spf_record: Optional[str] = None
    dmarc_record: Optional[str] = None
    dnssec_enabled: bool = False
    ip_addresses: List[str] = field(default_factory=list)


DNS_RECORD_TYPES = {
    "A": "IPv4地址记录",
    "AAAA": "IPv6地址记录",
    "MX": "邮件交换记录",
    "NS": "域名服务器记录",
    "TXT": "文本记录",
    "CNAME": "别名记录",
    "SOA": "起始授权记录",
    "PTR": "指针记录",
    "SRV": "服务记录",
    "CAA": "证书颁发机构授权记录",
}

PUBLIC_DNS_SERVERS = [
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "9.9.9.9",
    "208.67.222.222",
]


class DNSQuery:
    """
    DNS记录查询
    
    功能:
    - A/AAAA记录查询
    - MX记录查询
    - NS记录查询
    - TXT记录查询
    - CNAME记录查询
    - SOA记录查询
    - SPF/DMARC记录分析
    - DNSSEC检测
    """
    
    def __init__(self, domain: str, config: Optional[Dict[str, Any]] = None):
        self.domain = self._normalize_domain(domain)
        self.config = config or {}
        
        self.timeout = self.config.get("timeout", 10)
        self.dns_server = self.config.get("dns_server", "8.8.8.8")
        
        self._result = DNSResult(domain=self.domain)
        self._dns_available = DNS_AVAILABLE
        
        if self._dns_available:
            self._resolver = dns.resolver.Resolver()
            self._resolver.nameservers = [self.dns_server]
            self._resolver.timeout = self.timeout
            self._resolver.lifetime = self.timeout
    
    def _normalize_domain(self, domain: str) -> str:
        domain = domain.strip().lower()
        if domain.startswith(("http://", "https://")):
            domain = urlparse(domain).netloc
        domain = domain.split(":")[0]
        return domain
    
    def query(self) -> Dict[str, Any]:
        logger.info(f"[DNSQuery] 查询DNS记录: {self.domain}")
        
        if self._dns_available:
            self._query_with_dnspython()
        else:
            self._query_with_api()
        
        self._analyze_spf()
        self._query_dmarc()
        self._check_dnssec()
        
        return self._result_to_dict()
    
    def _query_with_dnspython(self) -> None:
        self._query_record_type("A")
        self._query_record_type("AAAA")
        self._query_record_type("MX")
        self._query_record_type("NS")
        self._query_record_type("TXT")
        self._query_record_type("CNAME")
        self._query_record_type("SOA")
    
    def _query_record_type(self, record_type: str) -> None:
        try:
            answers = self._resolver.resolve(self.domain, record_type)
            
            for rdata in answers:
                record = self._create_dns_record(record_type, rdata)
                self._add_record(record_type, record)
                
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            logger.debug(f"[DNSQuery] 域名不存在: {self.domain}")
        except dns.exception.DNSException as e:
            logger.debug(f"[DNSQuery] {record_type}查询失败: {e}")
    
    def _create_dns_record(self, record_type: str, rdata) -> DNSRecord:
        if record_type == "A":
            value = str(rdata.address)
            self._result.ip_addresses.append(value)
            return DNSRecord(
                record_type=record_type,
                name=self.domain,
                value=value,
                ttl=0,
                description="IPv4地址"
            )
        elif record_type == "AAAA":
            value = str(rdata.address)
            return DNSRecord(
                record_type=record_type,
                name=self.domain,
                value=value,
                ttl=0,
                description="IPv6地址"
            )
        elif record_type == "MX":
            value = str(rdata.exchange).rstrip(".")
            return DNSRecord(
                record_type=record_type,
                name=self.domain,
                value=value,
                ttl=0,
                description=f"邮件服务器 (优先级: {rdata.preference})"
            )
        elif record_type == "NS":
            value = str(rdata.target).rstrip(".")
            return DNSRecord(
                record_type=record_type,
                name=self.domain,
                value=value,
                ttl=0,
                description="域名服务器"
            )
        elif record_type == "TXT":
            value = "".join([s.decode() if isinstance(s, bytes) else s for s in rdata.strings])
            return DNSRecord(
                record_type=record_type,
                name=self.domain,
                value=value,
                ttl=0,
                description="文本记录"
            )
        elif record_type == "CNAME":
            value = str(rdata.target).rstrip(".")
            return DNSRecord(
                record_type=record_type,
                name=self.domain,
                value=value,
                ttl=0,
                description="别名"
            )
        elif record_type == "SOA":
            return DNSRecord(
                record_type=record_type,
                name=self.domain,
                value=f"{rdata.mname.rstrip('.')} {rdata.rname.rstrip('.')} {rdata.serial}",
                ttl=0,
                description=f"序列号: {rdata.serial}, 刷新: {rdata.refresh}"
            )
        
        return DNSRecord(
            record_type=record_type,
            name=self.domain,
            value=str(rdata),
            ttl=0
        )
    
    def _add_record(self, record_type: str, record: DNSRecord) -> None:
        if record_type == "A":
            self._result.a_records.append(record)
        elif record_type == "AAAA":
            self._result.aaaa_records.append(record)
        elif record_type == "MX":
            self._result.mx_records.append(record)
        elif record_type == "NS":
            self._result.ns_records.append(record)
        elif record_type == "TXT":
            self._result.txt_records.append(record)
        elif record_type == "CNAME":
            self._result.cname_records.append(record)
        elif record_type == "SOA":
            self._result.soa_record = record
    
    def _query_with_api(self) -> None:
        url = f"https://dns.google/resolve?name={self.domain}&type=ANY"
        
        try:
            response = requests.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                answers = data.get("Answer", [])
                
                for answer in answers:
                    record_type = dns.rdatatype.to_text(answer.get("type", 0))
                    value = answer.get("data", "")
                    
                    record = DNSRecord(
                        record_type=record_type,
                        name=answer.get("name", "").rstrip("."),
                        value=value,
                        ttl=answer.get("TTL", 0),
                        description=DNS_RECORD_TYPES.get(record_type, "")
                    )
                    
                    self._add_record(record_type, record)
                    
                    if record_type == "A":
                        self._result.ip_addresses.append(value)
                        
        except (Timeout, ConnectionError, RequestException) as e:
            logger.debug(f"[DNSQuery] API查询失败: {e}")
    
    def _analyze_spf(self) -> None:
        for record in self._result.txt_records:
            if record.value.startswith("v=spf1"):
                self._result.spf_record = record.value
                break
    
    def _query_dmarc(self) -> None:
        dmarc_domain = f"_dmarc.{self.domain}"
        
        if self._dns_available:
            try:
                answers = self._resolver.resolve(dmarc_domain, "TXT")
                for rdata in answers:
                    value = "".join([s.decode() if isinstance(s, bytes) else s for s in rdata.strings])
                    if value.startswith("v=DMARC1"):
                        self._result.dmarc_record = value
                        break
            except dns.exception.DNSException:
                pass
        else:
            try:
                url = f"https://dns.google/resolve?name={dmarc_domain}&type=TXT"
                response = requests.get(url, timeout=self.timeout)
                
                if response.status_code == 200:
                    data = response.json()
                    for answer in data.get("Answer", []):
                        value = answer.get("data", "")
                        if value.startswith("v=DMARC1"):
                            self._result.dmarc_record = value
                            break
            except (Timeout, ConnectionError, RequestException):
                pass
    
    def _check_dnssec(self) -> None:
        if self._dns_available:
            try:
                answers = self._resolver.resolve(self.domain, "DNSKEY")
                if answers:
                    self._result.dnssec_enabled = True
            except dns.exception.DNSException:
                pass
    
    def _result_to_dict(self) -> Dict[str, Any]:
        return {
            "success": True,
            "domain": self._result.domain,
            "records": {
                "A": [self._record_to_dict(r) for r in self._result.a_records],
                "AAAA": [self._record_to_dict(r) for r in self._result.aaaa_records],
                "MX": [self._record_to_dict(r) for r in self._result.mx_records],
                "NS": [self._record_to_dict(r) for r in self._result.ns_records],
                "TXT": [self._record_to_dict(r) for r in self._result.txt_records],
                "CNAME": [self._record_to_dict(r) for r in self._result.cname_records],
                "SOA": self._record_to_dict(self._result.soa_record) if self._result.soa_record else None,
            },
            "ip_addresses": list(set(self._result.ip_addresses)),
            "spf_record": self._result.spf_record,
            "dmarc_record": self._result.dmarc_record,
            "dnssec_enabled": self._result.dnssec_enabled,
            "security_analysis": self._analyze_security(),
        }
    
    def _record_to_dict(self, record: DNSRecord) -> Dict[str, Any]:
        return {
            "record_type": record.record_type,
            "name": record.name,
            "value": record.value,
            "ttl": record.ttl,
            "description": record.description,
        }
    
    def _analyze_security(self) -> Dict[str, Any]:
        analysis = {
            "spf_configured": self._result.spf_record is not None,
            "dmarc_configured": self._result.dmarc_record is not None,
            "dnssec_enabled": self._result.dnssec_enabled,
            "issues": [],
            "recommendations": [],
        }
        
        if not self._result.spf_record:
            analysis["issues"].append("未配置SPF记录，可能导致邮件伪造")
            analysis["recommendations"].append("建议配置SPF记录以防止邮件伪造")
        
        if not self._result.dmarc_record:
            analysis["issues"].append("未配置DMARC记录")
            analysis["recommendations"].append("建议配置DMARC记录以增强邮件安全")
        
        if not self._result.dnssec_enabled:
            analysis["issues"].append("未启用DNSSEC")
            analysis["recommendations"].append("建议启用DNSSEC以防止DNS劫持")
        
        if not self._result.mx_records and self._result.txt_records:
            for txt in self._result.txt_records:
                if "v=spf1" in txt.value:
                    analysis["issues"].append("配置了SPF但无MX记录")
                    break
        
        return analysis


def query_dns(domain: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    DNS记录查询便捷函数
    
    Args:
        domain: 目标域名
        config: 配置选项
        
    Returns:
        查询结果
    """
    dns_query = DNSQuery(domain, config)
    return dns_query.query()
