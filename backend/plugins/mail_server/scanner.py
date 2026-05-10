# -*- coding:utf-8 -*-

"""
邮件服务器检测模块
功能:
1. MX记录查询
2. SMTP服务检测（多端口）
3. SPF/DKIM/DMARC记录检测
4. 邮件服务器安全配置分析
5. 开放中继检测
6. SMTP用户枚举检测
"""

import logging
import socket
import dns.resolver
import re
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("MailServerDetector")

@dataclass
class MXRecord:
    priority: int = 0
    server: str = ""
    ip_addresses: List[str] = field(default_factory=list)

@dataclass
class SMTPInfo:
    host: str = ""
    port: int = 25
    is_reachable: bool = False
    banner: str = ""
    supports_starttls: bool = False
    supports_auth: bool = False
    auth_methods: List[str] = field(default_factory=list)
    supports_pipelining: bool = False
    supports_8bitmime: bool = False
    supports_size: bool = False
    max_size: int = 0
    is_open_relay: bool = False
    supports_vrfy: bool = False
    supports_expn: bool = False
    software: str = ""
    error: str = ""

@dataclass
class DNSRecord:
    record_type: str = ""
    value: str = ""
    exists: bool = False

@dataclass
class MailServerResult:
    domain: str = ""
    mx_records: List[MXRecord] = field(default_factory=list)
    smtp_servers: List[SMTPInfo] = field(default_factory=list)
    spf_record: Optional[DNSRecord] = None
    dkim_record: Optional[DNSRecord] = None
    dmarc_record: Optional[DNSRecord] = None
    has_mail_server: bool = False
    security_score: int = 0
    recommendations: List[str] = field(default_factory=list)
    error: str = ""

class DNSQuery:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
    
    def query_mx(self, domain: str) -> List[MXRecord]:
        records = []
        try:
            answers = self.resolver.resolve(domain, 'MX')
            for rdata in answers:
                mx = MXRecord()
                mx.priority = rdata.preference
                mx.server = str(rdata.exchange).rstrip('.')
                
                try:
                    a_answers = self.resolver.resolve(mx.server, 'A')
                    mx.ip_addresses = [str(ip) for ip in a_answers]
                except:
                    pass
                
                records.append(mx)
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            pass
        except Exception as e:
            logger.warning(f"MX查询异常: {str(e)[:50]}")
        
        return records
    
    def query_txt(self, domain: str) -> List[str]:
        records = []
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                record = ''.join([s.decode() if isinstance(s, bytes) else s for s in rdata.strings])
                records.append(record)
        except:
            pass
        return records
    
    def query_spf(self, domain: str) -> Optional[DNSRecord]:
        txt_records = self.query_txt(domain)
        for record in txt_records:
            if record.startswith("v=spf1"):
                return DNSRecord(record_type="SPF", value=record, exists=True)
        return DNSRecord(record_type="SPF", exists=False)
    
    def query_dkim(self, domain: str, selectors: List[str] = None) -> Optional[DNSRecord]:
        if selectors is None:
            selectors = ["default", "selector1", "selector2", "google", "k1", "mail", "dkim"]
        
        for selector in selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{domain}"
                answers = self.resolver.resolve(dkim_domain, 'TXT')
                for rdata in answers:
                    record = ''.join([s.decode() if isinstance(s, bytes) else s for s in rdata.strings])
                    if "v=DKIM1" in record or "k=rsa" in record:
                        return DNSRecord(record_type="DKIM", value=record, exists=True)
            except:
                pass
        
        return DNSRecord(record_type="DKIM", exists=False)
    
    def query_dmarc(self, domain: str) -> Optional[DNSRecord]:
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = self.resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                record = ''.join([s.decode() if isinstance(s, bytes) else s for s in rdata.strings])
                if record.startswith("v=DMARC1"):
                    return DNSRecord(record_type="DMARC", value=record, exists=True)
        except:
            pass
        
        return DNSRecord(record_type="DMARC", exists=False)

class SMTPDetector:
    SMTP_PORTS = [25, 465, 587, 2525]
    
    SOFTWARE_PATTERNS = {
        "Postfix": r"postfix",
        "Exim": r"exim",
        "Sendmail": r"sendmail",
        "Microsoft Exchange": r"microsoft|exchange",
        "Dovecot": r"dovecot",
        "Zimbra": r"zimbra",
        "Qmail": r"qmail",
        "Courier": r"courier",
        "Haraka": r"haraka",
    }
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    def detect(self, host: str, port: int = 25) -> SMTPInfo:
        info = SMTPInfo(host=host, port=port)
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            info.banner = banner.strip()
            info.is_reachable = True
            
            info.software = self._detect_software(info.banner)
            
            sock.send(b"EHLO test.com\r\n")
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            
            if "STARTTLS" in response.upper():
                info.supports_starttls = True
            
            if "PIPELINING" in response.upper():
                info.supports_pipelining = True
            
            if "8BITMIME" in response.upper():
                info.supports_8bitmime = True
            
            size_match = re.search(r"SIZE\s+(\d+)", response, re.IGNORECASE)
            if size_match:
                info.supports_size = True
                info.max_size = int(size_match.group(1))
            
            if "AUTH" in response.upper():
                info.supports_auth = True
                auth_match = re.search(r"AUTH\s+([^\r\n]+)", response, re.IGNORECASE)
                if auth_match:
                    info.auth_methods = auth_match.group(1).strip().split()
            
            sock.send(b"VRFY root\r\n")
            vrfy_response = sock.recv(1024).decode('utf-8', errors='ignore')
            if "250" in vrfy_response or "252" in vrfy_response:
                info.supports_vrfy = True
            
            sock.send(b"EXPN root\r\n")
            expn_response = sock.recv(1024).decode('utf-8', errors='ignore')
            if "250" in expn_response:
                info.supports_expn = True
            
            sock.send(b"QUIT\r\n")
            sock.close()
            
        except socket.timeout:
            info.is_reachable = False
            info.error = "连接超时"
        except socket.error as e:
            info.is_reachable = False
            info.error = f"连接失败: {str(e)[:50]}"
            logger.warning(f"SMTP连接失败 {host}:{port}: {str(e)[:50]}")
        except Exception as e:
            info.is_reachable = False
            info.error = f"检测异常: {str(e)[:50]}"
            logger.warning(f"SMTP检测异常: {str(e)[:50]}")
        
        return info
    
    def detect_open_relay(self, host: str, port: int = 25, test_email: str = "test@example.com") -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            sock.recv(1024)
            
            sock.send(b"EHLO test.com\r\n")
            sock.recv(1024)
            
            sock.send(f"MAIL FROM:<{test_email}>\r\n".encode())
            mail_from_response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if "250" not in mail_from_response:
                sock.close()
                return False
            
            sock.send(f"RCPT TO:<external@external-domain-test-12345.com>\r\n".encode())
            rcpt_to_response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            sock.send(b"QUIT\r\n")
            sock.close()
            
            return "250" in rcpt_to_response
            
        except Exception as e:
            logger.warning(f"开放中继检测异常: {str(e)[:50]}")
            return False
    
    def _detect_software(self, banner: str) -> str:
        banner_lower = banner.lower()
        for software, pattern in self.SOFTWARE_PATTERNS.items():
            if re.search(pattern, banner_lower):
                return software
        return ""
    
    def detect_multi_port(self, host: str) -> List[SMTPInfo]:
        results = []
        for port in self.SMTP_PORTS:
            info = self.detect(host, port)
            if info.is_reachable:
                results.append(info)
        return results

class MailServerAnalyzer:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 10)
        self._dns = DNSQuery(timeout=self.timeout)
        self._smtp = SMTPDetector(timeout=self.timeout)
    
    def analyze(self, domain: str) -> MailServerResult:
        result = MailServerResult(domain=domain)
        
        domain = domain.strip().lower()
        if domain.startswith(("http://", "https://")):
            domain = domain.split("//")[-1].split("/")[0]
        
        result.mx_records = self._dns.query_mx(domain)
        
        if result.mx_records:
            result.has_mail_server = True
            
            for mx in result.mx_records[:3]:
                for ip in mx.ip_addresses[:1]:
                    smtp_infos = self._smtp.detect_multi_port(ip)
                    for smtp_info in smtp_infos:
                        smtp_info.host = mx.server
                        result.smtp_servers.append(smtp_info)
                    
                    if smtp_infos:
                        is_open_relay = self._smtp.detect_open_relay(ip)
                        for smtp_info in result.smtp_servers:
                            if smtp_info.host == mx.server:
                                smtp_info.is_open_relay = is_open_relay
        
        result.spf_record = self._dns.query_spf(domain)
        result.dkim_record = self._dns.query_dkim(domain)
        result.dmarc_record = self._dns.query_dmarc(domain)
        
        result.security_score = self._calculate_security_score(result)
        result.recommendations = self._generate_recommendations(result)
        
        return result
    
    def _calculate_security_score(self, result: MailServerResult) -> int:
        score = 0
        
        if result.has_mail_server:
            score += 10
        
        if result.spf_record and result.spf_record.exists:
            score += 20
            if "-all" in result.spf_record.value:
                score += 10
            elif "~all" in result.spf_record.value:
                score += 5
        
        if result.dkim_record and result.dkim_record.exists:
            score += 25
        
        if result.dmarc_record and result.dmarc_record.exists:
            score += 25
            if "p=reject" in result.dmarc_record.value:
                score += 10
            elif "p=quarantine" in result.dmarc_record.value:
                score += 5
        
        for smtp in result.smtp_servers:
            if smtp.supports_starttls:
                score += 5
            if smtp.is_open_relay:
                score -= 20
            if smtp.supports_vrfy:
                score -= 5
            if smtp.supports_expn:
                score -= 5
        
        return max(0, min(100, score))
    
    def _generate_recommendations(self, result: MailServerResult) -> List[str]:
        recommendations = []
        
        if not result.spf_record or not result.spf_record.exists:
            recommendations.append("建议添加SPF记录以防止邮件伪造")
        
        if not result.dkim_record or not result.dkim_record.exists:
            recommendations.append("建议配置DKIM签名以提高邮件可信度")
        
        if not result.dmarc_record or not result.dmarc_record.exists:
            recommendations.append("建议配置DMARC策略以增强邮件安全")
        
        for smtp in result.smtp_servers:
            if not smtp.supports_starttls:
                recommendations.append(f"建议在 {smtp.host}:{smtp.port} 启用STARTTLS加密")
            
            if smtp.is_open_relay:
                recommendations.append(f"警告: {smtp.host} 存在开放中继漏洞，请立即修复")
            
            if smtp.supports_vrfy or smtp.supports_expn:
                recommendations.append(f"建议在 {smtp.host} 禁用VRFY/EXPN命令以防止用户枚举")
        
        if result.spf_record and result.spf_record.exists:
            if "+all" in result.spf_record.value:
                recommendations.append("SPF记录使用+all过于宽松，建议使用~all或-all")
        
        return recommendations

def detect_mail_server(domain: str) -> Dict[str, Any]:
    analyzer = MailServerAnalyzer()
    result = analyzer.analyze(domain)
    
    return {
        "success": True,
        "domain": result.domain,
        "has_mail_server": result.has_mail_server,
        "mx_records": [
            {"priority": mx.priority, "server": mx.server, "ips": mx.ip_addresses}
            for mx in result.mx_records
        ],
        "smtp_servers": [
            {
                "host": smtp.host,
                "port": smtp.port,
                "is_reachable": smtp.is_reachable,
                "supports_starttls": smtp.supports_starttls,
                "supports_auth": smtp.supports_auth,
                "auth_methods": smtp.auth_methods,
                "supports_pipelining": smtp.supports_pipelining,
                "is_open_relay": smtp.is_open_relay,
                "supports_vrfy": smtp.supports_vrfy,
                "supports_expn": smtp.supports_expn,
                "software": smtp.software,
                "banner": smtp.banner[:100] if smtp.banner else "",
            }
            for smtp in result.smtp_servers
        ],
        "spf": {
            "exists": result.spf_record.exists if result.spf_record else False,
            "value": result.spf_record.value if result.spf_record else ""
        },
        "dkim": {
            "exists": result.dkim_record.exists if result.dkim_record else False,
        },
        "dmarc": {
            "exists": result.dmarc_record.exists if result.dmarc_record else False,
            "value": result.dmarc_record.value if result.dmarc_record else ""
        },
        "security_score": result.security_score,
        "recommendations": result.recommendations,
        "error": result.error
    }

if __name__ == '__main__':
    test_domains = ["gmail.com", "qq.com", "github.com"]
    for domain in test_domains:
        print(f"\n{'='*60}")
        print(f"检测域名: {domain}")
        result = detect_mail_server(domain)
        print(f"有邮件服务器: {result['has_mail_server']}")
        print(f"安全评分: {result['security_score']}/100")
        
        if result['mx_records']:
            print(f"MX记录:")
            for mx in result['mx_records']:
                print(f"  - {mx['priority']} {mx['server']}")
        
        print(f"SPF记录: {'已配置' if result['spf']['exists'] else '未配置'}")
        print(f"DKIM记录: {'已配置' if result['dkim']['exists'] else '未配置'}")
        print(f"DMARC记录: {'已配置' if result['dmarc']['exists'] else '未配置'}")
        
        if result['recommendations']:
            print(f"安全建议:")
            for rec in result['recommendations']:
                print(f"  - {rec}")
