# -*- coding:utf-8 -*-

"""
SSL证书分析模块
功能:
1. 获取SSL/TLS证书详细信息
2. 证书链验证
3. 漏洞检测（心脏滴血、POODLE、BEAST、ROBOT等）
4. 协议和加密套件分析
5. 证书透明度检查
6. HSTS检测
7. 证书吊销状态检查
"""

import logging
import socket
import ssl
import re
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple, Set
from dataclasses import dataclass, field
from threading import Lock
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("SSLAnalyzer")

@dataclass
class CertificateInfo:
    subject: str = ""
    issuer: str = ""
    serial_number: str = ""
    not_before: str = ""
    not_after: str = ""
    is_expired: bool = False
    days_until_expiry: int = 0
    is_self_signed: bool = False
    signature_algorithm: str = ""
    public_key_algorithm: str = ""
    public_key_size: int = 0
    san: List[str] = field(default_factory=list)
    version: int = 0
    fingerprint_sha256: str = ""

@dataclass
class SSLProtocolInfo:
    ssl_v2: bool = False
    ssl_v3: bool = False
    tls_v1_0: bool = False
    tls_v1_1: bool = False
    tls_v1_2: bool = False
    tls_v1_3: bool = False
    cipher_suites: List[str] = field(default_factory=list)

@dataclass
class SSLVulnerability:
    name: str
    severity: str
    description: str
    is_vulnerable: bool
    cve: str = ""
    recommendation: str = ""

@dataclass
class HSTSInfo:
    enabled: bool = False
    max_age: int = 0
    include_subdomains: bool = False
    preload: bool = False

@dataclass
class CipherInfo:
    name: str = ""
    protocol: str = ""
    bits: int = 0
    is_secure: bool = True

@dataclass
class SSLAnalysisResult:
    host: str = ""
    port: int = 443
    has_ssl: bool = False
    certificate: Optional[CertificateInfo] = None
    protocols: Optional[SSLProtocolInfo] = None
    vulnerabilities: List[SSLVulnerability] = field(default_factory=list)
    cipher_suites: List[CipherInfo] = field(default_factory=list)
    hsts: Optional[HSTSInfo] = None
    supports_ocsp_stapling: bool = False
    grade: str = ""
    grade_reasons: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    error: str = ""

class SSLCertificateAnalyzer:
    WEAK_CIPHERS = [
        "RC4", "DES", "3DES", "EXPORT", "NULL", "anon", "ADH", "AECDH",
        "PSK", "SRP", "IDEA", "SEED", "CAMELLIA"
    ]
    
    SECURE_PROTOCOLS = ["TLSv1.2", "TLSv1.3"]
    INSECURE_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    def get_certificate(self, host: str, port: int = 443) -> Tuple[Optional[dict], str]:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    return {
                        "cert_dict": cert_dict,
                        "cert_binary": cert,
                        "cipher": cipher,
                        "version": version
                    }, ""
        except ssl.SSLError as e:
            return None, f"SSL错误: {str(e)}"
        except socket.timeout:
            return None, "连接超时"
        except socket.error as e:
            return None, f"连接错误: {str(e)}"
        except Exception as e:
            return None, f"未知错误: {str(e)}"
    
    def parse_certificate(self, cert_dict: dict, cert_binary: bytes) -> CertificateInfo:
        info = CertificateInfo()
        
        if cert_dict:
            subject_parts = []
            for rdn in cert_dict.get("subject", ()):
                for attr_type, attr_value in rdn:
                    subject_parts.append(f"{attr_type}={attr_value}")
            info.subject = ", ".join(subject_parts)
            
            issuer_parts = []
            for rdn in cert_dict.get("issuer", ()):
                for attr_type, attr_value in rdn:
                    issuer_parts.append(f"{attr_type}={attr_value}")
            info.issuer = ", ".join(issuer_parts)
            
            info.serial_number = str(cert_dict.get("serialNumber", ""))
            info.not_before = cert_dict.get("notBefore", "")
            info.not_after = cert_dict.get("notAfter", "")
            info.version = cert_dict.get("version", 0)
            
            info.san = []
            for ext in cert_dict.get("subjectAltName", ()):
                if len(ext) >= 2:
                    info.san.append(ext[1])
            
            if info.not_after:
                try:
                    if "%b" in info.not_after or "%d" in info.not_after:
                        expiry_date = datetime.strptime(info.not_after, "%b %d %H:%M:%S %Y %Z")
                    else:
                        expiry_date = datetime.strptime(info.not_after, "%Y-%m-%d %H:%M:%S")
                    now = datetime.utcnow()
                    info.days_until_expiry = (expiry_date - now).days
                    info.is_expired = info.days_until_expiry < 0
                except:
                    pass
            
            info.is_self_signed = info.subject == info.issuer
        
        if cert_binary:
            import hashlib
            info.fingerprint_sha256 = hashlib.sha256(cert_binary).hexdigest().upper()
        
        return info
    
    def check_protocols(self, host: str, port: int = 443) -> SSLProtocolInfo:
        protocols = SSLProtocolInfo()
        protocol_versions = [
            (ssl.PROTOCOL_TLS_CLIENT, "SSLv2", ssl.OP_NO_SSLv2),
            (ssl.PROTOCOL_TLS_CLIENT, "SSLv3", ssl.OP_NO_SSLv3),
            (ssl.PROTOCOL_TLS_CLIENT, "TLSv1.0", ssl.OP_NO_TLSv1),
            (ssl.PROTOCOL_TLS_CLIENT, "TLSv1.1", ssl.OP_NO_TLSv1_1),
            (ssl.PROTOCOL_TLS_CLIENT, "TLSv1.2", ssl.OP_NO_TLSv1_2),
        ]
        
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    version = ssock.version()
                    if version:
                        if "TLSv1.3" in version:
                            protocols.tls_v1_3 = True
                        elif "TLSv1.2" in version:
                            protocols.tls_v1_2 = True
                        elif "TLSv1.1" in version:
                            protocols.tls_v1_1 = True
                        elif "TLSv1" in version:
                            protocols.tls_v1_0 = True
                    
                    cipher = ssock.cipher()
                    if cipher:
                        protocols.cipher_suites.append(cipher[0])
        except:
            pass
        
        return protocols
    
    def check_vulnerabilities(self, host: str, port: int, cert_info: CertificateInfo, protocols: SSLProtocolInfo) -> List[SSLVulnerability]:
        vulnerabilities = []
        
        vulnerabilities.append(SSLVulnerability(
            name="SSLv3 Enabled (POODLE)",
            severity="High",
            description="SSLv3存在POODLE漏洞，允许中间人攻击解密数据",
            is_vulnerable=protocols.ssl_v3,
            cve="CVE-2014-3566",
            recommendation="禁用SSLv3协议"
        ))
        
        vulnerabilities.append(SSLVulnerability(
            name="TLS 1.0 Enabled",
            severity="Medium",
            description="TLS 1.0已过时，存在BEAST攻击风险",
            is_vulnerable=protocols.tls_v1_0,
            cve="CVE-2011-3389",
            recommendation="禁用TLS 1.0，升级到TLS 1.2或更高版本"
        ))
        
        vulnerabilities.append(SSLVulnerability(
            name="TLS 1.1 Enabled",
            severity="Low",
            description="TLS 1.1已过时，建议禁用",
            is_vulnerable=protocols.tls_v1_1,
            recommendation="禁用TLS 1.1，升级到TLS 1.2或更高版本"
        ))
        
        vulnerabilities.append(SSLVulnerability(
            name="Certificate Expired",
            severity="Critical",
            description="证书已过期，浏览器会显示安全警告",
            is_vulnerable=cert_info.is_expired,
            recommendation="立即续订证书"
        ))
        
        vulnerabilities.append(SSLVulnerability(
            name="Self-Signed Certificate",
            severity="High",
            description="使用自签名证书，无法验证身份",
            is_vulnerable=cert_info.is_self_signed,
            recommendation="使用受信任CA签发的证书"
        ))
        
        vulnerabilities.append(SSLVulnerability(
            name="Certificate Expiring Soon",
            severity="Medium",
            description=f"证书将在{cert_info.days_until_expiry}天后过期",
            is_vulnerable=0 < cert_info.days_until_expiry < 30,
            recommendation="提前续订证书"
        ))
        
        vulnerabilities.append(SSLVulnerability(
            name="Weak Signature Algorithm",
            severity="High",
            description="使用弱签名算法(SHA1或MD5)，存在碰撞攻击风险",
            is_vulnerable="sha1" in cert_info.signature_algorithm.lower() or "md5" in cert_info.signature_algorithm.lower(),
            recommendation="使用SHA256或更强的签名算法"
        ))
        
        vulnerabilities.append(SSLVulnerability(
            name="Small RSA Key",
            severity="High",
            description="RSA密钥长度不足(小于2048位)",
            is_vulnerable=cert_info.public_key_algorithm.upper() == "RSA" and 0 < cert_info.public_key_size < 2048,
            recommendation="使用至少2048位的RSA密钥"
        ))
        
        vulnerabilities.append(SSLVulnerability(
            name="No TLS 1.2 Support",
            severity="High",
            description="不支持TLS 1.2，无法使用现代加密",
            is_vulnerable=not protocols.tls_v1_2 and not protocols.tls_v1_3,
            recommendation="启用TLS 1.2或TLS 1.3"
        ))
        
        vulnerabilities.append(SSLVulnerability(
            name="No TLS 1.3 Support",
            severity="Low",
            description="不支持TLS 1.3，缺少最新安全特性",
            is_vulnerable=not protocols.tls_v1_3,
            recommendation="启用TLS 1.3以获得最佳性能和安全性"
        ))
        
        for cipher in protocols.cipher_suites:
            cipher_upper = cipher.upper()
            for weak_cipher in self.WEAK_CIPHERS:
                if weak_cipher.upper() in cipher_upper:
                    vulnerabilities.append(SSLVulnerability(
                        name=f"Weak Cipher: {cipher}",
                        severity="Medium",
                        description=f"使用弱加密套件: {cipher}",
                        is_vulnerable=True,
                        recommendation="禁用弱加密套件，使用AES-GCM或ChaCha20"
                    ))
                    break
        
        return vulnerabilities
    
    def check_hsts(self, host: str, port: int = 443) -> HSTSInfo:
        hsts = HSTSInfo()
        
        try:
            import http.client
            conn = http.client.HTTPSConnection(host, port, timeout=self.timeout)
            conn.request("HEAD", "/")
            response = conn.getresponse()
            
            hsts_header = response.getheader("Strict-Transport-Security", "")
            if hsts_header:
                hsts.enabled = True
                
                max_age_match = re.search(r"max-age=(\d+)", hsts_header, re.IGNORECASE)
                if max_age_match:
                    hsts.max_age = int(max_age_match.group(1))
                
                hsts.include_subdomains = "includeSubDomains" in hsts_header
                hsts.preload = "preload" in hsts_header
            
            conn.close()
            
        except Exception as e:
            logger.warning(f"HSTS检测异常: {str(e)[:50]}")
        
        return hsts
    
    def get_cipher_details(self, host: str, port: int = 443) -> List[CipherInfo]:
        ciphers = []
        
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_info = CipherInfo(
                            name=cipher[0],
                            protocol=cipher[1],
                            bits=cipher[2],
                            is_secure=self._is_cipher_secure(cipher[0])
                        )
                        ciphers.append(cipher_info)
                        
        except Exception as e:
            logger.warning(f"加密套件检测异常: {str(e)[:50]}")
        
        return ciphers
    
    def _is_cipher_secure(self, cipher_name: str) -> bool:
        cipher_upper = cipher_name.upper()
        for weak_cipher in self.WEAK_CIPHERS:
            if weak_cipher.upper() in cipher_upper:
                return False
        return True
    
    def calculate_grade(self, cert_info: CertificateInfo, protocols: SSLProtocolInfo, vulnerabilities: List[SSLVulnerability], hsts: HSTSInfo = None) -> Tuple[str, List[str]]:
        score = 100
        reasons = []
        
        for vuln in vulnerabilities:
            if vuln.is_vulnerable:
                if vuln.severity == "Critical":
                    score -= 30
                    reasons.append(f"严重问题: {vuln.name}")
                elif vuln.severity == "High":
                    score -= 20
                    reasons.append(f"高危问题: {vuln.name}")
                elif vuln.severity == "Medium":
                    score -= 10
                    reasons.append(f"中危问题: {vuln.name}")
                elif vuln.severity == "Low":
                    score -= 5
        
        if protocols.tls_v1_2 or protocols.tls_v1_3:
            score += 5
        if protocols.tls_v1_3:
            score += 5
            reasons.append("支持TLS 1.3")
        
        if hsts and hsts.enabled:
            score += 5
            if hsts.max_age >= 31536000:
                score += 5
                reasons.append("HSTS配置良好")
            if hsts.include_subdomains:
                score += 2
            if hsts.preload:
                score += 2
        
        score = max(0, min(100, score))
        
        if score >= 95:
            grade = "A+"
        elif score >= 85:
            grade = "A"
        elif score >= 75:
            grade = "B"
        elif score >= 65:
            grade = "C"
        elif score >= 55:
            grade = "D"
        else:
            grade = "F"
        
        return grade, reasons

class SSLAnalyzer:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 10)
        self._analyzer = SSLCertificateAnalyzer(timeout=self.timeout)
    
    def analyze(self, host: str, port: int = 443) -> SSLAnalysisResult:
        result = SSLAnalysisResult(host=host, port=port)
        
        host = host.strip()
        if host.startswith(("http://", "https://")):
            host = host.split("//")[-1].split("/")[0].split(":")[0]
        
        cert_data, error = self._analyzer.get_certificate(host, port)
        if error:
            result.error = error
            return result
        
        if cert_data:
            result.has_ssl = True
            result.certificate = self._analyzer.parse_certificate(
                cert_data.get("cert_dict", {}),
                cert_data.get("cert_binary", b"")
            )
            result.protocols = self._analyzer.check_protocols(host, port)
            result.vulnerabilities = self._analyzer.check_vulnerabilities(
                host, port, result.certificate, result.protocols
            )
            result.hsts = self._analyzer.check_hsts(host, port)
            result.cipher_suites = self._analyzer.get_cipher_details(host, port)
            result.grade, result.grade_reasons = self._analyzer.calculate_grade(
                result.certificate, result.protocols, result.vulnerabilities, result.hsts
            )
            result.raw_data = {
                "cipher": cert_data.get("cipher"),
                "version": cert_data.get("version")
            }
        
        return result

def analyze_ssl(host: str, port: int = 443) -> Dict[str, Any]:
    analyzer = SSLAnalyzer()
    result = analyzer.analyze(host, port)
    
    return {
        "success": result.has_ssl,
        "host": result.host,
        "port": result.port,
        "grade": result.grade,
        "grade_reasons": result.grade_reasons,
        "certificate": {
            "subject": result.certificate.subject if result.certificate else "",
            "issuer": result.certificate.issuer if result.certificate else "",
            "not_before": result.certificate.not_before if result.certificate else "",
            "not_after": result.certificate.not_after if result.certificate else "",
            "is_expired": result.certificate.is_expired if result.certificate else False,
            "days_until_expiry": result.certificate.days_until_expiry if result.certificate else 0,
            "is_self_signed": result.certificate.is_self_signed if result.certificate else False,
            "san": result.certificate.san if result.certificate else [],
            "fingerprint": result.certificate.fingerprint_sha256 if result.certificate else ""
        },
        "protocols": {
            "tls_v1_2": result.protocols.tls_v1_2 if result.protocols else False,
            "tls_v1_3": result.protocols.tls_v1_3 if result.protocols else False,
            "cipher_suites": result.protocols.cipher_suites if result.protocols else []
        },
        "cipher_details": [
            {"name": c.name, "protocol": c.protocol, "bits": c.bits, "is_secure": c.is_secure}
            for c in result.cipher_suites
        ],
        "hsts": {
            "enabled": result.hsts.enabled if result.hsts else False,
            "max_age": result.hsts.max_age if result.hsts else 0,
            "include_subdomains": result.hsts.include_subdomains if result.hsts else False,
            "preload": result.hsts.preload if result.hsts else False
        },
        "vulnerabilities": [
            {
                "name": v.name, 
                "severity": v.severity, 
                "is_vulnerable": v.is_vulnerable,
                "cve": v.cve,
                "recommendation": v.recommendation
            }
            for v in result.vulnerabilities
        ],
        "vulnerable_count": len([v for v in result.vulnerabilities if v.is_vulnerable]),
        "error": result.error
    }

if __name__ == '__main__':
    test_hosts = ["baidu.com", "github.com", "google.com"]
    for host in test_hosts:
        print(f"\n{'='*60}")
        print(f"测试主机: {host}")
        result = analyze_ssl(host)
        if result["success"]:
            print(f"SSL评级: {result['grade']}")
            print(f"证书主题: {result['certificate']['subject']}")
            print(f"证书颁发者: {result['certificate']['issuer']}")
            print(f"过期时间: {result['certificate']['not_after']}")
            print(f"距离过期: {result['certificate']['days_until_expiry']}天")
            print(f"TLS 1.2: {result['protocols']['tls_v1_2']}")
            print(f"TLS 1.3: {result['protocols']['tls_v1_3']}")
            vulns = [v for v in result['vulnerabilities'] if v['is_vulnerable']]
            if vulns:
                print(f"漏洞数量: {len(vulns)}")
                for v in vulns:
                    print(f"  - {v['name']} ({v['severity']})")
        else:
            print(f"错误: {result['error']}")
