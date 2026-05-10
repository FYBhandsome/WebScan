# -*- coding:utf-8 -*-

"""
Whois查询模块
功能:
1. 域名Whois信息查询
2. IP Whois信息查询
3. 多数据源聚合查询
4. 注册信息解析
5. 域名状态检测
6. 隐私保护检测
"""

import logging
import re
import socket
import time
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from threading import Lock
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("WhoisQuery")

@dataclass
class WhoisResult:
    query: str = ""
    query_type: str = ""
    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    updated_date: str = ""
    name_servers: List[str] = field(default_factory=list)
    status: List[str] = field(default_factory=list)
    registrant_name: str = ""
    registrant_email: str = ""
    registrant_phone: str = ""
    registrant_organization: str = ""
    registrant_country: str = ""
    registrant_state: str = ""
    registrant_city: str = ""
    admin_name: str = ""
    admin_email: str = ""
    tech_name: str = ""
    tech_email: str = ""
    dnssec: str = ""
    domain_id: str = ""
    domain_age_days: int = 0
    days_until_expiry: int = 0
    is_privacy_protected: bool = False
    is_expired: bool = False
    is_expiring_soon: bool = False
    has_result: bool = False
    source: str = ""
    sources_used: List[str] = field(default_factory=list)
    raw_data: str = ""
    error: str = ""

class WhoisParser:
    PRIVACY_PATTERNS = [
        r"privacy",
        r"protect",
        r"guard",
        r"shield",
        r"proxy",
        r"whois.*guard",
        r"domains.*by.*proxy",
        r"private.*registration",
        r"data.*protected",
        r"redacted.*for.*privacy",
    ]
    
    DATE_FORMATS = [
        "%Y-%m-%d",
        "%Y-%m-%d %H:%M:%S",
        "%d-%m-%Y",
        "%d-%b-%Y",
        "%b %d %Y",
        "%b %d, %Y",
        "%d %b %Y",
        "%Y.%m.%d",
        "%Y/%m/%d",
        "%d/%m/%Y",
    ]
    
    @staticmethod
    def parse_domain_whois(raw_data: str) -> Dict[str, Any]:
        result = {}
        
        patterns = {
            "registrar": [
                r"Registrar:\s*(.+)",
                r"Registrar Name:\s*(.+)",
                r"Sponsoring Registrar:\s*(.+)",
                r"Registrar Organization:\s*(.+)",
            ],
            "creation_date": [
                r"Creation Date:\s*(.+)",
                r"Created:\s*(.+)",
                r"Registered:\s*(.+)",
                r"Registration Time:\s*(.+)",
                r"Domain Registration Date:\s*(.+)",
            ],
            "expiration_date": [
                r"Expiration Date:\s*(.+)",
                r"Expires:\s*(.+)",
                r"Expiry Date:\s*(.+)",
                r"Registry Expiry Date:\s*(.+)",
                r"Domain Expiration Date:\s*(.+)",
            ],
            "updated_date": [
                r"Updated Date:\s*(.+)",
                r"Last Updated:\s*(.+)",
                r"Modified:\s*(.+)",
                r"Last Modified:\s*(.+)",
            ],
            "name_servers": [
                r"Name Server:\s*(.+)",
                r"nserver:\s*(.+)",
                r"Nameservers:\s*\n((?:\s+.+\n)+)",
                r"DNS Servers:\s*(.+)",
            ],
            "status": [
                r"Status:\s*(.+)",
                r"Domain Status:\s*(.+)",
                r"state:\s*(.+)",
            ],
            "registrant_name": [
                r"Registrant Name:\s*(.+)",
                r"Registrant:\s*(.+)",
                r"Registrant Contact Name:\s*(.+)",
            ],
            "registrant_email": [
                r"Registrant Email:\s*(.+)",
                r"Email:\s*(.+)",
                r"Registrant Contact Email:\s*(.+)",
            ],
            "registrant_organization": [
                r"Registrant Organization:\s*(.+)",
                r"Org:\s*(.+)",
                r"Registrant Contact Organization:\s*(.+)",
            ],
            "registrant_country": [
                r"Registrant Country:\s*(.+)",
                r"Country:\s*(.+)",
            ],
            "registrant_state": [
                r"Registrant State/Province:\s*(.+)",
                r"State:\s*(.+)",
            ],
            "registrant_city": [
                r"Registrant City:\s*(.+)",
                r"City:\s*(.+)",
            ],
            "dnssec": [
                r"DNSSEC:\s*(.+)",
            ],
            "domain_id": [
                r"Domain ID:\s*(.+)",
                r"Registry Domain ID:\s*(.+)",
            ],
        }
        
        for field_name, pattern_list in patterns.items():
            for pattern in pattern_list:
                matches = re.findall(pattern, raw_data, re.IGNORECASE | re.MULTILINE)
                if matches:
                    if field_name in ["name_servers", "status"]:
                        result[field_name] = [m.strip() for m in matches if m.strip()]
                    else:
                        result[field_name] = matches[0].strip()
                    break
        
        return result
    
    @staticmethod
    def parse_ip_whois(raw_data: str) -> Dict[str, Any]:
        result = {}
        
        patterns = {
            "network_name": [r"NetName:\s*(.+)", r"network:\s*name:\s*(.+)"],
            "network_range": [r"NetRange:\s*(.+)", r"inetnum:\s*(.+)"],
            "cidr": [r"CIDR:\s*(.+)"],
            "organization": [r"Organization:\s*(.+)", r"owner:\s*(.+)"],
            "country": [r"Country:\s*(.+)", r"country:\s*(.+)"],
            "updated": [r"Updated:\s*(.+)", r"last-modified:\s*(.+)"],
        }
        
        for field_name, pattern_list in patterns.items():
            for pattern in pattern_list:
                matches = re.findall(pattern, raw_data, re.IGNORECASE)
                if matches:
                    result[field_name] = matches[0].strip()
                    break
        
        return result
    
    @staticmethod
    def detect_privacy_protection(raw_data: str, registrant_name: str = "", registrant_email: str = "") -> bool:
        combined = f"{raw_data} {registrant_name} {registrant_email}".lower()
        for pattern in WhoisParser.PRIVACY_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                return True
        return False
    
    @staticmethod
    def calculate_domain_age(creation_date: str) -> int:
        if not creation_date:
            return 0
        
        from datetime import datetime
        
        for fmt in WhoisParser.DATE_FORMATS:
            try:
                created = datetime.strptime(creation_date.split()[0], fmt)
                return (datetime.now() - created).days
            except:
                continue
        
        return 0
    
    @staticmethod
    def calculate_days_until_expiry(expiration_date: str) -> int:
        if not expiration_date:
            return 0
        
        from datetime import datetime
        
        for fmt in WhoisParser.DATE_FORMATS:
            try:
                expiry = datetime.strptime(expiration_date.split()[0], fmt)
                days = (expiry - datetime.now()).days
                return max(0, days)
            except:
                continue
        
        return 0

class WhoisAPI:
    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"]
        )
        session.mount("http://", HTTPAdapter(max_retries=retry_strategy))
        session.mount("https://", HTTPAdapter(max_retries=retry_strategy))
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/json",
        })
        return session
    
    def query_whois_api(self, query: str) -> WhoisResult:
        result = WhoisResult(query=query, source="whois-api")
        try:
            url = f"https://api.whois.vu/?q={query}"
            response = self.session.get(url, timeout=self.timeout)
            data = response.json()
            
            if data.get("error"):
                result.error = data.get("error")
                return result
            
            result.has_result = True
            result.registrar = data.get("registrar", "")
            result.creation_date = data.get("created", "")
            result.expiration_date = data.get("expires", "")
            result.updated_date = data.get("changed", "")
            result.registrant_name = data.get("owner", "")
            result.registrant_country = data.get("country", "")
            result.name_servers = data.get("nserver", "").split() if data.get("nserver") else []
            result.raw_data = str(data)
            result.sources_used.append("whois-api")
            
        except Exception as e:
            result.error = f"whois-api查询异常: {str(e)[:50]}"
        
        return result
    
    def query_whoisjson(self, domain: str) -> WhoisResult:
        result = WhoisResult(query=domain, source="whoisjson")
        try:
            url = f"https://whoisjson.com/whois/{domain}"
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                result.has_result = True
                
                domain_info = data.get("domain", {})
                registrar_info = data.get("registrar", {})
                
                result.registrar = registrar_info.get("name", "")
                result.creation_date = domain_info.get("created_date", "")
                result.expiration_date = domain_info.get("expiration_date", "")
                result.updated_date = domain_info.get("updated_date", "")
                result.domain_id = domain_info.get("id", "")
                
                nameservers = data.get("nameservers", [])
                result.name_servers = [ns.get("host", "") for ns in nameservers if ns.get("host")]
                
                result.sources_used.append("whoisjson")
                result.raw_data = str(data)[:1000]
                
        except Exception as e:
            result.error = f"whoisjson查询异常: {str(e)[:50]}"
        
        return result
    
    def query_ip_api(self, ip: str) -> WhoisResult:
        result = WhoisResult(query=ip, query_type="ip", source="ip-api")
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,asname,query"
            response = self.session.get(url, timeout=self.timeout)
            data = response.json()
            
            if data.get("status") != "success":
                result.error = data.get("message", "查询失败")
                return result
            
            result.has_result = True
            result.registrant_organization = data.get("org", "")
            result.registrant_country = data.get("country", "")
            result.registrant_state = data.get("regionName", "")
            result.registrant_city = data.get("city", "")
            result.raw_data = str(data)
            result.sources_used.append("ip-api")
            
        except Exception as e:
            result.error = f"ip-api查询异常: {str(e)[:50]}"
        
        return result
    
    def query_ipinfo(self, ip: str) -> WhoisResult:
        result = WhoisResult(query=ip, query_type="ip", source="ipinfo")
        try:
            url = f"https://ipinfo.io/{ip}/json"
            response = self.session.get(url, timeout=self.timeout)
            data = response.json()
            
            if "error" in data:
                result.error = data.get("error", {}).get("title", "查询失败")
                return result
            
            result.has_result = True
            result.registrant_organization = data.get("org", "")
            result.registrant_country = data.get("country", "")
            result.registrant_city = data.get("city", "")
            result.raw_data = str(data)
            result.sources_used.append("ipinfo")
            
        except Exception as e:
            result.error = f"ipinfo查询异常: {str(e)[:50]}"
        
        return result
    
    def query_rdap(self, domain: str) -> WhoisResult:
        result = WhoisResult(query=domain, source="rdap")
        try:
            tld = domain.split(".")[-1]
            rdap_urls = {
                "com": "https://rdap.verisign.com/com/v1/domain/",
                "net": "https://rdap.verisign.com/net/v1/domain/",
                "org": "https://rdap.publicinterestregistry.org/rdap/domain/",
                "io": "https://rdap.nic.io/domain/",
                "cn": "https://rdap.cnnic.cn/domain/",
                "xyz": "https://rdap.nic.xyz/domain/",
            }
            
            base_url = rdap_urls.get(tld, "https://rdap.org/domain/")
            url = base_url + domain
            
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                result.has_result = True
                result.raw_data = str(data)[:1000]
                result.sources_used.append("rdap")
                
                for event in data.get("events", []):
                    if event.get("eventAction") == "registration":
                        result.creation_date = event.get("eventDate", "")
                    elif event.get("eventAction") == "expiration":
                        result.expiration_date = event.get("eventDate", "")
                    elif event.get("eventAction") == "last update":
                        result.updated_date = event.get("eventDate", "")
                
                for ns in data.get("nameservers", []):
                    name = ns.get("ldhName", "")
                    if name:
                        result.name_servers.append(name.lower())
                
                for entity in data.get("entities", []):
                    for vcard in entity.get("vcardArray", []):
                        if isinstance(vcard, list):
                            for item in vcard:
                                if isinstance(item, list) and len(item) >= 4:
                                    if item[0] == "fn":
                                        result.registrant_name = item[3] if isinstance(item[3], str) else ""
                                    elif item[0] == "email":
                                        result.registrant_email = item[3] if isinstance(item[3], str) else ""
                
            else:
                result.error = f"RDAP查询失败: HTTP {response.status_code}"
                
        except Exception as e:
            result.error = f"RDAP查询异常: {str(e)[:50]}"
        
        return result

class WhoisQuery:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 15)
        self._api = WhoisAPI(timeout=self.timeout)
    
    def query(self, target: str) -> WhoisResult:
        target = target.strip().lower()
        
        if target.startswith(("http://", "https://")):
            target = target.split("//")[-1].split("/")[0]
        
        ip_pattern = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
        is_ip = bool(ip_pattern.match(target))
        
        if is_ip:
            result = self._query_ip(target)
            result.query_type = "ip"
        else:
            result = self._query_domain(target)
            result.query_type = "domain"
        
        return result
    
    def _query_domain(self, domain: str) -> WhoisResult:
        final_result = WhoisResult(query=domain, query_type="domain")
        
        apis = [
            ("whois-api", self._api.query_whois_api),
            ("whoisjson", self._api.query_whoisjson),
            ("rdap", self._api.query_rdap),
        ]
        
        for api_name, api_func in apis:
            try:
                result = api_func(domain)
                
                if result.has_result:
                    if not final_result.registrar and result.registrar:
                        final_result.registrar = result.registrar
                    if not final_result.creation_date and result.creation_date:
                        final_result.creation_date = result.creation_date
                    if not final_result.expiration_date and result.expiration_date:
                        final_result.expiration_date = result.expiration_date
                    if not final_result.updated_date and result.updated_date:
                        final_result.updated_date = result.updated_date
                    if not final_result.registrant_name and result.registrant_name:
                        final_result.registrant_name = result.registrant_name
                    if not final_result.registrant_email and result.registrant_email:
                        final_result.registrant_email = result.registrant_email
                    if not final_result.registrant_organization and result.registrant_organization:
                        final_result.registrant_organization = result.registrant_organization
                    if not final_result.registrant_country and result.registrant_country:
                        final_result.registrant_country = result.registrant_country
                    if not final_result.domain_id and result.domain_id:
                        final_result.domain_id = result.domain_id
                    
                    for ns in result.name_servers:
                        if ns not in final_result.name_servers:
                            final_result.name_servers.append(ns)
                    
                    for status in result.status:
                        if status not in final_result.status:
                            final_result.status.append(status)
                    
                    final_result.sources_used.extend(result.sources_used)
                    final_result.has_result = True
                    
            except Exception as e:
                logger.warning(f"{api_name} 查询异常: {str(e)[:50]}")
                continue
        
        if final_result.has_result:
            final_result.domain_age_days = WhoisParser.calculate_domain_age(final_result.creation_date)
            final_result.days_until_expiry = WhoisParser.calculate_days_until_expiry(final_result.expiration_date)
            final_result.is_expired = final_result.days_until_expiry == 0 and bool(final_result.expiration_date)
            final_result.is_expiring_soon = 0 < final_result.days_until_expiry < 30
            final_result.is_privacy_protected = WhoisParser.detect_privacy_protection(
                final_result.raw_data,
                final_result.registrant_name,
                final_result.registrant_email
            )
            
            if final_result.sources_used:
                final_result.source = final_result.sources_used[0]
        
        return final_result
    
    def _query_ip(self, ip: str) -> WhoisResult:
        final_result = WhoisResult(query=ip, query_type="ip")
        
        apis = [
            ("ip-api", self._api.query_ip_api),
            ("ipinfo", self._api.query_ipinfo),
        ]
        
        for api_name, api_func in apis:
            try:
                result = api_func(ip)
                
                if result.has_result:
                    if not final_result.registrant_organization and result.registrant_organization:
                        final_result.registrant_organization = result.registrant_organization
                    if not final_result.registrant_country and result.registrant_country:
                        final_result.registrant_country = result.registrant_country
                    if not final_result.registrant_state and result.registrant_state:
                        final_result.registrant_state = result.registrant_state
                    if not final_result.registrant_city and result.registrant_city:
                        final_result.registrant_city = result.registrant_city
                    
                    final_result.sources_used.extend(result.sources_used)
                    final_result.has_result = True
                    
            except Exception as e:
                logger.warning(f"{api_name} 查询异常: {str(e)[:50]}")
                continue
        
        if final_result.sources_used:
            final_result.source = final_result.sources_used[0]
        
        return final_result

def query_whois(target: str) -> Dict[str, Any]:
    query = WhoisQuery()
    result = query.query(target)
    
    return {
        "success": result.has_result,
        "query": result.query,
        "query_type": result.query_type,
        "registrar": result.registrar,
        "creation_date": result.creation_date,
        "expiration_date": result.expiration_date,
        "updated_date": result.updated_date,
        "name_servers": result.name_servers,
        "domain_id": result.domain_id,
        "domain_age_days": result.domain_age_days,
        "days_until_expiry": result.days_until_expiry,
        "is_expired": result.is_expired,
        "is_expiring_soon": result.is_expiring_soon,
        "is_privacy_protected": result.is_privacy_protected,
        "registrant": {
            "name": result.registrant_name,
            "email": result.registrant_email,
            "organization": result.registrant_organization,
            "country": result.registrant_country,
            "state": result.registrant_state,
            "city": result.registrant_city,
        },
        "status": result.status,
        "dnssec": result.dnssec,
        "source": result.source,
        "sources_used": result.sources_used,
        "error": result.error
    }

if __name__ == '__main__':
    test_targets = ["baidu.com", "github.com", "8.8.8.8"]
    for target in test_targets:
        print(f"\n{'='*60}")
        print(f"查询目标: {target}")
        result = query_whois(target)
        if result["success"]:
            print(f"类型: {result['query_type']}")
            print(f"注册商: {result['registrar']}")
            print(f"创建日期: {result['creation_date']}")
            print(f"过期日期: {result['expiration_date']}")
            print(f"注册人: {result['registrant']['name']}")
            print(f"注册机构: {result['registrant']['organization']}")
            print(f"国家: {result['registrant']['country']}")
            print(f"DNS服务器: {', '.join(result['name_servers'][:3])}")
        else:
            print(f"错误: {result['error']}")
