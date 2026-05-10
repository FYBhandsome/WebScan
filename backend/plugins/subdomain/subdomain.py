# -*- coding:utf-8 -*-

"""
子域名枚举模块（增强版）

功能:
1. 多接口聚合查询（ip138、chinaz、hackertarget、crt.sh等）
2. 字典爆破枚举
3. DNS记录查询（A、CNAME、MX、NS、TXT等）
4. 证书透明度日志查询
5. 搜索引擎子域名发现

特性:
- 多数据源聚合，提高发现率
- 异步并发查询，提高效率
- 智能去重和验证
- 支持自定义字典
- DNS解析验证

依赖:
- requests: HTTP请求
- dnspython: DNS查询（可选）
- concurrent.futures: 并发处理
"""

import logging
import re
import time
import socket
import hashlib
import json
from typing import List, Set, Dict, Optional, Any
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger("SubdomainScanner")


@dataclass
class SubdomainResult:
    domain: str
    sources: List[str] = field(default_factory=list)
    ip_addresses: List[str] = field(default_factory=list)
    is_valid: bool = True


@dataclass
class SubdomainConfig:
    timeout: int = 10
    max_workers: int = 10
    delay: float = 0.2
    enable_brute_force: bool = True
    enable_dns_query: bool = True
    enable_ct_logs: bool = True
    enable_search_engines: bool = True
    brute_force_depth: int = 2
    verify_dns: bool = True


REQUEST_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'Connection': 'keep-alive'
}

DNS_SERVERS = [
    '8.8.8.8',
    '8.8.4.4',
    '1.1.1.1',
    '1.0.0.1',
    '114.114.114.114',
    '223.5.5.5',
]

SUBDOMAIN_DICT_SMALL = [
    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
    'vpn', 'admin', 'portal', 'ssh', 'sftp', 'git', 'svn', 'api', 'test',
    'dev', 'staging', 'prod', 'app', 'mobile', 'm', 'wap', 'bbs', 'forum',
    'blog', 'wiki', 'docs', 'cdn', 'static', 'assets', 'img', 'images',
    'video', 'media', 'download', 'upload', 'files', 'backup', 'db',
    'mysql', 'postgres', 'mongodb', 'redis', 'memcached', 'elastic',
    'zabbix', 'nagios', 'grafana', 'prometheus', 'jenkins', 'gitlab',
    'jira', 'confluence', 'office', 'oa', 'erp', 'crm', 'hr', 'finance',
]

SUBDOMAIN_DICT_MEDIUM = SUBDOMAIN_DICT_SMALL + [
    'www1', 'www2', 'www3', 'mail1', 'mail2', 'ns3', 'ns4', 'dns1', 'dns2',
    'mx', 'mx1', 'mx2', 'imap', 'pop3', 'webdisk', 'autodiscover',
    'autoconfig', 'cpanel', 'whm', 'plesk', 'directadmin', 'ispconfig',
    'cloud', 'aws', 'azure', 'gcp', 'aliyun', 'tencent', 'huawei',
    'internal', 'intranet', 'extranet', 'secure', 'ssl', 'login',
    'signin', 'signup', 'register', 'account', 'user', 'member',
    'customer', 'client', 'partner', 'dealer', 'agent', 'reseller',
    'shop', 'store', 'mall', 'cart', 'checkout', 'pay', 'payment',
    'order', 'booking', 'reservation', 'ticket', 'support', 'help',
    'faq', 'kb', 'knowledge', 'community', 'social', 'chat', 'live',
    'news', 'press', 'media', 'events', 'calendar', 'careers', 'jobs',
    'contact', 'about', 'team', 'company', 'corp', 'investor', 'ir',
]

SUBDOMAIN_DICT_LARGE = SUBDOMAIN_DICT_MEDIUM + [
    'alpha', 'beta', 'gamma', 'delta', 'epsilon', 'zeta', 'eta', 'theta',
    'stage', 'sandbox', 'demo', 'poc', 'prototype', 'lab', 'research',
    'analytics', 'tracking', 'metrics', 'stats', 'monitor', 'status',
    'health', 'ping', 'heartbeat', 'probe', 'check', 'verify', 'validate',
    'proxy', 'gateway', 'router', 'lb', 'loadbalancer', 'haproxy', 'nginx',
    'apache', 'iis', 'tomcat', 'jboss', 'weblogic', 'websphere', 'glassfish',
    'oracle', 'sqlserver', 'sybase', 'informix', 'db2', 'sqlite', 'mariadb',
    'couchdb', 'cassandra', 'hbase', 'neo4j', 'riak', 'influxdb', 'timescaledb',
    'rabbitmq', 'kafka', 'activemq', 'zeromq', 'nsq', 'rocketmq',
    'zookeeper', 'consul', 'etcd', 'eureka', 'nacos', 'apollo', 'config',
    'registry', 'repository', 'nexus', 'artifactory', 'sonar', 'sonarqube',
    'quality', 'coverage', 'scan', 'security', 'waf', 'firewall', 'ids', 'ips',
]


def is_valid_domain(domain: str) -> bool:
    if not isinstance(domain, str) or not domain.strip():
        return False
    domain = domain.strip().lower()
    if domain.startswith('http://') or domain.startswith('https://'):
        parsed = urlparse(domain)
        domain = parsed.netloc
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'
        r'[a-zA-Z]{2,}$'
    )
    return bool(domain_pattern.match(domain))


def get_root_domain(domain: str) -> str:
    domain = domain.strip().lower()
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain


class SubdomainEnumerator:
    """
    子域名枚举器（增强版）
    
    支持多种枚举方式:
    - 多API接口聚合
    - 字典爆破
    - DNS记录查询
    - 证书透明度日志
    - 搜索引擎发现
    """
    
    def __init__(self, config: Optional[SubdomainConfig] = None):
        self.config = config or SubdomainConfig()
        self.session = self._create_session()
        self._subdomains: Dict[str, SubdomainResult] = {}
        self._dns_available = self._check_dns_module()
    
    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retry_config = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"]
        )
        session.mount("http://", HTTPAdapter(max_retries=retry_config))
        session.mount("https://", HTTPAdapter(max_retries=retry_config))
        session.headers.update(REQUEST_HEADERS)
        return session
    
    def _check_dns_module(self) -> bool:
        try:
            import dns.resolver
            return True
        except ImportError:
            logger.warning("dnspython未安装，DNS查询功能将被禁用")
            return False
    
    def enumerate(self, domain: str) -> List[str]:
        if not is_valid_domain(domain):
            logger.error(f"无效域名: {domain}")
            return []
        
        domain = domain.strip().lower()
        root_domain = get_root_domain(domain)
        self._subdomains = {}
        
        logger.info(f"开始枚举子域名: {domain}")
        
        self._query_multiple_apis(domain)
        
        if self.config.enable_ct_logs:
            self._query_ct_logs(domain)
        
        if self.config.enable_dns_query and self._dns_available:
            self._query_dns_records(domain)
        
        if self.config.enable_brute_force:
            self._brute_force_enumerate(root_domain)
        
        if self.config.enable_search_engines:
            self._search_engine_discovery(domain)
        
        if self.config.verify_dns:
            self._verify_subdomains()
        
        result = list(self._subdomains.keys())
        logger.info(f"枚举完成，共发现 {len(result)} 个子域名")
        return result
    
    def _add_subdomain(self, subdomain: str, source: str, ips: List[str] = None) -> None:
        subdomain = subdomain.strip().lower()
        if not is_valid_domain(subdomain):
            return
        
        if subdomain not in self._subdomains:
            self._subdomains[subdomain] = SubdomainResult(
                domain=subdomain,
                sources=[source],
                ip_addresses=ips or []
            )
        else:
            if source not in self._subdomains[subdomain].sources:
                self._subdomains[subdomain].sources.append(source)
            if ips:
                for ip in ips:
                    if ip not in self._subdomains[subdomain].ip_addresses:
                        self._subdomains[subdomain].ip_addresses.append(ip)
    
    def _query_multiple_apis(self, domain: str) -> None:
        """多API接口聚合查询"""
        api_methods = [
            self._query_ip138,
            self._query_chinaz,
            self._query_hackertarget,
            self._query_alienvault,
            self._query_threatcrowd,
            self._query_virustotal,
        ]
        
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = {executor.submit(method, domain): method.__name__ for method in api_methods}
            
            for future in as_completed(futures):
                method_name = futures[future]
                try:
                    subdomains = future.result()
                    for sub in subdomains:
                        self._add_subdomain(sub, method_name)
                except Exception as e:
                    logger.debug(f"{method_name} 查询失败: {e}")
    
    def _query_ip138(self, domain: str) -> List[str]:
        """ip138接口查询"""
        subdomains = []
        try:
            url = f'http://site.ip138.com/{domain}/domain.htm'
            response = self.session.get(url, timeout=self.config.timeout, verify=False)
            response.encoding = response.apparent_encoding or 'utf-8'
            
            pattern = re.compile(r'target="_blank">\s*([a-zA-Z0-9][-a-zA-Z0-9]*\.' + re.escape(domain) + r')\s*</a>', re.S)
            matches = pattern.findall(response.text)
            subdomains = list(set(matches))
            logger.debug(f"ip138 发现 {len(subdomains)} 个子域名")
        except Exception as e:
            logger.debug(f"ip138 查询异常: {e}")
        return subdomains
    
    def _query_chinaz(self, domain: str) -> List[str]:
        """站长之家接口查询"""
        subdomains = []
        try:
            url = f'https://alexa.chinaz.com/{domain}/'
            response = self.session.get(url, timeout=self.config.timeout)
            response.encoding = 'utf-8'
            
            pattern = re.compile(r'class="domain">\s*([a-zA-Z0-9][-a-zA-Z0-9]*\.' + re.escape(domain) + r')\s*</div>', re.S)
            matches = pattern.findall(response.text)
            subdomains = list(set(matches))
            logger.debug(f"chinaz 发现 {len(subdomains)} 个子域名")
        except Exception as e:
            logger.debug(f"chinaz 查询异常: {e}")
        return subdomains
    
    def _query_hackertarget(self, domain: str) -> List[str]:
        """HackerTarget接口查询"""
        subdomains = []
        try:
            url = f'https://api.hackertarget.com/hostsearch/?q={domain}'
            response = self.session.get(url, timeout=self.config.timeout)
            
            for line in response.text.strip().split('\n'):
                if ',' in line:
                    sub = line.split(',')[0].strip()
                    if sub and sub.endswith(domain):
                        subdomains.append(sub)
            logger.debug(f"hackertarget 发现 {len(subdomains)} 个子域名")
        except Exception as e:
            logger.debug(f"hackertarget 查询异常: {e}")
        return subdomains
    
    def _query_alienvault(self, domain: str) -> List[str]:
        """AlienVault OTX接口查询"""
        subdomains = []
        try:
            url = f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns'
            response = self.session.get(url, timeout=self.config.timeout)
            data = response.json()
            
            for item in data.get('passive_dns', []):
                sub = item.get('hostname', '')
                if sub and sub.endswith(domain):
                    subdomains.append(sub)
            logger.debug(f"alienvault 发现 {len(subdomains)} 个子域名")
        except Exception as e:
            logger.debug(f"alienvault 查询异常: {e}")
        return subdomains
    
    def _query_threatcrowd(self, domain: str) -> List[str]:
        """ThreatCrowd接口查询"""
        subdomains = []
        try:
            url = f'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}'
            response = self.session.get(url, timeout=self.config.timeout)
            data = response.json()
            
            for sub in data.get('subdomains', []):
                if sub and sub.endswith(domain):
                    subdomains.append(sub)
            logger.debug(f"threatcrowd 发现 {len(subdomains)} 个子域名")
        except Exception as e:
            logger.debug(f"threatcrowd 查询异常: {e}")
        return subdomains
    
    def _query_virustotal(self, domain: str) -> List[str]:
        """VirusTotal接口查询（无需API Key的基础查询）"""
        subdomains = []
        try:
            url = f'https://www.virustotal.com/ui/domains/{domain}/subdomains'
            headers = {
                **REQUEST_HEADERS,
                'Accept': 'application/json',
            }
            response = self.session.get(url, headers=headers, timeout=self.config.timeout)
            data = response.json()
            
            for item in data.get('data', []):
                sub = item.get('id', '')
                if sub and sub.endswith(domain):
                    subdomains.append(sub)
            logger.debug(f"virustotal 发现 {len(subdomains)} 个子域名")
        except Exception as e:
            logger.debug(f"virustotal 查询异常: {e}")
        return subdomains
    
    def _query_ct_logs(self, domain: str) -> None:
        """证书透明度日志查询"""
        ct_sources = [
            self._query_crt_sh,
            self._query_censys,
        ]
        
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {executor.submit(method, domain): method.__name__ for method in ct_sources}
            
            for future in as_completed(futures):
                method_name = futures[future]
                try:
                    subdomains = future.result()
                    for sub in subdomains:
                        self._add_subdomain(sub, method_name)
                except Exception as e:
                    logger.debug(f"{method_name} 查询失败: {e}")
    
    def _query_crt_sh(self, domain: str) -> List[str]:
        """crt.sh证书透明度日志查询"""
        subdomains = []
        try:
            url = f'https://crt.sh/?q=%.{domain}&output=json'
            response = self.session.get(url, timeout=self.config.timeout)
            
            if response.text:
                data = response.json()
                for item in data:
                    name = item.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub and sub.endswith(domain):
                            if sub.startswith('*.'):
                                sub = sub[2:]
                            subdomains.append(sub)
            logger.debug(f"crt.sh 发现 {len(subdomains)} 个子域名")
        except Exception as e:
            logger.debug(f"crt.sh 查询异常: {e}")
        return list(set(subdomains))
    
    def _query_censys(self, domain: str) -> List[str]:
        """Censys证书查询"""
        subdomains = []
        try:
            url = f'https://search.censys.io/api/v2/certificates/search?q={domain}'
            response = self.session.get(url, timeout=self.config.timeout)
            
            if response.status_code == 200:
                data = response.json()
                for item in data.get('result', {}).get('hits', []):
                    for name in item.get('names', []):
                        name = name.lower()
                        if name.endswith(domain):
                            subdomains.append(name)
            logger.debug(f"censys 发现 {len(subdomains)} 个子域名")
        except Exception as e:
            logger.debug(f"censys 查询异常: {e}")
        return list(set(subdomains))
    
    def _query_dns_records(self, domain: str) -> None:
        """DNS记录查询"""
        if not self._dns_available:
            return
        
        try:
            import dns.resolver
            
            record_types = ['NS', 'MX', 'TXT', 'SOA']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    for rdata in answers:
                        if record_type == 'NS':
                            ns = str(rdata).rstrip('.').lower()
                            if ns.endswith(domain):
                                self._add_subdomain(ns, f'DNS_{record_type}')
                        elif record_type == 'MX':
                            mx = str(rdata.exchange).rstrip('.').lower()
                            if mx.endswith(domain):
                                self._add_subdomain(mx, f'DNS_{record_type}')
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"DNS记录查询异常: {e}")
    
    def _brute_force_enumerate(self, root_domain: str) -> None:
        """字典爆破枚举"""
        if not self._dns_available:
            logger.warning("DNS模块不可用，跳过字典爆破")
            return
        
        import dns.resolver
        
        if self.config.brute_force_depth == 1:
            dictionary = SUBDOMAIN_DICT_SMALL
        elif self.config.brute_force_depth == 2:
            dictionary = SUBDOMAIN_DICT_MEDIUM
        else:
            dictionary = SUBDOMAIN_DICT_LARGE
        
        logger.info(f"开始字典爆破，字典大小: {len(dictionary)}")
        
        def resolve_subdomain(prefix: str) -> Optional[str]:
            subdomain = f"{prefix}.{root_domain}"
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = DNS_SERVERS
                resolver.timeout = 3
                resolver.lifetime = 3
                answers = resolver.resolve(subdomain, 'A')
                if answers:
                    ips = [str(rdata) for rdata in answers]
                    return subdomain, ips
            except Exception:
                pass
            return None
        
        found_count = 0
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = {executor.submit(resolve_subdomain, prefix): prefix for prefix in dictionary}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    subdomain, ips = result
                    self._add_subdomain(subdomain, 'brute_force', ips)
                    found_count += 1
                    logger.debug(f"爆破发现: {subdomain} -> {ips}")
        
        logger.info(f"字典爆破完成，发现 {found_count} 个子域名")
    
    def _search_engine_discovery(self, domain: str) -> None:
        """搜索引擎子域名发现"""
        search_engines = [
            self._search_bing,
            self._search_baidu,
        ]
        
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {executor.submit(method, domain): method.__name__ for method in search_engines}
            
            for future in as_completed(futures):
                method_name = futures[future]
                try:
                    subdomains = future.result()
                    for sub in subdomains:
                        self._add_subdomain(sub, method_name)
                except Exception as e:
                    logger.debug(f"{method_name} 查询失败: {e}")
    
    def _search_bing(self, domain: str) -> List[str]:
        """Bing搜索引擎发现"""
        subdomains = []
        try:
            url = f'https://www.bing.com/search?q=site%3A{domain}'
            response = self.session.get(url, timeout=self.config.timeout)
            
            pattern = re.compile(r'([a-zA-Z0-9][-a-zA-Z0-9]*\.' + re.escape(domain) + r')', re.I)
            matches = pattern.findall(response.text)
            subdomains = list(set(matches))
            logger.debug(f"bing 发现 {len(subdomains)} 个子域名")
        except Exception as e:
            logger.debug(f"bing 查询异常: {e}")
        return subdomains
    
    def _search_baidu(self, domain: str) -> List[str]:
        """百度搜索引擎发现"""
        subdomains = []
        try:
            url = f'https://www.baidu.com/s?wd=site:{domain}'
            response = self.session.get(url, timeout=self.config.timeout)
            response.encoding = 'utf-8'
            
            pattern = re.compile(r'([a-zA-Z0-9][-a-zA-Z0-9]*\.' + re.escape(domain) + r')', re.I)
            matches = pattern.findall(response.text)
            subdomains = list(set(matches))
            logger.debug(f"baidu 发现 {len(subdomains)} 个子域名")
        except Exception as e:
            logger.debug(f"baidu 查询异常: {e}")
        return subdomains
    
    def _verify_subdomains(self) -> None:
        """验证子域名有效性"""
        if not self._dns_available:
            return
        
        import dns.resolver
        
        invalid_subdomains = []
        
        for subdomain, result in self._subdomains.items():
            if not result.ip_addresses:
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = DNS_SERVERS
                    resolver.timeout = 3
                    resolver.lifetime = 3
                    answers = resolver.resolve(subdomain, 'A')
                    result.ip_addresses = [str(rdata) for rdata in answers]
                except Exception:
                    result.is_valid = False
                    invalid_subdomains.append(subdomain)
        
        for sub in invalid_subdomains:
            logger.debug(f"子域名验证失败: {sub}")


def get_subdomain(domain: str, config: Optional[SubdomainConfig] = None) -> List[str]:
    """
    获取域名的子域名（兼容旧接口）
    
    Args:
        domain: 主域名
        config: 配置选项
        
    Returns:
        子域名列表
    """
    enumerator = SubdomainEnumerator(config)
    return enumerator.enumerate(domain)


def get_subdomain_detailed(domain: str, config: Optional[SubdomainConfig] = None) -> Dict[str, Any]:
    """
    获取详细的子域名信息
    
    Args:
        domain: 主域名
        config: 配置选项
        
    Returns:
        包含详细信息的字典
    """
    enumerator = SubdomainEnumerator(config)
    subdomains = enumerator.enumerate(domain)
    
    return {
        'domain': domain,
        'total_count': len(subdomains),
        'subdomains': [
            {
                'domain': result.domain,
                'sources': result.sources,
                'ip_addresses': result.ip_addresses,
                'is_valid': result.is_valid
            }
            for result in enumerator._subdomains.values()
        ]
    }


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    test_domain = 'baidu.com'
    logger.info(f"=== 测试子域名枚举: {test_domain} ===")
    
    config = SubdomainConfig(
        enable_brute_force=True,
        enable_dns_query=True,
        enable_ct_logs=True,
        enable_search_engines=True,
        brute_force_depth=1,
        verify_dns=True
    )
    
    result = get_subdomain_detailed(test_domain, config)
    print(f"\n发现 {result['total_count']} 个子域名:")
    for sub in result['subdomains'][:20]:
        print(f"  - {sub['domain']}")
        if sub['ip_addresses']:
            print(f"    IP: {', '.join(sub['ip_addresses'])}")
        print(f"    来源: {', '.join(sub['sources'])}")
