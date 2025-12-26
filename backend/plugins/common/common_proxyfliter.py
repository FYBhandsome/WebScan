# -*- coding:utf-8 -*-
"""
FastAPI通用工具函数模块
功能：
1. 标准化JSON响应（成功/失败）
2. 用户IP获取（自动检测反向代理+防伪造+兼容Nginx/Apache/CDN）
3. 字符串安全过滤（防注入/XSS）
4. IP/URL/域名合法性校验（过滤禁止目标）
5. 域名解析（转IP）
"""

import re
import socket
from typing import Optional, Union, Dict, Any, List
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

# ======================== 核心配置（可根据服务器部署调整） ========================
# 禁止扫描的域名/IP特征（正则，忽略大小写）
FORBIDDEN_DOMAIN_PATTERN = re.compile(
    r'(127.0.*.*)'
    r'|(^192\.168\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[0-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[0-9])$)'
    r'|(local)|(gov.cn)',
    re.IGNORECASE
)

# 禁止扫描的IP段（正则）
FORBIDDEN_IP_PATTERN = re.compile(
    r'(^0\.0\.0\.0$)'
    r'|(120.55.58.175)'
    r'|(^10\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[0-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[0-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[0-9])$)'
    r'|(^127\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[0-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[0-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[0-9])$)'
    r'|(^172\.(1[6789]|2[0-9]|3[01])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[0-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[0-9])$)'
    r'|(^192\.168\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[0-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[0-9])$)'
)

# IP合法性校验正则（预编译）
IP_VALID_PATTERN = re.compile(
    r'^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])'
    r'\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)'
    r'\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)'
    r'\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$'
)

# DNS解析超时时间（秒）
DNS_TIMEOUT = 1

# ---------------------- 反向代理相关配置（关键！） ----------------------
# 1. 是否启用反向代理（可根据部署环境手动设置，比如Nginx代理时设为True）
USE_REVERSE_PROXY = True

# 2. 可信反向代理服务器IP列表（仅信任这些IP的代理请求，防止伪造）
# 示例：Nginx部署在127.0.0.1或192.168.1.100，就加这些IP
TRUSTED_PROXY_IPS = ["127.0.0.1", "::1", "192.168.1.0/24"]

# 3. 反向代理常用的真实IP请求头（优先级从高到低）
PROXY_IP_HEADERS = [
    "X-Real-IP",          # Nginx常用
    "X-Forwarded-For",    # 通用（CDN/多个代理时用）
    "Proxy-Client-IP",    # Apache常用
    "WL-Proxy-Client-IP"  # WebLogic常用
]

# 初始化FastAPI应用
app = FastAPI(title="通用工具函数API", version="1.0")

# ======================== 辅助函数：校验IP是否在可信代理列表 ========================
def is_trusted_proxy_ip(ip: str) -> bool:
    """
    校验IP是否属于可信反向代理服务器IP
    :param ip: 待校验IP
    :return: True（可信）| False（不可信）
    """
    if not ip or not check_ip(ip):
        return False
    
    # 匹配精确IP（比如127.0.0.1）
    if ip in TRUSTED_PROXY_IPS:
        return True
    
    # 匹配CIDR网段（比如192.168.1.0/24）
    import ipaddress
    try:
        ip_obj = ipaddress.ip_address(ip)
        for cidr in TRUSTED_PROXY_IPS:
            if '/' in cidr:
                if ip_obj in ipaddress.ip_network(cidr, strict=False):
                    return True
    except ValueError:
        pass
    return False

# ======================== 核心优化：自动检测反向代理 + 获取真实IP ========================
def get_user_ip(request: Request) -> str:
    """
    获取用户真实IP（自动检测反向代理+防伪造+兼容多种代理场景）
    逻辑：
    1. 若配置启用反向代理 + 请求来源是可信代理IP → 从代理头取真实IP；
    2. 若未启用反向代理 或 代理IP不可信 → 直接取客户端IP；
    3. 防伪造：仅信任可信代理IP的X-Forwarded-For头，避免恶意用户伪造。
    :param request: FastAPI Request对象
    :return: 用户真实IP字符串（默认空字符串）
    """
    real_ip = ""
    try:
        # 步骤1：获取请求的直接来源IP（代理服务器IP/客户端直连IP）
        proxy_server_ip = request.client.host if request.client else ""
        
        # 步骤2：判断是否使用反向代理（配置启用 + 来源IP是可信代理）
        use_proxy = USE_REVERSE_PROXY and is_trusted_proxy_ip(proxy_server_ip)
        
        if use_proxy:
            # 场景1：反向代理环境 → 从代理头取真实IP
            for header in PROXY_IP_HEADERS:
                ip_value = request.headers.get(header, "").strip()
                if not ip_value:
                    continue
                
                # 处理X-Forwarded-For（多个IP用逗号分隔，取第一个）
                if header == "X-Forwarded-For":
                    real_ip = ip_value.split(",")[0].strip()
                else:
                    # 其他头（X-Real-IP）直接取值
                    real_ip = ip_value
                
                # 校验取到的IP是否合法，合法则终止循环
                if check_ip(real_ip):
                    break
            # 兜底：代理环境下没取到合法IP，用代理服务器IP
            if not check_ip(real_ip):
                real_ip = proxy_server_ip
        else:
            # 场景2：无反向代理 → 直接取客户端IP
            real_ip = proxy_server_ip
        
        # 最终校验：确保IP格式合法
        if not check_ip(real_ip):
            real_ip = ""
            
    except Exception as e:
        print(f"[ERROR] 获取用户IP失败：{str(e)}")
        real_ip = ""
    
    return real_ip

# ======================== 其他工具函数（无修改，保留原有功能） ========================
def success(
    code: int = 200,
    data: Union[list, dict, None] = None,
    msg: str = 'success'
) -> JSONResponse:
    if data is None:
        data = []
    result: Dict[str, Any] = {
        'code': code,
        'data': data,
        'msg': msg,
    }
    return JSONResponse(content=result, status_code=code)


def error(
    code: int = 400,
    data: Union[list, dict, None] = None,
    msg: str = 'error'
) -> JSONResponse:
    if data is None:
        data = []
    result: Dict[str, Any] = {
        'code': code,
        'data': data,
        'msg': msg,
    }
    return JSONResponse(content=result, status_code=code)


def safe_addslashes(sstr: Optional[str]) -> str:
    if not sstr:
        return ""
    ss = str(sstr).strip()
    ss = ss.replace('\\', '\\\\')\
           .replace("'", "\\'")\
           .replace('"', '\\"')\
           .replace('<', '')\
           .replace('>', '')
    return ss


def get_domain(url: Optional[str]) -> Optional[str]:
    valid_url = check_url(url)
    if not valid_url:
        return None
    try:
        url_parts = valid_url.split('/')
        domain = url_parts[2]
        print(f'[LOG] 提取域名成功：{domain}')
        return domain
    except IndexError:
        print(f"[ERROR] 提取域名失败，URL格式异常：{valid_url}")
        return None


def get_domain_ip(host: Optional[str]) -> str:
    if not host:
        print("[ERROR] 域名/IP为空，解析失败")
        return '目标站点不可访问'

    if not IP_VALID_PATTERN.match(str(host)):
        domain = get_domain(host)
        if not domain:
            return '目标站点不可访问'
        socket.setdefaulttimeout(DNS_TIMEOUT)
        try:
            host = socket.gethostbyname(domain)
        except socket.gaierror:
            print(f"[ERROR] 域名解析失败：{domain}")
            return '目标站点不可访问'
        except Exception as e:
            print(f"[ERROR] 域名解析异常：{str(e)}")
            return '目标站点不可访问'

    if FORBIDDEN_IP_PATTERN.match(str(host)):
        return '目标站点不可访问'

    return host if host else '目标站点不可访问'


def check_ip(ipaddr: Optional[str]) -> bool:
    if not ipaddr:
        return False
    ip_str = str(ipaddr).strip()
    if not (6 < len(ip_str) < 16):
        return False
    if FORBIDDEN_IP_PATTERN.match(ip_str):
        return False
    return bool(IP_VALID_PATTERN.match(ip_str))


def check_url(url: Optional[str]) -> Union[str, bool]:
    if not url:
        return False
    url_clean = str(url).strip()\
        .replace('"', '').replace("'", '').replace('<', '').replace('>', '').replace(';', '')\
        .replace('\\', '/')
    if not (10 < len(url_clean) < 40):
        return False
    if FORBIDDEN_DOMAIN_PATTERN.search(url_clean):
        return False
    if not (url_clean.startswith('http://') or url_clean.startswith('https://')):
        return False
    try:
        url_parts = url_clean.split('/')
        domain = url_parts[2]
        if '.' not in domain:
            return False
    except IndexError:
        return False
    return url_clean.lower()

# ======================== 新增：测试反向代理IP获取的接口 ========================
@app.get("/get/real-ip", summary="获取用户真实IP（自动检测反向代理）")
async def api_get_real_ip(request: Request):
    """
    测试接口：获取用户真实IP，自动适配反向代理/直连场景
    """
    user_ip = get_user_ip(request)
    if user_ip:
        return success(data={"real_ip": user_ip}, msg="获取真实IP成功")
    else:
        return error(code=500, msg="获取真实IP失败")

# ======================== 原有示例路由（保留） ========================
@app.get("/check/ip", summary="校验IP合法性")
async def api_check_ip(ip: str):
    is_valid = check_ip(ip)
    if is_valid:
        return success(data={"ip": ip, "is_valid": True}, msg="IP合法")
    else:
        return error(code=403, data={"ip": ip, "is_valid": False}, msg="IP非法或禁止扫描")


@app.get("/check/url", summary="校验URL合法性")
async def api_check_url(url: str):
    valid_url = check_url(url)
    if valid_url:
        return success(data={"url": valid_url, "is_valid": True}, msg="URL合法")
    else:
        return error(code=403, data={"url": url, "is_valid": False}, msg="URL非法或禁止扫描")


@app.get("/domain/ip", summary="域名/URL转IP")
async def api_domain_to_ip(host: str):
    ip = get_domain_ip(host)
    if ip == "目标站点不可访问":
        return error(code=403, msg=ip)
    else:
        return success(data={"host": host, "ip": ip}, msg="解析成功")

# ======================== 增强版测试代码（含反向代理IP测试） ========================
def test_all_functions():
    """测试所有工具函数（新增反向代理IP测试）"""
    print("=" * 50)
    print("开始测试通用工具函数...")
    print("=" * 50)

    # 1. 测试IP校验
    print("\n【1. 测试IP校验】")
    test_ips = [
        ("8.8.8.8", True),       # 合法公网IP
        ("192.168.1.1", False),  # 禁止内网IP
        ("127.0.0.1", False),    # 本地IP
        ("256.0.0.1", False),    # 非法IP格式
        ("", False),             # 空IP
        ("10.0.0.1", False)      # 禁止内网IP
    ]
    for ip, expected in test_ips:
        result = check_ip(ip)
        print(f"IP: {ip:15} | 预期: {expected} | 实际: {result} | {'通过' if result == expected else '失败'}")

    # 2. 测试URL校验
    print("\n【2. 测试URL校验】")
    test_urls = [
        ("https://www.baidu.com", "https://www.baidu.com"),  # 合法URL
        ("https://192.168.1.1", False),                      # 禁止IP的URL
        ("http://local.test", False),                        # 禁止域名
        ("https://gov.cn/test", False),                      # 禁止域名
        ("www.baidu.com", False),                            # 无协议头
        ("https://a.cn", False),                             # 长度不足
    ]
    for url, expected in test_urls:
        result = check_url(url)
        print(f"URL: {url:25} | 预期: {expected} | 实际: {result} | {'通过' if result == expected else '失败'}")

    # 3. 测试域名解析
    print("\n【3. 测试域名解析】")
    test_hosts = [
        "https://www.baidu.com",  # 合法域名
        "192.168.1.1",            # 禁止IP
        "https://local.test",     # 禁止域名
        "invalid.domain.12345"    # 无效域名
    ]
    for host in test_hosts:
        result = get_domain_ip(host)
        print(f"Host: {host:25} | 解析结果: {result}")

    # 4. 测试安全过滤
    print("\n【4. 测试安全过滤】")
    test_strings = [
        ("", ""),
        (None, ""),
        ("<script>alert('xss')</script>", "scriptalert('xss')script"),
        ('select * from user where name="admin"', 'select * from user where name=\\"admin\\"'),
        ("\\test\\", "\\\\test\\\\"),
    ]
    for s, expected in test_strings:
        result = safe_addslashes(s)
        print(f"原始字符串: {repr(s):30} | 过滤后: {repr(result)} | {'通过' if result == expected else '失败'}")

    # 5. 测试反向代理IP检测（模拟请求）
    print("\n【5. 测试反向代理IP获取（模拟）】")
    class MockRequest:
        """模拟FastAPI Request对象"""
        def __init__(self, client_host: str, headers: dict = None):
            self.client = type('obj', (object,), {'host': client_host})
            self.headers = headers or {}

    # 测试场景1：直连（无代理）
    mock_request1 = MockRequest(client_host="8.8.8.8")
    ip1 = get_user_ip(mock_request1)
    print(f"场景1：直连（客户端IP 8.8.8.8）→ 获取IP: {ip1} | 预期: 8.8.8.8 | {'通过' if ip1 == '8.8.8.8' else '失败'}")

    # 测试场景2：反向代理（Nginx，X-Real-IP头）
    mock_request2 = MockRequest(
        client_host="127.0.0.1",  # 代理服务器IP（可信）
        headers={"X-Real-IP": "192.168.1.100"}  # 用户真实IP
    )
    ip2 = get_user_ip(mock_request2)
    print(f"场景2：Nginx代理（X-Real-IP）→ 获取IP: {ip2} | 预期: 192.168.1.100 | {'通过' if ip2 == '192.168.1.100' else '失败'}")

    # 测试场景3：CDN代理（X-Forwarded-For多IP）
    mock_request3 = MockRequest(
        client_host="192.168.1.100",  # 代理服务器IP（可信）
        headers={"X-Forwarded-For": "10.0.0.1, 172.16.0.1"}  # 第一个是用户真实IP
    )
    ip3 = get_user_ip(mock_request3)
    print(f"场景3：CDN代理（X-Forwarded-For）→ 获取IP: {ip3} | 预期: 10.0.0.1 | {'通过' if ip3 == '10.0.0.1' else '失败'}")

    # 测试场景4：伪造代理头（不可信代理IP）
    mock_request4 = MockRequest(
        client_host="2.2.2.2",  # 非可信代理IP
        headers={"X-Forwarded-For": "9.9.9.9"}  # 伪造的IP
    )
    ip4 = get_user_ip(mock_request4)
    print(f"场景4：伪造代理头（不可信IP）→ 获取IP: {ip4} | 预期: 2.2.2.2 | {'通过' if ip4 == '2.2.2.2' else '失败'}")

    # 6. 测试响应函数
    print("\n【6. 测试响应函数】")
    success_resp = success(data={"test": "data"}, msg="测试成功")
    error_resp = error(code=403, msg="测试失败")
    print(f"成功响应: {success_resp.body.decode('utf-8')}")
    print(f"失败响应: {error_resp.body.decode('utf-8')}")

    print("\n" + "=" * 50)
    print("工具函数测试完成！")
    print("=" * 50)


if __name__ == "__main__":
    # 第一步：运行所有工具函数测试
    test_all_functions()

    # 第二步：启动FastAPI测试服务器
    print("\n启动FastAPI测试服务器...")
    print("访问文档地址: http://127.0.0.1:8001/docs")
    print("测试获取真实IP接口: http://127.0.0.1:8001/get/real-ip")
    print("按 Ctrl+C 停止服务器")
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8001)