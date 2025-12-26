# -*- coding:utf-8 -*-
"""
FastAPI通用工具函数模块
功能：
1. 标准化JSON响应（成功/失败）
2. 用户IP获取（兼容反向代理/Nginx）
3. 字符串安全过滤（防注入/XSS）
4. IP/URL/域名合法性校验（过滤禁止目标）
5. 域名解析（转IP）
"""

import re
import socket
from typing import Optional, Union, Dict, Any
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

# ======================== 配置常量（正则预编译+注释清晰） ========================
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

# 初始化FastAPI应用（如需集成到已有项目，可注释此行，仅保留工具函数）
app = FastAPI(title="通用工具函数API", version="1.0")

# ======================== 标准化响应函数（适配FastAPI） ========================
def success(
    code: int = 200,
    data: Union[list, dict, None] = None,
    msg: str = 'success'
) -> JSONResponse:
    """
    返回标准化的成功JSON响应（适配FastAPI）
    :param code: 状态码（默认200）
    :param data: 返回数据（默认空列表）
    :param msg: 提示信息（默认success）
    :return: FastAPI JSONResponse
    """
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
    """
    返回标准化的失败JSON响应（适配FastAPI）
    :param code: 状态码（默认400）
    :param data: 返回数据（默认空列表）
    :param msg: 错误提示（默认error）
    :return: FastAPI JSONResponse
    """
    if data is None:
        data = []
    result: Dict[str, Any] = {
        'code': code,
        'data': data,
        'msg': msg,
    }
    return JSONResponse(content=result, status_code=code)

# ======================== IP处理函数（适配FastAPI Request） ========================
def get_user_ip(request: Request) -> str:
    """
    获取用户真实IP（适配FastAPI Request对象，兼容反向代理）
    :param request: FastAPI Request对象
    :return: 用户IP字符串（默认空字符串）
    """
    real_ip = ""
    try:
        # 场景1：反向代理（X-Forwarded-For）
        x_forwarded_for = request.headers.get("X-Forwarded-For", "")
        if x_forwarded_for and x_forwarded_for.strip():
            # 多个IP用逗号分隔，取第一个
            real_ip = x_forwarded_for.split(",")[0].strip()
        else:
            # 场景2：直接访问（request.client.host）
            real_ip = request.client.host if request.client else ""
    except Exception as e:
        print(f"[ERROR] 获取用户IP失败：{str(e)}")
        real_ip = ""
    return real_ip

# ======================== 安全过滤函数 ========================
def safe_addslashes(sstr: Optional[str]) -> str:
    """
    安全过滤字符串，转义特殊字符（防SQL注入/XSS）
    :param sstr: 待过滤字符串（允许None）
    :return: 过滤后的字符串
    """
    if not sstr:
        return ""
    ss = str(sstr).strip()
    # 转义特殊字符
    ss = ss.replace('\\', '\\\\')\
           .replace("'", "\\'")\
           .replace('"', '\\"')\
           .replace('<', '')\
           .replace('>', '')
    return ss

# ======================== 域名/URL处理函数 ========================
def get_domain(url: Optional[str]) -> Optional[str]:
    """
    从合法URL中提取域名
    :param url: 待解析URL
    :return: 域名字符串 | None
    """
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
    """
    域名/URL转IP，过滤禁止扫描的IP
    :param host: 域名/URL/IP字符串
    :return: 合法IP | 错误提示
    """
    if not host:
        print("[ERROR] 域名/IP为空，解析失败")
        return '目标站点不可访问'

    # 判断是否为IP格式
    if not IP_VALID_PATTERN.match(str(host)):
        domain = get_domain(host)
        if not domain:
            return '目标站点不可访问'
        # DNS解析域名转IP
        socket.setdefaulttimeout(DNS_TIMEOUT)
        try:
            host = socket.gethostbyname(domain)
        except socket.gaierror:
            print(f"[ERROR] 域名解析失败：{domain}")
            return '目标站点不可访问'
        except Exception as e:
            print(f"[ERROR] 域名解析异常：{str(e)}")
            return '目标站点不可访问'

    # 检查是否为禁止IP
    if FORBIDDEN_IP_PATTERN.match(str(host)):
        return '目标站点不可访问'

    return host if host else '目标站点不可访问'

# ======================== 合法性校验函数 ========================
def check_ip(ipaddr: Optional[str]) -> bool:
    """
    校验IP合法性（格式+非禁止IP）
    :param ipaddr: 待校验IP字符串
    :return: True（合法）| False（非法）
    """
    if not ipaddr:
        return False
    ip_str = str(ipaddr).strip()
    # 长度校验（6 < 长度 < 16）
    if not (6 < len(ip_str) < 16):
        return False
    # 禁止IP校验
    if FORBIDDEN_IP_PATTERN.match(ip_str):
        return False
    # 格式校验
    return bool(IP_VALID_PATTERN.match(ip_str))


def check_url(url: Optional[str]) -> Union[str, bool]:
    """
    校验URL合法性（格式+非禁止域名）
    :param url: 待校验URL字符串
    :return: 小写合法URL | False
    """
    if not url:
        return False
    # 清洗URL（移除危险字符）
    url_clean = str(url).strip()\
        .replace('"', '').replace("'", '').replace('<', '').replace('>', '').replace(';', '')\
        .replace('\\', '/')
    # 长度校验（10 < 长度 < 40）
    if not (10 < len(url_clean) < 40):
        return False
    # 禁止域名校验
    if FORBIDDEN_DOMAIN_PATTERN.search(url_clean):
        return False
    # 协议校验（http/https开头）
    if not (url_clean.startswith('http://') or url_clean.startswith('https://')):
        return False
    # 域名格式校验（含.）
    try:
        url_parts = url_clean.split('/')
        domain = url_parts[2]
        if '.' not in domain:
            return False
    except IndexError:
        return False
    # 返回小写URL
    return url_clean.lower()

# ======================== FastAPI示例路由（可根据业务扩展） ========================
@app.get("/check/ip", summary="校验IP合法性")
async def api_check_ip(ip: str):
    """
    FastAPI接口示例：校验IP合法性
    :param ip: 待校验的IP地址
    """
    is_valid = check_ip(ip)
    if is_valid:
        return success(data={"ip": ip, "is_valid": True}, msg="IP合法")
    else:
        return error(code=403, data={"ip": ip, "is_valid": False}, msg="IP非法或禁止扫描")


@app.get("/check/url", summary="校验URL合法性")
async def api_check_url(url: str):
    """
    FastAPI接口示例：校验URL合法性
    :param url: 待校验的URL
    """
    valid_url = check_url(url)
    if valid_url:
        return success(data={"url": valid_url, "is_valid": True}, msg="URL合法")
    else:
        return error(code=403, data={"url": url, "is_valid": False}, msg="URL非法或禁止扫描")


@app.get("/domain/ip", summary="域名/URL转IP")
async def api_domain_to_ip(host: str):
    """
    FastAPI接口示例：域名/URL转IP
    :param host: 域名/URL/IP
    """
    ip = get_domain_ip(host)
    if ip == "目标站点不可访问":
        return error(code=403, msg=ip)
    else:
        return success(data={"host": host, "ip": ip}, msg="解析成功")

# ======================== 完整测试代码 ========================
def test_all_functions():
    """测试所有工具函数"""
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

    # 5. 测试响应函数（打印结构，不实际返回）
    print("\n【5. 测试响应函数】")
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

    # 第二步：启动FastAPI测试服务器（需安装uvicorn：pip install uvicorn）
    print("\n启动FastAPI测试服务器...")
    print("访问文档地址: http://127.0.0.1:8888/docs")
    print("按 Ctrl+C 停止服务器")
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8001)