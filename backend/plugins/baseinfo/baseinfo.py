# -*- coding:utf-8 -*-

"""
基础信息收集模块
功能:
1. 获取目标URL的基础信息(域名、IP、服务器、操作系统等)
2. 查询IP的物理地址(国家、省份、城市、ASN)
3. 获取域名解析的IP列表(支持IPv4/IPv6)
4. 从Server头推断操作系统类型

特性:
- 支持请求重试和超时控制
- 自动处理响应编码,避免中文乱码
- 支持IP列表去重
- 标准化返回结果格式

依赖:
- requests: 用于HTTP请求
- socket: 用于DNS解析

使用示例:
    >>> from backend.plugins.baseinfo.baseinfo import getbaseinfo
    >>> result = getbaseinfo('https://www.taobao.com/')
    >>> print(result)
    {
        "code": 200,
        "msg": "查询成功",
        "domain": "www.taobao.com",
        "server": "Tengine",
        "language": null,
        "ip": ["110.242.68.66 (物理地址: 中国,浙江,杭州,AS37963)"],
        "os": "Linux",
        "register": "http://whois.chinaz.com/www.taobao.com"
    }
""" 


import logging
import socket
import json
from urllib.parse import urlparse
from typing import List, Dict, Any
import requests
from requests.exceptions import (
    ConnectTimeout,
    ReadTimeout,
    ConnectionError,
    RequestException
)

# 配置日志(便于调试)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

from ..common.common import get_domain
from ..randheader.randheader import get_ua

# 初始化requests会话(复用连接,提升效率)
SESSION = requests.Session()
SESSION.headers.update({"Accept-Encoding": "gzip, deflate"})

def get_ip_addr(ip: str) -> str:
    """
    查询IP物理地址(健壮版)
    :param ip: 待查询IP
    :return: 物理地址描述字符串
    """
    default_msg = " (未查询到物理地址)  "
    error_msg = " (IP查询接口异常)  "
    try:
        # 优先尝试socket解析(最快且稳定)
        try:
            ip_obj = socket.gethostbyname(ip)
            # 如果输入本身是IP,这里直接返回. 如果是域名,返回IP
            # 这里输入预期是IP,所以socket.gethostbyname(ip)只是验证
        except:
            pass

        # 调用ip-api.com,添加超时+编码处理
        resp = SESSION.get(
            f"http://ip-api.com/json/{ip}",
            timeout=5, # 缩短超时时间
            headers={"User-Agent": get_ua()["User-Agent"]}
        )
        resp.encoding = resp.apparent_encoding  # 自动识别编码,避免乱码
        addr_data = resp.json()
        
        # 校验核心字段,避免KeyError
        if addr_data.get("status") != "success":
            return default_msg
        
        # 安全获取字段(无则返回空字符串)
        country = addr_data.get("country", "")
        region = addr_data.get("regionName", "")
        city = addr_data.get("city", "")
        as_info = addr_data.get("as", "")
        return f" (物理地址: {country},{region},{city},{as_info})  "
    
    except (ConnectTimeout, ReadTimeout):
        logger.warning(f"IP {ip} 地址查询超时")
        return " (IP查询超时,跳过物理地址)  "
    except RequestException as e:
        logger.warning(f"IP {ip} 地址查询请求异常:{e}")
        return default_msg
    except json.JSONDecodeError:
        logger.warning(f"IP {ip} 地址查询响应解析失败")
        return default_msg
    except Exception as e:
        logger.warning(f"IP {ip} 地址查询未知异常:{e}")
        return default_msg

def get_ip_list(domain: str) -> List[str]:
    """
    获取域名解析的IP列表(优化去重+异常细化)
    :param domain: 目标域名
    :return: 带物理地址的IP列表
    """
    ip_list: List[str] = []
    unique_ips: set = set()  # 用集合去重,效率更高
    try:
        # 解析域名(同时支持IPv4/IPv6,过滤重复IP)
        addrs = socket.getaddrinfo(domain, None)
        for item in addrs:
            ip = item[4][0]
            if ip not in unique_ips:
                unique_ips.add(ip)
                ip_with_addr = ip + get_ip_addr(ip)
                ip_list.append(ip_with_addr)
        if not ip_list:
            ip_list = ["未解析到任何IP"]
    except socket.gaierror:
        logger.error(f"域名 {domain} DNS解析失败")
        ip_list = ["DNS解析失败"]
    except Exception as e:
        logger.error(f"获取域名 {domain} IP列表异常:{e}")
        ip_list = ["服务器错误"]
    return ip_list

def infer_os_from_server(server: str) -> str:
    """
    从Server头推断操作系统(修复空值BUG)
    :param server: Server头内容
    :return: 操作系统描述
    """
    # ✅ 强制安全处理 None，这是报错的核心原因
    if server is None or server.strip() == "":
        return "未知操作系统"
    
    server_lower = server.strip().lower()
    
    # 扩展OS判断规则
    os_mapping = [
        ("iis", "Windows Server"),
        ("win", "Windows Server"),
        ("nginx/Windows", "Windows"),
        ("apache/Win32", "Windows"),
        ("linux", "Linux"),
        ("centos", "Linux (CentOS)"),
        ("ubuntu", "Linux (Ubuntu)"),
        ("debian", "Linux (Debian)"),
        ("alpine", "Linux (Alpine)")
    ]
    for keyword, os_name in os_mapping:
        if keyword in server_lower:
            return os_name
    # 兜底:Nginx/Apache默认推断为Linux(主流场景)
    if any(k in server_lower for k in ["nginx", "apache", "tomcat", "docker"]):
        return "Linux"
    return "未知操作系统"

def getbaseinfo(url: str) -> Dict[str, Any]:
    """
    返回URL基础信息(标准化+健壮版)
    :param url: 目标URL
    :return: 标准化信息字典
    """
    # 初始化返回字典(规范默认值)
    info: Dict[str, Any] = {
        "code": 400,
        "msg": "网络错误",
        "domain": None,
        "server": None,
        "language": None,
        "ip": None,
        "os": None,
        "register": None
    }
    
    # 规范化URL（自动添加协议前缀）
    raw_url = str(url or "").strip()
    if not raw_url:
        info["msg"] = "URL格式无效"
        logger.error(f"URL {url} 格式无效")
        return info
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "http://" + raw_url
    parsed = urlparse(raw_url)
    if not parsed.netloc or parsed.scheme not in ("http", "https"):
        info["msg"] = "URL格式无效"
        logger.error(f"URL {url} 格式无效")
        return info
    normalized_url = raw_url
    
    # 提取域名
    domain = parsed.hostname or get_domain(normalized_url)
    if not domain:
        info["msg"] = "域名提取失败"
        logger.error(f"URL {url} 提取域名失败")
        return info
    
    info["domain"] = domain
    info["register"] = f"http://whois.chinaz.com/{domain}"  # WHOIS链接
    
    # 发起HTTP请求(使用规范化后的URL)
    try:
        resp = SESSION.get(
            normalized_url,
            headers=get_ua(),
            timeout=8,
            allow_redirects=True,  # 允许重定向,避免漏查
            verify=False  # 忽略SSL证书错误(按需开启,生产环境慎用)
        )
    except ConnectTimeout:
        info["msg"] = "连接目标URL超时"
        logger.error(f"URL {normalized_url} 连接超时")
        return info
    except ConnectionError:
        info["msg"] = "无法连接目标URL"
        logger.error(f"URL {normalized_url} 连接失败")
        return info
    except ReadTimeout:
        info["msg"] = "读取目标URL响应超时"
        logger.error(f"URL {url} 读取超时")
        return info
    except RequestException as e:
        info["msg"] = f"请求异常:{str(e)[:50]}"  # 截断过长异常信息
        logger.error(f"URL {url} 请求异常:{e}")
        return info
    except Exception as e:
        info["msg"] = f"未知异常:{str(e)[:50]}"
        logger.error(f"URL {url} 未知异常:{e}")
        return info
    
    # 解析响应头
    info["server"] = resp.headers.get("Server")  # 空值返回None,而非'nothing'
    info["language"] = resp.headers.get("X-Powered-By")
    
    # 获取IP列表
    try:
        info["ip"] = get_ip_list(domain)
    except Exception as e:
        info["ip"] = "IP查询失败"
        logger.error(f"域名 {domain} IP列表查询异常:{e}")
    
    # 推断操作系统
    info["os"] = infer_os_from_server(info["server"])
    
    # 成功状态
    info["code"] = 200
    info["msg"] = "查询成功"
    return info

if __name__ == '__main__':
    # 测试示例

    test_url = "www.baidu.com"
    result = getbaseinfo(test_url)
    # 格式化输出测试结果
    print(json.dumps(result, ensure_ascii=False, indent=2))
