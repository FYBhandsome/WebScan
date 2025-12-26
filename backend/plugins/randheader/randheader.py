# https://github.com/al0ne
import random
import socket
import struct
from typing import Dict, List, Optional
from fake_useragent import UserAgent, FakeUserAgentError  # 导入异常类

# ======================== 配置常量（可自定义） ========================
# 基础请求头模板
BASE_HEADERS = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'User-Agent': "",
    'Referer': 'https://www.google.com',
    'X-Forwarded-For': "",
    'X-Real-IP': "",
    'Connection': 'keep-alive',
}
# 排除内网IP段（避免生成内网IP，让伪造IP更真实）
PRIVATE_IP_RANGES = [
    (0x0A000000, 0x0AFFFFFF),    # 10.0.0.0/8
    (0xC0A80000, 0xC0A8FFFF),    # 192.168.0.0/16
    (0xAC100000, 0xAC1FFFFF),    # 172.16.0.0/12
    (0x7F000000, 0x7FFFFFFF),    # 127.0.0.0/8
    (0xFFFFFFFF, 0xFFFFFFFF),    # 255.255.255.255
    (0x00000000, 0x00000000),    # 0.0.0.0
]

# 初始化UserAgent（全局单例，避免重复初始化）
try:
    UA_GENERATOR = UserAgent()
except FakeUserAgentError as e:
    # 下载失败时使用备用UA列表
    print(f"[WARN] FakeUserAgent初始化失败：{e}，使用备用UA列表")
    BACKUP_UA_LIST = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'
    ]
    UA_GENERATOR = None


def generate_random_public_ip() -> str:
    """
    生成随机公网IPv4地址（排除内网/非法IP，伪造更真实）
    :return: 合法公网IP字符串
    """
    while True:
        # 生成1~0xFFFFFFFE的随机整数（排除255.255.255.255）
        ip_int = random.randint(1, 0xFFFFFFFE)
        # 检查是否属于内网/非法IP段
        is_private = False
        for start, end in PRIVATE_IP_RANGES:
            if start <= ip_int <= end:
                is_private = True
                break
        if not is_private:
            # 转换为IPv4字符串
            ip_bytes = struct.pack('>I', ip_int)
            return socket.inet_ntoa(ip_bytes)


def get_ua() -> Dict[str, str]:
    """
    获取随机User-Agent请求头（简化版，兼容旧代码）
    :return: 包含User-Agent的字典
    """
    return get_random_headers(conn_type="keep-alive")


def get_random_headers(conn_type: Optional[str] = "keep-alive") -> Dict[str, str]:
    """
    生成伪造的HTTP请求头（优化版）
    :param conn_type: Connection头值，可选keep-alive/close
    :return: 填充后的请求头字典
    """
    # 复制基础模板，避免修改原字典
    headers = BASE_HEADERS.copy()
    
    # 1. 生成随机User-Agent
    if UA_GENERATOR:
        try:
            ua = UA_GENERATOR.random
        except FakeUserAgentError:
            ua = random.choice(BACKUP_UA_LIST)
    else:
        ua = random.choice(BACKUP_UA_LIST)
    headers["User-Agent"] = ua
    
    # 2. 生成随机公网IP，填充XFF和X-Real-IP
    fake_ip = generate_random_public_ip()
    headers["X-Forwarded-For"] = fake_ip
    headers["X-Real-IP"] = fake_ip
    
    # 3. 设置Connection类型
    headers["Connection"] = conn_type if conn_type in ["keep-alive", "close"] else "keep-alive"
    
    return headers


def headers_to_list(headers: Dict[str, str]) -> List[str]:
    """
    将请求头字典转换为字符串列表（适配urllib/requests等库）
    :param headers: 请求头字典
    :return: 如 ['User-Agent: xxx', 'Accept: xxx']
    """
    return [f"{k}: {v}" for k, v in headers.items()]


if __name__ == "__main__":
    # 测试生成请求头
    for i in range(3):
        headers = get_random_headers(conn_type="keep-alive")
        headers_list = headers_to_list(headers)
        print(f"\n=== 第{i+1}组请求头 ===")
        print("字典形式：")
        for k, v in headers.items():
            print(f"  {k}: {v}")
        print("列表形式：")
        for line in headers_list:
            print(f"  {line}")