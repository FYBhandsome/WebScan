# -*- coding:utf-8 -*-
"""
TCP全连接端口扫描工具
功能：识别目标开放端口及对应服务，支持IP/域名/URL输入
优化点：线程安全、资源释放、正则预编译、代码规范、功能扩展
"""
import socket
import re
from concurrent.futures import ThreadPoolExecutor
import sys
import os
from typing import List, Dict, Set
from dataclasses import dataclass
import threading

# -------------------------- 配置项（集中管理，便于修改） --------------------------
THREAD_NUM = 64  # 线程数
SOCKET_TIMEOUT = 1  # 套接字超时时间（秒）
BANNER_BYTES = 1024  # 接收Banner最大字节数（避免截断）
MAX_OPEN_PORTS = 100  # 最大开放端口数（替代原无意义的25限制）

# -------------------------- 服务指纹（预编译正则，提升效率） --------------------------
@dataclass
class ServiceSign:
    """服务指纹数据类：协议/服务名/正则表达式"""
    proto: str
    service: str
    pattern: re.Pattern

# 预编译SIGNS正则（字节串匹配）
SIGNS = [
    ServiceSign(b'smb', b'smb', re.compile(b'^\0\0\0.\xffSMBr\0\0\0\0.*', re.IGNORECASE)),
    ServiceSign(b'xmpp', b'xmpp', re.compile(b'^\<\?xml version=\'1.0\'\?\>', re.IGNORECASE)),
    ServiceSign(b'netbios', b'netbios', re.compile(b'^\x79\x08.*BROWSE', re.IGNORECASE)),
    ServiceSign(b'http', b'http', re.compile(b'HTTP/1.1', re.IGNORECASE)),
    ServiceSign(b'ftp', b'ftp', re.compile(b'^220.*FTP', re.IGNORECASE)),
    ServiceSign(b'ssh', b'ssh', re.compile(b'^SSH-', re.IGNORECASE)),
    ServiceSign(b'redis', b'redis', re.compile(b'^-ERR unknown command', re.IGNORECASE)),
    ServiceSign(b'mysql', b'mysql', re.compile(b'mysql_native_password', re.IGNORECASE)),
    ServiceSign(b'rdp', b'rdp', re.compile(b'^\x03\x00\x00\x0b', re.IGNORECASE)),
    # 其余指纹可按此格式补充，省略部分以简化代码
]

# -------------------------- 端口-服务映射表 --------------------------
PORT_SERVICE_MAP: Dict[str, str] = {
    '21': 'FTP', '22': 'SSH', '23': 'Telnet', '25': 'SMTP', '53': 'DNS',
    '80': 'HTTP', '443': 'HTTPS', '139': 'NetBIOS', '445': 'SMB',
    '3306': 'MySQL/MariaDB', '3389': 'RDP', '6379': 'Redis',
    '27017': 'MongoDB', '11211': 'Memcached', '8080': 'HTTP',
    # 其余端口映射可补充
}

# -------------------------- 探测报文（多协议，覆盖更多场景） --------------------------
PROBES = [
    b'GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n',  # HTTP
    b'\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x75\x73\x65\x72\x6e\x61\x6d\x65\x00\x00\x00\x00',  # MySQL
    b'*1\r\n$4\r\nping\r\n',  # Redis
    b'SSH-2.0-Test\r\n',  # SSH
]

# -------------------------- 端口扫描核心类 --------------------------
class ScanPort:
    def __init__(self, target: str):
        """
        初始化端口扫描器
        :param target: 目标（IP/域名/URL）
        """
        self.target = target
        self.ipaddr: str = ""
        # 线程安全的结果存储（用锁保护）
        self.open_ports: Set[str] = set()
        self.service_results: Set[str] = set()
        self.lock = threading.Lock()
        self.portspoof_flag = False  # 是否触发端口欺骗标记

    def _normalize_target(self) -> bool:
        """
        标准化目标：去协议/路径、解析域名、提取IP
        :return: 标准化成功返回True，失败返回False
        """
        try:
            # 去除HTTP/HTTPS协议和路径
            normalized = self.target.replace('http://', '').replace('https://', '').rstrip('/')
            normalized = normalized.split('/')[0]
            
            # 提取IP（去除端口）
            if ':' in normalized:
                normalized = normalized.split(':')[0]
            
            # 检查是否为IP
            if re.match(r'\d+\.\d+\.\d+\.\d+', normalized):
                self.ipaddr = normalized
                return True
            
            # 域名解析（处理多IP场景，取第一个）
            ip_list = socket.gethostbyname_ex(normalized)[2]
            if ip_list:
                self.ipaddr = ip_list[0]
                return True
            else:
                print(f"[ERROR] 域名 {normalized} 未解析到IP")
                return False
        except (socket.gaierror, ValueError, TypeError) as e:
            print(f"[ERROR] 目标标准化失败：{e}")
            return False

    def _get_service_by_port(self, port: str) -> str:
        """
        通过端口号获取服务名
        :param port: 端口字符串
        :return: 服务名，未知则返回Unknown:端口
        """
        return PORT_SERVICE_MAP.get(port, f"Unknown:{port}")

    def _identify_service(self, banner: bytes, port: str) -> str:
        """
        识别服务：先匹配Banner指纹，再按端口映射
        :param banner: 端口返回的Banner
        :param port: 端口号
        :return: 服务标识（如http:80）
        """
        # 匹配Banner指纹
        for sign in SIGNS:
            if sign.pattern.search(banner):
                return f"{sign.service.decode()}:{port}"
        # 指纹未匹配，按端口映射
        service = self._get_service_by_port(port)
        return f"{service}:{port}"

    def socket_scan(self, host_port: str):
        """
        单端口扫描核心逻辑（线程安全）
        :param host_port: 格式为 "IP:端口"
        """
        try:
            ip, port = host_port.split(':')
            port_int = int(port)
            
            # 创建套接字并设置超时
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(SOCKET_TIMEOUT)
            
            # TCP全连接扫描
            result = sock.connect_ex((ip, port_int))
            if result == 0:  # 端口开放
                with self.lock:
                    # 检查开放端口数，避免端口欺骗
                    if len(self.open_ports) >= MAX_OPEN_PORTS:
                        self.portspoof_flag = True
                        sock.close()
                        return
                    self.open_ports.add(port)
                
                # 发送探测报文，获取Banner
                banner = b""
                for probe in PROBES:
                    try:
                        # 替换探测报文中的IP占位符
                        probe_data = probe.replace(b'{ip}', ip.encode())
                        sock.sendall(probe_data)
                        banner = sock.recv(BANNER_BYTES)
                        if banner:
                            break
                    except (socket.timeout, BrokenPipeError, ConnectionResetError):
                        continue
                
                # 识别服务并更新结果（线程安全）
                service = self._identify_service(banner, port)
                with self.lock:
                    self.service_results.add(service)
            
            # 确保套接字关闭（资源释放）
            sock.close()
        except Exception as e:
            # 仅打印错误，不中断整体扫描
            print(f"[WARNING] 扫描端口 {host_port} 失败：{e}")

    def run_scan(self) -> bool:
        """
        启动多线程扫描
        :return: 扫描成功返回True，失败返回False
        """
        # 先标准化目标
        if not self._normalize_target():
            return False
        
        # 生成待扫描端口列表
        ports = [
            21,22,23,25,53,80,443,139,445,3306,3389,6379,27017,11211,8080
        ]  # 简化端口列表，可替换为原完整列表
        host_ports = [f"{self.ipaddr}:{p}" for p in ports]
        
        # 多线程扫描
        try:
            with ThreadPoolExecutor(max_workers=THREAD_NUM) as executor:
                executor.map(self.socket_scan, host_ports)
            return True
        except Exception as e:
            print(f"[ERROR] 多线程扫描失败：{e}")
            return False

    def get_results(self) -> List[str]:
        """
        获取扫描结果（去重、格式化）
        :return: 开放端口+服务列表
        """
        if self.portspoof_flag:
            return ["Portspoof:0"]
        
        # 补充未识别服务的端口
        for port in self.open_ports:
            # 检查是否已通过Banner识别
            if not any(s.endswith(f":{port}") for s in self.service_results):
                service = self._get_service_by_port(port)
                self.service_results.add(f"{service}:{port}")
        
        # 去重并排序返回
        sorted_results = sorted(list(self.service_results), key=lambda x: int(x.split(':')[-1]))
        return sorted_results

# -------------------------- 主函数 --------------------------
def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <target>")
        print(f"Example: {sys.argv[0]} 127.0.0.1")
        print(f"Example: {sys.argv[0]} https://baidu.com")
        sys.exit(1)
    
    target = sys.argv[1]
    scanner = ScanPort(target)
    
    print(f"[INFO] 开始扫描目标：{target}")
    if scanner.run_scan():
        results = scanner.get_results()
        print(f"[INFO] 扫描完成，开放端口及服务：")
        for res in results:
            print(f"  {res}")
    else:
        print(f"[ERROR] 扫描目标 {target} 失败")

if __name__ == "__main__":
    main()