# -*- coding:utf-8 -*-
"""
TCP全连接端口扫描工具
功能:识别目标开放端口及对应服务,支持IP/域名/URL输入
优化点:线程安全、资源释放、正则预编译、代码规范、功能扩展
【扩充版】新增SRC高频端口、内网服务、测试后台、中间件、运维面板
"""
import socket
import re
from concurrent.futures import ThreadPoolExecutor
import sys
from typing import List, Dict, Set
from dataclasses import dataclass
import threading

# -------------------------- 配置项(集中管理,便于修改) --------------------------
THREAD_NUM = 64  # 线程数
SOCKET_TIMEOUT = 1  # 套接字超时时间(秒)
BANNER_BYTES = 1024  # 接收Banner最大字节数(避免截断)
MAX_OPEN_PORTS = 100  # 最大开放端口数(替代原无意义的25限制)

# -------------------------- 服务指纹(预编译正则,提升效率) --------------------------
@dataclass
class ServiceSign:
    """服务指纹数据类:协议/服务名/正则表达式"""
    proto: str
    service: str
    pattern: re.Pattern


# 预编译SIGNS正则(字节串匹配)【扩充完整版，SRC全场景覆盖】
SIGNS = [
    # 基础通用服务
    ServiceSign(b'smb', b'smb', re.compile(rb'^\0\0\0.\xffSMBr\0\0\0.*', re.IGNORECASE)),
    ServiceSign(b'xmpp', b'xmpp', re.compile(rb'^<\?xml version=\'1.0\'\?>', re.IGNORECASE)),
    ServiceSign(b'netbios', b'netbios', re.compile(rb'^\x79\x08.*BROWSE', re.IGNORECASE)),
    ServiceSign(b'http', b'http', re.compile(rb'HTTP/1.', re.IGNORECASE)),
    ServiceSign(b'ftp', b'ftp', re.compile(b'^220.*FTP', re.IGNORECASE)),
    ServiceSign(b'ssh', b'ssh', re.compile(b'^SSH-', re.IGNORECASE)),
    ServiceSign(b'redis', b'redis', re.compile(b'^-ERR unknown command|^\+PONG', re.IGNORECASE)),
    ServiceSign(b'mysql', b'mysql', re.compile(b'mysql_native_password|^\d\.\d\.\d{1,2}', re.IGNORECASE)),
    ServiceSign(b'rdp', b'rdp', re.compile(b'^\x03\x00\x00\x0b', re.IGNORECASE)),

    # Web中间件/服务器
    ServiceSign(b'nginx', b'nginx', re.compile(rb'Server: nginx', re.IGNORECASE)),
    ServiceSign(b'apache', b'apache', re.compile(rb'Server: Apache', re.IGNORECASE)),
    ServiceSign(b'tomcat', b'tomcat', re.compile(rb'Apache Tomcat', re.IGNORECASE)),
    ServiceSign(b'jetty', b'jetty', re.compile(rb'Jetty', re.IGNORECASE)),
    ServiceSign(b'weblogic', b'weblogic', re.compile(rb'WebLogic', re.IGNORECASE)),
    ServiceSign(b'jboss', b'jboss', re.compile(rb'JBoss|WildFly', re.IGNORECASE)),
    ServiceSign(b'iis', b'iis', re.compile(rb'Server: Microsoft-IIS', re.IGNORECASE)),

    # 数据库
    ServiceSign(b'postgresql', b'postgresql', re.compile(rb'^PostgreSQL', re.IGNORECASE)),
    ServiceSign(b'sqlserver', b'sqlserver', re.compile(rb'^\x04\x01\x00\x00', re.IGNORECASE)),
    ServiceSign(b'oracle', b'oracle', re.compile(rb'^\x00\x00\x06\x02', re.IGNORECASE)),
    ServiceSign(b'mongodb', b'mongodb', re.compile(rb'^MongoDB', re.IGNORECASE)),
    ServiceSign(b'elasticsearch', b'es', re.compile(rb'\"number\":\"[\d\.]+\"', re.IGNORECASE)),

    # 消息队列/分布式组件
    ServiceSign(b'rabbitmq', b'rabbitmq', re.compile(rb'RabbitMQ', re.IGNORECASE)),
    ServiceSign(b'kafka', b'kafka', re.compile(rb'Kafka', re.IGNORECASE)),
    ServiceSign(b'zookeeper', b'zookeeper', re.compile(rb'^ZooKeeper', re.IGNORECASE)),
    ServiceSign(b'nacos', b'nacos', re.compile(rb'Nacos', re.IGNORECASE)),
    ServiceSign(b'dubbo', b'dubbo', re.compile(rb'Dubbo', re.IGNORECASE)),

    # 运维/监控/测试面板
    ServiceSign(b'jenkins', b'jenkins', re.compile(rb'Jenkins', re.IGNORECASE)),
    ServiceSign(b'gitlab', b'gitlab', re.compile(rb'GitLab', re.IGNORECASE)),
    ServiceSign(b'prometheus', b'prometheus', re.compile(rb'Prometheus', re.IGNORECASE)),
    ServiceSign(b'grafana', b'grafana', re.compile(rb'Grafana', re.IGNORECASE)),
    ServiceSign(b'btpanel', b'btpanel', re.compile(rb'\xe5\xae\x9d\xe5\xa1\x94Linux\xe9\x9d\xa2\xe6\x9d\xbf', re.IGNORECASE)),
    ServiceSign(b'qinglong', b'qinglong', re.compile(rb'Qinglong', re.IGNORECASE)),

    # 内网/文件服务
    ServiceSign(b'minio', b'minio', re.compile(rb'Minio', re.IGNORECASE)),
    ServiceSign(b'fastdfs', b'fastdfs', re.compile(rb'FastDFS', re.IGNORECASE)),
    ServiceSign(b'svn', b'svn', re.compile(rb'svn', re.IGNORECASE)),
    ServiceSign(b'telnet', b'telnet', re.compile(rb'^Telnet', re.IGNORECASE)),
    ServiceSign(b'dns', b'dns', re.compile(rb'^DNS', re.IGNORECASE)),
]

# -------------------------- 端口-服务映射表【完整版扩充】 --------------------------
PORT_SERVICE_MAP: Dict[str, str] = {
    # 基础网络服务
    '21': 'FTP', '22': 'SSH', '23': 'Telnet', '25': 'SMTP', '53': 'DNS',
    '67': 'DHCP', '68': 'DHCP', '80': 'HTTP', '110': 'POP3', '143': 'IMAP',
    '443': 'HTTPS', '465': 'SMTP-SSL', '995': 'POP3-SSL',

    # Windows内网服务
    '135': 'RPC', '139': 'NetBIOS', '445': 'SMB', '5985': 'WinRM',

    # 数据库服务
    '1433': 'SQLServer', '1521': 'Oracle', '3306': 'MySQL', '5432': 'PostgreSQL',
    '6379': 'Redis', '8123': 'ClickHouse', '9200': 'Elasticsearch', '27017': 'MongoDB',

    # Web中间件/测试后台(SRC核心)
    '7001': 'WebLogic', '8080': 'Tomcat/HTTP', '8081': '测试后台', '8082': '内部服务',
    '8088': 'Hadoop', '8090': '测试接口', '8443': 'HTTPS-Tomcat', '9000': '测试面板',
    '9080': 'WebSphere', '9090': '监控面板',

    # 运维/面板服务
    '888': '宝塔面板', '8888': '宝塔/测试后台', '3000': 'NodeJS', '5601': 'Kibana',
    '9100': 'Prometheus', '3389': 'RDP', '5900': 'VNC',

    # 分布式/消息队列
    '2181': 'ZooKeeper', '5672': 'RabbitMQ', '8848': 'Nacos', '9092': 'Kafka',
    '20880': 'Dubbo', '11211': 'Memcached',

    # 文件/存储服务
    '873': 'RSYNC', '2049': 'NFS', '9001': 'MinIO',

    # SRC冷门边缘资产端口
    '7000': '内部系统', '8000': '通用后台', '8008': '废弃服务', '10000': '管理后台'
}

# -------------------------- 探测报文【完整版扩充】 --------------------------
PROBES = [
    # Web服务探测
    b'GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n',
    b'HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n',
    b'GET /manager/html HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n',  # Tomcat
    b'GET /login HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n',  # 通用后台

    # 数据库探测
    b'\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x75\x73\x65\x72\x6e\x61\x6d\x65\x00\x00\x00\x00',  # MySQL
    b'NAMESPACE system\r\nGET /_cat/health?v HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n',  # ES
    b'*1\r\n$4\r\nping\r\n',  # Redis

    # 远程/登录服务
    b'SSH-2.0-ScanTool\r\n',  # SSH
    b'\x03\x00\x00\x0b',  # RDP
]

# -------------------------- 端口扫描核心类 --------------------------
class ScanPort:
    def __init__(self, target: str):
        """
        初始化端口扫描器
        :param target: 目标(IP/域名/URL)
        """
        self.target = target
        self.ipaddr: str = ""
        self._last_error: str = ""
        self.open_ports: Set[str] = set()
        self.service_results: Set[str] = set()
        self.lock = threading.Lock()
        self.portspoof_flag = False

    def get_last_error(self) -> str:
        """获取最后一次错误信息"""
        return self._last_error

    def _normalize_target(self) -> bool:
        """
        标准化目标:去协议/路径、解析域名、提取IP
        :return: 标准化成功返回True,失败返回False
        """
        try:
            normalized = self.target.replace('http://', '').replace('https://', '').rstrip('/')
            normalized = normalized.split('/')[0]
            
            if ':' in normalized:
                normalized = normalized.split(':')[0]
            
            if re.match(r'\d+\.\d+\.\d+\.\d+', normalized):
                self.ipaddr = normalized
                return True
            
            try:
                ip_list = socket.gethostbyname_ex(normalized)[2]
                if ip_list:
                    self.ipaddr = ip_list[0]
                    return True
                else:
                    self._last_error = f"域名 {normalized} 未解析到IP地址，请检查域名是否正确"
                    return False
            except socket.gaierror as e:
                self._last_error = f"DNS解析失败: 域名 '{normalized}' 无法解析 (错误码: {e.errno})"
                return False
        except (ValueError, TypeError) as e:
            self._last_error = f"目标格式无效: {str(e)}"
            return False

    def _get_service_by_port(self, port: str) -> str:
        """
        通过端口号获取服务名
        :param port: 端口字符串
        :return: 服务名,未知则返回Unknown:端口
        """
        return PORT_SERVICE_MAP.get(port, f"Unknown:{port}")

    def _identify_service(self, banner: bytes, port: str) -> str:
        """
        识别服务:先匹配Banner指纹,再按端口映射
        :param banner: 端口返回的Banner
        :param port: 端口号
        :return: 服务标识(如http:80)
        """
        # 匹配Banner指纹
        for sign in SIGNS:
            if sign.pattern.search(banner):
                return f"{sign.service.decode()}:{port}"
        # 指纹未匹配,按端口映射
        service = self._get_service_by_port(port)
        return f"{service}:{port}"

    def socket_scan(self, host_port: str):
        """
        单端口扫描核心逻辑(线程安全)
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
                    # 检查开放端口数,避免端口欺骗
                    if len(self.open_ports) >= MAX_OPEN_PORTS:
                        self.portspoof_flag = True
                        sock.close()
                        return
                    self.open_ports.add(port)
                
                # 发送探测报文,获取Banner
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
                
                # 识别服务并更新结果(线程安全)
                service = self._identify_service(banner, port)
                with self.lock:
                    self.service_results.add(service)
            
            # 确保套接字关闭(资源释放)
            sock.close()
        except Exception as e:
            # 仅打印错误,不中断整体扫描
            print(f"[WARNING] 扫描端口 {host_port} 失败:{e}")

    def run_scan(self) -> bool:
        """
        启动多线程扫描
        :return: 扫描成功返回True,失败返回False
        """
        # 先标准化目标
        if not self._normalize_target():
            return False
        
        # 生成待扫描端口列表【完整版扩充，覆盖SRC全场景】
        ports = [
            21,22,23,25,53,80,135,139,443,445,
            888,1433,1521,3306,3389,5432,5900,6379,8000,8080,
            8081,8082,8088,8090,8443,8888,9000,9090,9200,2181,
            5672,8848,9092,20880,27017,11211,10000
        ]
        host_ports = [f"{self.ipaddr}:{p}" for p in ports]
        
        # 多线程扫描
        try:
            with ThreadPoolExecutor(max_workers=THREAD_NUM) as executor:
                executor.map(self.socket_scan, host_ports)
            return True
        except Exception as e:
            print(f"[ERROR] 多线程扫描失败:{e}")
            return False

    def get_results(self) -> List[str]:
        """
        获取扫描结果(去重、格式化)
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
        print(f"Example: {sys.argv[0]} http://testasp.vulnweb.com")
        sys.exit(1)
    
    target = sys.argv[1]
    scanner = ScanPort(target)
    
    print(f"[INFO] 开始扫描目标:{target}")
    if scanner.run_scan():
        results = scanner.get_results()
        print("[INFO] 扫描完成,开放端口及服务:")
        for res in results:
            print(f"  {res}")
    else:
        print(f"[ERROR] 扫描目标 {target} 失败")

if __name__ == "__main__":
    main()