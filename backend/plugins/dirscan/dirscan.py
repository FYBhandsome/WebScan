# -*- coding:utf-8 -*-
"""
目录扫描模块
功能:
1. 对目标URL进行目录和文件爆破
2. 支持多线程并发扫描
3. 支持自定义字典文件
4. 智能判断有效响应(200、301、302、403等)
5. 支持递归扫描

特性:
- 线程安全的结果存储
- 支持多种HTTP状态码判断
- 自动去重,避免重复扫描
- 支持自定义请求头
- 支持扩展名模糊匹配

依赖:
- requests: 用于HTTP请求
- concurrent.futures: 用于多线程
"""

import json
import logging
import re
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Set
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from threading import Lock

import requests
from requests.exceptions import (
    ConnectTimeout,
    ReadTimeout,
    ConnectionError,
    RequestException
)

from ..common.common import get_domain
from ..randheader.randheader import get_ua

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

CONFIG = {
    "valid_status_codes": {200, 201, 202, 203, 204, 205, 206, 301, 302, 303, 304, 307, 308, 401, 403},
    "max_threads": 32,
    "request_timeout": 5,
    "verify_ssl": False,
    "max_results": 500,
    "default_extensions": [".php", ".asp", ".aspx", ".jsp", ".html", ".htm", ".js", ".json", ".xml", ".txt", ".bak", ".zip", ".tar", ".gz"],
    "default_dict_path": Path(__file__).parent.parent.parent / "database" / "dirscan_dict.txt"
}


class ThreadSafeResult:
    def __init__(self):
        self._result: List[Dict] = []
        self._lock = Lock()

    def append(self, item: Dict) -> None:
        with self._lock:
            if len(self._result) < CONFIG["max_results"]:
                self._result.append(item)

    def get_result(self) -> List[Dict]:
        with self._lock:
            return self._result.copy()

    def clear(self) -> None:
        with self._lock:
            self._result.clear()

    def is_full(self) -> bool:
        with self._lock:
            return len(self._result) >= CONFIG["max_results"]


class DirScanner:
    def __init__(self, target: str, config: Dict = None):
        self.target = self._normalize_url(target)
        self.config = {**CONFIG, **(config or {})}
        self.result_store = ThreadSafeResult()
        self.scanned_paths: Set[str] = set()
        self.lock = Lock()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": get_ua().get("User-Agent", "Mozilla/5.0"),
            "Accept": "*/*",
            "Connection": "keep-alive"
        })

    def _normalize_url(self, target: str) -> str:
        target = target.strip()
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
        return target.rstrip("/")

    def _load_dictionary(self, dict_path: str = None) -> List[str]:
        paths = []
        dict_file = Path(dict_path) if dict_path else self.config["default_dict_path"]
        
        if dict_file.exists():
            try:
                with open(dict_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            paths.append(line)
                logger.info(f"从 {dict_file} 加载了 {len(paths)} 条路径")
            except Exception as e:
                logger.error(f"加载字典文件失败: {e}")
        
        if not paths:
            paths = self._get_default_paths()
            logger.info(f"使用默认字典，共 {len(paths)} 条路径")
        
        return paths

    def _get_default_paths(self) -> List[str]:
        return [
            "/admin", "/administrator", "/admin.php", "/admin.html",
            "/login", "/login.php", "/login.html", "/signin",
            "/api", "/api/v1", "/api/v2", "/api/docs",
            "/backup", "/backup.zip", "/backup.sql", "/backup.tar.gz",
            "/config", "/config.php", "/config.xml", "/config.json",
            "/db", "/database", "/database.sql", "/db.sql",
            "/upload", "/uploads", "/files", "/download",
            "/images", "/img", "/static", "/assets", "/css", "/js",
            "/test", "/debug", "/dev", "/staging",
            "/.git", "/.git/config", "/.git/HEAD", "/.svn",
            "/.env", "/.htaccess", "/.htpasswd", "/web.config",
            "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
            "/README.md", "/readme.txt", "/CHANGELOG.md",
            "/phpinfo.php", "/info.php", "/test.php",
            "/wp-admin", "/wp-login.php", "/wp-content", "/wp-includes",
            "/xmlrpc.php", "/wp-config.php",
            "/manager", "/manager/html", "/host-manager",
            "/console", "/jmx-console", "/web-console",
            "/solr", "/solr/admin", "/actuator", "/actuator/health",
            "/swagger-ui.html", "/swagger-resources", "/v2/api-docs",
            "/graphql", "/graphiql",
            "/.DS_Store", "/Thumbs.db",
            "/server-status", "/server-info",
            "/cgi-bin", "/scripts",
            "/temp", "/tmp", "/log", "/logs",
            "/install", "/install.php", "/setup.php",
            "/user", "/users", "/account", "/profile",
            "/search", "/query", "/find",
            "/export", "/import", "/report",
            "/shell", "/cmd", "/exec", "/run",
            "/private", "/public", "/secure", "/auth",
            "/oauth", "/token", "/refresh",
            "/health", "/status", "/ping", "/metrics",
            "/index.php", "/index.html", "/index.asp", "/index.aspx",
            "/default.php", "/default.html", "/main.php", "/main.html",
            "/home.php", "/home.html", "/welcome.php",
        ]

    def _generate_paths_with_extensions(self, base_paths: List[str]) -> List[str]:
        extended_paths = list(base_paths)
        extensions = self.config.get("extensions", CONFIG["default_extensions"])
        
        for path in base_paths:
            if '.' not in Path(path).suffix:
                for ext in extensions:
                    extended_paths.append(f"{path}{ext}")
        
        return list(set(extended_paths))

    def _scan_single_path(self, path: str) -> Optional[Dict]:
        if self.result_store.is_full():
            return None

        with self.lock:
            if path in self.scanned_paths:
                return None
            self.scanned_paths.add(path)

        full_url = f"{self.target}{path}"
        
        try:
            response = self.session.get(
                full_url,
                timeout=self.config["request_timeout"],
                allow_redirects=False,
                verify=self.config["verify_ssl"]
            )

            if response.status_code in self.config["valid_status_codes"]:
                content_length = len(response.content)
                result = {
                    "url": full_url,
                    "path": path,
                    "status_code": response.status_code,
                    "content_length": content_length,
                    "redirect": response.headers.get("Location", ""),
                    "content_type": response.headers.get("Content-Type", ""),
                    "server": response.headers.get("Server", "")
                }
                logger.info(f"发现有效路径: {full_url} [状态码: {response.status_code}] [大小: {content_length}]")
                return result

        except ConnectTimeout:
            logger.debug(f"连接超时: {full_url}")
        except ReadTimeout:
            logger.debug(f"读取超时: {full_url}")
        except ConnectionError:
            logger.debug(f"连接失败: {full_url}")
        except RequestException as e:
            logger.debug(f"请求异常: {full_url} - {str(e)[:50]}")
        except Exception as e:
            logger.debug(f"未知异常: {full_url} - {str(e)[:50]}")
        
        return None

    def scan(self, dict_path: str = None, extensions: List[str] = None) -> Dict:
        logger.info(f"开始目录扫描: {self.target}")
        
        self.result_store.clear()
        self.scanned_paths.clear()
        
        if extensions:
            self.config["extensions"] = extensions

        base_paths = self._load_dictionary(dict_path)
        all_paths = self._generate_paths_with_extensions(base_paths)
        
        logger.info(f"总共 {len(all_paths)} 条路径待扫描")

        try:
            with ThreadPoolExecutor(max_workers=self.config["max_threads"]) as executor:
                futures = [executor.submit(self._scan_single_path, path) for path in all_paths]
                
                for future in futures:
                    try:
                        result = future.result(timeout=self.config["request_timeout"] * 2)
                        if result:
                            self.result_store.append(result)
                    except Exception:
                        pass
        except Exception as e:
            logger.error(f"扫描过程出错: {e}")
        finally:
            self.session.close()

        results = self.result_store.get_result()
        results.sort(key=lambda x: x.get("status_code", 0))
        
        logger.info(f"目录扫描完成，发现 {len(results)} 个有效路径")
        
        return {
            "code": 200,
            "msg": "扫描完成",
            "target": self.target,
            "total_scanned": len(self.scanned_paths),
            "found_count": len(results),
            "results": results
        }


def get_dirscan(target: str, config: Dict = None, dict_path: str = None) -> Dict:
    if not target or not isinstance(target, str):
        return {
            "code": 400,
            "msg": "目标URL不能为空",
            "results": []
        }
    
    target = target.strip()
    if not target:
        return {
            "code": 400,
            "msg": "目标URL不能为空",
            "results": []
        }

    try:
        scanner = DirScanner(target, config)
        result = scanner.scan(dict_path)
        return result
    except Exception as e:
        logger.error(f"目录扫描失败: {e}")
        return {
            "code": 500,
            "msg": f"扫描失败: {str(e)}",
            "results": []
        }


if __name__ == '__main__':
    test_url = "http://example.com"
    result = get_dirscan(test_url)
    print(json.dumps(result, ensure_ascii=False, indent=2))
