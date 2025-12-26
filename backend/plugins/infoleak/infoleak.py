# -*- coding:utf-8 -*-
import json
import logging
import os
from pathlib import Path
from typing import List, Tuple, Optional, Dict, Any
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

# ======================== 配置项（集中管理，便于修改） ========================
# 判定风险链接的HTTP状态码
RISK_STATUS_CODES = {200, 206, 401, 305, 407}
# 最大并发线程数
MAX_THREADS = 32
# 请求超时时间（秒）
REQUEST_TIMEOUT = 3
# 是否禁用SSL证书校验（生产环境建议设为True）
VERIFY_SSL = False
# 风险路径字典文件路径
INFOLEAK_JSON_PATH = Path(__file__).parent.parent.parent / "database" / "infoleak.json"

# ======================== 日志配置（统一管理扫描日志） ========================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# ======================== 线程安全的结果存储 ========================
class ThreadSafeResult:
    """线程安全的结果存储类，替代全局列表"""
    def __init__(self):
        self._result: List[Tuple[str, str]] = []
        self._lock = Lock()

    def append(self, item: Tuple[str, str]) -> None:
        """线程安全的添加元素"""
        with self._lock:
            self._result.append(item)

    def get_result(self) -> List[Tuple[str, str]]:
        """获取最终结果"""
        with self._lock:
            return self._result.copy()

    def clear(self) -> None:
        """清空结果"""
        with self._lock:
            self._result.clear()

# ======================== 模拟外部依赖（实际使用时替换为真实导入） ========================
def get_ua() -> Dict[str, str]:
    """生成随机请求头（模拟原代码的randheader.get_ua）"""
    from fake_useragent import UserAgent
    try:
        return {"User-Agent": UserAgent().random}
    except Exception:
        return {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"
        }

# ======================== 核心工具函数 ========================
def load_infoleak_payloads() -> Dict[str, List[str]]:
    """
    加载风险路径字典（健壮版）
    :return: 风险路径字典 {风险类型key: [payload1, payload2,...]}
    """
    # 检查文件是否存在
    if not INFOLEAK_JSON_PATH.exists():
        logger.error(f"风险路径字典文件不存在：{INFOLEAK_JSON_PATH}")
        return {}

    # 读取并解析JSON
    try:
        with open(INFOLEAK_JSON_PATH, 'r', encoding='utf-8') as fp:
            json_data = json.load(fp)
        # 校验JSON结构（兼容原代码格式）
        if not isinstance(json_data, dict) or 'data' not in json_data:
            logger.error(f"infoleak.json格式错误，缺少'data'字段")
            return {}
        # 取第一个data元素（兼容原代码json_data['data'][0]）
        payload_dict = json_data['data'][0] if isinstance(json_data['data'], list) else json_data['data']
        # 去重并过滤空payload
        for key in payload_dict:
            payload_dict[key] = list({p.strip() for p in payload_dict[key] if p.strip()})
        return payload_dict
    except json.JSONDecodeError as e:
        logger.error(f"infoleak.json解析失败：{e}")
        return {}
    except Exception as e:
        logger.error(f"加载风险路径字典异常：{e}")
        return {}

def safe_url_join(base_url: str, payload: str) -> str:
    """
    安全拼接URL（解决//问题）
    :param base_url: 基础URL（如https://test.com/）
    :param payload: 风险路径（如/backup.sql）
    :return: 拼接后的URL（如https://test.com/backup.sql）
    """
    # 确保base_url以/结尾（urljoin的要求）
    if not base_url.endswith('/'):
        base_url += '/'
    # 使用urljoin拼接，自动处理//问题
    return urljoin(base_url, payload.lstrip('/'))

def scan_single_url(url: str, key: str, result_store: ThreadSafeResult, session: requests.Session) -> None:
    """
    扫描单个URL（线程安全版）
    :param url: 待扫描的完整URL
    :param key: 风险类型key
    :param result_store: 线程安全的结果存储对象
    :param session: requests会话（复用连接）
    """
    try:
        # 发起请求（复用会话，减少连接开销）
        response = session.get(
            url,
            headers=get_ua(),
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            verify=VERIFY_SSL
        )
        # 判断是否命中风险状态码
        if response.status_code in RISK_STATUS_CODES:
            logger.info(f"发现风险链接 | 类型：{key} | URL：{url} | 状态码：{response.status_code}")
            result_store.append((key, url))
        else:
            logger.debug(f"无风险 | URL：{url} | 状态码：{response.status_code}")
    except ConnectTimeout:
        logger.warning(f"连接超时 | URL：{url}")
    except ReadTimeout:
        logger.warning(f"读取超时 | URL：{url}")
    except ConnectionError:
        logger.warning(f"连接失败 | URL：{url}")
    except RequestException as e:
        logger.error(f"请求异常 | URL：{url} | 原因：{str(e)[:50]}")
    except Exception as e:
        logger.error(f"未知异常 | URL：{url} | 原因：{str(e)[:50]}")

# ======================== 核心扫描函数 ========================
def get_infoleak(target_url: Optional[str]) -> List[Tuple[str, str]]:
    """
    扫描目标URL的信息泄露风险链接（优化版）
    :param target_url: 目标URL（如https://jwt1399.top/）
    :return: 风险链接列表 [(风险类型key, 风险URL), ...]
    """
    # 1. 输入校验
    if not target_url or not isinstance(target_url, str):
        logger.error("输入URL为空或非字符串类型")
        return []
    target_url = target_url.strip()
    if not target_url:
        logger.error("输入URL为空字符串")
        return []

    # 2. 初始化结果存储
    result_store = ThreadSafeResult()
    result_store.clear()

    # 3. 加载风险路径字典
    payload_dict = load_infoleak_payloads()
    if not payload_dict:
        logger.error("未加载到任何风险路径，扫描终止")
        return []

    # 4. 生成待扫描的URL列表（去重+安全拼接）
    scan_list = []
    for key, payloads in payload_dict.items():
        for payload in payloads:
            full_url = safe_url_join(target_url, payload)
            scan_list.append((full_url, key))
    # 去重（避免重复扫描相同URL）
    scan_list = list({(url, key) for url, key in scan_list})
    logger.info(f"待扫描URL总数：{len(scan_list)}")

    if not scan_list:
        logger.info("无待扫描URL，扫描终止")
        return []

    # 5. 初始化requests会话（复用连接）
    session = requests.Session()
    session.headers.update({"Connection": "keep-alive"})

    # 6. 多线程扫描（使用ThreadPoolExecutor，更优雅）
    try:
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            # 提交所有扫描任务
            futures = [
                executor.submit(scan_single_url, url, key, result_store, session)
                for url, key in scan_list
            ]
            # 等待所有任务完成（设置总超时，避免无限等待）
            total_timeout = len(scan_list) * REQUEST_TIMEOUT + 10  # 总超时=单任务超时*数量+缓冲
            for future in futures:
                try:
                    future.result(timeout=total_timeout)
                except TimeoutError:
                    logger.error("扫描任务超时")
                except Exception as e:
                    logger.error(f"任务执行异常：{e}")
    except Exception as e:
        logger.error(f"线程池执行异常：{e}")
    finally:
        # 关闭会话，释放连接
        session.close()

    # 7. 返回扫描结果
    final_result = result_store.get_result()
    logger.info(f"扫描完成 | 发现风险链接数：{len(final_result)}")
    return final_result

# ======================== 测试入口 ========================
if __name__ == '__main__':
    test_url = "https://jwt1399.top/"
    risk_links = get_infoleak(test_url)
    print("\n=== 扫描结果 ===")
    for key, url in risk_links:
        print(f"风险类型：{key} | 风险URL：{url}")