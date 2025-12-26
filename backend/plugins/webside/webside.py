# -*- coding:utf-8 -*-
import logging
import re
import json
from typing import Dict, List, Optional, Union
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ======================== 配置项集中管理（便于修改） ========================
# API 配置
WEBSCAN_API_URL = "http://api.webscan.cc/?action=query&ip={ip}"
# 请求配置
REQUEST_HEADERS = {
    'Host': 'api.webscan.cc',
    'Origin': 'http://webscan.cc',
    'Pragma': 'no-cache',
    'Referer': 'http://webscan.cc/',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132'
}
REQUEST_TIMEOUT = 8  # 超时时间（秒）
RETRY_TIMES = 2      # 重试次数（网络波动时自动重试）
# 合法 IPv4 正则（校验IP格式）
IPV4_PATTERN = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")

# ======================== 日志配置（便于排查问题） ========================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("WebScanSideInfo")

def is_valid_ipv4(ip: str) -> bool:
    """
    校验是否为合法的 IPv4 地址
    :param ip: 待校验的 IP 字符串
    :return: True（合法）/False（非法）
    """
    if not isinstance(ip, str) or not ip.strip():
        logger.warning(f"IP 输入为空或非字符串：{ip}")
        return False
    return bool(IPV4_PATTERN.match(ip.strip()))

def get_side_info(ip: str) -> Dict[str, Union[bool, str, List[Dict]]]:
    """
    获取 IP 对应的旁站信息（优化版）
    :param ip: 待查询的 IPv4 地址
    :return: 标准化结果字典
        {
            "success": True/False,  # 接口请求是否成功
            "has_data": True/False, # 是否有旁站数据
            "data": [],             # 旁站数据（列表），无数据则为空
            "message": ""           # 结果说明（成功/失败原因）
        }
    """
    # 初始化标准化返回结果
    result = {
        "success": False,
        "has_data": False,
        "data": [],
        "message": ""
    }

    # 1. 校验 IP 格式
    ip = ip.strip() if isinstance(ip, str) else ""
    if not is_valid_ipv4(ip):
        result["message"] = f"IP 格式非法：{ip}"
        logger.error(result["message"])
        return result

    # 2. 创建 Session 并配置重试（提升请求稳定性）
    session = requests.Session()
    retry_strategy = Retry(
        total=RETRY_TIMES,
        backoff_factor=0.5,  # 重试间隔：0.5s → 1s → 2s
        status_forcelist=[429, 500, 502, 503, 504],  # 这些状态码触发重试
        allowed_methods=["GET"]
    )
    session.mount("http://", HTTPAdapter(max_retries=retry_strategy))
    session.mount("https://", HTTPAdapter(max_retries=retry_strategy))
    session.keep_alive = False  # 关闭多余连接

    try:
        # 3. 拼接 API URL 并发起请求
        api_url = WEBSCAN_API_URL.format(ip=ip)
        logger.info(f"发起旁站查询请求 | IP：{ip} | API URL：{api_url}")
        
        response = session.get(
            api_url,
            headers=REQUEST_HEADERS,
            timeout=REQUEST_TIMEOUT,
            verify=False  # 忽略 SSL 校验（API 为 http，无影响）
        )

        # 4. 校验响应状态码（非 200 直接判定请求失败）
        response.raise_for_status()
        logger.info(f"请求成功 | IP：{ip} | 状态码：{response.status_code}")

        # 5. 处理响应编码和 BOM 字符（通用方式）
        response.encoding = response.apparent_encoding or "utf-8"
        text = response.text
        # 移除 UTF-8 BOM 字符（兼容不同 BOM 格式）
        if text.startswith('\ufeff'):
            text = text[1:]

        # 6. 判断是否有数据（返回 null 表示无数据）
        if "null" in text.strip().lower():
            result["success"] = True
            result["has_data"] = False
            result["message"] = f"IP {ip} 无旁站信息"
            logger.info(result["message"])
            return result

        # 7. 解析 JSON 数据
        side_data = json.loads(text)
        result["success"] = True
        result["has_data"] = True
        result["data"] = side_data
        result["message"] = f"IP {ip} 查询到 {len(side_data)} 条旁站信息"
        logger.info(result["message"])

    # 8. 细化异常处理（精准定位问题）
    except requests.exceptions.ConnectTimeout:
        result["message"] = f"IP {ip} 连接 API 超时（{REQUEST_TIMEOUT}秒）"
        logger.error(result["message"])
    except requests.exceptions.ReadTimeout:
        result["message"] = f"IP {ip} 读取 API 响应超时（{REQUEST_TIMEOUT}秒）"
        logger.error(result["message"])
    except requests.exceptions.HTTPError as e:
        result["message"] = f"IP {ip} 请求失败 | 状态码：{e.response.status_code} | 原因：{e}"
        logger.error(result["message"])
    except json.JSONDecodeError:
        result["message"] = f"IP {ip} API 返回内容非合法 JSON | 内容：{text[:100]}..."
        logger.error(result["message"])
    except requests.exceptions.RequestException as e:
        result["message"] = f"IP {ip} 请求异常 | 原因：{str(e)[:50]}"
        logger.error(result["message"])
    except Exception as e:
        result["message"] = f"IP {ip} 查询未知异常 | 原因：{str(e)[:50]}"
        logger.error(result["message"])
    finally:
        # 关闭 Session，释放连接资源
        session.close()

    return result

# ======================== 测试入口 ========================
if __name__ == '__main__':
    # 测试 1：合法 IP（有数据/无数据均可）
    test_ip1 = "139.224.112.182"
    result1 = get_side_info(test_ip1)
    print(f"测试 IP {test_ip1} 结果：\n{json.dumps(result1, ensure_ascii=False, indent=2)}")

    # 测试 2：非法 IP
    test_ip2 = "256.0.0.1"
    result2 = get_side_info(test_ip2)
    print(f"\n测试 IP {test_ip2} 结果：\n{json.dumps(result2, ensure_ascii=False, indent=2)}")