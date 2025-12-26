# -*- coding:utf-8 -*-
import logging
import re
from typing import Optional, Dict, Any
import requests
from requests.exceptions import ConnectTimeout, ReadTimeout, RequestException

# ======================== 配置项（集中管理） ========================
# IP归属地查询API地址
IP_API_URL = "http://ip-api.com/json/{ip}?lang=zh-CN"
# 请求超时时间（秒）
REQUEST_TIMEOUT = 4
# 合法IPv4正则（校验输入IP格式）
IPV4_PATTERN = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")

# ======================== 日志配置（便于排查问题） ========================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("IPLocating")

# ======================== 初始化requests会话（复用连接） ========================
SESSION = requests.Session()
SESSION.headers.update({"Accept-Encoding": "gzip, deflate"})  # 启用压缩，提升速度

def is_valid_ipv4(ip: str) -> bool:
    """
    校验是否为合法IPv4地址
    :param ip: 待校验的IP字符串
    :return: True（合法）/False（非法）
    """
    if not isinstance(ip, str) or not ip.strip():
        return False
    return bool(IPV4_PATTERN.match(ip.strip()))

def get_locating(ip: str) -> str:
    """
    获取IP归属地（健壮版）
    :param ip: 待查询的IPv4地址
    :return: 格式化的归属地字符串 / 错误提示字符串
    """
    # 1. 输入校验
    if not is_valid_ipv4(ip):
        error_msg = f"输入IP {ip} 格式非法，请输入合法IPv4地址"
        logger.warning(error_msg)
        return error_msg

    ip = ip.strip()
    # 2. 拼接API URL
    api_url = IP_API_URL.format(ip=ip)

    try:
        # 3. 发起请求（复用会话+指定编码）
        response = SESSION.get(api_url, timeout=REQUEST_TIMEOUT)
        response.encoding = response.apparent_encoding  # 自动识别编码，避免中文乱码
        
        # 4. 解析JSON响应
        json_data: Dict[str, Any] = response.json()
        
        # 5. 校验API返回状态（ip-api.com的核心状态字段）
        if json_data.get("status") != "success":
            error_reason = json_data.get("message", "未知错误")
            error_msg = f"IP {ip} 查询失败：{error_reason}"
            logger.warning(error_msg)
            return error_msg
        
        # 6. 安全提取字段（无则返回空字符串）
        country = json_data.get("country", "")
        region_name = json_data.get("regionName", "")
        city = json_data.get("city", "")
        
        # 7. 格式化返回（空值处理）
        result_str = f"国家({country or '未知'})，省份({region_name or '未知'})，城市({city or '未知'})"
        logger.info(f"IP {ip} 归属地查询成功：{result_str}")
        return result_str

    # 8. 细化异常处理
    except ConnectTimeout:
        error_msg = f"IP {ip} 查询超时（连接API服务器超时）"
        logger.error(error_msg)
        return error_msg
    except ReadTimeout:
        error_msg = f"IP {ip} 查询超时（读取API响应超时）"
        logger.error(error_msg)
        return error_msg
    except RequestException as e:
        error_msg = f"IP {ip} 请求异常：{str(e)[:50]}"
        logger.error(error_msg)
        return error_msg
    except ValueError:  # JSON解析失败
        error_msg = f"IP {ip} 响应解析失败（API返回非JSON数据）"
        logger.error(error_msg)
        return error_msg
    except Exception as e:
        error_msg = f"IP {ip} 查询未知异常：{str(e)[:50]}"
        logger.error(error_msg)
        return error_msg

if __name__ == '__main__':
    # 测试用例1：合法IP（正常场景）
    print("测试1 - 合法IP：", get_locating('139.224.112.182'))
    # 测试用例2：非法IP（格式错误）
    print("测试2 - 非法IP：", get_locating('256.0.0.1'))
    # 测试用例3：空值（输入异常）
    print("测试3 - 空值IP：", get_locating(''))
    # 测试用例4：API返回失败的IP（如保留地址）
    print("测试4 - 保留地址IP：", get_locating('127.0.0.1'))