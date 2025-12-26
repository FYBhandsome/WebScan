# -*- coding:utf-8 -*-
import logging
import json
from typing import Dict, Union, Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ======================== 配置项集中管理（便于维护） ========================
# 爱站API配置（建议将密钥移到环境变量/配置文件，避免硬编码）
AIZHAN_API_KEY = "37c7d94115d0c84a46527e7689a2ab72"
AIZHAN_API_URL = f"https://apistore.aizhan.com/baidurank/siteinfos/{AIZHAN_API_KEY}?domains="
# 请求配置
REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Referer": "https://www.aizhan.com/"
}
REQUEST_TIMEOUT = 4  # 超时时间（秒）
RETRY_TIMES = 2      # 重试次数（网络波动时自动重试）

# ======================== 日志配置（便于排查问题） ========================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("AizhanWebWeight")

# ======================== 模拟getdomain函数（适配原代码依赖） ========================
def getdomain(domain: str) -> str:
    """
    提取纯域名（移除协议、路径、端口等）
    :param domain: 原始域名/URL（如https://jwt1399.top/）
    :return: 纯域名（如jwt1399.top）
    """
    if not isinstance(domain, str) or not domain.strip():
        return ""
    domain = domain.strip()
    # 移除协议（http/https）
    if domain.startswith(("http://", "https://")):
        domain = domain.split("//")[-1]
    # 移除路径、端口、参数等
    domain = domain.split("/")[0].split(":")[0]
    return domain

def is_valid_domain(domain: str) -> bool:
    """
    校验域名格式是否合法（简单校验，满足基础需求）
    :param domain: 纯域名
    :return: True（合法）/False（非法）
    """
    if not domain or "." not in domain:
        return False
    # 基础域名正则（匹配 xxx.xxx 格式）
    import re
    domain_pattern = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$')
    return bool(domain_pattern.match(domain))

def get_web_weight(domain: str) -> Dict[str, Union[bool, str, Dict]]:
    """
    获取网站权重（优化版）
    :param domain: 原始域名/URL（如https://jwt1399.top/）
    :return: 标准化结果字典
        {
            "success": True/False,  # 请求+解析是否成功
            "result": "",           # 格式化结果字符串
            "raw_data": {},         # API返回的原始数据（便于调试）
            "message": ""           # 成功/失败原因
        }
    """
    # 初始化标准化返回结果
    result = {
        "success": False,
        "result": "获取数据失败，请稍后再试",
        "raw_data": {},
        "message": ""
    }

    # 1. 提取纯域名并校验格式
    pure_domain = getdomain(domain)
    if not is_valid_domain(pure_domain):
        result["message"] = f"域名格式非法：{domain} → 提取纯域名：{pure_domain}"
        logger.error(result["message"])
        return result

    # 2. 创建Session并配置重试（提升请求稳定性）
    session = requests.Session()
    retry_strategy = Retry(
        total=RETRY_TIMES,
        backoff_factor=0.5,  # 重试间隔：0.5s → 1s → 2s
        status_forcelist=[429, 500, 502, 503, 504],  # 这些状态码触发重试
        allowed_methods=["GET"]
    )
    session.mount("https://", HTTPAdapter(max_retries=retry_strategy))
    session.keep_alive = False  # 关闭多余连接

    try:
        # 3. 拼接API URL并发起请求
        api_url = AIZHAN_API_URL + pure_domain
        logger.info(f"发起权重查询请求 | 原始域名：{domain} | 纯域名：{pure_domain} | API URL：{api_url}")
        
        response = session.get(
            api_url,
            headers=REQUEST_HEADERS,
            timeout=REQUEST_TIMEOUT,
            verify=False  # 忽略SSL校验（生产环境建议True）
        )

        # 4. 校验响应状态码（非200直接判定失败）
        response.raise_for_status()
        logger.info(f"请求成功 | 状态码：{response.status_code}")

        # 5. 处理编码，避免JSON解析乱码
        response.encoding = response.apparent_encoding or "utf-8"
        raw_text = response.text
        res_json = json.loads(raw_text)
        result["raw_data"] = res_json  # 保存原始数据，便于调试

        # 6. 容错提取权重字段（逐层判断，避免KeyError）
        # 提取success列表
        success_list = res_json.get("data", {}).get("success", [])
        if not success_list:
            result["message"] = f"API返回无有效数据 | 纯域名：{pure_domain} | 原始响应：{raw_text[:100]}..."
            logger.warning(result["message"])
            return result

        # 提取第一个数据项的权重字段（无则返回"未知"）
        weight_data = success_list[0]
        pc_br = weight_data.get("pc_br", "未知")
        m_br = weight_data.get("m_br", "未知")
        ip = weight_data.get("ip", "未知")

        # 7. 格式化结果
        result["success"] = True
        result["result"] = f"PC权重({pc_br})，移动权重({m_br})，预计来路({ip})  --数据来源于aizhan.com"
        result["message"] = f"域名 {pure_domain} 权重查询成功"
        logger.info(result["message"])

    # 8. 细化异常处理（精准定位问题）
    except requests.exceptions.ConnectTimeout:
        result["message"] = f"连接API超时（{REQUEST_TIMEOUT}秒）| 纯域名：{pure_domain}"
        logger.error(result["message"])
    except requests.exceptions.ReadTimeout:
        result["message"] = f"读取API响应超时（{REQUEST_TIMEOUT}秒）| 纯域名：{pure_domain}"
        logger.error(result["message"])
    except requests.exceptions.HTTPError as e:
        error_msg = f"请求失败 | 状态码：{e.response.status_code} | 纯域名：{pure_domain} | 响应内容：{raw_text[:100]}..."
        result["message"] = error_msg
        logger.error(error_msg)
        # 特殊处理：403通常是API密钥失效
        if e.response.status_code == 403:
            result["message"] += "（可能是API密钥失效）"
    except json.JSONDecodeError:
        result["message"] = f"JSON解析失败 | 纯域名：{pure_domain} | 响应内容：{raw_text[:100]}..."
        logger.error(result["message"])
    except requests.exceptions.RequestException as e:
        result["message"] = f"请求异常 | 纯域名：{pure_domain} | 原因：{str(e)[:50]}"
        logger.error(result["message"])
    except Exception as e:
        result["message"] = f"未知异常 | 纯域名：{pure_domain} | 原因：{str(e)[:50]}"
        logger.error(result["message"])
    finally:
        # 关闭Session，释放连接资源
        session.close()

    return result

# ======================== 兼容原代码的返回格式（可选） ========================
def get_web_weight_compat(domain: str) -> str:
    """
    兼容原代码的返回格式（仅返回字符串）
    :param domain: 原始域名/URL
    :return: 格式化结果字符串 / 失败提示
    """
    result = get_web_weight(domain)
    return result["result"]

# ======================== 测试入口 ========================
if __name__ == '__main__':
    # 测试1：使用优化后的标准化返回
    test_domain1 = "https://jwt1399.top/"
    result1 = get_web_weight(test_domain1)
    print(f"测试域名 {test_domain1} 结果（标准化）：\n{json.dumps(result1, ensure_ascii=False, indent=2)}")

    # 测试2：使用兼容原代码的返回格式
    test_domain2 = "https://jwt1399.top/"
    result2 = get_web_weight_compat(test_domain2)
    print(f"\n测试域名 {test_domain2} 结果（兼容原格式）：{result2}")

    # 测试3：非法域名
    test_domain3 = "invalid_domain"
    result3 = get_web_weight_compat(test_domain3)
    print(f"\n测试域名 {test_domain3} 结果（兼容原格式）：{result3}")