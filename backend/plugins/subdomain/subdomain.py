# -*- coding:utf-8 -*-
import logging
import re
from typing import List, Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ======================== 配置项（集中管理，便于修改） ========================
# 请求头配置
REQUEST_HEADERS = {
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.62 Safari/537.36',
    'Referer': 'http://www.baidu.com/',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'zh-CN,zh;q=0.9'
}
# ip138子域名查询接口
IP138_SUBDOMAIN_URL = 'http://site.ip138.com/{domain}/domain.htm'
# 请求超时时间（秒）
REQUEST_TIMEOUT = 10
# 重试配置
RETRY_CONFIG = Retry(
    total=5,  # 总重试次数
    backoff_factor=0.5,  # 重试间隔（0.5s, 1s, 2s...）
    status_forcelist=[429, 500, 502, 503, 504],  # 触发重试的状态码
    allowed_methods=["GET"]  # 仅GET请求重试
)
# 子域名匹配正则（更健壮，兼容空格/换行）
SUBDOMAIN_PATTERN = re.compile(r'target="_blank">\s*(.*?)\s*</a>\s*</p>', re.S)

# ======================== 日志配置 ========================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("SubdomainScanner")

def is_valid_domain(domain: str) -> bool:
    """
    校验域名格式是否合法（简单校验，满足基础需求）
    :param domain: 待校验域名
    :return: True（合法）/False（非法）
    """
    if not isinstance(domain, str) or not domain.strip():
        return False
    # 基础域名正则（匹配 xxx.xxx 格式）
    domain_pattern = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$')
    return bool(domain_pattern.match(domain.strip()))

def get_subdomain(domain: str) -> List[str]:
    """
    获取域名的子域名（健壮版）
    :param domain: 主域名（如 baidu.com）
    :return: 去重后的子域名列表，异常时返回空列表
    """
    # 1. 输入校验
    domain = domain.strip() if isinstance(domain, str) else ""
    if not is_valid_domain(domain):
        logger.error(f"输入域名 {domain} 格式非法")
        return []

    # 2. 创建Session并配置重试
    session = requests.Session()
    session.mount("http://", HTTPAdapter(max_retries=RETRY_CONFIG))
    session.mount("https://", HTTPAdapter(max_retries=RETRY_CONFIG))
    session.keep_alive = False  # 关闭多余连接

    try:
        # 3. 拼接URL并发起请求
        url = IP138_SUBDOMAIN_URL.format(domain=domain)
        logger.info(f"发起请求：{url}")
        response = session.get(
            url,
            headers=REQUEST_HEADERS,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,  # 关闭重定向，避免跳转到其他页面
            verify=False  # 忽略SSL校验（ip138为http，实际无影响）
        )
        # 4. 校验响应状态码
        response.raise_for_status()  # 非200状态码抛出异常

        # 5. 处理编码，避免乱码
        response.encoding = response.apparent_encoding or 'utf-8'

        # 6. 正则匹配子域名
        subdomains = SUBDOMAIN_PATTERN.findall(response.text)
        # 7. 去重、过滤空值
        subdomains = list({sub for sub in subdomains if sub.strip()})
        logger.info(f"提取到 {len(subdomains)} 个唯一子域名：{subdomains}")

        if not subdomains:
            logger.warning(f"未提取到 {domain} 的子域名，ip138接口可能异常或无数据")

        return subdomains

    # 8. 细化异常处理
    except requests.exceptions.ConnectTimeout:
        logger.error(f"连接 ip138 接口超时（{REQUEST_TIMEOUT}秒）")
    except requests.exceptions.ReadTimeout:
        logger.error(f"读取 ip138 接口响应超时（{REQUEST_TIMEOUT}秒）")
    except requests.exceptions.HTTPError as e:
        logger.error(f"请求失败，状态码：{e.response.status_code} | 原因：{e}")
    except requests.exceptions.RequestException as e:
        logger.error(f"请求 ip138 接口异常：{str(e)[:50]}")
    except Exception as e:
        logger.error(f"提取子域名未知异常：{str(e)[:50]}")
    finally:
        # 9. 关闭Session，释放连接
        session.close()

    return []

if __name__ == '__main__':
    # 测试用例1：合法域名
    logger.info("=== 测试1：查询baidu.com子域名 ===")
    baidu_subs = get_subdomain('baidu.com')
    print("最终结果：", baidu_subs)

    # 测试用例2：非法域名
    logger.info("\n=== 测试2：查询非法域名（baidu）===")
    invalid_subs = get_subdomain('baidu')
    print("最终结果：", invalid_subs)