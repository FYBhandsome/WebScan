# -*- coding:utf-8 -*-

"""
WAF(Web应用防火墙)检测模块
功能:
1. 检测目标网站是否部署WAF
2. 支持多种WAF类型识别(360、CloudFlare、F5、Baidu等)
3. 通过HTTP响应头和内容特征进行识别
4. 支持URL/域名/IP作为输入

特性:
- 内置多种WAF识别规则
- 支持自定义检测规则
- 返回WAF名称和匹配特征

依赖:
- requests: 用于HTTP请求
- chardet: 用于编码检测

使用示例:
    >>> from backend.plugins.waf.waf import get_waf
    >>> result = get_waf('https://www.www.baidu.com/')
    >>> print(result)
    {
        "status": "success",
        "has_waf": "yes",
        "waf_name": "CloudFlare",
        "message": "检测到CloudFlare CDN/WAF"
    }
""" 


import re
import logging
from typing import Dict, Tuple, List, Optional
import requests
import chardet
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urljoin
from TOSKill.utils.target import normalize_scan_target

# === 配置项(集中管理,便于修改) ===
# WAF检测规则(格式:WAF名|匹配对象|匹配属性|正则规则)
WAF_RULES = (
    r'WAF|headers|Server|WAF',
    r'360|headers|X-Powered-By-360wzb|wangzhan\.360\.cn',
    r'360|headers|X-Powered-By|360',
    r'360wzws|headers|Server|360wzws',
    r'Anquanbao|headers|X-Powered-By-Anquanbao|MISS',
    r'Armor|headers|Server|armor',
    r'BaiduYunjiasu|headers|Server|yunjiasu-nginx',
    r'BinarySEC|headers|x-binarysec-cache|miss',
    r'BinarySEC|headers|x-binarysec-via|binarysec\.com',
    r'BinarySEC|headers|Server|BinarySec',
    r'BlockDoS|headers|Server|BlockDos\.net',
    r'CloudFlare CDN|headers|Server|cloudflare-nginx',
    r'CloudFlare CDN|headers|Server|cloudflare',
    r'cloudflare CDN|headers|CF-RAY|.+',
    r'Cloudfront CDN|headers|Server|cloudfront',
    r'Cloudfront CDN|headers|X-Cache|cloudfront',
    r'Cloudfront CDN|headers|X-Cache|Error\sfrom\scloudfront',
    r'mod_security|headers|Server|mod_security',
    r'Barracuda NG|headers|Server|Barracuda',
    r'mod_security|headers|Server|Mod_Security',
    r'F5 BIG-IP APM|headers|Server|BigIP',
    r'F5 BIG-IP APM|headers|Server|BIG-IP',
    r'F5 BIG-IP ASM|headers|X-WA-Info|.+',
    r'F5 BIG-IP ASM|headers|X-Cnection|close',
    r'F5-TrafficShield|headers|Server|F5-TrafficShield',
    r'GoDaddy|headers|X-Powered-By|GoDaddy',
    r'Bluedon IST|headers|Server|BDWAF',
    r'Comodo|headers|Server|Protected by COMODO',
    r'Airee CDN|headers|Server|Airee',
    r'Beluga CDN|headers|Server|Beluga',
    r'Fastly CDN|headers|X-Fastly-Request-ID|\w+',
    r'limelight CDN|headers|Set-Cookie|limelight',
    r'CacheFly CDN|headers|BestCDN|CacheFly',
    r'maxcdn CDN|headers|X-CDN|maxcdn',
    r'DenyAll|headers|Set-Cookie|\Asessioncookie=',
    r'AdNovum|headers|Set-Cookie|^Navajo.*?$',
    r'dotDefender|headers|X-dotDefender-denied|1',
    r'Incapsula CDN|headers|X-CDN|Incapsula',
    r'Jiasule|headers|Set-Cookie|jsluid=',
    r'KONA|headers|Server|AkamaiGHost',
    r'ModSecurity|headers|Server|NYOB',
    r'ModSecurity|headers|Server|NOYB',
    r'ModSecurity|headers|Server|.*mod_security',
    r'NetContinuum|headers|Cneonction|\Aclose',
    r'NetContinuum|headers|nnCoection|\Aclose',
    r'NetContinuum|headers|Set-Cookie|citrix_ns_id',
    r'Newdefend|headers|Server|newdefend',
    r'NSFOCUS|headers|Server|NSFocus',
    r'Safe3|headers|X-Powered-By|Safe3WAF',
    r'Safe3|headers|Server|Safe3 Web Firewall',
    r'Safedog|headers|X-Powered-By|WAF/2\.0',
    r'Safedog|headers|Server|Safedog',
    r'Safedog|headers|Set-Cookie|Safedog',
    r'SonicWALL|headers|Server|SonicWALL',
    r'ZenEdge Firewall|headers|Server|ZENEDGE',
    r'WatchGuard|headers|Server|WatchGuard',
    r'Stingray|headers|Set-Cookie|\AX-Mapping-',
    r'Art of Defence HyperGuard|headers|Set-Cookie|WODSESSION=',
    r'Sucuri|headers|Server|Sucuri/Cloudproxy',
    r'Usp-Sec|headers|Server|Secure Entry Server',
    r'Varnish|headers|X-Varnish|.+',
    r'Varnish|headers|Server|varnish',
    r'Wallarm|headers|Server|nginx-wallarm',
    r'WebKnight|headers|Server|WebKnight',
    r'Yundun|headers|Server|YUNDUN',
    r'Teros WAF|headers|Set-Cookie|st8id=',
    r'Imperva SecureSphere|headers|X-Iinfo|.+',
    r'NetContinuum WAF|headers|Set-Cookie|NCI__SessionId=',
    r'Yundun|headers|X-Cache|YUNDUN',
    r'Yunsuo|headers|Set-Cookie|yunsuo',
    r'Immunify360|headers|Server|imunify360',
    r'ISAServer|headers|Via|.+ISASERVER',
    r'Qiniu CDN|headers|X-Qiniu-Zone|0',
    r'azion CDN|headers|Server|azion',
    r'HyperGuard Firewall|headers|Set-cookie|ODSESSION=',
    r'ArvanCloud|headers|Server|ArvanCloud',
    r'GreyWizard Firewall|headers|Server|greywizard.*',
    r'FortiWeb Firewall|headers|Set-Cookie|cookiesession1',
    r'Beluga CDN|headers|Server|Beluga',
    r'DoSArrest Internet Security|headers|X-DIS-Request-ID|.+',
    r'ChinaCache CDN|headers|Powered-By-ChinaCache|\w+',
    r'ChinaCache CDN|headers|Server|ChinaCache',
    r'HuaweiCloudWAF|headers|Server|HuaweiCloudWAF',
    r'HuaweiCloudWAF|headers|Set-Cookie|HWWAFSESID',
    r'KeyCDN|headers|Server|KeyCDN',
    r'Reblaze Firewall|headers|Set-cookie|rbzid=\w+',
    r'Distil Firewall|headers|X-Distil-CS|.+',
    r'ZSWS|headers|Server|ZSWS',
    r'KnownSec|headers|Server|KS-WAF',
    r'KnownSec|headers|Server|KnownSec-WAF',
)


def getwaf(url: str, headers: Dict[str, str] = None, content: str = None) -> Optional[str]:
    """
    检测 WAF
    :param url: 目标 URL
    :param headers: 响应头 (字典)
    :param content: 响应内容 (字符串)
    :return: WAF 名称或 None
    """
    try:
        # 如果没有提供 headers 和 content,则主动发起请求
        if headers is None and content is None:
            try:
                resp = requests.get(url, timeout=10, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
                headers = resp.headers
                content = resp.text
            except Exception as e:
                logging.debug(f"WAF detect request failed: {e}")
                return None

        # 确保 headers 是字典
        if not isinstance(headers, dict) and hasattr(headers, 'items'):
             headers = dict(headers)
        
        # 遍历规则进行匹配
        for rule in WAF_RULES:
            try:
                # rule format: name|match_location|key|regex
                parts = rule.split('|')
                if len(parts) != 4:
                    continue
                
                waf_name, match_location, key, regex = parts
                
                if match_location == 'headers':
                    # 检查 headers
                    if headers and key in headers:
                        if re.search(regex, str(headers[key]), re.I):
                            return waf_name
                    # 有些 header key 可能是大小写敏感的,或者 requests headers 是不敏感的
                    # requests headers 是 CaseInsensitiveDict,所以直接 key in headers 应该可以
                    # 但为了保险,可以遍历 headers
                    
                elif match_location == 'content':
                    # 检查 content
                    if content and re.search(regex, content, re.I):
                        return waf_name
            except Exception:
                continue
                
        return None
    except Exception as e:
        logging.error(f"WAF detection error: {e}")
        return None

# 恶意Payload(触发WAF的试探参数)
DETECT_PAYLOAD = r'/?id=1%27&d=2"&y=3%27or%27select%20*%20from%20users%20limit%200,1&b=<script>alert(1)</script>&o=eval&yy=%0a%0d'
# 请求配置
REQUEST_TIMEOUT = 15  # 超时时间(秒)
RETRY_TIMES = 3      # 重试次数
VERIFY_SSL = False   # 是否验证SSL证书(生产环境建议True)
# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("WAFDetector")

# === 预编译WAF规则(提升匹配效率) ===
def compile_waf_rules() -> List[Tuple[str, str, str, re.Pattern]]:
    """
    预编译WAF规则,校验规则格式并返回编译后的规则列表
    :return: [(WAF名, 匹配对象, 匹配属性, 预编译正则), ...]
    """
    compiled_rules = []
    for idx, rule in enumerate(WAF_RULES):
        try:
            # 拆分规则并校验格式
            parts = rule.split('|')
            if len(parts) != 4:
                logger.warning(f"第{idx+1}条规则格式错误(需4部分):{rule}")
                continue
            name, method, position, regex_str = parts
            # 预编译正则(忽略大小写、多行匹配)
            regex = re.compile(regex_str, re.I | re.M)
            compiled_rules.append((name, method, position, regex))
        except re.error as e:
            logger.error(f"第{idx+1}条规则正则编译失败:{rule} | 原因:{e}")
        except Exception as e:
            logger.error(f"第{idx+1}条规则解析失败:{rule} | 原因:{e}")
    logger.info(f"成功编译 {len(compiled_rules)} 条WAF检测规则")
    return compiled_rules

# 预编译规则(程序启动时执行一次)
COMPILED_WAF_RULES = compile_waf_rules()

# === 模拟get_ua(适配原代码依赖,实际使用时替换为真实导入) ===
def get_ua() -> Dict[str, str]:
    """生成随机请求头(模拟原代码的randheader.get_ua)"""
    try:
        from fake_useragent import UserAgent
        return {"User-Agent": UserAgent().random}
    except Exception:
        return {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"
        }

# === 核心检测函数 ===
def check_waf(headers: Dict[str, str], content: str) -> Tuple[bool, str]:
    """
    检测是否存在WAF(优化版)
    :param headers: 响应头字典
    :param content: 响应内容字符串
    :return: (是否存在WAF, WAF名称/原因)
    """
    if not COMPILED_WAF_RULES:
        return False, "无可用WAF检测规则"
    
    for name, method, position, regex in COMPILED_WAF_RULES:
        try:
            if method == 'headers':
                # 匹配响应头
                header_value = headers.get(position, '')
                if regex.search(str(header_value)):
                    logger.info(f"匹配到WAF特征 | WAF名:{name} | 匹配方式:headers[{position}] | 匹配值:{header_value}")
                    return True, name
            elif method == 'content':
                # 匹配响应内容(仅取前10000字符,避免内容过大)
                content_slice = content[:10000]
                if regex.search(content_slice):
                    logger.info(f"匹配到WAF特征 | WAF名:{name} | 匹配方式:content | 匹配内容片段:{content_slice[:50]}...")
                    return True, name
        except Exception as e:
            logger.warning(f"匹配WAF规则失败 | WAF名:{name} | 原因:{e}")
    return False, "未匹配到已知WAF特征"

def is_valid_url(url: str) -> bool:
    """
    校验URL格式是否合法
    :param url: 待校验URL
    :return: True(合法)/False(非法)
    """
    if not isinstance(url, str) or not re.match(r"^https?://", url.strip(), re.IGNORECASE):
        return False
    try:
        normalize_scan_target(url)
    except (TypeError, ValueError):
        return False
    return True

def get_waf(url: str) -> Dict[str, str]:
    """
    检测目标URL是否部署WAF(主函数,优化版)
    :param url: 目标URL
    :return: 标准化结果字典 {
        "status": "success/fail",  # 检测状态
        "has_waf": "yes/no/unknown",  # 是否存在WAF
        "waf_name": "360/CloudFlare/未知/无",  # WAF名称
        "message": "详细说明"  # 详细信息
    }
    """
    # 初始化结果
    result = {
        "status": "fail",
        "has_waf": "unknown",
        "waf_name": "未知",
        "message": ""
    }

    # 1. 输入URL校验
    if not is_valid_url(url):
        result["message"] = f"URL格式非法:{url}(需以http/https开头且包含有效域名)"
        logger.error(result["message"])
        return result

    url = normalize_scan_target(url)
    # 2. 安全拼接Payload(避免//问题)
    full_url = urljoin(url, DETECT_PAYLOAD.lstrip('/'))
    logger.info(f"开始检测WAF | 目标URL:{url} | 拼接Payload后:{full_url}")

    # 3. 创建Session并配置重试
    session = requests.Session()
    retry_strategy = Retry(
        total=RETRY_TIMES,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"]
    )
    session.mount("http://", HTTPAdapter(max_retries=retry_strategy))
    session.mount("https://", HTTPAdapter(max_retries=retry_strategy))
    session.keep_alive = False

    try:
        # 4. 发起请求
        response = session.get(
            full_url,
            headers=get_ua(),
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,  # 关闭重定向,避免跳转到其他页面
            verify=VERIFY_SSL
        )
        logger.info(f"请求成功 | 状态码:{response.status_code}")

        # 5. 处理响应编码(解决chardet返回None的问题)
        raw_content = response.content
        charset = chardet.detect(raw_content).get('encoding') or 'utf-8'
        # 兼容常见编码错误(如GB2312→GBK)
        if charset == 'GB2312':
            charset = 'GBK'
        try:
            content = raw_content.decode(charset, errors='ignore')
        except Exception:
            content = raw_content.decode('utf-8', errors='ignore')
        response_headers = dict(response.headers)

        # 6. 检测WAF
        has_waf, waf_name = check_waf(response_headers, content)

        # 7. 优化403状态码判断(结合规则,避免误判)
        if response.status_code == 403:
            if has_waf:
                result["has_waf"] = "yes"
                result["waf_name"] = waf_name
                result["message"] = f"检测到WAF({waf_name}),响应状态码403"
            else:
                result["has_waf"] = "unknown"
                result["message"] = "响应状态码403,但未匹配到已知WAF特征(可能是服务器配置/未知WAF)"
        else:
            if has_waf:
                result["has_waf"] = "yes"
                result["waf_name"] = waf_name
                result["message"] = f"检测到WAF:{waf_name}"
            else:
                result["has_waf"] = "no"
                result["waf_name"] = "无"
                result["message"] = "未检测到已知WAF特征"
        
        result["status"] = "success"

    except requests.exceptions.ConnectTimeout:
        result["message"] = f"连接超时({REQUEST_TIMEOUT}秒)"
        logger.error(result["message"])
    except requests.exceptions.ReadTimeout:
        result["message"] = f"读取响应超时({REQUEST_TIMEOUT}秒)"
        logger.error(result["message"])
    except requests.exceptions.SSLError:
        result["message"] = "SSL证书验证失败"
        logger.error(result["message"])
    except requests.exceptions.RequestException as e:
        result["message"] = f"请求异常:{str(e)[:50]}"
        logger.error(result["message"])
    except Exception as e:
        result["message"] = f"检测未知异常:{str(e)[:50]}"
        logger.error(result["message"])
    finally:
        # 关闭Session,释放连接
        session.close()

    return result

# === 测试入口 ===
if __name__ == '__main__':
    # 测试用例1:合法URL
    logger.info("=== 测试1:检测https://jwt1399.top ===")
    result1 = get_waf('https://jwt1399.top')
    print("检测结果:", result1)

    # 测试用例2:非法URL
    logger.info("\n=== 测试2:检测非法URL(http://)===")
    result2 = get_waf('http://')
    print("检测结果:", result2)

    # 测试用例3:带/的URL
    logger.info("\n=== 测试3:检测带/的URL(https://jwt1399.top/)===")
    result3 = get_waf('https://jwt1399.top/')
    print("检测结果:", result3)
