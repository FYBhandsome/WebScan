#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import os
import re
import json
import logging
from typing import Dict, List, Set, Optional, Union
import requests
import chardet
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ======================== 配置项集中管理 ========================
# 规则文件路径（兼容跨平台）
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_DIR = os.path.normpath(os.path.join(BASE_DIR, '../../database'))
APPS_JSON_PATH = os.path.join(DATABASE_DIR, 'apps.json')
APPS_TXT_PATH = os.path.join(DATABASE_DIR, 'apps.txt')

# 请求配置
REQUEST_TIMEOUT = 4  # 超时时间（秒）
RETRY_TIMES = 2      # 重试次数
REQUEST_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'zh-CN,zh;q=0.9'
}

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),  # 控制台输出
        logging.FileHandler(os.path.join(BASE_DIR, 'whatcms.log'), encoding='utf-8')  # 文件输出
    ]
)
logger = logging.getLogger("WhatCMSDetector")

# ======================== 模拟randheader.get_ua（适配原代码依赖） ========================
def get_ua() -> Dict[str, str]:
    """生成随机请求头（兼容原代码）"""
    return REQUEST_HEADERS

# ======================== 单例Wappalyzer（避免重复读取文件） ========================
class SingletonWappalyzer:
    """单例模式的Wappalyzer，仅初始化一次"""
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            # 初始化Wappalyzer核心数据
            cls._instance._init_wappalyzer()
        return cls._instance

    def _init_wappalyzer(self):
        """初始化Wappalyzer规则（读取apps.json并预处理）"""
        try:
            # 检查文件是否存在
            if not os.path.exists(APPS_JSON_PATH):
                raise FileNotFoundError(f"apps.json文件不存在：{APPS_JSON_PATH}")
            
            with open(APPS_JSON_PATH, 'rb') as fd:
                obj = json.load(fd)
            
            self.categories = obj.get('categories', {})
            self.apps = obj.get('apps', {})

            # 预处理所有应用规则
            for name, app in self.apps.items():
                self._prepare_app(app)
            
            logger.info(f"成功加载Wappalyzer规则，共{len(self.apps)}个应用")

        except FileNotFoundError as e:
            logger.error(f"加载apps.json失败：{e}")
            self.apps = {}
            self.categories = {}
        except json.JSONDecodeError as e:
            logger.error(f"apps.json格式错误：{e}")
            self.apps = {}
            self.categories = {}
        except Exception as e:
            logger.error(f"初始化Wappalyzer失败：{str(e)[:100]}")
            self.apps = {}
            self.categories = {}

    def _prepare_app(self, app: Dict):
        """标准化应用规则，预处理正则"""
        # 确保核心字段为列表
        for key in ['url', 'html', 'script', 'implies']:
            value = app.get(key)
            if value is None:
                app[key] = []
            elif not isinstance(value, list):
                app[key] = [value]

        # 确保headers/meta字段存在且为字典
        for key in ['headers', 'meta']:
            app[key] = app.get(key, {})
            if not isinstance(app[key], dict):
                app[key] = {'generator': app[key]}

        # 字段名转小写
        for key in ['headers', 'meta']:
            app[key] = {k.lower(): v for k, v in app[key].items()}

        # 预编译正则（忽略大小写）
        for key in ['url', 'html', 'script']:
            app[key] = [self._compile_regex(pattern) for pattern in app[key]]
        
        for key in ['headers', 'meta']:
            for name, pattern in app[key].items():
                app[key][name] = self._compile_regex(pattern)

    def _compile_regex(self, pattern: str) -> re.Pattern:
        """编译正则表达式，失败则返回永不匹配的正则"""
        if not pattern:
            return re.compile(r'(?!x)x')
        try:
            regex, _, _ = pattern.partition('\\;')
            return re.compile(regex, re.I)
        except re.error as e:
            logger.warning(f"正则编译失败：{pattern} | 原因：{e}")
            return re.compile(r'(?!x)x')

    def _has_app(self, app: Dict, webpage: 'WebPage') -> bool:
        """检测单个应用是否匹配网页特征"""
        # URL匹配
        for regex in app['url']:
            if regex.search(webpage.url):
                return True

        # 响应头匹配
        for name, regex in app['headers'].items():
            if name in webpage.headers:
                if regex.search(str(webpage.headers[name])):
                    return True

        # 脚本URL匹配
        for regex in app['script']:
            for script in webpage.scripts:
                if regex.search(script):
                    return True

        # Meta标签匹配
        for name, regex in app['meta'].items():
            if name in webpage.meta:
                if regex.search(str(webpage.meta[name])):
                    return True

        # HTML内容匹配
        for regex in app['html']:
            if regex.search(webpage.html):
                return True

        return False

    def _get_implied_apps(self, detected_apps: Set[str]) -> Set[str]:
        """递归获取隐含的应用"""
        def __get_implied(apps: Set[str]) -> Set[str]:
            implied = set()
            try:
                for app in apps:
                    implied.update(self.apps.get(app, {}).get('implies', []))
                return implied
            except Exception as e:
                logger.warning(f"获取隐含应用失败：{e}")
                return set()

        all_implied = set()
        implied = __get_implied(detected_apps)
        while not all_implied.issuperset(implied):
            all_implied.update(implied)
            implied = __get_implied(all_implied)
        return all_implied

    def analyze(self, webpage: 'WebPage') -> Set[str]:
        """识别网页应用栈"""
        if not self.apps:
            return set()

        detected = set()
        # 匹配核心规则
        for app_name, app in self.apps.items():
            if self._has_app(app, webpage):
                detected.add(app_name)

        # 补充隐含应用
        detected.update(self._get_implied_apps(detected))
        return detected

# ======================== WebPage核心类 ========================
class WebPage:
    """网页数据封装与分析类"""
    def __init__(self, url: str, html: str, headers: Dict[str, str]):
        self.url = url
        self.html = html
        self.headers = {k.lower(): v for k, v in headers.items()}  # 响应头转小写，避免大小写问题

        # 解析HTML
        self.parsed_html = BeautifulSoup(html, "html.parser")
        self.scripts = self._extract_scripts()
        self.meta = self._extract_meta()
        self.title = self._extract_title()

        # 识别应用（复用单例Wappalyzer）
        self.wappalyzer = SingletonWappalyzer()
        self.apps = self.wappalyzer.analyze(self)
        self.result = ';'.join(self.apps)

    def _extract_scripts(self) -> List[str]:
        """提取所有script标签的src属性（容错处理）"""
        scripts = []
        try:
            for script in self.parsed_html.find_all('script', src=True):
                src = script.get('src', '').strip()
                if src:
                    scripts.append(src)
        except Exception as e:
            logger.warning(f"提取脚本URL失败：{e}")
        return scripts

    def _extract_meta(self) -> Dict[str, str]:
        """提取meta标签（name-content键值对，转小写）"""
        meta = {}
        try:
            for tag in self.parsed_html.find_all('meta', attrs={'name': True, 'content': True}):
                name = tag.get('name', '').lower().strip()
                content = tag.get('content', '').strip()
                if name and content:
                    meta[name] = content
        except Exception as e:
            logger.warning(f"提取Meta标签失败：{e}")
        return meta

    def _extract_title(self) -> str:
        """提取网页标题（容错处理）"""
        try:
            title_tag = self.parsed_html.title
            return title_tag.string.strip() if title_tag and title_tag.string else 'None'
        except Exception as e:
            logger.warning(f"提取标题失败：{e}")
            return 'None'

    def check_custom_rules(self) -> List[str]:
        """加载自定义apps.txt规则并匹配"""
        out = []
        try:
            if not os.path.exists(APPS_TXT_PATH):
                logger.warning(f"自定义规则文件不存在：{APPS_TXT_PATH}")
                return out

            # 读取规则并去重
            with open(APPS_TXT_PATH, 'r', encoding='utf-8') as f:
                apps_rules = [line.strip() for line in f.readlines() if line.strip()]

            # 解析并匹配每条规则
            for rule in apps_rules:
                try:
                    # 拆分规则：name|method|position|regex
                    name, method, position, regex = rule.split("|", 3)
                    position = position.lower()  # 统一转小写

                    if method == 'headers':
                        header_value = self.headers.get(position, '')
                        if re.search(regex, str(header_value), re.I):
                            out.append(name)
                    elif method == 'html':
                        if re.search(regex, self.html, re.I):
                            out.append(name)
                except ValueError:
                    logger.warning(f"规则格式错误（需4部分）：{rule}")
                except re.error:
                    logger.warning(f"规则正则错误：{rule}")
                except Exception as e:
                    logger.warning(f"匹配规则失败：{rule} | 原因：{e}")

        except Exception as e:
            logger.error(f"加载自定义规则失败：{e}")

        return list(set(out))  # 去重

    def info(self) -> Dict[str, Union[List[str], str]]:
        """整合所有识别结果"""
        # 合并Wappalyzer和自定义规则结果（去重）
        apps_wappalyzer = self.result.split(';') if self.result else []
        apps_custom = self.check_custom_rules()
        all_apps = list(set(apps_wappalyzer + apps_custom))

        # 提取服务器信息（容错）
        server = self.headers.get('server', 'None')

        # 提取安全响应头
        security_headers = []
        security_keys = [
            'content-security-policy',
            'x-webkit-csp',
            'x-xss-protection',
            'strict-transport-security'
        ]
        for key in security_keys:
            if key in self.headers:
                security_headers.append(key.replace('-', ' ').title())  # 格式化显示

        return {
            "apps": all_apps,
            "title": self.title,
            "server": server,
            "security": security_headers,
            "url": self.url
        }

# ======================== 核心识别函数 ========================
def getwhatcms(url: str = '') -> Dict[str, Union[bool, str, List[str], Dict]]:
    """
    获取CMS及Web技术栈信息（优化版）
    :param url: 目标URL
    :return: 标准化结果字典
    """
    # 初始化返回结果
    result = {
        "success": False,
        "message": "未能识别，请联系管理员",
        "data": {
            "apps": [],
            "title": "None",
            "server": "None",
            "security": [],
            "url": url
        }
    }

    # 1. 校验URL格式
    if not isinstance(url, str) or not url.strip():
        result["message"] = "URL为空"
        logger.error(result["message"])
        return result

    url = url.strip()
    if not (url.startswith('https://') or url.startswith('http://')):
        result["message"] = f"URL格式非法（需以http/https开头）：{url}"
        logger.error(result["message"])
        return result

    # 2. 创建Session并配置重试
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
        # 3. 发起请求
        logger.info(f"开始识别CMS | URL：{url}")
        response = session.get(
            url=url,
            headers=get_ua(),
            timeout=REQUEST_TIMEOUT,
            verify=False,  # 生产环境建议改为True
            allow_redirects=True  # 跟随重定向，获取最终页面
        )
        response.raise_for_status()  # 非200状态码触发异常

        # 4. 处理编码（解决chardet返回None的问题）
        raw_content = response.content
        codetype = chardet.detect(raw_content).get('encoding') or 'utf-8'
        # 兼容GB2312→GBK
        if codetype == 'GB2312':
            codetype = 'GBK'
        response.encoding = codetype
        html_text = response.text

        # 5. 分析网页数据
        webpage = WebPage(response.url, html_text, dict(response.headers))
        webinfo = webpage.info()

        # 6. 组装结果
        result["success"] = True
        result["data"] = webinfo
        if webinfo["apps"]:
            result["message"] = f"识别成功：{','.join(webinfo['apps'])}，Server【{webinfo['server']}】"
        else:
            result["message"] = "未识别到任何应用栈信息"

        logger.info(f"识别完成 | URL：{url} | 结果：{result['message']}")

    except requests.exceptions.ConnectTimeout:
        result["message"] = f"连接超时（{REQUEST_TIMEOUT}秒）：{url}"
        logger.error(result["message"])
    except requests.exceptions.ReadTimeout:
        result["message"] = f"读取响应超时（{REQUEST_TIMEOUT}秒）：{url}"
        logger.error(result["message"])
    except requests.exceptions.HTTPError as e:
        result["message"] = f"请求失败 | 状态码：{e.response.status_code} | URL：{url}"
        logger.error(result["message"])
    except requests.exceptions.RequestException as e:
        result["message"] = f"请求异常：{str(e)[:50]} | URL：{url}"
        logger.error(result["message"])
    except Exception as e:
        result["message"] = f"识别未知异常：{str(e)[:50]} | URL：{url}"
        logger.error(result["message"])
    finally:
        session.close()

    return result

# ======================== 兼容原代码的返回格式 ========================
def getwhatcms_compat(url: str = '') -> str:
    """兼容原代码的返回格式（仅返回字符串）"""
    result = getwhatcms(url)
    if result["success"] and result["data"]["apps"]:
        return f"{','.join(result['data']['apps'])}，Server【{result['data']['server']}】"
    return result["message"]

# ======================== 测试入口 ========================
if __name__ == '__main__':
    # 测试1：标准化返回格式
    test_url = "https://jwt1399.top/"
    result = getwhatcms(test_url)
    print(f"标准化结果：\n{json.dumps(result, ensure_ascii=False, indent=2)}")

    # 测试2：兼容原代码格式
    compat_result = getwhatcms_compat(test_url)
    print(f"\n兼容原格式结果：{compat_result}")