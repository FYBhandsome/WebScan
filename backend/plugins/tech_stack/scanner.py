# -*- coding:utf-8 -*-

"""
技术栈识别模块
功能:
1. Web框架识别
2. JavaScript库检测
3. 服务器类型识别
4. CMS检测
5. 编程语言检测
6. 数据库类型推断
7. 中间件检测
8. 安全组件检测
"""

import logging
import re
from typing import Dict, Any, Optional, List, Set
from dataclasses import dataclass, field
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("TechStackDetector")

@dataclass
class Technology:
    name: str
    category: str
    version: str = ""
    confidence: int = 100
    source: str = ""

@dataclass
class TechStackResult:
    url: str = ""
    technologies: List[Technology] = field(default_factory=list)
    categories: Dict[str, List[str]] = field(default_factory=dict)
    server: str = ""
    programming_languages: List[str] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)
    cms: str = ""
    javascript_libs: List[str] = field(default_factory=list)
    has_result: bool = False
    raw_data: Dict[str, Any] = field(default_factory=dict)
    error: str = ""

class TechPatterns:
    FRAMEWORKS = {
        "React": [r"react\.js", r"react-dom", r"_reactRootContainer", r"data-reactroot", r"__REACT"],
        "Vue.js": [r"vue\.js", r"Vue\.", r"__VUE__", r"data-v-", r"vue-router"],
        "Angular": [r"angular\.js", r"ng-version", r"ng-app", r"angular\.module", r"ng-binding"],
        "jQuery": [r"jquery", r"\$\(document\)", r"jQuery\(", r"jquery-\d"],
        "Bootstrap": [r"bootstrap", r"btn-primary", r"container-fluid", r"bootstrap\.min"],
        "Laravel": [r"laravel", r"XSRF-TOKEN", r"laravel_session"],
        "Django": [r"csrfmiddlewaretoken", r"__admin_media_prefix__", r"django"],
        "Flask": [r"flask", r"Werkzeug"],
        "Express": [r"express", r"X-Powered-By.*Express"],
        "Next.js": [r"__NEXT_DATA__", r"_next/static", r"next/dist"],
        "Nuxt.js": [r"__NUXT__", r"_nuxt/"],
        "Spring": [r"spring", r"JSESSIONID", r"springframework"],
        "ASP.NET": [r"asp\.net", r"__VIEWSTATE", r"__EVENTVALIDATION", r"\.aspx", r"aspnet"],
        "Ruby on Rails": [r"ruby.*rails", r"csrf-token", r"_rails_session", r"rails"],
        "Phoenix": [r"phoenix", r"_csrf_token"],
        "FastAPI": [r"fastapi", r"uvicorn"],
        "Gin": [r"gin-gonic"],
        "Echo": [r"labstack/echo"],
        "Koa": [r"koa\.js", r"koa-router"],
        "Svelte": [r"svelte", r"__svelte"],
        "SolidJS": [r"solid-js", r"solid\.js"],
        "Qwik": [r"qwik", r"qwikloader"],
        "Remix": [r"remix", r"__remix"],
        "Astro": [r"astro", r"_astro"],
    }
    
    CMS = {
        "WordPress": [r"wp-content", r"wp-includes", r"wp-json", r"wordpress", r"wp-embed"],
        "Drupal": [r"drupal", r"Drupal\.settings", r"sites/default/files", r"drupal\.js"],
        "Joomla": [r"joomla", r"option=com_", r"/components/com_", r"joomla\.js"],
        "Magento": [r"magento", r"Mage\.", r"/skin/frontend/", r"Magento"],
        "Shopify": [r"shopify", r"Shopify\.theme", r"cdn\.shopify\.com", r"myshopify"],
        "Wix": [r"wix\.com", r"wix-code", r"_wix_browser_sess", r"wixstatic"],
        "Squarespace": [r"squarespace", r"sqs-block", r"static\.squarespace", r"sqs-block"],
        "Ghost": [r"ghost", r"ghost-url", r"/ghost/api/", r"ghost\.io"],
        "Hugo": [r"hugo", r"/hugo/"],
        "Hexo": [r"hexo", r"/hexo/"],
        "Jekyll": [r"jekyll", r"jekyll-seo-tag"],
        "Typecho": [r"typecho", r"typecho/"],
        "Discuz": [r"discuz", r"discuz_uid"],
        "DedeCMS": [r"dedecms", r"dedeajax"],
        "ThinkPHP": [r"thinkphp", r"think_template"],
    }
    
    SERVERS = {
        "Nginx": [r"nginx"],
        "Apache": [r"apache", r"httpd"],
        "IIS": [r"microsoft-iis", r"iis"],
        "Tomcat": [r"tomcat"],
        "Node.js": [r"node\.js", r"express"],
        "Gunicorn": [r"gunicorn"],
        "uWSGI": [r"uwsgi"],
        "Caddy": [r"caddy"],
        "OpenResty": [r"openresty"],
        "LiteSpeed": [r"litespeed"],
        "Jetty": [r"jetty"],
        "Undertow": [r"undertow"],
        "Tengine": [r"tengine"],
        "Lighttpd": [r"lighttpd"],
    }
    
    JAVASCRIPT_LIBS = {
        "jQuery": [r"jquery[-.]?(\d+\.\d+\.\d+)?", r"jQuery v(\d+\.\d+\.\d+)?"],
        "Lodash": [r"lodash", r"_\.VERSION"],
        "Underscore.js": [r"underscore", r"_\.VERSION"],
        "Axios": [r"axios"],
        "Moment.js": [r"moment\.js", r"moment\(\)"],
        "D3.js": [r"d3\.js", r"d3\.select"],
        "Chart.js": [r"chart\.js", r"Chart\("],
        "Three.js": [r"three\.js", r"THREE\."],
        "GSAP": [r"gsap", r"TweenMax", r"TweenLite"],
        "Swiper": [r"swiper", r"Swiper\("],
        "Socket.io": [r"socket\.io", r"socket\.io-client"],
        "Redux": [r"redux", r"createStore"],
        "MobX": [r"mobx", r"observable"],
        "Zustand": [r"zustand"],
        "Tailwind CSS": [r"tailwindcss", r"tailwind"],
    }
    
    PROGRAMMING_LANGUAGES = {
        "PHP": [r"\.php", r"PHPSESSID", r"X-Powered-By.*PHP"],
        "Python": [r"\.py", r"python", r"uwsgi", r"gunicorn", r"fastapi"],
        "Java": [r"\.jsp", r"JSESSIONID", r"java", r"tomcat", r"spring"],
        "Ruby": [r"\.rb", r"ruby", r"rails"],
        "Node.js": [r"node", r"express", r"\.js.*server"],
        "Go": [r"golang", r"go-http", r"gin-gonic"],
        "ASP.NET": [r"\.aspx?", r"\.ashx", r"asp\.net", r"\.asmx"],
        "Rust": [r"rust", r"actix", r"rocket"],
        "Elixir": [r"elixir", r"phoenix"],
    }
    
    ANALYTICS = {
        "Google Analytics": [r"google-analytics\.com", r"gtag\(", r"ga\(", r"UA-\d+"],
        "Google Tag Manager": [r"googletagmanager\.com", r"GTM-"],
        "Facebook Pixel": [r"connect\.facebook\.net.*fbevents", r"fbq\("],
        "Hotjar": [r"hotjar\.com", r"hj\("],
        "Mixpanel": [r"mixpanel\.com", r"mixpanel\."],
        "Segment": [r"segment\.com", r"analytics\.track"],
        "Amplitude": [r"amplitude\.com", r"amplitude"],
        "Heap": [r"heap\.io", r"heap\."],
        "Plausible": [r"plausible\.io", r"plausible"],
        "Matomo": [r"matomo", r"piwik"],
    }
    
    CDNS = {
        "Cloudflare": [r"cloudflare", r"cf-ray", r"__cfduid", r"cdnjs\.cloudflare"],
        "Akamai": [r"akamai", r"akamaihd\.net", r"edgesuite"],
        "AWS CloudFront": [r"cloudfront\.net", r"X-Amz-Cf-"],
        "Fastly": [r"fastly", r"X-Served-By"],
        "Azure CDN": [r"azureedge\.net", r"windows\.net"],
        "jsDelivr": [r"jsdelivr\.net"],
        "unpkg": [r"unpkg\.com"],
        "cdnjs": [r"cdnjs\.cloudflare\.com"],
        "CDNJS": [r"cdnjs"],
    }
    
    SECURITY = {
        "reCAPTCHA": [r"recaptcha", r"g-recaptcha"],
        "hCaptcha": [r"hcaptcha", r"h-captcha"],
        "Cloudflare Turnstile": [r"turnstile", r"cf-turnstile"],
        "Imperva": [r"imperva", r"incapsula"],
        "Akamai Bot Manager": [r"akamai.*bot", r"bot-manager"],
        "DataDome": [r"datadome", r"dd-"],
        "PerimeterX": [r"perimeterx", r"px-"],
        "WAF": [r"waf", r"web application firewall"],
    }
    
    DATABASE = {
        "MySQL": [r"mysql", r"mysqli"],
        "PostgreSQL": [r"postgresql", r"pgsql"],
        "MongoDB": [r"mongodb", r"mongo"],
        "Redis": [r"redis"],
        "SQLite": [r"sqlite"],
        "Oracle": [r"oracle", r"oci"],
        "SQL Server": [r"sqlserver", r"mssql"],
        "Elasticsearch": [r"elasticsearch", r"elastic"],
    }
    
    BUILD_TOOLS = {
        "Webpack": [r"webpack", r"webpackChunk"],
        "Vite": [r"vite", r"vite-plugin"],
        "Rollup": [r"rollup", r"rollup-plugin"],
        "Parcel": [r"parcel", r"parcel-bundler"],
        "esbuild": [r"esbuild"],
        "Babel": [r"babel", r"@babel"],
        "TypeScript": [r"typescript", r"\.ts[x]?\""],
    }

class TechStackDetector:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 15)
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"]
        )
        session.mount("http://", HTTPAdapter(max_retries=retry_strategy))
        session.mount("https://", HTTPAdapter(max_retries=retry_strategy))
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })
        return session
    
    def _normalize_url(self, url: str) -> str:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url
    
    def _detect_from_headers(self, headers: dict) -> List[Technology]:
        techs = []
        
        server = headers.get("Server", "")
        if server:
            for name, patterns in TechPatterns.SERVERS.items():
                for pattern in patterns:
                    if re.search(pattern, server, re.IGNORECASE):
                        techs.append(Technology(
                            name=name,
                            category="Web Server",
                            version="",
                            source="header"
                        ))
                        break
        
        x_powered_by = headers.get("X-Powered-By", "")
        if x_powered_by:
            if "php" in x_powered_by.lower():
                version_match = re.search(r"PHP/([\d.]+)", x_powered_by)
                techs.append(Technology(
                    name="PHP",
                    category="Programming Language",
                    version=version_match.group(1) if version_match else "",
                    source="header"
                ))
            elif "express" in x_powered_by.lower():
                techs.append(Technology(
                    name="Express",
                    category="Web Framework",
                    source="header"
                ))
            elif "asp" in x_powered_by.lower():
                techs.append(Technology(
                    name="ASP.NET",
                    category="Web Framework",
                    source="header"
                ))
        
        return techs
    
    def _detect_from_html(self, html: str) -> List[Technology]:
        techs = []
        html_lower = html.lower()
        
        for name, patterns in TechPatterns.FRAMEWORKS.items():
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    techs.append(Technology(
                        name=name,
                        category="Web Framework",
                        source="html"
                    ))
                    break
        
        for name, patterns in TechPatterns.CMS.items():
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    techs.append(Technology(
                        name=name,
                        category="CMS",
                        source="html"
                    ))
                    break
        
        for name, patterns in TechPatterns.JAVASCRIPT_LIBS.items():
            for pattern in patterns:
                match = re.search(pattern, html, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.lastindex else ""
                    techs.append(Technology(
                        name=name,
                        category="JavaScript Library",
                        version=version,
                        source="html"
                    ))
                    break
        
        for name, patterns in TechPatterns.ANALYTICS.items():
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    techs.append(Technology(
                        name=name,
                        category="Analytics",
                        source="html"
                    ))
                    break
        
        for name, patterns in TechPatterns.CDNS.items():
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    techs.append(Technology(
                        name=name,
                        category="CDN",
                        source="html"
                    ))
                    break
        
        for name, patterns in TechPatterns.SECURITY.items():
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    techs.append(Technology(
                        name=name,
                        category="Security",
                        source="html"
                    ))
                    break
        
        for name, patterns in TechPatterns.BUILD_TOOLS.items():
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    techs.append(Technology(
                        name=name,
                        category="Build Tool",
                        source="html"
                    ))
                    break
        
        return techs
    
    def _detect_from_cookies(self, cookies: dict) -> List[Technology]:
        techs = []
        cookie_names = [c.lower() for c in cookies.keys()]
        
        if "phpsessid" in cookie_names:
            techs.append(Technology(name="PHP", category="Programming Language", source="cookie"))
        if "jsessionid" in cookie_names:
            techs.append(Technology(name="Java", category="Programming Language", source="cookie"))
        if "laravel_session" in cookie_names:
            techs.append(Technology(name="Laravel", category="Web Framework", source="cookie"))
        if any("wordpress" in c for c in cookie_names):
            techs.append(Technology(name="WordPress", category="CMS", source="cookie"))
        if any("drupal" in c for c in cookie_names):
            techs.append(Technology(name="Drupal", category="CMS", source="cookie"))
        
        return techs
    
    def detect(self, url: str) -> TechStackResult:
        result = TechStackResult(url=self._normalize_url(url))
        
        try:
            response = self.session.get(
                result.url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            
            result.has_result = True
            result.raw_data = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
            }
            
            all_techs = []
            all_techs.extend(self._detect_from_headers(response.headers))
            all_techs.extend(self._detect_from_html(response.text))
            all_techs.extend(self._detect_from_cookies(response.cookies))
            
            seen = set()
            for tech in all_techs:
                key = f"{tech.category}:{tech.name}"
                if key not in seen:
                    seen.add(key)
                    result.technologies.append(tech)
            
            result.categories = {}
            for tech in result.technologies:
                if tech.category not in result.categories:
                    result.categories[tech.category] = []
                result.categories[tech.category].append(tech.name)
            
            result.server = result.categories.get("Web Server", ["未知"])[0]
            result.programming_languages = result.categories.get("Programming Language", [])
            result.frameworks = result.categories.get("Web Framework", [])
            result.javascript_libs = result.categories.get("JavaScript Library", [])
            
            cms_list = result.categories.get("CMS", [])
            result.cms = cms_list[0] if cms_list else ""
            
        except Exception as e:
            result.error = f"检测异常: {str(e)[:50]}"
        
        return result

def detect_tech_stack(url: str) -> Dict[str, Any]:
    detector = TechStackDetector()
    result = detector.detect(url)
    
    return {
        "success": result.has_result,
        "url": result.url,
        "server": result.server,
        "cms": result.cms,
        "programming_languages": result.programming_languages,
        "frameworks": result.frameworks,
        "javascript_libs": result.javascript_libs,
        "technologies": [
            {
                "name": t.name,
                "category": t.category,
                "version": t.version,
                "source": t.source
            }
            for t in result.technologies
        ],
        "categories": result.categories,
        "error": result.error
    }

if __name__ == '__main__':
    test_urls = ["https://github.com", "https://www.baidu.com", "https://wordpress.org"]
    for url in test_urls:
        print(f"\n{'='*60}")
        print(f"检测URL: {url}")
        result = detect_tech_stack(url)
        if result["success"]:
            print(f"服务器: {result['server']}")
            print(f"CMS: {result['cms'] or '未检测到'}")
            print(f"编程语言: {', '.join(result['programming_languages']) or '未检测到'}")
            print(f"Web框架: {', '.join(result['frameworks']) or '未检测到'}")
            print(f"JS库: {', '.join(result['javascript_libs'][:5]) or '未检测到'}")
            print(f"检测到的技术({len(result['technologies'])}个):")
            for tech in result['technologies'][:10]:
                print(f"  - {tech['category']}: {tech['name']}")
        else:
            print(f"错误: {result['error']}")
