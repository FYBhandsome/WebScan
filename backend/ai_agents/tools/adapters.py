"""
工具适配器模块

适配现有插件和POC，提供统一的调用接口。
所有适配器返回统一的 PluginResult 格式。

主要组件：
- BaseAdapter: 适配器基类，提供通用功能
- PluginAdapter: 插件适配器，适配扫描插件
- POCAdapter: POC适配器，适配漏洞验证脚本
- DependencyAdapter: 依赖安装适配器
"""
import asyncio
import logging
from typing import Any, Dict, List, Optional, Callable, TypeVar

from .result_types import PluginResult
from .wrappers import (
    with_timeout_and_error_handling,
    create_progress_reporter,
    ProgressReporter
)

logger = logging.getLogger(__name__)

T = TypeVar('T')


class BaseAdapter:
    """
    适配器基类
    
    提供通用的适配器功能，包括：
    - 进度报告
    - 延迟导入
    - 结果构建
    """
    
    @staticmethod
    def create_reporter(
        tool_name: str,
        target: str,
        callback: Optional[Callable] = None
    ) -> Optional[ProgressReporter]:
        """创建进度报告器"""
        return create_progress_reporter(tool_name, target, callback)
    
    @staticmethod
    def lazy_import(module_path: str):
        """
        延迟导入模块
        
        Args:
            module_path: 模块路径，如 'backend.plugins.baseinfo.baseinfo'
        
        Returns:
            导入的模块
        """
        parts = module_path.split('.')
        module = __import__(parts[0])
        for part in parts[1:]:
            module = getattr(module, part)
        return module


class PluginAdapter(BaseAdapter):
    """
    插件适配器
    
    适配现有的扫描插件，提供统一的调用接口。
    所有适配器支持超时控制、异常捕获和进度回调。
    """
    
    PLUGIN_CONFIGS = {
        "baseinfo": {
            "timeout": 60.0,
            "module": "backend.plugins.baseinfo.baseinfo",
            "func": "getbaseinfo",
            "description": "基础信息收集"
        },
        "portscan": {
            "timeout": 120.0,
            "module": "backend.plugins.portscan.portscan",
            "func": "ScanPort",
            "description": "端口扫描"
        },
        "waf_detect": {
            "timeout": 60.0,
            "module": "backend.plugins.waf.waf",
            "func": "get_waf",
            "description": "WAF检测"
        },
        "cdn_detect": {
            "timeout": 30.0,
            "module": "backend.plugins.cdnexist.cdnexist",
            "func": "iscdn",
            "description": "CDN检测"
        },
        "cms_identify": {
            "timeout": 60.0,
            "module": "backend.plugins.whatcms.whatcms",
            "func": "getwhatcms",
            "description": "CMS识别"
        },
        "infoleak_scan": {
            "timeout": 60.0,
            "module": "backend.plugins.infoleak.infoleak",
            "func": "get_infoleak",
            "description": "信息泄露扫描"
        },
        "subdomain_scan": {
            "timeout": 120.0,
            "module": "backend.plugins.subdomain.subdomain",
            "func": "get_subdomain",
            "description": "子域名扫描"
        },
        "webside_scan": {
            "timeout": 60.0,
            "module": "backend.plugins.webside.webside",
            "func": "get_side_info",
            "description": "站点信息扫描"
        },
        "webweight_scan": {
            "timeout": 30.0,
            "module": "backend.plugins.webweight.webweight",
            "func": "get_web_weight",
            "description": "网站权重查询"
        },
        "iplocating": {
            "timeout": 30.0,
            "module": "backend.plugins.iplocating.iplocating",
            "func": "get_locating",
            "description": "IP定位"
        },
        "loginfo": {
            "timeout": 30.0,
            "module": "backend.plugins.loginfo.loginfo",
            "func": "LogHandler",
            "description": "日志处理"
        },
        "randheader": {
            "timeout": 30.0,
            "module": "backend.plugins.randheader.randheader",
            "func": "get_random_headers",
            "description": "随机请求头生成"
        },
        "dirscan": {
            "timeout": 180.0,
            "module": "backend.plugins.dirscan.dirscan",
            "func": "get_dirscan",
            "description": "目录扫描"
        },
        "awvs": {
            "timeout": 300.0,
            "module": "backend.AVWS.API",
            "func": "awvs_scan",
            "description": "AWVS扫描"
        },
        "crawler": {
            "timeout": 300.0,
            "module": "backend.plugins.crawler.crawler",
            "func": "WebCrawler",
            "description": "Web爬虫"
        },
        "sqli_scan": {
            "timeout": 120.0,
            "module": "backend.vulnerability_scan_plugins.sqli.scanner",
            "func": "SQLiScanner",
            "description": "SQL注入扫描"
        },
        "xss_scan": {
            "timeout": 120.0,
            "module": "backend.vulnerability_scan_plugins.xss.scanner",
            "func": "XSSScanner",
            "description": "XSS扫描"
        },
        "csrf_scan": {
            "timeout": 60.0,
            "module": "backend.vulnerability_scan_plugins.csrf.scanner",
            "func": "CSRFScanner",
            "description": "CSRF扫描"
        },
        "vuln_infoleak_scan": {
            "timeout": 60.0,
            "module": "backend.vulnerability_scan_plugins.infoleak.scanner",
            "func": "InfoLeakScanner",
            "description": "敏感信息泄露扫描"
        },
        "fileupload_scan": {
            "timeout": 120.0,
            "module": "backend.vulnerability_scan_plugins.fileupload.scanner",
            "func": "FileUploadScanner",
            "description": "文件上传漏洞扫描"
        },
        "cmdi_scan": {
            "timeout": 180.0,
            "module": "backend.vulnerability_scan_plugins.cmdi.scanner",
            "func": "CmdiScanner",
            "description": "命令注入扫描"
        },
        "weakpass_scan": {
            "timeout": 300.0,
            "module": "backend.vulnerability_scan_plugins.weakpass.scanner",
            "func": "WeakPassScanner",
            "description": "弱口令扫描"
        },
        "lfi_scan": {
            "timeout": 180.0,
            "module": "backend.vulnerability_scan_plugins.lfi.scanner",
            "func": "LfiScanner",
            "description": "文件包含扫描"
        },
        "ssrf_scan": {
            "timeout": 180.0,
            "module": "backend.vulnerability_scan_plugins.ssrf.scanner",
            "func": "SsrfScanner",
            "description": "SSRF扫描"
        },
    }

    @staticmethod
    @with_timeout_and_error_handling(default_timeout=60.0, tool_name="baseinfo")
    async def adapt_baseinfo(
        target: str,
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable] = None
    ) -> PluginResult:
        """适配基础信息收集插件"""
        reporter = PluginAdapter.create_reporter("baseinfo", target, progress_callback)
        
        if reporter:
            reporter.report("初始化", 10, "开始基础信息收集")
        
        from backend.plugins.baseinfo.baseinfo import getbaseinfo
        
        if reporter:
            reporter.report("执行中", 50, "正在收集基础信息")
        
        result = await asyncio.to_thread(getbaseinfo, target)
        
        if reporter:
            reporter.report("完成", 100, "基础信息收集完成")
        
        return PluginResult.success(
            data={"base_info": result, "target": target},
            tool_name="baseinfo",
            target=target
        )
    
    @staticmethod
    @with_timeout_and_error_handling(default_timeout=120.0, tool_name="portscan")
    async def adapt_portscan(
        target: str,
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable] = None,
        ports: Optional[str] = None
    ) -> PluginResult:
        """适配端口扫描插件"""
        reporter = PluginAdapter.create_reporter("portscan", target, progress_callback)
        
        if reporter:
            reporter.report("初始化", 10, "初始化端口扫描器")
        
        from backend.plugins.portscan.portscan import ScanPort
        
        def run_scan():
            scanner = ScanPort(target)
            if ports:
                scanner.ports = ports
            success = scanner.run_scan()
            if success:
                return scanner.get_results()
            return []
        
        if reporter:
            reporter.report("扫描中", 30, "开始端口扫描")
        
        open_ports = await asyncio.to_thread(run_scan)
        
        if reporter:
            reporter.report("完成", 100, f"扫描完成，发现{len(open_ports)}个开放端口")
        
        return PluginResult.success(
            data={"open_ports": open_ports, "target": target},
            tool_name="portscan",
            target=target,
            open_port_count=len(open_ports)
        )
    
    @staticmethod
    @with_timeout_and_error_handling(default_timeout=60.0, tool_name="waf_detect")
    async def adapt_waf_detect(
        target: str,
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable] = None
    ) -> PluginResult:
        """适配WAF检测插件"""
        reporter = PluginAdapter.create_reporter("waf_detect", target, progress_callback)
        
        if reporter:
            reporter.report("初始化", 10, "开始WAF检测")
        
        from backend.plugins.waf.waf import get_waf
        
        if reporter:
            reporter.report("检测中", 50, "正在检测WAF")
        
        result = await asyncio.to_thread(get_waf, target)
        
        if reporter:
            reporter.report("完成", 100, "WAF检测完成")
        
        return PluginResult.success(
            data={"waf_info": result, "target": target},
            tool_name="waf_detect",
            target=target
        )
    
    @staticmethod
    @with_timeout_and_error_handling(default_timeout=30.0, tool_name="cdn_detect")
    async def adapt_cdn_detect(
        target: str,
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable] = None
    ) -> PluginResult:
        """适配CDN检测插件"""
        reporter = PluginAdapter.create_reporter("cdn_detect", target, progress_callback)
        
        if reporter:
            reporter.report("初始化", 10, "开始CDN检测")
        
        from backend.plugins.cdnexist.cdnexist import iscdn
        
        if reporter:
            reporter.report("检测中", 50, "正在检测CDN")
        
        result = await asyncio.to_thread(iscdn, target)
        
        if reporter:
            reporter.report("完成", 100, "CDN检测完成")
        
        return PluginResult.success(
            data={"has_cdn": bool(result), "cdn_info": str(result) if result else None, "target": target},
            tool_name="cdn_detect",
            target=target
        )
    
    @staticmethod
    @with_timeout_and_error_handling(default_timeout=60.0, tool_name="cms_identify")
    async def adapt_cms_identify(
        target: str,
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable] = None
    ) -> PluginResult:
        """适配CMS识别插件"""
        reporter = PluginAdapter.create_reporter("cms_identify", target, progress_callback)
        
        if reporter:
            reporter.report("初始化", 10, "开始CMS识别")
        
        from backend.plugins.whatcms.whatcms import getwhatcms
        
        if reporter:
            reporter.report("识别中", 50, "正在识别CMS类型")
        
        result = await asyncio.to_thread(getwhatcms, target)
        
        if reporter:
            reporter.report("完成", 100, "CMS识别完成")
        
        return PluginResult.success(
            data={"cms_info": result, "target": target},
            tool_name="cms_identify",
            target=target
        )
    
    @staticmethod
    @with_timeout_and_error_handling(default_timeout=60.0, tool_name="infoleak_scan")
    async def adapt_infoleak_scan(
        target: str,
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable] = None
    ) -> PluginResult:
        """适配信息泄露扫描插件"""
        reporter = PluginAdapter.create_reporter("infoleak_scan", target, progress_callback)
        
        if reporter:
            reporter.report("初始化", 10, "开始信息泄露扫描")
        
        from backend.plugins.infoleak.infoleak import get_infoleak
        
        if reporter:
            reporter.report("扫描中", 50, "正在扫描信息泄露")
        
        result = await asyncio.to_thread(get_infoleak, target)
        
        if reporter:
            reporter.report("完成", 100, "信息泄露扫描完成")
        
        return PluginResult.success(
            data={"leak_info": result, "target": target},
            tool_name="infoleak_scan",
            target=target
        )
    
    @staticmethod
    @with_timeout_and_error_handling(default_timeout=120.0, tool_name="subdomain_scan")
    async def adapt_subdomain_scan(
        target: str,
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable] = None
    ) -> PluginResult:
        """适配子域名扫描插件"""
        reporter = PluginAdapter.create_reporter("subdomain_scan", target, progress_callback)
        
        if reporter:
            reporter.report("初始化", 10, "开始子域名扫描")
        
        from backend.plugins.subdomain.subdomain import get_subdomain
        
        if reporter:
            reporter.report("扫描中", 50, "正在扫描子域名")
        
        result = await asyncio.to_thread(get_subdomain, target)
        
        subdomain_count = len(result) if isinstance(result, (list, dict)) else 0
        
        if reporter:
            reporter.report("完成", 100, f"子域名扫描完成，发现{subdomain_count}个子域名")
        
        return PluginResult.success(
            data={"subdomains": result, "target": target},
            tool_name="subdomain_scan",
            target=target,
            subdomain_count=subdomain_count
        )
    
    @staticmethod
    @with_timeout_and_error_handling(default_timeout=60.0, tool_name="webside_scan")
    async def adapt_webside_scan(
        target: str,
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable] = None
    ) -> PluginResult:
        """适配站点信息扫描插件"""
        reporter = PluginAdapter.create_reporter("webside_scan", target, progress_callback)
        
        if reporter:
            reporter.report("初始化", 10, "开始站点信息扫描")
        
        from backend.plugins.webside.webside import get_side_info
        
        if reporter:
            reporter.report("扫描中", 50, "正在获取站点信息")
        
        result = await asyncio.to_thread(get_side_info, target)
        
        if reporter:
            reporter.report("完成", 100, "站点信息扫描完成")
        
        return PluginResult.success(
            data={"side_info": result, "target": target},
            tool_name="webside_scan",
            target=target
        )
    
    @staticmethod
    @with_timeout_and_error_handling(default_timeout=30.0, tool_name="webweight_scan")
    async def adapt_webweight_scan(
        target: str,
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable] = None
    ) -> PluginResult:
        """适配网站权重扫描插件"""
        reporter = PluginAdapter.create_reporter("webweight_scan", target, progress_callback)
        
        if reporter:
            reporter.report("初始化", 10, "开始网站权重查询")
        
        from backend.plugins.webweight.webweight import get_web_weight
        
        if reporter:
            reporter.report("查询中", 50, "正在查询网站权重")
        
        result = await asyncio.to_thread(get_web_weight, target)
        
        if reporter:
            reporter.report("完成", 100, "网站权重查询完成")
        
        return PluginResult.success(
            data={"weight_info": result, "target": target},
            tool_name="webweight_scan",
            target=target
        )
    
    @staticmethod
    @with_timeout_and_error_handling(default_timeout=30.0, tool_name="iplocating")
    async def adapt_iplocating(
        target: str,
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable] = None
    ) -> PluginResult:
        """适配IP定位插件"""
        reporter = PluginAdapter.create_reporter("iplocating", target, progress_callback)
        
        if reporter:
            reporter.report("初始化", 10, "开始IP定位")
        
        from backend.plugins.iplocating.iplocating import get_locating
        
        if reporter:
            reporter.report("定位中", 50, "正在定位IP地址")
        
        result = await asyncio.to_thread(get_locating, target)
        
        if reporter:
            reporter.report("完成", 100, "IP定位完成")
        
        return PluginResult.success(
            data={"location_info": result, "target": target},
            tool_name="iplocating",
            target=target
        )

    @staticmethod
    @with_timeout_and_error_handling(default_timeout=30.0, tool_name="loginfo")
    async def adapt_loginfo(
        target: str,
        log_name: str = "default",
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable] = None
    ) -> PluginResult:
        """适配日志处理插件"""
        reporter = PluginAdapter.create_reporter("loginfo", target, progress_callback)
        
        if reporter:
            reporter.report("初始化", 10, "初始化日志处理器")
        
        from backend.plugins.loginfo.loginfo import LogHandler
        
        if reporter:
            reporter.report("配置中", 50, "正在配置日志处理器")
        
        return PluginResult.success(
            data={"log_name": log_name, "target": target, "status": "ready"},
            tool_name="loginfo",
            target=target
        )

    @staticmethod
    @with_timeout_and_error_handling(default_timeout=30.0, tool_name="randheader")
    async def adapt_randheader(
        target: str,
        conn_type: str = "keep-alive",
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable] = None
    ) -> PluginResult:
        """适配随机请求头生成插件"""
        reporter = PluginAdapter.create_reporter("randheader", target, progress_callback)
        
        if reporter:
            reporter.report("初始化", 10, "开始生成随机请求头")
        
        from backend.plugins.randheader.randheader import get_random_headers
        
        if reporter:
            reporter.report("生成中", 50, "正在生成随机请求头")
        
        result = await asyncio.to_thread(get_random_headers, conn_type)
        
        if reporter:
            reporter.report("完成", 100, "随机请求头生成完成")
        
        return PluginResult.success(
            data={"headers": result, "target": target},
            tool_name="randheader",
            target=target
        )

    @staticmethod
    @with_timeout_and_error_handling(default_timeout=180.0, tool_name="dirscan")
    async def adapt_dirscan(
        target: str,
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable] = None,
        dict_path: Optional[str] = None,
        extensions: Optional[List[str]] = None
    ) -> PluginResult:
        """适配目录扫描插件"""
        reporter = PluginAdapter.create_reporter("dirscan", target, progress_callback)
        
        if reporter:
            reporter.report("初始化", 10, "开始目录扫描")
        
        from backend.plugins.dirscan.dirscan import get_dirscan
        
        if reporter:
            reporter.report("扫描中", 30, "正在进行目录爆破")
        
        config = {}
        if extensions:
            config["extensions"] = extensions
        
        result = await asyncio.to_thread(get_dirscan, target, config, dict_path)
        
        found_count = result.get("found_count", 0) if isinstance(result, dict) else 0
        
        if reporter:
            reporter.report("完成", 100, f"目录扫描完成，发现{found_count}个有效路径")
        
        return PluginResult.success(
            data={"dirscan_results": result, "target": target},
            tool_name="dirscan",
            target=target,
            found_count=found_count
        )

    @staticmethod
    @with_timeout_and_error_handling(default_timeout=300.0, tool_name="awvs")
    async def adapt_awvs(
        target: str,
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable] = None,
        scan_type: str = "full_scan"
    ) -> PluginResult:
        """适配AWVS扫描"""
        reporter = PluginAdapter.create_reporter("awvs", target, progress_callback)
        
        if reporter:
            reporter.report("初始化", 10, "检查AWVS配置")
        
        from backend.config import settings
        from backend.AVWS.API.Target import Target
        from backend.AVWS.API.Scan import Scan
        
        api_url = settings.AWVS_API_URL
        api_key = settings.AWVS_API_KEY
        
        if not api_url or not api_key:
            return PluginResult.failed(
                error="AWVS配置缺失(API_URL或API_KEY)",
                tool_name="awvs",
                target=target
            )
        
        if reporter:
            reporter.report("添加目标", 30, "正在添加扫描目标")
        
        def run_awvs():
            target_api = Target(api_url, api_key)
            scan_api = Scan(api_url, api_key)
            
            target_id = target_api.add(target)
            if not target_id:
                raise Exception("添加目标失败")
            
            return target_api, scan_api, target_id
        
        target_api, scan_api, target_id = await asyncio.to_thread(run_awvs)
        
        if reporter:
            reporter.report("启动扫描", 60, "正在启动AWVS扫描")
        
        scan_id = await asyncio.to_thread(scan_api.add, target_id, scan_type)
        if not scan_id:
            return PluginResult.failed(
                error="启动扫描失败",
                tool_name="awvs",
                target=target,
                target_id=target_id
            )
        
        if reporter:
            reporter.report("完成", 100, "AWVS扫描任务已启动")
        
        return PluginResult.success(
            data={
                "message": "AWVS扫描任务已启动",
                "scan_id": scan_id,
                "target_id": target_id,
                "target": target
            },
            tool_name="awvs",
            target=target,
            scan_type=scan_type
        )
    
    @staticmethod
    @with_timeout_and_error_handling(default_timeout=300.0, tool_name="crawler")
    async def adapt_crawler(
        target: str,
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable] = None,
        max_depth: int = 3,
        max_pages: int = 100
    ) -> PluginResult:
        """适配Web爬虫插件"""
        reporter = PluginAdapter.create_reporter("crawler", target, progress_callback)
        
        if reporter:
            reporter.report("初始化", 10, "开始Web爬虫")
        
        from backend.plugins.crawler.crawler import WebCrawler
        
        config = {
            "max_depth": max_depth,
            "max_pages": max_pages
        }
        
        crawler = WebCrawler(target, config)
        
        if reporter:
            reporter.report("爬取中", 30, "正在爬取网站")
        
        result = await asyncio.to_thread(crawler.crawl)
        
        if reporter:
            reporter.report("完成", 100, f"爬取完成，发现 {result.get('total_pages', 0)} 个页面")
        
        return PluginResult.success(
            data={"crawler_results": result, "target": target},
            tool_name="crawler",
            target=target,
            pages_found=result.get("total_pages", 0)
        )
    
    @staticmethod
    @with_timeout_and_error_handling(default_timeout=120.0, tool_name="fileupload_scan")
    async def adapt_fileupload_scan(
        target: str,
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable] = None
    ) -> PluginResult:
        """文件上传漏洞扫描适配器"""
        reporter = PluginAdapter.create_reporter("fileupload_scan", target, progress_callback)
        
        if reporter:
            reporter.report("初始化", 10, "开始文件上传漏洞扫描")
        
        from backend.vulnerability_scan_plugins.fileupload.scanner import FileUploadScanner
        
        scanner = FileUploadScanner(target)
        
        if reporter:
            reporter.report("扫描中", 30, "正在检测文件上传漏洞")
        
        result = await asyncio.to_thread(scanner.scan)
        
        if reporter:
            reporter.report("完成", 100, f"扫描完成，发现 {len(result.vulnerabilities)} 个漏洞")
        
        return PluginResult.success(
            data={"fileupload_results": result.to_dict(), "target": target},
            tool_name="fileupload_scan",
            target=target,
            found_count=len(result.vulnerabilities)
        )
    
    @staticmethod
    @with_timeout_and_error_handling(default_timeout=180.0, tool_name="cmdi_scan")
    async def adapt_cmdi_scan(
        target: str,
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable] = None
    ) -> PluginResult:
        """命令注入扫描适配器"""
        reporter = PluginAdapter.create_reporter("cmdi_scan", target, progress_callback)
        
        if reporter:
            reporter.report("初始化", 10, "开始命令注入扫描")
        
        from backend.vulnerability_scan_plugins.cmdi.scanner import CmdiScanner
        
        scanner = CmdiScanner(target)
        
        if reporter:
            reporter.report("扫描中", 30, "正在检测命令注入漏洞")
        
        result = await asyncio.to_thread(scanner.scan)
        
        if reporter:
            reporter.report("完成", 100, f"扫描完成，发现 {len(result.vulnerabilities)} 个漏洞")
        
        return PluginResult.success(
            data={"cmdi_results": result.to_dict(), "target": target},
            tool_name="cmdi_scan",
            target=target,
            found_count=len(result.vulnerabilities)
        )
    
    @staticmethod
    @with_timeout_and_error_handling(default_timeout=300.0, tool_name="weakpass_scan")
    async def adapt_weakpass_scan(
        target: str,
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable] = None
    ) -> PluginResult:
        """弱口令扫描适配器"""
        reporter = PluginAdapter.create_reporter("weakpass_scan", target, progress_callback)
        
        if reporter:
            reporter.report("初始化", 10, "开始弱口令扫描")
        
        from backend.vulnerability_scan_plugins.weakpass.scanner import WeakPassScanner
        
        scanner = WeakPassScanner(target)
        
        if reporter:
            reporter.report("扫描中", 30, "正在检测弱口令")
        
        result = await asyncio.to_thread(scanner.scan)
        
        if reporter:
            reporter.report("完成", 100, f"扫描完成，发现 {len(result.vulnerabilities)} 个弱口令")
        
        return PluginResult.success(
            data={"weakpass_results": result.to_dict(), "target": target},
            tool_name="weakpass_scan",
            target=target,
            found_count=len(result.vulnerabilities)
        )
    
    @staticmethod
    @with_timeout_and_error_handling(default_timeout=180.0, tool_name="lfi_scan")
    async def adapt_lfi_scan(
        target: str,
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable] = None
    ) -> PluginResult:
        """文件包含扫描适配器"""
        reporter = PluginAdapter.create_reporter("lfi_scan", target, progress_callback)
        
        if reporter:
            reporter.report("初始化", 10, "开始文件包含扫描")
        
        from backend.vulnerability_scan_plugins.lfi.scanner import LfiScanner
        
        scanner = LfiScanner(target)
        
        if reporter:
            reporter.report("扫描中", 30, "正在检测文件包含漏洞")
        
        result = await asyncio.to_thread(scanner.scan)
        
        if reporter:
            reporter.report("完成", 100, f"扫描完成，发现 {len(result.vulnerabilities)} 个漏洞")
        
        return PluginResult.success(
            data={"lfi_results": result.to_dict(), "target": target},
            tool_name="lfi_scan",
            target=target,
            found_count=len(result.vulnerabilities)
        )
    
    @staticmethod
    @with_timeout_and_error_handling(default_timeout=180.0, tool_name="ssrf_scan")
    async def adapt_ssrf_scan(
        target: str,
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable] = None
    ) -> PluginResult:
        """SSRF扫描适配器"""
        reporter = PluginAdapter.create_reporter("ssrf_scan", target, progress_callback)
        
        if reporter:
            reporter.report("初始化", 10, "开始SSRF扫描")
        
        from backend.vulnerability_scan_plugins.ssrf.scanner import SsrfScanner
        
        scanner = SsrfScanner(target)
        
        if reporter:
            reporter.report("扫描中", 30, "正在检测SSRF漏洞")
        
        result = await asyncio.to_thread(scanner.scan)
        
        if reporter:
            reporter.report("完成", 100, f"扫描完成，发现 {len(result.vulnerabilities)} 个漏洞")
        
        return PluginResult.success(
            data={"ssrf_results": result.to_dict(), "target": target},
            tool_name="ssrf_scan",
            target=target,
            found_count=len(result.vulnerabilities)
        )
    
    @staticmethod
    @with_timeout_and_error_handling(default_timeout=120.0, tool_name="sqli_scan")
    async def adapt_sqli_scan(
        target: str,
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable] = None
    ) -> PluginResult:
        """SQL注入扫描适配器"""
        reporter = PluginAdapter.create_reporter("sqli_scan", target, progress_callback)
        
        if reporter:
            reporter.report("初始化", 10, "开始SQL注入扫描")
        
        from backend.vulnerability_scan_plugins.sqli.scanner import SQLiScanner
        
        scanner = SQLiScanner(target)
        
        if reporter:
            reporter.report("扫描中", 30, "正在检测SQL注入漏洞")
        
        result = await asyncio.to_thread(scanner.scan)
        
        if reporter:
            reporter.report("完成", 100, f"扫描完成，发现 {len(result.vulnerabilities)} 个漏洞")
        
        return PluginResult.success(
            data={"sqli_results": result.to_dict(), "target": target},
            tool_name="sqli_scan",
            target=target,
            found_count=len(result.vulnerabilities)
        )
    
    @staticmethod
    @with_timeout_and_error_handling(default_timeout=120.0, tool_name="xss_scan")
    async def adapt_xss_scan(
        target: str,
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable] = None
    ) -> PluginResult:
        """XSS扫描适配器"""
        reporter = PluginAdapter.create_reporter("xss_scan", target, progress_callback)
        
        if reporter:
            reporter.report("初始化", 10, "开始XSS扫描")
        
        from backend.vulnerability_scan_plugins.xss.scanner import XSSScanner
        
        scanner = XSSScanner(target)
        
        if reporter:
            reporter.report("扫描中", 30, "正在检测XSS漏洞")
        
        result = await asyncio.to_thread(scanner.scan)
        
        if reporter:
            reporter.report("完成", 100, f"扫描完成，发现 {len(result.vulnerabilities)} 个漏洞")
        
        return PluginResult.success(
            data={"xss_results": result.to_dict(), "target": target},
            tool_name="xss_scan",
            target=target,
            found_count=len(result.vulnerabilities)
        )
    
    @staticmethod
    @with_timeout_and_error_handling(default_timeout=60.0, tool_name="csrf_scan")
    async def adapt_csrf_scan(
        target: str,
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable] = None
    ) -> PluginResult:
        """CSRF扫描适配器"""
        reporter = PluginAdapter.create_reporter("csrf_scan", target, progress_callback)
        
        if reporter:
            reporter.report("初始化", 10, "开始CSRF扫描")
        
        from backend.vulnerability_scan_plugins.csrf.scanner import CSRFScanner
        
        scanner = CSRFScanner(target)
        
        if reporter:
            reporter.report("扫描中", 30, "正在检测CSRF漏洞")
        
        result = await asyncio.to_thread(scanner.scan)
        
        if reporter:
            reporter.report("完成", 100, f"扫描完成，发现 {len(result.vulnerabilities)} 个漏洞")
        
        return PluginResult.success(
            data={"csrf_results": result.to_dict(), "target": target},
            tool_name="csrf_scan",
            target=target,
            found_count=len(result.vulnerabilities)
        )
    
    @staticmethod
    @with_timeout_and_error_handling(default_timeout=60.0, tool_name="vuln_infoleak_scan")
    async def adapt_vuln_infoleak_scan(
        target: str,
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable] = None
    ) -> PluginResult:
        """敏感信息泄露扫描适配器"""
        reporter = PluginAdapter.create_reporter("vuln_infoleak_scan", target, progress_callback)
        
        if reporter:
            reporter.report("初始化", 10, "开始敏感信息泄露扫描")
        
        from backend.vulnerability_scan_plugins.infoleak.scanner import InfoLeakScanner
        
        scanner = InfoLeakScanner(target)
        
        if reporter:
            reporter.report("扫描中", 30, "正在检测敏感信息泄露")
        
        result = await asyncio.to_thread(scanner.scan)
        
        if reporter:
            reporter.report("完成", 100, f"扫描完成，发现 {len(result.vulnerabilities)} 个漏洞")
        
        return PluginResult.success(
            data={"infoleak_results": result.to_dict(), "target": target},
            tool_name="vuln_infoleak_scan",
            target=target,
            found_count=len(result.vulnerabilities)
        )
    
    @staticmethod
    def get_adapters() -> Dict[str, Callable]:
        """
        获取所有插件适配器
        
        Returns:
            Dict[str, Callable]: 适配器名称到函数的映射
        """
        return {
            "baseinfo": PluginAdapter.adapt_baseinfo,
            "portscan": PluginAdapter.adapt_portscan,
            "waf_detect": PluginAdapter.adapt_waf_detect,
            "cdn_detect": PluginAdapter.adapt_cdn_detect,
            "cms_identify": PluginAdapter.adapt_cms_identify,
            "infoleak_scan": PluginAdapter.adapt_infoleak_scan,
            "subdomain_scan": PluginAdapter.adapt_subdomain_scan,
            "webside_scan": PluginAdapter.adapt_webside_scan,
            "webweight_scan": PluginAdapter.adapt_webweight_scan,
            "iplocating": PluginAdapter.adapt_iplocating,
            "loginfo": PluginAdapter.adapt_loginfo,
            "randheader": PluginAdapter.adapt_randheader,
            "dirscan": PluginAdapter.adapt_dirscan,
            "awvs": PluginAdapter.adapt_awvs,
            "crawler": PluginAdapter.adapt_crawler,
            "sqli_scan": PluginAdapter.adapt_sqli_scan,
            "xss_scan": PluginAdapter.adapt_xss_scan,
            "csrf_scan": PluginAdapter.adapt_csrf_scan,
            "vuln_infoleak_scan": PluginAdapter.adapt_vuln_infoleak_scan,
            "fileupload_scan": PluginAdapter.adapt_fileupload_scan,
            "cmdi_scan": PluginAdapter.adapt_cmdi_scan,
            "weakpass_scan": PluginAdapter.adapt_weakpass_scan,
            "lfi_scan": PluginAdapter.adapt_lfi_scan,
            "ssrf_scan": PluginAdapter.adapt_ssrf_scan,
        }


class POCAdapter(BaseAdapter):
    """
    POC适配器
    
    适配现有的POC脚本，提供统一的调用接口。
    支持超时控制、异常捕获和进度回调。
    """
    
    DEFAULT_POC_TIMEOUT = 30.0
    
    @staticmethod
    @with_timeout_and_error_handling(default_timeout=30.0, tool_name="poc")
    async def adapt_poc(
        target: str,
        poc_name: str,
        poc_module: Any,
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable] = None
    ) -> PluginResult:
        """
        执行单个POC检测
        
        Args:
            target: 目标地址
            poc_name: POC名称
            poc_module: POC模块
            timeout: 超时时间(秒)
            progress_callback: 进度回调函数
        
        Returns:
            PluginResult: 统一格式的执行结果
        """
        reporter = POCAdapter.create_reporter(f"poc_{poc_name}", target, progress_callback)
        
        if reporter:
            reporter.report("初始化", 10, f"开始执行POC: {poc_name}")
        
        if hasattr(poc_module, 'poc'):
            poc_func = poc_module.poc
        else:
            poc_func = poc_module
        
        if reporter:
            reporter.report("执行中", 50, "正在执行漏洞检测")
        
        actual_timeout = timeout if timeout is not None else POCAdapter.DEFAULT_POC_TIMEOUT
        is_vulnerable, message = await asyncio.to_thread(poc_func, target, actual_timeout)
        
        if reporter:
            status = "存在漏洞" if is_vulnerable else "未发现漏洞"
            reporter.report("完成", 100, f"检测完成: {status}")
        
        return PluginResult.success(
            data={
                "vulnerable": is_vulnerable,
                "message": message,
                "poc_name": poc_name,
                "target": target
            },
            tool_name=f"poc_{poc_name}",
            target=target,
            is_vulnerable=is_vulnerable
        )
    
    @staticmethod
    async def run_poc_batch(
        target: str,
        poc_names: List[str],
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable] = None
    ) -> List[PluginResult]:
        """
        批量执行多个POC
        
        Args:
            target: 目标地址
            poc_names: POC名称列表
            timeout: 单个POC超时时间(秒)
            progress_callback: 进度回调函数
        
        Returns:
            List[PluginResult]: 所有POC的执行结果列表
        """
        results = []
        pocs = POCAdapter.get_all_pocs()
        total = len(poc_names)
        
        reporter = POCAdapter.create_reporter("poc_batch", target, progress_callback)
        
        for idx, poc_name in enumerate(poc_names):
            if poc_name not in pocs:
                results.append(PluginResult.failed(
                    error=f"POC {poc_name} 不存在",
                    tool_name=f"poc_{poc_name}",
                    target=target
                ))
                continue
            
            if reporter:
                progress = int((idx / total) * 100)
                reporter.report("批量检测", progress, f"执行 {poc_name} ({idx+1}/{total})")
            
            result = await POCAdapter.adapt_poc(
                target=target,
                poc_name=poc_name,
                poc_module=pocs[poc_name],
                timeout=timeout,
                progress_callback=None
            )
            results.append(result)
        
        if reporter:
            reporter.report("完成", 100, f"批量检测完成，共检测{total}个POC")
        
        return results
    
    @staticmethod
    def get_all_pocs() -> Dict[str, Any]:
        """
        获取所有POC模块
        
        Returns:
            Dict[str, Any]: POC名称到模块的映射
        """
        from backend.poc import (
            cve_2020_2551_poc, cve_2018_2628_poc, cve_2018_2894_poc,
            cve_2020_14756_poc, cve_2023_21839_poc,
            struts2_009_poc, struts2_032_poc,
            cve_2017_12615_poc, cve_2022_22965_poc, cve_2022_47986_poc,
            cve_2017_12149_poc, cve_2020_10199_poc, cve_2018_7600_poc,
            poc_99617_ai_poc, poc_manual_thinkphp_ai_poc
        )
        
        return {
            "poc_weblogic_2020_2551": cve_2020_2551_poc,
            "poc_weblogic_2018_2628": cve_2018_2628_poc,
            "poc_weblogic_2018_2894": cve_2018_2894_poc,
            "poc_weblogic_2020_14756": cve_2020_14756_poc,
            "poc_weblogic_2023_21839": cve_2023_21839_poc,
            "poc_struts2_009": struts2_009_poc,
            "poc_struts2_032": struts2_032_poc,
            "poc_tomcat_2017_12615": cve_2017_12615_poc,
            "poc_tomcat_2022_22965": cve_2022_22965_poc,
            "poc_tomcat_2022_47986": cve_2022_47986_poc,
            "poc_jboss_2017_12149": cve_2017_12149_poc,
            "poc_nexus_2020_10199": cve_2020_10199_poc,
            "poc_drupal_2018_7600": cve_2018_7600_poc,
            "poc_thinkphp_99617": poc_99617_ai_poc,
            "poc_thinkphp_manual": poc_manual_thinkphp_ai_poc,
        }
    
    @staticmethod
    def get_poc_by_cms(cms: str) -> List[str]:
        """
        根据CMS类型获取相关POC
        
        Args:
            cms: CMS类型
            
        Returns:
            List[str]: 相关POC名称列表
        """
        cms_lower = cms.lower()
        poc_mapping = {
            "weblogic": ["poc_weblogic_2020_2551", "poc_weblogic_2018_2628", 
                       "poc_weblogic_2018_2894", "poc_weblogic_2020_14756", "poc_weblogic_2023_21839"],
            "struts2": ["poc_struts2_009", "poc_struts2_032"],
            "tomcat": ["poc_tomcat_2017_12615", "poc_tomcat_2022_22965", "poc_tomcat_2022_47986"],
            "jboss": ["poc_jboss_2017_12149"],
            "nexus": ["poc_nexus_2020_10199"],
            "drupal": ["poc_drupal_2018_7600"],
            "thinkphp": ["poc_thinkphp_99617", "poc_thinkphp_manual"],
        }
        
        for key, pocs in poc_mapping.items():
            if key in cms_lower:
                return pocs
        
        return []
    
    @staticmethod
    def get_poc_by_port(port: int) -> List[str]:
        """
        根据端口获取相关POC
        
        Args:
            port: 端口号
            
        Returns:
            List[str]: 相关POC名称列表
        """
        port_mapping = {
            7001: ["poc_weblogic_2020_2551", "poc_weblogic_2018_2628", 
                    "poc_weblogic_2018_2894", "poc_weblogic_2020_14756", "poc_weblogic_2023_21839"],
            8080: ["poc_tomcat_2017_12615", "poc_tomcat_2022_22965", "poc_tomcat_2022_47986"],
        }
        
        return port_mapping.get(port, [])


class DependencyAdapter(BaseAdapter):
    """
    依赖安装适配器
    
    适配依赖安装功能，提供统一的调用接口。
    支持超时控制、异常捕获和进度回调。
    """
    
    @staticmethod
    @with_timeout_and_error_handling(default_timeout=300.0, tool_name="dependency_install")
    async def adapt_install_dependencies(
        target: str,
        packages: Optional[str] = None,
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable] = None,
        **kwargs
    ) -> PluginResult:
        """
        适配依赖安装功能
        
        Args:
            target: 目标地址(用于兼容性，实际不使用)
            packages: 要安装的包列表，逗号分隔
            timeout: 超时时间(秒)
            progress_callback: 进度回调函数
            **kwargs: 其他参数
        
        Returns:
            PluginResult: 统一格式的执行结果
        """
        reporter = DependencyAdapter.create_reporter("dependency_install", target or "system", progress_callback)
        
        if reporter:
            reporter.report("初始化", 10, "准备安装依赖")
        
        from backend.ai_agents.tools.dependency_installer import install_dependencies
        
        if packages:
            package_list = [p.strip() for p in packages.split(',')]
        else:
            package_list = []
        
        if reporter:
            reporter.report("安装中", 30, f"正在安装 {len(package_list)} 个包")
        
        result = await asyncio.to_thread(install_dependencies, package_list, **kwargs)
        
        if reporter:
            installed_count = len(result.get("installed_packages", []))
            reporter.report("完成", 100, f"安装完成，成功安装 {installed_count} 个包")
        
        if result["status"] == "success":
            return PluginResult.success(
                data={
                    "installed_packages": result["installed_packages"],
                    "output": result["output"],
                    "target": target
                },
                tool_name="dependency_install",
                target=target
            )
        else:
            return PluginResult.failed(
                error=result.get("error", "安装失败"),
                tool_name="dependency_install",
                target=target,
                output=result.get("output")
            )
    
    @staticmethod
    @with_timeout_and_error_handling(default_timeout=30.0, tool_name="check_package")
    async def adapt_check_package(
        target: str,
        package: Optional[str] = None,
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable] = None,
        **kwargs
    ) -> PluginResult:
        """
        适配包检查功能
        
        Args:
            target: 目标地址(用于兼容性)
            package: 要检查的包名
            timeout: 超时时间(秒)
            progress_callback: 进度回调函数
            **kwargs: 其他参数
        
        Returns:
            PluginResult: 统一格式的执行结果
        """
        reporter = DependencyAdapter.create_reporter("check_package", target or "system", progress_callback)
        
        if not package:
            return PluginResult.failed(
                error="未指定包名",
                tool_name="check_package",
                target=target
            )
        
        if reporter:
            reporter.report("检查中", 50, f"正在检查包: {package}")
        
        from .dependency_installer import check_package_installed
        
        installed = await asyncio.to_thread(check_package_installed, package)
        
        if reporter:
            status = "已安装" if installed else "未安装"
            reporter.report("完成", 100, f"检查完成: {package} {status}")
        
        return PluginResult.success(
            data={"installed": installed, "package": package, "target": target},
            tool_name="check_package",
            target=target
        )
    
    @staticmethod
    @with_timeout_and_error_handling(default_timeout=30.0, tool_name="list_packages")
    async def adapt_get_packages(
        target: str,
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable] = None,
        **kwargs
    ) -> PluginResult:
        """
        适配获取已安装包列表功能
        
        Args:
            target: 目标地址(用于兼容性)
            timeout: 超时时间(秒)
            progress_callback: 进度回调函数
            **kwargs: 其他参数
        
        Returns:
            PluginResult: 统一格式的执行结果
        """
        reporter = DependencyAdapter.create_reporter("list_packages", target or "system", progress_callback)
        
        if reporter:
            reporter.report("获取中", 50, "正在获取已安装包列表")
        
        from .dependency_installer import get_installed_packages
        
        packages = await asyncio.to_thread(get_installed_packages)
        
        if reporter:
            reporter.report("完成", 100, f"获取完成，共 {len(packages)} 个包")
        
        return PluginResult.success(
            data={"packages": packages, "count": len(packages), "target": target},
            tool_name="list_packages",
            target=target
        )


async def run_plugin(
    plugin_name: str,
    target: str,
    timeout: Optional[float] = None,
    progress_callback: Optional[Callable] = None,
    **kwargs
) -> PluginResult:
    """
    统一的插件运行入口
    
    提供统一的插件调用接口，自动选择对应的适配器执行。
    
    Args:
        plugin_name: 插件名称
        target: 目标地址
        timeout: 超时时间(秒)
        progress_callback: 进度回调函数
        **kwargs: 传递给插件的其他参数
    
    Returns:
        PluginResult: 统一格式的执行结果
    
    Example:
        result = await run_plugin("portscan", "example.com", timeout=60)
        if result.is_success:
            print(result.data)
    """
    adapters = PluginAdapter.get_adapters()
    
    if plugin_name not in adapters:
        return PluginResult.failed(
            error=f"未知的插件: {plugin_name}",
            tool_name=plugin_name,
            target=target,
            available_plugins=list(adapters.keys())
        )
    
    adapter_func = adapters[plugin_name]
    return await adapter_func(
        target=target,
        timeout=timeout,
        progress_callback=progress_callback,
        **kwargs
    )


async def run_multiple_plugins(
    plugin_names: List[str],
    target: str,
    timeout: Optional[float] = None,
    progress_callback: Optional[Callable] = None
) -> Dict[str, PluginResult]:
    """
    批量运行多个插件
    
    Args:
        plugin_names: 插件名称列表
        target: 目标地址
        timeout: 单个插件超时时间(秒)
        progress_callback: 进度回调函数
    
    Returns:
        Dict[str, PluginResult]: 插件名称到执行结果的映射
    """
    results = {}
    total = len(plugin_names)
    
    for idx, plugin_name in enumerate(plugin_names):
        if progress_callback:
            def plugin_progress(name, stage, progress, info):
                overall_progress = int((idx / total) * 100 + (progress / total))
                progress_callback(name, stage, overall_progress, info)
        else:
            plugin_progress = None
        
        results[plugin_name] = await run_plugin(
            plugin_name=plugin_name,
            target=target,
            timeout=timeout,
            progress_callback=plugin_progress
        )
    
    return results
