"""
插件适配器

适配现有插件，提供统一的调用接口。
"""
import asyncio
import logging
from typing import Any, Dict, Optional, Callable

logger = logging.getLogger(__name__)


class PluginResult:
    """插件执行结果"""
    
    def __init__(
        self,
        success: bool,
        data: Any = None,
        error: Optional[str] = None,
        execution_time: float = 0.0
    ):
        self.success = success
        self.data = data
        self.error = error
        self.execution_time = execution_time
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "execution_time": self.execution_time
        }
    
    @classmethod
    def success_result(cls, data: Any = None, execution_time: float = 0.0) -> 'PluginResult':
        return cls(success=True, data=data, execution_time=execution_time)
    
    @classmethod
    def failed_result(cls, error: str, execution_time: float = 0.0) -> 'PluginResult':
        return cls(success=False, error=error, execution_time=execution_time)


class PluginAdapter:
    """
    插件适配器
    
    适配现有的扫描插件，提供统一的调用接口。
    """
    
    @staticmethod
    async def adapt_baseinfo(target: str, **kwargs) -> PluginResult:
        """适配基础信息收集插件"""
        try:
            from backend.plugins.baseinfo.baseinfo import getbaseinfo
            result = await asyncio.to_thread(getbaseinfo, target)
            return PluginResult.success_result(data=result)
        except Exception as e:
            return PluginResult.failed_result(error=str(e))
    
    @staticmethod
    async def adapt_portscan(target: str, **kwargs) -> PluginResult:
        """适配端口扫描插件"""
        try:
            from backend.plugins.portscan.portscan import ScanPort
            def run_scan():
                scanner = ScanPort(target)
                success = scanner.run_scan()
                return scanner.get_results() if success else []
            result = await asyncio.to_thread(run_scan)
            return PluginResult.success_result(data={"open_ports": result, "target": target})
        except Exception as e:
            return PluginResult.failed_result(error=str(e))
    
    @staticmethod
    async def adapt_waf_detect(target: str, **kwargs) -> PluginResult:
        """适配WAF检测插件"""
        try:
            from backend.plugins.waf.waf import get_waf
            result = await asyncio.to_thread(get_waf, target)
            return PluginResult.success_result(data={"waf_info": result, "target": target})
        except Exception as e:
            return PluginResult.failed_result(error=str(e))
    
    @staticmethod
    async def adapt_cdn_detect(target: str, **kwargs) -> PluginResult:
        """适配CDN检测插件"""
        try:
            from backend.plugins.cdnexist.cdnexist import iscdn
            result = await asyncio.to_thread(iscdn, target)
            return PluginResult.success_result(data={"has_cdn": bool(result), "target": target})
        except Exception as e:
            return PluginResult.failed_result(error=str(e))
    
    @staticmethod
    async def adapt_cms_identify(target: str, **kwargs) -> PluginResult:
        """适配CMS识别插件"""
        try:
            from backend.plugins.whatcms.whatcms import getwhatcms
            result = await asyncio.to_thread(getwhatcms, target)
            return PluginResult.success_result(data={"cms_info": result, "target": target})
        except Exception as e:
            return PluginResult.failed_result(error=str(e))
    
    @staticmethod
    async def adapt_subdomain_scan(target: str, **kwargs) -> PluginResult:
        """适配子域名扫描插件"""
        try:
            from backend.plugins.subdomain.subdomain import get_subdomain
            result = await asyncio.to_thread(get_subdomain, target)
            return PluginResult.success_result(data={"subdomains": result, "target": target})
        except Exception as e:
            return PluginResult.failed_result(error=str(e))
    
    @staticmethod
    async def adapt_webside_scan(target: str, **kwargs) -> PluginResult:
        """适配站点信息扫描插件"""
        try:
            from backend.plugins.webside.webside import get_side_info
            result = await asyncio.to_thread(get_side_info, target)
            return PluginResult.success_result(data={"side_info": result, "target": target})
        except Exception as e:
            return PluginResult.failed_result(error=str(e))
    
    @staticmethod
    async def adapt_webweight_scan(target: str, **kwargs) -> PluginResult:
        """适配网站权重扫描插件"""
        try:
            from backend.plugins.webweight.webweight import get_web_weight
            result = await asyncio.to_thread(get_web_weight, target)
            return PluginResult.success_result(data={"weight_info": result, "target": target})
        except Exception as e:
            return PluginResult.failed_result(error=str(e))
    
    @staticmethod
    async def adapt_iplocating(target: str, **kwargs) -> PluginResult:
        """适配IP定位插件"""
        try:
            from backend.plugins.iplocating.iplocating import get_locating
            result = await asyncio.to_thread(get_locating, target)
            return PluginResult.success_result(data={"location_info": result, "target": target})
        except Exception as e:
            return PluginResult.failed_result(error=str(e))
    
    @staticmethod
    async def adapt_infoleak_scan(target: str, **kwargs) -> PluginResult:
        """适配信息泄露扫描插件"""
        try:
            from backend.plugins.infoleak.infoleak import get_infoleak
            result = await asyncio.to_thread(get_infoleak, target)
            return PluginResult.success_result(data={"leak_info": result, "target": target})
        except Exception as e:
            return PluginResult.failed_result(error=str(e))
    
    @staticmethod
    async def adapt_dirscan(target: str, **kwargs) -> PluginResult:
        """适配目录扫描插件"""
        try:
            from backend.plugins.dirscan.dirscan import get_dirscan
            result = await asyncio.to_thread(get_dirscan, target, {}, None)
            return PluginResult.success_result(data={"dirscan_results": result, "target": target})
        except Exception as e:
            return PluginResult.failed_result(error=str(e))
    
    @staticmethod
    async def adapt_loginfo(target: str, **kwargs) -> PluginResult:
        """适配日志处理插件"""
        try:
            from backend.plugins.loginfo.loginfo import LogHandler
            return PluginResult.success_result(data={"log_name": kwargs.get("log_name", "default"), "target": target, "status": "ready"})
        except Exception as e:
            return PluginResult.failed_result(error=str(e))
    
    @staticmethod
    async def adapt_randheader(target: str, **kwargs) -> PluginResult:
        """适配随机请求头生成插件"""
        try:
            from backend.plugins.randheader.randheader import get_random_headers
            result = await asyncio.to_thread(get_random_headers, kwargs.get("conn_type", "keep-alive"))
            return PluginResult.success_result(data={"headers": result, "target": target})
        except Exception as e:
            return PluginResult.failed_result(error=str(e))
    
    @staticmethod
    async def adapt_crawler(target: str, **kwargs) -> PluginResult:
        """适配Web爬虫插件"""
        try:
            from backend.plugins.crawler.crawler import WebCrawler
            config = {
                "max_depth": kwargs.get("max_depth", 3),
                "max_pages": kwargs.get("max_pages", 100)
            }
            crawler = WebCrawler(target, config)
            result = await asyncio.to_thread(crawler.crawl)
            return PluginResult.success_result(data={"crawler_results": result, "target": target})
        except Exception as e:
            return PluginResult.failed_result(error=str(e))
    
    @staticmethod
    async def adapt_sqli_scan(target: str, **kwargs) -> PluginResult:
        """适配SQL注入扫描插件"""
        try:
            from backend.vulnerability_scan_plugins.sqli.scanner import SQLiScanner
            scanner = SQLiScanner(target)
            result = await asyncio.to_thread(scanner.scan)
            return PluginResult.success_result(data={"sqli_results": result.to_dict(), "target": target})
        except Exception as e:
            return PluginResult.failed_result(error=str(e))
    
    @staticmethod
    async def adapt_xss_scan(target: str, **kwargs) -> PluginResult:
        """适配XSS扫描插件"""
        try:
            from backend.vulnerability_scan_plugins.xss.scanner import XSSScanner
            scanner = XSSScanner(target)
            result = await asyncio.to_thread(scanner.scan)
            return PluginResult.success_result(data={"xss_results": result.to_dict(), "target": target})
        except Exception as e:
            return PluginResult.failed_result(error=str(e))
    
    @staticmethod
    async def adapt_csrf_scan(target: str, **kwargs) -> PluginResult:
        """适配CSRF扫描插件"""
        try:
            from backend.vulnerability_scan_plugins.csrf.scanner import CSRFScanner
            scanner = CSRFScanner(target)
            result = await asyncio.to_thread(scanner.scan)
            return PluginResult.success_result(data={"csrf_results": result.to_dict(), "target": target})
        except Exception as e:
            return PluginResult.failed_result(error=str(e))
    
    @staticmethod
    async def adapt_fileupload_scan(target: str, **kwargs) -> PluginResult:
        """适配文件上传漏洞扫描插件"""
        try:
            from backend.vulnerability_scan_plugins.fileupload.scanner import FileUploadScanner
            scanner = FileUploadScanner(target)
            result = await asyncio.to_thread(scanner.scan)
            return PluginResult.success_result(data={"fileupload_results": result.to_dict(), "target": target})
        except Exception as e:
            return PluginResult.failed_result(error=str(e))
    
    @staticmethod
    async def adapt_cmdi_scan(target: str, **kwargs) -> PluginResult:
        """适配命令注入扫描插件"""
        try:
            from backend.vulnerability_scan_plugins.cmdi.scanner import CmdiScanner
            scanner = CmdiScanner(target)
            result = await asyncio.to_thread(scanner.scan)
            return PluginResult.success_result(data={"cmdi_results": result.to_dict(), "target": target})
        except Exception as e:
            return PluginResult.failed_result(error=str(e))
    
    @staticmethod
    async def adapt_lfi_scan(target: str, **kwargs) -> PluginResult:
        """适配文件包含扫描插件"""
        try:
            from backend.vulnerability_scan_plugins.lfi.scanner import LfiScanner
            scanner = LfiScanner(target)
            result = await asyncio.to_thread(scanner.scan)
            return PluginResult.success_result(data={"lfi_results": result.to_dict(), "target": target})
        except Exception as e:
            return PluginResult.failed_result(error=str(e))
    
    @staticmethod
    async def adapt_ssrf_scan(target: str, **kwargs) -> PluginResult:
        """适配SSRF扫描插件"""
        try:
            from backend.vulnerability_scan_plugins.ssrf.scanner import SsrfScanner
            scanner = SsrfScanner(target)
            result = await asyncio.to_thread(scanner.scan)
            return PluginResult.success_result(data={"ssrf_results": result.to_dict(), "target": target})
        except Exception as e:
            return PluginResult.failed_result(error=str(e))
    
    @staticmethod
    async def adapt_weakpass_scan(target: str, **kwargs) -> PluginResult:
        """适配弱口令扫描插件"""
        try:
            from backend.vulnerability_scan_plugins.weakpass.scanner import WeakPassScanner
            scanner = WeakPassScanner(target)
            result = await asyncio.to_thread(scanner.scan)
            return PluginResult.success_result(data={"weakpass_results": result.to_dict(), "target": target})
        except Exception as e:
            return PluginResult.failed_result(error=str(e))
    
    @staticmethod
    async def adapt_vuln_infoleak_scan(target: str, **kwargs) -> PluginResult:
        """适配敏感信息泄露扫描插件"""
        try:
            from backend.vulnerability_scan_plugins.infoleak.scanner import InfoLeakScanner
            scanner = InfoLeakScanner(target)
            result = await asyncio.to_thread(scanner.scan)
            return PluginResult.success_result(data={"infoleak_results": result.to_dict(), "target": target})
        except Exception as e:
            return PluginResult.failed_result(error=str(e))
    
    @staticmethod
    def get_adapters() -> Dict[str, Callable]:
        """获取所有插件适配器"""
        return {
            "baseinfo": PluginAdapter.adapt_baseinfo,
            "portscan": PluginAdapter.adapt_portscan,
            "waf_detect": PluginAdapter.adapt_waf_detect,
            "cdn_detect": PluginAdapter.adapt_cdn_detect,
            "cms_identify": PluginAdapter.adapt_cms_identify,
            "subdomain_scan": PluginAdapter.adapt_subdomain_scan,
            "webside_scan": PluginAdapter.adapt_webside_scan,
            "webweight_scan": PluginAdapter.adapt_webweight_scan,
            "iplocating": PluginAdapter.adapt_iplocating,
            "infoleak_scan": PluginAdapter.adapt_infoleak_scan,
            "dirscan": PluginAdapter.adapt_dirscan,
            "loginfo": PluginAdapter.adapt_loginfo,
            "randheader": PluginAdapter.adapt_randheader,
            "crawler": PluginAdapter.adapt_crawler,
            "sqli_scan": PluginAdapter.adapt_sqli_scan,
            "xss_scan": PluginAdapter.adapt_xss_scan,
            "csrf_scan": PluginAdapter.adapt_csrf_scan,
            "fileupload_scan": PluginAdapter.adapt_fileupload_scan,
            "cmdi_scan": PluginAdapter.adapt_cmdi_scan,
            "lfi_scan": PluginAdapter.adapt_lfi_scan,
            "ssrf_scan": PluginAdapter.adapt_ssrf_scan,
            "weakpass_scan": PluginAdapter.adapt_weakpass_scan,
            "vuln_infoleak_scan": PluginAdapter.adapt_vuln_infoleak_scan,
        }
