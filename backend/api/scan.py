"""
扫描功能相关的 API 路由
整合原有的 plugins 功能模块
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Dict, Any
import logging

logger = logging.getLogger(__name__)

router = APIRouter()


# 请求模型
class IPRequest(BaseModel):
    ip: str


class URLRequest(BaseModel):
    url: str


class DomainRequest(BaseModel):
    domain: str


class PortScanRequest(BaseModel):
    ip: str
    ports: Optional[str] = "1-1000"  # 默认扫描端口范围


class SubdomainRequest(BaseModel):
    domain: str
    deep_scan: Optional[bool] = False


# 响应模型
class APIResponse(BaseModel):
    code: int
    message: str
    data: Optional[Any] = None


# ==================== 端口扫描 ====================
@router.post("/port-scan", response_model=APIResponse)
async def port_scan(request: PortScanRequest):
    """
    端口扫描
    """
    try:
        from plugins.portscan.portscan import ScanPort
        from plugins.common.common import check_ip
        
        if not check_ip(request.ip):
            raise HTTPException(status_code=400, detail="请填写正确的IP地址")
        
        scanner = ScanPort(request.ip)
        if scanner.run_scan():
            result = scanner.get_results()
        else:
            result = []
        logger.info(f"端口扫描完成: {request.ip}")
        
        return APIResponse(code=200, message="扫描成功", data=result)
    except Exception as e:
        logger.error(f"端口扫描失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 信息泄露检测 ====================
@router.post("/info-leak", response_model=APIResponse)
async def info_leak(request: URLRequest):
    """
    信息泄露检测
    """
    try:
        from plugins.infoleak.infoleak import get_infoleak
        from plugins.common.common import check_url
        
        url = check_url(request.url)
        if not url:
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        result = get_infoleak(url)
        logger.info(f"信息泄露检测完成: {url}")
        
        return APIResponse(code=200, message="检测成功", data=result)
    except Exception as e:
        logger.error(f"信息泄露检测失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 旁站扫描 ====================
@router.post("/web-side", response_model=APIResponse)
async def web_side_scan(request: IPRequest):
    """
    获取旁站信息
    """
    try:
        from plugins.webside.webside import get_side_info
        from plugins.common.common import check_ip
        
        if not check_ip(request.ip):
            raise HTTPException(status_code=400, detail="请填写正确的IP地址")
        
        result = get_side_info(request.ip)
        if not result:
            return APIResponse(code=400, message="未找到旁站信息", data=None)
        
        logger.info(f"旁站扫描完成: {request.ip}")
        return APIResponse(code=200, message="扫描成功", data=result)
    except Exception as e:
        logger.error(f"旁站扫描失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 网站基本信息 ====================
@router.post("/baseinfo", response_model=APIResponse)
async def get_base_info(request: URLRequest):
    """
    获取网站基本信息
    """
    try:
        from plugins.baseinfo.baseinfo import getbaseinfo
        from plugins.common.common import check_url
        
        url = check_url(request.url)
        if not url:
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        result = getbaseinfo(url)
        logger.info(f"网站基本信息获取完成: {url}")
        
        return APIResponse(code=result.get('code', 200), message=result.get('msg', '成功'), data=result)
    except Exception as e:
        logger.error(f"获取网站基本信息失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 网站权重 ====================
@router.post("/web-weight", response_model=APIResponse)
async def get_web_weight(request: URLRequest):
    """
    获取网站权重
    """
    try:
        from plugins.webweight.webweight import get_web_weight
        from plugins.common.common import check_url
        
        url = check_url(request.url)
        if not url:
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        result = get_web_weight(url)
        logger.info(f"网站权重获取完成: {url}")
        
        return APIResponse(code=200, message="获取成功", data=result)
    except Exception as e:
        logger.error(f"获取网站权重失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== IP定位 ====================
@router.post("/ip-locating", response_model=APIResponse)
async def ip_locating(request: IPRequest):
    """
    IP定位
    """
    try:
        from plugins.iplocating.iplocating import get_locating
        from plugins.common.common import check_ip
        
        if not check_ip(request.ip):
            raise HTTPException(status_code=400, detail="请填写正确的IP地址")
        
        result = get_locating(request.ip)
        logger.info(f"IP定位完成: {request.ip}")
        
        return APIResponse(code=200, message="定位成功", data=result)
    except Exception as e:
        logger.error(f"IP定位失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== CDN检测 ====================
@router.post("/cdn-check", response_model=APIResponse)
async def cdn_check(request: URLRequest):
    """
    判断是否使用CDN
    """
    try:
        from plugins.cdnexist.cdnexist import iscdn
        from plugins.common.common import check_url
        
        url = check_url(request.url)
        if not url:
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        result_str = iscdn(url)
        if result_str == '目标站点不可访问':
            return APIResponse(code=200, message="网络错误", data=result_str)
        
        result = "存在CDN（源IP可能不正确）" if result_str else "无CDN"
        logger.info(f"CDN检测完成: {url}")
        
        return APIResponse(code=200, message="检测成功", data=result)
    except Exception as e:
        logger.error(f"CDN检测失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== WAF检测 ====================
@router.post("/waf-check", response_model=APIResponse)
async def waf_check(request: URLRequest):
    """
    判断是否使用WAF
    """
    try:
        from plugins.waf.waf import getwaf
        from plugins.common.common import check_url
        
        url = check_url(request.url)
        if not url:
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        result = getwaf(url)
        logger.info(f"WAF检测完成: {url}")
        
        return APIResponse(code=200, message="检测成功", data=result)
    except Exception as e:
        logger.error(f"WAF检测失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== CMS指纹识别 ====================
@router.post("/what-cms", response_model=APIResponse)
async def what_cms(request: URLRequest):
    """
    CMS指纹识别
    """
    try:
        from plugins.whatcms.whatcms import getwhatcms
        from plugins.common.common import check_url
        
        url = check_url(request.url)
        if not url:
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        result = getwhatcms(url)
        logger.info(f"CMS指纹识别完成: {url}")
        
        return APIResponse(code=200, message="识别成功", data=result)
    except Exception as e:
        logger.error(f"CMS指纹识别失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 子域名扫描 ====================
@router.post("/subdomain", response_model=APIResponse)
async def subdomain_scan(request: SubdomainRequest):
    """
    子域名扫描
    """
    try:
        from plugins.subdomain.subdomain import get_subdomain
        
        if not request.domain:
            raise HTTPException(status_code=400, detail="请填写正确的域名")
        
        result = get_subdomain(request.domain)
        logger.info(f"子域名扫描完成: {request.domain}, 发现 {len(result)} 个子域名")
        
        return APIResponse(code=200, message="扫描成功", data=result)
    except Exception as e:
        logger.error(f"子域名扫描失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 目录扫描 ====================
@router.post("/dir-scan", response_model=APIResponse)
async def dir_scan(request: URLRequest):
    """
    目录扫描
    """
    try:
        from dirsearcch.dir_scanner import DirScanner
        from plugins.common.common import check_url
        
        url = check_url(request.url)
        if not url:
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        scanner = DirScanner(url)
        result = scanner.scan()
        logger.info(f"目录扫描完成: {url}")
        
        return APIResponse(code=200, message="扫描成功", data=result)
    except Exception as e:
        logger.error(f"目录扫描失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 综合扫描 ====================
@router.post("/comprehensive", response_model=APIResponse)
async def comprehensive_scan(request: URLRequest):
    """
    综合扫描（执行多个检测项）
    """
    try:
        from plugins.common.common import check_url
        
        url = check_url(request.url)
        if not url:
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        results = {}
        
        # 执行各项检测
        try:
            from plugins.baseinfo.baseinfo import getbaseinfo
            results['baseinfo'] = getbaseinfo(url)
        except Exception as e:
            results['baseinfo'] = {'error': str(e)}
        
        try:
            from plugins.whatcms.whatcms import getwhatcms
            results['cms'] = getwhatcms(url)
        except Exception as e:
            results['cms'] = {'error': str(e)}
        
        try:
            from plugins.cdnexist.cdnexist import iscdn
            results['cdn'] = "存在CDN" if iscdn(url) else "无CDN"
        except Exception as e:
            results['cdn'] = {'error': str(e)}
        
        try:
            from plugins.waf.waf import getwaf
            results['waf'] = getwaf(url)
        except Exception as e:
            results['waf'] = {'error': str(e)}
        
        logger.info(f"综合扫描完成: {url}")
        return APIResponse(code=200, message="综合扫描完成", data=results)
    except Exception as e:
        logger.error(f"综合扫描失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


