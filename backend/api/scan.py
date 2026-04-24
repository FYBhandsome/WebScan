"""
扫描功能相关的 API 路由

整合原有的 backend.plugins 功能模块,统一使用异步任务执行。
提供完整的插件 API 接口,包括:
- plugins: portscan, infoleak, webside, baseinfo, webweight, iplocating, cdnexist, waf, whatcms, subdomain, dirscan, crawler, loginfo, randheader, common
- vulnerability_scan_plugins: cmdi, csrf, fileupload, infoleak, lfi, sqli, ssrf, weakpass, xss
- poc: weblogic, struts2, tomcat, jboss, nexus, drupal, thinkphp

API 响应格式:
    成功: {"code": 200, "message": "xxx", "data": {...}}
    失败: {"code": 400/500, "message": "错误信息", "data": None}

使用示例:
    POST /api/scan/port-scan
    Body: {"ip": "192.168.1.1", "ports": "1-1000"}
    Response: {"code": 200, "message": "端口扫描任务已启动", "data": {"task_id": 1}}
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Any, Dict, List
from enum import Enum
import logging
import asyncio
import json

from backend.api.common import APIResponse
from backend.api.task_utils import create_scan_task, start_task_execution, get_task_response, handle_task_error
from backend.api.validation_utils import validate_ip, validate_url, validate_domain, validate_port_range

logger = logging.getLogger(__name__)

router = APIRouter()


# ==================== 请求模型定义 ====================

class IPRequest(BaseModel):
    """IP 地址请求模型"""
    ip: str = Field(..., description="目标 IP 地址")


class URLRequest(BaseModel):
    """URL 请求模型"""
    url: str = Field(..., description="目标 URL 地址")


class DomainRequest(BaseModel):
    """域名请求模型"""
    domain: str = Field(..., description="目标域名")


class PortScanRequest(BaseModel):
    """端口扫描请求模型"""
    ip: str = Field(..., description="目标 IP 地址")
    ports: Optional[str] = Field(default="1-1000", description="端口范围,如 '1-1000' 或 '80,443,8080'")


class SubdomainRequest(BaseModel):
    """子域名扫描请求模型"""
    domain: str = Field(..., description="目标域名")
    deep_scan: Optional[bool] = Field(default=False, description="是否启用深度扫描")


class CrawlerRequest(BaseModel):
    """爬虫请求模型"""
    url: str = Field(..., description="目标 URL 地址")
    max_depth: Optional[int] = Field(default=3, description="最大爬取深度")
    max_pages: Optional[int] = Field(default=100, description="最大爬取页面数")


class VulnScanRequest(BaseModel):
    """漏洞扫描请求模型"""
    url: str = Field(..., description="目标 URL 地址")
    timeout: Optional[int] = Field(default=10, description="请求超时时间(秒)")
    max_payloads: Optional[int] = Field(default=50, description="最大 payload 数量")


class POCScanRequest(BaseModel):
    """POC 扫描请求模型"""
    url: str = Field(..., description="目标 URL 地址")
    timeout: Optional[int] = Field(default=10, description="请求超时时间(秒)")


class WeakPassRequest(BaseModel):
    """弱口令检测请求模型"""
    url: str = Field(..., description="目标 URL 地址")
    username: Optional[str] = Field(default="admin", description="用户名")
    password_list: Optional[List[str]] = Field(default=None, description="密码列表")


class FileUploadScanRequest(BaseModel):
    """文件上传漏洞扫描请求模型"""
    url: str = Field(..., description="目标 URL 地址")
    allowed_extensions: Optional[List[str]] = Field(default=None, description="允许的文件扩展名")


class CSRFScanRequest(BaseModel):
    """CSRF 漏洞扫描请求模型"""
    url: str = Field(..., description="目标 URL 地址")
    check_forms: Optional[bool] = Field(default=True, description="是否检查表单")


class SSRFScanRequest(BaseModel):
    """SSRF 漏洞扫描请求模型"""
    url: str = Field(..., description="目标 URL 地址")
    callback_url: Optional[str] = Field(default=None, description="回调 URL")


class LFIScanRequest(BaseModel):
    """LFI 漏洞扫描请求模型"""
    url: str = Field(..., description="目标 URL 地址")
    parameters: Optional[List[str]] = Field(default=None, description="要测试的参数列表")


class XSSScanRequest(BaseModel):
    """XSS 漏洞扫描请求模型"""
    url: str = Field(..., description="目标 URL 地址")
    scan_type: Optional[str] = Field(default="reflected", description="扫描类型: reflected/stored/dom")


class CMDIScanRequest(BaseModel):
    """命令注入漏洞扫描请求模型"""
    url: str = Field(..., description="目标 URL 地址")
    parameters: Optional[List[str]] = Field(default=None, description="要测试的参数列表")





# ====== 端口扫描 ======
@router.post("/port-scan", response_model=APIResponse)
async def port_scan(request: PortScanRequest):
    """
    端口扫描 (异步)
    """
    try:
        logger.info(f"[端口扫描] 开始处理请求 | IP: {request.ip} | 端口范围: {request.ports}")
        
        if not validate_ip(request.ip):
            logger.warning(f"[端口扫描] IP验证失败 | IP: {request.ip}")
            raise HTTPException(status_code=400, detail="请填写正确的IP地址")
        
        logger.info(f"[端口扫描] 创建任务 | 目标: {request.ip}")
        new_task = await create_scan_task(
            task_name=f"Port Scan: {request.ip}",
            task_type='scan_port',
            target=request.ip,
            config={'ports': request.ports}
        )
        logger.info(f"[端口扫描] 任务创建成功 | 任务ID: {new_task.id}")
        
        await start_task_execution(
            task_id=new_task.id,
            target=request.ip,
            scan_config={'ports': request.ports}
        )
        logger.info(f"[端口扫描] 任务已启动执行 | 任务ID: {new_task.id}")
        
        return APIResponse(code=200, message="端口扫描任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(f"[端口扫描] 任务执行失败 | IP: {request.ip} | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ====== 信息泄露检测 ======
@router.post("/info-leak", response_model=APIResponse)
async def info_leak(request: URLRequest):
    """
    信息泄露检测 (异步)
    """
    try:
        logger.info(f"[信息泄露检测] 开始处理请求 | URL: {request.url}")
        
        url = validate_url(request.url)
        if not url:
            logger.warning(f"[信息泄露检测] URL验证失败 | URL: {request.url}")
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        logger.info(f"[信息泄露检测] 创建任务 | 目标: {url}")
        new_task = await create_scan_task(
            task_name=f"Info Leak: {url}",
            task_type='scan_infoleak',
            target=url
        )
        logger.info(f"[信息泄露检测] 任务创建成功 | 任务ID: {new_task.id}")
        
        await start_task_execution(
            task_id=new_task.id,
            target=url
        )
        logger.info(f"[信息泄露检测] 任务已启动执行 | 任务ID: {new_task.id}")
        
        return APIResponse(code=200, message="信息泄露检测任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(f"[信息泄露检测] 任务执行失败 | URL: {request.url} | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ====== 旁站扫描 ======
@router.post("/web-side", response_model=APIResponse)
async def web_side_scan(request: IPRequest):
    """
    获取旁站信息 (异步)
    """
    try:
        logger.info(f"[旁站扫描] 开始处理请求 | IP: {request.ip}")
        
        if not validate_ip(request.ip):
            logger.warning(f"[旁站扫描] IP验证失败 | IP: {request.ip}")
            raise HTTPException(status_code=400, detail="请填写正确的IP地址")
        
        logger.info(f"[旁站扫描] 创建任务 | 目标: {request.ip}")
        new_task = await create_scan_task(
            task_name=f"Web Side: {request.ip}",
            task_type='scan_webside',
            target=request.ip
        )
        logger.info(f"[旁站扫描] 任务创建成功 | 任务ID: {new_task.id}")
        
        await start_task_execution(
            task_id=new_task.id,
            target=request.ip
        )
        logger.info(f"[旁站扫描] 任务已启动执行 | 任务ID: {new_task.id}")
        
        return APIResponse(code=200, message="旁站扫描任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(f"[旁站扫描] 任务执行失败 | IP: {request.ip} | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ====== 网站基本信息 ======
@router.post("/baseinfo", response_model=APIResponse)
async def get_base_info(request: URLRequest):
    """
    获取网站基本信息 (异步)
    """
    try:
        logger.info(f"[网站基本信息] 开始处理请求 | URL: {request.url}")
        
        url = validate_url(request.url)
        if not url:
            logger.warning(f"[网站基本信息] URL验证失败 | URL: {request.url}")
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        logger.info(f"[网站基本信息] 创建任务 | 目标: {url}")
        new_task = await create_scan_task(
            task_name=f"Base Info: {url}",
            task_type='scan_baseinfo',
            target=url
        )
        logger.info(f"[网站基本信息] 任务创建成功 | 任务ID: {new_task.id}")
        
        await start_task_execution(
            task_id=new_task.id,
            target=url
        )
        logger.info(f"[网站基本信息] 任务已启动执行 | 任务ID: {new_task.id}")
        
        return APIResponse(code=200, message="网站基本信息获取任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(f"[网站基本信息] 任务执行失败 | URL: {request.url} | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ====== 网站权重 ======
@router.post("/web-weight", response_model=APIResponse)
async def get_web_weight(request: URLRequest):
    """
    获取网站权重 (异步)
    """
    try:
        url = validate_url(request.url)
        if not url:
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        new_task = await create_scan_task(
            task_name=f"Web Weight: {url}",
            task_type='scan_webweight',
            target=url
        )
        
        await start_task_execution(
            task_id=new_task.id,
            target=url
        )
        
        return APIResponse(code=200, message="网站权重获取任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(handle_task_error(e, "获取网站权重启动"))
        raise HTTPException(status_code=500, detail=str(e))


# ====== IP定位 ======
@router.post("/ip-locating", response_model=APIResponse)
async def ip_locating(request: IPRequest):
    """
    IP定位 (异步)
    """
    try:
        if not validate_ip(request.ip):
            raise HTTPException(status_code=400, detail="请填写正确的IP地址")
        
        new_task = await create_scan_task(
            task_name=f"IP Locating: {request.ip}",
            task_type='scan_iplocating',
            target=request.ip
        )
        
        await start_task_execution(
            task_id=new_task.id,
            target=request.ip
        )
        
        return APIResponse(code=200, message="IP定位任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(handle_task_error(e, "IP定位启动"))
        raise HTTPException(status_code=500, detail=str(e))


# ====== CDN检测 ======
@router.post("/cdn-check", response_model=APIResponse)
async def cdn_check(request: URLRequest):
    """
    CDN检测 (异步)
    """
    try:
        url = validate_url(request.url)
        if not url:
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        new_task = await create_scan_task(
            task_name=f"CDN Check: {url}",
            task_type='scan_cdn',
            target=url
        )
        
        await start_task_execution(
            task_id=new_task.id,
            target=url
        )
        
        return APIResponse(code=200, message="CDN检测任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(handle_task_error(e, "CDN检测启动"))
        raise HTTPException(status_code=500, detail=str(e))


# ====== WAF检测 ======
@router.post("/waf-check", response_model=APIResponse)
async def waf_check(request: URLRequest):
    """
    WAF检测 (异步)
    """
    try:
        url = validate_url(request.url)
        if not url:
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        new_task = await create_scan_task(
            task_name=f"WAF Check: {url}",
            task_type='scan_waf',
            target=url
        )
        
        await start_task_execution(
            task_id=new_task.id,
            target=url
        )
        
        return APIResponse(code=200, message="WAF检测任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(handle_task_error(e, "WAF检测启动"))
        raise HTTPException(status_code=500, detail=str(e))


# ====== CMS指纹识别 ======
@router.post("/what-cms", response_model=APIResponse)
async def what_cms(request: URLRequest):
    """
    CMS指纹识别 (异步)
    """
    try:
        url = validate_url(request.url)
        if not url:
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        new_task = await create_scan_task(
            task_name=f"CMS Detect: {url}",
            task_type='scan_cms',
            target=url
        )
        
        await start_task_execution(
            task_id=new_task.id,
            target=url
        )
        
        return APIResponse(code=200, message="CMS指纹识别任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(handle_task_error(e, "CMS指纹识别启动"))
        raise HTTPException(status_code=500, detail=str(e))


# ====== 子域名扫描 ======
@router.post("/subdomain", response_model=APIResponse)
async def subdomain_scan(request: SubdomainRequest):
    """
    子域名扫描 (异步)
    """
    try:
        logger.info(f"[子域名扫描] 开始处理请求 | 域名: {request.domain} | 深度扫描: {request.deep_scan}")
        
        if not request.domain:
            logger.warning(f"[子域名扫描] 域名验证失败 | 域名为空")
            raise HTTPException(status_code=400, detail="请填写正确的域名")
        
        logger.info(f"[子域名扫描] 创建任务 | 目标: {request.domain}")
        new_task = await create_scan_task(
            task_name=f"Subdomain: {request.domain}",
            task_type='scan_subdomain',
            target=request.domain,
            config={'deep_scan': request.deep_scan}
        )
        logger.info(f"[子域名扫描] 任务创建成功 | 任务ID: {new_task.id}")
        
        await start_task_execution(
            task_id=new_task.id,
            target=request.domain,
            scan_config={'deep_scan': request.deep_scan}
        )
        logger.info(f"[子域名扫描] 任务已启动执行 | 任务ID: {new_task.id}")
        
        return APIResponse(code=200, message="子域名扫描任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(f"[子域名扫描] 任务执行失败 | 域名: {request.domain} | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ====== 目录扫描 ======
@router.post("/dir-scan", response_model=APIResponse)
async def dir_scan(request: URLRequest):
    """
    目录扫描 (异步)
    """
    try:
        url = validate_url(request.url)
        if not url:
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        new_task = await create_scan_task(
            task_name=f"Dir Scan: {url}",
            task_type='scan_dir',
            target=url
        )
        
        await start_task_execution(
            task_id=new_task.id,
            target=url
        )
        
        return APIResponse(code=200, message="目录扫描任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(handle_task_error(e, "目录扫描启动"))
        raise HTTPException(status_code=500, detail=str(e))


# ====== 综合扫描 ======
@router.post("/comprehensive", response_model=APIResponse)
async def comprehensive_scan(request: URLRequest):
    """
    综合扫描 (异步)
    
    执行多种扫描任务的组合,包括端口扫描、信息泄露检测、漏洞扫描等。
    
    Args:
        request: URLRequest 对象,包含目标 URL
    
    Returns:
        APIResponse: 包含任务 ID 的响应
    
    Raises:
        HTTPException: 当 URL 验证失败或任务创建失败时
    """
    try:
        url = validate_url(request.url)
        if not url:
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        new_task = await create_scan_task(
            task_name=f"Comprehensive: {url}",
            task_type='scan_comprehensive',
            target=url
        )
        
        await start_task_execution(
            task_id=new_task.id,
            target=url
        )
        
        return APIResponse(code=200, message="综合扫描任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(handle_task_error(e, "综合扫描启动"))
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 补充 Plugins API 接口 ====================

# ====== 爬虫扫描 ======
@router.post("/crawler", response_model=APIResponse)
async def crawler_scan(request: CrawlerRequest):
    """
    网站爬虫扫描 (异步)
    
    从目标 URL 开始爬取,自动跟踪链接构建站点地图。
    支持深度限制、范围限制和登录态爬取。
    
    Args:
        request: CrawlerRequest 对象,包含:
            - url: 目标 URL 地址
            - max_depth: 最大爬取深度 (默认 3)
            - max_pages: 最大爬取页面数 (默认 100)
    
    Returns:
        APIResponse: 包含任务 ID 的响应
    
    Raises:
        HTTPException: 当 URL 验证失败或任务创建失败时
    """
    try:
        logger.info(f"[爬虫扫描] 开始处理请求 | URL: {request.url}")
        
        url = validate_url(request.url)
        if not url:
            logger.warning(f"[爬虫扫描] URL验证失败 | URL: {request.url}")
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        logger.info(f"[爬虫扫描] 创建任务 | 目标: {url}")
        new_task = await create_scan_task(
            task_name=f"Crawler: {url}",
            task_type='scan_crawler',
            target=url,
            config={
                'max_depth': request.max_depth,
                'max_pages': request.max_pages
            }
        )
        logger.info(f"[爬虫扫描] 任务创建成功 | 任务ID: {new_task.id}")
        
        await start_task_execution(
            task_id=new_task.id,
            target=url,
            scan_config={
                'max_depth': request.max_depth,
                'max_pages': request.max_pages
            }
        )
        logger.info(f"[爬虫扫描] 任务已启动执行 | 任务ID: {new_task.id}")
        
        return APIResponse(code=200, message="爬虫扫描任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(f"[爬虫扫描] 任务执行失败 | URL: {request.url} | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ====== 随机请求头生成 ======
@router.post("/random-headers", response_model=APIResponse)
async def generate_random_headers(request: URLRequest):
    """
    生成随机请求头 (异步)
    
    生成随机的 User-Agent、X-Forwarded-For、X-Real-IP 等请求头,
    用于绕过简单的安全检测。
    
    Args:
        request: URLRequest 对象 (url 参数在此仅用于任务记录)
    
    Returns:
        APIResponse: 包含任务 ID 的响应
    
    Raises:
        HTTPException: 当任务创建失败时
    """
    try:
        logger.info(f"[随机请求头] 开始处理请求")
        
        new_task = await create_scan_task(
            task_name=f"Random Headers",
            task_type='generate_headers',
            target=request.url or 'N/A'
        )
        
        await start_task_execution(
            task_id=new_task.id,
            target=request.url or 'N/A'
        )
        
        return APIResponse(code=200, message="随机请求头生成任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(f"[随机请求头] 任务执行失败 | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ====== 日志信息 ======
@router.post("/log-info", response_model=APIResponse)
async def log_info(request: URLRequest):
    """
    获取日志信息 (异步)
    
    获取指定任务的日志信息,用于调试和监控。
    
    Args:
        request: URLRequest 对象
    
    Returns:
        APIResponse: 包含任务 ID 的响应
    
    Raises:
        HTTPException: 当任务创建失败时
    """
    try:
        logger.info(f"[日志信息] 开始处理请求 | URL: {request.url}")
        
        new_task = await create_scan_task(
            task_name=f"Log Info: {request.url}",
            task_type='get_loginfo',
            target=request.url
        )
        
        await start_task_execution(
            task_id=new_task.id,
            target=request.url
        )
        
        return APIResponse(code=200, message="日志信息获取任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(f"[日志信息] 任务执行失败 | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ====== 通用工具 ======
@router.post("/common/check-ip", response_model=APIResponse)
async def common_check_ip(request: IPRequest):
    """
    IP 地址合法性校验 (同步)
    
    校验 IP 地址格式是否正确,并检查是否为禁止扫描的 IP 段。
    
    Args:
        request: IPRequest 对象,包含目标 IP 地址
    
    Returns:
        APIResponse: 包含校验结果的响应
    
    Raises:
        HTTPException: 当 IP 验证失败时
    """
    try:
        logger.info(f"[IP校验] 开始处理请求 | IP: {request.ip}")
        
        is_valid = validate_ip(request.ip)
        
        return APIResponse(
            code=200,
            message="IP校验完成",
            data={
                "ip": request.ip,
                "is_valid": is_valid,
                "message": "IP地址合法" if is_valid else "IP地址非法或在禁止扫描范围内"
            }
        )
    except Exception as e:
        logger.error(f"[IP校验] 处理失败 | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/common/check-url", response_model=APIResponse)
async def common_check_url(request: URLRequest):
    """
    URL 地址合法性校验 (同步)
    
    校验 URL 格式是否正确,并检查是否为禁止扫描的域名。
    
    Args:
        request: URLRequest 对象,包含目标 URL 地址
    
    Returns:
        APIResponse: 包含校验结果的响应
    
    Raises:
        HTTPException: 当 URL 验证失败时
    """
    try:
        logger.info(f"[URL校验] 开始处理请求 | URL: {request.url}")
        
        valid_url = validate_url(request.url)
        
        return APIResponse(
            code=200,
            message="URL校验完成",
            data={
                "url": request.url,
                "valid_url": valid_url,
                "is_valid": bool(valid_url),
                "message": "URL地址合法" if valid_url else "URL地址非法或在禁止扫描范围内"
            }
        )
    except Exception as e:
        logger.error(f"[URL校验] 处理失败 | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/common/check-domain", response_model=APIResponse)
async def common_check_domain(request: DomainRequest):
    """
    域名合法性校验 (同步)
    
    校验域名格式是否正确。
    
    Args:
        request: DomainRequest 对象,包含目标域名
    
    Returns:
        APIResponse: 包含校验结果的响应
    
    Raises:
        HTTPException: 当域名验证失败时
    """
    try:
        logger.info(f"[域名校验] 开始处理请求 | 域名: {request.domain}")
        
        is_valid = validate_domain(request.domain)
        
        return APIResponse(
            code=200,
            message="域名校验完成",
            data={
                "domain": request.domain,
                "is_valid": is_valid,
                "message": "域名格式正确" if is_valid else "域名格式错误"
            }
        )
    except Exception as e:
        logger.error(f"[域名校验] 处理失败 | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 漏洞扫描插件 API 接口 ====================

# ====== SQL 注入扫描 ======
@router.post("/vuln/sqli", response_model=APIResponse)
async def sqli_scan(request: VulnScanRequest):
    """
    SQL 注入漏洞扫描 (异步)
    
    检测目标 URL 是否存在 SQL 注入漏洞,支持:
    - 错误回显注入检测
    - 时间盲注检测
    - 布尔盲注检测
    - Union 注入检测
    
    Args:
        request: VulnScanRequest 对象,包含:
            - url: 目标 URL 地址
            - timeout: 请求超时时间(秒)
            - max_payloads: 最大 payload 数量
    
    Returns:
        APIResponse: 包含任务 ID 的响应
    
    Raises:
        HTTPException: 当 URL 验证失败或任务创建失败时
    """
    try:
        logger.info(f"[SQL注入扫描] 开始处理请求 | URL: {request.url}")
        
        url = validate_url(request.url)
        if not url:
            logger.warning(f"[SQL注入扫描] URL验证失败 | URL: {request.url}")
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        logger.info(f"[SQL注入扫描] 创建任务 | 目标: {url}")
        new_task = await create_scan_task(
            task_name=f"SQLi Scan: {url}",
            task_type='vuln_sqli',
            target=url,
            config={
                'timeout': request.timeout,
                'max_payloads': request.max_payloads
            }
        )
        logger.info(f"[SQL注入扫描] 任务创建成功 | 任务ID: {new_task.id}")
        
        await start_task_execution(
            task_id=new_task.id,
            target=url,
            scan_config={
                'timeout': request.timeout,
                'max_payloads': request.max_payloads
            }
        )
        logger.info(f"[SQL注入扫描] 任务已启动执行 | 任务ID: {new_task.id}")
        
        return APIResponse(code=200, message="SQL注入扫描任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(f"[SQL注入扫描] 任务执行失败 | URL: {request.url} | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ====== XSS 扫描 ======
@router.post("/vuln/xss", response_model=APIResponse)
async def xss_scan(request: XSSScanRequest):
    """
    XSS 跨站脚本漏洞扫描 (异步)
    
    检测目标 URL 是否存在 XSS 漏洞,支持:
    - 反射型 XSS
    - 存储型 XSS
    - DOM 型 XSS
    
    Args:
        request: XSSScanRequest 对象,包含:
            - url: 目标 URL 地址
            - scan_type: 扫描类型 (reflected/stored/dom)
    
    Returns:
        APIResponse: 包含任务 ID 的响应
    
    Raises:
        HTTPException: 当 URL 验证失败或任务创建失败时
    """
    try:
        logger.info(f"[XSS扫描] 开始处理请求 | URL: {request.url} | 类型: {request.scan_type}")
        
        url = validate_url(request.url)
        if not url:
            logger.warning(f"[XSS扫描] URL验证失败 | URL: {request.url}")
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        logger.info(f"[XSS扫描] 创建任务 | 目标: {url}")
        new_task = await create_scan_task(
            task_name=f"XSS Scan: {url}",
            task_type='vuln_xss',
            target=url,
            config={
                'scan_type': request.scan_type
            }
        )
        logger.info(f"[XSS扫描] 任务创建成功 | 任务ID: {new_task.id}")
        
        await start_task_execution(
            task_id=new_task.id,
            target=url,
            scan_config={
                'scan_type': request.scan_type
            }
        )
        logger.info(f"[XSS扫描] 任务已启动执行 | 任务ID: {new_task.id}")
        
        return APIResponse(code=200, message="XSS扫描任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(f"[XSS扫描] 任务执行失败 | URL: {request.url} | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ====== CSRF 扫描 ======
@router.post("/vuln/csrf", response_model=APIResponse)
async def csrf_scan(request: CSRFScanRequest):
    """
    CSRF 跨站请求伪造漏洞扫描 (异步)
    
    检测目标 URL 的表单是否存在 CSRF 漏洞。
    
    Args:
        request: CSRFScanRequest 对象,包含:
            - url: 目标 URL 地址
            - check_forms: 是否检查表单
    
    Returns:
        APIResponse: 包含任务 ID 的响应
    
    Raises:
        HTTPException: 当 URL 验证失败或任务创建失败时
    """
    try:
        logger.info(f"[CSRF扫描] 开始处理请求 | URL: {request.url}")
        
        url = validate_url(request.url)
        if not url:
            logger.warning(f"[CSRF扫描] URL验证失败 | URL: {request.url}")
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        logger.info(f"[CSRF扫描] 创建任务 | 目标: {url}")
        new_task = await create_scan_task(
            task_name=f"CSRF Scan: {url}",
            task_type='vuln_csrf',
            target=url,
            config={
                'check_forms': request.check_forms
            }
        )
        logger.info(f"[CSRF扫描] 任务创建成功 | 任务ID: {new_task.id}")
        
        await start_task_execution(
            task_id=new_task.id,
            target=url,
            scan_config={
                'check_forms': request.check_forms
            }
        )
        logger.info(f"[CSRF扫描] 任务已启动执行 | 任务ID: {new_task.id}")
        
        return APIResponse(code=200, message="CSRF扫描任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(f"[CSRF扫描] 任务执行失败 | URL: {request.url} | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ====== SSRF 扫描 ======
@router.post("/vuln/ssrf", response_model=APIResponse)
async def ssrf_scan(request: SSRFScanRequest):
    """
    SSRF 服务端请求伪造漏洞扫描 (异步)
    
    检测目标 URL 是否存在 SSRF 漏洞。
    
    Args:
        request: SSRFScanRequest 对象,包含:
            - url: 目标 URL 地址
            - callback_url: 回调 URL
    
    Returns:
        APIResponse: 包含任务 ID 的响应
    
    Raises:
        HTTPException: 当 URL 验证失败或任务创建失败时
    """
    try:
        logger.info(f"[SSRF扫描] 开始处理请求 | URL: {request.url}")
        
        url = validate_url(request.url)
        if not url:
            logger.warning(f"[SSRF扫描] URL验证失败 | URL: {request.url}")
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        logger.info(f"[SSRF扫描] 创建任务 | 目标: {url}")
        new_task = await create_scan_task(
            task_name=f"SSRF Scan: {url}",
            task_type='vuln_ssrf',
            target=url,
            config={
                'callback_url': request.callback_url
            }
        )
        logger.info(f"[SSRF扫描] 任务创建成功 | 任务ID: {new_task.id}")
        
        await start_task_execution(
            task_id=new_task.id,
            target=url,
            scan_config={
                'callback_url': request.callback_url
            }
        )
        logger.info(f"[SSRF扫描] 任务已启动执行 | 任务ID: {new_task.id}")
        
        return APIResponse(code=200, message="SSRF扫描任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(f"[SSRF扫描] 任务执行失败 | URL: {request.url} | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ====== LFI 扫描 ======
@router.post("/vuln/lfi", response_model=APIResponse)
async def lfi_scan(request: LFIScanRequest):
    """
    LFI 本地文件包含漏洞扫描 (异步)
    
    检测目标 URL 是否存在本地文件包含漏洞。
    
    Args:
        request: LFIScanRequest 对象,包含:
            - url: 目标 URL 地址
            - parameters: 要测试的参数列表
    
    Returns:
        APIResponse: 包含任务 ID 的响应
    
    Raises:
        HTTPException: 当 URL 验证失败或任务创建失败时
    """
    try:
        logger.info(f"[LFI扫描] 开始处理请求 | URL: {request.url}")
        
        url = validate_url(request.url)
        if not url:
            logger.warning(f"[LFI扫描] URL验证失败 | URL: {request.url}")
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        logger.info(f"[LFI扫描] 创建任务 | 目标: {url}")
        new_task = await create_scan_task(
            task_name=f"LFI Scan: {url}",
            task_type='vuln_lfi',
            target=url,
            config={
                'parameters': request.parameters
            }
        )
        logger.info(f"[LFI扫描] 任务创建成功 | 任务ID: {new_task.id}")
        
        await start_task_execution(
            task_id=new_task.id,
            target=url,
            scan_config={
                'parameters': request.parameters
            }
        )
        logger.info(f"[LFI扫描] 任务已启动执行 | 任务ID: {new_task.id}")
        
        return APIResponse(code=200, message="LFI扫描任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(f"[LFI扫描] 任务执行失败 | URL: {request.url} | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ====== 命令注入扫描 ======
@router.post("/vuln/cmdi", response_model=APIResponse)
async def cmdi_scan(request: CMDIScanRequest):
    """
    命令注入漏洞扫描 (异步)
    
    检测目标 URL 是否存在命令注入漏洞。
    
    Args:
        request: CMDIScanRequest 对象,包含:
            - url: 目标 URL 地址
            - parameters: 要测试的参数列表
    
    Returns:
        APIResponse: 包含任务 ID 的响应
    
    Raises:
        HTTPException: 当 URL 验证失败或任务创建失败时
    """
    try:
        logger.info(f"[命令注入扫描] 开始处理请求 | URL: {request.url}")
        
        url = validate_url(request.url)
        if not url:
            logger.warning(f"[命令注入扫描] URL验证失败 | URL: {request.url}")
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        logger.info(f"[命令注入扫描] 创建任务 | 目标: {url}")
        new_task = await create_scan_task(
            task_name=f"CMDI Scan: {url}",
            task_type='vuln_cmdi',
            target=url,
            config={
                'parameters': request.parameters
            }
        )
        logger.info(f"[命令注入扫描] 任务创建成功 | 任务ID: {new_task.id}")
        
        await start_task_execution(
            task_id=new_task.id,
            target=url,
            scan_config={
                'parameters': request.parameters
            }
        )
        logger.info(f"[命令注入扫描] 任务已启动执行 | 任务ID: {new_task.id}")
        
        return APIResponse(code=200, message="命令注入扫描任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(f"[命令注入扫描] 任务执行失败 | URL: {request.url} | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ====== 文件上传漏洞扫描 ======
@router.post("/vuln/fileupload", response_model=APIResponse)
async def fileupload_scan(request: FileUploadScanRequest):
    """
    文件上传漏洞扫描 (异步)
    
    检测目标 URL 是否存在文件上传漏洞。
    
    Args:
        request: FileUploadScanRequest 对象,包含:
            - url: 目标 URL 地址
            - allowed_extensions: 允许的文件扩展名
    
    Returns:
        APIResponse: 包含任务 ID 的响应
    
    Raises:
        HTTPException: 当 URL 验证失败或任务创建失败时
    """
    try:
        logger.info(f"[文件上传扫描] 开始处理请求 | URL: {request.url}")
        
        url = validate_url(request.url)
        if not url:
            logger.warning(f"[文件上传扫描] URL验证失败 | URL: {request.url}")
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        logger.info(f"[文件上传扫描] 创建任务 | 目标: {url}")
        new_task = await create_scan_task(
            task_name=f"FileUpload Scan: {url}",
            task_type='vuln_fileupload',
            target=url,
            config={
                'allowed_extensions': request.allowed_extensions
            }
        )
        logger.info(f"[文件上传扫描] 任务创建成功 | 任务ID: {new_task.id}")
        
        await start_task_execution(
            task_id=new_task.id,
            target=url,
            scan_config={
                'allowed_extensions': request.allowed_extensions
            }
        )
        logger.info(f"[文件上传扫描] 任务已启动执行 | 任务ID: {new_task.id}")
        
        return APIResponse(code=200, message="文件上传扫描任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(f"[文件上传扫描] 任务执行失败 | URL: {request.url} | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ====== 弱口令检测 ======
@router.post("/vuln/weakpass", response_model=APIResponse)
async def weakpass_scan(request: WeakPassRequest):
    """
    弱口令检测 (异步)
    
    检测目标 URL 是否存在弱口令漏洞。
    
    Args:
        request: WeakPassRequest 对象,包含:
            - url: 目标 URL 地址
            - username: 用户名
            - password_list: 密码列表
    
    Returns:
        APIResponse: 包含任务 ID 的响应
    
    Raises:
        HTTPException: 当 URL 验证失败或任务创建失败时
    """
    try:
        logger.info(f"[弱口令检测] 开始处理请求 | URL: {request.url}")
        
        url = validate_url(request.url)
        if not url:
            logger.warning(f"[弱口令检测] URL验证失败 | URL: {request.url}")
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        logger.info(f"[弱口令检测] 创建任务 | 目标: {url}")
        new_task = await create_scan_task(
            task_name=f"WeakPass Scan: {url}",
            task_type='vuln_weakpass',
            target=url,
            config={
                'username': request.username,
                'password_list': request.password_list
            }
        )
        logger.info(f"[弱口令检测] 任务创建成功 | 任务ID: {new_task.id}")
        
        await start_task_execution(
            task_id=new_task.id,
            target=url,
            scan_config={
                'username': request.username,
                'password_list': request.password_list
            }
        )
        logger.info(f"[弱口令检测] 任务已启动执行 | 任务ID: {new_task.id}")
        
        return APIResponse(code=200, message="弱口令检测任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(f"[弱口令检测] 任务执行失败 | URL: {request.url} | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ====== 信息泄露扫描 (漏洞扫描插件) ======
@router.post("/vuln/infoleak", response_model=APIResponse)
async def vuln_infoleak_scan(request: VulnScanRequest):
    """
    信息泄露漏洞扫描 (异步)
    
    检测目标 URL 是否存在敏感信息泄露漏洞。
    
    Args:
        request: VulnScanRequest 对象,包含:
            - url: 目标 URL 地址
            - timeout: 请求超时时间(秒)
    
    Returns:
        APIResponse: 包含任务 ID 的响应
    
    Raises:
        HTTPException: 当 URL 验证失败或任务创建失败时
    """
    try:
        logger.info(f"[信息泄露扫描] 开始处理请求 | URL: {request.url}")
        
        url = validate_url(request.url)
        if not url:
            logger.warning(f"[信息泄露扫描] URL验证失败 | URL: {request.url}")
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        logger.info(f"[信息泄露扫描] 创建任务 | 目标: {url}")
        new_task = await create_scan_task(
            task_name=f"InfoLeak Vuln Scan: {url}",
            task_type='vuln_infoleak',
            target=url,
            config={
                'timeout': request.timeout
            }
        )
        logger.info(f"[信息泄露扫描] 任务创建成功 | 任务ID: {new_task.id}")
        
        await start_task_execution(
            task_id=new_task.id,
            target=url,
            scan_config={
                'timeout': request.timeout
            }
        )
        logger.info(f"[信息泄露扫描] 任务已启动执行 | 任务ID: {new_task.id}")
        
        return APIResponse(code=200, message="信息泄露扫描任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(f"[信息泄露扫描] 任务执行失败 | URL: {request.url} | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== POC 扫描 API 接口 ====================

# ====== WebLogic POC ======
@router.post("/poc/weblogic/cve-2020-2551", response_model=APIResponse)
async def weblogic_cve_2020_2551(request: POCScanRequest):
    """
    WebLogic CVE-2020-2551 POC 检测 (异步)
    
    检测目标是否存在 WebLogic CVE-2020-2551 漏洞。
    WebLogic Server 的 T3/IIOP 协议存在反序列化漏洞。
    
    影响版本:
    - Oracle WebLogic Server 10.3.6.0.0
    - Oracle WebLogic Server 12.1.3.0.0
    - Oracle WebLogic Server 12.2.1.3.0
    - Oracle WebLogic Server 12.2.1.4.0
    - Oracle WebLogic Server 14.1.1.0.0
    
    Args:
        request: POCScanRequest 对象,包含:
            - url: 目标 URL 地址
            - timeout: 请求超时时间(秒)
    
    Returns:
        APIResponse: 包含任务 ID 的响应
    
    Raises:
        HTTPException: 当 URL 验证失败或任务创建失败时
    """
    try:
        logger.info(f"[WebLogic CVE-2020-2551] 开始处理请求 | URL: {request.url}")
        
        url = validate_url(request.url)
        if not url:
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        new_task = await create_scan_task(
            task_name=f"WebLogic CVE-2020-2551: {url}",
            task_type='poc_weblogic_2020_2551',
            target=url,
            config={'timeout': request.timeout}
        )
        
        await start_task_execution(
            task_id=new_task.id,
            target=url,
            scan_config={'timeout': request.timeout}
        )
        
        return APIResponse(code=200, message="WebLogic CVE-2020-2551 检测任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(f"[WebLogic CVE-2020-2551] 任务执行失败 | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/poc/weblogic/cve-2018-2628", response_model=APIResponse)
async def weblogic_cve_2018_2628(request: POCScanRequest):
    """
    WebLogic CVE-2018-2628 POC 检测 (异步)
    
    检测目标是否存在 WebLogic CVE-2018-2628 漏洞。
    WebLogic Server T3 协议反序列化远程代码执行漏洞。
    
    Args:
        request: POCScanRequest 对象
    
    Returns:
        APIResponse: 包含任务 ID 的响应
    """
    try:
        logger.info(f"[WebLogic CVE-2018-2628] 开始处理请求 | URL: {request.url}")
        
        url = validate_url(request.url)
        if not url:
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        new_task = await create_scan_task(
            task_name=f"WebLogic CVE-2018-2628: {url}",
            task_type='poc_weblogic_2018_2628',
            target=url,
            config={'timeout': request.timeout}
        )
        
        await start_task_execution(
            task_id=new_task.id,
            target=url,
            scan_config={'timeout': request.timeout}
        )
        
        return APIResponse(code=200, message="WebLogic CVE-2018-2628 检测任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(f"[WebLogic CVE-2018-2628] 任务执行失败 | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/poc/weblogic/cve-2018-2894", response_model=APIResponse)
async def weblogic_cve_2018_2894(request: POCScanRequest):
    """
    WebLogic CVE-2018-2894 POC 检测 (异步)
    
    检测目标是否存在 WebLogic CVE-2018-2894 漏洞。
    WebLogic 管理控制台未授权访问漏洞。
    
    Args:
        request: POCScanRequest 对象
    
    Returns:
        APIResponse: 包含任务 ID 的响应
    """
    try:
        url = validate_url(request.url)
        if not url:
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        new_task = await create_scan_task(
            task_name=f"WebLogic CVE-2018-2894: {url}",
            task_type='poc_weblogic_2018_2894',
            target=url,
            config={'timeout': request.timeout}
        )
        
        await start_task_execution(
            task_id=new_task.id,
            target=url,
            scan_config={'timeout': request.timeout}
        )
        
        return APIResponse(code=200, message="WebLogic CVE-2018-2894 检测任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(f"[WebLogic CVE-2018-2894] 任务执行失败 | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/poc/weblogic/cve-2020-14756", response_model=APIResponse)
async def weblogic_cve_2020_14756(request: POCScanRequest):
    """
    WebLogic CVE-2020-14756 POC 检测 (异步)
    
    检测目标是否存在 WebLogic CVE-2020-14756 漏洞。
    
    Args:
        request: POCScanRequest 对象
    
    Returns:
        APIResponse: 包含任务 ID 的响应
    """
    try:
        url = validate_url(request.url)
        if not url:
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        new_task = await create_scan_task(
            task_name=f"WebLogic CVE-2020-14756: {url}",
            task_type='poc_weblogic_2020_14756',
            target=url,
            config={'timeout': request.timeout}
        )
        
        await start_task_execution(
            task_id=new_task.id,
            target=url,
            scan_config={'timeout': request.timeout}
        )
        
        return APIResponse(code=200, message="WebLogic CVE-2020-14756 检测任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(f"[WebLogic CVE-2020-14756] 任务执行失败 | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/poc/weblogic/cve-2023-21839", response_model=APIResponse)
async def weblogic_cve_2023_21839(request: POCScanRequest):
    """
    WebLogic CVE-2023-21839 POC 检测 (异步)
    
    检测目标是否存在 WebLogic CVE-2023-21839 漏洞。
    WebLogic Server 远程代码执行漏洞。
    
    Args:
        request: POCScanRequest 对象
    
    Returns:
        APIResponse: 包含任务 ID 的响应
    """
    try:
        url = validate_url(request.url)
        if not url:
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        new_task = await create_scan_task(
            task_name=f"WebLogic CVE-2023-21839: {url}",
            task_type='poc_weblogic_2023_21839',
            target=url,
            config={'timeout': request.timeout}
        )
        
        await start_task_execution(
            task_id=new_task.id,
            target=url,
            scan_config={'timeout': request.timeout}
        )
        
        return APIResponse(code=200, message="WebLogic CVE-2023-21839 检测任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(f"[WebLogic CVE-2023-21839] 任务执行失败 | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ====== Struts2 POC ======
@router.post("/poc/struts2/s2-009", response_model=APIResponse)
async def struts2_s2_009(request: POCScanRequest):
    """
    Struts2 S2-009 POC 检测 (异步)
    
    检测目标是否存在 Struts2 S2-009 漏洞。
    Apache Struts2 的 REST 插件存在远程代码执行漏洞。
    
    影响版本:
    - Struts 2.1.0 - Struts 2.3.4.1
    
    Args:
        request: POCScanRequest 对象
    
    Returns:
        APIResponse: 包含任务 ID 的响应
    """
    try:
        logger.info(f"[Struts2 S2-009] 开始处理请求 | URL: {request.url}")
        
        url = validate_url(request.url)
        if not url:
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        new_task = await create_scan_task(
            task_name=f"Struts2 S2-009: {url}",
            task_type='poc_struts2_009',
            target=url,
            config={'timeout': request.timeout}
        )
        
        await start_task_execution(
            task_id=new_task.id,
            target=url,
            scan_config={'timeout': request.timeout}
        )
        
        return APIResponse(code=200, message="Struts2 S2-009 检测任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(f"[Struts2 S2-009] 任务执行失败 | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/poc/struts2/s2-032", response_model=APIResponse)
async def struts2_s2_032(request: POCScanRequest):
    """
    Struts2 S2-032 POC 检测 (异步)
    
    检测目标是否存在 Struts2 S2-032 漏洞。
    Struts2 动态方法调用远程代码执行漏洞。
    
    影响版本:
    - Struts 2.3.20 - Struts 2.3.28
    
    Args:
        request: POCScanRequest 对象
    
    Returns:
        APIResponse: 包含任务 ID 的响应
    """
    try:
        url = validate_url(request.url)
        if not url:
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        new_task = await create_scan_task(
            task_name=f"Struts2 S2-032: {url}",
            task_type='poc_struts2_032',
            target=url,
            config={'timeout': request.timeout}
        )
        
        await start_task_execution(
            task_id=new_task.id,
            target=url,
            scan_config={'timeout': request.timeout}
        )
        
        return APIResponse(code=200, message="Struts2 S2-032 检测任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(f"[Struts2 S2-032] 任务执行失败 | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ====== Tomcat POC ======
@router.post("/poc/tomcat/cve-2017-12615", response_model=APIResponse)
async def tomcat_cve_2017_12615(request: POCScanRequest):
    """
    Tomcat CVE-2017-12615 POC 检测 (异步)
    
    检测目标是否存在 Tomcat CVE-2017-12615 漏洞。
    Apache Tomcat 在 Windows 系统下存在 PUT 方法任意文件写入漏洞。
    
    影响版本:
    - Apache Tomcat 7.0.0 - 7.0.79
    - Apache Tomcat 8.0.0 - 8.0.43
    - Apache Tomcat 8.5.0 - 8.5.23
    - Apache Tomcat 9.0.0.M1 - 9.0.1
    
    Args:
        request: POCScanRequest 对象
    
    Returns:
        APIResponse: 包含任务 ID 的响应
    """
    try:
        logger.info(f"[Tomcat CVE-2017-12615] 开始处理请求 | URL: {request.url}")
        
        url = validate_url(request.url)
        if not url:
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        new_task = await create_scan_task(
            task_name=f"Tomcat CVE-2017-12615: {url}",
            task_type='poc_tomcat_2017_12615',
            target=url,
            config={'timeout': request.timeout}
        )
        
        await start_task_execution(
            task_id=new_task.id,
            target=url,
            scan_config={'timeout': request.timeout}
        )
        
        return APIResponse(code=200, message="Tomcat CVE-2017-12615 检测任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(f"[Tomcat CVE-2017-12615] 任务执行失败 | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/poc/tomcat/cve-2022-22965", response_model=APIResponse)
async def tomcat_cve_2022_22965(request: POCScanRequest):
    """
    Tomcat CVE-2022-22965 (Spring4Shell) POC 检测 (异步)
    
    检测目标是否存在 Spring4Shell 漏洞。
    Spring Framework 远程代码执行漏洞。
    
    Args:
        request: POCScanRequest 对象
    
    Returns:
        APIResponse: 包含任务 ID 的响应
    """
    try:
        url = validate_url(request.url)
        if not url:
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        new_task = await create_scan_task(
            task_name=f"Tomcat CVE-2022-22965: {url}",
            task_type='poc_tomcat_2022_22965',
            target=url,
            config={'timeout': request.timeout}
        )
        
        await start_task_execution(
            task_id=new_task.id,
            target=url,
            scan_config={'timeout': request.timeout}
        )
        
        return APIResponse(code=200, message="Tomcat CVE-2022-22965 检测任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(f"[Tomcat CVE-2022-22965] 任务执行失败 | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/poc/tomcat/cve-2022-47986", response_model=APIResponse)
async def tomcat_cve_2022_47986(request: POCScanRequest):
    """
    Tomcat CVE-2022-47986 POC 检测 (异步)
    
    检测目标是否存在 CVE-2022-47986 漏洞。
    
    Args:
        request: POCScanRequest 对象
    
    Returns:
        APIResponse: 包含任务 ID 的响应
    """
    try:
        url = validate_url(request.url)
        if not url:
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        new_task = await create_scan_task(
            task_name=f"Tomcat CVE-2022-47986: {url}",
            task_type='poc_tomcat_2022_47986',
            target=url,
            config={'timeout': request.timeout}
        )
        
        await start_task_execution(
            task_id=new_task.id,
            target=url,
            scan_config={'timeout': request.timeout}
        )
        
        return APIResponse(code=200, message="Tomcat CVE-2022-47986 检测任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(f"[Tomcat CVE-2022-47986] 任务执行失败 | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ====== JBoss POC ======
@router.post("/poc/jboss/cve-2017-12149", response_model=APIResponse)
async def jboss_cve_2017_12149(request: POCScanRequest):
    """
    JBoss CVE-2017-12149 POC 检测 (异步)
    
    检测目标是否存在 JBoss CVE-2017-12149 漏洞。
    JBoss AS 5.x/6.x 反序列化漏洞。
    
    影响版本:
    - JBoss AS 5.x
    - JBoss AS 6.x
    
    Args:
        request: POCScanRequest 对象
    
    Returns:
        APIResponse: 包含任务 ID 的响应
    """
    try:
        logger.info(f"[JBoss CVE-2017-12149] 开始处理请求 | URL: {request.url}")
        
        url = validate_url(request.url)
        if not url:
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        new_task = await create_scan_task(
            task_name=f"JBoss CVE-2017-12149: {url}",
            task_type='poc_jboss_2017_12149',
            target=url,
            config={'timeout': request.timeout}
        )
        
        await start_task_execution(
            task_id=new_task.id,
            target=url,
            scan_config={'timeout': request.timeout}
        )
        
        return APIResponse(code=200, message="JBoss CVE-2017-12149 检测任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(f"[JBoss CVE-2017-12149] 任务执行失败 | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ====== Nexus POC ======
@router.post("/poc/nexus/cve-2020-10199", response_model=APIResponse)
async def nexus_cve_2020_10199(request: POCScanRequest):
    """
    Nexus CVE-2020-10199 POC 检测 (异步)
    
    检测目标是否存在 Nexus Repository Manager CVE-2020-10199 漏洞。
    Nexus Repository Manager 远程代码执行漏洞。
    
    影响版本:
    - Nexus Repository Manager OSS/Pro 3.x < 3.21.2
    
    Args:
        request: POCScanRequest 对象
    
    Returns:
        APIResponse: 包含任务 ID 的响应
    """
    try:
        logger.info(f"[Nexus CVE-2020-10199] 开始处理请求 | URL: {request.url}")
        
        url = validate_url(request.url)
        if not url:
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        new_task = await create_scan_task(
            task_name=f"Nexus CVE-2020-10199: {url}",
            task_type='poc_nexus_2020_10199',
            target=url,
            config={'timeout': request.timeout}
        )
        
        await start_task_execution(
            task_id=new_task.id,
            target=url,
            scan_config={'timeout': request.timeout}
        )
        
        return APIResponse(code=200, message="Nexus CVE-2020-10199 检测任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(f"[Nexus CVE-2020-10199] 任务执行失败 | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ====== Drupal POC ======
@router.post("/poc/drupal/cve-2018-7600", response_model=APIResponse)
async def drupal_cve_2018_7600(request: POCScanRequest):
    """
    Drupal CVE-2018-7600 (Drupalgeddon2) POC 检测 (异步)
    
    检测目标是否存在 Drupal CVE-2018-7600 漏洞。
    Drupal 远程代码执行漏洞。
    
    影响版本:
    - Drupal 6.x < 6.38
    - Drupal 7.x < 7.58
    - Drupal 8.x < 8.5.1
    
    Args:
        request: POCScanRequest 对象
    
    Returns:
        APIResponse: 包含任务 ID 的响应
    """
    try:
        logger.info(f"[Drupal CVE-2018-7600] 开始处理请求 | URL: {request.url}")
        
        url = validate_url(request.url)
        if not url:
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        new_task = await create_scan_task(
            task_name=f"Drupal CVE-2018-7600: {url}",
            task_type='poc_drupal_2018_7600',
            target=url,
            config={'timeout': request.timeout}
        )
        
        await start_task_execution(
            task_id=new_task.id,
            target=url,
            scan_config={'timeout': request.timeout}
        )
        
        return APIResponse(code=200, message="Drupal CVE-2018-7600 检测任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(f"[Drupal CVE-2018-7600] 任务执行失败 | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ====== ThinkPHP POC ======
@router.post("/poc/thinkphp/rce", response_model=APIResponse)
async def thinkphp_rce(request: POCScanRequest):
    """
    ThinkPHP 远程代码执行 POC 检测 (异步)
    
    检测目标是否存在 ThinkPHP 远程代码执行漏洞。
    ThinkPHP 5.x 远程代码执行漏洞。
    
    影响版本:
    - ThinkPHP 5.0.x < 5.0.23
    - ThinkPHP 5.1.x < 5.1.31
    
    Args:
        request: POCScanRequest 对象
    
    Returns:
        APIResponse: 包含任务 ID 的响应
    """
    try:
        logger.info(f"[ThinkPHP RCE] 开始处理请求 | URL: {request.url}")
        
        url = validate_url(request.url)
        if not url:
            raise HTTPException(status_code=400, detail="请填写正确的URL地址")
        
        new_task = await create_scan_task(
            task_name=f"ThinkPHP RCE: {url}",
            task_type='poc_thinkphp_rce',
            target=url,
            config={'timeout': request.timeout}
        )
        
        await start_task_execution(
            task_id=new_task.id,
            target=url,
            scan_config={'timeout': request.timeout}
        )
        
        return APIResponse(code=200, message="ThinkPHP RCE 检测任务已启动", data={"task_id": new_task.id})
    except Exception as e:
        logger.error(f"[ThinkPHP RCE] 任务执行失败 | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 批量扫描 API 接口 ====================

class BatchScanRequest(BaseModel):
    """批量扫描请求模型"""
    urls: List[str] = Field(..., description="目标 URL 列表")
    scan_types: List[str] = Field(..., description="扫描类型列表")


@router.post("/batch", response_model=APIResponse)
async def batch_scan(request: BatchScanRequest):
    """
    批量扫描 (异步)
    
    对多个目标 URL 执行多种类型的扫描任务。
    
    Args:
        request: BatchScanRequest 对象,包含:
            - urls: 目标 URL 列表
            - scan_types: 扫描类型列表
    
    Returns:
        APIResponse: 包含任务 ID 列表的响应
    
    Raises:
        HTTPException: 当参数验证失败或任务创建失败时
    """
    try:
        logger.info(f"[批量扫描] 开始处理请求 | URL数量: {len(request.urls)} | 扫描类型: {request.scan_types}")
        
        if not request.urls:
            raise HTTPException(status_code=400, detail="目标URL列表不能为空")
        
        if not request.scan_types:
            raise HTTPException(status_code=400, detail="扫描类型列表不能为空")
        
        task_ids = []
        
        for url in request.urls:
            valid_url = validate_url(url)
            if not valid_url:
                logger.warning(f"[批量扫描] URL验证失败,跳过 | URL: {url}")
                continue
            
            for scan_type in request.scan_types:
                new_task = await create_scan_task(
                    task_name=f"Batch {scan_type}: {valid_url}",
                    task_type=f'batch_{scan_type}',
                    target=valid_url
                )
                
                await start_task_execution(
                    task_id=new_task.id,
                    target=valid_url
                )
                
                task_ids.append(new_task.id)
        
        return APIResponse(
            code=200,
            message=f"批量扫描任务已启动,共创建 {len(task_ids)} 个任务",
            data={"task_ids": task_ids, "total": len(task_ids)}
        )
    except Exception as e:
        logger.error(f"[批量扫描] 任务执行失败 | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== API 接口列表 ====================

@router.get("/list", response_model=APIResponse)
async def list_scan_apis():
    """
    获取所有可用的扫描 API 接口列表
    
    Returns:
        APIResponse: 包含所有 API 接口信息的响应
    """
    apis = {
        "plugins": {
            "port_scan": "/api/scan/port-scan",
            "info_leak": "/api/scan/info-leak",
            "web_side": "/api/scan/web-side",
            "baseinfo": "/api/scan/baseinfo",
            "web_weight": "/api/scan/web-weight",
            "ip_locating": "/api/scan/ip-locating",
            "cdn_check": "/api/scan/cdn-check",
            "waf_check": "/api/scan/waf-check",
            "what_cms": "/api/scan/what-cms",
            "subdomain": "/api/scan/subdomain",
            "dir_scan": "/api/scan/dir-scan",
            "crawler": "/api/scan/crawler",
            "random_headers": "/api/scan/random-headers",
            "log_info": "/api/scan/log-info",
            "comprehensive": "/api/scan/comprehensive"
        },
        "common": {
            "check_ip": "/api/scan/common/check-ip",
            "check_url": "/api/scan/common/check-url",
            "check_domain": "/api/scan/common/check-domain"
        },
        "vulnerability_scan": {
            "sqli": "/api/scan/vuln/sqli",
            "xss": "/api/scan/vuln/xss",
            "csrf": "/api/scan/vuln/csrf",
            "ssrf": "/api/scan/vuln/ssrf",
            "lfi": "/api/scan/vuln/lfi",
            "cmdi": "/api/scan/vuln/cmdi",
            "fileupload": "/api/scan/vuln/fileupload",
            "weakpass": "/api/scan/vuln/weakpass",
            "infoleak": "/api/scan/vuln/infoleak"
        },
        "poc": {
            "weblogic": {
                "cve_2020_2551": "/api/scan/poc/weblogic/cve-2020-2551",
                "cve_2018_2628": "/api/scan/poc/weblogic/cve-2018-2628",
                "cve_2018_2894": "/api/scan/poc/weblogic/cve-2018-2894",
                "cve_2020_14756": "/api/scan/poc/weblogic/cve-2020-14756",
                "cve_2023_21839": "/api/scan/poc/weblogic/cve-2023-21839"
            },
            "struts2": {
                "s2_009": "/api/scan/poc/struts2/s2-009",
                "s2_032": "/api/scan/poc/struts2/s2-032"
            },
            "tomcat": {
                "cve_2017_12615": "/api/scan/poc/tomcat/cve-2017-12615",
                "cve_2022_22965": "/api/scan/poc/tomcat/cve-2022-22965",
                "cve_2022_47986": "/api/scan/poc/tomcat/cve-2022-47986"
            },
            "jboss": {
                "cve_2017_12149": "/api/scan/poc/jboss/cve-2017-12149"
            },
            "nexus": {
                "cve_2020_10199": "/api/scan/poc/nexus/cve-2020-10199"
            },
            "drupal": {
                "cve_2018_7600": "/api/scan/poc/drupal/cve-2018-7600"
            },
            "thinkphp": {
                "rce": "/api/scan/poc/thinkphp/rce"
            }
        },
        "batch": {
            "batch_scan": "/api/scan/batch"
        }
    }
    
    return APIResponse(
        code=200,
        message="获取API接口列表成功",
        data=apis
    )
