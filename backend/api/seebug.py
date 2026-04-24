"""
Seebug API 路由模块

提供统一的 Seebug API 接口，包括：
- API 状态检查
- 漏洞搜索
- POC 搜索和下载
- 漏洞详情获取
- 缓存和统计信息管理

API 端点:
    GET  /status              - 获取 Seebug API 状态
    POST /search              - 搜索漏洞
    GET  /test-connection     - 测试 API 连接
    GET  /poc/search          - 搜索 POC
    GET  /poc/{ssvid}         - 获取 POC 详情
    GET  /poc/{ssvid}/download - 下载 POC 代码
    GET  /vulnerability/{ssvid} - 获取漏洞详情
    GET  /crawl               - 爬取最新漏洞
    GET  /statistics          - 获取统计信息
    POST /cache/clear         - 清除缓存
    GET  /cache/stats         - 获取缓存统计

响应格式:
    所有接口返回统一格式:
    {
        "code": 200,           # 状态码
        "data": {...},         # 响应数据
        "message": "操作成功"   # 响应消息
    }
"""
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
import logging
import asyncio

from backend.utils.seebug_utils import seebug_utils

router = APIRouter()
logger = logging.getLogger(__name__)


class SearchRequest(BaseModel):
    """搜索请求模型"""
    keyword: str = Field(..., description="搜索关键词")
    page: int = Field(1, ge=1, description="页码")
    page_size: int = Field(10, ge=1, le=100, description="每页数量")


class StandardResponse(BaseModel):
    """标准响应格式"""
    code: int
    data: Optional[Any] = None
    message: str


def create_response(code: int = 200, data: Any = None, message: str = "操作成功") -> Dict[str, Any]:
    """
    创建统一格式的响应
    
    Args:
        code: 状态码
        data: 响应数据
        message: 响应消息
        
    Returns:
        统一格式的响应字典
    """
    return {
        "code": code,
        "data": data,
        "message": message
    }


@router.get("/status", response_model=StandardResponse, summary="获取 Seebug API 状态")
async def get_status():
    """
    获取 Seebug API 状态
    
    检查 Seebug Agent 是否可用，并验证 API Key 是否有效。
    
    请求示例:
        GET /api/seebug/status
    
    响应示例:
        {
            "code": 200,
            "data": {
                "available": true,
                "message": "API Key 有效"
            },
            "message": "获取状态成功"
        }
    
    响应字段:
        - available (bool): Seebug API 是否可用
        - message (str): 状态说明信息
    
    状态码:
        - 200: 成功获取状态
        - 500: 获取状态失败
    """
    try:
        if not seebug_utils.is_available():
            return create_response(
                code=200,
                data={
                    "available": False,
                    "message": "Seebug Agent 模块不可用，请检查依赖和配置"
                },
                message="获取状态成功"
            )
        
        loop = asyncio.get_event_loop()
        status = await loop.run_in_executor(
            None,
            seebug_utils.validate_api_key
        )
        
        available = status.get("status") == "success"
        message = status.get("msg", "")
        
        return create_response(
            code=200,
            data={
                "available": available,
                "message": message
            },
            message="获取状态成功"
        )
    except Exception as e:
        logger.error(f"获取 Seebug Agent 状态失败: {e}")
        return create_response(
            code=500,
            data={
                "available": False,
                "message": f"获取状态失败: {str(e)}"
            },
            message="获取状态失败"
        )


@router.post("/search", response_model=StandardResponse, summary="搜索漏洞")
async def search_vulnerabilities(request: SearchRequest):
    """
    搜索 Seebug 漏洞
    
    根据关键词搜索漏洞信息，支持分页查询。
    
    请求参数:
        - keyword (str, 必填): 搜索关键词
        - page (int, 可选): 页码，默认为 1
        - page_size (int, 可选): 每页数量，默认为 10，范围 1-100
    
    请求示例:
        POST /api/seebug/search
        {
            "keyword": "Apache",
            "page": 1,
            "page_size": 20
        }
    
    响应示例:
        {
            "code": 200,
            "data": {
                "results": [
                    {
                        "ssvid": "SSVID-12345",
                        "name": "Apache 远程代码执行漏洞",
                        "severity": "高危",
                        "cve_id": "CVE-2024-xxxx"
                    }
                ],
                "total": 100
            },
            "message": "搜索成功"
        }
    
    状态码:
        - 200: 搜索成功
        - 500: 搜索失败
        - 503: Seebug Agent 模块不可用
    """
    try:
        if not seebug_utils.is_available():
            raise HTTPException(
                status_code=503,
                detail="Seebug Agent 模块不可用"
            )
        
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            seebug_utils.search_vulnerabilities,
            request.keyword,
            request.page,
            request.page_size
        )
        
        return create_response(
            code=200,
            data=result,
            message="搜索成功"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"搜索漏洞失败: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"搜索失败: {str(e)}"
        )


@router.get("/test-connection", response_model=StandardResponse, summary="测试 API 连接")
async def test_connection():
    """
    测试 Seebug API 连接
    
    验证 API Key 是否有效，测试与 Seebug 服务的连接状态。
    
    请求示例:
        GET /api/seebug/test-connection
    
    响应示例:
        {
            "code": 200,
            "data": {
                "success": true,
                "message": "API Key 验证成功",
                "data": {...}
            },
            "message": "测试连接完成"
        }
    
    响应字段:
        - success (bool): 连接是否成功
        - message (str): 连接状态说明
        - data (dict): 详细验证数据
    
    状态码:
        - 200: 测试完成
        - 500: 测试连接失败
    """
    try:
        if not seebug_utils.is_available():
            return create_response(
                code=200,
                data={
                    "success": False,
                    "message": "Seebug Agent 模块不可用"
                },
                message="测试连接完成"
            )
        
        loop = asyncio.get_event_loop()
        status = await loop.run_in_executor(
            None,
            seebug_utils.validate_api_key
        )
        
        return create_response(
            code=200,
            data={
                "success": status.get("status") == "success",
                "message": status.get("msg", ""),
                "data": status
            },
            message="测试连接完成"
        )
    except Exception as e:
        logger.error(f"测试 Seebug 连接失败: {e}")
        return create_response(
            code=500,
            data={
                "success": False,
                "message": f"测试连接失败: {str(e)}"
            },
            message="测试连接失败"
        )


@router.get("/poc/search", response_model=StandardResponse, summary="搜索 POC")
async def search_poc(
    keyword: str = Query("", description="搜索关键词"),
    page: int = Query(1, ge=1, description="页码"),
    page_size: int = Query(10, ge=1, le=100, description="每页数量")
):
    """
    搜索 POC
    
    根据关键词搜索 POC 信息，支持分页查询。
    
    查询参数:
        - keyword (str, 可选): 搜索关键词，默认为空
        - page (int, 可选): 页码，默认为 1
        - page_size (int, 可选): 每页数量，默认为 10，范围 1-100
    
    请求示例:
        GET /api/seebug/poc/search?keyword=Apache&page=1&page_size=20
    
    响应示例:
        {
            "code": 200,
            "data": {
                "results": [
                    {
                        "ssvid": 12345,
                        "name": "Apache Struts2 远程代码执行 POC",
                        "severity": "高危",
                        "poc_available": true
                    }
                ],
                "total": 50
            },
            "message": "搜索成功"
        }
    
    状态码:
        - 200: 搜索成功
        - 500: 搜索失败
    """
    try:
        result = await seebug_utils.search_poc(keyword, page, page_size)
        
        if not result.success:
            return create_response(
                code=result.status_code,
                data=None,
                message=result.message
            )
        
        return create_response(
            code=200,
            data=result.data,
            message=result.message or "搜索成功"
        )
    except Exception as e:
        logger.error(f"搜索 POC 失败: {e}")
        return create_response(
            code=500,
            data=None,
            message=f"搜索失败: {str(e)}"
        )


@router.get("/poc/{ssvid}", response_model=StandardResponse, summary="获取 POC 详情")
async def get_poc_detail(ssvid: int):
    """
    获取 POC 详情
    
    根据 SSVID 获取 POC 的详细信息，包括漏洞描述、影响版本等。
    
    路径参数:
        - ssvid (int, 必填): 漏洞 SSVID 编号
    
    请求示例:
        GET /api/seebug/poc/12345
    
    响应示例:
        {
            "code": 200,
            "data": {
                "ssvid": 12345,
                "name": "Apache Struts2 远程代码执行漏洞",
                "severity": "高危",
                "description": "漏洞详细描述...",
                "affected_versions": ["2.0.0 - 2.3.31"],
                "cve_id": "CVE-2017-5638",
                "poc_available": true
            },
            "message": "获取成功"
        }
    
    状态码:
        - 200: 获取成功
        - 404: POC 不存在
        - 500: 获取失败
    """
    try:
        result = await seebug_utils.get_poc_detail(ssvid)
        
        if not result.success:
            return create_response(
                code=result.status_code,
                data=None,
                message=result.message
            )
        
        return create_response(
            code=200,
            data=result.data,
            message=result.message or "获取成功"
        )
    except Exception as e:
        logger.error(f"获取 POC 详情失败: {e}")
        return create_response(
            code=500,
            data=None,
            message=f"获取失败: {str(e)}"
        )


@router.get("/poc/{ssvid}/download", response_model=StandardResponse, summary="下载 POC 代码")
async def download_poc(ssvid: int):
    """
    下载 POC 代码
    
    根据 SSVID 下载 POC 的利用代码，需要有效的 API Key 权限。
    
    路径参数:
        - ssvid (int, 必填): 漏洞 SSVID 编号
    
    请求示例:
        GET /api/seebug/poc/12345/download
    
    响应示例:
        {
            "code": 200,
            "data": {
                "ssvid": 12345,
                "poc_code": "#!/usr/bin/env python3\n...",
                "language": "python",
                "file_name": "poc_12345.py"
            },
            "message": "下载成功"
        }
    
    响应字段:
        - poc_code (str): POC 代码内容
        - language (str): 代码语言
        - file_name (str): 建议的文件名
    
    状态码:
        - 200: 下载成功
        - 403: 无权限下载
        - 404: POC 不存在
        - 500: 下载失败
    """
    try:
        result = await seebug_utils.download_poc(ssvid)
        
        if not result.success:
            return create_response(
                code=result.status_code,
                data=None,
                message=result.message
            )
        
        return create_response(
            code=200,
            data=result.data,
            message=result.message or "下载成功"
        )
    except Exception as e:
        logger.error(f"下载 POC 失败: {e}")
        return create_response(
            code=500,
            data=None,
            message=f"下载失败: {str(e)}"
        )


@router.get("/vulnerability/{ssvid}", response_model=StandardResponse, summary="获取漏洞详情")
async def get_vulnerability_detail(ssvid: str):
    """
    获取漏洞详情
    
    根据 SSVID 获取漏洞的详细信息，包括漏洞描述、修复建议等。
    
    路径参数:
        - ssvid (str, 必填): 漏洞 SSVID 编号
    
    请求示例:
        GET /api/seebug/vulnerability/SSVID-12345
    
    响应示例:
        {
            "code": 200,
            "data": {
                "ssvid": "SSVID-12345",
                "name": "Apache 远程代码执行漏洞",
                "severity": "高危",
                "cvss_score": 9.8,
                "cve_id": "CVE-2024-xxxx",
                "description": "漏洞详细描述...",
                "solution": "升级到最新版本...",
                "references": ["https://..."]
            },
            "message": "获取成功"
        }
    
    状态码:
        - 200: 获取成功
        - 404: 漏洞不存在
        - 500: 获取失败
        - 503: Seebug Agent 模块不可用
    """
    try:
        if not seebug_utils.is_available():
            return create_response(
                code=503,
                data=None,
                message="Seebug Agent 模块不可用"
            )
        
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            seebug_utils.get_vulnerability_detail,
            ssvid
        )
        
        if result.get("status") != "success":
            return create_response(
                code=404,
                data=None,
                message=result.get("msg", "获取漏洞详情失败")
            )
        
        return create_response(
            code=200,
            data=result.get("data"),
            message="获取成功"
        )
    except Exception as e:
        logger.error(f"获取漏洞详情失败: {e}")
        return create_response(
            code=500,
            data=None,
            message=f"获取失败: {str(e)}"
        )


@router.get("/crawl", response_model=StandardResponse, summary="爬取最新漏洞")
async def crawl_vulnerabilities(
    limit: int = Query(20, ge=1, le=100, description="爬取数量限制")
):
    """
    爬取最新漏洞
    
    从 Seebug 爬取最新的漏洞信息，用于更新本地漏洞库。
    
    查询参数:
        - limit (int, 可选): 爬取数量限制，默认为 20，范围 1-100
    
    请求示例:
        GET /api/seebug/crawl?limit=50
    
    响应示例:
        {
            "code": 200,
            "data": {
                "vulnerabilities": [
                    {
                        "ssvid": "SSVID-12345",
                        "name": "新漏洞名称",
                        "severity": "高危",
                        "publish_date": "2024-01-01"
                    }
                ],
                "count": 50
            },
            "message": "爬取成功"
        }
    
    状态码:
        - 200: 爬取成功
        - 500: 爬取失败
    """
    try:
        result = await seebug_utils.crawl_recent_vulnerabilities(limit)
        
        if not result.success:
            return create_response(
                code=result.status_code,
                data=None,
                message=result.message
            )
        
        return create_response(
            code=200,
            data=result.data,
            message=result.message or "爬取成功"
        )
    except Exception as e:
        logger.error(f"爬取漏洞失败: {e}")
        return create_response(
            code=500,
            data=None,
            message=f"爬取失败: {str(e)}"
        )


@router.get("/statistics", response_model=StandardResponse, summary="获取统计信息")
async def get_statistics():
    """
    获取统计信息
    
    获取 Seebug API 的使用统计信息，包括缓存状态、请求计数等。
    
    请求示例:
        GET /api/seebug/statistics
    
    响应示例:
        {
            "code": 200,
            "data": {
                "total_requests": 1000,
                "successful_requests": 980,
                "failed_requests": 20,
                "cache_hits": 500,
                "cache_misses": 500,
                "last_request_time": "2024-01-01T12:00:00Z"
            },
            "message": "获取统计信息成功"
        }
    
    状态码:
        - 200: 获取成功
        - 500: 获取失败
    """
    try:
        stats = seebug_utils.get_statistics()
        return create_response(
            code=200,
            data=stats,
            message="获取统计信息成功"
        )
    except Exception as e:
        logger.error(f"获取统计信息失败: {e}")
        return create_response(
            code=500,
            data=None,
            message=f"获取失败: {str(e)}"
        )


@router.post("/cache/clear", response_model=StandardResponse, summary="清除缓存")
async def clear_cache():
    """
    清除缓存
    
    清除 Seebug API 的所有缓存数据，用于刷新数据或解决缓存问题。
    
    请求示例:
        POST /api/seebug/cache/clear
    
    响应示例:
        {
            "code": 200,
            "data": null,
            "message": "缓存已清除"
        }
    
    状态码:
        - 200: 清除成功
        - 500: 清除失败
    """
    try:
        seebug_utils.clear_cache()
        return create_response(
            code=200,
            data=None,
            message="缓存已清除"
        )
    except Exception as e:
        logger.error(f"清除缓存失败: {e}")
        return create_response(
            code=500,
            data=None,
            message=f"清除失败: {str(e)}"
        )


@router.get("/cache/stats", response_model=StandardResponse, summary="获取缓存统计")
async def get_cache_stats():
    """
    获取缓存统计
    
    获取 Seebug API 的缓存统计信息，包括缓存大小、命中率等。
    
    请求示例:
        GET /api/seebug/cache/stats
    
    响应示例:
        {
            "code": 200,
            "data": {
                "cache_size": 100,
                "hit_rate": 0.85,
                "miss_rate": 0.15,
                "total_hits": 850,
                "total_misses": 150,
                "cached_items": ["ssvid_12345", "ssvid_67890"]
            },
            "message": "获取缓存统计成功"
        }
    
    状态码:
        - 200: 获取成功
        - 500: 获取失败
    """
    try:
        stats = seebug_utils.get_cache_stats()
        return create_response(
            code=200,
            data=stats,
            message="获取缓存统计成功"
        )
    except Exception as e:
        logger.error(f"获取缓存统计失败: {e}")
        return create_response(
            code=500,
            data=None,
            message=f"获取失败: {str(e)}"
        )
