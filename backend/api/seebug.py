"""
Seebug API 路由模块

提供统一的 Seebug API 接口，包括：
- API 状态检查
- 漏洞搜索
- POC 详情获取

API 端点:
    GET  /status              - 获取 Seebug API 状态
    POST /search              - 搜索漏洞
    GET  /test-connection     - 测试 API 连接
    GET  /poc/{ssvid}/detail  - 获取 POC 详情

响应格式:
    所有接口返回统一格式:
    {
        "code": 200,           # 状态码
        "data": {...},         # 响应数据
        "message": "操作成功"   # 响应消息
    }
"""
from fastapi import APIRouter, HTTPException
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


def create_response(code: int = 200, data: Any = None, message: str = "操作成功") -> StandardResponse:
    """
    创建统一格式的响应
    
    Args:
        code: 状态码
        data: 响应数据
        message: 响应消息
        
    Returns:
        统一格式的响应对象
    """
    return StandardResponse(
        code=code,
        data=data,
        message=message
    )


@router.get("/status", response_model=StandardResponse, summary="获取 Seebug API 状态")
async def get_status():
    """
    获取 Seebug API 状态
    
    检查 Seebug Agent 是否可用，并验证 API Key 是否有效。
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
        
        status = await seebug_utils.validate_api_key()
        
        available = status.success
        message = status.message
        
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
    """
    try:
        if not seebug_utils.is_available():
            raise HTTPException(
                status_code=503,
                detail="Seebug Agent 模块不可用"
            )
        
        loop = asyncio.get_running_loop()
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
        
        status = await seebug_utils.validate_api_key()
        
        return create_response(
            code=200,
            data={
                "success": status.success,
                "message": status.message,
                "data": {
                    "success": status.success,
                    "message": status.message,
                    "status_code": status.status_code
                }
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


@router.get("/poc/{ssvid}/detail", response_model=StandardResponse, summary="获取 POC 详情")
async def get_poc_detail(ssvid: int):
    """
    获取 POC 详情
    
    根据 SSVID 获取 POC 的详细信息，包括漏洞描述、影响版本等。
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
