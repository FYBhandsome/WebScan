"""
POC 漏洞扫描 API 路由
提供中间件和框架的 CVE 漏洞检测接口

支持的 POC 类型:
- WebLogic: CVE-2020-2551, CVE-2018-2628, CVE-2018-2894, CVE-2020-14756, CVE-2023-21839
- Struts2: S2-009, S2-032
- Tomcat: CVE-2017-12615, CVE-2022-22965, CVE-2022-47986
- JBoss: CVE-2017-12149
- Nexus: CVE-2020-10199
- drupal: CVE-2018-7600

主要功能:
- 创建和管理 POC 扫描任务
- 执行单个或批量 POC 漏洞检测
- 获取 POC 类型和详细信息
- 扫描结果存储和查询
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator
from typing import List, Optional, Any, Dict
import asyncio
import json
import logging
from datetime import datetime

from backend.poc import (
    cve_2020_2551_poc, cve_2018_2628_poc, cve_2018_2894_poc, cve_2020_14756_poc, cve_2023_21839_poc,
    struts2_009_poc, struts2_032_poc, cve_2017_12615_poc, cve_2022_22965_poc, cve_2022_47986_poc,
    cve_2017_12149_poc, cve_2020_10199_poc, cve_2018_7600_poc
)
from backend.api.common import APIResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/poc", tags=["POC扫描"])


# 请求/响应模型
class POCScanRequest(BaseModel):
    """
    POC 扫描请求模型
    
    Attributes:
        target: 扫描目标 URL
        poc_types: POC 类型列表,如果不指定则扫描所有类型
        timeout: 超时时间(秒),默认 10 秒
    """
    target: str
    poc_types: Optional[List[str]] = None
    timeout: int = 10


class POCScanResult(BaseModel):
    """
    POC 扫描结果模型
    
    Attributes:
        poc_type: POC 类型
        target: 扫描目标
        vulnerable: 是否存在漏洞
        message: 扫描消息
        timestamp: 扫描时间戳
    """
    poc_type: str
    target: str
    vulnerable: bool
    message: str
    timestamp: str


# POC 映射表
POC_FUNCTIONS = {
    "weblogic_cve_2020_2551": cve_2020_2551_poc,
    "weblogic_cve_2018_2628": cve_2018_2628_poc,
    "weblogic_cve_2018_2894": cve_2018_2894_poc,
    "weblogic_cve_2020_14756": cve_2020_14756_poc,
    "weblogic_cve_2023_21839": cve_2023_21839_poc,
    "struts2_009": struts2_009_poc,
    "struts2_032": struts2_032_poc,
    "tomcat_cve_2017_12615": cve_2017_12615_poc,
    "tomcat_cve_2022_22965": cve_2022_22965_poc,
    "tomcat_cve_2022_47986": cve_2022_47986_poc,
    "jboss_cve_2017_12149": cve_2017_12149_poc,
    "nexus_cve_2020_10199": cve_2020_10199_poc,
    "drupal_cve_2018_7600": cve_2018_7600_poc,
}


@router.get("/types", response_model=APIResponse)
async def get_available_poc_types():
    """
    获取所有可用的 POC 类型
    
    返回系统支持的所有 POC 类型列表。
    
    Returns:
        APIResponse: POC 类型列表,包含value和label字段
        
    Examples:
        >>> 获取 POC 类型
        >>> GET /poc/types
        >>> {
        ...     "code": 200,
        ...     "message": "获取成功",
        ...     "data": [
        ...         {"value": "weblogic_cve_2020_2551", "label": "WebLogic CVE-2020-2551"},
        ...         {"value": "struts2_009", "label": "Struts2 S2-009"}
        ...     ]
        ... }
    """
    from backend.api.common import APIResponse
    
    poc_types = []
    for poc_key in POC_FUNCTIONS.keys():
        label = poc_key.replace('_', ' ').title()
        poc_types.append({
            "value": poc_key,
            "label": label
        })
    
    return APIResponse(
        code=200,
        message="获取成功",
        data=poc_types
    ).model_dump()


@router.post("/scan", response_model=APIResponse)
async def scan_poc(request: POCScanRequest):
    """
    创建 POC 扫描任务(异步执行)
    
    创建一个新的 POC 扫描任务并启动异步执行。
    支持指定多个 POC 类型,如果不指定则扫描所有类型。
    
    Args:
        request: POC 扫描请求,包含目标 URL、POC 类型和超时时间
        
    Returns:
        APIResponse: 包含任务信息的响应,结构如下:
            {
                "code": 200,
                "message": "POC 扫描任务已创建",
                "data": {
                    "task_id": 任务ID,
                    "status": "pending",
                    "target": "目标URL",
                    "poc_count": POC数量
                }
            }
        
    Raises:
        HTTPException: 创建任务失败时抛出 500 错误
        
    Examples:
        >>> 扫描指定目标的所有 POC
        >>> POST /poc/scan
        >>> {
        ...     "target": "https://www.baidu.com",
        ...     "poc_types": ["weblogic_cve_2020_2551"],
        ...     "timeout": 10
        ... }
    """
    try:
        if not request.target or not request.target.strip():
            raise HTTPException(status_code=400, detail="扫描目标不能为空")
        
        if not request.target.startswith(('http://', 'https://')):
            raise HTTPException(status_code=400, detail="扫描目标必须是有效的URL格式(以http://或https://开头)")
        
        if request.timeout < 1 or request.timeout > 300:
            raise HTTPException(status_code=400, detail="超时时间必须在1-300秒之间")
        
        if request.poc_types:
            invalid_types = [t for t in request.poc_types if t not in POC_FUNCTIONS]
            if invalid_types:
                raise HTTPException(status_code=400, detail=f"无效的POC类型: {', '.join(invalid_types)}")
        
        logger.info(f"[POC扫描] 开始处理请求 | 目标: {request.target} | POC类型: {request.poc_types}")
        
        from backend.models import Task
        from task_executor import task_executor
        
        poc_types = request.poc_types if request.poc_types else list(POC_FUNCTIONS.keys())
        task_name = f"POC Scan: {request.target}"
        if len(poc_types) == 1:
            task_name = f"POC Scan ({poc_types[0]}): {request.target}"
        
        logger.info(f"[POC扫描] 创建任务 | 目标: {request.target} | POC数量: {len(poc_types)}")
        new_task = await Task.create(
            task_name=task_name,
            task_type="poc_scan",
            target=request.target,
            status="pending",
            progress=0,
            config=json.dumps({
                "poc_types": poc_types,
                "timeout": request.timeout
            }),
            result=None
        )
        logger.info(f"[POC扫描] 任务创建成功 | 任务ID: {new_task.id}")
        
        asyncio.create_task(task_executor.start_task(
            task_id=new_task.id,
            target=request.target,
            scan_config={
                "poc_types": poc_types,
                "timeout": request.timeout
            }
        ))
        logger.info(f"[POC扫描] 任务已启动执行 | 任务ID: {new_task.id}")
        
        return APIResponse(
            code=200,
            message="POC 扫描任务已创建",
            data={
                "task_id": new_task.id,
                "status": "pending",
                "target": request.target,
                "poc_count": len(poc_types)
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[POC扫描] 任务执行失败 | 目标: {request.target} | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=f"创建任务失败: {str(e)}")



