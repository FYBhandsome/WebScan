"""
漏洞管理API接口
"""
from fastapi import APIRouter, HTTPException, Query
from typing import Optional, List
from backend.models import Vulnerability, Task
from pydantic import BaseModel
from datetime import datetime
import logging

logger = logging.getLogger("backend.api.vulnerabilities")

router = APIRouter(prefix="/vulnerabilities", tags=["漏洞管理"])


class VulnerabilityResponse(BaseModel):
    id: int
    vuln_id: Optional[str] = None
    vuln_type: Optional[str] = None
    severity: Optional[str] = None
    title: Optional[str] = None
    url: Optional[str] = None
    description: Optional[str] = None
    solution: Optional[str] = None
    task_id: Optional[int] = None
    created_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class VulnerabilityListResponse(BaseModel):
    total: int
    items: List[VulnerabilityResponse]


@router.get("/", response_model=VulnerabilityListResponse)
async def list_vulnerabilities(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: Optional[str] = None,
    vuln_type: Optional[str] = None,
    task_id: Optional[int] = None
):
    """获取漏洞列表"""
    query = Vulnerability.all()
    
    if severity:
        query = query.filter(severity=severity)
    if vuln_type:
        query = query.filter(vuln_type=vuln_type)
    if task_id:
        query = query.filter(task_id=task_id)
    
    total = await query.count()
    items = await query.order_by('-created_at').offset((page - 1) * page_size).limit(page_size)
    
    return VulnerabilityListResponse(
        total=total,
        items=[VulnerabilityResponse.model_validate(item) for item in items]
    )


@router.get("/{vuln_id}", response_model=VulnerabilityResponse)
async def get_vulnerability(vuln_id: int):
    """获取漏洞详情"""
    vuln = await Vulnerability.get_or_none(id=vuln_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    return VulnerabilityResponse.model_validate(vuln)


@router.get("/{vuln_id}/related")
async def get_related_vulnerabilities(
    vuln_id: int,
    limit: int = Query(5, ge=1, le=20)
):
    """获取相关漏洞"""
    vuln = await Vulnerability.get_or_none(id=vuln_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    
    related = await Vulnerability.filter(
        vuln_type=vuln.vuln_type
    ).exclude(id=vuln_id).order_by('-created_at').limit(limit)
    
    return {
        "total": len(related),
        "items": [VulnerabilityResponse.model_validate(v) for v in related]
    }


@router.delete("/{vuln_id}")
async def delete_vulnerability(vuln_id: int):
    """删除漏洞"""
    vuln = await Vulnerability.get_or_none(id=vuln_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    
    await vuln.delete()
    return {"message": "删除成功"}
