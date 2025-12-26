"""
POC 漏洞扫描 API 路由
提供中间件和框架的 CVE 漏洞检测接口
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, HttpUrl
from typing import List, Optional, Dict
import asyncio
from datetime import datetime

from poc import (
    cve_2020_2551_poc, cve_2018_2628_poc, cve_2018_2894_poc,
    struts2_009_poc, struts2_032_poc, cve_2017_12615_poc,
    cve_2017_12149_poc, cve_2020_10199_poc, cve_2018_7600_poc
)

router = APIRouter(prefix="/poc", tags=["POC扫描"])


# 请求/响应模型
class POCScanRequest(BaseModel):
    target: str
    poc_types: Optional[List[str]] = None
    timeout: int = 10


class POCScanResult(BaseModel):
    poc_type: str
    target: str
    vulnerable: bool
    message: str
    timestamp: str


class POCScanResponse(BaseModel):
    success: bool
    results: List[POCScanResult]
    total_scanned: int
    vulnerable_count: int
    timestamp: str


# POC 映射表
POC_FUNCTIONS = {
    "weblogic_cve_2020_2551": cve_2020_2551_poc,
    "weblogic_cve_2018_2628": cve_2018_2628_poc,
    "weblogic_cve_2018_2894": cve_2018_2894_poc,
    "struts2_009": struts2_009_poc,
    "struts2_032": struts2_032_poc,
    "tomcat_cve_2017_12615": cve_2017_12615_poc,
    "jboss_cve_2017_12149": cve_2017_12149_poc,
    "nexus_cve_2020_10199": cve_2020_10199_poc,
    "drupal_cve_2018_7600": cve_2018_7600_poc,
}


@router.get("/types", response_model=List[str])
async def get_available_poc_types():
    """
    获取所有可用的 POC 类型
    """
    return list(POC_FUNCTIONS.keys())


@router.post("/scan", response_model=POCScanResponse)
async def scan_poc(request: POCScanRequest):
    """
    执行 POC 漏洞扫描
    """
    try:
        # 如果未指定 POC 类型，则扫描所有类型
        poc_types = request.poc_types if request.poc_types else list(POC_FUNCTIONS.keys())
        
        results = []
        vulnerable_count = 0
        
        for poc_type in poc_types:
            if poc_type not in POC_FUNCTIONS:
                results.append(POCScanResult(
                    poc_type=poc_type,
                    target=request.target,
                    vulnerable=False,
                    message=f"未知的 POC 类型: {poc_type}",
                    timestamp=datetime.now().isoformat()
                ))
                continue
            
            try:
                # 执行 POC 扫描
                poc_func = POC_FUNCTIONS[poc_type]
                is_vulnerable, message = await asyncio.to_thread(
                    poc_func, request.target, request.timeout
                )
                
                if is_vulnerable:
                    vulnerable_count += 1
                
                results.append(POCScanResult(
                    poc_type=poc_type,
                    target=request.target,
                    vulnerable=is_vulnerable,
                    message=message,
                    timestamp=datetime.now().isoformat()
                ))
                
            except Exception as e:
                results.append(POCScanResult(
                    poc_type=poc_type,
                    target=request.target,
                    vulnerable=False,
                    message=f"扫描失败: {str(e)}",
                    timestamp=datetime.now().isoformat()
                ))
        
        return POCScanResponse(
            success=True,
            results=results,
            total_scanned=len(results),
            vulnerable_count=vulnerable_count,
            timestamp=datetime.now().isoformat()
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"POC 扫描失败: {str(e)}")


@router.post("/scan/{poc_type}", response_model=POCScanResult)
async def scan_single_poc(poc_type: str, target: str, timeout: int = 10):
    """
    执行单个 POC 漏洞扫描
    """
    if poc_type not in POC_FUNCTIONS:
        raise HTTPException(status_code=400, detail=f"未知的 POC 类型: {poc_type}")
    
    try:
        poc_func = POC_FUNCTIONS[poc_type]
        is_vulnerable, message = await asyncio.to_thread(
            poc_func, target, timeout
        )
        
        return POCScanResult(
            poc_type=poc_type,
            target=target,
            vulnerable=is_vulnerable,
            message=message,
            timestamp=datetime.now().isoformat()
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"POC 扫描失败: {str(e)}")


@router.get("/info/{poc_type}")
async def get_poc_info(poc_type: str):
    """
    获取 POC 详细信息
    """
    poc_info = {
        "weblogic_cve_2020_2551": {
            "name": "WebLogic CVE-2020-2551",
            "description": "WebLogic Server 反序列化漏洞",
            "severity": "高危",
            "cve": "CVE-2020-2551"
        },
        "weblogic_cve_2018_2628": {
            "name": "WebLogic CVE-2018-2628",
            "description": "WebLogic Server 反序列化漏洞",
            "severity": "高危",
            "cve": "CVE-2018-2628"
        },
        "weblogic_cve_2018_2894": {
            "name": "WebLogic CVE-2018-2894",
            "description": "WebLogic Server 任意文件上传漏洞",
            "severity": "高危",
            "cve": "CVE-2018-2894"
        },
        "struts2_009": {
            "name": "Struts2 S2-009",
            "description": "Struts2 远程代码执行漏洞",
            "severity": "高危",
            "cve": "CVE-2011-3923"
        },
        "struts2_032": {
            "name": "Struts2 S2-032",
            "description": "Struts2 远程代码执行漏洞",
            "severity": "高危",
            "cve": "CVE-2016-3081"
        },
        "tomcat_cve_2017_12615": {
            "name": "Tomcat CVE-2017-12615",
            "description": "Tomcat 任意文件写入漏洞",
            "severity": "高危",
            "cve": "CVE-2017-12615"
        },
        "jboss_cve_2017_12149": {
            "name": "JBoss CVE-2017-12149",
            "description": "JBoss 反序列化漏洞",
            "severity": "高危",
            "cve": "CVE-2017-12149"
        },
        "nexus_cve_2020_10199": {
            "name": "Nexus CVE-2020-10199",
            "description": "Nexus Repository Manager 远程代码执行漏洞",
            "severity": "高危",
            "cve": "CVE-2020-10199"
        },
        "drupal_cve_2018_7600": {
            "name": "Drupal CVE-2018-7600",
            "description": "Drupal 远程代码执行漏洞",
            "severity": "高危",
            "cve": "CVE-2018-7600"
        }
    }
    
    if poc_type not in poc_info:
        raise HTTPException(status_code=404, detail=f"未知的 POC 类型: {poc_type}")
    
    return poc_info[poc_type]

