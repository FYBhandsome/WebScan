"""
TOSKill RESTful API 接口层

直接调用工具集执行扫描任务，不依赖 graph 工作流。
支持单个工具执行和批量工具执行。
"""
import logging
import asyncio
from typing import Optional, List, Dict, Any
from datetime import datetime
from uuid import uuid4
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field

from TOSKill.AI.tools import (
    TOOL_MAP, 
    get_tool_by_name, 
    get_all_tool_names,
    TOOL_SEQUENCE_INFO,
    TOOL_SEQUENCE_VULN,
    INFO_COLLECTION_TOOLS,
    VULN_SCAN_TOOLS,
    ALL_TOOLS
)
from TOSKill.AI.tools import clean_target

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/toskill", tags=["TOSKill API"])

executor = ThreadPoolExecutor(max_workers=4)

_scan_tasks: Dict[str, Dict] = {}


class ScanRequest(BaseModel):
    target: str = Field(..., description="扫描目标")
    tools: Optional[List[str]] = Field(None, description="指定工具列表，为空则使用默认工具集")
    generate_report: bool = Field(default=True, description="是否生成报告")


class ToolExecuteRequest(BaseModel):
    tool_name: str = Field(..., description="工具名称")
    target: str = Field(..., description="扫描目标")
    params: Optional[Dict[str, Any]] = Field(None, description="工具参数")


class BatchToolExecuteRequest(BaseModel):
    tool_names: List[str] = Field(..., description="工具名称列表")
    target: str = Field(..., description="扫描目标")
    parallel: bool = Field(default=True, description="是否并行执行")


class SessionRequest(BaseModel):
    target: Optional[str] = Field(default="", description="扫描目标")
    tools: Optional[List[str]] = Field(None, description="工具列表")


class APIResponse(BaseModel):
    code: int = 200
    message: str = "success"
    data: Optional[dict] = None


def _execute_single_tool(tool_name: str, target: str) -> Dict[str, Any]:
    """执行单个工具"""
    tool = get_tool_by_name(tool_name)
    if not tool:
        return {"tool": tool_name, "success": False, "error": f"工具 {tool_name} 不存在"}
    
    cleaned_target = clean_target(target)
    logger.info(f"执行工具: {tool_name} -> {cleaned_target}")
    
    try:
        result = tool.invoke(cleaned_target)
        return {
            "tool": tool_name,
            "success": True,
            "result": result,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"工具执行失败 {tool_name}: {e}")
        return {
            "tool": tool_name,
            "success": False,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }


def _execute_tools_sequential(tool_names: List[str], target: str) -> List[Dict]:
    """顺序执行多个工具"""
    results = []
    for tool_name in tool_names:
        result = _execute_single_tool(tool_name, target)
        results.append(result)
    return results


def _execute_tools_parallel(tool_names: List[str], target: str) -> List[Dict]:
    """并行执行多个工具"""
    futures = []
    for tool_name in tool_names:
        future = executor.submit(_execute_single_tool, tool_name, target)
        futures.append((tool_name, future))
    
    results = []
    for tool_name, future in futures:
        try:
            result = future.result(timeout=300)
            results.append(result)
        except Exception as e:
            results.append({
                "tool": tool_name,
                "success": False,
                "error": str(e)
            })
    return results


@router.post("/scan", response_model=APIResponse)
async def api_scan(request: ScanRequest):
    """执行扫描 - 自动选择工具集或使用指定工具"""
    target = request.target
    if not target:
        raise HTTPException(status_code=400, detail="扫描目标不能为空")
    
    if request.tools:
        tool_names = request.tools
        for t in tool_names:
            if t not in TOOL_MAP:
                raise HTTPException(status_code=400, detail=f"工具 {t} 不存在")
    else:
        tool_names = get_all_tool_names()
    
    logger.info(f"开始扫描: {target}, 工具数量: {len(tool_names)}")
    
    results = _execute_tools_parallel(tool_names, target)
    
    success_count = sum(1 for r in results if r.get("success"))
    error_count = len(results) - success_count
    
    return APIResponse(
        message=f"扫描完成: {success_count}/{len(results)} 工具执行成功",
        data={
            "target": target,
            "total_tools": len(results),
            "success_count": success_count,
            "error_count": error_count,
            "results": results,
            "timestamp": datetime.now().isoformat()
        }
    )


@router.post("/scan/info", response_model=APIResponse)
async def api_info_collection(request: ScanRequest):
    """信息收集扫描 - 执行信息收集工具集"""
    target = request.target
    if not target:
        raise HTTPException(status_code=400, detail="扫描目标不能为空")
    
    tool_names = request.tools if request.tools else TOOL_SEQUENCE_INFO
    
    for t in tool_names:
        if t not in TOOL_MAP:
            raise HTTPException(status_code=400, detail=f"工具 {t} 不存在")
    
    logger.info(f"开始信息收集: {target}")
    
    results = _execute_tools_parallel(tool_names, target)
    
    success_count = sum(1 for r in results if r.get("success"))
    
    return APIResponse(
        message=f"信息收集完成: {success_count}/{len(results)}",
        data={
            "target": target,
            "scan_type": "info_collection",
            "tools_used": tool_names,
            "results": results,
            "timestamp": datetime.now().isoformat()
        }
    )


@router.post("/scan/vuln", response_model=APIResponse)
async def api_vuln_scan(request: ScanRequest):
    """漏洞扫描 - 执行漏洞扫描工具集"""
    target = request.target
    if not target:
        raise HTTPException(status_code=400, detail="扫描目标不能为空")
    
    tool_names = request.tools if request.tools else TOOL_SEQUENCE_VULN
    
    for t in tool_names:
        if t not in TOOL_MAP:
            raise HTTPException(status_code=400, detail=f"工具 {t} 不存在")
    
    logger.info(f"开始漏洞扫描: {target}")
    
    results = _execute_tools_parallel(tool_names, target)
    
    success_count = sum(1 for r in results if r.get("success"))
    vuln_found = sum(1 for r in results if r.get("success") and r.get("result", {}).get("vulnerable"))
    
    return APIResponse(
        message=f"漏洞扫描完成: {success_count}/{len(results)}, 发现漏洞: {vuln_found}",
        data={
            "target": target,
            "scan_type": "vuln_scan",
            "tools_used": tool_names,
            "vulnerabilities_found": vuln_found,
            "results": results,
            "timestamp": datetime.now().isoformat()
        }
    )


@router.post("/scan/full", response_model=APIResponse)
async def api_full_scan(request: ScanRequest):
    """完整扫描 - 执行所有工具并生成报告"""
    target = request.target
    if not target:
        raise HTTPException(status_code=400, detail="扫描目标不能为空")
    
    tool_names = request.tools if request.tools else (TOOL_SEQUENCE_INFO + TOOL_SEQUENCE_VULN)
    
    for t in tool_names:
        if t not in TOOL_MAP:
            raise HTTPException(status_code=400, detail=f"工具 {t} 不存在")
    
    logger.info(f"开始完整扫描: {target}")
    
    session_id = str(uuid4())[:8]
    
    info_results = _execute_tools_parallel(
        [t for t in tool_names if t in TOOL_SEQUENCE_INFO],
        target
    )
    
    vuln_results = _execute_tools_parallel(
        [t for t in tool_names if t in TOOL_SEQUENCE_VULN],
        target
    )
    
    all_results = info_results + vuln_results
    success_count = sum(1 for r in all_results if r.get("success"))
    vuln_found = sum(1 for r in vuln_results if r.get("success") and r.get("result", {}).get("vulnerable"))
    
    response_data = {
        "session_id": session_id,
        "target": target,
        "scan_type": "full_scan",
        "info_collection": {
            "tools_count": len(info_results),
            "results": info_results
        },
        "vuln_scan": {
            "tools_count": len(vuln_results),
            "vulnerabilities_found": vuln_found,
            "results": vuln_results
        },
        "timestamp": datetime.now().isoformat()
    }
    
    if request.generate_report and success_count > 0:
        try:
            from TOSKill.tools.report.report_manager import get_report_manager
            report_manager = get_report_manager()
            
            tool_results = {}
            vulnerabilities = []
            
            for r in all_results:
                if r.get("success") and r.get("result"):
                    tool_results[r["tool"]] = r["result"]
                    if isinstance(r["result"], dict) and r["result"].get("vulnerable"):
                        vulnerabilities.append({
                            "type": r["tool"].replace("_scan", ""),
                            "severity": r["result"].get("severity", "medium"),
                            "url": target,
                            "description": r["result"].get("description", "")
                        })
            
            report_content = await report_manager.generate_ai_report_content_async(
                tool_results, vulnerabilities, target
            )
            
            report_info = report_manager.save_report(
                session_id=session_id,
                content=report_content,
                metadata={
                    "target": target,
                    "tool_results": tool_results,
                    "vulnerabilities": vulnerabilities,
                    "scan_summary": {
                        "tool_count": len(tool_results),
                        "vulnerability_count": len(vulnerabilities)
                    }
                }
            )
            
            response_data["report_url"] = report_info.get("download_url", "")
            response_data["report_id"] = report_info.get("report_id", "")
            
            logger.info(f"报告已生成: {report_info.get('download_url')}")
            
        except Exception as e:
            logger.error(f"生成报告失败: {e}")
    
    return APIResponse(
        message=f"完整扫描完成: {success_count}/{len(all_results)}, 发现漏洞: {vuln_found}",
        data=response_data
    )


@router.get("/tools", response_model=APIResponse)
async def api_list_tools():
    """获取所有可用工具列表"""
    tools = [
        {
            "name": name,
            "description": tool.description,
            "category": "info_collection" if tool in INFO_COLLECTION_TOOLS else
                       "vuln_scan" if tool in VULN_SCAN_TOOLS else "poc"
        }
        for name, tool in TOOL_MAP.items()
    ]
    return APIResponse(data={"tools": tools, "count": len(tools)})


@router.get("/tools/categories", response_model=APIResponse)
async def api_list_tools_by_category():
    """获取按类别分组的工具列表"""
    return APIResponse(data={
        "info_collection": [t.name for t in INFO_COLLECTION_TOOLS],
        "vuln_scan": [t.name for t in VULN_SCAN_TOOLS],
        "poc": [t.name for t in ALL_TOOLS if t not in INFO_COLLECTION_TOOLS and t not in VULN_SCAN_TOOLS],
        "all": get_all_tool_names()
    })


@router.post("/tools/execute", response_model=APIResponse)
async def api_execute_tool(request: ToolExecuteRequest):
    """执行单个工具"""
    if request.tool_name not in TOOL_MAP:
        raise HTTPException(status_code=404, detail=f"工具 {request.tool_name} 不存在")
    
    if not request.target:
        raise HTTPException(status_code=400, detail="扫描目标不能为空")
    
    logger.info(f"执行单个工具: {request.tool_name} -> {request.target}")
    
    result = _execute_single_tool(request.tool_name, request.target)
    
    if result["success"]:
        return APIResponse(message="工具执行完成", data=result)
    else:
        raise HTTPException(status_code=500, detail=result.get("error", "执行失败"))


@router.post("/tools/execute/batch", response_model=APIResponse)
async def api_execute_tools_batch(request: BatchToolExecuteRequest):
    """批量执行工具"""
    if not request.tool_names:
        raise HTTPException(status_code=400, detail="工具列表不能为空")
    
    if not request.target:
        raise HTTPException(status_code=400, detail="扫描目标不能为空")
    
    for t in request.tool_names:
        if t not in TOOL_MAP:
            raise HTTPException(status_code=400, detail=f"工具 {t} 不存在")
    
    logger.info(f"批量执行工具: {request.tool_names} -> {request.target}")
    
    if request.parallel:
        results = _execute_tools_parallel(request.tool_names, request.target)
    else:
        results = _execute_tools_sequential(request.tool_names, request.target)
    
    success_count = sum(1 for r in results if r.get("success"))
    
    return APIResponse(
        message=f"批量执行完成: {success_count}/{len(results)}",
        data={
            "target": request.target,
            "tools": request.tool_names,
            "total": len(results),
            "success_count": success_count,
            "results": results
        }
    )


@router.get("/tools/{tool_name}", response_model=APIResponse)
async def api_get_tool_info(tool_name: str):
    """获取单个工具详情"""
    tool = get_tool_by_name(tool_name)
    if not tool:
        raise HTTPException(status_code=404, detail=f"工具 {tool_name} 不存在")
    
    return APIResponse(data={
        "name": tool.name,
        "description": tool.description,
        "category": "info_collection" if tool in INFO_COLLECTION_TOOLS else
                   "vuln_scan" if tool in VULN_SCAN_TOOLS else "poc"
    })


@router.get("/health", response_model=APIResponse)
async def api_health_check():
    """健康检查"""
    return APIResponse(
        message="TOSKill API 服务正常",
        data={
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "tools_count": len(TOOL_MAP),
            "available_tools": get_all_tool_names()
        }
    )


@router.post("/sessions", response_model=APIResponse)
async def api_create_session(request: SessionRequest):
    """创建扫描会话"""
    session_id = str(uuid4())[:8]
    _scan_tasks[session_id] = {
        "target": request.target,
        "tools": request.tools or get_all_tool_names(),
        "status": "created",
        "created_at": datetime.now().isoformat()
    }
    return APIResponse(message="会话创建成功", data={"session_id": session_id})


@router.get("/sessions/{session_id}", response_model=APIResponse)
async def api_get_session(session_id: str):
    """获取会话状态"""
    if session_id not in _scan_tasks:
        raise HTTPException(status_code=404, detail=f"会话 {session_id} 不存在")
    
    return APIResponse(data=_scan_tasks[session_id])


@router.delete("/sessions/{session_id}", response_model=APIResponse)
async def api_delete_session(session_id: str):
    """删除会话"""
    if session_id not in _scan_tasks:
        raise HTTPException(status_code=404, detail=f"会话 {session_id} 不存在")
    
    del _scan_tasks[session_id]
    return APIResponse(message="会话删除成功")
