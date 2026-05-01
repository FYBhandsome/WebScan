"""
TOSKill RESTful API 接口层

提供简洁高效的HTTP API接口。
REST API 直接执行工具，不使用图的 interrupt 机制。
WebSocket 用于交互式流程。
"""
import logging
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

from TOSKill.AI.graph import memory_store, get_agent_orchestrator, get_llm
from TOSKill.AI.state import create_initial_state, append_chat, update_state, get_state_summary
from TOSKill.AI.tools import (
    TOOL_MAP, get_tool_by_name, get_all_tool_names,
    INFO_COLLECTION_TOOLS, VULN_SCAN_TOOLS, clean_target
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/toskill", tags=["TOSKill API"])


# ==================== 请求模型 ====================

class ScanRequest(BaseModel):
    target: str = Field(..., description="扫描目标")
    session_id: Optional[str] = Field(None, description="会话ID")
    tools: Optional[List[str]] = Field(None, description="指定工具列表")

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("target 不能为空")
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError("target 必须以 http:// 或 https:// 开头")
        return clean_target(v)


class ToolExecuteRequest(BaseModel):
    tool_name: str = Field(..., description="工具名称")
    target: str = Field(..., description="扫描目标")

    @field_validator("tool_name")
    @classmethod
    def validate_tool_name(cls, v: str) -> str:
        if v not in TOOL_MAP:
            valid_tools = ", ".join(list(TOOL_MAP.keys())[:10]) + "..."
            raise ValueError(f"工具 '{v}' 不存在。可用工具: {valid_tools}")
        return v

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("target 不能为空")
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError("target 必须以 http:// 或 https:// 开头")
        return clean_target(v)


class BatchToolExecuteRequest(BaseModel):
    tool_names: List[str] = Field(..., description="工具名称列表")
    target: str = Field(..., description="扫描目标")


class ChatRequest(BaseModel):
    session_id: str = Field(..., description="会话ID")
    role: str = Field(default="user", description="角色")
    content: str = Field(..., description="消息内容")


class SessionRequest(BaseModel):
    target: Optional[str] = Field(default="", description="扫描目标")
    mode: str = Field(default="info_collection", description="扫描模式")


class APIResponse(BaseModel):
    code: int = 200
    message: str = "success"
    data: Optional[dict] = None
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())


# ==================== 辅助函数 ====================

def _create_session_id() -> str:
    return str(uuid4())[:8]


def _prepare_session(request: ScanRequest, mode: str) -> Tuple[str, Dict]:
    session_id = request.session_id or _create_session_id()
    state = memory_store.get_session(session_id)
    if not state:
        state = create_initial_state(target=request.target, task_id=session_id, mode=mode)
    return session_id, update_state(state, target=request.target, mode=mode)


def _get_tools_for_mode(mode: str, custom_tools: List[str] = None) -> List[str]:
    if custom_tools:
        return [t for t in custom_tools if t in TOOL_MAP]
    if mode == "info_collection":
        return [t.name for t in INFO_COLLECTION_TOOLS]
    elif mode == "vuln_scan":
        return [t.name for t in VULN_SCAN_TOOLS]
    else:
        return [t.name for t in INFO_COLLECTION_TOOLS] + [t.name for t in VULN_SCAN_TOOLS]


def _execute_tools_sync(target: str, tools: List[str]) -> Tuple[List[Dict], List[str]]:
    results = []
    errors = []
    cleaned_target = clean_target(target)
    
    for tool_name in tools:
        tool = get_tool_by_name(tool_name)
        if not tool:
            errors.append(f"工具 {tool_name} 不存在")
            continue
        try:
            result = tool.invoke(cleaned_target)
            results.append({
                "tool": tool_name,
                "success": True,
                "result": result,
                "timestamp": datetime.now().isoformat()
            })
        except Exception as e:
            errors.append(f"{tool_name}: {str(e)}")
            results.append({
                "tool": tool_name,
                "success": False,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            })
    
    return results, errors


def _validate_session(session_id: str) -> Dict:
    state = memory_store.get_session(session_id)
    if not state:
        raise HTTPException(status_code=404, detail=f"会话 {session_id} 不存在")
    return state


# ==================== 会话管理接口 ====================

@router.post("/sessions", response_model=APIResponse)
async def api_create_session(request: SessionRequest):
    session_id = _create_session_id()
    state = create_initial_state(target=request.target, task_id=session_id, mode=request.mode)
    memory_store.save_session(session_id, state)
    return APIResponse(message="会话创建成功", data={"session_id": session_id})


@router.get("/sessions/{session_id}", response_model=APIResponse)
async def api_get_session(session_id: str):
    state = _validate_session(session_id)
    return APIResponse(data=get_state_summary(state))


@router.delete("/sessions/{session_id}", response_model=APIResponse)
async def api_delete_session(session_id: str):
    _validate_session(session_id)
    memory_store.delete_session(session_id)
    return APIResponse(message="会话删除成功")


# ==================== 扫描接口 ====================

@router.post("/scan/info", response_model=APIResponse)
async def api_info_collection(request: ScanRequest):
    session_id, state = _prepare_session(request, "info_collection")
    tools = _get_tools_for_mode("info_collection", request.tools)
    
    results, errors = _execute_tools_sync(request.target, tools)
    
    tool_results = {r["tool"]: r.get("result", r.get("error")) for r in results if r["success"]}
    completed_tasks = [r["tool"] for r in results if r["success"]]
    
    state = update_state(state, tool_results=tool_results, completed_tasks=completed_tasks, errors=errors)
    memory_store.save_session(session_id, state)
    
    return APIResponse(
        message=f"信息收集完成: {len(completed_tasks)}/{len(tools)}",
        data={
            "session_id": session_id,
            "target": request.target,
            "scan_type": "info_collection",
            "tools_used": tools,
            "results": results,
            "errors": errors,
            "timestamp": datetime.now().isoformat()
        }
    )


@router.post("/scan/vuln", response_model=APIResponse)
async def api_vuln_scan(request: ScanRequest):
    session_id, state = _prepare_session(request, "vuln_scan")
    tools = _get_tools_for_mode("vuln_scan", request.tools)
    
    results, errors = _execute_tools_sync(request.target, tools)
    
    tool_results = {r["tool"]: r.get("result", r.get("error")) for r in results if r["success"]}
    completed_tasks = [r["tool"] for r in results if r["success"]]
    
    vulnerabilities = []
    for r in results:
        if r["success"] and isinstance(r.get("result"), dict):
            if r["result"].get("vulnerable"):
                vulnerabilities.append({
                    "tool": r["tool"],
                    "type": r["result"].get("vuln_type", "unknown"),
                    "severity": r["result"].get("severity", "medium")
                })
    
    state = update_state(state, tool_results=tool_results, completed_tasks=completed_tasks, errors=errors, vulnerabilities=vulnerabilities)
    memory_store.save_session(session_id, state)
    
    return APIResponse(
        message=f"漏洞扫描完成: {len(completed_tasks)}/{len(tools)}",
        data={
            "session_id": session_id,
            "target": request.target,
            "scan_type": "vuln_scan",
            "tools_used": tools,
            "results": results,
            "vulnerabilities": vulnerabilities,
            "errors": errors,
            "timestamp": datetime.now().isoformat()
        }
    )


@router.post("/scan/full", response_model=APIResponse)
async def api_full_scan(request: ScanRequest):
    session_id, state = _prepare_session(request, "full_scan")
    tools = _get_tools_for_mode("full_scan", request.tools)
    
    results, errors = _execute_tools_sync(request.target, tools)
    
    tool_results = {r["tool"]: r.get("result", r.get("error")) for r in results if r["success"]}
    completed_tasks = [r["tool"] for r in results if r["success"]]
    
    vulnerabilities = []
    for r in results:
        if r["success"] and isinstance(r.get("result"), dict):
            if r["result"].get("vulnerable"):
                vulnerabilities.append({
                    "tool": r["tool"],
                    "type": r["result"].get("vuln_type", "unknown"),
                    "severity": r["result"].get("severity", "medium")
                })
    
    scan_summary = {
        "total_tools": len(tools),
        "completed_tools": len(completed_tasks),
        "vulnerabilities_found": len(vulnerabilities),
        "errors_count": len(errors),
        "timestamp": datetime.now().isoformat()
    }
    
    state = update_state(
        state, 
        tool_results=tool_results, 
        completed_tasks=completed_tasks, 
        errors=errors, 
        vulnerabilities=vulnerabilities,
        scan_summary=scan_summary,
        is_complete=True
    )
    memory_store.save_session(session_id, state)
    
    return APIResponse(
        message=f"完整扫描完成: {len(completed_tasks)}/{len(tools)}",
        data={
            "session_id": session_id,
            "target": request.target,
            "scan_type": "full_scan",
            "tools_used": tools,
            "results": results,
            "vulnerabilities": vulnerabilities,
            "scan_summary": scan_summary,
            "errors": errors,
            "timestamp": datetime.now().isoformat()
        }
    )


# ==================== 工具执行接口 ====================

@router.get("/tools", response_model=APIResponse)
async def api_list_tools():
    tools = [{"name": n, "description": getattr(t, 'description', '')} for n, t in TOOL_MAP.items()]
    return APIResponse(data={"tools": tools, "count": len(tools)})


@router.get("/tools/categories", response_model=APIResponse)
async def api_list_tools_by_category():
    return APIResponse(data={
        "info_collection": [t.name for t in INFO_COLLECTION_TOOLS],
        "vuln_scan": [t.name for t in VULN_SCAN_TOOLS],
        "all": list(TOOL_MAP.keys())
    })


@router.post("/tools/execute", response_model=APIResponse)
async def api_execute_tool(request: ToolExecuteRequest):
    tool = get_tool_by_name(request.tool_name)
    if not tool:
        raise HTTPException(status_code=404, detail=f"工具 {request.tool_name} 不存在")
    
    target = clean_target(request.target)
    
    try:
        result = tool.invoke(target)
        return APIResponse(message="工具执行完成", data={
            "tool_name": request.tool_name,
            "target": target,
            "success": True,
            "result": result,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return APIResponse(
            code=500,
            message=f"工具执行失败: {str(e)}",
            data={
                "tool_name": request.tool_name,
                "target": target,
                "success": False,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
        )


@router.post("/tools/execute/batch", response_model=APIResponse)
async def api_execute_tools_batch(request: BatchToolExecuteRequest):
    results, errors = _execute_tools_sync(request.target, request.tool_names)
    
    return APIResponse(
        message=f"批量执行完成: {len([r for r in results if r['success']])}/{len(request.tool_names)}",
        data={"results": results, "errors": errors}
    )


# ==================== 报告接口 ====================

@router.post("/reports/generate/{session_id}", response_model=APIResponse)
async def api_generate_report(session_id: str):
    state = _validate_session(session_id)
    
    tool_results = state.get("tool_results", {})
    vulnerabilities = state.get("vulnerabilities", [])
    target = state.get("target", "")
    
    if not tool_results:
        return APIResponse(code=400, message="无扫描结果，无法生成报告", data=None)
    
    report = f"""# 安全扫描报告

## 目标
{target}

## 扫描摘要
- 扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- 执行工具数: {len(tool_results)}
- 发现漏洞数: {len(vulnerabilities)}

## 工具执行结果
"""
    for tool_name, result in tool_results.items():
        report += f"\n### {tool_name}\n```\n{str(result)[:500]}\n```\n"
    
    if vulnerabilities:
        report += "\n## 发现的漏洞\n"
        for vuln in vulnerabilities:
            report += f"- **{vuln.get('tool', 'Unknown')}**: {vuln.get('type', 'Unknown')} ({vuln.get('severity', 'Medium')})\n"
    
    state = update_state(state, report=report, is_complete=True)
    memory_store.save_session(session_id, state)
    
    return APIResponse(message="报告生成成功", data={
        "report": report,
        "vulnerabilities_count": len(vulnerabilities),
        "tools_count": len(tool_results)
    })


# ==================== 聊天接口 ====================

@router.post("/chat/message", response_model=APIResponse)
async def api_append_chat_message(request: ChatRequest):
    state = _validate_session(request.session_id)
    
    new_state = append_chat(state, request.role, request.content)
    memory_store.save_session(request.session_id, new_state)
    memory_store.append_chat(request.session_id, request.role, request.content)
    
    return APIResponse(message="消息已添加")


@router.get("/chat/history/{session_id}", response_model=APIResponse)
async def api_get_chat_history(session_id: str, limit: int = 20):
    history = memory_store.get_chat_history(session_id)
    return APIResponse(data={"history": history[-limit:] if history else []})


# ==================== 健康检查 ====================

@router.get("/health", response_model=APIResponse)
async def api_health_check():
    ai_model_status = "disconnected"
    try:
        llm = get_llm()
        response = llm.invoke("ping", timeout=5)
        ai_model_status = "connected"
    except Exception as e:
        logger.warning(f"AI模型连通性检测失败: {e}")

    return APIResponse(
        message="TOSKill API 服务正常",
        data={
            "status": "healthy",
            "ai_model_status": ai_model_status,
            "tools_count": len(TOOL_MAP),
            "timestamp": datetime.now().isoformat()
        }
    )


# ==================== 决策测试接口 ====================

class DecisionTestRequest(BaseModel):
    target: str = Field(..., description="测试目标URL")
    mode: str = Field(default="deep", description="扫描模式")
    completed_tools: List[str] = Field(default_factory=list, description="已完成工具")
    last_result: dict = Field(default_factory=dict, description="上一步结果")

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("target 不能为空")
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError("target 必须以 http:// 或 https:// 开头")
        return clean_target(v)


@router.post("/decision/test", response_model=APIResponse)
async def api_test_decision(request: DecisionTestRequest):
    """测试 ReACT 决策效果"""
    try:
        from TOSKill.AI.graph import build_react_prompt, parse_react_response
        state = create_initial_state(target=request.target, mode=request.mode)
        state = update_state(state, completed_tasks=request.completed_tools, task_result=request.last_result)

        llm = get_llm()
        prompt = build_react_prompt(state, "")
        response = llm.invoke(prompt, timeout=30)
        response_text = response.content if hasattr(response, 'content') else str(response)
        decision = parse_react_response(response_text)

        return APIResponse(message="决策测试完成", data={
            "prompt": prompt,
            "raw_response": response_text,
            "decision": decision
        })
    except Exception as e:
        return APIResponse(code=500, message=f"决策测试失败: {str(e)}", data=None)


# ==================== 全局异常处理 ====================

async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"未处理的异常: {type(exc).__name__}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "code": 500,
            "message": "Internal Server Error",
            "data": None,
            "timestamp": datetime.now().isoformat()
        }
    )


def register_exception_handlers(app):
    """注册全局异常处理器"""
    app.add_exception_handler(Exception, global_exception_handler)
    logger.info("全局异常处理器已注册")
