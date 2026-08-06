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

from TOSKill.AI.graph import memory_store, get_llm
from TOSKill.AI.state import create_initial_state, update_state, get_state_summary
from TOSKill.AI.tools import (
    TOOL_MAP, get_tool_by_name, get_all_tool_names,
    INFO_COLLECTION_TOOLS, VULN_SCAN_TOOLS, clean_target
)
from TOSKill.analysis.result_analyzer import get_analyzer
from TOSKill.AI.task_status_store import get_task_status_store

logger = logging.getLogger(__name__)
router = APIRouter(prefix="", tags=["TOSKill API"])


# ==================== 请求模型 ====================

class ScanRequest(BaseModel):
    target: str = Field(..., description="扫描目标")
    session_id: Optional[str] = Field(None, description="会话ID")
    tools: Optional[List[str]] = Field(None, description="指定工具列表")
    generate_report: bool = Field(default=True, description="是否自动生成报告")

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
    params: Optional[dict] = Field(None, description="工具额外参数")
    analyze: bool = Field(default=True, description="是否生成AI分析")

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


class ChatSendRequest(BaseModel):
    session_id: str = Field(..., description="会话ID")
    message: str = Field(..., description="消息内容")


class ParseIntentRequest(BaseModel):
    message: str = Field(..., description="用户输入的自然语言消息")


class SessionRequest(BaseModel):
    target: Optional[str] = Field(default="", description="扫描目标")
    mode: str = Field(default="info_collection", description="扫描模式")


class APIResponse(BaseModel):
    code: int = 200
    message: str = "success"
    data: Optional[dict] = None
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat(),
        description="API 响应时间戳；data.timestamp 为业务时间戳（如扫描/注册时间），两者区分用途")


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
    elif mode == "full_scan":
        return [t.name for t in INFO_COLLECTION_TOOLS] + [t.name for t in VULN_SCAN_TOOLS]
    else:
        logger.warning(f"未识别的扫描模式: {mode}，回退到全量工具")
        return [t.name for t in INFO_COLLECTION_TOOLS] + [t.name for t in VULN_SCAN_TOOLS]


async def _execute_tools_async(target: str, tools: List[str]) -> Tuple[List[Dict], List[str]]:
    results = []
    errors = []
    cleaned_target = clean_target(target)
    
    for tool_name in tools:
        tool = get_tool_by_name(tool_name)
        if not tool:
            errors.append(f"工具 {tool_name} 不存在")
            continue
        try:
            if hasattr(tool, 'ainvoke') and callable(getattr(tool, 'ainvoke')):
                result = await tool.ainvoke(cleaned_target)
            else:
                result = tool.invoke(cleaned_target)
            results.append({
                "tool": tool_name,
                "success": True,
                "result": result,
                "timestamp": datetime.now().isoformat()
            })
        except Exception as e:
            logger.error(f"工具 {tool_name} 执行失败: {e}")
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
    
    results, errors = await _execute_tools_async(request.target, tools)
    
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
            "completed_tasks": completed_tasks,
            "tool_results": tool_results,
            "errors": errors,
            "timestamp": datetime.now().isoformat()
        }
    )


@router.post("/scan/vuln", response_model=APIResponse)
async def api_vuln_scan(request: ScanRequest):
    session_id, state = _prepare_session(request, "vuln_scan")
    tools = _get_tools_for_mode("vuln_scan", request.tools)
    
    results, errors = await _execute_tools_async(request.target, tools)
    
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
            "completed_tasks": completed_tasks,
            "tool_results": tool_results,
            "vulnerabilities": vulnerabilities,
            "errors": errors,
            "timestamp": datetime.now().isoformat()
        }
    )


@router.post("/scan/full", response_model=APIResponse)
async def api_full_scan(request: ScanRequest):
    session_id, state = _prepare_session(request, "full_scan")
    tools = _get_tools_for_mode("full_scan", request.tools)
    
    results, errors = await _execute_tools_async(request.target, tools)
    
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
            "completed_tasks": completed_tasks,
            "tool_results": tool_results,
            "vulnerabilities": vulnerabilities,
            "scan_summary": scan_summary,
            "errors": errors,
            "timestamp": datetime.now().isoformat()
        }
    )


# ==================== 任务状态轮询接口 ====================

@router.get("/scan/tasks/{task_id}/status")
async def get_task_status(task_id: str):
    """获取扫描任务状态（轮询端点，不依赖 WebSocket）

    返回 {task_id, status, progress, stage, waiting_input?, waiting_script?, result?, error?}。
    任务不存在时返回 200 + status:"unknown"，便于前端轮询判断。
    """
    store = get_task_status_store()
    data = store.get_status(task_id)
    if data is None:
        return {
            "task_id": task_id,
            "status": "unknown",
            "progress": 0,
            "stage": "",
            "message": "任务不存在或尚未创建",
        }
    return data


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
    target = clean_target(request.target)
    
    try:
        result = tool.invoke(target)
        response_data = {
            "tool_name": request.tool_name,
            "target": target,
            "success": True,
            "result": result,
            "timestamp": datetime.now().isoformat()
        }

        if request.analyze:
            try:
                analyzer = get_analyzer()
                analysis = analyzer.analyze(
                    request.tool_name, target, result
                )
                response_data["analysis"] = {
                    "tool_title": analysis.tool_title,
                    "target": analysis.target,
                    "success": analysis.success,
                    **analyzer.to_websocket_payload(analysis),
                    "formatted": analyzer.format_display(analysis)
                }
            except Exception as e:
                logger.warning(f"AI分析生成失败: {e}")
                response_data["analysis"] = {
                    "error": f"分析生成失败: {str(e)}",
                    "analysis": "AI 分析暂时不可用，请查看原始扫描结果。",
                    "summary": "分析生成失败"
                }

        return APIResponse(message="工具执行完成", data=response_data)
    except Exception as e:
        error_data = {
            "tool_name": request.tool_name,
            "target": target,
            "success": False,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

        if request.analyze:
            try:
                analyzer = get_analyzer()
                analysis = analyzer.analyze(
                    request.tool_name, target, None, error=str(e)
                )
                error_data["analysis"] = {
                    "tool_title": analysis.tool_title,
                    "target": analysis.target,
                    "success": False,
                    **analyzer.to_websocket_payload(analysis),
                    "formatted": analyzer.format_display(analysis)
                }
            except Exception as ae:
                logger.warning(f"AI失败分析生成失败: {ae}")

        return APIResponse(
            code=500,
            message=f"工具执行失败: {str(e)}",
            data=error_data
        )


@router.post("/tools/execute/batch", response_model=APIResponse)
async def api_execute_tools_batch(request: BatchToolExecuteRequest):
    results, errors = await _execute_tools_async(request.target, request.tool_names)
    
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
    
    memory_store.append_chat(request.session_id, request.role, request.content)
    new_state = update_state(state, last_activity_time=datetime.now().isoformat())
    memory_store.save_session(request.session_id, new_state)
    
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


# ==================== 自然语言解析接口 ====================

@router.post("/parse-intent", response_model=APIResponse)
async def api_parse_intent(request: ParseIntentRequest):
    """使用AI解析用户自然语言输入，提取扫描目标和意图"""
    import re
    import json
    
    message = request.message.strip()
    if not message:
        return APIResponse(code=400, message="消息不能为空", data=None)
    
    url_pattern = r'(https?://[a-zA-Z0-9\.-]+(?::\d+)?(?:/[a-zA-Z0-9\./_-]*)?)'
    domain_pattern = r'([a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]\.[a-zA-Z0-9.-]{2,})'
    ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    
    extracted_target = None
    url_match = re.search(url_pattern, message)
    if url_match:
        extracted_target = url_match.group(1)
    else:
        domain_match = re.search(domain_pattern, message)
        if domain_match:
            extracted_target = f"http://{domain_match.group(1)}"
        else:
            ip_match = re.search(ip_pattern, message)
            if ip_match:
                extracted_target = f"http://{ip_match.group(1)}"
    
    mode_keywords = {
        "info": ["信息收集", "信息", "收集", "资产", "端口扫描", "子域名", "info", "端口"],
        "vuln": ["漏洞扫描", "漏洞", "安全检测", "渗透", "vuln", "漏洞检测", "注入", "xss", "sql"],
        "full": ["完整扫描", "全面扫描", "深度扫描", "full", "全部", "完整"]
    }
    
    detected_mode = None
    message_lower = message.lower()
    for mode, keywords in mode_keywords.items():
        for kw in keywords:
            if kw in message_lower:
                detected_mode = mode
                break
        if detected_mode:
            break
    
    action_keywords = {
        "scan": ["扫描", "检测", "测试", "分析", "scan", "check", "test", "进行"],
        "help": ["帮助", "help", "怎么", "如何", "用法", "指令"],
        "status": ["状态", "进度", "status", "当前"],
        "stop": ["停止", "取消", "stop", "cancel", "终止"]
    }
    
    detected_action = None
    for action, keywords in action_keywords.items():
        for kw in keywords:
            if kw in message_lower:
                detected_action = action
                break
        if detected_action:
            break
    
    if extracted_target and not detected_action:
        detected_action = "scan"
    
    try:
        llm = get_llm()
        prompt = f"""分析用户输入，提取关键信息。用户输入："{message}"

请以JSON格式输出以下信息：
1. target: 提取的扫描目标URL（如果有的话，确保以http://或https://开头，不要包含其他文字）
2. mode: 扫描模式（info/vuln/full，根据用户意图判断，默认full）
3. action: 用户意图（scan/help/status/stop/chat）
4. confidence: 置信度（0.0-1.0）
5. explanation: 简要解释用户意图

注意：target字段只提取纯URL，不要包含任何中文或其他文字。

只输出JSON，不要其他内容：
{{"target": "...", "mode": "...", "action": "...", "confidence": 0.0, "explanation": "..."}}"""
        
        response = llm.invoke(prompt, timeout=10)
        response_text = response.content if hasattr(response, 'content') else str(response)
        
        json_match = re.search(r'\{[^{}]*\}', response_text)
        if json_match:
            ai_result = json.loads(json_match.group())
            
            if ai_result.get("target"):
                ai_target = ai_result["target"].strip()
                if not ai_target.startswith(("http://", "https://")):
                    ai_target = f"http://{ai_target}"
                if extracted_target:
                    pass
                else:
                    extracted_target = ai_target
            
            if ai_result.get("mode") and not detected_mode:
                detected_mode = ai_result["mode"]
            
            if ai_result.get("action") and not detected_action:
                detected_action = ai_result["action"]
            
            confidence = ai_result.get("confidence", 0.8)
            explanation = ai_result.get("explanation", "")
        else:
            confidence = 0.6
            explanation = "基于规则解析"
            
    except Exception as e:
        logger.warning(f"AI解析失败，使用规则解析: {e}")
        confidence = 0.5
        explanation = "AI解析失败，使用规则解析"
    
    if not detected_action:
        detected_action = "chat"
    
    if not detected_mode:
        detected_mode = "full"
    
    return APIResponse(
        message="意图解析完成",
        data={
            "original_message": message,
            "target": extracted_target,
            "mode": detected_mode,
            "action": detected_action,
            "confidence": confidence,
            "explanation": explanation,
            "should_start_scan": extracted_target is not None and detected_action == "scan",
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


chat_router = APIRouter(prefix="/chat", tags=["聊天兼容"])

@chat_router.post("/send", response_model=APIResponse)
async def api_chat_send(request: ChatSendRequest):
    state = _validate_session(request.session_id)
    memory_store.append_chat(request.session_id, "user", request.message)
    new_state = update_state(state, last_activity_time=datetime.now().isoformat())
    memory_store.save_session(request.session_id, new_state)
    return APIResponse(message="消息已发送")

@chat_router.get("/history/{session_id}", response_model=APIResponse)
async def api_chat_history(session_id: str, limit: int = 20):
    history = memory_store.get_chat_history(session_id)
    return APIResponse(data={"history": history[-limit:] if history else []})


script_router = APIRouter(prefix="/scripts", tags=["脚本管理"])

@script_router.get("/history", response_model=APIResponse)
async def get_script_history(limit: int = 50):
    """获取脚本历史"""
    history = memory_store.get_script_history(limit)
    return APIResponse(data={"scripts": history, "total": len(history)})

@script_router.get("/{tool_name}/source", response_model=APIResponse)
async def get_script_source(tool_name: str):
    """获取脚本源码"""
    script = memory_store.get_script_by_name(tool_name)
    if not script:
        raise HTTPException(status_code=404, detail=f"脚本 '{tool_name}' 不存在")
    return APIResponse(data={"script": script})

@script_router.delete("/{tool_name}", response_model=APIResponse)
async def delete_script(tool_name: str):
    """删除脚本"""
    success = memory_store.delete_script_history(tool_name)
    if not success:
        raise HTTPException(status_code=500, detail="删除脚本失败")
    return APIResponse(message=f"脚本 '{tool_name}' 已删除")

@script_router.post("/save", response_model=APIResponse)
async def save_script(request: dict):
    """保存脚本"""
    tool_name = request.get("tool_name")
    script_content = request.get("script_content")
    description = request.get("description", "")
    source = request.get("source", "upload")
    
    if not tool_name or not script_content:
        raise HTTPException(status_code=400, detail="tool_name 和 script_content 不能为空")
    
    success = memory_store.save_script_history(tool_name, script_content, description, source)
    if not success:
        raise HTTPException(status_code=500, detail="保存脚本失败")
    return APIResponse(message=f"脚本 '{tool_name}' 已保存")
