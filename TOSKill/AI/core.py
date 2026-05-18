"""
TOSKill 核心业务逻辑层

提供统一的 API 供 WebSocket 和 REST API 调用，消除重复代码。
"""
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from uuid import uuid4

from langchain_core.messages import HumanMessage, AIMessage, SystemMessage

from .state import ScanState, create_initial_state, update_state
from .graph import get_agent_orchestrator, memory_store, safe_ws_send
from .tools import get_tool_by_name, get_all_tool_names, clean_target, TOOL_MAP
from .llm_client import get_llm
from ..config import settings

logger = logging.getLogger(__name__)

CHAT_SYSTEM_PROMPT = """你是WebScan AI，一个专业的Web安全顾问。
专业领域：OWASP Top 10漏洞、Web框架漏洞、渗透测试、安全加固。
回复要求：专业准确、清晰易懂、可执行。"""


def _get_llm():
    return get_llm()


def create_session(target: str = "", mode: str = "full_scan") -> str:
    session_id = str(uuid4())[:8]
    state = create_initial_state(target=target, task_id=session_id, mode=mode)
    memory_store.save_session(session_id, state)
    logger.info(f"创建会话: {session_id}")
    return session_id


def get_session(session_id: str) -> Optional[ScanState]:
    return memory_store.get_session(session_id)


def delete_session(session_id: str) -> bool:
    state = memory_store.get_session(session_id)
    if state:
        memory_store.delete_session(session_id)
        logger.info(f"删除会话: {session_id}")
        return True
    return False


def validate_session(session_id: str) -> ScanState:
    state = memory_store.get_session(session_id)
    if not state:
        raise ValueError(f"会话 {session_id} 不存在")
    return state


async def run_info_collection(target: str, session_id: str = None) -> Dict[str, Any]:
    if not session_id:
        session_id = create_session(target=target, mode="info_collection")
    
    state = memory_store.get_session(session_id)
    if not state:
        state = create_initial_state(target=target, task_id=session_id, mode="info_collection")
    
    state = update_state(state, target=target, mode="info_collection")
    orchestrator = get_agent_orchestrator()
    result = await orchestrator.run_info_collection(state)
    memory_store.save_session(session_id, result)
    
    return _build_scan_result(session_id, target, result, "info_collection")


async def run_vuln_scan(target: str, session_id: str = None) -> Dict[str, Any]:
    if not session_id:
        session_id = create_session(target=target, mode="vuln_scan")
    
    state = memory_store.get_session(session_id)
    if not state:
        state = create_initial_state(target=target, task_id=session_id, mode="vuln_scan")
    
    state = update_state(state, target=target, mode="vuln_scan")
    orchestrator = get_agent_orchestrator()
    result = await orchestrator.run_vuln_scan(state)
    memory_store.save_session(session_id, result)
    
    return _build_scan_result(session_id, target, result, "vuln_scan")


async def run_full_scan(target: str, session_id: str = None) -> Dict[str, Any]:
    if not session_id:
        session_id = create_session(target=target, mode="full_scan")
    
    state = memory_store.get_session(session_id)
    if not state:
        state = create_initial_state(target=target, task_id=session_id, mode="full_scan")
    
    state = update_state(state, target=target, mode="full_scan")
    orchestrator = get_agent_orchestrator()
    result = await orchestrator.run_full_scan(state)
    memory_store.save_session(session_id, result)
    
    return _build_scan_result(session_id, target, result, "full_scan")


async def run_scan(mode: str, target: str, session_id: str = None) -> Dict[str, Any]:
    mode_map = {
        "info": run_info_collection,
        "info_collection": run_info_collection,
        "vuln": run_vuln_scan,
        "vuln_scan": run_vuln_scan,
        "full": run_full_scan,
        "full_scan": run_full_scan,
    }
    
    handler = mode_map.get(mode)
    if handler is None:
        logger.warning(f"Unknown scan mode '{mode}', falling back to full_scan")
        handler = run_full_scan
    return await handler(target, session_id)


def _build_scan_result(session_id: str, target: str, result: ScanState, mode: str) -> Dict[str, Any]:
    base = {
        "session_id": session_id,
        "target": target,
        "completed_tasks": result.get("completed_tasks", []),
        "tool_results": result.get("tool_results", {}),
        "errors": result.get("errors", []),
    }
    
    if result.get("report"):
        base["report"] = result.get("report", "")
        base["report_url"] = result.get("report_url", "")
        base["report_id"] = result.get("report_id", "")
        base["scan_summary"] = result.get("scan_summary", {})
    
    if mode in ["vuln_scan", "vuln", "full_scan", "full"]:
        base["vulnerabilities"] = result.get("vulnerabilities", [])
    
    return base


def execute_tool(tool_name: str, target: str) -> Dict[str, Any]:
    tool = get_tool_by_name(tool_name)
    if not tool:
        raise ValueError(f"工具 {tool_name} 不存在")
    
    cleaned_target = clean_target(target)
    logger.info(f"执行工具: {tool_name} -> {cleaned_target}")
    
    result = tool.invoke(cleaned_target)
    
    return {
        "tool_name": tool_name,
        "target": cleaned_target,
        "result": result,
        "timestamp": datetime.now().isoformat()
    }


def execute_tools_batch(tool_names: List[str], target: str) -> Dict[str, Any]:
    cleaned_target = clean_target(target)
    results = {}
    errors = []
    
    for tool_name in tool_names:
        tool = get_tool_by_name(tool_name)
        if not tool:
            errors.append(f"工具 {tool_name} 不存在")
            continue
        
        try:
            results[tool_name] = tool.invoke(cleaned_target)
        except Exception as e:
            errors.append(f"{tool_name}: {str(e)}")
    
    return {
        "results": results,
        "errors": errors,
        "total": len(tool_names),
        "success": len(results)
    }


def get_tools() -> List[Dict[str, str]]:
    return [
        {"name": name, "description": getattr(tool, 'description', '')}
        for name, tool in TOOL_MAP.items()
    ]


def get_tools_by_category() -> Dict[str, List[str]]:
    from .tools import INFO_COLLECTION_TOOLS, VULN_SCAN_TOOLS
    return {
        "info_collection": [t.name for t in INFO_COLLECTION_TOOLS],
        "vuln_scan": [t.name for t in VULN_SCAN_TOOLS],
        "all": list(TOOL_MAP.keys())
    }


async def chat(session_id: str, content: str) -> str:
    state = memory_store.get_session(session_id)
    if not state:
        state = create_initial_state(target="", task_id=session_id)
        memory_store.save_session(session_id, state)
    
    memory_store.append_chat(session_id, "user", content)
    
    messages = [SystemMessage(content=CHAT_SYSTEM_PROMPT)]
    for msg in memory_store.get_chat_history(session_id)[-10:]:
        if msg["role"] == "user":
            messages.append(HumanMessage(content=msg["content"]))
        elif msg["role"] == "assistant":
            messages.append(AIMessage(content=msg["content"]))
    
    if not any(isinstance(m, HumanMessage) for m in messages[1:]):
        messages.append(HumanMessage(content=content))
    
    llm = _get_llm()
    
    await safe_ws_send(session_id, {
        "type": "ai_thinking_start",
        "payload": {}
    })
    
    full_response = ""
    async for chunk in llm.astream(messages):
        token = chunk.content if hasattr(chunk, 'content') else str(chunk)
        if token:
            full_response += token
            await safe_ws_send(session_id, {
                "type": "ai_thinking",
                "payload": {"token": token}
            })
    
    thought, clean_content = _parse_chat_response(full_response)
    
    memory_store.append_chat(session_id, "assistant", clean_content)
    
    await safe_ws_send(session_id, {
        "type": "ai_chat",
        "payload": {"thought": thought, "content": clean_content}
    })
    
    return clean_content


def _parse_chat_response(full_response: str):
    """从LLM完整响应中分离思考过程和最终回复"""
    import re
    thought = ""
    content = full_response
    match = re.match(
        r'(?:思考[：:]\s*|分析[：:]\s*|Thought:\s*)(.*?)(?=回复[：:]|回答[：:]|Response:|$)',
        full_response, re.DOTALL
    )
    if match:
        thought = match.group(1).strip()
        remaining = full_response[match.end():].strip()
        remaining = re.sub(r'^(?:回复[：:]|回答[：:]|Response:)\s*', '', remaining)
        content = remaining if remaining else content
    return thought, content


def append_chat_message(session_id: str, role: str, content: str) -> bool:
    state = memory_store.get_session(session_id)
    if not state:
        return False
    
    memory_store.append_chat(session_id, role, content)
    
    return True


def get_chat_history(session_id: str, limit: int = 20) -> List[Dict]:
    history = memory_store.get_chat_history(session_id)
    return history[-limit:] if history else []


async def generate_report(session_id: str) -> Dict[str, Any]:
    state = memory_store.get_session(session_id)
    if not state:
        raise ValueError(f"会话 {session_id} 不存在")
    
    orchestrator = get_agent_orchestrator()
    result = await orchestrator.run_report(state)
    memory_store.save_session(session_id, result)
    
    return {
        "report": result.get("report", ""),
        "scan_summary": result.get("scan_summary", {})
    }


def get_session_status(session_id: str) -> Optional[Dict[str, Any]]:
    state = memory_store.get_session(session_id)
    if not state:
        return None
    
    return {
        "task_id": state.get("task_id", ""),
        "target": state.get("target", ""),
        "mode": state.get("mode", ""),
        "completed_tasks": state.get("completed_tasks", []),
        "is_complete": state.get("is_complete", False)
    }
