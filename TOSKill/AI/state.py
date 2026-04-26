"""
TOSKill AI 简化版状态定义

类比 demo.py 的 ScanState，使用 TypedDict 定义状态。
支持记忆化存储，简化数据结构。
"""
from typing import TypedDict, List, Dict, Any, Optional
from datetime import datetime


class ScanState(TypedDict, total=False):
    """扫描状态 - 类比 demo.py 的 ScanState"""
    target: str
    task_id: str
    mode: str
    planned_tasks: List[str]
    completed_tasks: List[str]
    tool_results: Dict[str, Any]
    vulnerabilities: List[Dict[str, Any]]
    target_context: Dict[str, Any]
    execution_history: List[Dict[str, Any]]
    is_complete: bool
    should_continue: bool
    next_action: str
    decision_history: List[Dict[str, Any]]
    errors: List[str]
    vuln_scan_results: Dict[str, Any]
    scan_summary: Dict[str, Any]
    report: str
    user_choice: str
    chat_history: List[Dict[str, str]]
    chat_summary: str
    user_name: str
    need_generate_script: bool
    next_task: str
    task_result: Dict[str, Any]
    task_history: List[str]
    stage_status: Dict[str, Dict[str, Any]]
    websocket_session_id: Optional[str]


def create_initial_state(target: str, task_id: str = None, mode: str = "info_collection") -> ScanState:
    """创建初始状态"""
    import uuid
    return ScanState(
        target=target,
        task_id=task_id or str(uuid.uuid4())[:8],
        mode=mode,
        planned_tasks=[],
        completed_tasks=[],
        tool_results={},
        vulnerabilities=[],
        target_context={},
        execution_history=[],
        is_complete=False,
        should_continue=True,
        next_action="",
        decision_history=[],
        errors=[],
        vuln_scan_results={},
        scan_summary={},
        report="",
        user_choice="",
        chat_history=[],
        chat_summary="无",
        user_name="用户",
        need_generate_script=False,
        next_task="",
        task_result={},
        task_history=[],
        stage_status={
            "planning": {"status": "pending", "sub_status": "pending", "progress": 0, "logs": []},
            "tool_execution": {"status": "pending", "sub_status": "pending", "progress": 0, "logs": []},
            "report": {"status": "pending", "sub_status": "pending", "progress": 0, "logs": []}
        },
        websocket_session_id=None
    )


def append_chat(state: ScanState, role: str, content: str) -> ScanState:
    """追加聊天历史 - 类比 demo.py 的 append_chat"""
    h = state.get("chat_history", []).copy()
    h.append({"role": role, "content": content, "timestamp": datetime.now().isoformat()})
    return {**state, "chat_history": h}


def update_state(state: ScanState, **kwargs) -> ScanState:
    """更新状态"""
    return {**state, **kwargs}


def get_state_summary(state: ScanState) -> Dict[str, Any]:
    """获取状态摘要"""
    return {
        "task_id": state.get("task_id", ""),
        "target": state.get("target", ""),
        "mode": state.get("mode", ""),
        "completed_tasks": len(state.get("completed_tasks", [])),
        "vulnerabilities": len(state.get("vulnerabilities", [])),
        "errors": len(state.get("errors", [])),
        "is_complete": state.get("is_complete", False),
        "chat_history_count": len(state.get("chat_history", []))
    }
