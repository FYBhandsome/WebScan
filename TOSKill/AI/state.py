"""
TOSKill AI 简化版状态定义

ScanState，使用 TypedDict 定义状态。
支持记忆化存储，简化数据结构。
"""
from typing import TypedDict, List, Dict, Any, Optional, NotRequired
from datetime import datetime


class ScanState(TypedDict, total=False):
    """扫描状态"""
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
    intent_type: str
    direct_tool: str
    direct_target: str
    tool_formatted_result: str
    user_input: str
    intent_confidence: float
    intent_valid: bool
    intent_error: str
    script_type: str
    script_content: str
    script_path: str
    script_name: str
    script_description: str
    registered_tool_name: str
    validation_status: str
    missing_fields: List[str]
    validation_message: str
    extracted_params: Dict[str, Any]
    needs_input: bool
    input_field: str
    intent_context: Dict[str, Any]
    clarification_needed: bool
    clarification_question: str
    tool_exists: bool
    report_url: str
    report_id: str
    html_report_url: str
    last_activity_time: str
    conversation_turn: int
    auth_cookies: Dict[str, str]
    auth_headers: Dict[str, str]
    auth_token: str
    session_cookies: Dict[str, str]
    session_token: str
    auth_config: Dict[str, Any]
    authentication_used: bool
    credentials_obtained: bool
    auth_info: NotRequired[Dict[str, Any]]
    auth_timestamp: NotRequired[str]
    auth_expires_at: NotRequired[str]
    rag_last_strategy: str
    rag_enabled: bool
    rejection_count: NotRequired[int]
    alternative_options: NotRequired[List[Dict]]
    pending_action_type: NotRequired[str]
    skipped_tasks: NotRequired[List[str]]
    tool_confirm_required: NotRequired[bool]
    confirm_target: NotRequired[str]
    confirm_tool: NotRequired[str]
    
    # 交互控制
    pending_confirmation: NotRequired[bool]
    confirmation_type: NotRequired[str]
    confirmation_message: NotRequired[str]
    confirmation_options: NotRequired[List[Dict]]
    confirmed: NotRequired[bool]
    
    # 风险控制
    highest_risk_level: NotRequired[str]
    risk_summary: NotRequired[Dict[str, int]]
    skip_remaining_tasks: NotRequired[bool]


def create_initial_state(target: str, task_id: str = None, mode: str = "info_collection") -> ScanState:
    """创建初始状态"""
    import uuid
    now = datetime.now().isoformat()
    
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
        websocket_session_id=None,
        intent_type="",
        direct_tool="",
        direct_target="",
        tool_formatted_result="",
        user_input="",
        intent_confidence=0.0,
        intent_valid=True,
        intent_error="",
        script_type="",
        script_content="",
        script_path="",
        script_name="",
        script_description="",
        registered_tool_name="",
        validation_status="",
        missing_fields=[],
        validation_message="",
        extracted_params={},
        needs_input=False,
        input_field="",
        intent_context={},
        clarification_needed=False,
        clarification_question="",
        tool_exists=True,
        report_url="",
        report_id="",
        html_report_url="",
        last_activity_time=now,
        conversation_turn=0,
        auth_cookies={},
        auth_headers={},
        auth_token="",
        session_cookies={},
        session_token="",
        auth_config={},
        authentication_used=False,
        credentials_obtained=False,
        auth_info={},
        auth_timestamp="",
        auth_expires_at="",
        rag_last_strategy="",
        rag_enabled=True,
        rejection_count=0,
        alternative_options=[],
        pending_action_type="",
        skipped_tasks=[],
        tool_confirm_required=False,
        confirm_target="",
        confirm_tool="",
    )


def append_chat(state: ScanState, role: str, content: str) -> ScanState:
    """追加聊天历史 - 类比 demo.py 的 append_chat"""
    h = state.get("chat_history", []).copy()
    h.append({"role": role, "content": content, "timestamp": datetime.now().isoformat()})
    return {**state, "chat_history": h}


def update_state(state: ScanState, **kwargs) -> ScanState:
    """更新状态"""
    new_state = dict(state)
    new_state.update(kwargs)
    return new_state


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
