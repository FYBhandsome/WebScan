"""
AI对话WebSocket处理器

处理AI对话相关的WebSocket消息，支持悬浮球对话功能。
"""
import logging
import asyncio
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from uuid import uuid4

from fastapi import WebSocket, WebSocketDisconnect, APIRouter

from TOSKill.AI.state import create_initial_state, append_chat, update_state
from TOSKill.AI.graph import memory_store, get_agent_orchestrator, get_llm as _get_llm, scan_total_tasks
from TOSKill.AI.auto_scan import AutoScanRunner
from TOSKill.AI.core import CHAT_SYSTEM_PROMPT
from TOSKill.AI.decision_context import build_decision_context
from TOSKill.AI.tools import get_tool_by_name, get_all_tool_names
from TOSKill.tools.tool_categories import (
    collect_information_results,
    information_items,
    information_summary_text,
    tool_category,
)
from TOSKill.AI.log_collector import log_collector
from TOSKill.AI.maas_client import MaaSRequestError, get_maas_client
from TOSKill.utils.error_handler import create_error_response, format_tool_error, ErrorSource, ErrorCategory
from TOSKill.utils.log_writer import log_info, log_warn, log_error, log_success, log_debug
from TOSKill.utils.target import normalize_scan_target
from TOSKill.config import settings
from TOSKill.api.scan_protocol import (
    PAUSE_FOR_CHAT_MESSAGE,
    RESUME_SCAN_MESSAGE,
    SCAN_PROTOCOL_REQUESTS,
    SCAN_PROTOCOL_VERSION,
    ScanProtocolValidationError,
    normalize_scan_protocol_payload,
    protocol_response,
)

router = APIRouter(prefix="/ai-chat", tags=["AI对话WebSocket"])
logger = logging.getLogger(__name__)


SCAN_MODE_MAP = {"info": "info_collection", "vuln": "vuln_scan", "full": "full_scan"}
SCRIPT_TOOL_CATEGORIES = {"info_collection", "vuln_scan"}


def _requested_script_category(payload: Dict[str, Any]) -> str:
    category = str(payload.get("tool_category") or "").strip().lower()
    return category if category in SCRIPT_TOOL_CATEGORIES else ""


def _truncate_chat_text(value: Any, limit: int) -> str:
    """Limit prompt fields without failing on non-string scan results."""
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return f"{text[:limit]}\n[内容已截断]"


def _build_chat_messages(state: Dict[str, Any], history: List[Dict[str, Any]], content: str) -> List[Dict[str, str]]:
    """Build a bounded, MaaS-compatible chat-completions message list.

    The MaaS endpoint used by this project accepts the OpenAI chat schema but
    returned 400 for the previous LangChain request shape.  Keep a single
    system message and cap all dynamic context so a paused scan cannot make a
    simple chat message exceed the provider's request limits.
    """
    decision_context = state.get("decision_context") or {}
    compact_decision_context = {
        key: decision_context.get(key)
        for key in (
            "version",
            "user_constraints",
            "requested_tasks",
            "excluded_tasks",
            "priority_tasks",
            "risk_tolerance",
            "latest_request",
        )
        if decision_context.get(key) not in (None, "", [], {})
    }
    scan_context = {
        "target": state.get("target", ""),
        "mode": state.get("mode", ""),
        "completed_tasks": (state.get("completed_tasks") or [])[-20:],
        "next_task": state.get("next_task", ""),
        "vulnerabilities": (state.get("vulnerabilities") or [])[-5:],
        "errors": (state.get("errors") or [])[-5:],
        "report": _truncate_chat_text(state.get("report", ""), 800),
        "scan_status": state.get("scan_status", ""),
        "decision_context": compact_decision_context,
    }

    system_content = CHAT_SYSTEM_PROMPT.strip()
    if any(scan_context.values()):
        context_json = json.dumps(scan_context, ensure_ascii=False, default=str)
        system_content = (
            f"{system_content}\n\n"
            "当前会话的扫描上下文如下，请结合它回答后续问题：\n"
            f"{_truncate_chat_text(context_json, settings.CHAT_CONTEXT_MAX_CHARS)}"
        )

    messages: List[Dict[str, str]] = [{"role": "system", "content": system_content}]
    for item in history[-settings.CHAT_HISTORY_MAX_MESSAGES:]:
        role = item.get("role")
        if role not in ("user", "assistant"):
            continue
        message_content = _truncate_chat_text(
            item.get("content", ""), settings.CHAT_HISTORY_MESSAGE_MAX_CHARS
        )
        if message_content:
            messages.append({"role": role, "content": message_content})

    if not any(item["role"] == "user" for item in messages[1:]):
        messages.append({"role": "user", "content": _truncate_chat_text(content, settings.CHAT_HISTORY_MESSAGE_MAX_CHARS)})
    return messages

RUN_EVENT_TYPES = {
    "scan_started", "scan_flow_started", "scan_completed", "scan_cancelled", "scan_terminated",
    "workflow_progress", "workflow_log", "tool_progress", "ai_decision", "ai_decision_complete",
    "task_started", "task_completed", "task_analysis_updated", "task_error", "task_skipped",
    "direct_tool_started", "direct_tool_completed", "direct_tool_error",
    "report_generation_started", "report_generated", "report_error", "run_snapshot",
    "interaction_required", "high_risk_vulnerability_detected", "tool_confirm_required",
    "scan_paused_for_chat", "scan_resume_requested", "decision_replanned", "workflow_resumed",
}


class AIChatManager:
    """AI对话连接管理器"""
    
    def __init__(self):
        self.connections: Dict[str, WebSocket] = {}
        self.tasks: Dict[str, asyncio.Task] = {}
        self.run_types: Dict[str, str] = {}
        self._cancelled_automatic_sessions = set()
        self.llm = None
        self.maas_client = None
        self._event_sequences: Dict[str, int] = {}
        self._run_events: Dict[str, List[Dict]] = {}
        self._completion_notified = set()
        self._disconnect_cleanup: Dict[str, asyncio.Task] = {}
        # 多会话订阅：client_id -> {session_id1, session_id2, ...}
        self._subscriptions: Dict[str, set] = {}
        self._workflow_locks: Dict[str, asyncio.Lock] = {}
        # WebSocket -> client_id 映射
        self._ws_to_client: Dict[WebSocket, str] = {}
    
    def _get_llm(self):
        if not self.llm:
            self.llm = _get_llm()
        return self.llm

    def _get_maas_client(self):
        if self.maas_client is None:
            self.maas_client = get_maas_client()
        return self.maas_client
    
    async def connect(self, websocket: WebSocket, session_id: str = None) -> str:
        await websocket.accept()
        session_id = session_id or str(uuid4())[:8]
        client_id = str(uuid4())[:8]
        self._ws_to_client[websocket] = client_id
        existing_state = memory_store.get_session(session_id)
        resumed = existing_state is not None
        self.connections[session_id] = websocket
        # 初始化该连接的订阅集合，默认订阅自身会话
        self._subscriptions[client_id] = {session_id}
        cleanup_task = self._disconnect_cleanup.pop(session_id, None)
        if cleanup_task and not cleanup_task.done():
            cleanup_task.cancel()
        if not resumed:
            memory_store.save_session(session_id, create_initial_state(target="", task_id=session_id))
        
        log_info("WebSocket连接建立", category="api", node="ai_chat", session_id=session_id,
                 details={"client_ip": websocket.client.host if websocket.client else "unknown"})
        
        await self._send(session_id, {
            "type": "connected",
            "payload": {
                "session_id": session_id,
                "available_tools": get_all_tool_names(),
                "resumed": resumed,
            }
        })
        if resumed:
            run_id = existing_state.get("run_id") or session_id
            for event in self._run_events.get(run_id, [])[-200:]:
                await websocket.send_json(event)
            await self._send_run_snapshot(session_id, existing_state)
            pending = memory_store.get_pending_interaction(session_id)
            if pending:
                await websocket.send_json(self._pending_for_client(session_id, pending))
        return session_id
    
    def disconnect(self, session_id: str, websocket: WebSocket = None):
        if websocket is not None and self.connections.get(session_id) is not websocket:
            return
        self.connections.pop(session_id, None)
        # 清理订阅映射
        if websocket is not None:
            client_id = self._ws_to_client.pop(websocket, None)
            if client_id:
                self._subscriptions.pop(client_id, None)
        running_task = self.tasks.get(session_id)
        if running_task and not running_task.done():
            cleanup = asyncio.create_task(self._cancel_disconnected_task(session_id, 60))
            self._disconnect_cleanup[session_id] = cleanup

    async def _cancel_disconnected_task(self, session_id: str, grace_seconds: int):
        try:
            await asyncio.sleep(grace_seconds)
            if session_id not in self.connections:
                task = self.tasks.pop(session_id, None)
                if task and not task.done():
                    task.cancel()
        except asyncio.CancelledError:
            pass
        finally:
            self._disconnect_cleanup.pop(session_id, None)

    def _decorate_run_event(self, session_id: str, message: Dict) -> Dict:
        message_type = message.get("type")
        if message_type not in RUN_EVENT_TYPES:
            return message

        state = memory_store.get_session(session_id) or {}
        payload = dict(message.get("payload") or {})
        run_id = payload.get("run_id") or state.get("run_id") or session_id
        self._event_sequences[run_id] = self._event_sequences.get(run_id, 0) + 1

        details = payload.get("details") if isinstance(payload.get("details"), dict) else {}
        tool = payload.get("tool") or payload.get("tool_name") or details.get("tool")
        if not tool and message_type == "workflow_log" and payload.get("node") == "execute_task":
            tool = state.get("current_tool") or state.get("current_task") or state.get("next_task")
        if message_type.startswith("task_") or message_type.startswith("direct_tool_") or message_type == "tool_progress":
            step_id = f"tool:{tool or 'unknown'}"
        elif message_type.startswith("report_"):
            step_id = "report"
        elif message_type == "ai_decision":
            step_id = f"decision:{payload.get('next_task') or 'next'}"
        elif message_type == "workflow_log":
            step_id = f"tool:{tool}" if tool else f"workflow:{payload.get('node') or 'log'}"
        else:
            step_id = payload.get("step_id") or "scan"

        status_map = {
            "scan_completed": "completed", "scan_cancelled": "cancelled", "scan_terminated": "failed",
            "task_started": "running", "task_completed": "completed", "task_error": "failed",
            "task_skipped": "skipped", "direct_tool_started": "running",
            "direct_tool_completed": "completed", "direct_tool_error": "failed",
            "report_generation_started": "running", "report_generated": "completed", "report_error": "failed",
            "interaction_required": "waiting", "high_risk_vulnerability_detected": "waiting",
            "tool_confirm_required": "waiting",
        }
        payload.update({
            "run_id": run_id,
            "run_type": payload.get("run_type") or state.get("run_type", "interactive"),
            "step_id": payload.get("step_id") or details.get("step_id") or step_id,
            "sequence": self._event_sequences[run_id],
            "event": message_type,
            "status": payload.get("status") or details.get("task_status") or status_map.get(message_type, "running"),
            "timestamp": payload.get("timestamp") or datetime.now().isoformat(),
        })
        decorated = {**message, "payload": payload}
        if message_type != "run_snapshot":
            history = self._run_events.setdefault(run_id, [])
            history.append(decorated)
            if len(history) > 500:
                del history[:-500]
        return decorated

    async def _send_run_snapshot(self, session_id: str, state: Dict):
        pending_interaction = memory_store.get_pending_interaction(session_id)
        await self._send(session_id, {
            "type": "run_snapshot",
            "payload": {
                "run_id": state.get("run_id") or session_id,
                "target": state.get("target", ""),
                "mode": state.get("mode", ""),
                "completed_tasks": state.get("completed_tasks", []),
                "failed_tasks": state.get("failed_tasks", []),
                "tool_results": state.get("tool_results", {}),
                "is_complete": state.get("is_complete", False),
                "total_tasks": scan_total_tasks(state),
                "progress": state.get("progress", 0),
                "current_tool": state.get("current_tool", ""),
                "current_task": state.get("current_task", ""),
                "scan_status": state.get("scan_status", ""),
                "cancelled": state.get("cancelled", False),
                "run_type": state.get("run_type", "interactive"),
                "vulnerabilities": state.get("vulnerabilities", []),
                "errors": state.get("errors", []),
                "report": state.get("report", ""),
                "report_url": state.get("report_url", ""),
                "report_id": state.get("report_id", ""),
                "html_report_url": state.get("html_report_url", ""),
                # The persisted scan state is not enough to reconstruct the
                # active form after a reconnect.  Include the authoritative
                # pending interaction so the client can discard stale cards
                # restored from localStorage.
                "pending_interaction": self._pending_for_client(session_id, pending_interaction),
                "logs": log_collector.get_logs(session_id)[-100:],
            },
        })
    
    async def _send(self, session_id: str, message: Dict):
        message = self._decorate_run_event(session_id, message)
        if ws := self.connections.get(session_id):
            try:
                await ws.send_json(message)
            except Exception as e:
                logger.error(f"发送消息失败: {e}")

    def _pending_for_client(self, session_id: str, pending: Optional[Dict]) -> Optional[Dict]:
        """Add routing metadata to a pending interaction replay."""
        if not pending:
            return None
        state = memory_store.get_session(session_id) or {}
        message = dict(pending)
        payload = dict(message.get("payload") or {})
        payload.setdefault("session_id", session_id)
        if state.get("run_id"):
            payload.setdefault("run_id", state["run_id"])
        message["payload"] = payload
        message.setdefault("session_id", session_id)
        return message

    async def _send_multi(self, session_id: str, message: Dict):
        """向所有订阅了 session_id 的连接发送消息（用于后台任务事件广播）"""
        if (
            session_id in self._cancelled_automatic_sessions
            and message.get("type") != "scan_cancelled"
        ):
            return
        message = self._decorate_run_event(session_id, message)
        # 在消息 payload 中注入 session_id，供前端路由
        payload = dict(message.get("payload") or {})
        if "session_id" not in payload:
            payload["session_id"] = session_id
            message["payload"] = payload
        for client_id, sessions in self._subscriptions.items():
            if session_id in sessions:
                # 找到 client_id 对应的 WebSocket
                for ws_conn, cid in self._ws_to_client.items():
                    if cid == client_id:
                        try:
                            await ws_conn.send_json(message)
                        except Exception as e:
                            logger.error(f"广播消息失败: {e}")
                        break
    
    async def _send_error(self, session_id: str, error: str, error_code: str = None, **extra):
        if error_code:
            error_response = create_error_response(error_code, custom_message=error, details=extra)
        else:
            error_response = {
                "type": "error",
                "payload": {
                    "code": "E999",
                    "message": error,
                    "source": ErrorSource.BACKEND.value,
                    "category": ErrorCategory.EXECUTION.value,
                    "suggestion": "请查看详细错误信息，或联系技术支持",
                    "details": extra
                }
            }
        if extra.get("run_type"):
            error_response.setdefault("payload", {})["run_type"] = extra["run_type"]
        await self._send(session_id, error_response)

    async def _send_scan_completed_if_ready(
        self,
        session_id: str,
        result: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Emit one canonical completion payload after an interactive resume.

        Interactive scans can resume through several handlers (normal choice,
        high-risk confirmation, tool confirmation, script input, or an
        alternative tool).  Historically only ``user_choice`` emitted the
        final event, so a scan could finish in storage while the UI remained
        stuck on the last interaction card.  Read the durable state as the
        source of truth and include the full report fields in every completion
        event.
        """
        state = memory_store.get_session(session_id) or {}
        candidate = dict(state)
        if isinstance(result, dict):
            candidate.update(result)
        # The graph return value can be a checkpoint from just before the
        # durable merge.  Never let that stale ``False`` hide a completed
        # state that was already persisted by the resume path.
        candidate["is_complete"] = bool(
            state.get("is_complete") or (result or {}).get("is_complete")
        )
        if not candidate["is_complete"]:
            return False

        # A completion event may be replayed by a reconnect or by two related
        # confirmation handlers.  Keep the event idempotent per run.
        run_id = candidate.get("run_id") or session_id
        if run_id in self._completion_notified:
            return True
        self._completion_notified.add(run_id)

        await self._send(session_id, {
            "type": "scan_completed",
            "payload": self._build_scan_result_payload(
                candidate,
                candidate.get("target", ""),
                candidate.get("run_type", "interactive"),
            ),
        })
        return True

    def _matches_pending_interaction(self, session_id: str, payload: Dict, expected_type: str) -> bool:
        pending = memory_store.get_pending_interaction(session_id)
        if not pending or pending.get("type") != expected_type:
            logger.warning(f"[{session_id}] 忽略过期交互响应: expected={expected_type}, pending={pending and pending.get('type')}")
            return False
        interaction_id = payload.get("interaction_id")
        pending_id = pending.get("interaction_id")
        if interaction_id and pending_id and interaction_id != pending_id:
            logger.warning(f"[{session_id}] 忽略交互ID不匹配的响应: {interaction_id} != {pending_id}")
            return False
        return True
    
    async def handle_message(self, session_id: str, message: Dict):
        msg_type = message.get("type")
        payload = message.get("payload", {})

        if msg_type in SCAN_PROTOCOL_REQUESTS:
            try:
                payload = normalize_scan_protocol_payload(msg_type, payload)
            except ScanProtocolValidationError as exc:
                request_id = payload.get("request_id") if isinstance(payload, dict) else None
                await self._send_error(
                    session_id,
                    str(exc),
                    error_code="INVALID_PROTOCOL_PAYLOAD",
                    request_id=request_id or uuid4().hex,
                    protocol_version=SCAN_PROTOCOL_VERSION,
                    **exc.details,
                )
                return
        
        logger.info(f"[{session_id}] 收到WebSocket消息: type={msg_type}, payload={payload}")
        log_debug(f"收到消息: {msg_type}", category="api", node="ai_chat", session_id=session_id,
                  details={"type": msg_type})
        
        handlers = {
            "user_input": self._handle_user_input,
            "user_confirm": self._handle_user_confirm,
            "user_choice": self._handle_user_confirm,
            "pause_for_chat": self._handle_pause_for_chat,
            "resume_scan": self._handle_resume_scan,
            "start_scan": self._handle_start_scan,
            "start_auto_scan": self._handle_start_auto_scan,
            "stop_scan": self._handle_stop_scan,
            "get_history": self._handle_get_history,
            "get_status": self._handle_get_status,
            "chat": self._handle_chat,
            "execute_tool": self._handle_execute_tool,
            "script_content": self._handle_script_content,
            "script_description": self._handle_script_description,
            "input_response": self._handle_input_response,
            "subscribe": self._handle_subscribe,
            "subscribe_multi": self._handle_subscribe_multi,
            "unsubscribe": self._handle_unsubscribe,
            "high_risk_confirm": self._handle_high_risk_confirm,
            "tool_confirmed": self._handle_tool_confirmed,
            "tool_rejected": self._handle_tool_rejected,
            "alternative_selected": self._handle_alternative_selected,
            "task_error": self._handle_task_error,
        }
        
        if handler := handlers.get(msg_type):
            logger.info(f"[{session_id}] 调用处理器: {handler.__name__}")
            await handler(session_id, payload)
        else:
            logger.warning(f"[{session_id}] 未知消息类型: {msg_type}")
    
    async def _handle_user_input(self, session_id: str, payload: Dict):
        content = payload.get("content", "")
        memory_store.append_chat(session_id, "user", content)
        state = memory_store.get_session(session_id)
        if state:
            memory_store.save_session(session_id, append_chat(state, "user", content))
        await self._send(session_id, {"type": "user_message_received", "payload": {"content": content}})
    
    async def _handle_user_confirm(self, session_id: str, payload: Dict):
        choice = payload.get("choice", "confirm")

        # 兼容旧版前端：交互卡片的“聊天”仍发送 choice=3，但后端统一进入
        # 可恢复的 pause_for_chat 状态，而不是继续走普通 chat 节点。
        if str(choice) in ("3", "chat", "chat_pause", "pause_for_chat"):
            pause_payload = dict(payload)
            pause_payload.setdefault("request_id", uuid4().hex)
            pause_payload.setdefault("protocol_version", SCAN_PROTOCOL_VERSION)
            await self._handle_pause_for_chat(session_id, pause_payload)
            return
        
        orchestrator = get_agent_orchestrator()
        await orchestrator._ensure_initialized()
        
        if self._matches_pending_interaction(session_id, payload, "interaction_required"):
            logger.info(f"[{session_id}] 用户确认交互，选择: {choice}")
            
            memory_store.append_chat(session_id, "system", f"用户选择: {choice}")
            
            try:
                result = await orchestrator.resume_workflow(session_id, choice)
                
                if result:
                    await self._send(session_id, {
                        "type": "workflow_resumed",
                        "payload": {
                            "choice": choice,
                            "completed_tasks": result.get("completed_tasks", []),
                            "total_tasks": scan_total_tasks(result),
                            "is_complete": result.get("is_complete", False)
                        }
                    })
                    
                    await self._send_scan_completed_if_ready(session_id, result)
                else:
                    await self._send_error(session_id, "恢复工作流失败：会话不存在")
            except Exception as e:
                logger.error(f"[{session_id}] 恢复工作流失败: {e}")
                await self._send_error(session_id, f"恢复工作流失败: {str(e)}")
        else:
            # A browser can still submit a card restored from an earlier
            # interaction. Keep the strict ID check, but resend the current
            # pending interaction so the UI can replace the stale card.
            pending = memory_store.get_pending_interaction(session_id)
            if pending and pending.get("type") == "interaction_required":
                await self._send(session_id, self._pending_for_client(session_id, pending))
    
    async def _handle_pause_for_chat(self, session_id: str, payload: Dict):
        """Serialize pause requests so duplicate clicks/retries share one pause snapshot."""
        lock = self._workflow_locks.setdefault(session_id, asyncio.Lock())
        async with lock:
            await self._handle_pause_for_chat_impl(session_id, payload)

    async def _handle_pause_for_chat_impl(self, session_id: str, payload: Dict):
        """在人机交互节点保存可恢复的聊天暂停状态。"""
        request_id = payload.get("request_id") or uuid4().hex
        state = memory_store.get_session(session_id)
        if not state:
            await self._send_error(
                session_id,
                "扫描会话不存在",
                error_code="SCAN_SESSION_NOT_FOUND",
                request_id=request_id,
                protocol_version=SCAN_PROTOCOL_VERSION,
            )
            return

        if state.get("run_type", "interactive") != "interactive":
            await self._send_error(
                session_id,
                "只有控制台人机交互扫描支持暂停聊天",
                error_code="PAUSE_NOT_SUPPORTED",
                run_type=state.get("run_type", "interactive"),
                request_id=request_id,
                protocol_version=SCAN_PROTOCOL_VERSION,
            )
            return

        pending = memory_store.get_pending_interaction(session_id)
        if not pending or pending.get("type") != "interaction_required":
            await self._send_error(
                session_id,
                "当前不在可暂停的用户交互节点",
                error_code="PAUSE_NOT_ALLOWED",
                request_id=request_id,
                protocol_version=SCAN_PROTOCOL_VERSION,
            )
            return

        interaction_id = payload.get("interaction_id")
        pending_id = pending.get("interaction_id")
        if interaction_id and pending_id and interaction_id != pending_id:
            await self._send_error(
                session_id,
                "交互请求已过期",
                error_code="STALE_INTERACTION",
                request_id=request_id,
                protocol_version=SCAN_PROTOCOL_VERSION,
            )
            return

        if state.get("current_tool"):
            await self._send_error(
                session_id,
                "当前工具正在执行，请等待任务回到用户交互节点后再暂停",
                error_code="PAUSE_UNSAFE_BOUNDARY",
                request_id=request_id,
                protocol_version=SCAN_PROTOCOL_VERSION,
            )
            return

        existing_pause = state.get("pause_info") or {}
        if state.get("scan_status") == "paused_for_chat" and existing_pause.get("pause_id"):
            await self._send_multi(session_id, {
                "type": "scan_paused_for_chat",
                "payload": protocol_response(
                    session_id,
                    request_id,
                    pause_id=existing_pause.get("pause_id"),
                    interaction_id=existing_pause.get("interaction_id", ""),
                    next_task=existing_pause.get("next_task", ""),
                    paused_at=existing_pause.get("paused_at"),
                    expires_at=existing_pause.get("expires_at"),
                    state_version=existing_pause.get("state_version", 0),
                    status="paused",
                    chat_enabled=True,
                    can_resume=True,
                ),
            })
            return

        now = datetime.now()
        pause_id = f"{session_id}:pause:{uuid4().hex[:12]}"
        pause_info = {
            "pause_id": pause_id,
            "session_id": session_id,
            "interaction_id": pending_id or interaction_id or "",
            "source_node": state.get("workflow_node") or "user_interact",
            "next_task": state.get("next_task") or pending.get("payload", {}).get("next_task", ""),
            "status": "paused",
            "request_id": request_id,
            "protocol_version": SCAN_PROTOCOL_VERSION,
            "paused_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=int(getattr(settings, "SCAN_PAUSE_TTL", 86400)))).isoformat(),
            "state_version": memory_store.get_session_version(session_id),
        }

        state = update_state(
            state,
            scan_status="paused_for_chat",
            workflow_node="user_interact",
            pause_info=pause_info,
            chat_mode=True,
            is_complete=False,
            cancelled=False,
            last_activity_time=now.isoformat(),
        )
        version = memory_store.save_session(session_id, state)
        pause_info["state_version"] = version
        state = update_state(state, pause_info=pause_info)
        memory_store.save_session(session_id, state)
        if not memory_store.save_scan_pause(session_id, pause_info):
            await self._send_error(
                session_id,
                "扫描暂停状态持久化失败",
                error_code="PAUSE_PERSIST_FAILED",
                request_id=request_id,
                protocol_version=SCAN_PROTOCOL_VERSION,
            )
            return

        await self._send_multi(session_id, {
            "type": "scan_paused_for_chat",
            "payload": protocol_response(
                session_id,
                request_id,
                pause_id=pause_id,
                interaction_id=pause_info["interaction_id"],
                next_task=pause_info["next_task"],
                paused_at=pause_info["paused_at"],
                expires_at=pause_info["expires_at"],
                state_version=pause_info["state_version"],
                status="paused",
                chat_enabled=True,
                can_resume=True,
            ),
        })

    async def _handle_resume_scan(self, session_id: str, payload: Dict):
        """恢复聊天暂停的交互式工作流，并在恢复前重新执行 AI 决策。"""
        request_id = payload.get("request_id") or uuid4().hex
        state = memory_store.get_session(session_id)
        if not state:
            await self._send_error(
                session_id,
                "扫描会话不存在",
                error_code="SCAN_SESSION_NOT_FOUND",
                request_id=request_id,
                protocol_version=SCAN_PROTOCOL_VERSION,
            )
            return
        if state.get("run_type", "interactive") != "interactive":
            await self._send_error(
                session_id,
                "当前扫描模式不支持恢复",
                error_code="RESUME_NOT_SUPPORTED",
                request_id=request_id,
                protocol_version=SCAN_PROTOCOL_VERSION,
            )
            return

        pause_info = state.get("pause_info") or {}
        pause_id = payload.get("pause_id") or pause_info.get("pause_id")
        if state.get("scan_status") != "paused_for_chat" or not pause_id:
            await self._send_error(
                session_id,
                "当前没有可恢复的聊天暂停",
                error_code="RESUME_NOT_ALLOWED",
                request_id=request_id,
                protocol_version=SCAN_PROTOCOL_VERSION,
            )
            return
        if pause_info.get("pause_id") != pause_id:
            await self._send_error(
                session_id,
                "暂停请求已过期",
                error_code="STALE_PAUSE",
                request_id=request_id,
                protocol_version=SCAN_PROTOCOL_VERSION,
            )
            return

        lock = self._workflow_locks.setdefault(session_id, asyncio.Lock())
        async with lock:
            current = memory_store.get_session(session_id) or state
            if current.get("scan_status") != "paused_for_chat":
                await self._send_error(
                    session_id,
                    "扫描已被其他请求恢复",
                    error_code="RESUME_ALREADY_HANDLED",
                    request_id=request_id,
                    protocol_version=SCAN_PROTOCOL_VERSION,
                )
                return

            now = datetime.now()
            resuming_pause = {**pause_info, "status": "resuming", "resume_requested_at": now.isoformat()}
            current = update_state(
                current,
                scan_status="replanning",
                workflow_node="resume_after_chat",
                pause_info=resuming_pause,
                chat_mode=False,
                last_activity_time=now.isoformat(),
            )
            memory_store.save_session(session_id, current)
            memory_store.update_scan_pause(pause_id, status="resuming", resume_requested_at=now.isoformat())

            await self._send_multi(session_id, {
                "type": "scan_resume_requested",
                "payload": protocol_response(
                    session_id,
                    request_id,
                    pause_id=pause_id,
                    status="replanning",
                ),
            })

            orchestrator = get_agent_orchestrator()
            await orchestrator._ensure_initialized()
            try:
                async def _resume_ws_callback(message: Dict):
                    await self._send_multi(session_id, message)

                orchestrator.set_websocket_callback(session_id, _resume_ws_callback)
                result = await orchestrator.resume_workflow(
                    session_id,
                    {"choice": "resume_after_chat", "action": "resume_after_chat", "pause_id": pause_id},
                )
                stored = memory_store.get_session(session_id) or {}
                pending = memory_store.get_pending_interaction(session_id)
                final_status = "waiting_user" if pending else (
                    "completed" if stored.get("is_complete") else "running"
                )
                completed_pause = {
                    **pause_info,
                    "status": "resumed",
                    "resumed_at": datetime.now().isoformat(),
                }
                stored = update_state(
                    stored,
                    scan_status=final_status,
                    workflow_node="user_interact" if pending else stored.get("workflow_node", ""),
                    pause_info={},
                    chat_mode=False,
                    last_activity_time=datetime.now().isoformat(),
                )
                memory_store.save_session(session_id, stored)
                memory_store.update_scan_pause(
                    pause_id,
                    status="resumed",
                    resumed_at=completed_pause["resumed_at"],
                )

                await self._send_multi(session_id, {
                    "type": "decision_replanned",
                    "payload": protocol_response(
                        session_id,
                        request_id,
                        pause_id=pause_id,
                        decision_context_version=stored.get("decision_context_version", 0),
                        next_task=stored.get("next_task", ""),
                        scan_status=final_status,
                    ),
                })
                await self._send_multi(session_id, {
                    "type": "workflow_resumed",
                    "payload": protocol_response(
                        session_id,
                        request_id,
                        pause_id=pause_id,
                        replanned=True,
                        next_task=stored.get("next_task", ""),
                        completed_tasks=stored.get("completed_tasks", []),
                        scan_status=final_status,
                        is_complete=stored.get("is_complete", False),
                        result_available=result is not None,
                    ),
                })
                await self._send_scan_completed_if_ready(session_id, result)
            except Exception as exc:
                logger.exception(f"[{session_id}] 恢复聊天暂停失败: {exc}")
                failed_state = memory_store.get_session(session_id) or current
                failed_state = update_state(
                    failed_state,
                    scan_status="paused_for_chat",
                    workflow_node="user_interact",
                    pause_info={**pause_info, "status": "paused"},
                    chat_mode=True,
                    last_activity_time=datetime.now().isoformat(),
                )
                memory_store.save_session(session_id, failed_state)
                memory_store.update_scan_pause(pause_id, status="paused")
                await self._send_error(
                    session_id,
                    f"恢复扫描失败: {exc}",
                    error_code="RESUME_FAILED",
                    request_id=request_id,
                    protocol_version=SCAN_PROTOCOL_VERSION,
                )

    async def _handle_start_scan(self, session_id: str, payload: Dict):
        """Start an interactive scan with per-session duplicate protection."""
        lock = self._workflow_locks.setdefault(session_id, asyncio.Lock())
        async with lock:
            existing_task = self.tasks.get(session_id)
            if existing_task and not existing_task.done():
                await self._send_error(
                    session_id,
                    "当前会话已有扫描正在执行",
                    error_code="SCAN_ALREADY_RUNNING",
                    run_type="interactive",
                )
                return

            existing_state = memory_store.get_session(session_id) or {}
            if (
                existing_state.get("run_type", "interactive") == "interactive"
                and existing_state.get("target")
                and existing_state.get("scan_status") in {"scanning", "replanning", "paused_for_chat"}
                and not existing_state.get("is_complete")
                and not existing_state.get("cancelled")
            ):
                await self._send_error(
                    session_id,
                    "当前会话已有扫描正在执行",
                    error_code="SCAN_ALREADY_RUNNING",
                    run_type="interactive",
                )
                return

            await self._handle_start_scan_impl(session_id, payload)

    async def _handle_start_scan_impl(self, session_id: str, payload: Dict):
        target = payload.get("target", "")
        scan_mode = payload.get("scan_mode", "info")
        logger.info(f"[{session_id}] ========== 开始扫描请求 ==========")
        logger.info(f"[{session_id}] 原始目标: {target}")
        logger.info(f"[{session_id}] 扫描模式: {scan_mode}")
        logger.info(f"[{session_id}] 完整payload: {payload}")
        
        if not target:
            logger.error(f"[{session_id}] 目标地址为空")
            await self._send_error(session_id, "目标地址不能为空", error_code="INVALID_TARGET")
            return
        
        try:
            target = normalize_scan_target(target)
        except ValueError as exc:
            logger.error(f"[{session_id}] 目标地址格式无效: {target}")
            await self._send_error(
                session_id, 
                str(exc),
                error_code="INVALID_TARGET",
                valid_formats=["example.com", "192.168.1.1", "http://example.com", "example.com:8080"]
            )
            return
        
        mode = SCAN_MODE_MAP.get(scan_mode, "info_collection")
        logger.info(f"[{session_id}] 映射后模式: {mode}")
        
        state = create_initial_state(target=target, task_id=session_id, mode=mode)
        state["report_type"] = mode
        state["websocket_session_id"] = session_id
        state["run_id"] = f"{session_id}:{uuid4().hex[:8]}"
        state["run_type"] = "interactive"
        memory_store.save_session(session_id, state)
        
        logger.info(f"[{session_id}] 创建扫描任务，目标: {target}, 模式: {mode}")
        log_collector.add_log(session_id, "handle_start_scan", "info", f"扫描开始: 目标={target}, 模式={mode}")
        self.tasks[session_id] = asyncio.create_task(self._run_scan(session_id, target, mode, state))
        self.run_types[session_id] = "interactive"
        logger.info(f"[{session_id}] 扫描任务已创建并启动")

    async def _handle_start_auto_scan(self, session_id: str, payload: Dict):
        """启动扫描页使用的全自动扫描，不进入控制台交互图。"""
        existing_task = self.tasks.get(session_id)
        if existing_task and not existing_task.done():
            await self._send_error(
                session_id,
                "当前会话已有扫描正在执行",
                error_code="SCAN_ALREADY_RUNNING",
                run_type="automatic",
            )
            return

        try:
            target = normalize_scan_target(payload.get("target", ""))
        except ValueError as exc:
            await self._send_error(
                session_id,
                str(exc),
                error_code="INVALID_TARGET",
                valid_formats=["example.com", "192.168.1.1", "http://example.com", "example.com:8080"],
                run_type="automatic",
            )
            return

        scan_mode = payload.get("scan_mode", "info")
        if scan_mode not in SCAN_MODE_MAP:
            await self._send_error(
                session_id,
                f"不支持的扫描模式: {scan_mode}",
                error_code="INVALID_SCAN_MODE",
                run_type="automatic",
            )
            return

        mode = SCAN_MODE_MAP[scan_mode]
        state = create_initial_state(target=target, task_id=session_id, mode=mode)
        state["report_type"] = mode
        state["websocket_session_id"] = session_id
        state["run_id"] = f"{session_id}:{uuid4().hex[:8]}"
        state["run_type"] = "automatic"
        state["scan_mode"] = "全自动"
        state["scan_status"] = "queued"
        state["progress"] = 0
        memory_store.save_session(session_id, state)
        self.run_types[session_id] = "automatic"
        self._cancelled_automatic_sessions.discard(session_id)

        async def emit(message: Dict[str, Any]):
            await self._send_multi(session_id, message)

        memory_store.set_websocket_callback(session_id, emit)
        runner = AutoScanRunner(
            session_id=session_id,
            target=target,
            mode=mode,
            emit=emit,
        )
        self.tasks[session_id] = asyncio.create_task(
            self._run_auto_scan(session_id, target, runner, state)
        )

        await self._send(session_id, {
            "type": "scan_started",
            "payload": {
                "task_id": session_id,
                "session_id": session_id,
                "target": target,
                "scan_mode": scan_mode,
                "mode": mode,
                "run_type": "automatic",
                "status": "running",
            },
        })

    async def _run_auto_scan(
        self,
        session_id: str,
        target: str,
        runner: AutoScanRunner,
        state: Dict[str, Any],
    ):
        logger.info(f"[{session_id}] 全自动扫描开始: target={target}, mode={runner.mode}")
        try:
            result = await runner.run(state)
            memory_store.save_session(session_id, result)
            await self._send(session_id, {
                "type": "scan_completed",
                "payload": self._build_scan_result_payload(result, target, "automatic"),
            })
        except asyncio.CancelledError:
            logger.info(f"[{session_id}] 全自动扫描任务已取消")
            raise
        except Exception as exc:
            logger.exception(f"[{session_id}] 全自动扫描异常: {exc}")
            current = memory_store.get_session(session_id) or state
            errors = list(current.get("errors", []))
            errors.append(str(exc))
            current = update_state(
                current,
                errors=errors,
                is_complete=True,
                scan_status="failed",
                run_type="automatic",
            )
            memory_store.save_session(session_id, current)
            await self._send_error(
                session_id,
                f"全自动扫描失败: {exc}",
                error_code="AUTO_SCAN_FAILED",
                run_type="automatic",
            )
        finally:
            if memory_store.get_websocket_callback(session_id) is not None:
                memory_store.clear_websocket_callback(session_id)

    @staticmethod
    def _build_scan_result_payload(state: Dict[str, Any], target: str, run_type: str) -> Dict[str, Any]:
        return {
            "session_id": state.get("task_id", ""),
            "target": target,
            "mode": state.get("mode", ""),
            "report_type": state.get("report_type", state.get("mode", "")),
            "scan_mode": state.get("scan_mode", "全自动"),
            "run_type": run_type,
            "completed_tasks": state.get("completed_tasks", []),
            "failed_tasks": state.get("failed_tasks", []),
            "tool_results": state.get("tool_results", {}),
            "information_results": collect_information_results(state.get("tool_results", {})),
            "vulnerabilities": state.get("vulnerabilities", []),
            "vulnerabilities_count": len(state.get("vulnerabilities", [])),
            "errors": state.get("errors", []),
            "scan_status": state.get("scan_status", ""),
            "current_tool": state.get("current_tool", ""),
            "current_task": state.get("current_task", ""),
            "cancelled": state.get("cancelled", False),
            "scan_summary": state.get("scan_summary", {}),
            "report": state.get("report", ""),
            "report_url": state.get("report_url", ""),
            "report_id": state.get("report_id", ""),
            "html_report_url": state.get("html_report_url", ""),
            "progress": state.get("progress", 100),
        }
    
    async def _run_scan(self, session_id: str, target: str, mode: str, state: Dict):
        logger.info(f"[{session_id}] ========== _run_scan 开始执行 ==========")
        log_collector.add_log(session_id, "run_scan", "info", f"扫描执行开始: 目标={target}, 模式={mode}")
        logger.info(f"[{session_id}] 目标: {target}, 模式: {mode}")
        
        orchestrator = get_agent_orchestrator()
        logger.info(f"[{session_id}] 获取到 orchestrator 实例")
        
        await orchestrator._ensure_initialized()
        logger.info(f"[{session_id}] orchestrator 初始化完成")
        
        async def _ws_callback(message: Dict):
            logger.debug(f"[{session_id}] WebSocket 回调消息: {message.get('type', 'unknown')}")
            await self._send_multi(session_id, message)
        
        orchestrator.set_websocket_callback(session_id, _ws_callback)
        logger.info(f"[{session_id}] WebSocket 回调已设置")
        
        try:
            await self._send(session_id, {"type": "scan_started", "payload": {"task_id": session_id, "target": target}})
            logger.info(f"[{session_id}] scan_started 消息已发送")
            
            methods = {
                "full_scan": orchestrator.run_full_scan,
                "info_collection": orchestrator.run_info_collection,
                "vuln_scan": orchestrator.run_vuln_scan
            }
            method = methods.get(mode, orchestrator.run_info_collection)
            logger.info(f"[{session_id}] 调用扫描方法: {method.__name__}")
            
            result = await method(state)
            logger.info(f"[{session_id}] 扫描方法执行完成，结果类型: {type(result)}")
            
            if result and result.get("__interrupt__"):
                logger.info(f"[{session_id}] 工作流中断，等待用户交互")
                persisted_result, _ = orchestrator._merge_workflow_result(session_id, result)
                if persisted_result:
                    memory_store.save_session(session_id, persisted_result)
                return
            
            persisted_result, _ = orchestrator._merge_workflow_result(session_id, result)
            if persisted_result:
                memory_store.save_session(session_id, persisted_result)
            
            await self._send_scan_completed_if_ready(session_id, result)
        except asyncio.CancelledError:
            await self._send(session_id, {"type": "scan_cancelled", "payload": {"session_id": session_id}})
        except Exception as e:
            logger.error(f"[{session_id}] 扫描任务异常: {e}")
            await self._send_error(session_id, str(e))
    
    async def _handle_get_history(self, session_id: str, payload: Dict):
        history = memory_store.get_chat_history(session_id)
        await self._send(session_id, {"type": "history", "payload": {"history": history}})
    
    async def _handle_get_status(self, session_id: str, payload: Dict):
        state = memory_store.get_session(session_id)
        if state:
            await self._send(session_id, {
                "type": "status",
                "payload": {
                    "state": {
                        "task_id": state.get("task_id", ""),
                        "target": state.get("target", ""),
                        "mode": state.get("mode", ""),
                        "report_type": state.get("report_type", state.get("mode", "")),
                        "planned_tasks": state.get("planned_tasks", []),
                        "total_tasks": scan_total_tasks(state),
                        "completed_tasks": state.get("completed_tasks", []),
                        "failed_tasks": state.get("failed_tasks", []),
                        "tool_results": state.get("tool_results", {}),
                        "information_results": collect_information_results(state.get("tool_results", {})),
                        "vulnerabilities": state.get("vulnerabilities", []),
                        "errors": state.get("errors", []),
                        "report": state.get("report", ""),
                        "is_complete": state.get("is_complete", False),
                        "progress": state.get("progress", 0),
                        "current_tool": state.get("current_tool", ""),
                        "current_task": state.get("current_task", ""),
                        "scan_status": state.get("scan_status", ""),
                        "cancelled": state.get("cancelled", False),
                        "run_type": state.get("run_type", "interactive"),
                        "state_version": state.get("state_version", 0),
                        "workflow_node": state.get("workflow_node", ""),
                        "pause_info": state.get("pause_info", {}),
                        "chat_mode": state.get("chat_mode", False),
                        "decision_context_version": state.get("decision_context_version", 0),
                        "report_url": state.get("report_url", ""),
                        "report_id": state.get("report_id", ""),
                        "html_report_url": state.get("html_report_url", ""),
                        "pending_interaction": memory_store.get_pending_interaction(session_id),
                    }
                }
            })
        else:
            await self._send(session_id, {"type": "status", "payload": {"state": None}})
    
    async def _handle_chat(self, session_id: str, payload: Dict):
        content = payload.get("content", "")
        if not content:
            return
        
        try:
            state = memory_store.get_session(session_id) or {}
            is_paused_scan_chat = state.get("scan_status") == "paused_for_chat"
            memory_store.append_chat(session_id, "user", content)

            if is_paused_scan_chat:
                context_version = int(state.get("decision_context_version", 0) or 0) + 1
                decision_context = build_decision_context(
                    state.get("decision_context"),
                    content,
                    version=context_version,
                    pause_id=payload.get("pause_id") or (state.get("pause_info") or {}).get("pause_id", ""),
                )
                state = update_state(
                    append_chat(state, "user", content),
                    decision_context=decision_context,
                    decision_context_version=context_version,
                    last_activity_time=datetime.now().isoformat(),
                )
                memory_store.save_session(session_id, state)

            messages = _build_chat_messages(
                state, memory_store.get_chat_history(session_id), content
            )
            logger.info(
                "[%s] 调用 MaaS 聊天接口: messages=%s, context_chars=%s, max_tokens=%s",
                session_id,
                len(messages),
                len(messages[0]["content"]),
                settings.CHAT_MAX_TOKENS,
            )
            ai_content = await self._get_maas_client().complete(
                messages=messages,
                max_tokens=settings.CHAT_MAX_TOKENS,
                timeout=settings.CHAT_AI_TIMEOUT,
                max_retries=settings.CHAT_AI_MAX_RETRIES,
                temperature=settings.LLM_TEMPERATURE,
            )
            memory_store.append_chat(session_id, "assistant", ai_content)

            if is_paused_scan_chat:
                latest = memory_store.get_session(session_id) or state
                memory_store.save_session(session_id, append_chat(latest, "assistant", ai_content))
                await self._send(session_id, {
                    "type": "decision_context_updated",
                    "payload": {
                        "session_id": session_id,
                        "pause_id": (latest.get("pause_info") or {}).get("pause_id", ""),
                        "decision_context_version": latest.get("decision_context_version", 0),
                    },
                })
            
            await self._send(session_id, {"type": "ai_message", "payload": {"content": ai_content}})
        except MaaSRequestError as e:
            logger.warning("[%s] AI对话模型请求失败 [%s]: %s", session_id, e.code, e)
            await self._send_error(
                session_id,
                str(e),
                error_code=e.code,
                retryable=e.retryable,
                message_count=len(locals().get("messages", [])),
            )
        except Exception as e:
            logger.exception("[%s] AI对话请求失败", session_id)
            await self._send_error(
                session_id,
                f"AI对话失败: {str(e)}",
                error_code="AI_MODEL_ERROR",
                provider_error=str(e),
                message_count=len(locals().get("messages", [])),
            )
    
    async def _handle_execute_tool(self, session_id: str, payload: Dict):
        tool_name = payload.get("tool_name", "")
        target = payload.get("target", "")
        
        if not tool_name or not target:
            await self._send_error(session_id, "工具名称和目标地址不能为空")
            return
        
        tool = get_tool_by_name(tool_name)
        if not tool:
            await self._send_error(session_id, f"工具 {tool_name} 不存在")
            return
        
        try:
            await self._send(session_id, {"type": "tool_execution_started", "payload": {"tool_name": tool_name, "target": target}})
            result = tool.invoke(target)
            category = tool_category(tool_name)
            await self._send(session_id, {
                "type": "tool_execution_completed",
                "payload": {
                    "tool_name": tool_name,
                    "tool_category": category,
                    "result": result,
                    "information_summary": information_items(tool_name, result) if category == "info_collection" else [],
                    "result_summary": information_summary_text(tool_name, result) if category == "info_collection" else "",
                },
            })
        except Exception as e:
            await self._send_error(session_id, f"工具执行失败: {str(e)}", tool_name=tool_name)
    
    async def _handle_script_content(self, session_id: str, payload: Dict):
        script_content = payload.get("script_content", "")
        filename = payload.get("filename", "")
        
        if not script_content:
            await self._send_error(session_id, "脚本内容不能为空", error_code="EMPTY_SCRIPT")
            return

        # Console scanning pauses the LangGraph workflow while waiting for a
        # script.  In that case the submitted content must resume the pending
        # interrupt, rather than bypassing the workflow through the standalone
        # script-management path below.
        pending = memory_store.get_pending_interaction(session_id)
        if (
            pending
            and pending.get("type") == "script_upload_request"
        ):
            if payload.get("interaction_id") != pending.get("interaction_id"):
                await self._send_error(
                    session_id,
                    "脚本上传请求已过期，请使用当前上传表单",
                    error_code="INTERACTION_ID_MISMATCH",
                    expected_interaction_id=pending.get("interaction_id"),
                )
                await self._send(session_id, self._pending_for_client(session_id, pending))
                return
            try:
                orchestrator = get_agent_orchestrator()
                await orchestrator._ensure_initialized()
                result = await orchestrator.resume_workflow(session_id, {
                    "script_content": script_content,
                    "script_name": payload.get("script_name", ""),
                    "tool_category": _requested_script_category(payload),
                })
                if result is None:
                    await self._send_error(session_id, "恢复脚本上传工作流失败")
                else:
                    await self._send(session_id, {
                        "type": "workflow_resumed",
                        "payload": {
                            "completed_tasks": result.get("completed_tasks", []),
                            "total_tasks": scan_total_tasks(result),
                            "is_complete": result.get("is_complete", False),
                            "scan_status": result.get("scan_status", "running"),
                        },
                    })
                    await self._send_scan_completed_if_ready(session_id, result)
            except Exception as exc:
                logger.exception(f"[{session_id}] 恢复脚本上传工作流失败: {exc}")
                await self._send_error(session_id, f"恢复脚本上传工作流失败: {exc}")
            return
        
        try:
            from TOSKill.AI.script_safety import (
                validate_script_full, sanitize_script_name,
                ValidationStage
            )
            
            await self._send(session_id, {
                "type": "script_upload_progress",
                "payload": {"stage": "validating", "progress": 20, "message": "正在验证脚本..."}
            })
            
            is_valid, msg, details = validate_script_full(script_content, filename)
            if not is_valid:
                await self._send(session_id, {
                    "type": "script_upload_progress",
                    "payload": {"stage": "failed", "progress": 100, "message": msg, "details": details}
                })
                await self._send_error(session_id, f"脚本验证失败: {msg}", error_code="VALIDATION_FAILED")
                return
            
            await self._send(session_id, {
                "type": "script_upload_progress",
                "payload": {"stage": "analyzing", "progress": 40, "message": "正在分析脚本..."}
            })
            
            from TOSKill.AI.tools import script_manager
            from datetime import datetime
            
            script_name = payload.get("script_name", f"custom_{datetime.now().strftime('%Y%m%d%H%M%S')}")
            safe_name, name_err = sanitize_script_name(script_name)
            script_name = safe_name or f"custom_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            
            analysis = await script_manager.analyze_script_with_ai(script_content)
            selected_category = _requested_script_category(payload) or analysis.get("category", "other")
            
            await self._send(session_id, {
                "type": "script_upload_progress",
                "payload": {"stage": "registering", "progress": 70, "message": "正在注册工具..."}
            })
            
            # 保留用户输入的脚本名称；只有名称为空时才使用 AI 分析名称/默认名称。
            registered_name = script_name or analysis.get("tool_name", "")
            result = script_manager.register_script_as_tool(
                script_content=script_content,
                script_name=registered_name,
                description=analysis.get("description", "自定义扫描脚本"),
                category=selected_category,
                creation_method="upload",
            )
            
            if result.get("success"):
                await self._send(session_id, {
                    "type": "script_upload_progress",
                    "payload": {"stage": "completed", "progress": 100, "message": "脚本注册成功"}
                })
                await self._send(session_id, {
                    "type": "script_registered",
                    "payload": {
                        "tool_name": result["tool_name"],
                        "description": analysis.get("description"),
                        "script_content": script_content,
                        "category": selected_category,
                        "creation_method": "upload",
                        "message": f"脚本已注册为工具: {result['tool_name']}"
                    }
                })
            else:
                await self._send(session_id, {
                    "type": "script_upload_progress",
                    "payload": {"stage": "failed", "progress": 100, "message": result.get("error", "注册失败")}
                })
                await self._send_error(session_id, result.get("error", "注册失败"), error_code="REGISTER_FAILED")
        except Exception as e:
            logger.error(f"脚本内容处理失败: {e}")
            await self._send(session_id, {
                "type": "script_upload_progress",
                "payload": {"stage": "failed", "progress": 100, "message": str(e)}
            })
            await self._send_error(session_id, f"脚本处理失败: {str(e)}")
    
    async def _handle_script_description(self, session_id: str, payload: Dict):
        description = payload.get("description", "")
        if not description:
            await self._send_error(session_id, "脚本描述不能为空", error_code="EMPTY_DESCRIPTION")
            return

        # See _handle_script_content.  A matching interaction ID keeps the
        # console workflow separate from standalone script generation in the
        # Tools view, which intentionally continues through the legacy path.
        pending = memory_store.get_pending_interaction(session_id)
        if (
            pending
            and pending.get("type") == "script_generate_request"
        ):
            if payload.get("interaction_id") != pending.get("interaction_id"):
                await self._send_error(
                    session_id,
                    "脚本生成请求已过期，请使用当前生成表单",
                    error_code="INTERACTION_ID_MISMATCH",
                    expected_interaction_id=pending.get("interaction_id"),
                )
                await self._send(session_id, self._pending_for_client(session_id, pending))
                return
            try:
                orchestrator = get_agent_orchestrator()
                await orchestrator._ensure_initialized()
                result = await orchestrator.resume_workflow(session_id, {
                    "description": description,
                    "tool_category": _requested_script_category(payload),
                })
                if result is None:
                    await self._send_error(session_id, "恢复脚本生成工作流失败")
                else:
                    await self._send(session_id, {
                        "type": "workflow_resumed",
                        "payload": {
                            "completed_tasks": result.get("completed_tasks", []),
                            "total_tasks": scan_total_tasks(result),
                            "is_complete": result.get("is_complete", False),
                            "scan_status": result.get("scan_status", "running"),
                        },
                    })
                    await self._send_scan_completed_if_ready(session_id, result)
            except Exception as exc:
                logger.exception(f"[{session_id}] 恢复脚本生成工作流失败: {exc}")
                await self._send_error(session_id, f"恢复脚本生成工作流失败: {exc}")
            return
        
        try:
            from TOSKill.AI.tools import script_manager
            from TOSKill.AI.script_safety import validate_script_full, sanitize_script_name
            from datetime import datetime
            
            await self._send(session_id, {
                "type": "script_generation_progress",
                "payload": {"stage": "analyzing", "progress": 10, "message": "正在分析需求..."}
            })
            
            await self._send(session_id, {
                "type": "script_generation_progress",
                "payload": {"stage": "generating", "progress": 30, "message": "AI正在生成脚本..."}
            })
            
            script_code = await script_manager.generate_script_with_ai(description)
            
            if not script_code:
                await self._send(session_id, {
                    "type": "script_generation_progress",
                    "payload": {"stage": "failed", "progress": 100, "message": "AI生成脚本失败"}
                })
                await self._send_error(session_id, "AI生成脚本失败", error_code="GENERATION_FAILED")
                return
            
            await self._send(session_id, {
                "type": "script_generation_progress",
                "payload": {"stage": "validating", "progress": 60, "message": "正在安全审查..."}
            })
            
            is_valid, msg, details = validate_script_full(script_code)
            if not is_valid:
                await self._send(session_id, {
                    "type": "script_generation_progress",
                    "payload": {"stage": "failed", "progress": 100, "message": f"安全审查未通过: {msg}"}
                })
                await self._send_error(session_id, f"AI生成脚本安全审查未通过: {msg}", error_code="VALIDATION_FAILED")
                return
            
            selected_category = _requested_script_category(payload) or "info_collection"
            default_name = f"ai_gen_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            tool_name = default_name
            safe_name, name_err = sanitize_script_name(tool_name)
            tool_name = safe_name or default_name
            
            # Standalone generation (Tools view) returns a preview only. The
            # final, possibly edited code is persisted exactly once through
            # POST /tools/custom after the user confirms it. Console workflow
            # generation is handled by the pending-interaction branch above.
            await self._send(session_id, {
                "type": "script_generation_progress",
                "payload": {"stage": "completed", "progress": 100, "message": "脚本生成完成，等待确认"}
            })
            await self._send(session_id, {
                "type": "script_generated",
                "payload": {
                    "tool_name": tool_name,
                    "description": description,
                    "script_code": script_code,
                    "suggested_category": selected_category,
                    "registered": False,
                    "message": "AI脚本已生成，请预览并确认注册"
                }
            })
        except MaaSRequestError as e:
            logger.warning(f"脚本生成模型请求失败 [{e.code}]: {e}")
            await self._send(session_id, {
                "type": "script_generation_progress",
                "payload": {"stage": "failed", "progress": 100, "message": str(e), "error_code": e.code}
            })
            await self._send(session_id, {
                "type": "script_error",
                "payload": {"error": str(e), "error_code": e.code, "retryable": e.retryable}
            })
        except Exception as e:
            logger.error(f"脚本生成处理失败: {e}")
            await self._send(session_id, {
                "type": "script_generation_progress",
                "payload": {"stage": "failed", "progress": 100, "message": str(e)}
            })
            await self._send_error(session_id, f"脚本生成失败: {str(e)}")
    
    async def _handle_input_response(self, session_id: str, payload: Dict):
        field = payload.get("field", "")
        value = payload.get("value", "")
        state = memory_store.get_session(session_id)
        if state and field:
            from TOSKill.AI.state import update_state
            memory_store.save_session(session_id, update_state(state, **{field: value}))
            await self._send(session_id, {
                "type": "input_received",
                "payload": {"field": field, "value": value}
            })
            logger.info(f"[{session_id}] 输入响应: {field}={value}")
    
    async def _handle_stop_scan(self, session_id: str, payload: Dict):
        """停止指定会话的扫描任务"""
        if self.run_types.get(session_id) == "automatic":
            self._cancelled_automatic_sessions.add(session_id)
            task = self.tasks.get(session_id)
            if task and not task.done():
                task.cancel()
                try:
                    await asyncio.wait_for(task, timeout=5.0)
                except (asyncio.CancelledError, asyncio.TimeoutError):
                    pass
            self.tasks.pop(session_id, None)

            state = memory_store.get_session(session_id)
            if state:
                state = update_state(
                    state,
                    is_complete=True,
                    cancelled=True,
                    scan_status="cancelled",
                    run_type="automatic",
                )
                memory_store.save_session(session_id, state)
            memory_store.clear_websocket_callback(session_id)

            await self._send_multi(session_id, {
                "type": "scan_cancelled",
                "payload": {
                    "session_id": session_id,
                    "run_type": "automatic",
                    "reason": "用户手动停止",
                    "completed_tasks": state.get("completed_tasks", []) if state else [],
                    "tool_results": state.get("tool_results", {}) if state else {},
                    "information_results": collect_information_results(state.get("tool_results", {})) if state else [],
                    "vulnerabilities": state.get("vulnerabilities", []) if state else [],
                    "errors": state.get("errors", []) if state else [],
                    "progress": state.get("progress", 0) if state else 0,
                },
            })
            logger.info(f"[{session_id}] 全自动扫描已停止")
            return

        task = self.tasks.get(session_id)
        if task and not task.done():
            task.cancel()
            try:
                await asyncio.wait_for(task, timeout=5.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
        self.tasks.pop(session_id, None)

        # 清理 orchestrator 中的运行任务
        orchestrator = get_agent_orchestrator()
        running_task = getattr(orchestrator, '_running_tasks', {}).pop(session_id, None)
        if running_task and not running_task.done():
            running_task.cancel()

        # 更新 memory_store 状态
        state = memory_store.get_session(session_id)
        if state:
            state["is_complete"] = True
            state["cancelled"] = True
            memory_store.save_session(session_id, state)

        await self._send_multi(session_id, {
            "type": "scan_cancelled",
            "payload": {"session_id": session_id, "reason": "用户手动停止"}
        })
        logger.info(f"[{session_id}] 扫描已停止")

    async def _handle_subscribe_multi(self, session_id: str, payload: Dict):
        """订阅多个会话（不取消旧订阅）"""
        ws_conn = self.connections.get(session_id)
        if not ws_conn:
            return
        client_id = self._ws_to_client.get(ws_conn)
        if not client_id:
            return
        target_sessions = payload.get("session_ids", [])
        for sid in target_sessions:
            self._subscriptions.setdefault(client_id, set()).add(sid)
            # 如果该会话有运行中的任务，发送快照
            state = memory_store.get_session(sid)
            if state and state.get("target"):
                await self._send_run_snapshot(sid, state)
                pending = memory_store.get_pending_interaction(sid)
                if pending:
                    await ws_conn.send_json(self._pending_for_client(sid, pending))
        logger.info(f"[{session_id}] 多会话订阅: {target_sessions}")

    async def _handle_unsubscribe(self, session_id: str, payload: Dict):
        """取消订阅某个会话"""
        ws_conn = self.connections.get(session_id)
        if not ws_conn:
            return
        client_id = self._ws_to_client.get(ws_conn)
        if not client_id:
            return
        target_sid = payload.get("session_id")
        if target_sid and target_sid != session_id:
            self._subscriptions.get(client_id, set()).discard(target_sid)
            logger.info(f"[{session_id}] 取消订阅: {target_sid}")

    async def _handle_subscribe(self, session_id: str, payload: Dict):
        subscribe_id = payload.get("session_id", "")
        if not subscribe_id:
            await self._send_error(session_id, "订阅的会话ID不能为空")
            return
        
        state = memory_store.get_session(subscribe_id)
        if not state:
            state = create_initial_state(target="", task_id=subscribe_id)
            memory_store.save_session(subscribe_id, state)
        
        old_ws = self.connections.pop(session_id, None)
        old_session = session_id
        self.connections[subscribe_id] = self.connections.get(session_id) or old_ws
        if old_session != subscribe_id:
            self.connections.pop(old_session, None)
        
        await self._send(subscribe_id, {
            "type": "subscribed",
            "payload": {
                "session_id": subscribe_id,
                "available_tools": get_all_tool_names(),
                "state": {
                    "task_id": state.get("task_id", ""),
                    "target": state.get("target", ""),
                    "mode": state.get("mode", ""),
                    "run_id": state.get("run_id", ""),
                    "planned_tasks": state.get("planned_tasks", []),
                    "total_tasks": scan_total_tasks(state),
                    "completed_tasks": state.get("completed_tasks", []),
                    "failed_tasks": state.get("failed_tasks", []),
                    "is_complete": state.get("is_complete", False),
                    "scan_status": state.get("scan_status", ""),
                    "current_task": state.get("current_task", ""),
                    "next_task": state.get("next_task", ""),
                    "pending_interaction": memory_store.get_pending_interaction(subscribe_id),
                }
            }
        })
        pending = memory_store.get_pending_interaction(subscribe_id)
        if pending:
            await self._send(subscribe_id, self._pending_for_client(subscribe_id, pending))
        logger.info(f"会话订阅: {old_session} -> {subscribe_id}")
    
    async def _handle_high_risk_confirm(self, session_id: str, payload: Dict):
        """处理高危漏洞确认"""
        choice = payload.get("choice", "continue")

        if not self._matches_pending_interaction(session_id, payload, "high_risk_vulnerability_detected"):
            return
        
        state = memory_store.get_session(session_id)
        if not state:
            await self._send_error(session_id, "会话不存在")
            return
        
        memory_store.update_session(session_id, confirmed=True, user_choice=choice)
        
        orchestrator = get_agent_orchestrator()
        await orchestrator._ensure_initialized()
        result = await orchestrator.resume_workflow(session_id, choice)
        
        await self._send(session_id, {
            "type": "high_risk_confirmed",
            "payload": {"choice": choice, "resumed": result is not None}
        })
        await self._send_scan_completed_if_ready(session_id, result)
        logger.info(f"[{session_id}] 高危漏洞确认: {choice}")

    async def _handle_tool_confirmed(self, session_id: str, payload: Dict):
        orchestrator = get_agent_orchestrator()
        await orchestrator._ensure_initialized()

        if self._matches_pending_interaction(session_id, payload, "tool_confirm_required"):
            logger.info(f"[{session_id}] 用户确认执行工具")
            memory_store.append_chat(session_id, "system", "用户确认执行工具")

            try:
                await self._send(session_id, {
                    "type": "tool_execution_proceed",
                    "payload": {"status": "executing"}
                })
                result = await orchestrator.resume_workflow(session_id, {"confirmed": True})
                await self._send_scan_completed_if_ready(session_id, result)
            except Exception as e:
                logger.error(f"[{session_id}] 恢复工作流失败: {e}")
                await self._send_error(session_id, f"恢复工作流失败: {str(e)}")

    async def _handle_tool_rejected(self, session_id: str, payload: Dict):
        orchestrator = get_agent_orchestrator()
        await orchestrator._ensure_initialized()

        if self._matches_pending_interaction(session_id, payload, "tool_confirm_required"):
            logger.info(f"[{session_id}] 用户拒绝执行工具")
            memory_store.append_chat(session_id, "system", "用户拒绝执行工具，等待替代方案")

            try:
                result = await orchestrator.resume_workflow(session_id, {"confirmed": False})
                if result:
                    await self._send(session_id, {
                        "type": "tool_rejected_processing",
                        "payload": {"status": "generating_alternatives"}
                    })
                    await self._send_scan_completed_if_ready(session_id, result)
            except Exception as e:
                logger.error(f"[{session_id}] 恢复工作流失败: {e}")
                await self._send_error(session_id, f"恢复工作流失败: {str(e)}")

    async def _handle_alternative_selected(self, session_id: str, payload: Dict):
        choice_index = payload.get("choice_index", 0)
        choice_label = payload.get("choice_label", "")

        orchestrator = get_agent_orchestrator()
        await orchestrator._ensure_initialized()

        if orchestrator.has_pending_interaction(session_id):
            logger.info(f"[{session_id}] 用户选择替代方案: [{choice_index}] {choice_label}")
            memory_store.append_chat(session_id, "system", f"用户选择替代方案: {choice_label}")

            try:
                result = await orchestrator.resume_workflow(session_id, {
                    "choice_index": choice_index,
                    "choice_label": choice_label
                })
                if result:
                    await self._send(session_id, {
                        "type": "alternative_applied",
                        "payload": {"choice_index": choice_index, "choice_label": choice_label}
                    })

                    await self._send_scan_completed_if_ready(session_id, result)
            except Exception as e:
                logger.error(f"[{session_id}] 恢复工作流失败: {e}")
                await self._send_error(session_id, f"恢复工作流失败: {str(e)}")

    async def _handle_task_error(self, session_id: str, payload: Dict):
        tool = payload.get("tool", "")
        target = payload.get("target", "")
        error = payload.get("error", "")
        ai_analysis = payload.get("ai_analysis", "")

        logger.info(f"[{session_id}] 收到任务错误报告: tool={tool}, target={target}")
        if ai_analysis:
            logger.info(f"[{session_id}] AI分析结果: {ai_analysis[:200]}")

            state = memory_store.get_session(session_id)
            if state:
                errors = state.get("errors", []).copy()
                errors.append(f"[AI分析] {tool}: {ai_analysis[:300]}")
                memory_store.update_session(session_id, errors=errors)

        await self._send(session_id, {
            "type": "task_error_ack",
            "payload": {
                "tool": tool,
                "target": target,
                "ai_analysis": ai_analysis,
                "timestamp": datetime.now().isoformat()
            }
        })


manager = AIChatManager()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    session_id = None
    try:
        requested_session_id = websocket.query_params.get("session_id")
        session_id = await manager.connect(websocket, requested_session_id)
        while True:
            try:
                data = await websocket.receive_json()
                await manager.handle_message(session_id, data)
            except WebSocketDisconnect:
                break
            except json.JSONDecodeError:
                await manager._send_error(session_id, "无效的JSON格式")
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WebSocket错误: {e}")
    finally:
        if session_id:
            manager.disconnect(session_id, websocket)
