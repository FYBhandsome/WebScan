"""
AI对话WebSocket处理器

处理AI对话相关的WebSocket消息，支持悬浮球对话功能。
"""
import logging
import asyncio
import json
from typing import Dict, Any, List
from datetime import datetime
from uuid import uuid4

from fastapi import WebSocket, WebSocketDisconnect, APIRouter
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage

from TOSKill.AI.state import create_initial_state, update_state
from TOSKill.AI.graph import memory_store, get_agent_orchestrator, get_llm as _get_llm
from TOSKill.AI.core import CHAT_SYSTEM_PROMPT
from TOSKill.AI.tools import get_tool_by_name, get_all_tool_names, get_tool_sequence
from TOSKill.AI.log_collector import log_collector
from TOSKill.AI.task_status_store import (
    get_task_status_store,
    STATUS_QUEUED,
    STATUS_RUNNING,
    STATUS_COMPLETED,
    STATUS_EXCEPTION,
    STATUS_WAITING_USER_INPUT,
    STATUS_WAITING_USER_CHOICE,
    STATUS_WAITING_SCRIPT_UPLOAD,
)
from TOSKill.utils.error_handler import create_error_response, format_tool_error, ErrorSource, ErrorCategory
from TOSKill.utils.log_writer import log_info, log_warn, log_error, log_success, log_debug

router = APIRouter(prefix="/ai-chat", tags=["AI对话WebSocket"])
logger = logging.getLogger(__name__)


SCAN_MODE_MAP = {"info": "info_collection", "vuln": "vuln_scan", "full": "full_scan"}


def _safe_set_task_status(task_id: str, status: str, **kwargs) -> None:
    """容错写入 TaskStatusStore，失败仅 logger.warning，不影响主流程。"""
    if not task_id:
        return
    try:
        get_task_status_store().set_status(task_id, status, **kwargs)
    except Exception as e:
        logger.warning(f"[{task_id}] set_status({status}) 失败（不影响主流程）: {e}")


def _parse_input_fields(payload: Dict) -> List[Dict]:
    """从 input_response payload 解析字段列表，兼容旧单字段格式。

    Args:
        payload: 新格式 {fields:[{field, value}]} 或旧格式 {field, value}

    Returns:
        [{"field": str, "value": str}, ...]，空列表表示无有效字段
    """
    fields_list = payload.get("fields")
    if fields_list is None:
        # 旧格式兼容 {field, value}
        f = payload.get("field", "")
        v = payload.get("value", "")
        fields_list = [{"field": f, "value": v}] if f else []

    return [
        {"field": str(item.get("field", "")), "value": item.get("value", "")}
        for item in fields_list
        if item.get("field")
    ]


def _apply_input_to_state(state: Dict, params: Dict) -> Dict:
    """将用户提交参数回填到 state 的 user_directed_params / extracted_params。

    Args:
        state: 当前会话状态
        params: {field_name: value, ...}

    Returns:
        更新后的 state（浅拷贝）
    """
    if not params:
        return state
    user_directed = dict(state.get("user_directed_params", {}))
    user_directed.update(params)
    extracted = dict(state.get("extracted_params", {}))
    extracted.update(params)
    return update_state(state, user_directed_params=user_directed, extracted_params=extracted)


def _sync_interrupt_status(session_id: str, result: Dict) -> None:
    """根据中断结果同步任务状态到 TaskStatusStore，供前端轮询。

    graph.py 的 wait_user_input 仅写 state.task_status 字段，未写 store，
    这里补写以保证轮询端点能正确返回 waiting_user_input / waiting_script_upload。
    """
    if not result:
        return
    task_status = result.get("task_status", "")
    if task_status == "waiting_user_choice":
        interaction = memory_store.get_pending_interaction(session_id) or {}
        _safe_set_task_status(session_id, STATUS_WAITING_USER_CHOICE, stage="等待用户选择", interaction=interaction.get("payload", interaction))
        return
    if task_status == "waiting_script_upload":
        _safe_set_task_status(
            session_id, STATUS_WAITING_SCRIPT_UPLOAD, stage="等待脚本上传",
            waiting_script=result.get("pending_script_request", {})
        )
    else:
        # 默认按等待用户输入处理
        _safe_set_task_status(
            session_id, STATUS_WAITING_USER_INPUT, stage="等待用户输入",
            waiting_input=result.get("pending_input_request", {})
        )


class AIChatManager:
    """AI对话连接管理器"""
    
    CONFIRM_DEBOUNCE_SECONDS = 2
    
    def __init__(self):
        self.connections: Dict[str, WebSocket] = {}
        self.tasks: Dict[str, asyncio.Task] = {}
        self.llm = None
        self._last_confirm_time: Dict[str, float] = {}
        # Serialize concurrent workflow events per session and expose a
        # monotonically increasing sequence for deterministic client rendering.
        self._send_locks: Dict[str, asyncio.Lock] = {}
        self._event_sequences: Dict[str, int] = {}
    
    def _get_llm(self):
        if not self.llm:
            self.llm = _get_llm()
        return self.llm
    
    async def connect(self, websocket: WebSocket, session_id: str = None) -> str:
        await websocket.accept()
        session_id = session_id or str(uuid4())[:8]
        self.connections[session_id] = websocket
        
        existing_state = memory_store.get_session(session_id)
        if existing_state:
            pass
        else:
            memory_store.save_session(session_id, create_initial_state(target="", task_id=session_id))
        
        async def _ws_callback(message: Dict):
            await self._send(session_id, message)
        
        memory_store.set_websocket_callback(session_id, _ws_callback)
        
        log_info("WebSocket连接建立", category="api", node="ai_chat", session_id=session_id,
                 details={"client_ip": websocket.client.host if websocket.client else "unknown", "reconnected": existing_state is not None})
        
        reconnect_payload = {
            "session_id": session_id, 
            "available_tools": get_all_tool_names()
        }
        
        if existing_state:
            reconnect_payload["reconnected"] = True
            reconnect_payload["state"] = {
                "task_id": existing_state.get("task_id", ""),
                "target": existing_state.get("target", ""),
                "mode": existing_state.get("mode", ""),
                "completed_tasks": existing_state.get("completed_tasks", []),
                "is_complete": existing_state.get("is_complete", False),
                "vulnerabilities_count": len(existing_state.get("vulnerabilities", [])),
                "risk_level": existing_state.get("risk_level", "info"),
                "risk_confidence": existing_state.get("risk_confidence", 0),
                "report_url": existing_state.get("report_url", ""),
                "report_id": existing_state.get("report_id", ""),
                "html_report_url": existing_state.get("html_report_url", ""),
                "report_analysis": existing_state.get("report_analysis", {}),
            }
            pending = memory_store.get_pending_interaction(session_id)
            if pending:
                reconnect_payload["pending_interaction"] = pending
        
        await self._send(session_id, {
            "type": "connected",
            "payload": reconnect_payload
        })
        
        if existing_state:
            pending_msgs = existing_state.get("_pending_ws_messages", [])
            if pending_msgs:
                logger.info(f"[{session_id}] 重连后重放 {len(pending_msgs)} 条缓存消息")
                for msg in pending_msgs:
                    try:
                        await self._send(session_id, msg)
                    except Exception as e:
                        logger.error(f"[{session_id}] 重放消息失败: {e}")
                        break
                memory_store.update_session(session_id, _pending_ws_messages=[])
        return session_id
    
    def disconnect(self, session_id: str):
        self.connections.pop(session_id, None)
        memory_store.clear_websocket_callback(session_id)
        if session_id in self.tasks:
            task = self.tasks[session_id]
            if not task.done():
                logger.info(f"[{session_id}] WebSocket断开，扫描任务继续运行(后台)")
            else:
                self.tasks.pop(session_id, None)
    
    async def _send(self, session_id: str, message: Dict):
        """Serialize outbound events so the UI receives a causal sequence."""
        lock = self._send_locks.get(session_id)
        if lock is None:
            lock = asyncio.Lock()
            self._send_locks[session_id] = lock
        async with lock:
            event_seq = self._event_sequences.get(session_id, 0) + 1
            outbound = dict(message)
            outbound["event_seq"] = event_seq
            outbound.setdefault("emitted_at", datetime.now().isoformat())
            delivered = await self._send_unlocked(session_id, outbound)
            if delivered:
                self._event_sequences[session_id] = event_seq

    async def _send_unlocked(self, session_id: str, message: Dict):
        """发送WebSocket消息，带连接状态检查"""
        if ws := self.connections.get(session_id):
            try:
                # 检查WebSocket连接状态
                if hasattr(ws, 'client_state'):
                    from starlette.websockets import WebSocketState
                    if ws.client_state != WebSocketState.CONNECTED:
                        logger.warning(f"[{session_id}] WebSocket未连接，清理连接 (state={ws.client_state})")
                        self.disconnect(session_id)
                        return

                await ws.send_json(message)
                return True
            except Exception as e:
                logger.error(f"[{session_id}] 发送消息失败: {e}")
                # 发送失败时清理连接
                self.disconnect(session_id)
    
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
        await self._send(session_id, error_response)
    
    async def handle_message(self, session_id: str, message: Dict):
        msg_type = message.get("type")
        payload = message.get("payload", {})
        if not isinstance(payload, dict):
            await self._send_error(
                session_id,
                "payload must be a JSON object.",
                error_code="INVALID_PAYLOAD",
            )
            return
        
        logger.info(f"[{session_id}] 收到WebSocket消息: type={msg_type}, payload={payload}")
        log_debug(f"收到消息: {msg_type}", category="api", node="ai_chat", session_id=session_id,
                  details={"type": msg_type})
        
        handlers = {
            "user_input": self._handle_user_input,
            "user_confirm": self._handle_user_confirm,
            "user_choice": self._handle_user_confirm,
            "start_scan": self._handle_start_scan,
            "stop_scan": self._handle_stop_scan,
            "get_history": self._handle_get_history,
            "get_status": self._handle_get_status,
            "chat": self._handle_chat,
            "scan_chat": self._handle_scan_chat,
            "interaction_chat": self._handle_interaction_chat,
            "decision_override": self._handle_decision_override,
            "execute_tool": self._handle_execute_tool,
            "script_content": self._handle_script_content,
            "script_description": self._handle_script_description,
            "input_response": self._handle_input_response,
            "subscribe": self._handle_subscribe,
            "high_risk_confirm": self._handle_high_risk_confirm,
            "tool_confirmed": self._handle_tool_confirmed,
            "tool_rejected": self._handle_tool_rejected,
            "alternative_selected": self._handle_alternative_selected,
            "task_error": self._handle_task_error,
            "ping": self._handle_ping,
        }
        
        if handler := handlers.get(msg_type):
            logger.info(f"[{session_id}] 调用处理器: {handler.__name__}")
            try:
                await handler(session_id, payload)
            except Exception as e:
                logger.error(f"[{session_id}] 处理器 {handler.__name__} 异常: {e}", exc_info=True)
                await self._send_error(session_id, f"处理请求失败: {str(e)}")
        else:
            logger.warning(f"[{session_id}] 未知消息类型: {msg_type}")
            await self._send_error(
                session_id,
                f"Unknown WebSocket message type: {msg_type}",
                error_code="UNKNOWN_MESSAGE_TYPE",
            )
    
    async def _handle_user_input(self, session_id: str, payload: Dict):
        content = payload.get("content", "")
        memory_store.append_chat(session_id, "user", content)
        state = memory_store.get_session(session_id)
        if state:
            memory_store.save_session(session_id, update_state(state, last_activity_time=datetime.now().isoformat()))
        await self._send(session_id, {"type": "user_message_received", "payload": {"content": content}})
    
    async def _handle_user_confirm(self, session_id: str, payload: Dict):
        import time
        now = time.time()
        last_time = self._last_confirm_time.get(session_id, 0)
        if now - last_time < self.CONFIRM_DEBOUNCE_SECONDS:
            logger.warning(f"[{session_id}] 用户确认请求过于频繁，已忽略 (间隔: {now - last_time:.1f}s)")
            return
        self._last_confirm_time[session_id] = now
        
        choice = payload.get("choice", "confirm")
        choice = str(choice)
        if choice not in {"1", "2", "3", "4", "5", "confirm"}:
            await self._send_error(session_id, "Unsupported interaction choice.", error_code="INVALID_CHOICE")
            return
        
        orchestrator = get_agent_orchestrator()
        await orchestrator._ensure_initialized()
        
        if orchestrator.has_pending_interaction(session_id):
            logger.info(f"[{session_id}] 用户确认交互，选择: {choice}")
            
            memory_store.append_chat(session_id, "system", f"用户选择: {choice}")
            
            try:
                result = await orchestrator.resume_workflow(session_id, choice)
                if result and result.get("is_complete") and not result.get("report") and result.get("tool_results"):
                    result = await orchestrator.run_report(result)

                if result and result.get("__interrupt__"):
                    if choice == "4":
                        _safe_set_task_status(
                            session_id, STATUS_WAITING_SCRIPT_UPLOAD,
                            stage="等待脚本上传",
                            waiting_script={"capability": "custom_scan", "params": []},
                        )
                    elif choice == "5":
                        _safe_set_task_status(
                            session_id, STATUS_WAITING_USER_INPUT,
                            stage="等待脚本需求描述",
                            waiting_input={
                                "context": "script_generate",
                                "fields": [{
                                    "name": "script_description", "type": "text",
                                    "description": "请描述希望 AI 生成的扫描脚本功能",
                                    "required": True,
                                }],
                            },
                        )
                    else:
                        _sync_interrupt_status(session_id, result)
                
                if result:
                    await self._send(session_id, {
                        "type": "workflow_resumed",
                        "payload": {
                            "choice": choice,
                            "completed_tasks": result.get("completed_tasks", []),
                            "is_complete": result.get("is_complete", False)
                        }
                    })
                    
                    if result.get("is_complete"):
                        await self._send(session_id, {
                            "type": "scan_completed",
                            "payload": {
                                "session_id": session_id,
                                "target": result.get("target", ""),
                                "completed_tasks": result.get("completed_tasks", []),
                                "vulnerabilities_count": len(result.get("vulnerabilities", [])),
                                "vulnerabilities": result.get("vulnerabilities", [])[:20],
                                "report": result.get("report", ""),
                                "report_url": result.get("report_url", ""),
                                "report_id": result.get("report_id", ""),
                                "html_report_url": result.get("html_report_url", ""),
                                "report_analysis": result.get("report_analysis", {}),
                                "errors": result.get("errors", [])
                            }
                        })
                else:
                    await self._send_error(session_id, "恢复工作流失败：会话不存在")
                    
            except Exception as e:
                logger.error(f"[{session_id}] 恢复工作流失败: {e}")
                await self._send_error(session_id, f"恢复工作流失败: {str(e)}")
        else:
            state = memory_store.get_session(session_id)
            if state:
                memory_store.save_session(session_id, update_state(state, user_choice="1" if choice == "confirm" else "2"))
            memory_store.append_chat(session_id, "system", f"用户选择: {choice}")
    
    async def _handle_start_scan(self, session_id: str, payload: Dict):
        target = payload.get("target", "")
        scan_mode = payload.get("scan_mode", "info")
        initial_params = payload.get("params") or {}

        previous_task = self.tasks.get(session_id)
        if previous_task and not previous_task.done():
            previous_task.cancel()
        
        logger.info(f"[{session_id}] ========== 开始扫描请求 ==========")
        logger.info(f"[{session_id}] 原始目标: {target}")
        logger.info(f"[{session_id}] 扫描模式: {scan_mode}")
        logger.info(f"[{session_id}] 完整payload: {payload}")
        
        if not target:
            logger.error(f"[{session_id}] 目标地址为空")
            await self._send_error(session_id, "目标地址不能为空", error_code="INVALID_TARGET")
            return
        if not isinstance(initial_params, dict):
            await self._send_error(session_id, "Scan parameters must be a JSON object.", error_code="INVALID_PARAMS")
            return
        
        from urllib.parse import urlparse
        target = target.strip()
        parsed_target = urlparse(target if "://" in target else f"http://{target}")
        if parsed_target.scheme not in {"http", "https"} or not parsed_target.hostname:
            logger.error(f"[{session_id}] 目标地址格式无效: {target}")
            await self._send_error(
                session_id, 
                f"目标地址格式无效: {target}", 
                error_code="INVALID_TARGET",
                valid_formats=["example.com", "192.168.1.1", "http://example.com", "example.com:8080"]
            )
            return
        
        mode = SCAN_MODE_MAP.get(scan_mode, "info_collection")
        logger.info(f"[{session_id}] 映射后模式: {mode}")
        
        state = create_initial_state(target=target, task_id=session_id, mode=mode)
        state["websocket_session_id"] = session_id
        state = update_state(
            state,
            user_directed_params=dict(initial_params),
            __extend_params=dict(initial_params),
        )
        memory_store.save_session(session_id, state)
        # SubTask 4.3: 任务入队状态同步
        _safe_set_task_status(session_id, STATUS_QUEUED, stage="排队", progress=0)

        logger.info(f"[{session_id}] 创建扫描任务，目标: {target}, 模式: {mode}")
        log_collector.add_log(session_id, "handle_start_scan", "info", f"扫描开始: 目标={target}, 模式={mode}")
        self.tasks[session_id] = asyncio.create_task(self._run_scan(session_id, target, mode, state))
        logger.info(f"[{session_id}] 扫描任务已创建并启动")

    async def _handle_stop_scan(self, session_id: str, payload: Dict):
        task = self.tasks.get(session_id)
        if task and not task.done():
            task.cancel()
            _safe_set_task_status(session_id, STATUS_EXCEPTION, stage="已取消", error="用户取消扫描")
            return

        state = memory_store.get_session(session_id)
        if state:
            memory_store.save_session(session_id, update_state(
                state,
                should_continue=False,
                task_status="cancelled",
                is_complete=False,
            ))
        await self._send(session_id, {
            "type": "scan_cancelled",
            "payload": {"session_id": session_id, "reason": "no_active_task"},
        })

    async def _run_scan(self, session_id: str, target: str, mode: str, state: Dict):
        logger.info(f"[{session_id}] ========== _run_scan 开始执行 ==========")
        log_collector.add_log(session_id, "run_scan", "info", f"扫描执行开始: 目标={target}, 模式={mode}")
        logger.info(f"[{session_id}] 目标: {target}, 模式: {mode}")
        # SubTask 4.3: 扫描启动状态同步
        _safe_set_task_status(session_id, STATUS_RUNNING, stage="扫描启动")
        
        orchestrator = get_agent_orchestrator()
        logger.info(f"[{session_id}] 获取到 orchestrator 实例")
        
        await orchestrator._ensure_initialized()
        logger.info(f"[{session_id}] orchestrator 初始化完成")
        
        async def _ws_callback(message: Dict):
            logger.debug(f"[{session_id}] WebSocket 回调消息: {message.get('type', 'unknown')}")
            await self._send(session_id, message)
        
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
            # Guarantee report generation when a mode-specific or resumed
            # graph completes without visiting the report node.
            if result and result.get("is_complete") and not result.get("report") and result.get("tool_results"):
                result = await orchestrator.run_report(result)
            logger.info(f"[{session_id}] 扫描方法执行完成，结果类型: {type(result)}")
            
            if result and result.get("__interrupt__"):
                logger.info(f"[{session_id}] 工作流中断，等待用户交互")
                memory_store.save_session(session_id, result)
                # SubTask 4.3: 同步中断状态到 store 供前端轮询
                _sync_interrupt_status(session_id, result)
                return

            memory_store.save_session(session_id, result)

            if result and result.get("is_complete"):
                from TOSKill.analysis.result_analyzer import sanitize_result_for_display
                await self._send(session_id, {
                    "type": "scan_completed",
                    "payload": {
                        "session_id": session_id,
                        "target": target,
                        "completed_tasks": result.get("completed_tasks", []),
                        "vulnerabilities_count": len(result.get("vulnerabilities", [])),
                        "vulnerabilities": sanitize_result_for_display(
                            result.get("vulnerabilities", [])[:20]
                        ),
                        "scan_summary": result.get("scan_summary", {}),
                        "risk_level": result.get("risk_level", "info"),
                        "risk_confidence": result.get("risk_confidence", 0),
                        "risk_summary": result.get("risk_summary", {}),
                        "report": result.get("report", ""),
                        "report_url": result.get("report_url", ""),
                        "report_id": result.get("report_id", ""),
                        "html_report_url": result.get("html_report_url", ""),
                        "report_analysis": result.get("report_analysis", {}),
                        "errors": result.get("errors", []),
                    }
                })
            # SubTask 4.3: 正常结束状态同步
            _safe_set_task_status(session_id, STATUS_COMPLETED, progress=100, stage="完成")
        except asyncio.CancelledError:
            await self._send(session_id, {"type": "scan_cancelled", "payload": {"session_id": session_id}})
        except Exception as e:
            logger.error(f"[{session_id}] 扫描任务异常: {e}")
            # SubTask 4.3: 异常状态同步
            _safe_set_task_status(session_id, STATUS_EXCEPTION, stage="异常", error=str(e))
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
                        "completed_tasks": state.get("completed_tasks", []),
                        "is_complete": state.get("is_complete", False),
                        "vulnerabilities_count": len(state.get("vulnerabilities", [])),
                        "risk_level": state.get("risk_level", "info"),
                        "risk_confidence": state.get("risk_confidence", 0),
                        "risk_summary": state.get("risk_summary", {}),
                        "report_url": state.get("report_url", ""),
                        "report_id": state.get("report_id", ""),
                        "html_report_url": state.get("html_report_url", ""),
                        "report_analysis": state.get("report_analysis", {}),
                        "errors": state.get("errors", []),
                    }
                }
            })
        else:
            await self._send(session_id, {"type": "status", "payload": {"state": None}})
    
    async def _handle_chat(self, session_id: str, payload: Dict):
        content = payload.get("content", "")
        if not content:
            return

        memory_store.append_chat(session_id, "user", content)

        try:
            messages = [SystemMessage(content=CHAT_SYSTEM_PROMPT)]
            for msg in memory_store.get_chat_history(session_id)[-10:]:
                if msg["role"] == "user":
                    messages.append(HumanMessage(content=msg["content"]))
                elif msg["role"] == "assistant":
                    messages.append(AIMessage(content=msg["content"]))

            if not any(isinstance(m, HumanMessage) for m in messages[1:]):
                messages.append(HumanMessage(content=content))

            response = await self._get_llm().ainvoke(messages)
            ai_content = response.content
            memory_store.append_chat(session_id, "assistant", ai_content)

            await self._send(session_id, {"type": "ai_message", "payload": {"content": ai_content}})
        except Exception as e:
            await self._send_error(session_id, f"AI对话失败: {str(e)}")

    async def _handle_scan_chat(self, session_id: str, payload: Dict):
        """扫描运行中处理用户聊天消息——支持实时干预决策

        用户交互指令优先级 > 知识库 > AI默认决策。
        将用户聊天内容写入state，供下一个扫描任务节点读取。
        """
        content = payload.get("content", "")
        if not content:
            return

        memory_store.append_chat(session_id, "user", content)

        state = memory_store.get_session(session_id)
        if not state:
            await self._send_error(session_id, "无活跃扫描会话")
            return

        # 更新user_chat_context——下一个决策节点会读取
        chat_history = memory_store.get_chat_history(session_id)
        recent_user_msgs = [m["content"] for m in chat_history[-6:] if m.get("role") == "user"]
        user_chat_context = "\n".join(recent_user_msgs[-3:]) if recent_user_msgs else content

        # 尝试提取扫描指令
        user_directed_next_task = ""
        user_directed_params = dict(state.get("user_directed_params", {}) or {})

        try:
            from TOSKill.AI.tools import get_tool_sequence
            mode = state.get("mode", "full_scan")
            remaining = [t for t in get_tool_sequence(mode)
                         if t not in state.get("completed_tasks", [])]

            import re, json
            llm = self._get_llm()
            extraction_prompt = f"""你是一个指令解析器，从用户输入中提取扫描指令和参数。

## 可用任务列表
{", ".join(remaining) if remaining else "无"}

## 当前扫描目标
{state.get("target", "")}

## 用户输入
{content}

请严格输出以下JSON格式，不要添加任何其他内容：
{{"has_directive":false,"next_task":"","params":{{}},"reason":""}}

字段说明:
- has_directive: 布尔值，用户是否指定了扫描任务
- next_task: 字符串，必须是可用任务列表中的任务名，否则为空
- params: 对象，用户提供的参数
- reason: 字符串，判断理由

现在请分析用户输入并输出JSON："""

            response = await llm.ainvoke(extraction_prompt)
            resp_text = response.content if hasattr(response, 'content') else str(response)
            json_match = re.search(r'\{[\s\S]*\}', resp_text)
            if json_match:
                extraction_result = json.loads(json_match.group())
                if extraction_result.get("has_directive") or extraction_result.get("params"):
                    directed_task = extraction_result.get("next_task", "")
                    if directed_task in remaining:
                        user_directed_next_task = directed_task
                        logger.info(f"[{session_id}] 👤 扫描中用户指令提取: next_task={directed_task}")
                    extracted_params = extraction_result.get("params", {})
                    if extracted_params:
                        user_directed_params = extracted_params
                        logger.info(f"[{session_id}] 👤 扫描中用户参数提取: params={extracted_params}")
        except Exception as e:
            logger.warning(f"[{session_id}] 扫描中用户指令提取失败（不影响流程）: {e}")

        # 更新state——下一个决策节点会读取这些字段
        updated_state = update_state(state,
            user_chat_context=user_chat_context,
            user_directed_next_task=user_directed_next_task,
            user_directed_params=user_directed_params,
            last_activity_time=datetime.now().isoformat()
        )
        memory_store.save_session(session_id, updated_state)

        # 推送确认消息
        await self._send(session_id, {
            "type": "user_directive_ack",
            "payload": {
                "received": True,
                "next_task": user_directed_next_task,
                "params": user_directed_params,
                "message": (
                    f"已接收用户指令，下一步将执行: {user_directed_next_task}"
                    if user_directed_next_task
                    else "已接收用户参数，将影响后续扫描决策"
                )
            }
        })

        logger.info(f"[{session_id}] 扫描中聊天消息已处理，user_chat_context已更新")
    
    async def _handle_interaction_chat(self, session_id: str, payload: Dict):
        """Resume a pending interaction through the graph chat branch."""
        content = str(payload.get("content", "") or "").strip()
        if not content:
            await self._send_error(session_id, "Chat content cannot be empty.", error_code="EMPTY_CHAT")
            return

        orchestrator = get_agent_orchestrator()
        await orchestrator._ensure_initialized()
        if not orchestrator.has_pending_interaction(session_id):
            await self._send_error(session_id, "No pending agent interaction.", error_code="NO_PENDING_INTERACTION")
            return

        memory_store.append_chat(session_id, "user", content)
        result = await orchestrator.resume_workflow(
            session_id,
            {"choice": "3", "chat_content": content},
        )
        if result and result.get("__interrupt__"):
            _sync_interrupt_status(session_id, result)
        await self._send(session_id, {
            "type": "workflow_resumed",
            "payload": {"choice": "3", "chat": True, "resumed": result is not None},
        })

    async def _handle_decision_override(self, session_id: str, payload: Dict):
        """Apply an explicit human decision without creating an automatic fallback."""
        state = memory_store.get_session(session_id)
        if not state:
            await self._send_error(session_id, "No active scan session.")
            return

        next_task = str(payload.get("next_task", "") or "").strip()
        params = payload.get("params") or {}
        reason = str(payload.get("reason", "") or "").strip()
        if not isinstance(params, dict):
            await self._send_error(session_id, "Decision parameters must be a JSON object.")
            return

        allowed = get_tool_sequence(state.get("mode", "full_scan"))
        completed = set(state.get("completed_tasks", []))
        if next_task and (next_task not in allowed or next_task in completed):
            repair_info = {
                "code": "INVALID_DECISION_OVERRIDE",
                "message": "The selected next task is not available in the current scan plan.",
                "suggestion": "Choose one of the unfinished tasks supplied by the decision card.",
                "available_tasks": [task for task in allowed if task not in completed],
                "mode": "no_fallback_strict",
            }
            memory_store.save_session(session_id, update_state(
                state,
                fallback_rule_set=None,
                enable_fallback=False,
                repair_required=True,
                repair_prompt_info=repair_info,
                exec_script="",
                task_status="repair_required",
            ))
            await self._send(session_id, {"type": "repair_prompt_info", "payload": repair_info})
            return

        merged_params = dict(state.get("user_directed_params", {}) or {})
        merged_params.update(params)
        updated_state = update_state(
            state,
            user_directed_next_task=next_task or state.get("user_directed_next_task", ""),
            user_directed_params=merged_params,
            user_chat_context=reason or state.get("user_chat_context", ""),
            fallback_rule_set=None,
            enable_fallback=False,
            repair_required=False,
            repair_prompt_info={},
            exec_script="",
            last_activity_time=datetime.now().isoformat(),
        )
        memory_store.save_session(session_id, updated_state)

        resumed = False
        orchestrator = get_agent_orchestrator()
        await orchestrator._ensure_initialized()
        if orchestrator.has_pending_interaction(session_id):
            result = await orchestrator.resume_workflow(session_id, {
                "choice": "1",
                "override_next_task": next_task,
                "params": params,
            })
            resumed = result is not None

        await self._send(session_id, {
            "type": "decision_override_applied",
            "payload": {
                "next_task": next_task,
                "params": params,
                "reason": reason,
                "resumed": resumed,
                "mode": "no_fallback_strict",
            }
        })

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
            params = payload.get("params") or {}
            if not isinstance(params, dict):
                await self._send_error(session_id, "Tool parameters must be a JSON object.")
                return
            await self._send(session_id, {
                "type": "tool_execution_started",
                "payload": {
                    "tool_name": tool_name,
                    "target": target,
                    "params": params,
                    "source": "direct_websocket",
                    "timestamp": datetime.now().isoformat(),
                },
            })
            orchestrator = get_agent_orchestrator()
            await orchestrator._ensure_initialized()
            result = await orchestrator.run_direct_tool(
                tool_name,
                target,
                session_id,
                websocket_callback=lambda event: self._send(session_id, event),
                params=params,
            )
            await self._send(session_id, {
                "type": "tool_execution_completed",
                "payload": {
                    "tool_name": tool_name,
                    "target": target,
                    "params": params,
                    "result": result.get("result"),
                    "formatted_result": result.get("formatted_result", ""),
                    "analysis": result.get("analysis", {}),
                    "timestamp": datetime.now().isoformat(),
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
            
            await self._send(session_id, {
                "type": "script_upload_progress",
                "payload": {"stage": "registering", "progress": 70, "message": "正在注册工具..."}
            })
            
            result = script_manager.register_script_as_tool(
                script_content=script_content,
                script_name=analysis.get("tool_name", script_name),
                description=analysis.get("description", "自定义扫描脚本"),
                category=analysis.get("category", "custom")
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
                        "message": f"脚本已注册为工具: {result['tool_name']}"
                    }
                })

                # 脚本注册成功后恢复 waiting_script_upload 中断；失败路径保持暂停
                try:
                    orchestrator = get_agent_orchestrator()
                    await orchestrator._ensure_initialized()
                    resumed_result = await orchestrator.resume_workflow(
                        session_id,
                        {
                            "script_content": script_content,
                            "script_name": result["tool_name"],
                            "tool_name": result["tool_name"],
                        },
                    )
                    if resumed_result and resumed_result.get("__interrupt__"):
                        _sync_interrupt_status(session_id, resumed_result)
                    elif resumed_result and resumed_result.get("is_complete"):
                        _safe_set_task_status(session_id, STATUS_COMPLETED, progress=100, stage="完成")
                    else:
                        _safe_set_task_status(session_id, STATUS_RUNNING, stage="恢复执行")
                    await self._send(session_id, {
                        "type": "workflow_resumed",
                        "payload": {
                            "session_id": session_id,
                            "resumed": resumed_result is not None,
                        },
                    })
                except Exception as resume_error:
                    logger.error(f"[{session_id}] 脚本注册后恢复工作流失败: {resume_error}")
                    await self._send_error(
                        session_id,
                        f"脚本注册成功，但恢复工作流失败: {resume_error}",
                        error_code="RESUME_FAILED",
                    )
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
        """处理AI脚本生成请求，带超时控制和进度反馈"""
        description = payload.get("description", "")
        if not description:
            await self._send_error(session_id, "脚本描述不能为空", error_code="EMPTY_DESCRIPTION")
            return

        try:
            from TOSKill.AI.tools import script_manager
            from TOSKill.AI.script_safety import validate_script_full, sanitize_script_name
            from datetime import datetime

            # 进度发送任务（防止WebSocket超时）
            async def send_progress_heartbeat():
                """定期发送进度心跳，保持连接活跃"""
                progress = 30
                while progress < 55:
                    try:
                        await asyncio.sleep(15)  # 每15秒发送一次
                        progress = min(progress + 5, 55)
                        await self._send(session_id, {
                            "type": "script_generation_progress",
                            "payload": {
                                "stage": "generating",
                                "progress": progress,
                                "message": f"AI正在生成脚本...{progress}%"
                            }
                        })
                    except asyncio.CancelledError:
                        break
                    except Exception as e:
                        logger.debug(f"[{session_id}] 进度心跳发送失败: {e}")
                        break

            await self._send(session_id, {
                "type": "script_generation_progress",
                "payload": {"stage": "analyzing", "progress": 10, "message": "正在分析需求..."}
            })

            await self._send(session_id, {
                "type": "script_generation_progress",
                "payload": {"stage": "generating", "progress": 30, "message": "AI正在生成脚本..."}
            })

            # 启动进度心跳任务
            heartbeat_task = asyncio.create_task(send_progress_heartbeat())

            try:
                # 添加超时控制（90秒）
                script_code = await asyncio.wait_for(
                    script_manager.generate_script_with_ai(description),
                    timeout=90.0
                )
            except asyncio.TimeoutError:
                logger.error(f"[{session_id}] AI生成脚本超时")
                await self._send(session_id, {
                    "type": "script_generation_progress",
                    "payload": {"stage": "failed", "progress": 100, "message": "AI生成脚本超时（90秒）"}
                })
                await self._send_error(session_id, "AI生成脚本超时，请稍后重试", error_code="GENERATION_TIMEOUT")
                return
            finally:
                # 取消心跳任务
                heartbeat_task.cancel()
                try:
                    await heartbeat_task
                except asyncio.CancelledError:
                    pass

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

            await self._send(session_id, {
                "type": "script_generation_progress",
                "payload": {"stage": "registering", "progress": 80, "message": "正在注册工具..."}
            })

            # 分析脚本也添加超时
            analysis = await asyncio.wait_for(
                script_manager.analyze_script_with_ai(script_code),
                timeout=30.0
            )
            default_name = f"ai_gen_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            tool_name = analysis.get("tool_name", default_name)
            safe_name, name_err = sanitize_script_name(tool_name)
            tool_name = safe_name or default_name

            result = script_manager.register_script_as_tool(
                script_content=script_code,
                script_name=tool_name,
                description=analysis.get("description", description),
                category=analysis.get("category", "custom")
            )

            if result.get("success"):
                await self._send(session_id, {
                    "type": "script_generation_progress",
                    "payload": {"stage": "completed", "progress": 100, "message": "脚本生成并注册成功"}
                })
                await self._send(session_id, {
                    "type": "script_generated",
                    "payload": {
                        "tool_name": result["tool_name"],
                        "description": analysis.get("description"),
                        "script_code": script_code,
                        "message": f"AI生成的脚本已注册为工具: {result['tool_name']}"
                    }
                })
                # A generated tool may satisfy a graph interruption caused by
                # a missing capability. Resume with the registered name just
                # as the uploaded-script path does.
                try:
                    orchestrator = get_agent_orchestrator()
                    await orchestrator._ensure_initialized()
                    resumed_result = await orchestrator.resume_workflow(
                        session_id,
                        {
                            "script_content": script_code,
                            "script_name": result["tool_name"],
                            "tool_name": result["tool_name"],
                        },
                    )
                    if resumed_result and resumed_result.get("__interrupt__"):
                        _sync_interrupt_status(session_id, resumed_result)
                    elif resumed_result and resumed_result.get("is_complete"):
                        _safe_set_task_status(session_id, STATUS_COMPLETED, progress=100, stage="completed")
                    else:
                        _safe_set_task_status(session_id, STATUS_RUNNING, stage="resumed")
                    await self._send(session_id, {
                        "type": "workflow_resumed",
                        "payload": {"session_id": session_id, "resumed": resumed_result is not None},
                    })
                except Exception as resume_error:
                    logger.error("[%s] generated script workflow resume failed: %s", session_id, resume_error)
                    await self._send_error(
                        session_id,
                        f"Script registered but workflow resume failed: {resume_error}",
                        error_code="RESUME_FAILED",
                    )
            else:
                await self._send(session_id, {
                    "type": "script_generation_progress",
                    "payload": {"stage": "failed", "progress": 100, "message": result.get("error", "注册失败")}
                })
                await self._send_error(session_id, result.get("error", "注册失败"), error_code="REGISTER_FAILED")
        except Exception as e:
            logger.error(f"[{session_id}] 脚本生成处理失败: {e}")
            await self._send(session_id, {
                "type": "script_generation_progress",
                "payload": {"stage": "failed", "progress": 100, "message": str(e)}
            })
            await self._send_error(session_id, f"脚本生成失败: {str(e)}")
    
    async def _handle_input_response(self, session_id: str, payload: Dict):
        """处理用户提交的参数输入响应（多字段结构化），回填 state 并恢复中断调度。

        兼容旧单字段格式 {field, value} 和新多字段格式 {fields:[{field, value}]}。
        resume 传入 {"params": {...}}，与 graph.py wait_user_input 的 interrupt 返回值
        处理逻辑对齐（wait_user_input 支持 {"params": {...}} 或扁平 dict 两种格式）。
        """
        fields_list = _parse_input_fields(payload)

        if not fields_list:
            await self._send_error(session_id, "input_response 缺少有效 fields", error_code="EMPTY_FIELDS")
            return

        # 构造参数 dict
        params = {item["field"]: item["value"] for item in fields_list}

        # 回填 state: user_directed_params / extracted_params / chat_history
        state = memory_store.get_session(session_id)
        if state:
            memory_store.append_chat(session_id, "user", f"用户补充参数: {params}")
            new_state = _apply_input_to_state(state, params)
            memory_store.save_session(session_id, new_state)

        # resume 恢复被 wait_user_input 中断的调度，传入 {"params": {...}} 对齐 graph.py
        try:
            orchestrator = get_agent_orchestrator()
            await orchestrator._ensure_initialized()
            result = await orchestrator.resume_workflow(session_id, {"params": params})

            # Resumed workflows can finish directly after the interrupt and
            # therefore bypass the report node; keep completion behavior
            # identical to a normal scan.
            if result and result.get("is_complete") and not result.get("report") and result.get("tool_results"):
                result = await orchestrator.run_report(result)

            # 同步任务状态
            if result and result.get("__interrupt__"):
                _sync_interrupt_status(session_id, result)
            elif result and result.get("is_complete"):
                _safe_set_task_status(session_id, STATUS_COMPLETED, progress=100, stage="完成")
            else:
                _safe_set_task_status(session_id, STATUS_RUNNING, stage="恢复执行")

            await self._send(session_id, {
                "type": "input_received",
                "payload": {"fields": fields_list, "resumed": result is not None}
            })

            # 恢复后扫描完成，推送完成消息
            if result and result.get("is_complete"):
                await self._send(session_id, {
                    "type": "scan_completed",
                    "payload": {
                        "session_id": session_id,
                        "target": result.get("target", ""),
                        "completed_tasks": result.get("completed_tasks", []),
                        "vulnerabilities_count": len(result.get("vulnerabilities", [])),
                        "vulnerabilities": result.get("vulnerabilities", [])[:20],
                        "report": result.get("report", ""),
                        "report_url": result.get("report_url", ""),
                        "report_id": result.get("report_id", ""),
                        "html_report_url": result.get("html_report_url", ""),
                        "report_analysis": result.get("report_analysis", {}),
                        "errors": result.get("errors", [])
                    }
                })

            logger.info(f"[{session_id}] 输入响应处理完成: params={params}, resumed={result is not None}")
        except Exception as e:
            logger.error(f"[{session_id}] resume_workflow 失败: {e}", exc_info=True)
            _safe_set_task_status(session_id, STATUS_EXCEPTION, stage="恢复失败", error=str(e))
            await self._send_error(session_id, f"恢复调度失败: {e}", error_code="RESUME_FAILED")
    
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
                    "completed_tasks": state.get("completed_tasks", []),
                    "is_complete": state.get("is_complete", False)
                }
            }
        })
        logger.info(f"会话订阅: {old_session} -> {subscribe_id}")
    
    async def _handle_high_risk_confirm(self, session_id: str, payload: Dict):
        """处理高危漏洞确认"""
        import time
        now = time.time()
        last_time = self._last_confirm_time.get(f"{session_id}_risk", 0)
        if now - last_time < self.CONFIRM_DEBOUNCE_SECONDS:
            logger.warning(f"[{session_id}] 高危确认请求过于频繁，已忽略")
            return
        self._last_confirm_time[f"{session_id}_risk"] = now
        
        choice = payload.get("choice", "continue")
        
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
        logger.info(f"[{session_id}] 高危漏洞确认: {choice}")

    async def _handle_tool_confirmed(self, session_id: str, payload: Dict):
        import time
        now = time.time()
        last_time = self._last_confirm_time.get(f"{session_id}_tool", 0)
        if now - last_time < self.CONFIRM_DEBOUNCE_SECONDS:
            logger.warning(f"[{session_id}] 工具确认请求过于频繁，已忽略")
            return
        self._last_confirm_time[f"{session_id}_tool"] = now
        
        orchestrator = get_agent_orchestrator()
        await orchestrator._ensure_initialized()

        if orchestrator.has_pending_interaction(session_id):
            logger.info(f"[{session_id}] 用户确认执行工具")
            memory_store.append_chat(session_id, "system", "用户确认执行工具")

            try:
                params = payload.get("params") or {}
                if not isinstance(params, dict):
                    await self._send_error(session_id, "Tool parameters must be a JSON object.")
                    return
                result = await orchestrator.resume_workflow(
                    session_id,
                    {"confirmed": True, "params": params},
                )
                if result:
                    await self._send(session_id, {
                        "type": "tool_execution_proceed",
                        "payload": {"status": "executing"}
                    })
            except Exception as e:
                logger.error(f"[{session_id}] 恢复工作流失败: {e}")
                await self._send_error(session_id, f"恢复工作流失败: {str(e)}")

    async def _handle_tool_rejected(self, session_id: str, payload: Dict):
        import time
        now = time.time()
        last_time = self._last_confirm_time.get(f"{session_id}_reject", 0)
        if now - last_time < self.CONFIRM_DEBOUNCE_SECONDS:
            logger.warning(f"[{session_id}] 工具拒绝请求过于频繁，已忽略")
            return
        self._last_confirm_time[f"{session_id}_reject"] = now
        
        orchestrator = get_agent_orchestrator()
        await orchestrator._ensure_initialized()

        if orchestrator.has_pending_interaction(session_id):
            logger.info(f"[{session_id}] 用户拒绝执行工具")
            memory_store.append_chat(session_id, "system", "用户拒绝执行工具，等待替代方案")

            try:
                result = await orchestrator.resume_workflow(session_id, {"confirmed": False})
                if result:
                    await self._send(session_id, {
                        "type": "tool_rejected_processing",
                        "payload": {"status": "generating_alternatives"}
                    })
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

                    if result.get("is_complete"):
                        await self._send(session_id, {
                            "type": "scan_completed",
                            "payload": {
                                "session_id": session_id,
                                "target": result.get("target", ""),
                                "completed_tasks": result.get("completed_tasks", []),
                                "vulnerabilities_count": len(result.get("vulnerabilities", [])),
                                "report": result.get("report", "")
                            }
                        })
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

    async def _handle_ping(self, session_id: str, payload: Dict):
        """处理心跳ping，返回pong并更新连接状态"""
        # 更新最后活动时间
        state = memory_store.get_session(session_id)
        if state:
            memory_store.save_session(session_id, update_state(state, last_activity_time=datetime.now().isoformat()))

        # 发送pong响应
        await self._send(session_id, {
            "type": "pong",
            "payload": {
                "timestamp": datetime.now().isoformat(),
                "session_id": session_id
            }
        })


manager = AIChatManager()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    session_id = None
    try:
        query_session_id = websocket.query_params.get("session_id")
        session_id = await manager.connect(websocket, session_id=query_session_id)
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
            manager.disconnect(session_id)
