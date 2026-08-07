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

from TOSKill.AI.state import create_initial_state, append_chat, update_state
from TOSKill.AI.graph import memory_store, get_agent_orchestrator, get_llm as _get_llm
from TOSKill.AI.core import CHAT_SYSTEM_PROMPT
from TOSKill.AI.tools import get_tool_by_name, get_all_tool_names
from TOSKill.AI.log_collector import log_collector
from TOSKill.utils.error_handler import create_error_response, format_tool_error, ErrorSource, ErrorCategory
from TOSKill.utils.log_writer import log_info, log_warn, log_error, log_success, log_debug

router = APIRouter(prefix="/ai-chat", tags=["AI对话WebSocket"])
logger = logging.getLogger(__name__)


SCAN_MODE_MAP = {"info": "info_collection", "vuln": "vuln_scan", "full": "full_scan"}

RUN_EVENT_TYPES = {
    "scan_started", "scan_flow_started", "scan_completed", "scan_cancelled", "scan_terminated",
    "workflow_progress", "workflow_log", "tool_progress", "ai_decision", "ai_decision_complete",
    "task_started", "task_completed", "task_analysis_updated", "task_error", "task_skipped",
    "direct_tool_started", "direct_tool_completed", "direct_tool_error",
    "report_generation_started", "report_generated", "report_error", "run_snapshot",
    "interaction_required", "high_risk_vulnerability_detected", "tool_confirm_required",
}


class AIChatManager:
    """AI对话连接管理器"""
    
    def __init__(self):
        self.connections: Dict[str, WebSocket] = {}
        self.tasks: Dict[str, asyncio.Task] = {}
        self.llm = None
        self._event_sequences: Dict[str, int] = {}
        self._run_events: Dict[str, List[Dict]] = {}
        self._disconnect_cleanup: Dict[str, asyncio.Task] = {}
        # 多会话订阅：client_id -> {session_id1, session_id2, ...}
        self._subscriptions: Dict[str, set] = {}
        # WebSocket -> client_id 映射
        self._ws_to_client: Dict[WebSocket, str] = {}
    
    def _get_llm(self):
        if not self.llm:
            self.llm = _get_llm()
        return self.llm
    
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
                await websocket.send_json(pending)
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

        tool = payload.get("tool") or payload.get("tool_name")
        if not tool and message_type == "workflow_log" and payload.get("node") == "execute_task":
            tool = state.get("next_task")
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
            "step_id": payload.get("step_id") or step_id,
            "sequence": self._event_sequences[run_id],
            "event": message_type,
            "status": payload.get("status") or status_map.get(message_type, "running"),
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
                "total_tasks": len(state.get("planned_tasks", [])),
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

    async def _send_multi(self, session_id: str, message: Dict):
        """向所有订阅了 session_id 的连接发送消息（用于后台任务事件广播）"""
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
        await self._send(session_id, error_response)

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
                                "report": result.get("report", "")
                            }
                        })
                else:
                    await self._send_error(session_id, "恢复工作流失败：会话不存在")
                    
            except Exception as e:
                logger.error(f"[{session_id}] 恢复工作流失败: {e}")
                await self._send_error(session_id, f"恢复工作流失败: {str(e)}")
    
    async def _handle_start_scan(self, session_id: str, payload: Dict):
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
        
        import re
        target = target.strip()
        target_pattern = r'^[a-zA-Z0-9\.-]+(:\d+)?$|^https?://[a-zA-Z0-9\.-]+(:\d+)?(/.*)?$'
        if not re.match(target_pattern, target):
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
        state["run_id"] = f"{session_id}:{uuid4().hex[:8]}"
        memory_store.save_session(session_id, state)
        
        logger.info(f"[{session_id}] 创建扫描任务，目标: {target}, 模式: {mode}")
        log_collector.add_log(session_id, "handle_start_scan", "info", f"扫描开始: 目标={target}, 模式={mode}")
        self.tasks[session_id] = asyncio.create_task(self._run_scan(session_id, target, mode, state))
        logger.info(f"[{session_id}] 扫描任务已创建并启动")
    
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
                memory_store.save_session(session_id, result)
                return
            
            memory_store.save_session(session_id, result)
            
            if result and result.get("is_complete"):
                await self._send(session_id, {
                    "type": "scan_completed",
                    "payload": {
                        "session_id": session_id,
                        "target": target,
                        "completed_tasks": result.get("completed_tasks", []),
                        "vulnerabilities_count": len(result.get("vulnerabilities", [])),
                        "report": result.get("report", "")
                    }
                })
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
                        "planned_tasks": state.get("planned_tasks", []),
                        "total_tasks": len(state.get("planned_tasks", [])),
                        "completed_tasks": state.get("completed_tasks", []),
                        "failed_tasks": state.get("failed_tasks", []),
                        "tool_results": state.get("tool_results", {}),
                        "vulnerabilities": state.get("vulnerabilities", []),
                        "errors": state.get("errors", []),
                        "report": state.get("report", ""),
                        "is_complete": state.get("is_complete", False)
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
            state = memory_store.get_session(session_id) or {}
            scan_context = {
                "target": state.get("target", ""),
                "mode": state.get("mode", ""),
                "completed_tasks": state.get("completed_tasks", []),
                "vulnerabilities": state.get("vulnerabilities", []),
                "errors": state.get("errors", []),
                "report": state.get("report", ""),
            }
            if any(scan_context.values()):
                context_json = json.dumps(scan_context, ensure_ascii=False, default=str)
                messages.append(SystemMessage(
                    content=f"当前会话的扫描上下文如下，请结合它回答后续问题：\n{context_json[:6000]}"
                ))
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
            await self._send(session_id, {"type": "tool_execution_completed", "payload": {"tool_name": tool_name, "result": result}})
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
            
            await self._send(session_id, {
                "type": "script_generation_progress",
                "payload": {"stage": "registering", "progress": 80, "message": "正在注册工具..."}
            })
            
            analysis = await script_manager.analyze_script_with_ai(script_code)
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
            else:
                await self._send(session_id, {
                    "type": "script_generation_progress",
                    "payload": {"stage": "failed", "progress": 100, "message": result.get("error", "注册失败")}
                })
                await self._send_error(session_id, result.get("error", "注册失败"), error_code="REGISTER_FAILED")
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
                    "completed_tasks": state.get("completed_tasks", []),
                    "is_complete": state.get("is_complete", False)
                }
            }
        })
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
