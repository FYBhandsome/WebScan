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
from TOSKill.AI.tools import get_tool_by_name, get_all_tool_names
from TOSKill.AI.log_collector import log_collector
from TOSKill.utils.error_handler import create_error_response, format_tool_error, ErrorSource, ErrorCategory
from TOSKill.utils.log_writer import log_info, log_warn, log_error, log_success, log_debug

router = APIRouter(prefix="/ai-chat", tags=["AI对话WebSocket"])
logger = logging.getLogger(__name__)


SCAN_MODE_MAP = {"info": "info_collection", "vuln": "vuln_scan", "full": "full_scan"}


class AIChatManager:
    """AI对话连接管理器"""
    
    CONFIRM_DEBOUNCE_SECONDS = 2
    
    def __init__(self):
        self.connections: Dict[str, WebSocket] = {}
        self.tasks: Dict[str, asyncio.Task] = {}
        self.llm = None
        self._last_confirm_time: Dict[str, float] = {}
    
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
                "is_complete": existing_state.get("is_complete", False)
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
        if ws := self.connections.get(session_id):
            try:
                await ws.send_json(message)
            except Exception as e:
                logger.error(f"发送消息失败: {e}")
    
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
        
        logger.info(f"[{session_id}] 收到WebSocket消息: type={msg_type}, payload={payload}")
        log_debug(f"收到消息: {msg_type}", category="api", node="ai_chat", session_id=session_id,
                  details={"type": msg_type})
        
        handlers = {
            "user_input": self._handle_user_input,
            "user_confirm": self._handle_user_confirm,
            "user_choice": self._handle_user_confirm,
            "start_scan": self._handle_start_scan,
            "get_history": self._handle_get_history,
            "get_status": self._handle_get_status,
            "chat": self._handle_chat,
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
        
        orchestrator = get_agent_orchestrator()
        await orchestrator._ensure_initialized()
        
        if orchestrator.has_pending_interaction(session_id):
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
        else:
            state = memory_store.get_session(session_id)
            if state:
                memory_store.save_session(session_id, update_state(state, user_choice="1" if choice == "confirm" else "2"))
            memory_store.append_chat(session_id, "system", f"用户选择: {choice}")
    
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
                        "completed_tasks": state.get("completed_tasks", []),
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
                result = await orchestrator.resume_workflow(session_id, {"confirmed": True})
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
        await self._send(session_id, {"type": "pong", "payload": {}})


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
