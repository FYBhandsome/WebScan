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

router = APIRouter(prefix="/ai-chat", tags=["AI对话WebSocket"])
logger = logging.getLogger(__name__)


SCAN_MODE_MAP = {"info": "info_collection", "vuln": "vuln_scan", "full": "full_scan"}


class AIChatManager:
    """AI对话连接管理器"""
    
    def __init__(self):
        self.connections: Dict[str, WebSocket] = {}
        self.tasks: Dict[str, asyncio.Task] = {}
        self.llm = None
    
    def _get_llm(self):
        if not self.llm:
            self.llm = _get_llm()
        return self.llm
    
    async def connect(self, websocket: WebSocket, session_id: str = None) -> str:
        await websocket.accept()
        session_id = session_id or str(uuid4())[:8]
        self.connections[session_id] = websocket
        memory_store.save_session(session_id, create_initial_state(target="", task_id=session_id))
        
        await self._send(session_id, {
            "type": "connected",
            "payload": {"session_id": session_id, "available_tools": get_all_tool_names()}
        })
        return session_id
    
    def disconnect(self, session_id: str):
        self.connections.pop(session_id, None)
        if session_id in self.tasks:
            task = self.tasks.pop(session_id)
            if not task.done():
                task.cancel()
    
    async def _send(self, session_id: str, message: Dict):
        if ws := self.connections.get(session_id):
            try:
                await ws.send_json(message)
            except Exception as e:
                logger.error(f"发送消息失败: {e}")
    
    async def _send_error(self, session_id: str, error: str, **extra):
        await self._send(session_id, {"type": "error", "payload": {"error": error, **extra}})
    
    async def handle_message(self, session_id: str, message: Dict):
        msg_type = message.get("type")
        payload = message.get("payload", {})
        
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
        }
        
        if handler := handlers.get(msg_type):
            await handler(session_id, payload)
        else:
            logger.warning(f"未知消息类型: {msg_type}")
    
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
        if not target:
            await self._send_error(session_id, "目标地址不能为空")
            return
        
        task_id = str(uuid4())[:8]
        mode = SCAN_MODE_MAP.get(payload.get("scan_mode", "info"), "info_collection")
        state = create_initial_state(target=target, task_id=task_id, mode=mode)
        state["websocket_session_id"] = session_id
        memory_store.save_session(session_id, state)
        
        self.tasks[session_id] = asyncio.create_task(self._run_scan(session_id, task_id, target, mode, state))
    
    async def _run_scan(self, session_id: str, task_id: str, target: str, mode: str, state: Dict):
        orchestrator = get_agent_orchestrator()
        
        try:
            await self._send(session_id, {"type": "scan_started", "payload": {"task_id": task_id, "target": target}})
            
            methods = {
                "full_scan": orchestrator.run_full_scan,
                "info_collection": orchestrator.run_info_collection,
                "vuln_scan": orchestrator.run_vuln_scan
            }
            result = await methods.get(mode, orchestrator.run_info_collection)(state)
            
            if result and result.get("__interrupt__"):
                logger.info(f"[{session_id}] 工作流中断，等待用户交互")
                memory_store.save_session(session_id, result)
                return
            
            memory_store.save_session(session_id, result)
            
            if result and result.get("is_complete"):
                await self._send(session_id, {
                    "type": "scan_completed",
                    "payload": {
                        "task_id": task_id,
                        "target": target,
                        "completed_tasks": result.get("completed_tasks", []),
                        "vulnerabilities_count": len(result.get("vulnerabilities", [])),
                        "report": result.get("report", "")
                    }
                })
        except asyncio.CancelledError:
            await self._send(session_id, {"type": "scan_cancelled", "payload": {"task_id": task_id}})
        except Exception as e:
            logger.error(f"[{session_id}] 扫描任务异常: {e}")
            await self._send_error(session_id, str(e), task_id=task_id)
    
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
        if not script_content:
            await self._send_error(session_id, "脚本内容不能为空")
            return
        
        try:
            from TOSKill.AI.script_safety import validate_script_safety, sanitize_script_name
            
            is_safe, safety_err = validate_script_safety(script_content)
            if not is_safe:
                await self._send_error(session_id, f"脚本安全审查未通过: {safety_err}")
                return
            
            from TOSKill.AI.tools import script_manager
            from datetime import datetime
            script_name = payload.get("script_name", f"custom_{datetime.now().strftime('%Y%m%d%H%M%S')}")
            safe_name, name_err = sanitize_script_name(script_name)
            script_name = safe_name or f"custom_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            
            analysis = await script_manager.analyze_script_with_ai(script_content)
            result = script_manager.register_script_as_tool(
                script_content=script_content,
                script_name=analysis.get("tool_name", script_name),
                description=analysis.get("description", "自定义扫描脚本"),
                category=analysis.get("category", "custom")
            )
            
            if result.get("success"):
                await self._send(session_id, {
                    "type": "script_registered",
                    "payload": {
                        "tool_name": result["tool_name"],
                        "description": analysis.get("description"),
                        "message": f"脚本已注册为工具: {result['tool_name']}"
                    }
                })
            else:
                await self._send_error(session_id, result.get("error", "注册失败"))
        except Exception as e:
            logger.error(f"脚本内容处理失败: {e}")
            await self._send_error(session_id, f"脚本处理失败: {str(e)}")
    
    async def _handle_script_description(self, session_id: str, payload: Dict):
        description = payload.get("description", "")
        if not description:
            await self._send_error(session_id, "脚本描述不能为空")
            return
        
        try:
            from TOSKill.AI.tools import script_manager
            from TOSKill.AI.script_safety import validate_script_safety, sanitize_script_name
            from datetime import datetime
            
            await self._send(session_id, {"type": "script_generating", "payload": {"message": "AI正在生成脚本..."}})
            script_code = await script_manager.generate_script_with_ai(description)
            
            if not script_code:
                await self._send_error(session_id, "AI生成脚本失败")
                return
            
            is_safe, safety_err = validate_script_safety(script_code)
            if not is_safe:
                await self._send_error(session_id, f"AI生成脚本安全审查未通过: {safety_err}")
                return
            
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
                    "type": "script_generated",
                    "payload": {
                        "tool_name": result["tool_name"],
                        "description": analysis.get("description"),
                        "script_code": script_code,
                        "message": f"AI生成的脚本已注册为工具: {result['tool_name']}"
                    }
                })
            else:
                await self._send_error(session_id, result.get("error", "注册失败"))
        except Exception as e:
            logger.error(f"脚本生成处理失败: {e}")
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
        choice = payload.get("choice", "continue")
        
        state = memory_store.get_session(session_id)
        if not state:
            await self._send_error(session_id, "会话不存在")
            return
        
        memory_store.update_session(session_id, confirmed=True, user_choice=choice)
        
        orchestrator = get_agent_orchestrator()
        result = await orchestrator.resume_workflow(session_id, choice)
        
        await self._send(session_id, {
            "type": "high_risk_confirmed",
            "payload": {"choice": choice, "resumed": result is not None}
        })
        logger.info(f"[{session_id}] 高危漏洞确认: {choice}")

    async def _handle_tool_confirmed(self, session_id: str, payload: Dict):
        orchestrator = get_agent_orchestrator()

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
        orchestrator = get_agent_orchestrator()

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


manager = AIChatManager()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    session_id = None
    try:
        session_id = await manager.connect(websocket)
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
