"""
AI对话WebSocket处理器

处理AI对话相关的WebSocket消息，支持交互式工作流暂停/恢复。
"""
import logging
import asyncio
import json
from typing import Dict, Optional
from uuid import uuid4

from fastapi import WebSocket, WebSocketDisconnect, APIRouter
from langgraph.types import Command

from TOSKill.AI.core import (
    create_session, get_session, delete_session,
    run_scan, execute_tool, chat, get_chat_history, get_session_status,
    get_all_tool_names
)
from TOSKill.AI.state import create_initial_state, append_chat, update_state
from TOSKill.AI.graph import memory_store, get_agent_orchestrator

router = APIRouter(prefix="/ai-chat", tags=["AI对话WebSocket"])
logger = logging.getLogger(__name__)


class AIChatManager:
    """AI对话连接管理器 - 支持交互式工作流"""
    
    def __init__(self):
        self.connections: Dict[str, WebSocket] = {}
        self.scan_tasks: Dict[str, asyncio.Task] = {}
        self.pending_choices: Dict[str, asyncio.Future] = {}
    
    async def connect(self, websocket: WebSocket, session_id: str = None) -> str:
        await websocket.accept()
        session_id = session_id or str(uuid4())[:8]
        self.connections[session_id] = websocket
        memory_store.save_session(session_id, create_initial_state(target="", task_id=session_id))
        
        orchestrator = get_agent_orchestrator()
        orchestrator.set_websocket_callback(session_id, self._send_interaction_required)
        
        await self._send(session_id, {
            "type": "connected",
            "payload": {
                "session_id": session_id, 
                "available_tools": get_all_tool_names(),
                "default_mode": "full_scan"
            }
        })
        return session_id
    
    def disconnect(self, session_id: str):
        self.connections.pop(session_id, None)
        if session_id in self.scan_tasks:
            task = self.scan_tasks.pop(session_id)
            if not task.done():
                task.cancel()
        if session_id in self.pending_choices:
            future = self.pending_choices.pop(session_id)
            if not future.done():
                future.cancel()
    
    async def _send(self, session_id: str, message: Dict):
        if ws := self.connections.get(session_id):
            try:
                await ws.send_json(message)
            except Exception as e:
                logger.error(f"发送消息失败: {e}")
    
    async def _send_error(self, session_id: str, error: str, **extra):
        await self._send(session_id, {"type": "error", "payload": {"error": error, **extra}})
    
    async def _send_interaction_required(self, interaction_data: Dict):
        """发送交互请求到前端"""
        session_id = interaction_data.get("session_id")
        msg_type = interaction_data.get("type", "interaction_required")
        
        if session_id:
            await self._send(session_id, {
                "type": msg_type,
                "payload": interaction_data
            })
            logger.info(f"已发送消息: {msg_type} -> {session_id}")
    
    async def handle_message(self, session_id: str, message: Dict):
        msg_type = message.get("type")
        payload = message.get("payload", {})
        
        handlers = {
            "user_input": self._handle_user_input,
            "user_choice": self._handle_user_choice,
            "user_confirm": self._handle_user_confirm,
            "start_scan": self._handle_start_scan,
            "stop_scan": self._handle_stop_scan,
            "get_history": self._handle_get_history,
            "get_status": self._handle_get_status,
            "chat": self._handle_chat,
            "execute_tool": self._handle_execute_tool,
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
    
    async def _handle_user_choice(self, session_id: str, payload: Dict):
        """处理用户交互选择"""
        choice = payload.get("choice", "1")
        
        if session_id in self.pending_choices:
            future = self.pending_choices.pop(session_id)
            if not future.done():
                future.set_result(choice)
                logger.info(f"用户选择已设置: {choice}")
                await self._send(session_id, {
                    "type": "workflow_resumed",
                    "payload": {"choice": choice}
                })
        else:
            orchestrator = get_agent_orchestrator()
            orchestrator.resume_workflow(session_id, choice)
            await self._send(session_id, {
                "type": "workflow_resumed",
                "payload": {"choice": choice}
            })
        
        memory_store.append_chat(session_id, "system", f"用户选择: {choice}")
    
    async def _handle_user_confirm(self, session_id: str, payload: Dict):
        choice = payload.get("choice", "confirm")
        state = memory_store.get_session(session_id)
        if state:
            memory_store.save_session(session_id, update_state(state, user_choice="1" if choice == "confirm" else "2"))
        memory_store.append_chat(session_id, "system", f"用户选择: {choice}")
    
    async def _handle_start_scan(self, session_id: str, payload: Dict):
        target = payload.get("target", "")
        if not target:
            await self._send_error(session_id, "目标地址不能为空")
            return
        
        scan_mode = payload.get("scan_mode", "full")
        self.scan_tasks[session_id] = asyncio.create_task(
            self._run_interactive_scan(session_id, target, scan_mode)
        )
    
    async def _handle_stop_scan(self, session_id: str, payload: Dict):
        """停止扫描"""
        if session_id in self.scan_tasks:
            task = self.scan_tasks.pop(session_id)
            if not task.done():
                task.cancel()
            await self._send(session_id, {"type": "scan_cancelled", "payload": {}})
        
        if session_id in self.pending_choices:
            future = self.pending_choices.pop(session_id)
            if not future.done():
                future.set_result("2")
    
    async def _run_interactive_scan(self, session_id: str, target: str, mode: str):
        """运行交互式扫描流程"""
        task_id = str(uuid4())[:8]
        
        try:
            await self._send(session_id, {
                "type": "scan_started",
                "payload": {"task_id": task_id, "target": target, "mode": mode}
            })
            
            state = memory_store.get_session(session_id)
            if not state:
                state = create_initial_state(target=target, task_id=task_id)
            state = update_state(state, target=target, websocket_session_id=session_id)
            
            orchestrator = get_agent_orchestrator()
            
            async def websocket_callback(message_data: Dict):
                msg_type = message_data.get("type", "info")
                
                if msg_type == "interaction_required":
                    future = asyncio.Future()
                    self.pending_choices[session_id] = future
                    
                    await self._send(session_id, {
                        "type": "interaction_required",
                        "payload": message_data
                    })
                    
                    choice = await future
                    return choice
                else:
                    await self._send(session_id, {
                        "type": msg_type,
                        "payload": message_data.get("payload", message_data)
                    })
                    return None
            
            orchestrator.set_websocket_callback(session_id, websocket_callback)
            
            result = await run_scan(mode, target, session_id)
            
            await self._send(session_id, {
                "type": "scan_completed",
                "payload": {
                    "task_id": task_id,
                    "target": target,
                    "session_id": result.get("session_id"),
                    "completed_tasks": result.get("completed_tasks", []),
                    "vulnerabilities_count": len(result.get("vulnerabilities", [])),
                    "report": result.get("report", ""),
                    "report_url": result.get("report_url", ""),
                    "report_id": result.get("report_id", "")
                }
            })
            
        except asyncio.CancelledError:
            await self._send(session_id, {"type": "scan_cancelled", "payload": {"task_id": task_id}})
        except Exception as e:
            logger.error(f"扫描失败: {e}")
            await self._send_error(session_id, str(e), task_id=task_id)
        finally:
            self.pending_choices.pop(session_id, None)
    
    async def _handle_get_history(self, session_id: str, payload: Dict):
        history = get_chat_history(session_id)
        await self._send(session_id, {"type": "history", "payload": {"history": history}})
    
    async def _handle_get_status(self, session_id: str, payload: Dict):
        status = get_session_status(session_id)
        orchestrator = get_agent_orchestrator()
        pending = orchestrator.get_pending_interaction(session_id)
        
        await self._send(session_id, {
            "type": "status", 
            "payload": {
                "state": status,
                "waiting_for_user": pending is not None,
                "pending_interaction": pending
            }
        })
    
    async def _handle_chat(self, session_id: str, payload: Dict):
        content = payload.get("content", "")
        if not content:
            return
        
        try:
            ai_content = await chat(session_id, content)
            await self._send(session_id, {"type": "ai_message", "payload": {"content": ai_content}})
        except Exception as e:
            await self._send_error(session_id, f"AI对话失败: {str(e)}")
    
    async def _handle_execute_tool(self, session_id: str, payload: Dict):
        tool_name = payload.get("tool_name", "")
        target = payload.get("target", "")
        
        if not tool_name or not target:
            await self._send_error(session_id, "工具名称和目标地址不能为空")
            return
        
        try:
            await self._send(session_id, {
                "type": "tool_execution_started",
                "payload": {"tool_name": tool_name, "target": target}
            })
            
            result = execute_tool(tool_name, target)
            
            await self._send(session_id, {
                "type": "tool_execution_completed",
                "payload": {"tool_name": tool_name, "result": result}
            })
        except ValueError as e:
            await self._send_error(session_id, str(e), tool_name=tool_name)
        except Exception as e:
            await self._send_error(session_id, f"工具执行失败: {str(e)}", tool_name=tool_name)


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
