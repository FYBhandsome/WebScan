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
            "start_scan": self._handle_start_scan,
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
            memory_store.save_session(session_id, result)
            
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
