"""
AI对话WebSocket处理器

处理AI对话相关的WebSocket消息，包括：
- 用户输入处理
- 用户确认处理
- 工作流控制
- 消息广播
"""
import logging
import asyncio
import json
from typing import Dict, Any, Optional
from datetime import datetime
from uuid import uuid4

from fastapi import WebSocket, WebSocketDisconnect, APIRouter

from backend.ai_agents.memory import get_memory_manager

router = APIRouter(prefix="/ai-chat", tags=["AI对话WebSocket"])
from TOSKill.AI.state import AgentState
from TOSKill.AI.graph import get_agent_orchestrator

logger = logging.getLogger(__name__)


class AIChatConnectionManager:
    """AI对话WebSocket连接管理器"""
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.session_tasks: Dict[str, asyncio.Task] = {}
        self.session_states: Dict[str, AgentState] = {}
        
    async def connect(self, websocket: WebSocket, session_id: str = None):
        """接受WebSocket连接"""
        await websocket.accept()
        
        if session_id is None:
            session_id = str(uuid4())
        
        self.active_connections[session_id] = websocket
        
        memory_manager = get_memory_manager()
        memory_manager.create_session(session_id)
        
        logger.info(f"WebSocket连接建立: {session_id}")
        
        await self.send_message(session_id, {
            "type": "connected",
            "payload": {
                "session_id": session_id,
                "message": "WebSocket连接成功"
            }
        })
        
        return session_id
    
    def disconnect(self, session_id: str):
        """断开WebSocket连接"""
        if session_id in self.active_connections:
            del self.active_connections[session_id]
        
        if session_id in self.session_tasks:
            task = self.session_tasks[session_id]
            if not task.done():
                task.cancel()
            del self.session_tasks[session_id]
        
        if session_id in self.session_states:
            del self.session_states[session_id]
        
        logger.info(f"WebSocket连接断开: {session_id}")
    
    async def send_message(self, session_id: str, message: Dict[str, Any]):
        """发送消息到指定会话"""
        if session_id in self.active_connections:
            try:
                websocket = self.active_connections[session_id]
                await websocket.send_json(message)
                logger.debug(f"发送消息到 {session_id}: {message.get('type')}")
            except Exception as e:
                logger.error(f"发送消息失败: {e}")
    
    async def broadcast(self, message: Dict[str, Any]):
        """广播消息到所有连接"""
        for session_id in self.active_connections:
            await self.send_message(session_id, message)
    
    async def handle_message(self, session_id: str, message: Dict[str, Any]):
        """处理接收到的消息"""
        message_type = message.get("type")
        payload = message.get("payload", {})
        
        logger.info(f"收到消息 [{session_id}]: {message_type}")
        
        memory_manager = get_memory_manager()
        
        if message_type == "user_input":
            await self._handle_user_input(session_id, payload)
        
        elif message_type == "user_confirm":
            await self._handle_user_confirm(session_id, payload)
        
        elif message_type == "user_cancel":
            await self._handle_user_cancel(session_id, payload)
        
        elif message_type == "start_scan":
            await self._handle_start_scan(session_id, payload)
        
        elif message_type == "get_history":
            await self._handle_get_history(session_id)
        
        elif message_type == "get_status":
            await self._handle_get_status(session_id)
        
        else:
            logger.warning(f"未知消息类型: {message_type}")
    
    async def _handle_user_input(self, session_id: str, payload: Dict[str, Any]):
        """处理用户输入"""
        content = payload.get("content", "")
        
        memory_manager = get_memory_manager()
        memory_manager.add_message(session_id, "user", content)
        
        if session_id in self.session_states:
            state = self.session_states[session_id]
            state.append_chat_history("user", content)
        
        await self.send_message(session_id, {
            "type": "user_message_received",
            "payload": {
                "content": content,
                "timestamp": datetime.now().isoformat()
            }
        })
    
    async def _handle_user_confirm(self, session_id: str, payload: Dict[str, Any]):
        """处理用户确认"""
        choice = payload.get("choice", "confirm")
        
        if session_id in self.session_states:
            state = self.session_states[session_id]
            state.set_user_confirmation_result(choice)
            
            logger.info(f"用户确认 [{session_id}]: {choice}")
        
        memory_manager.add_message(session_id, "system", f"用户选择: {choice}")
    
    async def _handle_user_cancel(self, session_id: str, payload: Dict[str, Any]):
        """处理用户取消"""
        if session_id in self.session_tasks:
            task = self.session_tasks[session_id]
            if not task.done():
                task.cancel()
            
            await self.send_message(session_id, {
                "type": "scan_cancelled",
                "payload": {
                    "message": "扫描任务已取消"
                }
            })
        
        if session_id in self.session_states:
            state = self.session_states[session_id]
            state.set_user_confirmation_result("cancel")
    
    async def _handle_start_scan(self, session_id: str, payload: Dict[str, Any]):
        """处理开始扫描请求"""
        target = payload.get("target", "")
        scan_mode = payload.get("scan_mode", "full")
        
        if not target:
            await self.send_message(session_id, {
                "type": "error",
                "payload": {
                    "error": "目标地址不能为空"
                }
            })
            return
        
        task_id = str(uuid4())
        
        async def websocket_callback(message: Dict[str, Any]):
            await self.send_message(session_id, message)
        
        state = AgentState(
            target=target,
            task_id=task_id,
            websocket_session_id=session_id
        )
        state.set_websocket_callback(websocket_callback)
        state.update_websocket_status(True, session_id)
        
        self.session_states[session_id] = state
        
        memory_manager.add_message(session_id, "user", f"开始扫描目标: {target}")
        
        orchestrator = get_agent_orchestrator()
        
        async def run_scan():
            try:
                if scan_mode == "full":
                    await orchestrator.run_full_scan(state)
                elif scan_mode == "info":
                    await orchestrator.run_info_collection(state)
                elif scan_mode == "vuln":
                    await orchestrator.run_vuln_scan(state)
                elif scan_mode == "report":
                    await orchestrator.run_report(state)
                
                memory_manager.save_session(session_id, state.to_dict())
                
            except asyncio.CancelledError:
                logger.info(f"扫描任务被取消: {task_id}")
                await self.send_message(session_id, {
                    "type": "scan_cancelled",
                    "payload": {
                        "task_id": task_id
                    }
                })
            except Exception as e:
                logger.error(f"扫描任务失败: {e}")
                await self.send_message(session_id, {
                    "type": "error",
                    "payload": {
                        "error": str(e),
                        "task_id": task_id
                    }
                })
        
        task = asyncio.create_task(run_scan())
        self.session_tasks[session_id] = task
        
        await self.send_message(session_id, {
            "type": "scan_started",
            "payload": {
                "task_id": task_id,
                "target": target,
                "scan_mode": scan_mode
            }
        })
    
    async def _handle_get_history(self, session_id: str):
        """获取消息历史"""
        memory_manager = get_memory_manager()
        history = memory_manager.get_message_history(session_id)
        
        await self.send_message(session_id, {
            "type": "history",
            "payload": {
                "history": history
            }
        })
    
    async def _handle_get_status(self, session_id: str):
        """获取当前状态"""
        if session_id in self.session_states:
            state = self.session_states[session_id]
            
            await self.send_message(session_id, {
                "type": "status",
                "payload": {
                    "state": state.to_dict()
                }
            })
        else:
            await self.send_message(session_id, {
                "type": "status",
                "payload": {
                    "state": None,
                    "message": "无活动任务"
                }
            })


ai_chat_manager = AIChatConnectionManager()


@router.websocket("/ws")
async def ai_chat_websocket_endpoint(websocket: WebSocket):
    """AI对话WebSocket端点"""
    session_id = None
    
    try:
        session_id = await ai_chat_manager.connect(websocket)
        
        while True:
            try:
                data = await websocket.receive_json()
                await ai_chat_manager.handle_message(session_id, data)
            except WebSocketDisconnect:
                break
            except json.JSONDecodeError as e:
                logger.error(f"JSON解析错误: {e}")
                await ai_chat_manager.send_message(session_id, {
                    "type": "error",
                    "payload": {
                        "error": "无效的JSON格式"
                    }
                })
    
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WebSocket错误: {e}")
    finally:
        if session_id:
            ai_chat_manager.disconnect(session_id)


def get_ai_chat_manager() -> AIChatConnectionManager:
    """获取AI对话连接管理器"""
    return ai_chat_manager
