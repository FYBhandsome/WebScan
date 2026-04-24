from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import List, Dict, Any, Optional
import logging
import json
import asyncio
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)

router = APIRouter()

class ConnectionState(Enum):
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTING = "disconnecting"
    DISCONNECTED = "disconnected"
    ERROR = "error"

class ConnectionInfo:
    def __init__(self, websocket: WebSocket):
        self.websocket = websocket
        self.state = ConnectionState.CONNECTING
        self.connected_at: Optional[datetime] = None
        self.disconnected_at: Optional[datetime] = None
        self.error_count = 0
        self.last_error: Optional[str] = None
        self.client_host: Optional[str] = None

class ConnectionManager:
    """
    WebSocket 连接管理器
    负责处理 WebSocket 连接、断开和消息广播
    支持优雅关闭和连接状态追踪
    """
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.connection_info: Dict[WebSocket, ConnectionInfo] = {}
        self._is_shutting_down = False
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, client_host: str = None):
        if self._is_shutting_down:
            logger.warning("系统正在关闭，拒绝新的WebSocket连接")
            await websocket.close(code=1013, reason="Server is shutting down")
            return False
        
        async with self._lock:
            info = ConnectionInfo(websocket)
            info.client_host = client_host
            self.connection_info[websocket] = info
            
            try:
                await websocket.accept()
                info.state = ConnectionState.CONNECTED
                info.connected_at = datetime.now()
                self.active_connections.append(websocket)
                logger.info(
                    f"WebSocket connected. "
                    f"Client: {client_host or 'unknown'}, "
                    f"Total connections: {len(self.active_connections)}"
                )
                return True
            except Exception as e:
                info.state = ConnectionState.ERROR
                info.last_error = str(e)
                info.error_count += 1
                logger.error(f"WebSocket accept failed: {e}")
                return False

    async def disconnect(self, websocket: WebSocket):
        """
        安全断开 WebSocket 连接
        
        使用 try-finally 确保 socket 正确关闭，
        捕获 ConnectionResetError 等异常以避免 Windows 平台上的错误日志
        """
        async with self._lock:
            try:
                if websocket in self.connection_info:
                    info = self.connection_info[websocket]
                    info.state = ConnectionState.DISCONNECTING
                    info.disconnected_at = datetime.now()
                    duration = None
                    if info.connected_at:
                        duration = (info.disconnected_at - info.connected_at).total_seconds()
                    logger.info(
                        f"WebSocket disconnected. "
                        f"Client: {info.client_host or 'unknown'}, "
                        f"Duration: {duration:.2f}s, "
                        f"Total connections: {len(self.active_connections) - 1}"
                    )
                    del self.connection_info[websocket]
                
                if websocket in self.active_connections:
                    self.active_connections.remove(websocket)
                    
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError) as e:
                logger.debug(f"连接已由远程主机关闭: {type(e).__name__}")
            except Exception as e:
                logger.warning(f"断开连接时发生异常: {e}")
            finally:
                try:
                    if websocket.client_state.name == "CONNECTED":
                        await websocket.close(code=1000, reason="Normal closure")
                except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError, RuntimeError) as e:
                    logger.debug(f"关闭 WebSocket 时连接已失效: {type(e).__name__}")
                except Exception as e:
                    logger.debug(f"关闭 WebSocket 时发生预期异常: {e}")

    async def broadcast(self, message: Dict[str, Any]):
        if not self.active_connections:
            return
        
        connections = self.active_connections[:]
        failed_connections = []
        
        for connection in connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Error broadcasting to connection: {e}")
                if connection in self.connection_info:
                    info = self.connection_info[connection]
                    info.state = ConnectionState.ERROR
                    info.last_error = str(e)
                    info.error_count += 1
                failed_connections.append(connection)
        
        for conn in failed_connections:
            try:
                await self.disconnect(conn)
            except:
                pass

    async def close_all(self, reason: str = "Server shutting down"):
        """
        关闭所有WebSocket连接
        用于优雅关闭时批量断开所有客户端
        """
        if self._is_shutting_down:
            logger.warning("close_all已在执行中，跳过重复调用")
            return
        
        self._is_shutting_down = True
        
        logger.info(f"开始关闭所有WebSocket连接，总数: {len(self.active_connections)}")
        
        async with self._lock:
            connections = self.active_connections[:]
            
            for connection in connections:
                try:
                    if connection in self.connection_info:
                        self.connection_info[connection].state = ConnectionState.DISCONNECTING
                    
                    try:
                        if connection.client_state.name == "CONNECTED":
                            await connection.close(code=1001, reason=reason)
                    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError) as e:
                        logger.debug(f"连接已由远程主机关闭: {type(e).__name__}")
                except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError) as e:
                    logger.debug(f"关闭连接时发生预期的连接错误: {type(e).__name__}")
                except Exception as e:
                    logger.error(f"关闭WebSocket连接时发生错误: {e}")
                finally:
                    try:
                        if connection in self.active_connections:
                            self.active_connections.remove(connection)
                        if connection in self.connection_info:
                            del self.connection_info[connection]
                    except:
                        pass
        
        self._is_shutting_down = False
        logger.info("所有WebSocket连接已关闭")

    def get_connection_count(self) -> int:
        return len(self.active_connections)

    def get_connection_states(self) -> Dict[str, int]:
        states = {}
        for info in self.connection_info.values():
            state_name = info.state.value
            states[state_name] = states.get(state_name, 0) + 1
        return states

    def get_error_connections(self) -> List[Dict[str, Any]]:
        error_connections = []
        for ws, info in self.connection_info.items():
            if info.state == ConnectionState.ERROR or info.error_count > 0:
                error_connections.append({
                    "client_host": info.client_host,
                    "error_count": info.error_count,
                    "last_error": info.last_error,
                    "state": info.state.value
                })
        return error_connections

manager = ConnectionManager()

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    client_host = websocket.client.host if websocket.client else None
    
    connected = await manager.connect(websocket, client_host)
    if not connected:
        return
    
    try:
        while True:
            data = await websocket.receive_text()
            
            try:
                message = json.loads(data)
                message_type = message.get("type")
                
                if message_type == "ping":
                    await websocket.send_json({"type": "pong"})
                
                elif message_type == "chat_message":
                    from backend.api.ai import process_chat_message
                    
                    chat_instance_id = message.get("chat_instance_id")
                    user_message = message.get("message")
                    
                    response = await process_chat_message(
                        chat_instance_id=chat_instance_id,
                        message=user_message
                    )
                    
                    await websocket.send_json({
                        "type": "chat_response",
                        "chat_instance_id": chat_instance_id,
                        "content": response.get("content", response.get("response", "")),
                        "created_at": datetime.now().isoformat()
                    })
                
                elif message_type == "create_chat_instance":
                    from backend.api.ai import create_chat_instance
                    
                    title = message.get("title", "新对话")
                    instance = await create_chat_instance(title)
                    
                    await websocket.send_json({
                        "type": "chat_instance_created",
                        "instance_id": str(instance.get("id", "")),
                        "title": instance.get("title", title)
                    })
                
                elif message_type == "get_chat_history":
                    from backend.api.ai import get_chat_history
                    
                    instance_id = message.get("chat_instance_id")
                    history = await get_chat_history(instance_id)
                    
                    await websocket.send_json({
                        "type": "chat_history",
                        "history": history
                    })
                
                elif message_type == "ai_user_input":
                    payload = message.get("payload", {})
                    content = payload.get("content", "")
                    
                    await websocket.send_json({
                        "type": "user_message_received",
                        "payload": {
                            "content": content,
                            "timestamp": datetime.now().isoformat()
                        }
                    })
                
                elif message_type == "ai_user_confirm":
                    payload = message.get("payload", {})
                    choice = payload.get("choice", "confirm")
                    
                    await websocket.send_json({
                        "type": "confirmation_result",
                        "payload": {
                            "choice": choice,
                            "timestamp": datetime.now().isoformat()
                        }
                    })
                
                elif message_type == "ai_start_scan":
                    payload = message.get("payload", {})
                    target = payload.get("target", "")
                    scan_mode = payload.get("scan_mode", "full")
                    
                    await websocket.send_json({
                        "type": "scan_started",
                        "payload": {
                            "target": target,
                            "scan_mode": scan_mode,
                            "timestamp": datetime.now().isoformat()
                        }
                    })
                
                else:
                    if data == "ping":
                        await websocket.send_text("pong")
                    
            except json.JSONDecodeError:
                if data == "ping":
                    await websocket.send_text("pong")
                    
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await manager.disconnect(websocket)

@router.websocket("/ws/progress")
async def websocket_progress_endpoint(websocket: WebSocket):
    """
    WebSocket进度更新端点
    
    用于实时推送任务进度更新。
    前端可以通过此端点接收扫描任务的实时进度信息。
    """
    client_host = websocket.client.host if websocket.client else None
    
    connected = await manager.connect(websocket, client_host)
    if not connected:
        return
    
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
            elif data == "subscribe":
                await websocket.send_json({"type": "subscribed", "message": "已订阅进度更新"})
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket progress error: {e}")
        await manager.disconnect(websocket)
