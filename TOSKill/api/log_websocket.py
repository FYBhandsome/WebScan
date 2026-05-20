"""
日志WebSocket处理器

支持：
1. 实时日志推送
2. 历史日志读取
3. 会话订阅
4. 日志文件实时监控
"""
import logging
import asyncio
import json
from typing import Dict, Any, Set
from uuid import uuid4
from datetime import datetime

from fastapi import WebSocket, WebSocketDisconnect, APIRouter

router = APIRouter(prefix="/logs", tags=["日志WebSocket"])
logger = logging.getLogger(__name__)

MSG_LOGS_BATCH = "logs:batch"
MSG_LOGS_SINGLE = "logs:single"
MSG_HEARTBEAT = "logs:heartbeat"
MSG_SYSTEM_STATUS = "system:status"

HEARTBEAT_INTERVAL = 30


class LogWebSocketManager:
    """日志 WebSocket 连接管理器"""

    def __init__(self):
        self.connections: Dict[str, WebSocket] = {}
        self.subscriptions: Dict[str, Set[str]] = {}
        self._heartbeat_tasks: Dict[str, asyncio.Task] = {}
        self._file_monitor_task = None
        self._last_file_position = 0

    async def connect(self, websocket: WebSocket) -> str:
        await websocket.accept()
        client_id = str(uuid4())[:8]
        self.connections[client_id] = websocket
        self.subscriptions[client_id] = set()

        await self._send(client_id, {
            "type": "connected",
            "payload": {
                "client_id": client_id,
                "message": "日志服务已连接",
                "timestamp": datetime.now().isoformat()
            }
        })

        self._start_heartbeat(client_id)
        logger.info(f"日志客户端连接: {client_id} (当前连接数: {len(self.connections)})")
        
        await self._send_initial_logs(client_id)
        
        return client_id

    async def _send_initial_logs(self, client_id: str):
        try:
            from TOSKill.AI.log_collector import log_collector as _lc
            _lc.initialize()
            
            file_logs = _lc.get_file_logs(50)
            if file_logs:
                await self._send(client_id, {
                    "type": MSG_LOGS_BATCH,
                    "payload": {
                        "logs": file_logs,
                        "batch_size": len(file_logs),
                        "source": "history"
                    }
                })
        except Exception as e:
            logger.warning(f"发送初始日志失败: {e}")

    def disconnect(self, client_id: str):
        self.connections.pop(client_id, None)
        self.subscriptions.pop(client_id, None)
        self._stop_heartbeat(client_id)
        logger.info(f"日志客户端断开: {client_id} (当前连接数: {len(self.connections)})")

    async def broadcast(self, log_entry: Dict):
        for client_id in list(self.connections.keys()):
            await self._send(client_id, {
                "type": MSG_LOGS_SINGLE,
                "payload": log_entry
            })

    async def push_to_session(self, session_id: str, log_entry: Dict):
        for client_id, subs in list(self.subscriptions.items()):
            if not subs or session_id in subs:
                await self._send(client_id, {
                    "type": MSG_LOGS_SINGLE,
                    "payload": log_entry
                })

    async def push_batch(self, logs: list, client_id: str = None):
        payload = {"logs": logs, "batch_size": len(logs)}
        if client_id:
            await self._send(client_id, {"type": MSG_LOGS_BATCH, "payload": payload})
        else:
            for cid in list(self.connections.keys()):
                await self._send(cid, {"type": MSG_LOGS_BATCH, "payload": payload})

    async def _send(self, client_id: str, message: Dict):
        ws = self.connections.get(client_id)
        if ws is None:
            return
        try:
            await ws.send_json(message)
        except Exception as e:
            logger.error(f"发送消息到 {client_id} 失败: {e}")

    def _start_heartbeat(self, client_id: str):
        async def _beat():
            while client_id in self.connections:
                await asyncio.sleep(HEARTBEAT_INTERVAL)
                await self._send(client_id, {"type": MSG_HEARTBEAT})
        self._heartbeat_tasks[client_id] = asyncio.ensure_future(_beat())

    def _stop_heartbeat(self, client_id: str):
        task = self._heartbeat_tasks.pop(client_id, None)
        if task and not task.done():
            task.cancel()

    def has_clients(self) -> bool:
        return len(self.connections) > 0

    @property
    def client_count(self) -> int:
        return len(self.connections)


log_ws_manager = LogWebSocketManager()


@router.websocket("/ws")
async def log_websocket_endpoint(websocket: WebSocket):
    client_id = await log_ws_manager.connect(websocket)
    try:
        while True:
            raw = await websocket.receive_text()
            try:
                data = json.loads(raw)
                msg_type = data.get("type", "")
            except json.JSONDecodeError:
                continue

            if msg_type == "subscribe":
                session_id = data.get("session_id", "")
                if session_id and client_id in log_ws_manager.subscriptions:
                    log_ws_manager.subscriptions[client_id].add(session_id)
                    await log_ws_manager._send(client_id, {
                        "type": "subscribed",
                        "payload": {"session_id": session_id}
                    })
            elif msg_type == "unsubscribe":
                session_id = data.get("session_id", "")
                if session_id and client_id in log_ws_manager.subscriptions:
                    log_ws_manager.subscriptions[client_id].discard(session_id)
                    await log_ws_manager._send(client_id, {
                        "type": "unsubscribed",
                        "payload": {"session_id": session_id}
                    })
            elif msg_type == "get_history":
                session_id = data.get("session_id", "")
                count = data.get("count", 200)
                try:
                    from TOSKill.AI.log_collector import log_collector as _lc
                    _lc.initialize()
                    
                    if session_id:
                        logs = _lc.get_logs(session_id)
                    else:
                        logs = _lc.get_file_logs(count)
                    
                    await log_ws_manager.push_batch(logs[-count:], client_id)
                except Exception as e:
                    logger.warning(f"获取历史日志失败: {e}")
            elif msg_type == "get_file_logs":
                count = data.get("count", 200)
                try:
                    from TOSKill.AI.log_collector import log_collector as _lc
                    _lc.initialize()
                    logs = _lc.get_file_logs(count)
                    await log_ws_manager.push_batch(logs, client_id)
                except Exception as e:
                    logger.warning(f"获取文件日志失败: {e}")
            elif msg_type == "get_stats":
                session_id = data.get("session_id", "")
                try:
                    from TOSKill.AI.log_collector import log_collector as _lc
                    stats = _lc.get_stats(session_id)
                    await log_ws_manager._send(client_id, {
                        "type": "stats",
                        "payload": stats
                    })
                except Exception as e:
                    logger.warning(f"获取日志统计失败: {e}")
            elif msg_type == "clear_logs":
                try:
                    from TOSKill.AI.log_collector import log_collector as _lc
                    _lc.clear_logs()
                    await log_ws_manager._send(client_id, {
                        "type": "logs_cleared",
                        "payload": {"message": "日志已清空"}
                    })
                except Exception as e:
                    logger.warning(f"清空日志失败: {e}")
            elif msg_type == "ping":
                await log_ws_manager._send(client_id, {"type": "pong"})
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"日志 WebSocket 异常: {e}")
    finally:
        log_ws_manager.disconnect(client_id)


@router.get("/history")
async def get_log_history(count: int = 200, session_id: str = None):
    from TOSKill.AI.log_collector import log_collector as _lc
    _lc.initialize()
    
    if session_id:
        logs = _lc.get_logs(session_id)
    else:
        logs = _lc.get_file_logs(count)
    
    return {
        "code": 200,
        "message": "success",
        "data": {
            "logs": logs[-count:],
            "total": len(logs)
        }
    }


@router.get("/stats")
async def get_log_stats(session_id: str = None):
    from TOSKill.AI.log_collector import log_collector as _lc
    _lc.initialize()
    stats = _lc.get_stats(session_id)
    return {
        "code": 200,
        "message": "success",
        "data": stats
    }


@router.delete("/clear")
async def clear_logs():
    from TOSKill.AI.log_collector import log_collector as _lc
    _lc.clear_logs()
    return {
        "code": 200,
        "message": "日志已清空"
    }
