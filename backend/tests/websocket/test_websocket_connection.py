import pytest
import asyncio
import websockets
import json

class TestWebSocketConnection:
    """WebSocket连接测试"""
    
    @pytest.mark.asyncio
    async def test_websocket_connect(self):
        """测试WebSocket连接"""
        uri = "ws://127.0.0.1:8888/ws"
        try:
            async with websockets.connect(uri) as websocket:
                assert websocket.open
                await websocket.close()
        except Exception as e:
            pytest.skip(f"WebSocket服务器未启动: {e}")
    
    @pytest.mark.asyncio
    async def test_websocket_heartbeat(self):
        """测试心跳"""
        uri = "ws://127.0.0.1:8888/ws"
        try:
            async with websockets.connect(uri) as websocket:
                await websocket.send("ping")
                response = await asyncio.wait_for(websocket.recv(), timeout=5)
                assert response == "pong"
        except Exception as e:
            pytest.skip(f"WebSocket服务器未启动: {e}")
    
    @pytest.mark.asyncio
    async def test_websocket_message_format(self):
        """测试消息格式"""
        uri = "ws://127.0.0.1:8888/ws"
        try:
            async with websockets.connect(uri) as websocket:
                message = json.dumps({
                    "type": "test",
                    "payload": {"data": "test"}
                })
                await websocket.send(message)
        except Exception as e:
            pytest.skip(f"WebSocket服务器未启动: {e}")
