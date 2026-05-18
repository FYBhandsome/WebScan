"""
简单的WebSocket测试脚本
直接测试WebSocket消息收发
"""
import asyncio
import json
import websockets

WS_URL = "ws://127.0.0.1:8081/api/ai-chat/ws"

async def test():
    print(f"Connecting to {WS_URL}...")
    
    async with websockets.connect(WS_URL) as ws:
        # 接收连接消息
        msg = await ws.recv()
        print(f"Received: {msg}")
        
        # 发送 get_status 测试
        await ws.send(json.dumps({"type": "get_status", "payload": {}}))
        print("Sent: get_status")
        
        msg = await ws.recv()
        print(f"Received: {msg}")
        
        # 发送 start_scan 消息
        scan_msg = {
            "type": "start_scan",
            "payload": {
                "target": "http://testasp.vulnweb.com",
                "scan_mode": "info"
            }
        }
        await ws.send(json.dumps(scan_msg))
        print(f"Sent: start_scan")
        
        # 等待响应
        print("Waiting for response...")
        try:
            msg = await asyncio.wait_for(ws.recv(), timeout=10.0)
            print(f"Received: {msg}")
        except asyncio.TimeoutError:
            print("Timeout waiting for response")
        
        # 继续接收消息
        for i in range(5):
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=5.0)
                data = json.loads(msg)
                print(f"[{i+1}] Type: {data.get('type')}")
            except asyncio.TimeoutError:
                print(f"[{i+1}] Timeout")
                break

if __name__ == "__main__":
    asyncio.run(test())
