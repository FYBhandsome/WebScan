import asyncio
import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from tests.conftest import BASE_URL

try:
    import websockets
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False


async def test_ws_connection(uri, label):
    print(f"\n--- 测试连接: {label} ---")
    print(f"  URL: {uri}")
    try:
        async with websockets.connect(uri, ping_interval=None, close_timeout=5) as ws:
            print(f"  [OK] WebSocket 连接成功")
            print(f"  [INFO] 连接状态: open = {ws.open}")

            test_message = json.dumps({"type": "ping", "payload": {"timestamp": "test"}})
            await ws.send(test_message)
            print(f"  已发送消息: {test_message}")

            try:
                response = await asyncio.wait_for(ws.recv(), timeout=3)
                print(f"  收到响应: {response}")
            except asyncio.TimeoutError:
                print("  [INFO] 等待响应超时 (3秒内未收到响应)")

            return True
    except (websockets.exceptions.InvalidURI, websockets.exceptions.InvalidHandshake) as e:
        print(f"  [SKIP] WebSocket 握手失败: {e}")
        return False
    except ConnectionRefusedError:
        print(f"  [SKIP] 连接被拒绝, WebSocket 端点可能未启动")
        return False
    except OSError as e:
        print(f"  [SKIP] 操作系统错误: {e}")
        return False
    except asyncio.TimeoutError:
        print(f"  [SKIP] 连接超时")
        return False
    except Exception as e:
        print(f"  [SKIP] 连接失败 ({type(e).__name__}): {e}")
        return False


async def run_websocket_tests():
    print("=" * 70)
    print("  WebSocket 连接测试")
    print("=" * 70)

    if not WEBSOCKETS_AVAILABLE:
        print("\n[ERROR] websockets 库未安装!")
        print("请运行: pip install websockets")
        print("\n测试中止: 缺少 websockets 依赖")
        return

    print(f"\n[INFO] websockets 版本: {websockets.__version__}")
    print(f"[INFO] 目标服务器: {BASE_URL}")

    ws_url_1 = BASE_URL.replace("http://", "ws://") + "/ws"
    ws_url_2 = BASE_URL.replace("http://", "ws://") + "/api/ws"

    results = {}

    # 1. 尝试连接 ws://127.0.0.1:8899/ws
    results["/ws"] = await test_ws_connection(ws_url_1, "端点: /ws")

    # 2. 尝试连接 ws://127.0.0.1:8899/api/ws
    results["/api/ws"] = await test_ws_connection(ws_url_2, "端点: /api/ws")

    # 3. 总结
    print("\n" + "=" * 70)
    print("  WebSocket 连接测试总结")
    print("=" * 70)
    for path, connected in results.items():
        icon = "✓" if connected else "✗"
        print(f"  [{icon}] {path}: {'连接成功' if connected else '连接失败/跳过'}")
    if not any(results.values()):
        print("\n  [INFO] 所有 WebSocket 端点均不可达, 请确认 WebSocket 服务已启动")
    else:
        print("\n  [INFO] 至少有一个 WebSocket 端点可连接")

    return results


if __name__ == "__main__":
    asyncio.run(run_websocket_tests())