"""
TOSKill - Workflow Integration Test Suite

Tests the complete scan flow end-to-end:
1. parse-intent API
2. tools API
3. health API
4. WebSocket connection -> start_scan -> progress -> scan_completed
5. Report listing API
"""
import asyncio
import json
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx
import websockets

BASE_URL = "http://127.0.0.1:8081"
WS_URL = "ws://127.0.0.1:8081/api/ai-chat/ws"

passed = 0
failed = 0
results = []


def log_result(name, ok, detail=""):
    global passed, failed
    status = "PASS" if ok else "FAIL"
    if ok:
        passed += 1
    else:
        failed += 1
    results.append((name, status, detail))
    print(f"  [{status}] {name}")
    if detail:
        print(f"         {detail}")


async def test_health_api():
    print("\n--- Health API ---")
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{BASE_URL}/api/health", timeout=10.0)
            ok = resp.status_code == 200
            log_result("GET /api/health", ok, f"status={resp.status_code}")
    except Exception as e:
        log_result("GET /api/health", False, str(e))


async def test_parse_intent():
    print("\n--- Parse Intent API ---")
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{BASE_URL}/api/parse-intent",
                json={"message": "http://testasp.vulnweb.com port scan"},
                timeout=30.0
            )
            ok = resp.status_code == 200
            data = resp.json()
            detail = f"code={data.get('code')}, target={data.get('data', {}).get('target')}"
            log_result("POST /api/parse-intent", ok and data.get("code") == 200, detail)
            return data.get("data") if ok else None
    except Exception as e:
        log_result("POST /api/parse-intent", False, str(e))
        return None


async def test_tools_api():
    print("\n--- Tools API ---")
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{BASE_URL}/api/tools", timeout=10.0)
            ok = resp.status_code == 200
            data = resp.json()
            tool_count = len(data.get("data", {}).get("tools", data.get("data", [])))
            if isinstance(data.get("data"), list):
                tool_count = len(data.get("data"))
            log_result("GET /api/tools", ok, f"count={tool_count}")
    except Exception as e:
        log_result("GET /api/tools", False, str(e))


async def test_reports_api():
    print("\n--- Reports API ---")
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{BASE_URL}/api/reports/list", timeout=10.0)
            ok = resp.status_code == 200
            data = resp.json()
            report_count = len(data.get("reports", data.get("data", [])))
            log_result("GET /api/reports/list", ok, f"count={report_count}")
    except Exception as e:
        log_result("GET /api/reports/list", False, str(e))


async def test_websocket_full_flow(target="http://testasp.vulnweb.com", mode="info"):
    """完整的 WebSocket 测试流程，保持连接打开"""
    print(f"\n--- WebSocket Full Flow ({target}, mode={mode}) ---")
    
    try:
        async with websockets.connect(WS_URL, ping_interval=20, ping_timeout=10) as ws:
            msg = await asyncio.wait_for(ws.recv(), timeout=10.0)
            data = json.loads(msg)
            msg_type = data.get("type", "")
            
            if msg_type != "connected":
                log_result("WebSocket connect", False, f"unexpected type: {msg_type}")
                return
            
            session_id = data.get("payload", {}).get("session_id", "N/A")
            log_result("WebSocket connect", True, f"session={session_id}")
            
            scan_msg = {"type": "start_scan", "payload": {"target": target, "scan_mode": mode}}
            await ws.send(json.dumps(scan_msg))
            print(f"  Sent: start_scan({target}, {mode})")
            
            got_scan_started = False
            got_task_started = False
            got_task_completed = False
            got_workflow_log = False
            got_scan_completed = False
            got_task_error = False
            error_detail = ""
            msg_count = 0
            
            start_time = time.time()
            max_wait = 300
            
            while time.time() - start_time < max_wait:
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=60.0)
                    data = json.loads(msg)
                    msg_type = data.get("type", "")
                    msg_count += 1
                    
                    prefix = f"  [{msg_count}] {msg_type}: "
                    
                    if msg_type == "scan_started":
                        got_scan_started = True
                        print(f"{prefix}OK")
                    elif msg_type == "scan_completed":
                        got_scan_completed = True
                        payload = data.get("payload", {})
                        tasks = payload.get("completed_tasks", [])
                        vulns = payload.get("vulnerabilities_count", 0)
                        print(f"{prefix}OK (tasks={len(tasks)}, vulns={vulns})")
                        break
                    elif msg_type == "task_started":
                        got_task_started = True
                        tool = data.get("payload", {}).get("tool", "")
                        print(f"{prefix}{tool}")
                    elif msg_type == "task_completed":
                        got_task_completed = True
                        tool = data.get("payload", {}).get("tool", "")
                        print(f"{prefix}{tool}")
                    elif msg_type == "interaction_required":
                        payload = data.get("payload", {})
                        options = payload.get("options", [])
                        print(f"{prefix}等待用户确认，自动选择执行")
                        response = {"type": "user_choice", "payload": {"choice": "1"}}
                        await ws.send(json.dumps(response))
                        print(f"  -> 已发送确认: 执行")
                    elif msg_type == "tool_confirm_required":
                        payload = data.get("payload", {})
                        tool_name = payload.get("tool_name", "")
                        print(f"{prefix}工具确认: {tool_name}，自动确认")
                        response = {"type": "tool_confirmed", "payload": {"confirmed": True}}
                        await ws.send(json.dumps(response))
                        print(f"  -> 已确认执行工具")
                    elif msg_type == "workflow_log":
                        got_workflow_log = True
                        payload = data.get("payload", {})
                        level = payload.get("level", "")
                        msg_text = payload.get("message", "")
                        print(f"{prefix}[{level}] {msg_text[:100]}")
                    elif msg_type == "task_error":
                        got_task_error = True
                        tool = data.get("payload", {}).get("tool", "")
                        ai = data.get("payload", {}).get("ai_analysis", "")
                        error_detail = f"{tool}: {str(ai)[:100]}"
                        print(f"{prefix}{tool} (ai_analysis={bool(ai)})")
                    elif msg_type == "error":
                        error_detail = data.get("payload", {}).get("message", "")
                        print(f"{prefix}{error_detail}")
                        break
                    else:
                        print(f"{prefix}")
                        
                except asyncio.TimeoutError:
                    print(f"  [TIMEOUT] No message for 60s")
                    break
            
            print(f"\n  Results: messages={msg_count}, elapsed={time.time()-start_time:.0f}s")
            
            log_result("scan_started received", got_scan_started)
            log_result("task_started received", got_task_started)
            log_result("task_completed received", got_task_completed)
            log_result("workflow_log received", got_workflow_log)
            log_result("scan_completed received", got_scan_completed)
            
            if got_task_error and not error_detail:
                log_result("task_error with AI", False, error_detail)
                
    except Exception as e:
        log_result("WebSocket full flow", False, str(e))
        import traceback
        traceback.print_exc()


async def main():
    global passed, failed, results
    
    print("=" * 60)
    print("TOSKill Integration Test Suite")
    print("=" * 60)
    print(f"Target: {BASE_URL}")
    print(f"WS URL:  {WS_URL}")
    print()
    
    await test_health_api()
    intent = await test_parse_intent()
    await test_tools_api()
    await test_reports_api()
    
    target = intent.get("target") if intent else "http://testasp.vulnweb.com"
    mode = intent.get("mode", "info") if intent else "info"
    await test_websocket_full_flow(target=target, mode=mode)
    
    print("\n" + "=" * 60)
    print(f"TEST RESULTS: {passed} passed, {failed} failed")
    print("=" * 60)
    for name, status, detail in results:
        print(f"  [{status}] {name}")
        if detail:
            print(f"         {detail}")
    
    return failed == 0


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)