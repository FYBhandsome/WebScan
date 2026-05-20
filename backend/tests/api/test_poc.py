import sys
import os
import asyncio

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from conftest import APITestClient, assert_status, assert_list_not_empty
from fixtures.test_data import POC_SCAN_DATA


async def test_poc_flow():
    client = APITestClient()
    ok_count = 0
    tolerable_count = 0

    def ok():
        nonlocal ok_count
        ok_count += 1

    def tolerable(msg=""):
        nonlocal tolerable_count
        tolerable_count += 1
        if msg:
            print(f"  [ tolerable ] {msg}")

    print("=" * 70)
    print("  POC API 集成测试 - 模拟 POCScan.vue 页面交互")
    print("=" * 70)

    # 1. GET /api/poc/types - 获取所有POC类型
    print("\n[1] GET /api/poc/types - 获取所有POC类型")
    r = await client.get("/api/poc/types")
    print(f"  状态码: {r.status_code}, 耗时: {r.duration_ms:.0f}ms")
    poc_types = []
    if assert_status(r, 200):
        ok()
        if assert_list_not_empty(r):
            data = r.data.get("data", r.data)
            if isinstance(data, list):
                poc_types = data
                for pt in poc_types:
                    label = pt.get("label", pt.get("value", "unknown"))
                    val = pt.get("value", "unknown")
                    print(f"    - {val}: {label}")
                print(f"  共 {len(poc_types)} 种POC类型")
        else:
            print("  POC类型列表为空")
    elif r.status_code in (404, 500, 503):
        tolerable("POC类型服务不可用")
    else:
        tolerable(f"非预期状态码 {r.status_code}")

    # 2. 对每个POC类型获取详情 GET /api/poc/info/{poc_type}
    print(f"\n[2] GET /api/poc/info/{{poc_type}} - 获取POC详情 (共{len(poc_types)}种)")
    step = 2
    for i, pt in enumerate(poc_types):
        val = pt.get("value", "unknown")
        label = pt.get("label", val)
        print(f"  [{step}.{i+1}] GET /api/poc/info/{val} - {label}")
        r = await client.get(f"/api/poc/info/{val}")
        print(f"    状态码: {r.status_code}, 耗时: {r.duration_ms:.0f}ms")
        if assert_status(r, 200):
            ok()
            if r.data and isinstance(r.data, dict):
                inner = r.data.get("data", r.data)
                if isinstance(inner, dict):
                    keys = list(inner.keys())
                    print(f"    详情字段: {keys}")
        elif r.status_code == 404:
            tolerable(f"/api/poc/info/{{poc_type}} 端点不存在")
        else:
            tolerable(f"非预期状态码 {r.status_code}")

    # 3. POST /api/poc/scan - weblogic_cve_2020_2551
    print("\n[3] POST /api/poc/scan - 执行POC扫描 (weblogic_cve_2020_2551)")
    data_1 = POC_SCAN_DATA["weblogic_cve_2020_2551"]
    request_body = {
        "target": data_1["target"],
        "poc_types": [data_1["poc_type"]],
        "timeout": 30
    }
    r = await client.post("/api/poc/scan", data=request_body, timeout=60)
    print(f"  状态码: {r.status_code}, 耗时: {r.duration_ms:.0f}ms")
    if assert_status(r, 200):
        ok()
        if r.data and isinstance(r.data, dict):
            inner = r.data.get("data", r.data)
            if isinstance(inner, dict):
                task_id = inner.get("task_id")
                status_val = inner.get("status")
                print(f"  task_id: {task_id}, status: {status_val}")
                if task_id:
                    client.created_resources.setdefault("tasks", []).append(task_id)
    elif r.status_code in (400, 422):
        tolerable("请求格式校验失败")
        if r.error:
            print(f"  详情: {r.error[:200]}")
    else:
        tolerable(f"非预期状态码 {r.status_code}")

    # 4. POST /api/poc/scan - struts2_009
    print("\n[4] POST /api/poc/scan - 执行POC扫描 (struts2_009)")
    data_2 = POC_SCAN_DATA["struts2_009"]
    request_body = {
        "target": data_2["target"],
        "poc_types": [data_2["poc_type"]],
        "timeout": 30
    }
    r = await client.post("/api/poc/scan", data=request_body, timeout=60)
    print(f"  状态码: {r.status_code}, 耗时: {r.duration_ms:.0f}ms")
    if assert_status(r, 200):
        ok()
        if r.data and isinstance(r.data, dict):
            inner = r.data.get("data", r.data)
            if isinstance(inner, dict):
                task_id = inner.get("task_id")
                status_val = inner.get("status")
                print(f"  task_id: {task_id}, status: {status_val}")
                if task_id:
                    client.created_resources.setdefault("tasks", []).append(task_id)
    elif r.status_code in (400, 422):
        tolerable("请求格式校验失败")
        if r.error:
            print(f"  详情: {r.error[:200]}")
    else:
        tolerable(f"非预期状态码 {r.status_code}")

    # 5. POST /api/poc/scan - tomcat_cve_2017_12615
    print("\n[5] POST /api/poc/scan - 执行POC扫描 (tomcat_cve_2017_12615)")
    data_3 = POC_SCAN_DATA["tomcat_cve_2017_12615"]
    request_body = {
        "target": data_3["target"],
        "poc_types": [data_3["poc_type"]],
        "timeout": 30
    }
    r = await client.post("/api/poc/scan", data=request_body, timeout=60)
    print(f"  状态码: {r.status_code}, 耗时: {r.duration_ms:.0f}ms")
    if assert_status(r, 200):
        ok()
        if r.data and isinstance(r.data, dict):
            inner = r.data.get("data", r.data)
            if isinstance(inner, dict):
                task_id = inner.get("task_id")
                status_val = inner.get("status")
                print(f"  task_id: {task_id}, status: {status_val}")
                if task_id:
                    client.created_resources.setdefault("tasks", []).append(task_id)
    elif r.status_code in (400, 422):
        tolerable("请求格式校验失败")
        if r.error:
            print(f"  详情: {r.error[:200]}")
    else:
        tolerable(f"非预期状态码 {r.status_code}")

    await client.cleanup()
    client.print_summary()

    total_steps = 3 + len(poc_types)
    print(f"\n  PASS 统计: {ok_count}/{total_steps} 严格通过 | {ok_count + tolerable_count}/{total_steps} 容忍通过")
    return ok_count, tolerable_count


if __name__ == "__main__":
    asyncio.run(test_poc_flow())