"""
ScanTasks.vue 页面交互测试 - 扫描任务CRUD全流程
使用 asyncio.run() 作为入口，可独立运行
"""
import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from conftest import APITestClient, assert_status, assert_data_exists, assert_list_not_empty
from fixtures.test_data import TASK_DATA


async def run_task_tests():
    client = APITestClient()
    created_task_ids = []
    batch_task_ids = []
    passed = 0
    failed = 0
    errors = 0

    def record(result, step_name):
        nonlocal passed, failed, errors
        icon = {"PASS": "✓", "FAIL": "✗", "ERROR": "⚠"}.get(result.status, "?")
        print(f"  [{icon}] {step_name:45s} status={result.status_code} {result.duration_ms:.0f}ms")
        if result.status == "PASS":
            passed += 1
        elif result.status == "FAIL":
            failed += 1
        else:
            errors += 1
        if result.error:
            print(f"       Error: {result.error[:150]}")

    print("=" * 70)
    print("  ScanTasks.vue 页面交互测试 - 扫描任务CRUD全流程")
    print("=" * 70)

    # 1. 获取任务列表（带分页）
    print("\n[1/10] GET /api/tasks/ - 获取任务列表（分页）")
    r = await client.get("/api/tasks/", params={"page": 1, "page_size": 10})
    record(r, "GET /api/tasks/?page=1&page_size=10")
    assert_status(r, 200)
    assert_data_exists(r)

    # 2. 创建扫描任务
    print("\n[2/10] POST /api/tasks/create - 创建扫描任务")
    r = await client.post("/api/tasks/create", data=TASK_DATA["basic_scan"])
    record(r, "POST /api/tasks/")
    task_id = client.extract_id(r)
    if task_id:
        created_task_ids.append(task_id)
        client.created_resources["tasks"].append(task_id)
        print(f"       → 创建任务ID: {task_id}")
    assert_status(r, 200)
    assert_data_exists(r)

    # 3. 获取任务详情
    if task_id:
        print(f"\n[3/10] GET /api/tasks/{task_id} - 获取任务详情")
        r = await client.get(f"/api/tasks/{task_id}")
        record(r, f"GET /api/tasks/{task_id}")
        assert_status(r, 200)
        assert_data_exists(r)
    else:
        print(f"\n[3/10] GET /api/tasks/{{task_id}} - 跳过（无可用的 task_id）")
        errors += 1

    # 4. 更新任务
    if task_id:
        print(f"\n[4/10] PUT /api/tasks/{task_id} - 更新任务")
        r = await client.put(f"/api/tasks/{task_id}", data=TASK_DATA["update"])
        record(r, f"PUT /api/tasks/{task_id}")
        assert_status(r, 200)
        assert_data_exists(r)
    else:
        print(f"\n[4/10] PUT /api/tasks/{{task_id}} - 跳过")
        errors += 1

    # 5. 获取任务结果
    if task_id:
        print(f"\n[5/10] GET /api/tasks/{task_id}/results - 获取任务结果")
        r = await client.get(f"/api/tasks/{task_id}/results")
        record(r, f"GET /api/tasks/{task_id}/results")
        assert_status(r, 200)
        assert_data_exists(r)
    else:
        print(f"\n[5/10] GET /api/tasks/{{task_id}}/results - 跳过")
        errors += 1

    # 6. 获取任务漏洞
    if task_id:
        print(f"\n[6/10] GET /api/tasks/{task_id}/vulnerabilities - 获取任务漏洞")
        r = await client.get(f"/api/tasks/{task_id}/vulnerabilities")
        record(r, f"GET /api/tasks/{task_id}/vulnerabilities")
        assert_status(r, 200)
        assert_data_exists(r)
    else:
        print(f"\n[6/10] GET /api/tasks/{{task_id}}/vulnerabilities - 跳过")
        errors += 1

    # 7. 获取统计概览
    print("\n[7/10] GET /api/tasks/statistics/overview - 获取统计概览")
    r = await client.get("/api/tasks/statistics/overview")
    record(r, "GET /api/tasks/statistics/overview")
    assert_status(r, 200)
    assert_data_exists(r)

    # 8. 批量创建任务
    print("\n[8/10] POST /api/tasks/create - 批量创建任务")
    for i, batch_item in enumerate(TASK_DATA["batch_create"]):
        r = await client.post("/api/tasks/create", data=batch_item)
        batch_task_id = client.extract_id(r)
        if batch_task_id:
            batch_task_ids.append(batch_task_id)
            client.created_resources["tasks"].append(batch_task_id)
        record(r, f"POST /api/tasks/ [batch {i+1}/{len(TASK_DATA['batch_create'])}]")
        assert_status(r, 200)
        assert_data_exists(r)

    # 9. 按状态筛选
    print("\n[9/10] GET /api/tasks/?status=pending - 按状态筛选")
    r = await client.get("/api/tasks/", params={"status": "pending"})
    record(r, "GET /api/tasks/?status=pending")
    assert_status(r, 200)
    assert_data_exists(r)

    # 10. 删除任务（删除第一个创建的任务）
    if task_id:
        print(f"\n[10/10] DELETE /api/tasks/{task_id} - 删除任务")
        r = await client.delete(f"/api/tasks/{task_id}")
        record(r, f"DELETE /api/tasks/{task_id}")
        assert_status(r, 200)
    else:
        print(f"\n[10/10] DELETE /api/tasks/{{task_id}} - 跳过")
        errors += 1

    # 清理批量创建的任务
    print("\n--- 清理批量创建的任务 ---")
    for batch_id in batch_task_ids:
        try:
            r = await client.delete(f"/api/tasks/{batch_id}")
            print(f"  [CLEAN] 任务 {batch_id} 已删除")
        except Exception:
            pass

    # 打印总结
    total = passed + failed + errors
    print(f"\n{'='*70}")
    print(f"  ScanTasks.vue 测试总结: 总计 {total} | 通过 {passed} | 失败 {failed} | 错误 {errors}")
    print(f"{'='*70}")
    client.print_summary()

    return 0 if failed == 0 and errors == 0 else 1


if __name__ == "__main__":
    exit_code = asyncio.run(run_task_tests())
    sys.exit(exit_code)