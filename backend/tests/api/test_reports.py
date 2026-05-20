"""
Reports.vue 页面交互测试 - 报告生成/导出/预览/删除全流程
使用 asyncio.run() 作为入口，可独立运行
"""
import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from conftest import APITestClient, assert_field_exists
from fixtures.test_data import REPORT_DATA, TASK_DATA


async def run_report_tests():
    client = APITestClient()
    created_task_id = None
    created_report_id = None
    passed = 0
    failed = 0
    errors = 0

    def record(result, step_name):
        nonlocal passed, failed, errors
        icon = {"PASS": "✓", "FAIL": "✗", "ERROR": "⚠"}.get(result.status, "?")
        print(f"  [{icon}] {step_name:50s} status={result.status_code} {result.duration_ms:.0f}ms")
        if result.status == "PASS":
            passed += 1
        elif result.status == "FAIL":
            failed += 1
        else:
            errors += 1
        if result.error:
            print(f"       Error: {result.error[:150]}")

    print("=" * 70)
    print("  Reports.vue 页面交互测试 - 报告CRUD全流程")
    print("=" * 70)

    # 1. 获取报告列表（带分页）
    print("\n[1/12] GET /api/reports/?page=1&page_size=10 - 获取报告列表")
    r = await client.get("/api/reports/", params={"page": 1, "page_size": 10})
    record(r, "GET /api/reports/?page=1&page_size=10")
    assert_field_exists(r, "code")

    # 2. 先创建任务（作为报告的关联）
    print("\n[2/12] POST /api/tasks/create - 创建关联任务")
    r = await client.post("/api/tasks/create", data=TASK_DATA["basic_scan"])
    created_task_id = client.extract_id(r)
    if created_task_id:
        client.created_resources["tasks"].append(created_task_id)
        print(f"       → 创建任务ID: {created_task_id}")
    record(r, "POST /api/tasks/")
    assert_field_exists(r, "code")

    # 3. 创建报告（关联上述任务）
    if created_task_id:
        print(f"\n[3/12] POST /api/reports/ - 创建报告（关联任务 {created_task_id}）")
        report_data = dict(REPORT_DATA["basic_report"])
        report_data["task_id"] = created_task_id
        r = await client.post("/api/reports/", data=report_data)
        created_report_id = client.extract_id(r)
        if created_report_id:
            client.created_resources["reports"].append(created_report_id)
            print(f"       → 创建报告ID: {created_report_id}")
        record(r, "POST /api/reports/")
        assert_field_exists(r, "code")
    else:
        print(f"\n[3/12] POST /api/reports/ - 跳过（无可用的 task_id）")
        errors += 1

    # 4. 获取报告详情
    if created_report_id:
        print(f"\n[4/12] GET /api/reports/{created_report_id} - 获取报告详情")
        r = await client.get(f"/api/reports/{created_report_id}")
        record(r, f"GET /api/reports/{created_report_id}")
        assert_field_exists(r, "code")
    else:
        print(f"\n[4/12] GET /api/reports/{{report_id}} - 跳过")
        errors += 1

    # 5. 更新报告
    if created_report_id:
        print(f"\n[5/12] PUT /api/reports/{created_report_id} - 更新报告")
        r = await client.put(f"/api/reports/{created_report_id}", data={
            "report_name": "已更新-综合漏洞分析报告",
            "description": "更新后的报告描述"
        })
        record(r, f"PUT /api/reports/{created_report_id}")
        assert_field_exists(r, "code")
    else:
        print(f"\n[5/12] PUT /api/reports/{{report_id}} - 跳过")
        errors += 1

    # 6. 导出JSON格式
    if created_report_id:
        print(f"\n[6/12] GET /api/reports/{created_report_id}/export?format=json - 导出JSON")
        r = await client.get(f"/api/reports/{created_report_id}/export", params={"format": "json"})
        record(r, "GET /api/reports/{id}/export?format=json")
        assert_field_exists(r, "code")
    else:
        print(f"\n[6/12] GET /api/reports/{{report_id}}/export?format=json - 跳过")
        errors += 1

    # 7. 导出HTML格式
    if created_report_id:
        print(f"\n[7/12] GET /api/reports/{created_report_id}/export?format=html - 导出HTML")
        r = await client.get(f"/api/reports/{created_report_id}/export", params={"format": "html"})
        record(r, "GET /api/reports/{id}/export?format=html")
        assert_field_exists(r, "code")
    else:
        print(f"\n[7/12] GET /api/reports/{{report_id}}/export?format=html - 跳过")
        errors += 1

    # 8. 导出Markdown格式
    if created_report_id:
        print(f"\n[8/12] GET /api/reports/{created_report_id}/export?format=markdown - 导出Markdown")
        r = await client.get(f"/api/reports/{created_report_id}/export", params={"format": "markdown"})
        record(r, "GET /api/reports/{id}/export?format=markdown")
        assert_field_exists(r, "code")
    else:
        print(f"\n[8/12] GET /api/reports/{{report_id}}/export?format=markdown - 跳过")
        errors += 1

    # 9. 预览报告
    if created_report_id:
        print(f"\n[9/12] GET /api/reports/{created_report_id}/preview - 预览报告")
        r = await client.get(f"/api/reports/{created_report_id}/preview")
        record(r, f"GET /api/reports/{created_report_id}/preview")
        assert_field_exists(r, "code")
    else:
        print(f"\n[9/12] GET /api/reports/{{report_id}}/preview - 跳过")
        errors += 1

    # 10. 获取任务最新报告
    if created_task_id:
        print(f"\n[10/12] GET /api/reports/task/{created_task_id}/latest - 获取任务最新报告")
        r = await client.get(f"/api/reports/task/{created_task_id}/latest")
        record(r, f"GET /api/reports/task/{created_task_id}/latest")
        assert_field_exists(r, "code")
    else:
        print(f"\n[10/12] GET /api/reports/task/{{task_id}}/latest - 跳过")
        errors += 1

    # 11. 删除报告
    if created_report_id:
        print(f"\n[11/12] DELETE /api/reports/{created_report_id} - 删除报告")
        r = await client.delete(f"/api/reports/{created_report_id}")
        record(r, f"DELETE /api/reports/{created_report_id}")
        assert_field_exists(r, "code")
        created_report_id = None
    else:
        print(f"\n[11/12] DELETE /api/reports/{{report_id}} - 跳过")
        errors += 1

    # 12. 清理任务
    if created_task_id:
        print(f"\n[12/12] DELETE /api/tasks/{created_task_id} - 清理任务")
        r = await client.delete(f"/api/tasks/{created_task_id}")
        record(r, f"DELETE /api/tasks/{created_task_id}")
        assert_field_exists(r, "code")
    else:
        print(f"\n[12/12] DELETE /api/tasks/{{task_id}} - 跳过")
        errors += 1

    # 打印总结
    total = passed + failed + errors
    print(f"\n{'='*70}")
    print(f"  Reports.vue 测试总结: 总计 {total} | 通过 {passed} | 失败 {failed} | 错误 {errors}")
    print(f"{'='*70}")
    client.print_summary()

    return 0 if failed == 0 and errors == 0 else 1


if __name__ == "__main__":
    exit_code = asyncio.run(run_report_tests())
    sys.exit(exit_code)