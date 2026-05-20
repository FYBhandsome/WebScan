import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from tests.conftest import APITestClient, assert_status, assert_data_exists
from tests.fixtures.test_data import AI_AGENT_SCAN_DATA


async def run_ai_agents_tests():
    client = APITestClient()
    print("=" * 70)
    print("  AI Agents API 集成测试 (模拟前端 AgentScan.vue 页面)")
    print("=" * 70)

    task_id = None

    # 1. 获取AI Agent任务列表
    print("\n[1/11] GET /api/ai_agents/tasks - 获取AI Agent任务列表")
    result = await client.get("/api/ai_agents/tasks")
    print(f"  状态码: {result.status_code} | 结果: {result.status}")
    assert_status(result, 200)
    assert_data_exists(result)
    if result.data:
        count = client.extract_list_count(result)
        print(f"  当前任务数量: {count}")

    # 2. 获取可用工具列表
    print("\n[2/11] GET /api/ai_agents/tools - 获取可用工具列表")
    result = await client.get("/api/ai_agents/tools")
    print(f"  状态码: {result.status_code} | 结果: {result.status}")
    assert_status(result, 200)
    assert_data_exists(result)
    if result.data:
        count = client.extract_list_count(result)
        print(f"  可用工具数量: {count}")

    # 3. 获取Agent配置
    print("\n[3/11] GET /api/ai_agents/config - 获取Agent配置")
    result = await client.get("/api/ai_agents/config")
    print(f"  状态码: {result.status_code} | 结果: {result.status}")
    assert_status(result, 200)
    assert_data_exists(result)
    if result.data and isinstance(result.data, dict):
        data = result.data.get("data", result.data)
        if isinstance(data, dict):
            print(f"  配置项数量: {len(data)}")

    # 4. POC搜索 - 按关键词
    print("\n[4/11] POST /api/ai_agents/poc/search - POC搜索 (keyword)")
    result = await client.post("/api/ai_agents/poc/search", data={"keyword": "sql injection"})
    print(f"  状态码: {result.status_code} | 结果: {result.status}")
    assert_status(result, 200)
    assert_data_exists(result)
    if result.data:
        count = client.extract_list_count(result)
        print(f"  搜索结果数量: {count}")

    # 5. POC搜索 - 按CVE编号
    print("\n[5/11] POST /api/ai_agents/poc/search - POC搜索 (CVE)")
    result = await client.post("/api/ai_agents/poc/search", data={"cve_id": "CVE-2021-44228"})
    print(f"  状态码: {result.status_code} | 结果: {result.status}")
    assert_status(result, 200)
    assert_data_exists(result)
    if result.data:
        count = client.extract_list_count(result)
        print(f"  搜索结果数量: {count}")

    # 6. 工作流指标
    print("\n[6/11] GET /api/ai_agents/workflow/metrics - 工作流指标")
    result = await client.get("/api/ai_agents/workflow/metrics")
    print(f"  状态码: {result.status_code} | 结果: {result.status}")
    assert_status(result, 200)
    assert_data_exists(result)

    # 7. 环境信息
    print("\n[7/11] GET /api/ai_agents/environment/info - 环境信息")
    result = await client.get("/api/ai_agents/environment/info")
    print(f"  状态码: {result.status_code} | 结果: {result.status}")
    assert_status(result, 200)
    assert_data_exists(result)

    # 8. Agent能力列表
    print("\n[8/11] GET /api/ai_agents/capabilities/list - Agent能力列表")
    result = await client.get("/api/ai_agents/capabilities/list")
    print(f"  状态码: {result.status_code} | 结果: {result.status}")
    assert_status(result, 200)
    assert_data_exists(result)
    if result.data:
        count = client.extract_list_count(result)
        print(f"  能力项数量: {count}")

    # 9. 启动Agent扫描
    print("\n[9/11] POST /api/ai_agents/scan - 启动Agent扫描")
    scan_data = AI_AGENT_SCAN_DATA["quick_scan"]
    print(f"  扫描参数: target={scan_data['target']}, strategy={scan_data['strategy']}")
    result = await client.post("/api/ai_agents/scan", data=scan_data, timeout=30)
    print(f"  状态码: {result.status_code} | 结果: {result.status}")
    assert_status(result, 200)
    assert_data_exists(result)
    task_id = client.extract_id(result, "task_id")
    if task_id is None:
        task_id = client.extract_id(result, "id")
    if task_id:
        print(f"  创建的任务ID: {task_id}")
        client.created_resources["agent_tasks"].append(task_id)
    else:
        task_data = result.data
        if isinstance(task_data, dict):
            inner = task_data.get("data", task_data)
            if isinstance(inner, dict):
                task_id = inner.get("task_id") or inner.get("id")
        if task_id:
            print(f"  创建的任务ID: {task_id}")
            client.created_resources["agent_tasks"].append(task_id)
        else:
            print("  [WARN] 无法从响应中提取任务ID, 跳过轮询步骤")

    # 10. 轮询任务状态直到完成
    if task_id:
        print(f"\n[10/11] 轮询 GET /api/ai_agents/tasks/{task_id} 等待扫描完成")
        max_polls = 60
        poll_interval = 3
        final_status = None
        final_progress = 0

        for poll_num in range(1, max_polls + 1):
            result = await client.get(f"/api/ai_agents/tasks/{task_id}")
            if result.status == "PASS" and result.data:
                data = result.data.get("data", result.data)
                if isinstance(data, dict):
                    final_status = data.get("status", data.get("state"))
                    final_progress = data.get("progress", 0)
                    print(f"  轮询 [{poll_num}/{max_polls}] status={final_status} progress={final_progress}%")

                    if final_status in ("completed", "failed", "error"):
                        break
                    if final_progress >= 100:
                        break
            else:
                print(f"  轮询 [{poll_num}/{max_polls}] 请求失败: {result.status_code}")

            if poll_num < max_polls:
                await asyncio.sleep(poll_interval)

        # 11. 验证最终状态
        print(f"\n[11/11] 验证最终状态: status={final_status}, progress={final_progress}")
        if final_status == "completed" and final_progress == 100:
            print("  [PASS] 扫描任务已完成, 进度100% ✓")
        elif final_status == "completed":
            print(f"  [PASS] 扫描任务已完成 ✓ (进度: {final_progress}%)")
        elif final_status == "failed":
            print(f"  [WARN] 扫描任务失败 (进度: {final_progress}%)")
        elif final_status == "running":
            print(f"  [WARN] 扫描任务仍在运行 (进度: {final_progress}%), 可能超时")
        else:
            print(f"  [WARN] 最终状态: {final_status} (进度: {final_progress}%)")
    else:
        print("\n[10/11] [SKIP] 无任务ID, 跳过轮询步骤")
        print("[11/11] [SKIP] 无任务ID, 跳过状态验证步骤")

    client.print_summary()
    return client


if __name__ == "__main__":
    asyncio.run(run_ai_agents_tests())