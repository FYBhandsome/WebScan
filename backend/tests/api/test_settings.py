import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from tests.conftest import APITestClient, assert_status
from tests.fixtures.test_data import SETTINGS_DATA


async def run_settings_tests():
    client = APITestClient()
    print("=" * 70)
    print("  设置 (Settings) 模块 API 测试")
    print("=" * 70)

    # 1. 获取所有设置
    print("\n[1] GET /api/settings/ - 获取所有设置")
    r = await client.get("/api/settings/")
    print(f"    状态: {r.status} | 状态码: {r.status_code} | 耗时: {r.duration_ms:.0f}ms")
    if assert_status(r, 200):
        print(f"    所有设置获取成功")
    else:
        print(f"    错误: {r.error}")

    # 2. 更新设置
    print("\n[2] PUT /api/settings/ - 更新设置")
    r = await client.put("/api/settings/", data=SETTINGS_DATA["general"])
    print(f"    状态: {r.status} | 状态码: {r.status_code} | 耗时: {r.duration_ms:.0f}ms")
    if r.error:
        print(f"    错误: {r.error}")
    elif assert_status(r, 200):
        print(f"    设置更新成功")

    # 3. 获取分类
    print("\n[3] GET /api/settings/categories - 获取分类")
    r = await client.get("/api/settings/categories")
    print(f"    状态: {r.status} | 状态码: {r.status_code} | 耗时: {r.duration_ms:.0f}ms")
    if assert_status(r, 200):
        print(f"    分类获取成功")
    else:
        print(f"    错误: {r.error}")

    # 4. 按分类获取
    print("\n[4] GET /api/settings/category/general - 按分类获取")
    r = await client.get("/api/settings/category/general")
    print(f"    状态: {r.status} | 状态码: {r.status_code} | 耗时: {r.duration_ms:.0f}ms")
    if assert_status(r, 200):
        print(f"    general分类设置获取成功")
    else:
        print(f"    错误: {r.error}")

    # 5. 获取单个设置项
    print("\n[5] GET /api/settings/item/general/scan_timeout - 获取单个设置项")
    r = await client.get("/api/settings/item/general/scan_timeout")
    print(f"    状态: {r.status} | 状态码: {r.status_code} | 耗时: {r.duration_ms:.0f}ms")
    if assert_status(r, 200):
        print(f"    scan_timeout设置项获取成功")
    else:
        print(f"    错误: {r.error}")

    # 6. 更新单个设置项
    print("\n[6] PUT /api/settings/item - 更新单个设置项")
    r = await client.put("/api/settings/item", data={
        "category": "general",
        "key": "scan_timeout",
        "value": "600"
    })
    print(f"    状态: {r.status} | 状态码: {r.status_code} | 耗时: {r.duration_ms:.0f}ms")
    if r.error:
        print(f"    错误: {r.error}")
    elif assert_status(r, 200):
        print(f"    单个设置项更新成功")

    # 7. 系统信息
    print("\n[7] GET /api/settings/system-info - 系统信息")
    r = await client.get("/api/settings/system-info")
    print(f"    状态: {r.status} | 状态码: {r.status_code} | 耗时: {r.duration_ms:.0f}ms")
    if assert_status(r, 200):
        print(f"    系统信息获取成功")
    else:
        print(f"    错误: {r.error}")

    # 8. 统计信息
    print("\n[8] GET /api/settings/statistics?period=7 - 统计信息")
    r = await client.get("/api/settings/statistics", params={"period": 7})
    print(f"    状态: {r.status} | 状态码: {r.status_code} | 耗时: {r.duration_ms:.0f}ms")
    if assert_status(r, 200):
        print(f"    统计信息获取成功")
    else:
        print(f"    错误: {r.error}")

    # 9. API Key列表
    print("\n[9] GET /api/settings/api-keys - API Key列表")
    r = await client.get("/api/settings/api-keys")
    print(f"    状态: {r.status} | 状态码: {r.status_code} | 耗时: {r.duration_ms:.0f}ms")
    if assert_status(r, 200):
        print(f"    API Key列表获取成功")
    else:
        print(f"    错误: {r.error}")

    # 10. 创建API Key
    print("\n[10] POST /api/settings/api-keys - 创建API Key")
    r = await client.post("/api/settings/api-keys", data=SETTINGS_DATA["api_key_test"])
    print(f"    状态: {r.status} | 状态码: {r.status_code} | 耗时: {r.duration_ms:.0f}ms")
    if assert_status(r, 200):
        key_id = client.extract_id(r, "id")
        if key_id:
            client.created_resources["api_keys"].append(key_id)
            print(f"    API Key创建成功, ID: {key_id}")
        else:
            print(f"    API Key创建成功")
    else:
        print(f"    错误: {r.error}")

    await client.cleanup()
    client.print_summary()


if __name__ == "__main__":
    asyncio.run(run_settings_tests())