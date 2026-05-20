import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from tests.conftest import APITestClient, assert_status, assert_field_exists


async def run_user_tests():
    client = APITestClient()
    print("=" * 70)
    print("  用户 (User) 模块 API 测试")
    print("=" * 70)

    # 1. 获取用户资料
    print("\n[1] GET /api/user/profile?user_id=1 - 获取用户资料")
    r = await client.get("/api/user/profile", params={"user_id": 1})
    print(f"    状态: {r.status} | 状态码: {r.status_code} | 耗时: {r.duration_ms:.0f}ms")
    if assert_status(r, 200):
        has_username = assert_field_exists(r, "username")
        has_email = assert_field_exists(r, "email")
        print(f"    用户资料获取成功 (username: {has_username}, email: {has_email})")
    else:
        print(f"    错误: {r.error}")

    # 2. 更新用户资料
    print("\n[2] PUT /api/user/profile?user_id=1 - 更新用户资料")
    r = await client.put("/api/user/profile", data={
        "username": "admin",
        "email": "admin@example.com",
        "phone": "13800138000"
    }, timeout=30)
    print(f"    状态: {r.status} | 状态码: {r.status_code} | 耗时: {r.duration_ms:.0f}ms")
    if r.error:
        print(f"    错误: {r.error}")
    elif assert_status(r, 200):
        print(f"    用户资料更新成功")

    # 3. 获取用户权限
    print("\n[3] GET /api/user/permissions?user_id=1 - 获取用户权限")
    r = await client.get("/api/user/permissions", params={"user_id": 1})
    print(f"    状态: {r.status} | 状态码: {r.status_code} | 耗时: {r.duration_ms:.0f}ms")
    if assert_status(r, 200):
        print(f"    用户权限获取成功")
    else:
        print(f"    错误: {r.error}")

    # 4. 用户列表
    print("\n[4] GET /api/user/list - 用户列表")
    r = await client.get("/api/user/list")
    print(f"    状态: {r.status} | 状态码: {r.status_code} | 耗时: {r.duration_ms:.0f}ms")
    if assert_status(r, 200):
        count = client.extract_list_count(r)
        print(f"    用户总数: {count}")
    else:
        print(f"    错误: {r.error}")

    await client.cleanup()
    client.print_summary()


if __name__ == "__main__":
    asyncio.run(run_user_tests())