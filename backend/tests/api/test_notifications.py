import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from tests.conftest import APITestClient, assert_status
from tests.fixtures.test_data import NOTIFICATION_DATA


async def run_notification_tests():
    client = APITestClient()
    print("=" * 70)
    print("  通知系统 API 集成测试")
    print("=" * 70)

    created_notif_ids = []

    # 1. 获取通知列表
    print("\n[1/11] GET /api/notifications/ - 获取通知列表")
    result = await client.get("/api/notifications/")
    print(f"  状态码: {result.status_code} | 结果: {result.status}")
    assert_status(result, 200)
    if result.data:
        count = client.extract_list_count(result)
        print(f"  当前通知数量: {count}")

    # 2. 获取未读数
    print("\n[2/11] GET /api/notifications/count/unread - 获取未读数")
    result = await client.get("/api/notifications/count/unread")
    print(f"  状态码: {result.status_code} | 结果: {result.status}")
    assert_status(result, 200)
    if result.data and isinstance(result.data, dict):
        data = result.data.get("data", result.data)
        if isinstance(data, dict):
            unread = data.get("count", data.get("unread_count", "N/A"))
            print(f"  未读通知数量: {unread}")

    # 3. 创建通知 - 扫描完成
    print("\n[3/11] POST /api/notifications/ - 创建通知 (scan_completed)")
    payload = NOTIFICATION_DATA["scan_completed"]
    result = await client.post("/api/notifications/", data=payload)
    print(f"  状态码: {result.status_code} | 结果: {result.status}")
    assert_status(result, 200)
    notif_id = client.extract_id(result)
    if notif_id:
        print(f"  创建的通知ID: {notif_id}")
        created_notif_ids.append(notif_id)
        client.created_resources["notifications"].append(notif_id)

    # 4. 创建通知 - 漏洞发现
    print("\n[4/11] POST /api/notifications/ - 创建通知 (vuln_found)")
    payload = NOTIFICATION_DATA["vuln_found"]
    result = await client.post("/api/notifications/", data=payload)
    print(f"  状态码: {result.status_code} | 结果: {result.status}")
    assert_status(result, 200)
    notif_id = client.extract_id(result)
    if notif_id:
        print(f"  创建的通知ID: {notif_id}")
        created_notif_ids.append(notif_id)
        client.created_resources["notifications"].append(notif_id)

    # 5. 创建通知 - 扫描失败
    print("\n[5/11] POST /api/notifications/ - 创建通知 (scan_failed)")
    payload = NOTIFICATION_DATA["scan_failed"]
    result = await client.post("/api/notifications/", data=payload)
    print(f"  状态码: {result.status_code} | 结果: {result.status}")
    assert_status(result, 200)
    notif_id = client.extract_id(result)
    if notif_id:
        print(f"  创建的通知ID: {notif_id}")
        created_notif_ids.append(notif_id)
        client.created_resources["notifications"].append(notif_id)

    # 6. 获取单条通知
    if created_notif_ids:
        notif_id = created_notif_ids[0]
        print(f"\n[6/11] GET /api/notifications/{notif_id} - 获取单条通知")
        result = await client.get(f"/api/notifications/{notif_id}")
        print(f"  状态码: {result.status_code} | 结果: {result.status}")
        assert_status(result, 200)
        if result.data and isinstance(result.data, dict):
            data = result.data.get("data", result.data)
            if isinstance(data, dict):
                print(f"  通知标题: {data.get('title', 'N/A')}")
    else:
        print("\n[6/11] [SKIP] 无已创建的通知ID, 跳过获取单条通知")

    # 7. 标记已读
    if created_notif_ids:
        notif_id = created_notif_ids[0]
        print(f"\n[7/11] PUT /api/notifications/{notif_id}/read - 标记已读")
        result = await client.put(f"/api/notifications/{notif_id}/read")
        print(f"  状态码: {result.status_code} | 结果: {result.status}")
        assert_status(result, 200)
    else:
        print("\n[7/11] [SKIP] 无已创建的通知ID, 跳过标记已读")

    # 8. 全部标记已读
    print("\n[8/11] PUT /api/notifications/read-all - 全部标记已读")
    result = await client.put("/api/notifications/read-all")
    print(f"  状态码: {result.status_code} | 结果: {result.status}")
    assert_status(result, 200)

    # 9. 再次获取未读数
    print("\n[9/11] GET /api/notifications/count/unread - 再次获取未读数 (应为0)")
    result = await client.get("/api/notifications/count/unread")
    print(f"  状态码: {result.status_code} | 结果: {result.status}")
    assert_status(result, 200)
    if result.data and isinstance(result.data, dict):
        data = result.data.get("data", result.data)
        if isinstance(data, dict):
            unread = data.get("count", data.get("unread_count", "N/A"))
            print(f"  未读通知数量: {unread}")

    # 10. 删除单条通知
    if created_notif_ids:
        notif_id = created_notif_ids[0]
        print(f"\n[10/11] DELETE /api/notifications/{notif_id} - 删除通知")
        result = await client.delete(f"/api/notifications/{notif_id}")
        print(f"  状态码: {result.status_code} | 结果: {result.status}")
        assert_status(result, 200)
    else:
        print("\n[10/11] [SKIP] 无已创建的通知ID, 跳过删除通知")

    # 11. 删除已读通知
    print("\n[11/11] DELETE /api/notifications/ - 删除已读通知")
    result = await client.delete("/api/notifications/")
    print(f"  状态码: {result.status_code} | 结果: {result.status}")
    assert_status(result, 200)

    client.print_summary()
    return client


if __name__ == "__main__":
    asyncio.run(run_notification_tests())