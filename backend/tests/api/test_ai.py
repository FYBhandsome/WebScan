import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from tests.conftest import APITestClient, assert_status, assert_data_exists
from tests.fixtures.test_data import AI_CHAT_DATA


async def run_ai_tests():
    client = APITestClient()
    print("=" * 70)
    print("  AI 模块 API 测试")
    print("=" * 70)

    created_instance_id = None

    # 1. 获取对话实例列表
    print("\n[1] GET /api/ai/chat/instances - 获取对话实例列表")
    r = await client.get("/api/ai/chat/instances")
    print(f"    状态: {r.status} | 状态码: {r.status_code} | 耗时: {r.duration_ms:.0f}ms")
    if assert_status(r, 200):
        count = client.extract_list_count(r)
        print(f"    对话实例数: {count}")
    else:
        print(f"    错误: {r.error}")

    # 2. AI连接状态
    print("\n[2] GET /api/ai/status 和 GET /api/ai/connection-status - AI连接状态")
    r_status = await client.get("/api/ai/status")
    print(f"    /api/ai/status       -> 状态: {r_status.status} | 状态码: {r_status.status_code}")
    if r_status.error:
        print(f"    错误: {r_status.error}")

    r_conn = await client.get("/api/ai/connection-status")
    print(f"    /api/ai/connection-status -> 状态: {r_conn.status} | 状态码: {r_conn.status_code}")
    if r_conn.error:
        print(f"    错误: {r_conn.error}")

    # 3. 创建对话实例
    print("\n[3] POST /api/ai/chat/instances - 创建对话实例")
    r_create = await client.post("/api/ai/chat/instances", data=AI_CHAT_DATA["create_chat"])
    print(f"    状态: {r_create.status} | 状态码: {r_create.status_code} | 耗时: {r_create.duration_ms:.0f}ms")
    if assert_status(r_create, 200) and assert_data_exists(r_create):
        created_instance_id = client.extract_id(r_create, "id") or client.extract_id(r_create, "instance_id")
        print(f"    创建的对话实例ID: {created_instance_id}")
        client.created_resources["chats"].append(created_instance_id)
    else:
        print(f"    错误: {r_create.error}")

    # 4. 发送消息
    if created_instance_id:
        print(f"\n[4] POST /api/ai/chat?instance_id={created_instance_id} - 发送消息")
        r_chat = await client.post(f"/api/ai/chat?instance_id={created_instance_id}", data=AI_CHAT_DATA["chat_message"], timeout=60)
        print(f"    状态: {r_chat.status} | 状态码: {r_chat.status_code} | 耗时: {r_chat.duration_ms:.0f}ms")
        if r_chat.error:
            print(f"    错误: {r_chat.error}")
        else:
            print(f"    响应数据: {str(r_chat.data)[:200]}")

        # 5. 获取对话详情
        print(f"\n[5] GET /api/ai/chat/instances/{created_instance_id} - 获取对话详情")
        r_detail = await client.get(f"/api/ai/chat/instances/{created_instance_id}")
        print(f"    状态: {r_detail.status} | 状态码: {r_detail.status_code} | 耗时: {r_detail.duration_ms:.0f}ms")
        if assert_status(r_detail, 200) and assert_data_exists(r_detail):
            print(f"    对话详情获取成功")
        else:
            print(f"    错误: {r_detail.error}")
    else:
        print("\n[4] 跳过 - 无有效对话实例ID")
        print("\n[5] 跳过 - 无有效对话实例ID")

    # 6. AI漏洞分析
    print("\n[6] POST /api/ai/analyze - AI漏洞分析")
    r_analyze = await client.post("/api/ai/analyze", data=AI_CHAT_DATA["vuln_analysis"], timeout=60)
    print(f"    状态: {r_analyze.status} | 状态码: {r_analyze.status_code} | 耗时: {r_analyze.duration_ms:.0f}ms")
    if r_analyze.error:
        print(f"    错误: {r_analyze.error}")
    elif assert_data_exists(r_analyze):
        print(f"    漏洞分析完成")

    await client.cleanup()
    client.print_summary()


if __name__ == "__main__":
    asyncio.run(run_ai_tests())