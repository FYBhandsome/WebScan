import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from tests.conftest import APITestClient, assert_status


async def run_kb_tests():
    client = APITestClient()
    print("=" * 70)
    print("  知识库 (KB) 模块 API 测试")
    print("=" * 70)

    # 1. 漏洞列表（分页）
    print("\n[1] GET /api/kb/vulnerabilities?page=1&page_size=10 - 漏洞列表（分页）")
    r = await client.get("/api/kb/vulnerabilities", params={"page": 1, "page_size": 10})
    print(f"    状态: {r.status} | 状态码: {r.status_code} | 耗时: {r.duration_ms:.0f}ms")
    if assert_status(r, 200):
        count = client.extract_list_count(r)
        print(f"    返回记录数: {count}")
    else:
        print(f"    错误: {r.error}")

    # 2. 按严重度筛选
    print("\n[2] GET /api/kb/vulnerabilities?page=1&page_size=10&severity=critical - 按严重度筛选")
    r = await client.get("/api/kb/vulnerabilities", params={"page": 1, "page_size": 10, "severity": "critical"})
    print(f"    状态: {r.status} | 状态码: {r.status_code} | 耗时: {r.duration_ms:.0f}ms")
    if assert_status(r, 200):
        count = client.extract_list_count(r)
        print(f"    critical漏洞数: {count}")
    else:
        print(f"    错误: {r.error}")

    # 3. 搜索漏洞
    print("\n[3] GET /api/kb/vulnerabilities?page=1&page_size=10&search=sql - 搜索漏洞")
    r = await client.get("/api/kb/vulnerabilities", params={"page": 1, "page_size": 10, "search": "sql"})
    print(f"    状态: {r.status} | 状态码: {r.status_code} | 耗时: {r.duration_ms:.0f}ms")
    if assert_status(r, 200):
        count = client.extract_list_count(r)
        print(f"    搜索'sql'结果数: {count}")
    else:
        print(f"    错误: {r.error}")

    # 4. 同步漏洞知识库
    print("\n[4] POST /api/kb/sync - 同步漏洞知识库")
    r = await client.post("/api/kb/sync", timeout=60)
    print(f"    状态: {r.status} | 状态码: {r.status_code} | 耗时: {r.duration_ms:.0f}ms")
    if r.error:
        print(f"    错误: {r.error}")
    else:
        print(f"    同步完成")

    # 5. 从Seebug搜索
    print("\n[5] POST /api/kb/search-from-seebug - 从Seebug搜索")
    r = await client.post("/api/kb/search-from-seebug", data={"keyword": "log4j"}, timeout=30)
    print(f"    状态: {r.status} | 状态码: {r.status_code} | 耗时: {r.duration_ms:.0f}ms")
    if r.error:
        print(f"    错误: {r.error}")
    elif assert_status(r, 200):
        print(f"    Seebug搜索结果获取成功")

    # 6. Seebug状态
    print("\n[6] GET /api/seebug/status - Seebug状态")
    r = await client.get("/api/seebug/status")
    print(f"    状态: {r.status} | 状态码: {r.status_code} | 耗时: {r.duration_ms:.0f}ms")
    if r.error:
        print(f"    错误: {r.error}")
    elif assert_status(r, 200):
        print(f"    Seebug连接状态正常")

    # 7. 获取漏洞详情
    print("\n[7] GET /api/vulnerabilities/1 - 获取漏洞详情")
    r = await client.get("/api/vulnerabilities/1")
    print(f"    状态: {r.status} | 状态码: {r.status_code} | 耗时: {r.duration_ms:.0f}ms")
    if assert_status(r, 200):
        print(f"    漏洞详情获取成功")
    else:
        print(f"    错误: {r.error}")

    await client.cleanup()
    client.print_summary()


if __name__ == "__main__":
    asyncio.run(run_kb_tests())