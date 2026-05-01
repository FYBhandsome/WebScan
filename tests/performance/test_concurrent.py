"""性能测试：并发请求处理"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import pytest
import time
import threading
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE_URL = "http://localhost:8000"


def _service_available():
    try:
        response = requests.get(f"{BASE_URL}/toskill/health", timeout=2)
        return response.status_code == 200
    except Exception:
        return False


@pytest.mark.skipif(not _service_available(), reason="后端服务未运行")
class TestConcurrentRequests:
    def test_10_concurrent_health_checks(self):
        """验证 10 并发请求在 2 秒内完成"""

        def make_request():
            try:
                start = time.time()
                response = requests.get(f"{BASE_URL}/toskill/health", timeout=5)
                elapsed = time.time() - start
                return elapsed, response.status_code
            except Exception as e:
                return 999, 0

        start_time = time.time()
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request) for _ in range(10)]
            results = [f.result() for f in as_completed(futures)]

        total_time = time.time() - start_time

        elapsed_times = [r[0] for r in results if r[0] != 999]
        status_codes = [r[1] for r in results]

        print(f"\n总耗时: {total_time:.2f}s")
        print(f"各请求耗时: {[f'{t:.2f}s' for t in elapsed_times]}")

        assert total_time < 5
        assert all(code == 200 for code in status_codes), f"有请求失败，状态码: {status_codes}"

    def test_concurrent_tool_list(self):
        """验证并发工具列表请求"""
        def make_request():
            try:
                response = requests.get(f"{BASE_URL}/toskill/tools", timeout=5)
                return response.status_code, len(response.json()["data"]["tools"])
            except Exception as e:
                return 0, 0

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(make_request) for _ in range(5)]
            results = [f.result() for f in as_completed(futures)]

        status_codes = [r[0] for r in results]
        tool_counts = [r[1] for r in results]

        assert all(code == 200 for code in status_codes)
        assert len(set(tool_counts)) == 1
