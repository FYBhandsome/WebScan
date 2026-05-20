"""
测试基础配置 - 提供测试客户端、数据工厂、断言工具等基础设施
"""
import httpx
import json
import time
import sys
import os
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

BASE_URL = "http://127.0.0.1:8899"
API_PREFIX = "/api"

@dataclass
class TestResult:
    endpoint: str
    method: str
    status: str
    status_code: int
    data: Any
    error: Optional[str] = None
    duration_ms: float = 0

class APITestClient:
    """模拟前端的HTTP客户端，封装常见请求模式"""

    def __init__(self, base_url: str = BASE_URL):
        self.base_url = base_url
        self.results: List[TestResult] = []
        self.created_resources: Dict[str, List[int]] = {
            "tasks": [],
            "reports": [],
            "notifications": [],
            "api_keys": [],
            "chats": [],
            "agent_tasks": []
        }

    async def _request(self, method: str, path: str, data: Any = None, params: Dict = None, timeout: int = 30) -> TestResult:
        url = f"{self.base_url}{path}"
        start = time.time()
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                if method == "GET":
                    resp = await client.get(url, params=params)
                elif method == "POST":
                    resp = await client.post(url, json=data)
                elif method == "PUT":
                    resp = await client.put(url, json=data)
                elif method == "DELETE":
                    resp = await client.delete(url)
                else:
                    return TestResult(path, method, "SKIP", 0, None, f"Unknown method: {method}")

            duration = (time.time() - start) * 1000
            status_code = resp.status_code

            if resp.status_code < 400:
                try:
                    body = resp.json()
                except Exception:
                    body = resp.text
                result = TestResult(path, method, "PASS", status_code, body, duration_ms=duration)
            else:
                result = TestResult(path, method, "FAIL", status_code, None, f"HTTP {resp.status_code}: {resp.text[:200]}", duration)
        except Exception as e:
            duration = (time.time() - start) * 1000
            result = TestResult(path, method, "ERROR", 0, None, str(e), duration)

        self.results.append(result)
        return result

    async def get(self, path: str, params: Dict = None, timeout: int = 30) -> TestResult:
        return await self._request("GET", path, params=params, timeout=timeout)

    async def post(self, path: str, data: Any = None, timeout: int = 30) -> TestResult:
        return await self._request("POST", path, data=data, timeout=timeout)

    async def put(self, path: str, data: Any = None, timeout: int = 30) -> TestResult:
        return await self._request("PUT", path, data=data, timeout=timeout)

    async def delete(self, path: str, timeout: int = 30) -> TestResult:
        return await self._request("DELETE", path, timeout=timeout)

    def extract_id(self, result: TestResult, key: str = "id") -> Optional[int]:
        if result.data and isinstance(result.data, dict):
            data = result.data.get("data", result.data)
            if isinstance(data, dict):
                val = data.get(key)
                if val is not None:
                    return val
                for alt_key in ["task_id", "report_id", "notification_id", "id"]:
                    val = data.get(alt_key)
                    if val is not None:
                        return val
        return None

    def extract_list_count(self, result: TestResult) -> int:
        if result.data and isinstance(result.data, dict):
            data = result.data.get("data", result.data)
            if isinstance(data, list):
                return len(data)
            if isinstance(data, dict) and "items" in data:
                return len(data["items"])
            if isinstance(data, dict) and "total" in data:
                return data["total"]
        return 0

    async def cleanup(self):
        """清理所有测试创建的资源"""
        print("\n--- 清理测试资源 ---")
        for task_id in self.created_resources.get("tasks", []):
            try:
                await self.delete(f"/api/tasks/{task_id}")
                print(f"  [CLEAN] 任务 {task_id} 已删除")
            except Exception as e:
                print(f"  [SKIP] 任务 {task_id}: {e}")
        for report_id in self.created_resources.get("reports", []):
            try:
                await self.delete(f"/api/reports/{report_id}")
                print(f"  [CLEAN] 报告 {report_id} 已删除")
            except Exception:
                pass
        for notif_id in self.created_resources.get("notifications", []):
            try:
                await self.delete(f"/api/notifications/{notif_id}")
            except Exception:
                pass
        for key_id in self.created_resources.get("api_keys", []):
            try:
                await self.delete(f"/api/settings/api-keys/{key_id}")
            except Exception:
                pass

    def print_summary(self):
        passed = sum(1 for r in self.results if r.status == "PASS")
        failed = sum(1 for r in self.results if r.status == "FAIL")
        errors = sum(1 for r in self.results if r.status == "ERROR")
        total = len(self.results)
        print(f"\n{'='*70}")
        print(f"  测试总结: 总计 {total} | 通过 {passed} | 失败 {failed} | 错误 {errors}")
        print(f"{'='*70}")
        for r in self.results:
            icon = {"PASS": "✓", "FAIL": "✗", "ERROR": "⚠", "SKIP": "→"}.get(r.status, "?")
            print(f"  [{icon}] {r.method:6} {r.endpoint:55} {r.status_code:3} {r.duration_ms:.0f}ms")
            if r.error:
                print(f"       Error: {r.error[:120]}")

def assert_status(result: TestResult, expected_code: int = 200) -> bool:
    """断言HTTP状态码"""
    return result.status_code == expected_code

def assert_data_exists(result: TestResult) -> bool:
    """断言响应中有有效数据"""
    return result.data is not None

def assert_list_not_empty(result: TestResult) -> bool:
    """断言列表不为空"""
    if result.data and isinstance(result.data, dict):
        data = result.data.get("data", result.data)
        if isinstance(data, list):
            return len(data) > 0
        if isinstance(data, dict):
            return data.get("total", 0) > 0 or len(data.get("items", [])) > 0
    return False

def assert_field_exists(result: TestResult, field: str) -> bool:
    """断言字段存在"""
    if result.data and isinstance(result.data, dict):
        data = result.data.get("data", result.data)
        if isinstance(data, dict):
            return field in data
        if isinstance(data, list) and data:
            return field in data[0]
    return False