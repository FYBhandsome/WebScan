"""
集成测试脚本 - 测试完整的业务流程

测试内容:
1. POC 验证流程
2. Seebug 数据同步流程
3. 前端到后端的完整流程
"""
import asyncio
import httpx
import json
import sys
from datetime import datetime
from typing import Dict, Any, List, Optional

BASE_URL = "http://127.0.0.1:8888/api"
TIMEOUT = 30.0

class TestResult:
    def __init__(self, name: str):
        self.name = name
        self.success = False
        self.message = ""
        self.data: Optional[Dict[str, Any]] = None
        self.error: Optional[str] = None
        self.duration_ms = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "success": self.success,
            "message": self.message,
            "data": self.data,
            "error": self.error,
            "duration_ms": self.duration_ms
        }


class IntegrationTester:
    def __init__(self):
        self.client = httpx.AsyncClient(base_url=BASE_URL, timeout=TIMEOUT)
        self.results: List[TestResult] = []
        self.test_summary = {
            "total": 0,
            "passed": 0,
            "failed": 0,
            "start_time": None,
            "end_time": None
        }

    async def close(self):
        await self.client.aclose()

    def add_result(self, result: TestResult):
        self.results.append(result)
        self.test_summary["total"] += 1
        if result.success:
            self.test_summary["passed"] += 1
            status = "✅ PASS"
        else:
            self.test_summary["failed"] += 1
            status = "❌ FAIL"
        print(f"{status}: {result.name} ({result.duration_ms:.0f}ms)")
        if result.message:
            print(f"   消息: {result.message}")
        if result.error:
            print(f"   错误: {result.error}")

    async def test_health_check(self) -> TestResult:
        result = TestResult("健康检查 - 后端服务")
        start = datetime.now()
        try:
            response = await self.client.get("/../health")
            result.duration_ms = (datetime.now() - start).total_seconds() * 1000
            if response.status_code == 200:
                data = response.json()
                result.success = True
                result.message = "后端服务运行正常"
                result.data = data
            else:
                result.error = f"HTTP {response.status_code}"
                result.message = "后端服务异常"
        except Exception as e:
            result.duration_ms = (datetime.now() - start).total_seconds() * 1000
            result.error = str(e)
            result.message = "无法连接后端服务"
        return result

    async def test_poc_verification_health(self) -> TestResult:
        result = TestResult("POC 验证系统健康检查")
        start = datetime.now()
        try:
            response = await self.client.get("/poc/verification/health")
            result.duration_ms = (datetime.now() - start).total_seconds() * 1000
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 200:
                    result.success = True
                    result.message = "POC 验证系统运行正常"
                    result.data = data.get("data")
                else:
                    result.error = data.get("message", "未知错误")
                    result.message = "POC 验证系统异常"
            else:
                result.error = f"HTTP {response.status_code}"
                result.message = "POC 验证系统请求失败"
        except Exception as e:
            result.duration_ms = (datetime.now() - start).total_seconds() * 1000
            result.error = str(e)
            result.message = "POC 验证系统请求异常"
        return result

    async def test_poc_list_tasks(self) -> TestResult:
        result = TestResult("POC 验证任务列表")
        start = datetime.now()
        try:
            response = await self.client.get("/poc/verification/tasks", params={"page": 1, "page_size": 10})
            result.duration_ms = (datetime.now() - start).total_seconds() * 1000
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 200:
                    result.success = True
                    items = data.get("data", {}).get("items", [])
                    total = data.get("data", {}).get("total", 0)
                    result.message = f"获取任务列表成功，共 {total} 条记录"
                    result.data = {"total": total, "items_count": len(items)}
                else:
                    result.error = data.get("message", "未知错误")
                    result.message = "获取任务列表失败"
            else:
                result.error = f"HTTP {response.status_code}"
                result.message = "请求失败"
        except Exception as e:
            result.duration_ms = (datetime.now() - start).total_seconds() * 1000
            result.error = str(e)
            result.message = "请求异常"
        return result

    async def test_poc_types(self) -> TestResult:
        result = TestResult("POC 类型列表")
        start = datetime.now()
        try:
            response = await self.client.get("/poc/types")
            result.duration_ms = (datetime.now() - start).total_seconds() * 1000
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 200:
                    result.success = True
                    poc_types = data.get("data", [])
                    if isinstance(poc_types, list):
                        result.message = f"获取 POC 类型成功，共 {len(poc_types)} 种类型"
                        result.data = {"types_count": len(poc_types)}
                    else:
                        result.message = f"获取 POC 类型成功"
                        result.data = {"types": poc_types}
                else:
                    result.error = data.get("message", "未知错误")
                    result.message = "获取 POC 类型失败"
            else:
                result.error = f"HTTP {response.status_code}"
                result.message = "请求失败"
        except Exception as e:
            result.duration_ms = (datetime.now() - start).total_seconds() * 1000
            result.error = str(e)
            result.message = "请求异常"
        return result

    async def test_seebug_status(self) -> TestResult:
        result = TestResult("Seebug API 状态检查")
        start = datetime.now()
        try:
            response = await self.client.get("/seebug/status")
            result.duration_ms = (datetime.now() - start).total_seconds() * 1000
            if response.status_code == 200:
                data = response.json()
                result.success = True
                available = data.get("data", {}).get("available", False)
                if available:
                    result.message = "Seebug API 可用"
                else:
                    result.message = "Seebug API 不可用（可能未配置 API Key）"
                result.data = data.get("data")
            else:
                result.error = f"HTTP {response.status_code}"
                result.message = "请求失败"
        except Exception as e:
            result.duration_ms = (datetime.now() - start).total_seconds() * 1000
            result.error = str(e)
            result.message = "请求异常"
        return result

    async def test_seebug_poc_search(self) -> TestResult:
        result = TestResult("Seebug POC 搜索")
        start = datetime.now()
        try:
            response = await self.client.get("/seebug/poc/search", params={"keyword": "CVE", "page": 1, "page_size": 5})
            result.duration_ms = (datetime.now() - start).total_seconds() * 1000
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 200:
                    result.success = True
                    poc_list = data.get("data", {}).get("list", [])
                    result.message = f"POC 搜索成功，找到 {len(poc_list)} 条记录"
                    result.data = {"results_count": len(poc_list)}
                else:
                    result.error = data.get("message", "未知错误")
                    result.message = f"POC 搜索失败: {data.get('message', '')}"
            else:
                result.error = f"HTTP {response.status_code}"
                result.message = "请求失败"
        except Exception as e:
            result.duration_ms = (datetime.now() - start).total_seconds() * 1000
            result.error = str(e)
            result.message = "请求异常"
        return result

    async def test_seebug_statistics(self) -> TestResult:
        result = TestResult("Seebug 统计信息")
        start = datetime.now()
        try:
            response = await self.client.get("/seebug/statistics")
            result.duration_ms = (datetime.now() - start).total_seconds() * 1000
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 200:
                    result.success = True
                    result.message = "获取统计信息成功"
                    result.data = data.get("data")
                else:
                    result.error = data.get("message", "未知错误")
                    result.message = "获取统计信息失败"
            else:
                result.error = f"HTTP {response.status_code}"
                result.message = "请求失败"
        except Exception as e:
            result.duration_ms = (datetime.now() - start).total_seconds() * 1000
            result.error = str(e)
            result.message = "请求异常"
        return result

    async def test_tasks_list(self) -> TestResult:
        result = TestResult("任务列表")
        start = datetime.now()
        try:
            response = await self.client.get("/tasks/", params={"page": 1, "page_size": 10})
            result.duration_ms = (datetime.now() - start).total_seconds() * 1000
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 200:
                    result.success = True
                    items = data.get("data", {}).get("items", [])
                    total = data.get("data", {}).get("total", 0)
                    result.message = f"获取任务列表成功，共 {total} 条记录"
                    result.data = {"total": total, "items_count": len(items)}
                else:
                    result.error = data.get("message", "未知错误")
                    result.message = "获取任务列表失败"
            else:
                result.error = f"HTTP {response.status_code}"
                result.message = "请求失败"
        except Exception as e:
            result.duration_ms = (datetime.now() - start).total_seconds() * 1000
            result.error = str(e)
            result.message = "请求异常"
        return result

    async def test_reports_list(self) -> TestResult:
        result = TestResult("报告列表")
        start = datetime.now()
        try:
            response = await self.client.get("/reports/", params={"page": 1, "page_size": 10})
            result.duration_ms = (datetime.now() - start).total_seconds() * 1000
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 200:
                    result.success = True
                    items = data.get("data", {}).get("items", [])
                    total = data.get("data", {}).get("total", 0)
                    result.message = f"获取报告列表成功，共 {total} 条记录"
                    result.data = {"total": total, "items_count": len(items)}
                else:
                    result.error = data.get("message", "未知错误")
                    result.message = "获取报告列表失败"
            else:
                result.error = f"HTTP {response.status_code}"
                result.message = "请求失败"
        except Exception as e:
            result.duration_ms = (datetime.now() - start).total_seconds() * 1000
            result.error = str(e)
            result.message = "请求异常"
        return result

    async def test_vulnerability_kb(self) -> TestResult:
        result = TestResult("漏洞知识库")
        start = datetime.now()
        try:
            response = await self.client.get("/kb/vulnerabilities", params={"page": 1, "page_size": 10})
            result.duration_ms = (datetime.now() - start).total_seconds() * 1000
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 200:
                    result.success = True
                    items = data.get("data", {}).get("items", [])
                    total = data.get("data", {}).get("total", 0)
                    result.message = f"获取漏洞知识库成功，共 {total} 条记录"
                    result.data = {"total": total, "items_count": len(items)}
                else:
                    result.error = data.get("message", "未知错误")
                    result.message = "获取漏洞知识库失败"
            else:
                result.error = f"HTTP {response.status_code}"
                result.message = "请求失败"
        except Exception as e:
            result.duration_ms = (datetime.now() - start).total_seconds() * 1000
            result.error = str(e)
            result.message = "请求异常"
        return result

    async def test_ai_agents_tools(self) -> TestResult:
        result = TestResult("AI Agents 工具列表")
        start = datetime.now()
        try:
            response = await self.client.get("/ai_agents/tools")
            result.duration_ms = (datetime.now() - start).total_seconds() * 1000
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 200:
                    result.success = True
                    tools = data.get("data", {}).get("tools", [])
                    result.message = f"获取工具列表成功，共 {len(tools)} 个工具"
                    result.data = {"tools_count": len(tools)}
                else:
                    result.error = data.get("message", "未知错误")
                    result.message = "获取工具列表失败"
            else:
                result.error = f"HTTP {response.status_code}"
                result.message = "请求失败"
        except Exception as e:
            result.duration_ms = (datetime.now() - start).total_seconds() * 1000
            result.error = str(e)
            result.message = "请求异常"
        return result

    async def test_ai_agents_config(self) -> TestResult:
        result = TestResult("AI Agents 配置")
        start = datetime.now()
        try:
            response = await self.client.get("/ai_agents/config")
            result.duration_ms = (datetime.now() - start).total_seconds() * 1000
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 200:
                    result.success = True
                    result.message = "获取 AI Agents 配置成功"
                    result.data = data.get("data")
                else:
                    result.error = data.get("message", "未知错误")
                    result.message = "获取配置失败"
            else:
                result.error = f"HTTP {response.status_code}"
                result.message = "请求失败"
        except Exception as e:
            result.duration_ms = (datetime.now() - start).total_seconds() * 1000
            result.error = str(e)
            result.message = "请求异常"
        return result

    async def test_settings(self) -> TestResult:
        result = TestResult("系统设置")
        start = datetime.now()
        try:
            response = await self.client.get("/settings/")
            result.duration_ms = (datetime.now() - start).total_seconds() * 1000
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 200:
                    result.success = True
                    result.message = "获取系统设置成功"
                    result.data = data.get("data")
                else:
                    result.error = data.get("message", "未知错误")
                    result.message = "获取系统设置失败"
            else:
                result.error = f"HTTP {response.status_code}"
                result.message = "请求失败"
        except Exception as e:
            result.duration_ms = (datetime.now() - start).total_seconds() * 1000
            result.error = str(e)
            result.message = "请求异常"
        return result

    async def test_user_profile(self) -> TestResult:
        result = TestResult("用户信息")
        start = datetime.now()
        try:
            response = await self.client.get("/user/profile", params={"user_id": 1})
            result.duration_ms = (datetime.now() - start).total_seconds() * 1000
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 200:
                    result.success = True
                    result.message = "获取用户信息成功"
                    result.data = data.get("data")
                else:
                    result.error = data.get("message", "未知错误")
                    result.message = "获取用户信息失败"
            else:
                result.error = f"HTTP {response.status_code}"
                result.message = "请求失败"
        except Exception as e:
            result.duration_ms = (datetime.now() - start).total_seconds() * 1000
            result.error = str(e)
            result.message = "请求异常"
        return result

    async def test_notifications(self) -> TestResult:
        result = TestResult("通知列表")
        start = datetime.now()
        try:
            response = await self.client.get("/notifications/", params={"page": 1, "page_size": 10})
            result.duration_ms = (datetime.now() - start).total_seconds() * 1000
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 200:
                    result.success = True
                    items = data.get("data", {}).get("items", [])
                    total = data.get("data", {}).get("total", 0)
                    result.message = f"获取通知列表成功，共 {total} 条记录"
                    result.data = {"total": total, "items_count": len(items)}
                else:
                    result.error = data.get("message", "未知错误")
                    result.message = "获取通知列表失败"
            else:
                result.error = f"HTTP {response.status_code}"
                result.message = "请求失败"
        except Exception as e:
            result.duration_ms = (datetime.now() - start).total_seconds() * 1000
            result.error = str(e)
            result.message = "请求异常"
        return result

    async def test_awvs_health(self) -> TestResult:
        result = TestResult("AWVS 连接检查")
        start = datetime.now()
        try:
            response = await self.client.get("/awvs/health")
            result.duration_ms = (datetime.now() - start).total_seconds() * 1000
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 200:
                    result.success = True
                    connected = data.get("data", {}).get("connected", False)
                    if connected:
                        result.message = "AWVS 连接正常"
                    else:
                        result.message = "AWVS 未连接（可能未配置）"
                    result.data = data.get("data")
                else:
                    result.error = data.get("message", "未知错误")
                    result.message = "AWVS 连接检查失败"
            else:
                result.error = f"HTTP {response.status_code}"
                result.message = "请求失败"
        except Exception as e:
            result.duration_ms = (datetime.now() - start).total_seconds() * 1000
            result.error = str(e)
            result.message = "请求异常"
        return result

    async def run_all_tests(self):
        self.test_summary["start_time"] = datetime.now().isoformat()
        print("\n" + "=" * 60)
        print("开始集成测试")
        print("=" * 60 + "\n")

        print("--- 基础健康检查 ---")
        self.add_result(await self.test_health_check())

        print("\n--- POC 验证流程测试 ---")
        self.add_result(await self.test_poc_verification_health())
        self.add_result(await self.test_poc_types())
        self.add_result(await self.test_poc_list_tasks())

        print("\n--- Seebug 数据同步流程测试 ---")
        self.add_result(await self.test_seebug_status())
        self.add_result(await self.test_seebug_poc_search())
        self.add_result(await self.test_seebug_statistics())

        print("\n--- 前端到后端完整流程测试 ---")
        self.add_result(await self.test_tasks_list())
        self.add_result(await self.test_reports_list())
        self.add_result(await self.test_vulnerability_kb())
        self.add_result(await self.test_ai_agents_tools())
        self.add_result(await self.test_ai_agents_config())
        self.add_result(await self.test_settings())
        self.add_result(await self.test_user_profile())
        self.add_result(await self.test_notifications())
        self.add_result(await self.test_awvs_health())

        self.test_summary["end_time"] = datetime.now().isoformat()

    def generate_report(self) -> Dict[str, Any]:
        return {
            "summary": self.test_summary,
            "results": [r.to_dict() for r in self.results]
        }

    def print_summary(self):
        print("\n" + "=" * 60)
        print("测试总结")
        print("=" * 60)
        print(f"总测试数: {self.test_summary['total']}")
        print(f"通过: {self.test_summary['passed']}")
        print(f"失败: {self.test_summary['failed']}")
        pass_rate = (self.test_summary['passed'] / self.test_summary['total'] * 100) if self.test_summary['total'] > 0 else 0
        print(f"通过率: {pass_rate:.1f}%")
        print("=" * 60)


async def main():
    tester = IntegrationTester()
    try:
        await tester.run_all_tests()
        tester.print_summary()
        report = tester.generate_report()
        report_path = "test_reports/integration_test_report.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(f"\n测试报告已保存到: {report_path}")
        return 0 if tester.test_summary["failed"] == 0 else 1
    except Exception as e:
        print(f"测试执行失败: {e}")
        return 1
    finally:
        await tester.close()


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
