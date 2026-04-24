"""
详细业务流程集成测试

测试完整的业务流程:
1. POC 验证流程: 创建任务 -> 执行验证 -> 获取结果 -> 生成报告
2. Seebug 数据同步: 搜索漏洞 -> 获取详情 -> 下载 POC
3. 错误处理测试
"""
import asyncio
import httpx
import json
import sys
from datetime import datetime
from typing import Dict, Any, List, Optional

BASE_URL = "http://127.0.0.1:8888/api"
TIMEOUT = 60.0

class TestResult:
    def __init__(self, name: str, category: str = ""):
        self.name = name
        self.category = category
        self.success = False
        self.message = ""
        self.data: Optional[Dict[str, Any]] = None
        self.error: Optional[str] = None
        self.duration_ms = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "success": self.success,
            "message": self.message,
            "data": self.data,
            "error": self.error,
            "duration_ms": self.duration_ms
        }


class DetailedIntegrationTester:
    def __init__(self):
        self.client = httpx.AsyncClient(base_url=BASE_URL, timeout=TIMEOUT)
        self.results: List[TestResult] = []
        self.test_summary = {
            "total": 0,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
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

    async def test_poc_scan_flow(self) -> List[TestResult]:
        results = []
        print("\n--- POC 扫描流程测试 ---")
        
        result1 = TestResult("创建 POC 扫描任务", "POC扫描流程")
        start = datetime.now()
        try:
            response = await self.client.post("/poc/scan", json={
                "target": "http://example.com",
                "poc_types": ["weblogic_cve_2020_2551"],
                "timeout": 5
            })
            result1.duration_ms = (datetime.now() - start).total_seconds() * 1000
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 200:
                    result1.success = True
                    result1.message = "POC 扫描任务创建成功"
                    result1.data = data.get("data")
                    task_id = data.get("data", {}).get("task_id")
                    
                    if task_id:
                        await asyncio.sleep(2)
                        
                        result2 = TestResult("查询 POC 扫描任务状态", "POC扫描流程")
                        start2 = datetime.now()
                        try:
                            response2 = await self.client.get(f"/tasks/{task_id}")
                            result2.duration_ms = (datetime.now() - start2).total_seconds() * 1000
                            if response2.status_code == 200:
                                data2 = response2.json()
                                if data2.get("code") == 200:
                                    result2.success = True
                                    task_data = data2.get("data", {})
                                    result2.message = f"任务状态: {task_data.get('status', 'unknown')}"
                                    result2.data = task_data
                                else:
                                    result2.error = data2.get("message", "未知错误")
                                    result2.message = "查询任务状态失败"
                            else:
                                result2.error = f"HTTP {response2.status_code}"
                                result2.message = "请求失败"
                        except Exception as e:
                            result2.duration_ms = (datetime.now() - start2).total_seconds() * 1000
                            result2.error = str(e)
                            result2.message = "请求异常"
                        results.append(result2)
                else:
                    result1.error = data.get("message", "未知错误")
                    result1.message = "创建任务失败"
            else:
                result1.error = f"HTTP {response.status_code}"
                result1.message = "请求失败"
        except Exception as e:
            result1.duration_ms = (datetime.now() - start).total_seconds() * 1000
            result1.error = str(e)
            result1.message = "请求异常"
        results.append(result1)
        
        return results

    async def test_seebug_flow(self) -> List[TestResult]:
        results = []
        print("\n--- Seebug 数据同步流程测试 ---")
        
        result1 = TestResult("搜索 Seebug 漏洞", "Seebug同步流程")
        start = datetime.now()
        ssvid = None
        try:
            response = await self.client.get("/seebug/poc/search", params={
                "keyword": "CVE-2024",
                "page": 1,
                "page_size": 5
            })
            result1.duration_ms = (datetime.now() - start).total_seconds() * 1000
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 200:
                    result1.success = True
                    poc_list = data.get("data", {}).get("list", [])
                    result1.message = f"搜索成功，找到 {len(poc_list)} 条记录"
                    result1.data = {"results_count": len(poc_list)}
                    if poc_list:
                        ssvid = poc_list[0].get("ssvid")
                else:
                    result1.error = data.get("message", "未知错误")
                    result1.message = "搜索失败"
            else:
                result1.error = f"HTTP {response.status_code}"
                result1.message = "请求失败"
        except Exception as e:
            result1.duration_ms = (datetime.now() - start).total_seconds() * 1000
            result1.error = str(e)
            result1.message = "请求异常"
        results.append(result1)
        
        if ssvid:
            result2 = TestResult("获取 POC 详情", "Seebug同步流程")
            start2 = datetime.now()
            try:
                response2 = await self.client.get(f"/seebug/poc/{ssvid}")
                result2.duration_ms = (datetime.now() - start2).total_seconds() * 1000
                if response2.status_code == 200:
                    data2 = response2.json()
                    if data2.get("code") == 200:
                        result2.success = True
                        result2.message = "获取 POC 详情成功"
                        result2.data = {"ssvid": ssvid}
                    else:
                        result2.error = data2.get("message", "未知错误")
                        result2.message = f"获取详情失败: {data2.get('message', '')}"
                else:
                    result2.error = f"HTTP {response2.status_code}"
                    result2.message = "请求失败"
            except Exception as e:
                result2.duration_ms = (datetime.now() - start2).total_seconds() * 1000
                result2.error = str(e)
                result2.message = "请求异常"
            results.append(result2)
            
            result3 = TestResult("下载 POC 代码", "Seebug同步流程")
            start3 = datetime.now()
            try:
                response3 = await self.client.get(f"/seebug/poc/{ssvid}/download")
                result3.duration_ms = (datetime.now() - start3).total_seconds() * 1000
                if response3.status_code == 200:
                    data3 = response3.json()
                    if data3.get("code") == 200:
                        result3.success = True
                        poc_code = data3.get("data", {}).get("code", "")
                        result3.message = f"下载 POC 成功，代码长度: {len(poc_code)}"
                        result3.data = {"code_length": len(poc_code)}
                    else:
                        result3.error = data3.get("message", "未知错误")
                        result3.message = f"下载失败: {data3.get('message', '')}"
                else:
                    result3.error = f"HTTP {response3.status_code}"
                    result3.message = "请求失败"
            except Exception as e:
                result3.duration_ms = (datetime.now() - start3).total_seconds() * 1000
                result3.error = str(e)
                result3.message = "请求异常"
            results.append(result3)
        
        return results

    async def test_error_handling(self) -> List[TestResult]:
        results = []
        print("\n--- 错误处理测试 ---")
        
        result1 = TestResult("无效目标 URL 测试", "错误处理")
        start = datetime.now()
        try:
            response = await self.client.post("/poc/scan", json={
                "target": "invalid-url",
                "poc_types": ["weblogic_cve_2020_2551"]
            })
            result1.duration_ms = (datetime.now() - start).total_seconds() * 1000
            if response.status_code in [400, 422]:
                result1.success = True
                result1.message = "正确返回错误响应"
            else:
                result1.error = f"期望 400/422，实际 {response.status_code}"
                result1.message = "错误处理不正确"
        except Exception as e:
            result1.duration_ms = (datetime.now() - start).total_seconds() * 1000
            result1.error = str(e)
            result1.message = "请求异常"
        results.append(result1)
        
        result2 = TestResult("不存在的任务 ID 测试", "错误处理")
        start2 = datetime.now()
        try:
            response2 = await self.client.get("/tasks/999999")
            result2.duration_ms = (datetime.now() - start2).total_seconds() * 1000
            if response2.status_code == 200:
                data2 = response2.json()
                if data2.get("code") == 404 or data2.get("data") is None:
                    result2.success = True
                    result2.message = "正确处理不存在的任务"
                else:
                    result2.error = "应该返回 404 或 null"
                    result2.message = "错误处理不正确"
            else:
                result2.success = True
                result2.message = "正确返回错误响应"
        except Exception as e:
            result2.duration_ms = (datetime.now() - start2).total_seconds() * 1000
            result2.error = str(e)
            result2.message = "请求异常"
        results.append(result2)
        
        result3 = TestResult("无效 POC 类型测试", "错误处理")
        start3 = datetime.now()
        try:
            response3 = await self.client.post("/poc/scan", json={
                "target": "http://example.com",
                "poc_types": ["invalid_poc_type"]
            })
            result3.duration_ms = (datetime.now() - start3).total_seconds() * 1000
            if response3.status_code in [400, 422]:
                result3.success = True
                result3.message = "正确返回错误响应"
            else:
                result3.error = f"期望 400/422，实际 {response3.status_code}"
                result3.message = "错误处理不正确"
        except Exception as e:
            result3.duration_ms = (datetime.now() - start3).total_seconds() * 1000
            result3.error = str(e)
            result3.message = "请求异常"
        results.append(result3)
        
        return results

    async def test_api_response_format(self) -> List[TestResult]:
        results = []
        print("\n--- API 响应格式测试 ---")
        
        endpoints = [
            ("/tasks/", "任务列表"),
            ("/reports/", "报告列表"),
            ("/settings/", "系统设置"),
            ("/poc/types", "POC 类型"),
            ("/ai_agents/tools", "AI Agents 工具"),
        ]
        
        for endpoint, name in endpoints:
            result = TestResult(f"响应格式 - {name}", "响应格式")
            start = datetime.now()
            try:
                response = await self.client.get(endpoint)
                result.duration_ms = (datetime.now() - start).total_seconds() * 1000
                if response.status_code == 200:
                    data = response.json()
                    if "code" in data and "message" in data:
                        result.success = True
                        result.message = f"响应格式正确 (code={data.get('code')})"
                        result.data = {
                            "has_code": "code" in data,
                            "has_message": "message" in data,
                            "has_data": "data" in data
                        }
                    else:
                        result.error = "缺少必要字段"
                        result.message = "响应格式不正确"
                else:
                    result.error = f"HTTP {response.status_code}"
                    result.message = "请求失败"
            except Exception as e:
                result.duration_ms = (datetime.now() - start).total_seconds() * 1000
                result.error = str(e)
                result.message = "请求异常"
            results.append(result)
        
        return results

    async def test_data_integrity(self) -> List[TestResult]:
        results = []
        print("\n--- 数据完整性测试 ---")
        
        result1 = TestResult("任务数据完整性", "数据完整性")
        start = datetime.now()
        try:
            response = await self.client.get("/tasks/", params={"page": 1, "page_size": 5})
            result1.duration_ms = (datetime.now() - start).total_seconds() * 1000
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 200:
                    items = data.get("data", {}).get("items", [])
                    if items:
                        first_item = items[0]
                        required_fields = ["id", "task_name", "task_type", "target", "status"]
                        missing_fields = [f for f in required_fields if f not in first_item]
                        if not missing_fields:
                            result1.success = True
                            result1.message = "任务数据字段完整"
                            result1.data = {"sample_fields": list(first_item.keys())}
                        else:
                            result1.error = f"缺少字段: {missing_fields}"
                            result1.message = "任务数据字段不完整"
                    else:
                        result1.success = True
                        result1.message = "无任务数据，跳过完整性检查"
                else:
                    result1.error = data.get("message", "未知错误")
                    result1.message = "获取任务失败"
            else:
                result1.error = f"HTTP {response.status_code}"
                result1.message = "请求失败"
        except Exception as e:
            result1.duration_ms = (datetime.now() - start).total_seconds() * 1000
            result1.error = str(e)
            result1.message = "请求异常"
        results.append(result1)
        
        result2 = TestResult("漏洞知识库数据完整性", "数据完整性")
        start2 = datetime.now()
        try:
            response2 = await self.client.get("/kb/vulnerabilities", params={"page": 1, "page_size": 5})
            result2.duration_ms = (datetime.now() - start2).total_seconds() * 1000
            if response2.status_code == 200:
                data2 = response2.json()
                if data2.get("code") == 200:
                    items = data2.get("data", {}).get("items", [])
                    if items:
                        first_item = items[0]
                        required_fields = ["id", "cve_id", "name", "severity"]
                        missing_fields = [f for f in required_fields if f not in first_item]
                        if not missing_fields:
                            result2.success = True
                            result2.message = "漏洞知识库数据字段完整"
                            result2.data = {"sample_fields": list(first_item.keys())}
                        else:
                            result2.error = f"缺少字段: {missing_fields}"
                            result2.message = "漏洞知识库数据字段不完整"
                    else:
                        result2.success = True
                        result2.message = "无漏洞数据，跳过完整性检查"
                else:
                    result2.error = data2.get("message", "未知错误")
                    result2.message = "获取漏洞知识库失败"
            else:
                result2.error = f"HTTP {response2.status_code}"
                result2.message = "请求失败"
        except Exception as e:
            result2.duration_ms = (datetime.now() - start2).total_seconds() * 1000
            result2.error = str(e)
            result2.message = "请求异常"
        results.append(result2)
        
        return results

    async def run_all_tests(self):
        self.test_summary["start_time"] = datetime.now().isoformat()
        print("\n" + "=" * 60)
        print("开始详细业务流程集成测试")
        print("=" * 60)
        
        for result in await self.test_poc_scan_flow():
            self.add_result(result)
        
        for result in await self.test_seebug_flow():
            self.add_result(result)
        
        for result in await self.test_error_handling():
            self.add_result(result)
        
        for result in await self.test_api_response_format():
            self.add_result(result)
        
        for result in await self.test_data_integrity():
            self.add_result(result)
        
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
        
        if self.test_summary['failed'] > 0:
            print("\n失败的测试:")
            for r in self.results:
                if not r.success:
                    print(f"  - {r.name}: {r.error or r.message}")
        
        print("=" * 60)


async def main():
    tester = DetailedIntegrationTester()
    try:
        await tester.run_all_tests()
        tester.print_summary()
        report = tester.generate_report()
        report_path = "test_reports/detailed_integration_test_report.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(f"\n详细测试报告已保存到: {report_path}")
        return 0 if tester.test_summary["failed"] == 0 else 1
    except Exception as e:
        print(f"测试执行失败: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        await tester.close()


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
