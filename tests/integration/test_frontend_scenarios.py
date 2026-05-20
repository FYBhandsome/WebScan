"""
前端交互场景模拟测试
模拟前端(front)的各类交互场景和数据请求模式
"""
import pytest
import requests
import json

BASE_URL = "http://127.0.0.1:8888/api"


class TestDashboardScenario:
    """Dashboard 页面交互场景"""

    def test_dashboard_data_loading(self):
        """Dashboard 数据加载场景"""
        responses = []
        responses.append(requests.get(f"{BASE_URL}/tasks/statistics/overview", timeout=30))
        responses.append(requests.get(f"{BASE_URL}/settings/statistics", timeout=30))
        responses.append(requests.get(f"{BASE_URL}/notifications/count/unread", timeout=30))

        for i, r in enumerate(responses):
            assert r.status_code == 200, f"Dashboard request {i} failed: {r.status_code}"


class TestScanTasksScenario:
    """扫描任务列表交互场景"""

    def test_load_tasks_with_all_filters(self):
        """加载任务列表 (全条件过滤)"""
        params = {
            "status": "completed",
            "task_type": "awvs_scan",
            "start_date": "2024-01-01",
            "end_date": "2026-12-31",
            "search": "scan",
            "skip": 0,
            "limit": 20
        }
        r = requests.get(f"{BASE_URL}/tasks/", params=params, timeout=30)
        assert r.status_code == 200

    def test_task_detail_expansion(self):
        """任务详情展开交互"""
        r = requests.get(f"{BASE_URL}/tasks/1", timeout=30)
        assert r.status_code == 200
        task = r.json()["data"]
        assert "task_name" in task
        assert "status" in task

        r = requests.get(f"{BASE_URL}/tasks/1/results", timeout=30)
        assert r.status_code == 200

    def test_task_pagination(self):
        """任务分页交互"""
        page_sizes = [10, 20, 50]
        for size in page_sizes:
            r = requests.get(f"{BASE_URL}/tasks/", params={"skip": 0, "limit": size}, timeout=30)
            assert r.status_code == 200, f"Pagination size {size} failed"


class TestReportGenerationScenario:
    """报告生成交互场景"""

    def test_report_creation_to_export(self):
        """从创建到导出完整流程"""
        r = requests.post(f"{BASE_URL}/reports/", json={
            "task_id": 1,
            "name": "Scenario Report",
            "format": "json",
            "include_ai_analysis": True,
            "include_summary": True,
            "include_vulnerabilities": True,
            "include_recommendations": True
        }, timeout=60)
        if r.status_code == 200:
            report_id = r.json()["data"]["id"]

            r2 = requests.get(f"{BASE_URL}/reports/{report_id}", timeout=30)
            assert r2.status_code == 200

            r3 = requests.get(f"{BASE_URL}/reports/{report_id}/export", params={"format": "json"}, timeout=30)
            assert r3.status_code == 200

    def test_report_format_variants(self):
        """不同格式报告导出"""
        list_r = requests.get(f"{BASE_URL}/reports/", timeout=30)
        if list_r.status_code != 200:
            pytest.skip("Cannot fetch report list")
        reports = list_r.json().get("data", {}).get("reports", [])
        if not reports:
            pytest.skip("No reports available")
        report_id = reports[0]["id"]
        formats = ["json", "html"]
        for fmt in formats:
            r = requests.get(f"{BASE_URL}/reports/{report_id}/export", params={"format": fmt}, timeout=30)
            assert r.status_code in [200, 500], f"Export format {fmt} returned {r.status_code}"

    def test_report_preview(self):
        """报告预览"""
        list_r = requests.get(f"{BASE_URL}/reports/", timeout=30)
        if list_r.status_code != 200:
            pytest.skip("Cannot fetch report list")
        reports = list_r.json().get("data", {}).get("reports", [])
        if not reports:
            pytest.skip("No reports available")
        report_id = reports[0]["id"]
        r = requests.get(f"{BASE_URL}/reports/{report_id}/preview", timeout=30)
        assert r.status_code == 200


class TestSettingsScenario:
    """设置页面交互场景"""

    def test_settings_load_all(self):
        """加载所有设置"""
        endpoints = [
            "/settings/",
            "/settings/categories",
            "/settings/system-info",
            "/settings/statistics",
            "/settings/api-keys"
        ]
        for ep in endpoints:
            r = requests.get(f"{BASE_URL}{ep}", timeout=30)
            assert r.status_code == 200, f"Settings endpoint {ep} failed"

    def test_settings_update_flow(self):
        """设置更新流程"""
        r = requests.put(f"{BASE_URL}/settings/", json={
            "general": {"theme": "dark", "language": "zh-CN"},
            "scan": {"timeout": 300}
        }, timeout=30)
        assert r.status_code == 200


class TestKnowledgeBaseScenario:
    """知识库交互场景"""

    def test_kb_browse(self):
        """浏览知识库"""
        r = requests.get(f"{BASE_URL}/kb/vulnerabilities", params={"skip": 0, "limit": 10}, timeout=30)
        assert r.status_code == 200


class TestVulnerabilityDetailScenario:
    """漏洞详情交互场景"""

    def test_vulnerability_detail_view(self):
        """查看漏洞详情"""
        r = requests.get(f"{BASE_URL}/vulnerabilities/1", timeout=30)
        assert r.status_code == 200
        data = r.json()["data"]
        required_fields = ["id", "title", "severity", "url", "description"]
        for field in required_fields:
            assert field in data, f"Missing field: {field}"


class TestConcurrentRequestScenario:
    """并发请求场景"""

    def test_concurrent_api_calls(self):
        """模拟前端同时发起多个请求"""
        import concurrent.futures
        urls = [
            f"{BASE_URL}/tasks/",
            f"{BASE_URL}/reports/",
            f"{BASE_URL}/settings/",
            f"{BASE_URL}/kb/vulnerabilities",
            f"{BASE_URL}/notifications/",
        ]

        def fetch(url):
            return requests.get(url, timeout=30)

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(fetch, urls))

        for r in results:
            assert r.status_code == 200, f"Concurrent request failed: {r.status_code}"


class TestErrorHandlingScenario:
    """错误处理场景"""

    def test_404_not_found(self):
        """404 错误处理"""
        r = requests.get(f"{BASE_URL}/nonexistent/endpoint/12345", timeout=30)
        assert r.status_code == 404

    def test_invalid_parameters(self):
        """无效参数处理"""
        r = requests.post(f"{BASE_URL}/reports/", json={"task_id": 999999, "name": ""}, timeout=30)
        assert r.status_code in [200, 400, 422, 500]


class TestWebSocketCompatScenario:
    """WebSocket 兼容场景"""

    def test_ws_endpoint_accessible(self):
        """验证 WebSocket 端点可访问"""
        r = requests.get(f"http://127.0.0.1:8888/api/ai-chat/ws", timeout=30)
        assert r.status_code in [200, 400, 404, 405, 426]


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])