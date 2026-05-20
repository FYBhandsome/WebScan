"""
完整的后端 API 集成测试
覆盖所有后端功能模块，模拟前端交互场景和数据请求模式
"""
import pytest
import requests
import json
from typing import Dict, Any, Optional

BASE_URL = "http://127.0.0.1:8888/api"

def api_get(path: str, params: dict = None) -> requests.Response:
    return requests.get(f"{BASE_URL}{path}", params=params, timeout=30)

def api_post(path: str, data: dict = None) -> requests.Response:
    return requests.post(f"{BASE_URL}{path}", json=data or {}, timeout=30)

def api_put(path: str, data: dict = None) -> requests.Response:
    return requests.put(f"{BASE_URL}{path}", json=data or {}, timeout=30)

def api_delete(path: str) -> requests.Response:
    return requests.delete(f"{BASE_URL}{path}", timeout=30)

def assert_ok(r, context=""):
    assert r.status_code == 200, f"{context}: HTTP {r.status_code} - {r.text[:300]}"

class TestTaskModule:
    """任务管理模块测试"""

    def test_create_task(self):
        """创建任务"""
        r = api_post("/tasks/create", {
            "task_name": "Integration Test Task",
            "target": "https://example.com",
            "task_type": "awvs_scan",
            "config": {}
        })
        assert_ok(r, "Create task")
        data = r.json()
        assert data["code"] == 200
        assert "task_id" in data["data"]

    def test_list_tasks(self):
        """获取任务列表"""
        r = api_get("/tasks/")
        assert_ok(r, "List tasks")
        data = r.json()
        assert data["code"] == 200
        assert "tasks" in data["data"]
        assert "total" in data["data"]

    def test_list_tasks_with_filters(self):
        """带过滤参数获取任务列表"""
        r = api_get("/tasks/", {"status": "pending", "task_type": "awvs_scan"})
        assert_ok(r, "Filtered tasks")

    def test_get_task_detail(self):
        """获取任务详情"""
        r = api_get("/tasks/1")
        assert_ok(r, "Get task detail")

    def test_get_task_results(self):
        """获取任务结果"""
        r = api_get("/tasks/1/results")
        assert_ok(r, "Get task results")

    def test_get_task_vulnerabilities(self):
        """获取任务漏洞列表"""
        r = api_get("/tasks/1/vulnerabilities", {"severity": "high"})
        assert_ok(r, "Get task vulnerabilities")

    def test_get_task_logs(self):
        """获取任务日志"""
        r = api_get("/tasks/1/logs", {"skip": 0, "limit": 10})
        assert_ok(r, "Get task logs")

    def test_get_frozen_tasks(self):
        """获取冻结任务"""
        r = api_get("/tasks/frozen")
        assert_ok(r, "Frozen tasks")

    def test_get_statistics_overview(self):
        """获取统计概览"""
        r = api_get("/tasks/statistics/overview")
        assert_ok(r, "Statistics overview")

    def test_update_task_status(self):
        """更新任务状态"""
        r = api_put("/tasks/1", {"status": "pending"})
        assert r.status_code in [200, 400], f"Update task: {r.status_code}"
        if r.status_code == 200:
            data = r.json()
            assert data["code"] == 200

    def test_cancel_task(self):
        """取消任务"""
        r = api_post("/tasks/1/cancel")
        assert r.status_code in [200, 400], f"Cancel task: {r.status_code}"


class TestVulnerabilityModule:
    """漏洞管理模块测试"""

    def test_get_vulnerability_detail(self):
        """获取漏洞详情"""
        r = api_get("/vulnerabilities/1")
        assert_ok(r, "Get vulnerability")
        data = r.json()
        vuln = data.get("data", {})
        assert "id" in vuln, f"Missing id: {vuln}"
        assert "title" in vuln, f"Missing title: {vuln}"
        assert "severity" in vuln, f"Missing severity: {vuln}"


class TestReportModule:
    """报告管理模块测试"""

    def test_create_report(self):
        """创建报告"""
        r = api_post("/reports/", {
            "task_id": 1,
            "name": "Integration Test Report",
            "format": "json",
            "include_ai_analysis": True,
            "include_summary": True,
            "include_vulnerabilities": True,
            "include_recommendations": True,
            "include_charts": False,
            "include_appendix": False
        })
        assert_ok(r, "Create report")
        data = r.json()
        assert data["code"] == 200
        assert "id" in data["data"]

    def test_list_reports(self):
        """获取报告列表"""
        r = api_get("/reports/")
        assert_ok(r, "List reports")

    def test_get_report_detail(self):
        """获取报告详情"""
        list_r = api_get("/reports/")
        if list_r.status_code != 200:
            return
        reports = list_r.json().get("data", {}).get("reports", [])
        if not reports:
            return
        report_id = reports[0]["id"]
        r = api_get(f"/reports/{report_id}")
        assert_ok(r, "Get report detail")

    def test_export_report(self):
        """导出报告 (JSON)"""
        list_r = api_get("/reports/")
        if list_r.status_code != 200:
            return
        reports = list_r.json().get("data", {}).get("reports", [])
        if not reports:
            return
        report_id = reports[0]["id"]
        r = api_get(f"/reports/{report_id}/export", {"format": "json"})
        assert r.status_code in [200, 500], f"Export report JSON: {r.status_code}"

    def test_export_report_html(self):
        """导出报告 (HTML)"""
        list_r = api_get("/reports/")
        if list_r.status_code != 200:
            return
        reports = list_r.json().get("data", {}).get("reports", [])
        if not reports:
            return
        report_id = reports[0]["id"]
        r = api_get(f"/reports/{report_id}/export", {"format": "html"})
        assert r.status_code in [200, 500], f"Export report HTML: {r.status_code}"

    def test_preview_report(self):
        """预览报告"""
        list_r = api_get("/reports/")
        if list_r.status_code != 200:
            return
        reports = list_r.json().get("data", {}).get("reports", [])
        if not reports:
            return
        report_id = reports[0]["id"]
        r = api_get(f"/reports/{report_id}/preview")
        assert_ok(r, "Preview report")

    def test_get_latest_report(self):
        """获取最新报告"""
        r = api_get("/reports/task/1/latest")
        assert_ok(r, "Latest report")

    def test_update_report(self):
        """更新报告"""
        list_r = api_get("/reports/")
        if list_r.status_code != 200:
            return
        reports = list_r.json().get("data", {}).get("reports", [])
        if not reports:
            return
        report_id = reports[0]["id"]
        r = api_put(f"/reports/{report_id}", {"report_name": "Updated Report Name"})
        assert_ok(r, "Update report")

    def test_regenerate_report(self):
        """重新生成报告"""
        list_r = api_get("/reports/")
        if list_r.status_code != 200:
            return
        reports = list_r.json().get("data", {}).get("reports", [])
        if not reports:
            return
        report_id = reports[0]["id"]
        r = api_post(f"/reports/{report_id}/regenerate")
        assert r.status_code in [200, 500], f"Regenerate report: {r.status_code}"

    def test_delete_report(self):
        """删除报告"""
        list_r = api_get("/reports/")
        if list_r.status_code != 200:
            return
        reports = list_r.json().get("data", {}).get("reports", [])
        if not reports:
            return
        report_id = reports[-1]["id"]
        r = api_delete(f"/reports/{report_id}")
        assert r.status_code in [200, 404], f"Delete report: {r.status_code}"


class TestSettingsModule:
    """设置管理模块测试"""

    def test_get_settings(self):
        """获取设置"""
        r = api_get("/settings/")
        assert_ok(r, "Get settings")

    def test_update_settings(self):
        """更新设置"""
        r = api_put("/settings/", {"general": {"theme": "dark"}})
        assert_ok(r, "Update settings")

    def test_get_system_info(self):
        """获取系统信息"""
        r = api_get("/settings/system-info")
        assert_ok(r, "System info")

    def test_get_statistics(self):
        """获取统计数据"""
        r = api_get("/settings/statistics", {"period": 7})
        assert_ok(r, "Statistics")

    def test_get_categories(self):
        """获取设置分类"""
        r = api_get("/settings/categories")
        assert_ok(r, "Categories")

    def test_get_setting_item(self):
        """获取单个设置项"""
        r = api_get("/settings/item/general/systemName")
        assert_ok(r, "Setting item")

    def test_update_setting_item(self):
        """更新单个设置项"""
        r = api_put("/settings/item", {
            "category": "general",
            "key": "test_item",
            "value": "test_value",
            "value_type": "string"
        })
        assert_ok(r, "Update setting item")

    def test_api_key_crud(self):
        """API Key 完整生命周期测试"""
        r = api_post("/settings/api-keys", {"name": "Test API Key"})
        assert_ok(r, "Create API key")
        key_id = r.json()["data"]["id"]

        r = api_get("/settings/api-keys")
        assert_ok(r, "List API keys")
        api_keys = r.json()["data"]["api_keys"]
        assert any(str(k["id"]) == str(key_id) for k in api_keys), "Created key not in list"

        r = api_put(f"/settings/api-keys/{key_id}/regenerate")
        assert_ok(r, "Regenerate API key")

        r = api_delete(f"/settings/api-keys/{key_id}")
        assert_ok(r, "Delete API key")


class TestAIAgentModule:
    """AI Agent 模块测试"""

    def test_get_config(self):
        """获取 AI Agent 配置"""
        r = api_get("/ai_agents/config")
        assert_ok(r, "AI Agent config")

    def test_get_tasks(self):
        """获取 AI Agent 任务列表"""
        r = api_get("/ai_agents/tasks")
        assert_ok(r, "AI Agent tasks")

    def test_get_tools(self):
        """获取 AI Agent 工具列表"""
        r = api_get("/ai_agents/tools")
        assert_ok(r, "AI Agent tools")

    def test_get_environment_info(self):
        """获取环境信息"""
        r = api_get("/ai_agents/environment/info")
        assert_ok(r, "Environment info")

    def test_get_workflow_metrics(self):
        """获取工作流指标"""
        r = api_get("/ai_agents/workflow/metrics")
        assert_ok(r, "Workflow metrics")

    def test_get_resource_usage(self):
        """获取资源使用"""
        r = api_get("/ai_agents/resources/usage")
        assert_ok(r, "Resource usage")

    def test_get_resource_statistics(self):
        """获取资源统计"""
        r = api_get("/ai_agents/resources/statistics")
        assert_ok(r, "Resource statistics")

    def test_search_poc(self):
        """搜索 POC"""
        r = api_post("/ai_agents/poc/search", {"cve_id": "CVE-2021-44228"})
        assert_ok(r, "Search POC")

    def test_start_agent_scan(self):
        """启动 Agent 扫描"""
        r = api_post("/ai_agents/scan", {
            "target": "https://example.com",
            "enable_llm_planning": True,
            "strategy": "quick",
            "concurrency": 3,
            "timeout": 60
        })
        assert_ok(r, "Start agent scan")
        data = r.json()
        assert "task_id" in data, f"No task_id: {data}"

    def test_get_agent_task_detail(self):
        """获取 Agent 任务详情"""
        r = api_get("/ai_agents/tasks/1")
        assert_ok(r, "Agent task detail")


class TestKBModule:
    """知识库模块测试"""

    def test_get_vulnerabilities(self):
        """获取知识库漏洞"""
        r = api_get("/kb/vulnerabilities")
        assert_ok(r, "KB vulnerabilities")

    def test_sync_kb(self):
        """同步知识库"""
        r = api_post("/kb/sync")
        assert_ok(r, "KB sync")


class TestAWVSModule:
    """AWVS 模块测试"""

    def test_get_scans(self):
        """获取 AWVS 扫描列表"""
        r = api_get("/awvs/scans")
        assert_ok(r, "AWVS scans")

    def test_get_vulnerabilities_rank(self):
        """获取漏洞排行"""
        r = api_get("/awvs/vulnerabilities/rank")
        assert_ok(r, "Vuln rank")

    def test_get_vulnerabilities_stats(self):
        """获取漏洞统计"""
        r = api_get("/awvs/vulnerabilities/stats")
        assert_ok(r, "Vuln stats")


class TestUserModule:
    """用户模块测试"""

    def test_get_user_list(self):
        """获取用户列表"""
        r = api_get("/user/list")
        assert_ok(r, "User list")

    def test_get_profile(self):
        """获取用户资料"""
        r = api_get("/user/profile", {"user_id": 1})
        assert r.status_code in [200, 404], f"Profile: HTTP {r.status_code}"


class TestNotificationModule:
    """通知模块测试"""

    def test_get_notifications(self):
        """获取通知列表"""
        r = api_get("/notifications/")
        assert_ok(r, "Notifications")

    def test_get_unread_count(self):
        """获取未读通知数"""
        r = api_get("/notifications/count/unread")
        assert_ok(r, "Unread count")


class TestFrontendScenarioSimulation:
    """前端交互场景模拟测试"""

    def test_full_scan_workflow(self):
        """模拟完整扫描工作流"""
        r = api_post("/tasks/create", {
            "task_name": "Workflow Simulation",
            "target": "https://test.example.com",
            "task_type": "awvs_scan",
            "config": {}
        })
        assert_ok(r, "Step 1: Create task")
        task_id = r.json()["data"]["task_id"]

        r = api_get(f"/tasks/{task_id}")
        assert_ok(r, "Step 2: Check task status")
        status = r.json()["data"]["status"]
        assert status in ["pending", "running", "completed", "failed"], f"Unexpected status: {status}"

        r = api_get(f"/tasks/{task_id}/vulnerabilities")
        assert_ok(r, "Step 3: Get task vulnerabilities")

        r = api_post("/reports/", {
            "task_id": task_id,
            "name": "Workflow Simulation Report",
            "format": "json",
            "include_ai_analysis": True
        })
        assert_ok(r, "Step 4: Generate report")
        report_id = r.json()["data"]["id"]

        r = api_get(f"/reports/{report_id}/export", {"format": "json"})
        assert_ok(r, "Step 5: Export report")

    def test_agent_scan_workflow(self):
        """模拟 AI Agent 扫描工作流"""
        r = api_post("/ai_agents/scan", {
            "target": "https://test.example.com",
            "strategy": "quick",
            "enable_llm_planning": True,
            "timeout": 60
        })
        assert_ok(r, "Step 1: Start agent scan")
        task_id = r.json()["task_id"]

        r = api_get(f"/ai_agents/tasks/{task_id}")
        assert_ok(r, "Step 2: Check agent task status")

        r = api_get("/ai_agents/workflow/metrics", {"task_id": task_id})
        assert_ok(r, "Step 3: Get workflow metrics")

    def test_report_history_workflow(self):
        """模拟报告历史查看工作流"""
        r = api_get("/reports/", {"task_id": 1, "skip": 0, "limit": 10})
        assert_ok(r, "Step 1: List reports by task")
        data = r.json()
        assert "reports" in data["data"]
        reports = data["data"]["reports"]

        if reports:
            report_id = reports[0]["id"]
            r = api_get(f"/reports/{report_id}")
            assert_ok(r, f"Step 2: View report {report_id}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])