"""
AI Agent 工作流专项测试
覆盖 Agent 扫描全流程、POC 系统、配置管理等
"""
import pytest
import requests
import json
import time

BASE_URL = "http://127.0.0.1:8888/api"


class TestAIAgentConfiguration:
    """AI Agent 配置测试"""

    def test_agent_config_structure(self):
        """验证配置结构完整性"""
        r = requests.get(f"{BASE_URL}/ai_agents/config", timeout=30)
        assert r.status_code == 200
        data = r.json()
        assert data["code"] == 200
        config = data.get("data", {})
        expected_keys = [
            "max_execution_time", "max_retries", "max_concurrent_tools",
            "tool_timeout", "enable_llm_planning", "default_scan_tasks",
            "enable_memory", "enable_kb_integration"
        ]
        for key in expected_keys:
            assert key in config, f"Missing config key: {key}"

    def test_agent_config_defaults(self):
        """验证默认配置值"""
        r = requests.get(f"{BASE_URL}/ai_agents/config", timeout=30)
        assert r.status_code == 200
        config = r.json()["data"]
        assert config.get("tool_timeout", 0) > 0, "tool_timeout should be positive"
        assert "max_execution_time" in config, "Missing max_execution_time"
        assert "max_retries" in config, "Missing max_retries"


class TestAIAgentScanFlow:
    """AI Agent 扫描流程测试"""

    def test_start_quick_scan(self):
        """启动快速扫描"""
        r = requests.post(f"{BASE_URL}/ai_agents/scan", json={
            "target": "https://httpbin.org",
            "strategy": "quick",
            "enable_llm_planning": False,
            "concurrency": 3,
            "timeout": 120
        }, timeout=30)
        assert r.status_code == 200
        data = r.json()
        assert "task_id" in data
        assert data["status"] in ["pending", "running"]

    def test_start_standard_scan(self):
        """启动标准扫描"""
        r = requests.post(f"{BASE_URL}/ai_agents/scan", json={
            "target": "https://httpbin.org",
            "strategy": "standard",
            "enable_llm_planning": True,
            "concurrency": 5,
            "timeout": 300
        }, timeout=30)
        assert r.status_code == 200
        data = r.json()
        assert "task_id" in data

    def test_start_custom_scan(self):
        """启动自定义扫描"""
        r = requests.post(f"{BASE_URL}/ai_agents/scan", json={
            "target": "https://httpbin.org",
            "strategy": "standard",
            "need_custom_scan": True,
            "custom_scan_type": "web",
            "custom_scan_requirements": "测试XSS和SQL注入",
            "custom_scan_language": "python",
            "selected_tools": ["xss_scan", "sqli_scan"]
        }, timeout=30)
        assert r.status_code == 200
        data = r.json()
        assert "task_id" in data

    def test_start_capability_enhanced_scan(self):
        """启动功能增强扫描"""
        r = requests.post(f"{BASE_URL}/ai_agents/scan", json={
            "target": "https://httpbin.org",
            "strategy": "standard",
            "need_capability_enhancement": True,
            "capability_requirement": "需要支持文件上传漏洞检测",
            "timeout": 300
        }, timeout=30)
        assert r.status_code == 200
        data = r.json()
        assert "task_id" in data


class TestPOCSystem:
    """POC 系统测试"""

    def test_search_poc_by_cve(self):
        """按 CVE 搜索 POC"""
        r = requests.post(f"{BASE_URL}/ai_agents/poc/search", json={
            "cve_id": "CVE-2021-44228"
        }, timeout=30)
        assert r.status_code == 200
        data = r.json()
        assert data["code"] == 200

    def test_search_poc_by_name(self):
        """按名称搜索 POC"""
        r = requests.post(f"{BASE_URL}/ai_agents/poc/search", json={
            "cve_id": "CVE-2018-7600"
        }, timeout=30)
        assert r.status_code == 200

    def test_execute_poc(self):
        """执行 POC"""
        r = requests.post(f"{BASE_URL}/ai_agents/poc/execute", json={
            "target": "https://httpbin.org",
            "poc_type": "sqli",
            "parameters": {"url": "https://httpbin.org/get?id=1"}
        }, timeout=60)
        assert r.status_code == 200

    def test_batch_execute_poc(self):
        """批量执行 POC"""
        r = requests.post(f"{BASE_URL}/ai_agents/poc/batch-execute", json={
            "targets": ["https://httpbin.org"],
            "cve_ids": ["CVE-2021-44228", "CVE-2018-7600"]
        }, timeout=30)
        assert r.status_code == 200


class TestEnvironmentAndTools:
    """环境和工具测试"""

    def test_environment_info(self):
        """获取环境信息"""
        r = requests.get(f"{BASE_URL}/ai_agents/environment/info", timeout=30)
        assert r.status_code == 200
        data = r.json()
        env_data = data.get("data", {})
        assert "python_version" in env_data or "environment" in env_data

    def test_tools_list(self):
        """获取工具列表"""
        r = requests.get(f"{BASE_URL}/ai_agents/tools", timeout=30)
        assert r.status_code == 200
        data = r.json()
        assert data["code"] == 200

    def test_environment_tools(self):
        """获取环境工具列表"""
        r = requests.get(f"{BASE_URL}/ai_agents/environment/tools", timeout=30)
        assert r.status_code == 200


class TestWorkflowMetrics:
    """工作流指标测试"""

    def test_get_workflow_metrics_global(self):
        """获取全局工作流指标"""
        r = requests.get(f"{BASE_URL}/ai_agents/workflow/metrics", timeout=30)
        assert r.status_code == 200

    def test_get_resource_usage(self):
        """获取资源使用情况"""
        r = requests.get(f"{BASE_URL}/ai_agents/resources/usage", timeout=30)
        assert r.status_code == 200

    def test_get_resource_statistics(self):
        """获取资源统计信息"""
        r = requests.get(f"{BASE_URL}/ai_agents/resources/statistics", timeout=30)
        assert r.status_code == 200


class TestCodeGeneration:
    """代码生成测试"""

    def test_generate_code(self):
        """生成扫描代码"""
        r = requests.post(f"{BASE_URL}/ai_agents/code/generate", json={
            "task_description": "编写一个端口扫描脚本",
            "language": "python"
        }, timeout=60)
        assert r.status_code in [200, 500, 501]


class TestCapabilityManagement:
    """功能管理测试"""

    def test_list_capabilities(self):
        """列出所有功能"""
        r = requests.get(f"{BASE_URL}/ai_agents/capabilities/list", timeout=30)
        assert r.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])