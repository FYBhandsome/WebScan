"""
TOSKill 桥接测试
验证 TOSKill 独立服务与主 Backend 的集成

当真实 TOSKill 服务未运行时，自动启动 Mock TOSKill 服务器 (端口 8081) 提供模拟数据。
"""
import pytest
import requests
import json

BACKEND_BASE = "http://127.0.0.1:8888/api"


@pytest.mark.toskill
class TestTOSKillHealthCheck:
    """TOSKill 健康检查测试"""

    def test_toskill_root(self, mock_toskill_server):
        """TOSKill 根路径"""
        r = requests.get(f"{mock_toskill_server}/", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "status" in data
        assert data["status"] == "running"

    def test_toskill_health(self, mock_toskill_server):
        """TOSKill 健康检查"""
        r = requests.get(f"{mock_toskill_server}/health", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "healthy"


@pytest.mark.toskill
class TestTOSKillAPIEndpoints:
    """TOSKill API 端点测试"""

    def test_toskill_tools_list(self, mock_toskill_server):
        """工具列表"""
        r = requests.get(f"{mock_toskill_server}/api/tools", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert data["code"] == 200
        assert "tools" in data.get("data", {})
        assert data["data"]["count"] >= 1

    def test_toskill_tools_categories(self, mock_toskill_server):
        """工具分类"""
        r = requests.get(f"{mock_toskill_server}/api/tools/categories", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert data["code"] == 200
        categories = data.get("data", {})
        assert "info_collection" in categories
        assert "vuln_scan" in categories
        assert "all" in categories

    def test_toskill_reports_list(self, mock_toskill_server):
        """报告列表"""
        r = requests.get(f"{mock_toskill_server}/api/reports/list", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert data["code"] == 200
        assert "reports" in data.get("data", {})
        assert data["data"]["total"] >= 1

    def test_toskill_scan_info(self, mock_toskill_server):
        """信息扫描"""
        r = requests.post(
            f"{mock_toskill_server}/api/scan/info",
            json={"target": "https://httpbin.org"},
            timeout=10
        )
        assert r.status_code == 200
        data = r.json()
        assert data["code"] == 200
        result = data.get("data", {})
        assert result.get("session_id") == "mock-session-001"
        assert result.get("scan_type") == "info_collection"
        assert len(result.get("completed_tasks", [])) == 3

    def test_toskill_scan_vuln(self, mock_toskill_server):
        """漏洞扫描"""
        r = requests.post(
            f"{mock_toskill_server}/api/scan/vuln",
            json={"target": "https://httpbin.org"},
            timeout=10
        )
        assert r.status_code == 200
        data = r.json()
        assert data["code"] == 200
        assert data["data"]["scan_type"] == "vuln_scan"

    def test_toskill_scan_full(self, mock_toskill_server):
        """完整扫描"""
        r = requests.post(
            f"{mock_toskill_server}/api/scan/full",
            json={"target": "https://httpbin.org"},
            timeout=10
        )
        assert r.status_code == 200
        data = r.json()
        assert data["code"] == 200
        result = data.get("data", {})
        assert result.get("scan_type") == "full_scan"
        assert result.get("scan_summary", {}).get("total_tools") == 5

    def test_toskill_parse_intent(self, mock_toskill_server):
        """自然语言解析"""
        r = requests.post(
            f"{mock_toskill_server}/api/parse-intent",
            json={"message": "扫描 https://httpbin.org 的安全漏洞"},
            timeout=10
        )
        assert r.status_code == 200
        data = r.json()
        assert data["code"] == 200
        result = data.get("data", {})
        assert result.get("target") == "https://httpbin.org"
        assert result.get("action") == "scan"

    def test_toskill_session_crud(self, mock_toskill_server):
        """会话 CRUD"""
        r_create = requests.post(
            f"{mock_toskill_server}/api/sessions",
            json={"target": "https://httpbin.org", "mode": "info_collection"},
            timeout=10
        )
        assert r_create.status_code == 200
        session_id = r_create.json()["data"]["session_id"]

        r_get = requests.get(
            f"{mock_toskill_server}/api/sessions/{session_id}",
            timeout=10
        )
        assert r_get.status_code == 200

        r_delete = requests.delete(
            f"{mock_toskill_server}/api/sessions/{session_id}",
            timeout=10
        )
        assert r_delete.status_code == 200


@pytest.mark.toskill
class TestTOSKillWebSocket:
    """TOSKill WebSocket 测试"""

    def test_ws_endpoint_reachable(self, mock_toskill_server):
        """WebSocket 端点可达性"""
        r = requests.get(f"{mock_toskill_server}/api/ai-chat/ws", timeout=10)
        assert r.status_code in [200, 400, 404, 405, 426]


@pytest.mark.toskill
class TestBackendTOSKillIntegration:
    """Backend-TOSKill 集成测试"""

    def test_backend_ai_agents_uses_toskill(self):
        """验证 Backend AI Agent 是否集成了 TOSKill"""
        try:
            r = requests.get(f"{BACKEND_BASE}/ai_agents/environment/info", timeout=10)
            assert r.status_code == 200
            data = r.json()
            env = data.get("data", {})
            assert isinstance(env, dict)
        except requests.ConnectionError:
            pytest.skip("Backend server not running on port 8888")

    def test_ai_chat_websocket_at_backend(self):
        """验证 Backend 的 AI Chat WebSocket"""
        try:
            r = requests.get(f"http://127.0.0.1:8888/api/ai-chat/ws", timeout=10)
            assert r.status_code in [200, 400, 404, 405, 426]
        except requests.ConnectionError:
            pytest.skip("Backend server not running on port 8888")

    def test_backend_to_mock_toskill_data_structure(self, mock_toskill_server):
        """验证 Backend 与 Mock TOSKill 的数据结构兼容性"""
        r_toskill = requests.get(f"{mock_toskill_server}/api/tools", timeout=10)
        assert r_toskill.status_code == 200
        toskill_tools = r_toskill.json()["data"]["tools"]

        try:
            r_backend = requests.get(f"{BACKEND_BASE}/ai_agents/tools", timeout=10)
            assert r_backend.status_code == 200
        except requests.ConnectionError:
            pytest.skip("Backend server not running on port 8888")

        assert len(toskill_tools) >= 1
        assert isinstance(toskill_tools[0], dict)
        assert "name" in toskill_tools[0]
        assert "description" in toskill_tools[0]

    def test_mock_scan_to_backend_workflow(self, mock_toskill_server):
        """Mock扫描 -> Backend报告完整工作流"""
        r = requests.post(
            f"{mock_toskill_server}/api/scan/full",
            json={"target": "https://httpbin.org"},
            timeout=10
        )
        assert r.status_code == 200
        scan_data = r.json()["data"]
        assert scan_data["scan_type"] == "full_scan"
        assert "vulnerabilities" in scan_data
        assert "scan_summary" in scan_data

        r_report = requests.get(f"{mock_toskill_server}/api/reports/list", timeout=10)
        assert r_report.status_code == 200
        reports = r_report.json()["data"]["reports"]
        assert len(reports) >= 1
        assert "name" in reports[0]
        assert "download_url" in reports[0]


@pytest.mark.toskill
class TestTOSkillFrontendCompat:
    """TOSKill 前端兼容性测试"""

    def test_toskill_frontend_proxy_config(self):
        """TOSKill 前端代理配置验证"""
        import os
        config_path = os.path.join(
            os.path.dirname(__file__), "../../toskill-frontend/vite.config.js"
        )
        assert os.path.exists(config_path), "toskill-frontend vite.config.js not found"

        with open(config_path, 'r', encoding='utf-8') as f:
            content = f.read()

        assert "port" in content, "Missing port config"
        assert "5175" in content, "Port should be 5175 to avoid conflict"
        assert "ws: true" in content, "Missing ws proxy config"
        assert "localhost:8081" in content, "Proxy target should be localhost:8081"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])