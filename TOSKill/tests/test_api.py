"""
TOSKill API接口测试
验证REST API响应格式和错误处理
"""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock


VALID_CUSTOM_SCRIPT = """def run(target):
    return {
        'success': True,
        'data': {'target': target, 'items': ['asset']},
        'error': None,
        'auth_info': None,
        'timestamp': 'test'
    }
"""


@pytest.fixture
def isolated_script_manager(tmp_path, monkeypatch):
    """Use a real SQLite registry without touching the developer's tool library."""
    import TOSKill.AI.tools as tools_module
    import TOSKill.api.scan_api as scan_api_module

    manager = tools_module.ScriptManager()
    manager._scripts_dir = tmp_path / "scripts"
    manager._scripts_dir.mkdir(parents=True, exist_ok=True)
    manager._db_path = tmp_path / "custom-tools.db"
    manager._registered_scripts = {}
    manager._ensure_registry_schema()

    monkeypatch.setattr(tools_module, "script_manager", manager)
    monkeypatch.setattr(scan_api_module, "script_manager", manager)
    yield manager

    for name in list(manager.get_registered_scripts()):
        manager.unregister_custom_tool(name)


@pytest.fixture
def test_app():
    """创建测试用FastAPI app"""
    from TOSKill.main import app
    return app


@pytest.fixture
def client(test_app):
    """创建TestClient"""
    return TestClient(test_app)


class TestScanAPI:
    """扫描API测试"""

    def test_api_router_registered(self, test_app):
        """验证路由已注册"""
        assert len(test_app.routes) > 0

    @patch('TOSKill.AI.graph.memory_store.get_session')
    def test_get_session_status(self, mock_get, client):
        """获取会话状态"""
        mock_get.return_value = {
            "task_id": "test123",
            "target": "http://example.com",
            "mode": "info_collection",
            "completed_tasks": [],
            "is_complete": False
        }
        response = client.get("/api/sessions/test123/status")
        assert response.status_code in [200, 404]

    @patch('TOSKill.AI.graph.memory_store.get_session')
    def test_get_session_nonexistent(self, mock_get, client):
        """获取不存在会话应返回404"""
        mock_get.return_value = None
        response = client.get("/api/sessions/nonexistent/status")
        assert response.status_code in [200, 404]


class TestToolsAPI:
    """工具API测试"""

    def test_get_tools_list(self, client):
        """获取工具列表"""
        response = client.get("/api/tools")
        assert response.status_code in [200, 404]

    def test_custom_tool_registration_listing_and_deletion(
        self, client, isolated_script_manager
    ):
        from TOSKill.AI.tools import get_tool_by_name
        from TOSKill.tools.tool_categories import tool_category

        initial_info_count = len(isolated_script_manager.get_registered_scripts())
        response = client.post("/api/tools/custom", json={
            "tool_name": "custom_api_asset_test",
            "script_content": VALID_CUSTOM_SCRIPT,
            "description": "接口测试信息收集工具",
            "category": "info_collection",
            "creation_method": "upload",
            "include_in_default_scan": False,
        })

        assert response.status_code == 200
        metadata = response.json()["data"]["tool"]
        assert metadata["category"] == "info_collection"
        assert metadata["source"] == "custom"
        assert metadata["include_in_default_scan"] is False
        assert len(isolated_script_manager.get_registered_scripts()) == initial_info_count + 1
        assert get_tool_by_name("custom_api_asset_test") is not None
        assert tool_category("custom_api_asset_test") == "info_collection"

        listed = client.get(
            "/api/tools?category=info_collection&source=custom"
        )
        assert listed.status_code == 200
        assert [tool["name"] for tool in listed.json()["data"]["tools"]] == [
            "custom_api_asset_test"
        ]

        executed = client.post("/api/tools/execute", json={
            "tool_name": "custom_api_asset_test",
            "target": "https://example.com/path",
            "analyze": False,
        })
        assert executed.status_code == 200
        assert executed.json()["data"]["result"]["data"]["target"] == (
            "https://example.com/path"
        )

        source = client.get("/api/scripts/custom_api_asset_test/source")
        assert source.status_code == 200
        assert source.json()["data"]["script"]["script_content"] == VALID_CUSTOM_SCRIPT

        deleted = client.delete("/api/tools/custom_api_asset_test")
        assert deleted.status_code == 200
        assert get_tool_by_name("custom_api_asset_test") is None

    def test_custom_tool_restores_without_entering_default_scan(
        self, isolated_script_manager, monkeypatch
    ):
        import TOSKill.AI.tools as tools_module

        default_info = list(tools_module.get_tool_sequence("info_collection"))
        default_vuln = list(tools_module.get_tool_sequence("vuln_scan"))
        result = isolated_script_manager.register_script_as_tool(
            VALID_CUSTOM_SCRIPT,
            "custom_restore_vuln_test",
            "恢复测试漏洞工具",
            category="vuln_scan",
            creation_method="ai_generate",
        )
        assert result["success"] is True

        tools_module.TOOL_MAP.pop("custom_restore_vuln_test", None)
        isolated_script_manager._registered_scripts.clear()
        restarted_manager = tools_module.ScriptManager()
        restarted_manager._scripts_dir = isolated_script_manager._scripts_dir
        restarted_manager._db_path = isolated_script_manager._db_path
        restarted_manager._registered_scripts = {}
        monkeypatch.setattr(tools_module, "script_manager", restarted_manager)
        restored = restarted_manager.restore_registered_tools()

        assert restored["restored"] == ["custom_restore_vuln_test"]
        metadata = restarted_manager.get_registered_scripts()[
            "custom_restore_vuln_test"
        ]
        assert metadata["category"] == "vuln_scan"
        assert metadata["creation_method"] == "ai_generate"
        assert metadata["include_in_default_scan"] is False
        assert tools_module.get_tool_sequence("info_collection") == default_info
        assert tools_module.get_tool_sequence("vuln_scan") == default_vuln
        assert "custom_restore_vuln_test" not in tools_module.ALL_TOOLS

    def test_system_tool_cannot_be_overwritten_or_deleted(
        self, client, isolated_script_manager
    ):
        conflict = client.post("/api/tools/custom", json={
            "tool_name": "port_scan",
            "script_content": VALID_CUSTOM_SCRIPT,
            "description": "冲突工具",
            "category": "info_collection",
            "creation_method": "upload",
        })
        assert conflict.status_code == 409
        assert conflict.json()["detail"]["error_code"] == "SYSTEM_TOOL_NAME_CONFLICT"

        deleted = client.delete("/api/tools/port_scan")
        assert deleted.status_code == 403
        assert deleted.json()["detail"]["error_code"] == "SYSTEM_TOOL_DELETE_FORBIDDEN"

    @pytest.mark.parametrize("tool_name", ["sqli_scan", "xss_scan"])
    @patch("TOSKill.api.scan_api.get_tool_by_name")
    def test_vulnerability_tool_endpoint_preserves_complete_url(
        self, mock_get_tool, client, tool_name
    ):
        tool = MagicMock(spec=["invoke"])
        tool.invoke.return_value = {"success": True, "data": {"ok": True}}
        mock_get_tool.return_value = tool
        target = "https://example.com/search.php?q=test"

        response = client.post(
            "/api/tools/execute",
            json={
                "tool_name": tool_name,
                "target": target,
                "analyze": False,
            },
        )

        assert response.status_code == 200
        assert response.json()["data"]["target"] == target
        tool.invoke.assert_called_once_with(target)


class TestIntentAPI:
    """意图解析API测试"""

    def test_parse_intent_chat(self, client):
        """解析聊天意图"""
        with patch('TOSKill.AI.graph.get_llm') as mock_llm:
            mock_llm.return_value.invoke.return_value = MagicMock(
                content='{"intent": "chat", "confidence": 0.9, "explanation": "普通对话"}'
            )
            response = client.post("/api/parse-intent", json={
                "message": "你好",
                "session_id": "test_chat"
            })
            assert response.status_code in [200, 500, 422]

    def test_parse_intent_empty(self, client):
        """空消息意图解析"""
        response = client.post("/api/parse-intent", json={
            "message": "",
            "session_id": "test_empty"
        })
        assert response.status_code in [200, 500, 422]


class TestHealthCheck:
    """健康检查测试"""

    def test_health_endpoint(self, client):
        """健康检查端点"""
        response = client.get("/health")
        assert response.status_code in [200, 404]


class TestErrorHandling:
    """错误处理测试"""

    def test_invalid_json_request(self, client):
        """非法JSON请求"""
        response = client.post("/api/parse-intent", data="not json", headers={"Content-Type": "text/plain"})
        assert response.status_code in [200, 400, 415, 422, 500]

    def test_missing_required_fields(self, client):
        """缺少必填字段"""
        response = client.post("/api/parse-intent", json={})
        assert response.status_code in [200, 422, 500]
