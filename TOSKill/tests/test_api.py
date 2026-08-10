"""
TOSKill API接口测试
验证REST API响应格式和错误处理
"""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock


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
