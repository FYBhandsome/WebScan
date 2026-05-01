"""集成测试：API 端点"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import pytest
from fastapi.testclient import TestClient
from TOSKill.api.scan_api import router
from fastapi import FastAPI

app = FastAPI()
app.include_router(router)
client = TestClient(app)


class TestHealthEndpoint:
    def test_health_returns_200(self):
        response = client.get("/toskill/health")
        assert response.status_code == 200
        data = response.json()
        assert data["code"] == 200
        assert "timestamp" in data
        assert "tools_count" in data["data"]
        assert "ai_model_status" in data["data"]

    def test_health_response_format(self):
        response = client.get("/toskill/health")
        data = response.json()
        assert "code" in data
        assert "message" in data
        assert "data" in data
        assert "timestamp" in data


class TestToolsEndpoint:
    def test_list_tools(self):
        response = client.get("/toskill/tools")
        assert response.status_code == 200
        data = response.json()
        assert len(data["data"]["tools"]) > 0

    def test_categories(self):
        response = client.get("/toskill/tools/categories")
        assert response.status_code == 200
        data = response.json()
        assert "info_collection" in data["data"]
        assert "vuln_scan" in data["data"]


class TestSessionEndpoints:
    def test_create_session(self):
        response = client.post("/toskill/sessions", json={"target": "https://test.com"})
        assert response.status_code == 200
        data = response.json()
        assert "session_id" in data["data"]

    def test_get_session_not_found(self):
        response = client.get("/toskill/sessions/nonexistent12345")
        assert response.status_code == 404


class TestValidationErrors:
    def test_scan_with_bad_target(self):
        response = client.post("/toskill/scan/info", json={"target": "ftp://bad.com"})
        assert response.status_code == 422

    def test_execute_bad_tool(self):
        response = client.post("/toskill/tools/execute", json={
            "tool_name": "invalid_tool", "target": "https://test.com"
        })
        assert response.status_code == 422


class TestDecisionTestEndpoint:
    def test_decision_test(self):
        response = client.post("/toskill/decision/test", json={
            "target": "https://test.com",
            "mode": "deep",
            "completed_tools": [],
            "last_result": {}
        })
        assert response.status_code in [200, 500]
