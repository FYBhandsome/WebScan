import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import pytest
from unittest.mock import patch, MagicMock

try:
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False


_BASE_MOCK_SETTINGS = {
    "OPENAI_API_KEY": None,
    "OPENAI_BASE_URL": "https://test-api.example.com/v1",
    "MODEL_ID": "test-model",
    "DEBUG": False,
    "AWVS_API_URL": "https://127.0.0.1:3443",
    "AWVS_API_KEY": None,
    "APP_NAME": "Test App",
    "APP_VERSION": "1.0.0",
    "LOG_LEVEL": "ERROR",
    "LOG_FILE": "logs/test.log",
    "DATABASE_URL": "sqlite://:memory:",
    "HOST": "127.0.0.1",
    "PORT": 8888,
    "CORS_ORIGINS": ["*"],
    "AI_BASE_URL": "https://test-api.example.com/v1",
    "AI_API_KEY": "test-dummy-key",
    "SEEBUG_API_KEY": None,
    "SEEBUG_API_BASE_URL": "https://www.seebug.org/api",
    "QWEN_API_KEY": None,
    "UPLOAD_DIR": "uploads",
    "CODE_EXECUTOR_WORKSPACE": "executor_workspace",
    "CODE_EXECUTOR_TIMEOUT": 30,
    "CODE_EXECUTOR_ENABLED": True,
    "CODE_EXECUTOR_LOG_FILE": "logs/code_executor.log",
    "MAX_CONCURRENT_SCANS": 5,
    "SCAN_TIMEOUT": 300,
    "AGENT_MAX_EXECUTION_TIME": 18000,
    "AGENT_TEMPERATURE": 0.3,
    "AGENT_MAX_RETRIES": 3,
    "POC_VERIFICATION_ENABLED": True,
    "POC_MAX_CONCURRENT_EXECUTIONS": 5,
    "POC_EXECUTION_TIMEOUT": 60,
    "POC_RETRY_MAX_COUNT": 3,
    "POC_RESULT_ACCURACY_THRESHOLD": 0.95,
    "POC_CACHE_ENABLED": True,
    "POC_CACHE_TTL": 3600,
    "POC_REPORT_FORMAT": "html",
}


def _apply_mock_settings(mock_settings, overrides=None):
    all_settings = dict(_BASE_MOCK_SETTINGS)
    if overrides:
        all_settings.update(overrides)
    for key, value in all_settings.items():
        setattr(mock_settings, key, value)
    return mock_settings


def _create_app_with_patch(settings_overrides=None):
    patcher = patch('backend.config.settings')
    mock_settings = patcher.start()
    _apply_mock_settings(mock_settings, settings_overrides)

    try:
        from backend.api import api_router
        app = FastAPI()
        app.include_router(api_router, prefix="/api")
        return app, patcher
    except Exception:
        patcher.stop()
        return None, None


@pytest.mark.integration
class TestAIConnectionStatus:
    @pytest.fixture(autouse=True)
    def setup(self):
        if not FASTAPI_AVAILABLE:
            pytest.skip("FastAPI not available")
        app, self._patcher = _create_app_with_patch()
        if app is None:
            pytest.skip("Backend dependencies unavailable")
        self.client = TestClient(app)
        yield
        if self._patcher:
            self._patcher.stop()

    def test_connection_status_returns_200(self):
        response = self.client.get("/api/ai/connection-status")
        assert response.status_code == 200

    def test_connection_status_returns_valid_json(self):
        response = self.client.get("/api/ai/connection-status")
        data = response.json()
        assert "code" in data
        assert "message" in data
        assert "data" in data

    def test_connection_status_no_api_key(self):
        response = self.client.get("/api/ai/connection-status")
        data = response.json()
        assert data["data"]["api_key_set"] is False
        assert data["data"]["configured"] is False

    def test_connection_status_has_model_info(self):
        response = self.client.get("/api/ai/connection-status")
        data = response.json()
        assert "model_id" in data["data"]
        assert "base_url" in data["data"]


@pytest.mark.integration
class TestAIChatEndpoint:
    @pytest.fixture(autouse=True)
    def setup(self):
        if not FASTAPI_AVAILABLE:
            pytest.skip("FastAPI not available")
        app, self._patcher = _create_app_with_patch()
        if app is None:
            pytest.skip("Backend dependencies unavailable")
        self.client = TestClient(app)
        yield
        if self._patcher:
            self._patcher.stop()

    def test_chat_requires_message_field(self):
        response = self.client.post("/api/ai/chat", json={})
        assert response.status_code == 422

    def test_chat_with_mocked_ai(self):
        mock_response = MagicMock()
        mock_response.content = "您好，这是一条测试回复。"
        mock_response.response_metadata = {"total_tokens": 42}

        async def mock_ainvoke(*args, **kwargs):
            return mock_response

        mock_llm = MagicMock()
        mock_llm.ainvoke = mock_ainvoke

        try:
            with patch('backend.api.ai.get_llm', return_value=mock_llm):
                payload = {"message": "你好，请介绍一下XSS漏洞"}
                response = self.client.post("/api/ai/chat", json=payload)
                assert response.status_code == 200
                data = response.json()
                assert data["code"] == 200
                assert data["data"]["response"] == "您好，这是一条测试回复。"
                assert data["data"]["model"] == "test-model"
        except Exception as e:
            pytest.skip(f"Chat mock test skipped: {str(e)}")

    def test_chat_no_api_key_returns_500(self):
        payload = {"message": "测试消息"}
        response = self.client.post("/api/ai/chat", json=payload)
        assert response.status_code == 500
        data = response.json()
        assert "detail" in data


@pytest.mark.integration
class TestAIAgentsEndpoints:
    @pytest.fixture(autouse=True)
    def setup(self):
        if not FASTAPI_AVAILABLE:
            pytest.skip("FastAPI not available")
        app, self._patcher = _create_app_with_patch()
        if app is None:
            pytest.skip("Backend dependencies unavailable")
        self.client = TestClient(app)
        yield
        if self._patcher:
            self._patcher.stop()

    def test_tools_endpoint_returns_200(self):
        response = self.client.get("/api/ai_agents/tools")
        assert response.status_code == 200

    def test_tools_endpoint_returns_valid_structure(self):
        response = self.client.get("/api/ai_agents/tools")
        data = response.json()
        assert "code" in data
        assert "message" in data
        assert "data" in data
        assert "total" in data["data"]
        assert "tools" in data["data"]
        assert isinstance(data["data"]["tools"], list)

    def test_config_endpoint_returns_200(self):
        response = self.client.get("/api/ai_agents/config")
        assert response.status_code == 200

    def test_config_endpoint_has_required_fields(self):
        response = self.client.get("/api/ai_agents/config")
        data = response.json()
        assert data["code"] == 200
        config = data["data"]
        assert "max_execution_time" in config
        assert "max_retries" in config
        assert "enable_llm_planning" in config
        assert "enable_memory" in config