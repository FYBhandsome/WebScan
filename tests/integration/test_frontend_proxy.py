import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import pytest
import json

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


BACKEND_BASE_URL = "http://127.0.0.1:8888/api"
BACKEND_TIMEOUT = 5


def _is_backend_running():
    try:
        resp = requests.get(f"{BACKEND_BASE_URL}/ai/connection-status", timeout=BACKEND_TIMEOUT)
        return resp.status_code in (200, 500)
    except Exception:
        return False


def _skip_if_backend_down():
    if not REQUESTS_AVAILABLE and not HTTPX_AVAILABLE:
        pytest.skip("Neither requests nor httpx available")
    if not _is_backend_running():
        pytest.skip(f"Backend not running at {BACKEND_BASE_URL}")


@pytest.mark.integration
class TestBackendHealthViaProxy:
    def test_ai_connection_status_returns_valid_json(self):
        _skip_if_backend_down()
        try:
            resp = requests.get(
                f"{BACKEND_BASE_URL}/ai/connection-status",
                timeout=BACKEND_TIMEOUT
            )
            assert resp.status_code == 200
            data = resp.json()
            assert "code" in data
            assert "message" in data
            assert "data" in data
            assert "api_key_set" in data["data"] or "configured" in data["data"]
        except requests.exceptions.ConnectionError:
            pytest.skip("Backend connection refused")
        except requests.exceptions.Timeout:
            pytest.skip("Backend connection timed out")

    def test_ai_connection_status_response_content_type(self):
        _skip_if_backend_down()
        try:
            resp = requests.get(
                f"{BACKEND_BASE_URL}/ai/connection-status",
                timeout=BACKEND_TIMEOUT
            )
            if resp.status_code == 200:
                ct = resp.headers.get("content-type", "")
                assert "application/json" in ct
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            pytest.skip("Backend unavailable")

    def test_root_endpoint(self):
        _skip_if_backend_down()
        try:
            resp = requests.get(
                "http://127.0.0.1:8888/",
                timeout=BACKEND_TIMEOUT
            )
            assert resp.status_code == 200
            data = resp.json()
            assert "status" in data
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            pytest.skip("Backend unavailable")

    def test_health_endpoint(self):
        _skip_if_backend_down()
        try:
            resp = requests.get(
                "http://127.0.0.1:8888/health",
                timeout=BACKEND_TIMEOUT
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data.get("status") == "healthy"
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            pytest.skip("Backend unavailable")


@pytest.mark.integration
class TestCORSHeaders:
    def test_cors_allow_origin_on_options(self):
        _skip_if_backend_down()
        try:
            resp = requests.options(
                f"{BACKEND_BASE_URL}/ai/connection-status",
                headers={
                    "Origin": "http://localhost:5173",
                    "Access-Control-Request-Method": "GET",
                },
                timeout=BACKEND_TIMEOUT
            )
            assert resp.status_code == 200
            allow_origin = resp.headers.get("access-control-allow-origin")
            if allow_origin is not None:
                assert allow_origin == "*" or "localhost" in allow_origin
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            pytest.skip("Backend unavailable")

    def test_cors_headers_on_get(self):
        _skip_if_backend_down()
        try:
            resp = requests.get(
                f"{BACKEND_BASE_URL}/ai/connection-status",
                headers={"Origin": "http://localhost:5173"},
                timeout=BACKEND_TIMEOUT
            )
            assert resp.status_code == 200
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            pytest.skip("Backend unavailable")

    def test_cors_allow_methods_on_options(self):
        _skip_if_backend_down()
        try:
            resp = requests.options(
                f"{BACKEND_BASE_URL}/ai/connection-status",
                headers={
                    "Origin": "http://localhost:5173",
                    "Access-Control-Request-Method": "POST",
                },
                timeout=BACKEND_TIMEOUT
            )
            if resp.status_code == 200:
                allow_methods = resp.headers.get("access-control-allow-methods")
                if allow_methods is not None:
                    assert "POST" in allow_methods or allow_methods == "*"
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            pytest.skip("Backend unavailable")


@pytest.mark.integration
class TestProxySimulation:
    def test_proxy_get_request_simulated(self):
        _skip_if_backend_down()
        try:
            resp = requests.get(
                f"{BACKEND_BASE_URL}/ai/connection-status",
                headers={
                    "User-Agent": "Mozilla/5.0 FrontendProxy/1.0",
                    "Accept": "application/json",
                },
                timeout=BACKEND_TIMEOUT
            )
            assert resp.status_code == 200
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            pytest.skip("Backend unavailable")

    def test_proxy_post_request_simulated(self):
        _skip_if_backend_down()
        try:
            resp = requests.post(
                f"{BACKEND_BASE_URL}/ai/connection-status",
                headers={
                    "User-Agent": "Mozilla/5.0 FrontendProxy/1.0",
                    "Accept": "application/json",
                },
                timeout=BACKEND_TIMEOUT
            )
            assert resp.status_code in (200, 405, 404)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            pytest.skip("Backend unavailable")


@pytest.mark.integration
class TestHttpXFallback:
    @pytest.fixture(autouse=True)
    def check_httpx(self):
        if not HTTPX_AVAILABLE:
            pytest.skip("httpx not installed")

    def test_ai_connection_status_with_httpx(self):
        if not _is_backend_running():
            pytest.skip(f"Backend not running at {BACKEND_BASE_URL}")
        try:
            with httpx.Client(timeout=BACKEND_TIMEOUT, trust_env=False) as client:
                resp = client.get(f"{BACKEND_BASE_URL}/ai/connection-status")
                assert resp.status_code == 200
                data = resp.json()
                assert "code" in data
                assert "data" in data
        except httpx.ConnectError:
            pytest.skip("Backend connection refused via httpx")
        except httpx.TimeoutException:
            pytest.skip("Backend timed out via httpx")


@pytest.mark.integration
class TestAuthEndpointsViaProxy:
    def test_ai_connection_status_no_auth_required(self):
        _skip_if_backend_down()
        try:
            resp = requests.get(
                f"{BACKEND_BASE_URL}/ai/connection-status",
                timeout=BACKEND_TIMEOUT
            )
            assert resp.status_code == 200
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            pytest.skip("Backend unavailable")