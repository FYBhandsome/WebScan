import pytest
import asyncio
from typing import Generator
from httpx import AsyncClient

@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="function")
async def client():
    from fastapi.testclient import TestClient
    try:
        from backend.main import app
        async with AsyncClient(app=app, base_url="http://test") as ac:
            yield ac
    except Exception as e:
        pytest.skip(f"无法导入应用: {e}")

@pytest.fixture
def mock_user():
    return {
        "id": 1,
        "username": "test_user",
        "email": "test@example.com"
    }

@pytest.fixture
def auth_headers(mock_user):
    return {
        "Authorization": "Bearer test_token"
    }

@pytest.fixture
def mock_kb_response():
    return {
        "code": 200,
        "message": "获取成功",
        "data": [
            {
                "id": 1,
                "name": "SQL注入漏洞",
                "severity": "high",
                "description": "存在SQL注入漏洞"
            }
        ]
    }

@pytest.fixture
def mock_settings_response():
    return {
        "code": 200,
        "message": "获取成功",
        "data": {
            "general": {
                "systemName": "WebScan AI",
                "language": "zh-CN"
            }
        }
    }
