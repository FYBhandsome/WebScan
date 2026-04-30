# -*- coding:utf-8 -*-
"""
TOSKill 测试配置文件

提供 pytest fixtures 和测试配置。
"""

import pytest
import sys
import asyncio
import os
import tempfile
import json
from pathlib import Path
from typing import Dict, Any, Generator, AsyncGenerator
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime, timedelta

project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))


@pytest.fixture(scope="session")
def event_loop():
    """创建事件循环"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def test_client():
    """创建测试客户端会话级别fixture"""
    from TOSKill.main import app
    from fastapi.testclient import TestClient
    return TestClient(app)


@pytest.fixture(scope="function")
def fresh_client():
    """创建新的测试客户端（每个测试函数独立）"""
    from TOSKill.main import app
    from fastapi.testclient import TestClient
    return TestClient(app)


@pytest.fixture(scope="session")
def mock_target():
    """测试目标"""
    return "example.com"


@pytest.fixture(scope="session")
def mock_url():
    """测试URL"""
    return "http://example.com"


@pytest.fixture(scope="function")
def test_session_id():
    """生成测试会话ID"""
    import uuid
    return str(uuid.uuid4())[:8]


@pytest.fixture(scope="function")
def clean_memory_store():
    """清理记忆化存储"""
    from TOSKill.AI.graph import memory_store
    
    memory_store._sessions.clear()
    memory_store._chat_histories.clear()
    memory_store._pending_interactions.clear()
    memory_store._websocket_callbacks.clear()
    memory_store._session_timestamps.clear()
    memory_store._session_metadata.clear()
    
    yield memory_store
    
    memory_store._sessions.clear()
    memory_store._chat_histories.clear()
    memory_store._pending_interactions.clear()
    memory_store._websocket_callbacks.clear()
    memory_store._session_timestamps.clear()
    memory_store._session_metadata.clear()


@pytest.fixture(scope="function")
def mock_scan_state(test_session_id: str) -> Dict[str, Any]:
    """创建模拟扫描状态"""
    from TOSKill.AI.state import create_initial_state
    return create_initial_state(target="test.example.com", task_id=test_session_id)


@pytest.fixture(scope="function")
def mock_auth_state(mock_scan_state: Dict[str, Any]) -> Dict[str, Any]:
    """创建带认证信息的模拟状态"""
    from TOSKill.AI.state import update_state
    
    auth_info = {
        "type": "cookies",
        "cookies": {"session": "test_session_value", "token": "test_token_value"},
        "headers": {},
        "token": "",
        "source": "test"
    }
    
    return update_state(
        mock_scan_state,
        auth_info=auth_info,
        auth_timestamp=datetime.now().isoformat(),
        auth_expires_at=(datetime.now() + timedelta(minutes=30)).isoformat(),
        credentials_obtained=True
    )


@pytest.fixture(scope="function")
def expired_auth_state(mock_scan_state: Dict[str, Any]) -> Dict[str, Any]:
    """创建过期认证状态的模拟状态"""
    from TOSKill.AI.state import update_state
    
    auth_info = {
        "type": "cookies",
        "cookies": {"session": "expired_session"},
        "headers": {},
        "token": "",
        "source": "test"
    }
    
    return update_state(
        mock_scan_state,
        auth_info=auth_info,
        auth_timestamp=(datetime.now() - timedelta(hours=1)).isoformat(),
        auth_expires_at=(datetime.now() - timedelta(minutes=30)).isoformat(),
        credentials_obtained=True
    )


@pytest.fixture(scope="function")
def temp_reports_dir():
    """创建临时报告目录"""
    with tempfile.TemporaryDirectory() as tmpdir:
        reports_dir = Path(tmpdir) / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        
        original_dir = os.getcwd()
        os.chdir(tmpdir)
        
        yield reports_dir
        
        os.chdir(original_dir)


@pytest.fixture(scope="function")
def temp_logs_dir():
    """创建临时日志目录"""
    with tempfile.TemporaryDirectory() as tmpdir:
        logs_dir = Path(tmpdir) / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        yield logs_dir


@pytest.fixture(scope="function")
def mock_tool_result() -> Dict[str, Any]:
    """创建模拟工具结果"""
    return {
        "success": True,
        "data": {
            "ports": [80, 443, 8080],
            "server": "nginx",
            "title": "Test Page"
        },
        "error": None,
        "auth_info": None,
        "timestamp": datetime.now().isoformat()
    }


@pytest.fixture(scope="function")
def mock_vulnerability_result() -> Dict[str, Any]:
    """创建模拟漏洞扫描结果"""
    return {
        "success": True,
        "data": {
            "vulnerable": True,
            "injection_type": "error-based",
            "payload": "' OR '1'='1",
            "parameter": "id"
        },
        "error": None,
        "auth_info": None,
        "timestamp": datetime.now().isoformat()
    }


@pytest.fixture(scope="function")
def mock_auth_result() -> Dict[str, Any]:
    """创建模拟认证结果"""
    return {
        "success": True,
        "data": {
            "login_success": True,
            "username": "admin",
            "password": "admin123"
        },
        "cookies_obtained": {"session": "authenticated_session_value"},
        "tokens_obtained": "bearer_token_value",
        "authentication_used": True,
        "auth_type": "form_login",
        "auth_source": "weakpass_scan",
        "timestamp": datetime.now().isoformat()
    }


@pytest.fixture(scope="function")
def mock_websocket():
    """创建模拟 WebSocket"""
    mock_ws = AsyncMock()
    mock_ws.accept = AsyncMock()
    mock_ws.send_json = AsyncMock()
    mock_ws.receive_json = AsyncMock()
    mock_ws.close = AsyncMock()
    return mock_ws


@pytest.fixture(scope="function")
def mock_llm_response():
    """创建模拟 LLM 响应"""
    mock_response = MagicMock()
    mock_response.content = json.dumps({
        "intent_type": "scan",
        "tool_name": "",
        "target": "example.com",
        "confidence": 0.9
    })
    return mock_response


@pytest.fixture(scope="function")
def sample_report_content():
    """创建示例报告内容"""
    return """# 安全扫描报告

## 扫描概要
- 目标: example.com
- 扫描时间: 2024-01-01 12:00:00
- 工具数量: 5
- 发现漏洞: 2

## 信息收集结果
### 端口扫描
- 开放端口: 80, 443

### 子域名扫描
- 发现子域名: 3 个

## 漏洞扫描结果
### SQL注入
- 状态: 发现漏洞
- 严重程度: 高危

### XSS
- 状态: 未发现漏洞
"""


class MockTool:
    """模拟工具类"""
    
    def __init__(self, name: str, description: str, result: Dict[str, Any] = None):
        self.name = name
        self.description = description
        self._result = result or {"success": True, "data": {}}
    
    def invoke(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return self._result


@pytest.fixture(scope="function")
def mock_tool():
    """创建模拟工具"""
    return MockTool(
        name="test_tool",
        description="测试工具",
        result={"success": True, "data": {"test": "value"}}
    )


@pytest.fixture(scope="function")
def mock_tool_map(mock_tool: MockTool) -> Dict[str, MockTool]:
    """创建模拟工具映射"""
    return {
        "test_tool": mock_tool,
        "baseinfo_scan": MockTool("baseinfo_scan", "基础信息扫描"),
        "port_scan": MockTool("port_scan", "端口扫描"),
        "sqli_scan": MockTool("sqli_scan", "SQL注入扫描"),
        "xss_scan": MockTool("xss_scan", "XSS扫描"),
    }


def pytest_configure(config):
    """pytest配置"""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "unit: marks tests as unit tests"
    )
    config.addinivalue_line(
        "markers", "websocket: marks tests as WebSocket tests"
    )
    config.addinivalue_line(
        "markers", "auth: marks tests as authentication tests"
    )
    config.addinivalue_line(
        "markers", "memory: marks tests as memory store tests"
    )
    config.addinivalue_line(
        "markers", "api: marks tests as API tests"
    )
    config.addinivalue_line(
        "markers", "workflow: marks tests as workflow tests"
    )


def pytest_collection_modifyitems(config, items):
    """修改测试项"""
    for item in items:
        if "slow" in item.keywords:
            item.add_marker(pytest.mark.slow)
        if "integration" in item.keywords:
            item.add_marker(pytest.mark.integration)
        if "unit" in item.keywords:
            item.add_marker(pytest.mark.unit)
