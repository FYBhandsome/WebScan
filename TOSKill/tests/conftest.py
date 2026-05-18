"""
pytest conftest - 共享fixtures和mock配置
提供数据库、LLM客户端、WebSocket回调等通用fixture
"""
import os
import sys
import json
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

os.environ.setdefault("OPENAI_API_KEY", "test-key")
os.environ.setdefault("OPENAI_BASE_URL", "https://test-api.example.com/v2")
os.environ.setdefault("MODEL_ID", "test-model")


@pytest.fixture
def mock_llm_response():
    """Mock LLM响应"""
    from langchain_core.messages import AIMessage
    msg = AIMessage(content="mock response", tool_calls=[{"name": "baseinfo", "args": {}, "id": "call_1"}])
    return msg


@pytest.fixture
def mock_chat_openai():
    """Mock ChatOpenAI实例"""
    mock = MagicMock()
    mock.invoke.return_value = MagicMock(content="test", tool_calls=[])
    mock.astream.return_value = [MagicMock(content="chunk")]
    mock.bind_tools.return_value = mock
    return mock


@pytest.fixture
def sample_scan_state():
    """标准扫描状态"""
    from TOSKill.AI.state import ScanState
    state: ScanState = {
        "task_id": "test_session",
        "target": "http://test.example.com",
        "mode": "full_scan",
        "task_sequence": ["baseinfo", "portscan", "sqli"],
        "completed_tasks": [],
        "next_task": "",
        "tool_result": {},
        "tool_results": {},
        "task_result": {},
        "vulnerabilities": [],
        "errors": [],
        "is_complete": False,
        "report": "",
        "scan_summary": {},
        "websocket_session_id": "test_session",
        "direct_tool": "",
        "user_input": "",
        "user_choice": "",
        "chat_history": [],
        "pending_action_type": "",
        "rejection_count": 0,
        "confirm_tool": "",
        "confirm_target": "",
        "auth_status": "valid",
        "auth_data": {},
        "switches": {},
        "skipped_tasks": [],
        "need_generate_script": False,
        "rag_enabled": True,
        "rag_last_strategy": "",
        "report_id": "",
        "report_url": "",
    }
    return state


@pytest.fixture
def async_ws_callback():
    """异步WebSocket回调mock"""
    async def callback(data):
        return None
    return callback


@pytest.fixture
def sample_script_content():
    """示例上传脚本内容"""
    return '''
import requests
from typing import Dict

def run(target: str) -> Dict:
    """测试端口扫描脚本"""
    result = {"open_ports": [], "target": target}
    common_ports = [80, 443, 8080]
    for port in common_ports:
        try:
            response = requests.get(f"http://{target}:{port}", timeout=3)
            if response.status_code < 500:
                result["open_ports"].append(port)
        except Exception:
            pass
    return result
'''


@pytest.fixture
def sample_malicious_script():
    """示例恶意脚本（用于安全审查测试）"""
    return '''
import os
import subprocess

def run(target: str) -> dict:
    os.system(f"ping -c 1 {target}")
    subprocess.Popen(["nc", target, "4444"])
    eval(f"print({target})")
    exec(open("test.txt").read())
    return {"status": "done"}
'''


@pytest.fixture
def setup_test_environment():
    """设置测试环境 - 确保必要目录存在"""
    dirs = ["data", "logs", "reports", "scripts", "uploads", "scripts/custom"]
    for d in dirs:
        Path(d).mkdir(parents=True, exist_ok=True)
    yield