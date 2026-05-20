import pytest
import json
import sys
import os
import types
from pathlib import Path
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from fastapi.testclient import TestClient
from pydantic import BaseModel
from typing import Optional, Any


class APIResponse(BaseModel):
    code: int
    message: str
    data: Optional[Any] = None


def _preload_api_common():
    if 'backend.ai_agents.api.routes' in sys.modules:
        _fix_ai_agents_getattr()
        return

    if 'backend.api' not in sys.modules or not hasattr(sys.modules.get('backend.api'), '__path__'):
        import backend
        api_pkg = types.ModuleType('backend.api')
        api_pkg.__path__ = [str(Path(backend.__file__).parent / 'api')]
        api_pkg.__package__ = 'backend.api'
        sys.modules['backend.api'] = api_pkg

    if 'backend.api.common' not in sys.modules:
        import importlib.util
        spec = importlib.util.find_spec('backend.api.common')
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            sys.modules['backend.api.common'] = module
            spec.loader.exec_module(module)

    for mod_name in ['TOSKill', 'TOSKill.api']:
        if mod_name not in sys.modules:
            sys.modules[mod_name] = MagicMock()

    from backend.ai_agents.api.routes import router

    _fix_ai_agents_getattr()

    try:
        import backend.ai_agents.tools.registry
        _fix_ai_agents_getattr()
    except (ImportError, ModuleNotFoundError):
        pass

    try:
        import backend.api.workflow_schemas
    except (ImportError, ModuleNotFoundError):
        pass


def _fix_ai_agents_getattr():
    ai_agents_mod = sys.modules.get('backend.ai_agents')
    if ai_agents_mod is None:
        return
    for attr_name in ['api', 'core', 'tools', 'utils', 'analyzers', 'poc_system', 'planners']:
        mod_name = f'backend.ai_agents.{attr_name}'
        if mod_name in sys.modules and not hasattr(ai_agents_mod, attr_name):
            setattr(ai_agents_mod, attr_name, sys.modules[mod_name])


_preload_api_common()

_tools_registry_mod = sys.modules.get('backend.ai_agents.tools.registry')
_workflow_schemas_mod = sys.modules.get('backend.api.workflow_schemas')


@pytest.fixture
def mock_registry():
    reg = Mock()
    if _tools_registry_mod is not None:
        with patch.object(_tools_registry_mod, 'registry', reg):
            yield reg
    else:
        mock_module = types.ModuleType('backend.ai_agents.tools.registry')
        mock_module.registry = reg
        mock_module.__package__ = 'backend.ai_agents.tools'
        modules_to_patch = {'backend.ai_agents.tools.registry': mock_module}
        if 'backend.ai_agents.tools' not in sys.modules:
            tools_pkg = types.ModuleType('backend.ai_agents.tools')
            tools_pkg.__path__ = []
            tools_pkg.__package__ = 'backend.ai_agents.tools'
            modules_to_patch['backend.ai_agents.tools'] = tools_pkg
        with patch.dict(sys.modules, modules_to_patch):
            yield reg


@pytest.fixture
def mock_workflow_optimizer():
    optimizer = Mock()
    optimizer.get_execution_summary = Mock(return_value={})
    optimizer.get_execution_metrics = Mock(return_value=[])
    get_optimizer_fn = Mock(return_value=optimizer)
    if _workflow_schemas_mod is not None:
        with patch.object(_workflow_schemas_mod, 'get_execution_optimizer', get_optimizer_fn):
            yield get_optimizer_fn
    else:
        mock_module = types.ModuleType('backend.api.workflow_schemas')
        mock_module.get_execution_optimizer = get_optimizer_fn
        mock_module.__package__ = 'backend.api'
        with patch.dict(sys.modules, {'backend.api.workflow_schemas': mock_module}):
            yield get_optimizer_fn


def _create_test_app():
    _preload_api_common()
    from backend.ai_agents.api.routes import router
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router, prefix="/api")
    return app


@pytest.fixture
def mock_task():
    task = Mock()
    task.id = 1
    task.task_name = "AI Agent Scan http://example.com"
    task.task_type = "ai_agent_scan"
    task.target = "http://example.com"
    task.status = "pending"
    task.progress = 0
    task.config = json.dumps({"target": "http://example.com", "strategy": "standard"})
    task.result = None
    task.error_message = None
    task.created_at = datetime.now(timezone.utc)
    task.updated_at = datetime.now(timezone.utc)
    return task


@pytest.fixture
def mock_running_task():
    task = Mock()
    task.id = 2
    task.task_name = "AI Agent Scan http://running.com"
    task.task_type = "ai_agent_scan"
    task.target = "http://running.com"
    task.status = "running"
    task.progress = 50
    task.config = json.dumps({"target": "http://running.com", "strategy": "deep"})
    task.result = json.dumps({
        "execution_history": [{"step": 1, "tool": "portscan", "status": "completed"}],
        "stages": {
            "planning": {"status": "completed", "progress": 100},
            "tool_execution": {"status": "running", "progress": 50},
            "poc_verification": {"status": "pending", "progress": 0},
            "report": {"status": "pending", "progress": 0}
        },
        "graph_flow": {"nodes": ["planning", "tool_execution"]},
        "target_context": {"ip": "1.2.3.4"},
        "scan_summary": {"tools_executed": 5}
    })
    task.error_message = None
    task.created_at = datetime.now(timezone.utc)
    task.updated_at = datetime.now(timezone.utc)
    return task


@pytest.fixture
def mock_completed_task():
    task = Mock()
    task.id = 3
    task.task_name = "AI Agent Scan http://completed.com"
    task.task_type = "ai_agent_scan"
    task.target = "http://completed.com"
    task.status = "completed"
    task.progress = 100
    task.config = json.dumps({"target": "http://completed.com", "strategy": "quick"})
    task.result = json.dumps({
        "execution_history": [{"step": 1, "tool": "portscan", "status": "completed"}],
        "stages": {
            "planning": {"status": "completed", "progress": 100},
            "tool_execution": {"status": "completed", "progress": 100},
            "poc_verification": {"status": "completed", "progress": 100},
            "report": {"status": "completed", "progress": 100}
        },
        "final_output": {"vulnerabilities": []},
        "target_context": {"ip": "5.6.7.8"},
        "scan_summary": {"tools_executed": 10, "vulnerabilities_found": 0}
    })
    task.error_message = None
    task.created_at = datetime.now(timezone.utc)
    task.updated_at = datetime.now(timezone.utc)
    return task


class TestStartAgentScan:

    @patch("backend.ai_agents.api.routes.task_executor")
    @patch("backend.ai_agents.api.routes.Task")
    @patch("backend.ai_agents.api.routes.agent_config")
    def test_scan_success(self, mock_agent_config, mock_task_model, mock_executor):
        app = _create_test_app()
        client = TestClient(app)

        mock_task_obj = Mock()
        mock_task_obj.id = 42
        mock_task_model.create = AsyncMock(return_value=mock_task_obj)
        mock_executor.start_task = AsyncMock()

        response = client.post("/api/ai_agents/scan", json={
            "target": "http://example.com",
            "strategy": "standard",
            "concurrency": 5,
            "timeout": 300
        })

        assert response.status_code == 200
        data = response.json()
        assert data["task_id"] == "42"
        assert data["status"] == "pending"
        assert "message" in data

    @patch("backend.ai_agents.api.routes.task_executor")
    @patch("backend.ai_agents.api.routes.Task")
    @patch("backend.ai_agents.api.routes.agent_config")
    def test_scan_with_llm_planning(self, mock_agent_config, mock_task_model, mock_executor):
        app = _create_test_app()
        client = TestClient(app)

        mock_task_obj = Mock()
        mock_task_obj.id = 43
        mock_task_model.create = AsyncMock(return_value=mock_task_obj)
        mock_executor.start_task = AsyncMock()

        response = client.post("/api/ai_agents/scan", json={
            "target": "http://example.com",
            "enable_llm_planning": True,
            "strategy": "deep"
        })

        assert response.status_code == 200
        data = response.json()
        assert data["task_id"] == "43"
        assert data["status"] == "pending"

    def test_scan_missing_target(self):
        app = _create_test_app()
        client = TestClient(app)

        response = client.post("/api/ai_agents/scan", json={})

        assert response.status_code == 422

    def test_scan_invalid_strategy_type(self):
        app = _create_test_app()
        client = TestClient(app)

        response = client.post("/api/ai_agents/scan", json={
            "target": "http://example.com",
            "strategy": 123
        })

        assert response.status_code == 422

    def test_scan_invalid_concurrency_type(self):
        app = _create_test_app()
        client = TestClient(app)

        response = client.post("/api/ai_agents/scan", json={
            "target": "http://example.com",
            "concurrency": "not_a_number"
        })

        assert response.status_code == 422

    @patch("backend.ai_agents.api.routes.task_executor")
    @patch("backend.ai_agents.api.routes.Task")
    @patch("backend.ai_agents.api.routes.agent_config")
    def test_scan_with_custom_scan_options(self, mock_agent_config, mock_task_model, mock_executor):
        app = _create_test_app()
        client = TestClient(app)

        mock_task_obj = Mock()
        mock_task_obj.id = 44
        mock_task_model.create = AsyncMock(return_value=mock_task_obj)
        mock_executor.start_task = AsyncMock()

        response = client.post("/api/ai_agents/scan", json={
            "target": "http://example.com",
            "need_custom_scan": True,
            "custom_scan_type": "vuln_scan",
            "custom_scan_requirements": "Test for SQL injection",
            "custom_scan_language": "python",
            "selected_tools": ["sqli_scan", "xss_scan"]
        })

        assert response.status_code == 200

    @patch("backend.ai_agents.api.routes.task_executor")
    @patch("backend.ai_agents.api.routes.Task")
    @patch("backend.ai_agents.api.routes.agent_config")
    def test_scan_internal_error(self, mock_agent_config, mock_task_model, mock_executor):
        app = _create_test_app()
        client = TestClient(app)

        mock_task_model.create = AsyncMock(side_effect=Exception("DB connection failed"))

        response = client.post("/api/ai_agents/scan", json={
            "target": "http://example.com"
        })

        assert response.status_code == 500


class TestGetAgentTask:

    @patch("backend.ai_agents.api.routes.Task")
    def test_get_task_success(self, mock_task_model, mock_task):
        app = _create_test_app()
        client = TestClient(app)

        mock_task_model.get_or_none = AsyncMock(return_value=mock_task)

        response = client.get("/api/ai_agents/tasks/1")

        assert response.status_code == 200
        data = response.json()
        assert data["code"] == 200
        assert data["data"]["task_id"] == "1"
        assert data["data"]["status"] == "pending"
        assert "stages" in data["data"]
        assert "execution_history" in data["data"]

    @patch("backend.ai_agents.api.routes.Task")
    def test_get_running_task(self, mock_task_model, mock_running_task):
        app = _create_test_app()
        client = TestClient(app)

        mock_task_model.get_or_none = AsyncMock(return_value=mock_running_task)

        response = client.get("/api/ai_agents/tasks/2")

        assert response.status_code == 200
        data = response.json()
        assert data["data"]["status"] == "running"
        assert data["data"]["progress"] == 50
        assert "stages" in data["data"]

    @patch("backend.ai_agents.api.routes.Task")
    def test_get_completed_task(self, mock_task_model, mock_completed_task):
        app = _create_test_app()
        client = TestClient(app)

        mock_task_model.get_or_none = AsyncMock(return_value=mock_completed_task)

        response = client.get("/api/ai_agents/tasks/3")

        assert response.status_code == 200
        data = response.json()
        assert data["data"]["status"] == "completed"
        assert data["data"]["progress"] == 100

    @patch("backend.ai_agents.api.routes.Task")
    def test_get_task_not_found(self, mock_task_model):
        app = _create_test_app()
        client = TestClient(app)

        mock_task_model.get_or_none = AsyncMock(return_value=None)

        response = client.get("/api/ai_agents/tasks/9999")

        assert response.status_code == 404

    @patch("backend.ai_agents.api.routes.Task")
    def test_get_task_non_numeric_id(self, mock_task_model):
        app = _create_test_app()
        client = TestClient(app)

        mock_task_model.get_or_none = AsyncMock(return_value=None)

        response = client.get("/api/ai_agents/tasks/abc")

        assert response.status_code == 404

    @patch("backend.ai_agents.api.routes.Task")
    def test_get_task_response_format(self, mock_task_model, mock_task):
        app = _create_test_app()
        client = TestClient(app)

        mock_task_model.get_or_none = AsyncMock(return_value=mock_task)

        response = client.get("/api/ai_agents/tasks/1")
        data = response.json()

        assert "code" in data
        assert "message" in data
        assert "data" in data
        task_data = data["data"]
        expected_fields = [
            "task_id", "task_type", "target", "status", "progress",
            "config", "stages", "execution_history", "graph_flow",
            "target_context", "scan_summary", "created_at", "updated_at",
            "final_output", "error_message"
        ]
        for field in expected_fields:
            assert field in task_data, f"Missing field: {field}"

    @patch("backend.ai_agents.api.routes.Task")
    def test_get_task_internal_error(self, mock_task_model):
        app = _create_test_app()
        client = TestClient(app)

        mock_task_model.get_or_none = AsyncMock(side_effect=Exception("DB error"))

        response = client.get("/api/ai_agents/tasks/1")

        assert response.status_code == 500


class _AwaitableQuery(Mock):
    def __init__(self, *args, items=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._items = items or []
        self.filter = Mock(return_value=self)
        self.count = AsyncMock(return_value=len(self._items))
        self.order_by = Mock(return_value=self)
        self.offset = Mock(return_value=self)
        self.limit = Mock(return_value=self)

    def __await__(self):
        async def _resolve():
            return self
        return _resolve().__await__()

    def __aiter__(self):
        return iter(self._items)

    def __iter__(self):
        return iter(self._items)


class TestListAgentTasks:

    @patch("backend.ai_agents.api.routes.Task")
    def test_list_tasks_success(self, mock_task_model, mock_task):
        app = _create_test_app()
        client = TestClient(app)

        mock_query = _AwaitableQuery(items=[mock_task])
        mock_task_model.filter = Mock(return_value=mock_query)

        response = client.get("/api/ai_agents/tasks")

        assert response.status_code == 200
        data = response.json()
        assert data["code"] == 200
        assert "tasks" in data["data"]
        assert "total" in data["data"]
        assert "page" in data["data"]
        assert "page_size" in data["data"]
        assert "total_pages" in data["data"]

    @patch("backend.ai_agents.api.routes.Task")
    def test_list_tasks_with_pagination(self, mock_task_model, mock_task):
        app = _create_test_app()
        client = TestClient(app)

        mock_query = _AwaitableQuery(items=[mock_task])
        mock_query.count = AsyncMock(return_value=50)
        mock_task_model.filter = Mock(return_value=mock_query)

        response = client.get("/api/ai_agents/tasks?page=2&page_size=10")

        assert response.status_code == 200
        data = response.json()
        assert data["data"]["page"] == 2
        assert data["data"]["page_size"] == 10
        assert data["data"]["total_pages"] == 5

    @patch("backend.ai_agents.api.routes.Task")
    def test_list_tasks_with_status_filter(self, mock_task_model, mock_task):
        app = _create_test_app()
        client = TestClient(app)

        mock_query = _AwaitableQuery(items=[])
        mock_task_model.filter = Mock(return_value=mock_query)

        response = client.get("/api/ai_agents/tasks?status=completed")

        assert response.status_code == 200

    @patch("backend.ai_agents.api.routes.Task")
    def test_list_tasks_empty(self, mock_task_model):
        app = _create_test_app()
        client = TestClient(app)

        mock_query = _AwaitableQuery(items=[])
        mock_task_model.filter = Mock(return_value=mock_query)

        response = client.get("/api/ai_agents/tasks")

        assert response.status_code == 200
        data = response.json()
        assert data["data"]["tasks"] == []
        assert data["data"]["total"] == 0

    @patch("backend.ai_agents.api.routes.Task")
    def test_list_tasks_response_apiresponse_format(self, mock_task_model, mock_task):
        app = _create_test_app()
        client = TestClient(app)

        mock_query = _AwaitableQuery(items=[mock_task])
        mock_task_model.filter = Mock(return_value=mock_query)

        response = client.get("/api/ai_agents/tasks")
        data = response.json()

        assert "code" in data
        assert "message" in data
        assert "data" in data
        assert isinstance(data["code"], int)
        assert isinstance(data["message"], str)

    @patch("backend.ai_agents.api.routes.Task")
    def test_list_tasks_internal_error(self, mock_task_model):
        app = _create_test_app()
        client = TestClient(app)

        mock_query = _AwaitableQuery(items=[])
        mock_query.count = AsyncMock(side_effect=Exception("DB error"))
        mock_task_model.filter = Mock(return_value=mock_query)

        response = client.get("/api/ai_agents/tasks")

        assert response.status_code == 500


class TestCancelAgentTask:

    @patch("backend.ai_agents.api.routes.task_executor")
    @patch("backend.ai_agents.api.routes.Task")
    def test_cancel_running_task(self, mock_task_model, mock_executor, mock_running_task):
        app = _create_test_app()
        client = TestClient(app)

        mock_task_model.get_or_none = AsyncMock(return_value=mock_running_task)
        mock_executor.cancel_task = AsyncMock()
        mock_running_task.save = AsyncMock()

        response = client.post("/api/ai_agents/tasks/2/cancel")

        assert response.status_code == 200
        data = response.json()
        assert data["code"] == 200
        assert data["data"]["status"] == "cancelled"

    @patch("backend.ai_agents.api.routes.task_executor")
    @patch("backend.ai_agents.api.routes.Task")
    def test_cancel_pending_task(self, mock_task_model, mock_executor, mock_task):
        app = _create_test_app()
        client = TestClient(app)

        mock_task_model.get_or_none = AsyncMock(return_value=mock_task)
        mock_executor.cancel_task = AsyncMock()
        mock_task.save = AsyncMock()

        response = client.post("/api/ai_agents/tasks/1/cancel")

        assert response.status_code == 200
        data = response.json()
        assert data["data"]["status"] == "cancelled"

    @patch("backend.ai_agents.api.routes.Task")
    def test_cancel_task_not_found(self, mock_task_model):
        app = _create_test_app()
        client = TestClient(app)

        mock_task_model.get_or_none = AsyncMock(return_value=None)

        response = client.post("/api/ai_agents/tasks/9999/cancel")

        assert response.status_code == 404

    @patch("backend.ai_agents.api.routes.Task")
    def test_cancel_task_non_numeric_id(self, mock_task_model):
        app = _create_test_app()
        client = TestClient(app)

        mock_task_model.get_or_none = AsyncMock(return_value=None)

        response = client.post("/api/ai_agents/tasks/abc/cancel")

        assert response.status_code == 404

    @patch("backend.ai_agents.api.routes.task_executor")
    @patch("backend.ai_agents.api.routes.Task")
    def test_cancel_completed_task(self, mock_task_model, mock_executor, mock_completed_task):
        app = _create_test_app()
        client = TestClient(app)

        mock_task_model.get_or_none = AsyncMock(return_value=mock_completed_task)
        mock_executor.cancel_task = AsyncMock()

        response = client.post("/api/ai_agents/tasks/3/cancel")

        assert response.status_code == 200
        data = response.json()
        assert data["data"]["status"] == "cancelled"

    @patch("backend.ai_agents.api.routes.task_executor")
    @patch("backend.ai_agents.api.routes.Task")
    def test_cancel_task_internal_error(self, mock_task_model, mock_executor):
        app = _create_test_app()
        client = TestClient(app)

        mock_task_model.get_or_none = AsyncMock(side_effect=Exception("DB error"))

        response = client.post("/api/ai_agents/tasks/1/cancel")

        assert response.status_code == 500


class TestListTools:

    def test_list_tools_success(self, mock_registry):
        app = _create_test_app()
        client = TestClient(app)

        mock_registry.list_tools = Mock(return_value=[
            {"name": "portscan", "category": "plugin", "description": "Port scanner"},
            {"name": "sqli_scan", "category": "plugin", "description": "SQL injection scanner"}
        ])

        response = client.get("/api/ai_agents/tools")

        assert response.status_code == 200
        data = response.json()
        assert data["code"] == 200
        assert "tools" in data["data"]
        assert "total" in data["data"]
        assert data["data"]["total"] == 2

    def test_list_tools_with_category(self, mock_registry):
        app = _create_test_app()
        client = TestClient(app)

        mock_registry.list_tools = Mock(return_value=[
            {"name": "portscan", "category": "plugin", "description": "Port scanner"}
        ])

        response = client.get("/api/ai_agents/tools?category=plugin")

        assert response.status_code == 200
        data = response.json()
        assert data["data"]["total"] == 1

    def test_list_tools_empty(self, mock_registry):
        app = _create_test_app()
        client = TestClient(app)

        mock_registry.list_tools = Mock(return_value=[])

        response = client.get("/api/ai_agents/tools")

        assert response.status_code == 200
        data = response.json()
        assert data["data"]["total"] == 0
        assert data["data"]["tools"] == []

    def test_list_tools_internal_error(self, mock_registry):
        app = _create_test_app()
        client = TestClient(app)

        mock_registry.list_tools = Mock(side_effect=Exception("Registry error"))

        response = client.get("/api/ai_agents/tools")

        assert response.status_code == 500


class TestGetConfig:

    @patch("backend.ai_agents.api.routes.agent_config")
    def test_get_config_success(self, mock_agent_config):
        app = _create_test_app()
        client = TestClient(app)

        mock_agent_config.MAX_EXECUTION_TIME = 18000
        mock_agent_config.MAX_RETRIES = 3
        mock_agent_config.MAX_CONCURRENT_TOOLS = 5
        mock_agent_config.TOOL_TIMEOUT = 60
        mock_agent_config.ENABLE_LLM_PLANNING = True
        mock_agent_config.DEFAULT_SCAN_TASKS = ["portscan", "sqli_scan"]
        mock_agent_config.ENABLE_MEMORY = True
        mock_agent_config.ENABLE_KB_INTEGRATION = True

        response = client.get("/api/ai_agents/config")

        assert response.status_code == 200
        data = response.json()
        assert data["code"] == 200
        assert "max_execution_time" in data["data"]
        assert "max_retries" in data["data"]
        assert "max_concurrent_tools" in data["data"]
        assert "tool_timeout" in data["data"]
        assert "enable_llm_planning" in data["data"]
        assert "default_scan_tasks" in data["data"]
        assert "enable_memory" in data["data"]
        assert "enable_kb_integration" in data["data"]

    @patch("backend.ai_agents.api.routes.agent_config")
    def test_get_config_response_format(self, mock_agent_config):
        app = _create_test_app()
        client = TestClient(app)

        mock_agent_config.MAX_EXECUTION_TIME = 18000
        mock_agent_config.MAX_RETRIES = 3
        mock_agent_config.MAX_CONCURRENT_TOOLS = 5
        mock_agent_config.TOOL_TIMEOUT = 60
        mock_agent_config.ENABLE_LLM_PLANNING = True
        mock_agent_config.DEFAULT_SCAN_TASKS = []
        mock_agent_config.ENABLE_MEMORY = True
        mock_agent_config.ENABLE_KB_INTEGRATION = True

        response = client.get("/api/ai_agents/config")
        data = response.json()

        assert "code" in data
        assert "message" in data
        assert "data" in data
        assert isinstance(data["data"]["max_execution_time"], int)
        assert isinstance(data["data"]["enable_llm_planning"], bool)


class TestUpdateConfig:

    @patch("backend.ai_agents.api.routes.agent_config")
    def test_update_config_success(self, mock_agent_config):
        app = _create_test_app()
        client = TestClient(app)

        mock_agent_config.MAX_EXECUTION_TIME = 36000
        mock_agent_config.MAX_RETRIES = 5
        mock_agent_config.MAX_CONCURRENT_TOOLS = 10
        mock_agent_config.TOOL_TIMEOUT = 120
        mock_agent_config.ENABLE_LLM_PLANNING = False
        mock_agent_config.DEFAULT_SCAN_TASKS = []
        mock_agent_config.ENABLE_MEMORY = False
        mock_agent_config.ENABLE_KB_INTEGRATION = True

        response = client.post(
            "/api/ai_agents/config",
            params={
                "max_execution_time": 36000,
                "max_retries": 5,
                "max_concurrent_tools": 10,
                "tool_timeout": 120,
                "enable_llm_planning": False,
                "enable_memory": False
            }
        )

        assert response.status_code == 200
        data = response.json()
        assert data["code"] == 200
        assert data["message"] == "配置更新成功"
        assert data["data"]["max_execution_time"] == 36000

    @patch("backend.ai_agents.api.routes.agent_config")
    def test_update_config_partial(self, mock_agent_config):
        app = _create_test_app()
        client = TestClient(app)

        mock_agent_config.MAX_EXECUTION_TIME = 18000
        mock_agent_config.MAX_RETRIES = 3
        mock_agent_config.MAX_CONCURRENT_TOOLS = 5
        mock_agent_config.TOOL_TIMEOUT = 60
        mock_agent_config.ENABLE_LLM_PLANNING = True
        mock_agent_config.DEFAULT_SCAN_TASKS = []
        mock_agent_config.ENABLE_MEMORY = True
        mock_agent_config.ENABLE_KB_INTEGRATION = True

        response = client.post(
            "/api/ai_agents/config",
            params={"max_retries": 10}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["data"]["max_retries"] == 10

    @patch("backend.ai_agents.api.routes.agent_config")
    def test_update_config_empty(self, mock_agent_config):
        app = _create_test_app()
        client = TestClient(app)

        mock_agent_config.MAX_EXECUTION_TIME = 18000
        mock_agent_config.MAX_RETRIES = 3
        mock_agent_config.MAX_CONCURRENT_TOOLS = 5
        mock_agent_config.TOOL_TIMEOUT = 60
        mock_agent_config.ENABLE_LLM_PLANNING = True
        mock_agent_config.DEFAULT_SCAN_TASKS = []
        mock_agent_config.ENABLE_MEMORY = True
        mock_agent_config.ENABLE_KB_INTEGRATION = True

        response = client.post("/api/ai_agents/config")

        assert response.status_code == 200
        data = response.json()
        assert data["code"] == 200

    @patch("backend.ai_agents.api.routes.agent_config")
    def test_update_config_response_includes_all_fields(self, mock_agent_config):
        app = _create_test_app()
        client = TestClient(app)

        mock_agent_config.MAX_EXECUTION_TIME = 18000
        mock_agent_config.MAX_RETRIES = 3
        mock_agent_config.MAX_CONCURRENT_TOOLS = 5
        mock_agent_config.TOOL_TIMEOUT = 60
        mock_agent_config.ENABLE_LLM_PLANNING = True
        mock_agent_config.DEFAULT_SCAN_TASKS = []
        mock_agent_config.ENABLE_MEMORY = True
        mock_agent_config.ENABLE_KB_INTEGRATION = True

        response = client.post("/api/ai_agents/config")
        data = response.json()["data"]

        expected_fields = [
            "max_execution_time", "max_retries", "max_concurrent_tools",
            "tool_timeout", "enable_llm_planning", "default_scan_tasks",
            "enable_memory", "enable_kb_integration"
        ]
        for field in expected_fields:
            assert field in data, f"Missing field: {field}"


class TestGetWorkflowMetrics:

    def test_get_workflow_metrics_success(self, mock_workflow_optimizer):
        app = _create_test_app()
        client = TestClient(app)

        mock_optimizer = Mock()
        mock_optimizer.get_execution_summary = Mock(return_value={
            "total_nodes": 5,
            "successful_nodes": 4,
            "failed_nodes": 1,
            "avg_duration": 12.5
        })
        mock_metric = Mock()
        mock_metric.node_name = "portscan"
        mock_metric.task_id = "1"
        mock_metric.duration = 10.5
        mock_metric.success = True
        mock_metric.retries = 0
        mock_metric.skipped = False
        mock_metric.error = None
        mock_metric.timestamp = "2024-01-01T00:00:00Z"
        mock_optimizer.get_execution_metrics = Mock(return_value=[mock_metric])
        mock_workflow_optimizer.return_value = mock_optimizer

        response = client.get("/api/ai_agents/workflow/metrics")

        assert response.status_code == 200
        data = response.json()
        assert data["code"] == 200
        assert "summary" in data["data"]
        assert "metrics" in data["data"]

    def test_get_workflow_metrics_with_task_id(self, mock_workflow_optimizer):
        app = _create_test_app()
        client = TestClient(app)

        mock_optimizer = Mock()
        mock_optimizer.get_execution_summary = Mock(return_value={})
        mock_optimizer.get_execution_metrics = Mock(return_value=[])
        mock_workflow_optimizer.return_value = mock_optimizer

        response = client.get("/api/ai_agents/workflow/metrics?task_id=1")

        assert response.status_code == 200
        mock_optimizer.get_execution_summary.assert_called_once_with("1")
        mock_optimizer.get_execution_metrics.assert_called_once_with("1")

    def test_get_workflow_metrics_internal_error(self, mock_workflow_optimizer):
        app = _create_test_app()
        client = TestClient(app)

        mock_workflow_optimizer.side_effect = Exception("Optimizer error")

        response = client.get("/api/ai_agents/workflow/metrics")

        assert response.status_code == 500


class TestGetEnvironmentInfo:

    def test_get_environment_info_success(self):
        app = _create_test_app()
        client = TestClient(app)

        response = client.get("/api/ai_agents/environment/info")

        assert response.status_code == 200
        data = response.json()
        assert data["code"] == 200
        assert "python_version" in data["data"]
        assert "platform" in data["data"]
        assert "ai_agents_version" in data["data"]

    def test_get_environment_info_response_format(self):
        app = _create_test_app()
        client = TestClient(app)

        response = client.get("/api/ai_agents/environment/info")
        data = response.json()

        assert "code" in data
        assert "message" in data
        assert "data" in data
        assert isinstance(data["data"]["python_version"], str)
        assert isinstance(data["data"]["platform"], str)


class TestListCapabilities:

    def test_list_capabilities_success(self):
        app = _create_test_app()
        client = TestClient(app)

        response = client.get("/api/ai_agents/capabilities/list")

        assert response.status_code == 200
        data = response.json()
        assert data["code"] == 200
        assert "capabilities" in data["data"]

    def test_list_capabilities_response_format(self):
        app = _create_test_app()
        client = TestClient(app)

        response = client.get("/api/ai_agents/capabilities/list")
        data = response.json()

        assert "code" in data
        assert "message" in data
        assert "data" in data


class TestAPIResponseModelCompliance:

    @patch("backend.ai_agents.api.routes.agent_config")
    def test_config_get_apiresponse_format(self, mock_agent_config):
        app = _create_test_app()
        client = TestClient(app)

        mock_agent_config.MAX_EXECUTION_TIME = 18000
        mock_agent_config.MAX_RETRIES = 3
        mock_agent_config.MAX_CONCURRENT_TOOLS = 5
        mock_agent_config.TOOL_TIMEOUT = 60
        mock_agent_config.ENABLE_LLM_PLANNING = True
        mock_agent_config.DEFAULT_SCAN_TASKS = []
        mock_agent_config.ENABLE_MEMORY = True
        mock_agent_config.ENABLE_KB_INTEGRATION = True

        response = client.get("/api/ai_agents/config")
        data = response.json()

        assert set(data.keys()) == {"code", "message", "data"}
        assert isinstance(data["code"], int)
        assert isinstance(data["message"], str)

    def test_tools_apiresponse_format(self, mock_registry):
        app = _create_test_app()
        client = TestClient(app)

        mock_registry.list_tools = Mock(return_value=[])

        response = client.get("/api/ai_agents/tools")
        data = response.json()

        assert set(data.keys()) == {"code", "message", "data"}

    def test_environment_info_apiresponse_format(self):
        app = _create_test_app()
        client = TestClient(app)

        response = client.get("/api/ai_agents/environment/info")
        data = response.json()

        assert set(data.keys()) == {"code", "message", "data"}

    def test_capabilities_list_apiresponse_format(self):
        app = _create_test_app()
        client = TestClient(app)

        response = client.get("/api/ai_agents/capabilities/list")
        data = response.json()

        assert set(data.keys()) == {"code", "message", "data"}

    @patch("backend.ai_agents.api.routes.Task")
    def test_task_detail_apiresponse_format(self, mock_task_model, mock_task):
        app = _create_test_app()
        client = TestClient(app)

        mock_task_model.get_or_none = AsyncMock(return_value=mock_task)

        response = client.get("/api/ai_agents/tasks/1")
        data = response.json()

        assert set(data.keys()) == {"code", "message", "data"}


class TestFrontendAPIEndpointAvailability:

    def test_scan_endpoint_exists(self):
        app = _create_test_app()
        client = TestClient(app)

        with patch("backend.ai_agents.api.routes.task_executor"), \
             patch("backend.ai_agents.api.routes.Task") as mock_task_model, \
             patch("backend.ai_agents.api.routes.agent_config"):
            mock_task_obj = Mock()
            mock_task_obj.id = 1
            mock_task_model.create = AsyncMock(return_value=mock_task_obj)
            response = client.post("/api/ai_agents/scan", json={"target": "http://test.com"})
            assert response.status_code != 404

    @patch("backend.ai_agents.api.routes.Task")
    def test_get_task_endpoint_exists(self, mock_task_model):
        app = _create_test_app()
        client = TestClient(app)

        mock_task_model.get_or_none = AsyncMock(return_value=None)
        response = client.get("/api/ai_agents/tasks/1")
        assert response.status_code in (200, 404)

    @patch("backend.ai_agents.api.routes.Task")
    def test_list_tasks_endpoint_exists(self, mock_task_model):
        app = _create_test_app()
        client = TestClient(app)

        mock_query = _AwaitableQuery(items=[])
        mock_task_model.filter = Mock(return_value=mock_query)

        response = client.get("/api/ai_agents/tasks")
        assert response.status_code != 404

    def test_tools_endpoint_exists(self, mock_registry):
        app = _create_test_app()
        client = TestClient(app)

        mock_registry.list_tools = Mock(return_value=[])
        response = client.get("/api/ai_agents/tools")
        assert response.status_code != 404

    @patch("backend.ai_agents.api.routes.agent_config")
    def test_config_get_endpoint_exists(self, mock_agent_config):
        app = _create_test_app()
        client = TestClient(app)

        mock_agent_config.MAX_EXECUTION_TIME = 18000
        mock_agent_config.MAX_RETRIES = 3
        mock_agent_config.MAX_CONCURRENT_TOOLS = 5
        mock_agent_config.TOOL_TIMEOUT = 60
        mock_agent_config.ENABLE_LLM_PLANNING = True
        mock_agent_config.DEFAULT_SCAN_TASKS = []
        mock_agent_config.ENABLE_MEMORY = True
        mock_agent_config.ENABLE_KB_INTEGRATION = True

        response = client.get("/api/ai_agents/config")
        assert response.status_code != 404

    @patch("backend.ai_agents.api.routes.agent_config")
    def test_config_post_endpoint_exists(self, mock_agent_config):
        app = _create_test_app()
        client = TestClient(app)

        mock_agent_config.MAX_EXECUTION_TIME = 18000
        mock_agent_config.MAX_RETRIES = 3
        mock_agent_config.MAX_CONCURRENT_TOOLS = 5
        mock_agent_config.TOOL_TIMEOUT = 60
        mock_agent_config.ENABLE_LLM_PLANNING = True
        mock_agent_config.DEFAULT_SCAN_TASKS = []
        mock_agent_config.ENABLE_MEMORY = True
        mock_agent_config.ENABLE_KB_INTEGRATION = True

        response = client.post("/api/ai_agents/config")
        assert response.status_code != 404

    def test_environment_info_endpoint_exists(self):
        app = _create_test_app()
        client = TestClient(app)

        response = client.get("/api/ai_agents/environment/info")
        assert response.status_code != 404

    def test_capabilities_list_endpoint_exists(self):
        app = _create_test_app()
        client = TestClient(app)

        response = client.get("/api/ai_agents/capabilities/list")
        assert response.status_code != 404

    def test_workflow_metrics_endpoint_exists(self, mock_workflow_optimizer):
        app = _create_test_app()
        client = TestClient(app)

        mock_optimizer = Mock()
        mock_optimizer.get_execution_summary = Mock(return_value={})
        mock_optimizer.get_execution_metrics = Mock(return_value=[])
        mock_workflow_optimizer.return_value = mock_optimizer

        response = client.get("/api/ai_agents/workflow/metrics")
        assert response.status_code != 404

    @patch("backend.ai_agents.api.routes.task_executor")
    @patch("backend.ai_agents.api.routes.Task")
    def test_cancel_task_endpoint_exists(self, mock_task_model, mock_executor, mock_task):
        app = _create_test_app()
        client = TestClient(app)

        mock_task_model.get_or_none = AsyncMock(return_value=mock_task)
        mock_executor.cancel_task = AsyncMock()
        mock_task.save = AsyncMock()

        response = client.post("/api/ai_agents/tasks/1/cancel")
        assert response.status_code != 404
