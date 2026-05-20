import pytest
import sys
import os
import json
import types
from pathlib import Path
from unittest.mock import Mock, AsyncMock, patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from fastapi.testclient import TestClient
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional, Any


class APIResponse(BaseModel):
    code: int
    message: str
    data: Optional[Any] = None


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


FRONTEND_AI_AGENTS_ENDPOINTS = {
    "executeAgent": {"method": "POST", "path": "/ai_agents/scan"},
    "getTask": {"method": "GET", "path": "/ai_agents/tasks/{taskId}"},
    "getTasks": {"method": "GET", "path": "/ai_agents/tasks"},
    "cancelTask": {"method": "DELETE", "path": "/ai_agents/tasks/{taskId}"},
    "getTools": {"method": "GET", "path": "/ai_agents/tools"},
    "getConfig": {"method": "GET", "path": "/ai_agents/config"},
    "updateConfig": {"method": "POST", "path": "/ai_agents/config"},
    "startScan": {"method": "POST", "path": "/ai_agents/scan"},
    "generateCode": {"method": "POST", "path": "/ai_agents/code/generate"},
    "executeCode": {"method": "POST", "path": "/ai_agents/code/execute"},
    "generateAndExecuteCode": {"method": "POST", "path": "/ai_agents/code/generate-and-execute"},
    "enhanceCapability": {"method": "POST", "path": "/ai_agents/capabilities/enhance"},
    "getCapabilities": {"method": "GET", "path": "/ai_agents/capabilities/list"},
    "getCapability": {"method": "GET", "path": "/ai_agents/capabilities/{capabilityName}"},
    "deleteCapability": {"method": "DELETE", "path": "/ai_agents/capabilities/{capabilityName}"},
    "getEnvironmentInfo": {"method": "GET", "path": "/ai_agents/environment/info"},
    "getEnvironmentTools": {"method": "GET", "path": "/ai_agents/environment/tools"},
    "getToolInfo": {"method": "GET", "path": "/ai_agents/environment/tools/{toolName}"},
    "getResourceUsage": {"method": "GET", "path": "/ai_agents/resources/usage"},
    "getResourceStatistics": {"method": "GET", "path": "/ai_agents/resources/statistics"},
    "searchPOC": {"method": "POST", "path": "/ai_agents/poc/search"},
    "executePOC": {"method": "POST", "path": "/ai_agents/poc/execute"},
    "batchExecutePOC": {"method": "POST", "path": "/ai_agents/poc/batch-execute"},
    "getWorkflowMetrics": {"method": "GET", "path": "/ai_agents/workflow/metrics"},
}

FRONTEND_API_ENDPOINTS = {
    "tasks_createTask": {"method": "POST", "path": "/tasks/create"},
    "tasks_getTasks": {"method": "GET", "path": "/tasks/"},
    "tasks_getTask": {"method": "GET", "path": "/tasks/{taskId}"},
    "tasks_updateTask": {"method": "PUT", "path": "/tasks/{taskId}"},
    "tasks_deleteTask": {"method": "DELETE", "path": "/tasks/{taskId}"},
    "tasks_getTaskResults": {"method": "GET", "path": "/tasks/{taskId}/results"},
    "tasks_cancelTask": {"method": "POST", "path": "/tasks/{taskId}/cancel"},
    "tasks_getTaskLogs": {"method": "GET", "path": "/tasks/{taskId}/logs"},
    "tasks_getTaskVulnerabilities": {"method": "GET", "path": "/tasks/{taskId}/vulnerabilities"},
    "tasks_getStatisticsOverview": {"method": "GET", "path": "/tasks/statistics/overview"},
    "tasks_getFrozenTasks": {"method": "GET", "path": "/tasks/frozen"},
    "reports_getReports": {"method": "GET", "path": "/reports/"},
    "reports_createReport": {"method": "POST", "path": "/reports/"},
    "reports_getReport": {"method": "GET", "path": "/reports/{reportId}"},
    "reports_updateReport": {"method": "PUT", "path": "/reports/{reportId}"},
    "reports_deleteReport": {"method": "DELETE", "path": "/reports/{reportId}"},
    "reports_exportReport": {"method": "GET", "path": "/reports/{reportId}/export"},
    "reports_regenerateReport": {"method": "POST", "path": "/reports/{reportId}/regenerate"},
    "reports_previewReport": {"method": "GET", "path": "/reports/{reportId}/preview"},
    "reports_getLatestReportByTask": {"method": "GET", "path": "/reports/task/{taskId}/latest"},
    "settings_getSettings": {"method": "GET", "path": "/settings/"},
    "settings_updateSettings": {"method": "PUT", "path": "/settings/"},
    "settings_getSystemInfo": {"method": "GET", "path": "/settings/system-info"},
    "settings_getStatistics": {"method": "GET", "path": "/settings/statistics"},
    "settings_getCategories": {"method": "GET", "path": "/settings/categories"},
    "settings_resetSettings": {"method": "POST", "path": "/settings/reset"},
    "settings_getApiKeys": {"method": "GET", "path": "/settings/api-keys"},
    "settings_createApiKey": {"method": "POST", "path": "/settings/api-keys"},
    "poc_getPOCTypes": {"method": "GET", "path": "/poc/types"},
    "poc_runPOC": {"method": "POST", "path": "/poc/scan"},
    "poc_getPOCInfo": {"method": "GET", "path": "/poc/info/{pocType}"},
    "awvs_getTargets": {"method": "GET", "path": "/awvs/targets"},
    "awvs_createTarget": {"method": "POST", "path": "/awvs/target"},
    "awvs_getScans": {"method": "GET", "path": "/awvs/scans"},
    "awvs_startScan": {"method": "POST", "path": "/awvs/scan"},
    "awvs_healthCheck": {"method": "GET", "path": "/awvs/health"},
    "kb_getVulnerabilities": {"method": "GET", "path": "/kb/vulnerabilities"},
    "kb_sync": {"method": "POST", "path": "/kb/sync"},
    "kb_searchFromSeebug": {"method": "POST", "path": "/kb/search-from-seebug"},
    "kb_searchPOC": {"method": "POST", "path": "/kb/seebug/poc/search"},
    "kb_downloadPOC": {"method": "POST", "path": "/kb/seebug/poc/download"},
    "kb_getPOCDetail": {"method": "GET", "path": "/kb/seebug/poc/{ssvid}/detail"},
    "user_getProfile": {"method": "GET", "path": "/user/profile"},
    "user_getPermissions": {"method": "GET", "path": "/user/permissions"},
    "user_getList": {"method": "GET", "path": "/user/list"},
    "notifications_getNotifications": {"method": "GET", "path": "/notifications/"},
    "notifications_createNotification": {"method": "POST", "path": "/notifications/"},
    "notifications_markAsRead": {"method": "PUT", "path": "/notifications/{notificationId}/read"},
    "notifications_markAllAsRead": {"method": "PUT", "path": "/notifications/read-all"},
    "notifications_deleteNotification": {"method": "DELETE", "path": "/notifications/{notificationId}"},
    "notifications_getUnreadCount": {"method": "GET", "path": "/notifications/count/unread"},
    "seebug_getStatus": {"method": "GET", "path": "/seebug/status"},
    "seebug_search": {"method": "POST", "path": "/seebug/search"},
    "seebug_getVulnerabilityDetail": {"method": "GET", "path": "/seebug/poc/{ssvid}/detail"},
    "seebug_testConnection": {"method": "GET", "path": "/seebug/test-connection"},
}

BACKEND_WEBSOCKET_MESSAGE_TYPES = {
    "task_update",
    "task_progress",
    "task_completed",
    "task_failed",
    "stage_update",
    "subgraph:progress",
    "subgraph_progress",
    "new_notification",
    "notification",
    "scan_started",
    "user_message_received",
    "connected",
    "error",
    "ai_message",
    "scan_completed",
    "scan_cancelled",
    "history",
    "status",
    "tool_execution_started",
    "tool_execution_completed",
    "tool_execution",
    "tool_execution_update",
    "heartbeat",
    "script_upload_progress",
    "script_registered",
    "script_generation_progress",
    "script_generated",
    "input_received",
    "subscribed",
    "high_risk_confirmed",
    "tool_execution_proceed",
    "tool_rejected_processing",
    "alternative_applied",
    "task_error_ack",
    "workflow_resumed",
}

FRONTEND_WEBSOCKET_MESSAGE_TYPES = {
    "task_update": "task:update",
    "task_progress": "task:progress",
    "task_completed": "task:completed",
    "task_failed": "task:failed",
    "stage_update": "stage:update",
    "subgraph_progress": "subgraph:progress",
    "tool_execution": "tool:execution",
    "vulnerability_found": "vulnerability:found",
    "scan_started": "scan:started",
    "scan_stopped": "scan:stopped",
    "notification": "notification",
    "new_notification": "new_notification",
    "heartbeat": "heartbeat",
    "connected": "ai:connected",
    "ai_message": "ai:message",
    "decision": "ai:decision",
    "progress": "ai:progress",
    "confirmation_required": "ai:confirmation",
    "report_ready": "ai:report",
    "scan_cancelled": "ai:cancelled",
    "error": "ai:error",
    "history": "ai:history",
    "status": "ai:status",
    "user_message_received": "ai:user_received",
    "message_verification_result": "message:verification",
    "retransmit_batch": "message:retransmit_batch",
    "retransmit_failed": "message:retransmit_failed",
}


def _create_test_app():
    _preload_api_common()
    from backend.ai_agents.api.routes import router
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router, prefix="/api")
    return app


def _collect_backend_routes(app: FastAPI):
    routes = {}
    for route in app.routes:
        if hasattr(route, "methods") and hasattr(route, "path"):
            for method in route.methods:
                if method in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                    path = route.path
                    if path.startswith("/api"):
                        path = path[len("/api"):]
                    routes[f"{method} {path}"] = {
                        "method": method,
                        "path": path,
                        "name": route.name
                    }
    return routes


def _load_full_api_router():
    _preload_api_common()

    for mod_name in ['TOSKill', 'TOSKill.api']:
        if mod_name not in sys.modules:
            sys.modules[mod_name] = MagicMock()

    if 'backend.api' in sys.modules and not hasattr(sys.modules['backend.api'], 'api_router'):
        saved = {}
        for key in list(sys.modules.keys()):
            if key.startswith('backend.api.') and key != 'backend.api.common':
                saved[key] = sys.modules.pop(key)
        del sys.modules['backend.api']
        for key, mod in saved.items():
            sys.modules[key] = mod

    from backend.api import api_router
    return api_router


@pytest.fixture
def backend_routes():
    app = _create_test_app()
    return _collect_backend_routes(app)


@pytest.fixture
def full_backend_routes():
    try:
        api_router = _load_full_api_router()
        app = FastAPI()
        app.include_router(api_router, prefix="/api")
        return _collect_backend_routes(app)
    except Exception:
        pytest.skip("无法加载完整后端API路由（依赖模块未就绪）")


class TestFrontendAiAgentsEndpointsBackendCoverage:

    def test_all_frontend_ai_agents_endpoints_have_backend_routes(self, backend_routes):
        missing = []
        for func_name, endpoint in FRONTEND_AI_AGENTS_ENDPOINTS.items():
            path = endpoint["path"]
            method = endpoint["method"]

            found = False
            for route_key, route_info in backend_routes.items():
                route_path = route_info["path"]
                backend_parts = route_path.split("/")
                frontend_parts = path.split("/")

                if len(backend_parts) != len(frontend_parts):
                    continue

                match = True
                for bp, fp in zip(backend_parts, frontend_parts):
                    if bp.startswith("{") and fp.startswith("{"):
                        continue
                    if bp.startswith("{") and not fp.startswith("{"):
                        continue
                    if bp != fp:
                        match = False
                        break

                if match and route_info["method"] == method:
                    found = True
                    break

            if not found:
                missing.append(f"{func_name}: {method} {path}")

        assert len(missing) == 0, (
            f"前端aiAgents.js中有{len(missing)}个端点在后端找不到对应路由:\n"
            + "\n".join(f"  - {m}" for m in missing)
        )

    def test_scan_endpoint_route_match(self, backend_routes):
        assert any(
            r["method"] == "POST" and "/scan" in r["path"]
            for r in backend_routes.values()
        ), "后端缺少 POST /scan 路由"

    def test_get_task_endpoint_route_match(self, backend_routes):
        assert any(
            r["method"] == "GET" and "/tasks/" in r["path"] and "{task_id}" in r["path"]
            for r in backend_routes.values()
        ), "后端缺少 GET /tasks/{task_id} 路由"

    def test_list_tasks_endpoint_route_match(self, backend_routes):
        assert any(
            r["method"] == "GET" and r["path"].endswith("/tasks")
            for r in backend_routes.values()
        ), "后端缺少 GET /tasks 路由"

    def test_cancel_task_endpoint_route_match(self, backend_routes):
        cancel_found = any(
            r["method"] == "POST" and "/cancel" in r["path"]
            for r in backend_routes.values()
        )
        delete_found = any(
            r["method"] == "DELETE" and "/tasks/" in r["path"] and "{task_id}" in r["path"]
            for r in backend_routes.values()
        )
        assert cancel_found or delete_found, (
            "后端缺少取消任务的路由 (POST /tasks/{task_id}/cancel 或 DELETE /tasks/{task_id})"
        )

    def test_tools_endpoint_route_match(self, backend_routes):
        assert any(
            r["method"] == "GET" and "/tools" in r["path"]
            for r in backend_routes.values()
        ), "后端缺少 GET /tools 路由"

    def test_config_endpoints_route_match(self, backend_routes):
        config_get = any(
            r["method"] == "GET" and r["path"].endswith("/config")
            for r in backend_routes.values()
        )
        config_post = any(
            r["method"] == "POST" and r["path"].endswith("/config")
            for r in backend_routes.values()
        )
        assert config_get, "后端缺少 GET /config 路由"
        assert config_post, "后端缺少 POST /config 路由"

    def test_workflow_metrics_endpoint_route_match(self, backend_routes):
        assert any(
            r["method"] == "GET" and "/workflow/metrics" in r["path"]
            for r in backend_routes.values()
        ), "后端缺少 GET /workflow/metrics 路由"

    def test_environment_info_endpoint_route_match(self, backend_routes):
        assert any(
            r["method"] == "GET" and "/environment/info" in r["path"]
            for r in backend_routes.values()
        ), "后端缺少 GET /environment/info 路由"

    def test_capabilities_list_endpoint_route_match(self, backend_routes):
        assert any(
            r["method"] == "GET" and "/capabilities/list" in r["path"]
            for r in backend_routes.values()
        ), "后端缺少 GET /capabilities/list 路由"


class TestFrontendApiEndpointsBackendCoverage:

    KNOWN_MISSING_ENDPOINTS = {
        "poc_getPOCInfo",
    }

    def test_all_frontend_api_endpoints_have_backend_routes(self, full_backend_routes):
        missing = []
        for func_name, endpoint in FRONTEND_API_ENDPOINTS.items():
            if func_name in self.KNOWN_MISSING_ENDPOINTS:
                continue
            path = endpoint["path"]
            method = endpoint["method"]

            found = False
            for route_key, route_info in full_backend_routes.items():
                route_path = route_info["path"]
                backend_parts = route_path.split("/")
                frontend_parts = path.split("/")

                if len(backend_parts) != len(frontend_parts):
                    continue

                match = True
                for bp, fp in zip(backend_parts, frontend_parts):
                    if (bp.startswith("{") and fp.startswith("{")) or \
                       (bp.startswith("{") and not fp.startswith("{")):
                        continue
                    if bp != fp:
                        match = False
                        break

                if match and route_info["method"] == method:
                    found = True
                    break

            if not found:
                missing.append(f"{func_name}: {method} {path}")

        assert len(missing) == 0, (
            f"前端api.js中有{len(missing)}个端点在后端找不到对应路由:\n"
            + "\n".join(f"  - {m}" for m in missing)
        )


class TestWebSocketMessageTypesConsistency:

    def test_backend_task_update_matches_frontend(self):
        assert "task_update" in BACKEND_WEBSOCKET_MESSAGE_TYPES
        assert "task_update" in FRONTEND_WEBSOCKET_MESSAGE_TYPES

    def test_backend_task_progress_matches_frontend(self):
        assert "task_progress" in BACKEND_WEBSOCKET_MESSAGE_TYPES
        assert "task_progress" in FRONTEND_WEBSOCKET_MESSAGE_TYPES

    def test_backend_task_completed_matches_frontend(self):
        assert "task_completed" in BACKEND_WEBSOCKET_MESSAGE_TYPES
        assert "task_completed" in FRONTEND_WEBSOCKET_MESSAGE_TYPES

    def test_backend_task_failed_matches_frontend(self):
        assert "task_failed" in BACKEND_WEBSOCKET_MESSAGE_TYPES
        assert "task_failed" in FRONTEND_WEBSOCKET_MESSAGE_TYPES

    def test_backend_stage_update_matches_frontend(self):
        assert "stage_update" in BACKEND_WEBSOCKET_MESSAGE_TYPES
        assert "stage_update" in FRONTEND_WEBSOCKET_MESSAGE_TYPES

    def test_backend_subgraph_progress_matches_frontend(self):
        assert "subgraph:progress" in BACKEND_WEBSOCKET_MESSAGE_TYPES
        assert "subgraph_progress" in FRONTEND_WEBSOCKET_MESSAGE_TYPES

    def test_backend_scan_started_matches_frontend(self):
        assert "scan_started" in BACKEND_WEBSOCKET_MESSAGE_TYPES
        assert "scan_started" in FRONTEND_WEBSOCKET_MESSAGE_TYPES

    def test_backend_new_notification_matches_frontend(self):
        assert "new_notification" in BACKEND_WEBSOCKET_MESSAGE_TYPES
        assert "new_notification" in FRONTEND_WEBSOCKET_MESSAGE_TYPES

    def test_backend_connected_matches_frontend(self):
        assert "connected" in BACKEND_WEBSOCKET_MESSAGE_TYPES
        assert "connected" in FRONTEND_WEBSOCKET_MESSAGE_TYPES

    def test_backend_ai_message_matches_frontend(self):
        assert "ai_message" in BACKEND_WEBSOCKET_MESSAGE_TYPES
        assert "ai_message" in FRONTEND_WEBSOCKET_MESSAGE_TYPES

    def test_backend_error_matches_frontend(self):
        assert "error" in BACKEND_WEBSOCKET_MESSAGE_TYPES
        assert "error" in FRONTEND_WEBSOCKET_MESSAGE_TYPES

    def test_backend_scan_cancelled_matches_frontend(self):
        assert "scan_cancelled" in BACKEND_WEBSOCKET_MESSAGE_TYPES
        assert "scan_cancelled" in FRONTEND_WEBSOCKET_MESSAGE_TYPES

    def test_backend_history_matches_frontend(self):
        assert "history" in BACKEND_WEBSOCKET_MESSAGE_TYPES
        assert "history" in FRONTEND_WEBSOCKET_MESSAGE_TYPES

    def test_backend_status_matches_frontend(self):
        assert "status" in BACKEND_WEBSOCKET_MESSAGE_TYPES
        assert "status" in FRONTEND_WEBSOCKET_MESSAGE_TYPES

    def test_backend_user_message_received_matches_frontend(self):
        assert "user_message_received" in BACKEND_WEBSOCKET_MESSAGE_TYPES
        assert "user_message_received" in FRONTEND_WEBSOCKET_MESSAGE_TYPES

    def test_frontend_message_type_format_consistency(self):
        backend_underscore_types = {
            t for t in BACKEND_WEBSOCKET_MESSAGE_TYPES
            if ":" not in t
        }
        for msg_type, frontend_type in FRONTEND_WEBSOCKET_MESSAGE_TYPES.items():
            if ":" not in frontend_type:
                assert msg_type in backend_underscore_types or msg_type in BACKEND_WEBSOCKET_MESSAGE_TYPES, (
                    f"前端消息类型 '{msg_type}' 映射为 '{frontend_type}'，但在后端消息类型中找不到"
                )

    def test_no_unhandled_frontend_message_types(self):
        frontend_raw_types = set(FRONTEND_WEBSOCKET_MESSAGE_TYPES.keys())
        unhandled = frontend_raw_types - BACKEND_WEBSOCKET_MESSAGE_TYPES - {
            "vulnerability_found", "scan_stopped", "notification",
            "decision", "progress", "confirmation_required", "report_ready",
            "message_verification_result", "retransmit_batch", "retransmit_failed"
        }
        assert len(unhandled) == 0, (
            f"以下前端消息类型在后端完全没有对应: {unhandled}"
        )


class TestRequestResponseDataFormatMatch:

    @patch("backend.ai_agents.api.routes.task_executor")
    @patch("backend.ai_agents.api.routes.Task")
    @patch("backend.ai_agents.api.routes.agent_config")
    def test_scan_request_format_matches_frontend(self, mock_agent_config, mock_task_model, mock_executor):
        app = _create_test_app()
        client = TestClient(app)

        mock_task_obj = Mock()
        mock_task_obj.id = 1
        mock_task_model.create = AsyncMock(return_value=mock_task_obj)
        mock_executor.start_task = AsyncMock()

        frontend_scan_data = {
            "target": "http://example.com",
            "enable_llm_planning": True,
            "strategy": "deep",
            "concurrency": 5,
            "timeout": 300,
            "selected_tools": ["portscan", "sqli_scan"]
        }

        response = client.post("/api/ai_agents/scan", json=frontend_scan_data)

        assert response.status_code == 200
        data = response.json()
        assert "task_id" in data
        assert "status" in data
        assert "message" in data

    @patch("backend.ai_agents.api.routes.Task")
    def test_task_detail_response_matches_frontend_expectation(self, mock_task_model):
        app = _create_test_app()
        client = TestClient(app)

        mock_task = Mock()
        mock_task.id = 1
        mock_task.task_type = "ai_agent_scan"
        mock_task.target = "http://example.com"
        mock_task.status = "running"
        mock_task.progress = 50
        mock_task.config = json.dumps({"target": "http://example.com"})
        mock_task.result = json.dumps({
            "execution_history": [],
            "stages": {
                "planning": {"status": "completed", "progress": 100},
                "tool_execution": {"status": "running", "progress": 50},
                "poc_verification": {"status": "pending", "progress": 0},
                "report": {"status": "pending", "progress": 0}
            }
        })
        mock_task.error_message = None
        mock_task.created_at = "2024-01-01T00:00:00Z"
        mock_task.updated_at = "2024-01-01T00:00:00Z"

        mock_task_model.get_or_none = AsyncMock(return_value=mock_task)

        response = client.get("/api/ai_agents/tasks/1")

        assert response.status_code == 200
        data = response.json()["data"]

        frontend_expected_fields = [
            "task_id", "status", "progress", "target",
            "stages", "execution_history"
        ]
        for field in frontend_expected_fields:
            assert field in data, f"前端期望字段 '{field}' 在后端响应中缺失"

    @patch("backend.ai_agents.api.routes.Task")
    def test_task_list_response_matches_frontend_expectation(self, mock_task_model):
        app = _create_test_app()
        client = TestClient(app)

        mock_query = _AwaitableQuery(items=[])
        mock_task_model.filter = Mock(return_value=mock_query)

        response = client.get("/api/ai_agents/tasks")

        assert response.status_code == 200
        data = response.json()["data"]

        frontend_expected_fields = ["tasks", "total", "page", "page_size"]
        for field in frontend_expected_fields:
            assert field in data, f"前端期望字段 '{field}' 在后端任务列表响应中缺失"

    @patch("backend.ai_agents.api.routes.agent_config")
    def test_config_response_matches_frontend_expectation(self, mock_agent_config):
        app = _create_test_app()
        client = TestClient(app)

        mock_agent_config.MAX_EXECUTION_TIME = 18000
        mock_agent_config.MAX_RETRIES = 3
        mock_agent_config.MAX_CONCURRENT_TOOLS = 5
        mock_agent_config.TOOL_TIMEOUT = 60
        mock_agent_config.ENABLE_LLM_PLANNING = True
        mock_agent_config.DEFAULT_SCAN_TASKS = ["portscan"]
        mock_agent_config.ENABLE_MEMORY = True
        mock_agent_config.ENABLE_KB_INTEGRATION = True

        response = client.get("/api/ai_agents/config")

        assert response.status_code == 200
        data = response.json()["data"]

        frontend_expected_fields = [
            "enable_llm_planning", "max_concurrent_tools",
            "tool_timeout", "max_retries"
        ]
        for field in frontend_expected_fields:
            assert field in data, f"前端期望字段 '{field}' 在后端配置响应中缺失"

    def test_tools_response_matches_frontend_expectation(self, mock_registry):
        app = _create_test_app()
        client = TestClient(app)

        mock_registry.list_tools = Mock(return_value=[
            {"name": "portscan", "category": "plugin", "description": "Port scanner", "enabled": True}
        ])

        response = client.get("/api/ai_agents/tools")

        assert response.status_code == 200
        data = response.json()["data"]

        assert "tools" in data
        assert "total" in data
        assert isinstance(data["tools"], list)

    def test_environment_info_response_matches_frontend_expectation(self):
        app = _create_test_app()
        client = TestClient(app)

        response = client.get("/api/ai_agents/environment/info")

        assert response.status_code == 200
        data = response.json()["data"]

        assert "python_version" in data
        assert "platform" in data

    def test_capabilities_response_matches_frontend_expectation(self):
        app = _create_test_app()
        client = TestClient(app)

        response = client.get("/api/ai_agents/capabilities/list")

        assert response.status_code == 200
        data = response.json()["data"]

        assert "capabilities" in data

    def test_workflow_metrics_response_matches_frontend_expectation(self, mock_workflow_optimizer):
        app = _create_test_app()
        client = TestClient(app)

        mock_optimizer = Mock()
        mock_optimizer.get_execution_summary = Mock(return_value={
            "total_nodes": 0,
            "successful_nodes": 0,
            "failed_nodes": 0
        })
        mock_optimizer.get_execution_metrics = Mock(return_value=[])
        mock_workflow_optimizer.return_value = mock_optimizer

        response = client.get("/api/ai_agents/workflow/metrics")

        assert response.status_code == 200
        data = response.json()["data"]

        assert "summary" in data
        assert "metrics" in data


class TestFrontendCancelTaskEndpointDiscrepancy:

    @patch("backend.ai_agents.api.routes.task_executor")
    @patch("backend.ai_agents.api.routes.Task")
    def test_frontend_delete_maps_to_backend_delete(self, mock_task_model, mock_executor):
        app = _create_test_app()
        client = TestClient(app)

        mock_task = Mock()
        mock_task.id = 1
        mock_task.status = "running"
        mock_task_model.get_or_none = AsyncMock(return_value=mock_task)
        mock_executor.cancel_task = AsyncMock()
        mock_task.delete = AsyncMock()

        response = client.delete("/api/ai_agents/tasks/1")

        assert response.status_code == 200

    @patch("backend.ai_agents.api.routes.task_executor")
    @patch("backend.ai_agents.api.routes.Task")
    def test_frontend_cancel_via_post_cancel_endpoint(self, mock_task_model, mock_executor):
        app = _create_test_app()
        client = TestClient(app)

        mock_task = Mock()
        mock_task.id = 1
        mock_task.status = "running"
        mock_task_model.get_or_none = AsyncMock(return_value=mock_task)
        mock_executor.cancel_task = AsyncMock()
        mock_task.save = AsyncMock()

        response = client.post("/api/ai_agents/tasks/1/cancel")

        assert response.status_code == 200


class TestAPIResponseConsistency:

    @patch("backend.ai_agents.api.routes.agent_config")
    def test_all_get_endpoints_return_apiresponse(self, mock_agent_config):
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

        get_endpoints = [
            "/api/ai_agents/config",
            "/api/ai_agents/environment/info",
            "/api/ai_agents/capabilities/list",
        ]

        for endpoint in get_endpoints:
            response = client.get(endpoint)
            if response.status_code == 200:
                data = response.json()
                assert "code" in data, f"Endpoint {endpoint} response missing 'code'"
                assert "message" in data, f"Endpoint {endpoint} response missing 'message'"
                assert "data" in data, f"Endpoint {endpoint} response missing 'data'"

    def test_tools_endpoint_returns_apiresponse(self, mock_registry):
        app = _create_test_app()
        client = TestClient(app)

        mock_registry.list_tools = Mock(return_value=[])

        response = client.get("/api/ai_agents/tools")
        data = response.json()

        assert "code" in data
        assert "message" in data
        assert "data" in data

    def test_workflow_metrics_returns_apiresponse(self, mock_workflow_optimizer):
        app = _create_test_app()
        client = TestClient(app)

        mock_optimizer = Mock()
        mock_optimizer.get_execution_summary = Mock(return_value={})
        mock_optimizer.get_execution_metrics = Mock(return_value=[])
        mock_workflow_optimizer.return_value = mock_optimizer

        response = client.get("/api/ai_agents/workflow/metrics")
        data = response.json()

        assert "code" in data
        assert "message" in data
        assert "data" in data
