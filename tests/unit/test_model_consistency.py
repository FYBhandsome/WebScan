"""
数据库模型一致性测试
验证模型定义、数据库表结构、API返回字段三者一致性
"""
import pytest
import sqlite3
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))


class TestDatabaseSchema:
    """数据库 Schema 一致性测试"""

    @pytest.fixture(autouse=True)
    def setup_db(self):
        db_path = os.path.join(os.path.dirname(__file__), "../../data/webscan.db")
        if not os.path.exists(db_path):
            pytest.skip("Database file not found")
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)

    def teardown_method(self):
        if hasattr(self, 'conn'):
            self.conn.close()

    def _get_columns(self, table: str) -> list:
        cursor = self.conn.cursor()
        cursor.execute(f"PRAGMA table_info({table})")
        return [c[1] for c in cursor.fetchall()]

    def _get_tables(self) -> list:
        cursor = self.conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        return [t[0] for t in cursor.fetchall()]

    def test_core_tables_exist(self):
        """验证核心表存在"""
        required = [
            "tasks", "vulnerabilities", "reports",
            "system_settings", "users", "notifications",
            "ai_chat_instances", "ai_chat_messages",
            "vulnerability_kb"
        ]
        existing = self._get_tables()
        for table in required:
            assert table in existing, f"Missing table: {table}"

    def test_task_table_columns(self):
        """验证 tasks 表结构"""
        cols = self._get_columns("tasks")
        required = ["id", "task_name", "task_type", "target", "status",
                     "progress", "config", "result", "error_message",
                     "created_at", "updated_at"]
        for col in required:
            assert col in cols, f"Tasks missing column: {col}"

    def test_vulnerability_table_columns(self):
        """验证 vulnerabilities 表结构"""
        cols = self._get_columns("vulnerabilities")
        required = ["id", "title", "vuln_type", "severity", "url",
                     "description", "payload", "evidence", "remediation",
                     "ai_analysis", "risk_score", "fix_priority",
                     "cvss_score", "affected_product", "status",
                     "source_id", "source", "task_id",
                     "created_at", "updated_at"]
        for col in required:
            assert col in cols, f"Vulnerabilities missing column: {col}"

    def test_report_table_columns(self):
        """验证 reports 表结构"""
        cols = self._get_columns("reports")
        required = ["id", "report_name", "report_type", "content",
                     "file_path", "ai_analysis", "analyzed_at",
                     "analysis_model", "task_id",
                     "created_at", "updated_at"]
        for col in required:
            assert col in cols, f"Reports missing column: {col}"

    def test_system_settings_table_columns(self):
        """验证 system_settings 表结构"""
        cols = self._get_columns("system_settings")
        required = ["id", "category", "key", "value", "value_type",
                     "description", "is_public", "created_at", "updated_at"]
        for col in required:
            assert col in cols, f"System_settings missing column: {col}"

    def test_workflow_executions_columns(self):
        """验证 workflow_executions 表结构"""
        cols = self._get_columns("workflow_executions")
        required = ["id", "task_id", "workflow_name", "target", "status",
                     "progress", "start_time", "end_time",
                     "current_step", "total_steps", "completed_steps",
                     "graph_flow", "vulnerabilities", "tool_results",
                     "metadata", "error_message", "created_at", "updated_at"]
        for col in required:
            assert col in cols, f"Workflow_executions missing column: {col}"

    def test_poc_verification_results_columns(self):
        """验证 POC 验证结果表结构"""
        cols = self._get_columns("poc_verification_results")
        required = ["id", "poc_name", "poc_id", "target", "vulnerable",
                     "message", "output", "error", "execution_time",
                     "confidence", "severity", "cvss_score",
                     "analysis", "verification_task_id", "created_at"]
        for col in required:
            assert col in cols, f"POC verification results missing column: {col}"


class TestAPIModelMapping:
    """API 返回字段与模型字段映射测试"""

    def test_model_to_dict_mapping_vulnerability(self):
        """验证 Vulnerability 模型字段到 API 响应的映射"""
        import requests
        r = requests.get("http://127.0.0.1:8888/api/vulnerabilities/1", timeout=30)
        if r.status_code != 200:
            pytest.skip("Cannot get vulnerability data")
        data = r.json()["data"]

        expected_fields = {
            "id": int, "title": str, "type": str, "severity": str,
            "status": str, "url": str, "description": str,
            "payload": (str, type(None)),
            "evidence": (str, type(None)),
            "remediation": (str, type(None)),
            "source": str, "task_id": (int, type(None)),
            "risk_score": (int, float, type(None)),
            "fix_priority": (int, type(None)),
            "cvss_score": (int, float, type(None)),
            "affected_product": (str, type(None)),
        }

        for field, expected_type in expected_fields.items():
            assert field in data, f"Missing API field: {field}"
            assert isinstance(data[field], expected_type), \
                f"Field {field}: expected {expected_type}, got {type(data[field])}"

    def test_model_to_dict_mapping_task(self):
        """验证 Task 模型字段到 API 响应的映射"""
        import requests
        r = requests.get("http://127.0.0.1:8888/api/tasks/1", timeout=30)
        if r.status_code != 200:
            pytest.skip("Cannot get task data")
        data = r.json()["data"]

        expected_fields = ["id", "task_name", "task_type", "target",
                           "status", "progress", "config", "result",
                           "created_at", "updated_at"]
        for field in expected_fields:
            assert field in data, f"Missing API field: {field}"

    def test_model_to_dict_mapping_report(self):
        """验证 Report 模型字段到 API 响应的映射"""
        import requests
        r = requests.get("http://127.0.0.1:8888/api/reports/", timeout=30)
        if r.status_code != 200:
            pytest.skip("Cannot get reports data")
        data = r.json()["data"]
        if data.get("reports"):
            report = data["reports"][0]
            expected_fields = ["id", "task_id", "task_name", "report_name",
                               "report_type", "size", "created_at", "updated_at"]
            for field in expected_fields:
                assert field in report, f"Missing API field: {field}"


class TestFrontendFieldMapping:
    """前端请求参数与后端模型字段映射测试"""

    def test_create_task_params_match(self):
        """验证前端 createTask 参数与后端 CreateTaskRequest 一致"""
        from backend.api.tasks import CreateTaskRequest

        fields = CreateTaskRequest.model_fields
        expected = {"task_name", "target", "task_type", "config"}
        actual = set(fields.keys())
        assert expected == actual, f"Task params mismatch: expected {expected}, got {actual}"

    def test_create_report_params_match(self):
        """验证前端 createReport 参数与后端 ReportCreate 一致"""
        from backend.api.reports import ReportCreate

        fields = ReportCreate.model_fields
        required = {"task_id", "name", "format", "include_ai_analysis",
                     "include_summary", "include_vulnerabilities",
                     "include_recommendations", "include_charts",
                     "include_appendix"}
        actual = set(fields.keys())
        assert required == actual, f"Report params mismatch: expected {required}, got {actual}"

    def test_agent_scan_params_match(self):
        """验证前端 startScan 参数与后端 AgentScanRequest 一致"""
        from backend.ai_agents.api.routes import AgentScanRequest

        fields = AgentScanRequest.model_fields
        actual = set(fields.keys())
        required_keys = {"target", "strategy", "concurrency", "timeout",
                         "enable_llm_planning", "need_custom_scan",
                         "selected_tools"}
        for key in required_keys:
            assert key in actual, f"AgentScan params mismatch: missing {key}"

    def test_api_key_create_params_match(self):
        """验证前端 API Key 创建参数与后端 ApiKeyCreate 一致"""
        from backend.api.settings import ApiKeyCreate

        fields = ApiKeyCreate.model_fields
        expected = {"name"}
        actual = set(fields.keys())
        assert expected == actual, f"API key params mismatch: expected {expected}, got {actual}"


class TestModelFieldNameConsistency:
    """模型字段命名一致性测试"""

    def test_severity_naming_consistency(self):
        """验证 severity 字段命名一致性"""
        from backend.models import Vulnerability, VulnerabilityKB

        v_fields = set(Vulnerability._meta.fields_map.keys())
        k_fields = set(VulnerabilityKB._meta.fields_map.keys())

        assert "severity" in v_fields, "Vulnerability missing severity"
        assert "severity" in k_fields, "VulnerabilityKB missing severity"

    def test_created_at_consistency(self):
        """验证 created_at 字段一致性"""
        from backend.models import Task, Report, Vulnerability, VulnerabilityKB

        for model in [Task, Report, Vulnerability, VulnerabilityKB]:
            fields = set(model._meta.fields_map.keys())
            assert "created_at" in fields, f"{model.__name__} missing created_at"

    def test_foreign_key_naming(self):
        """验证外键命名一致性"""
        from backend.models import Vulnerability, Report, Task
        v_fields = set(Vulnerability._meta.fields_map.keys())
        r_fields = set(Report._meta.fields_map.keys())

        assert "task_id" in v_fields or "task" in v_fields, \
            "Vulnerability missing task foreign key"
        assert "task_id" in r_fields or "task" in r_fields, \
            "Report missing task foreign key"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])