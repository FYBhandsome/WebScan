# -*- coding:utf-8 -*-
"""
TOSKill API 接口测试用例

测试所有 REST API 接口，包括正常场景、边界条件和异常情况。
覆盖率目标 > 90%
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime

project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from fastapi.testclient import TestClient


@pytest.mark.api
class TestRootEndpoints:
    """根路径端点测试"""
    
    @pytest.fixture(scope="class")
    def client(self):
        from TOSKill.main import app
        return TestClient(app)
    
    def test_root_endpoint_success(self, client):
        """测试根路径返回成功"""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "version" in data
        assert "status" in data
        assert data["status"] == "running"
    
    def test_health_check_success(self, client):
        """测试健康检查返回成功"""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
    
    def test_health_check_response_format(self, client):
        """测试健康检查响应格式"""
        response = client.get("/health")
        data = response.json()
        assert isinstance(data, dict)
        assert "status" in data


@pytest.mark.api
class TestAPIHealthCheck:
    """API 健康检查测试"""
    
    @pytest.fixture(scope="class")
    def client(self):
        from TOSKill.main import app
        return TestClient(app)
    
    def test_api_health_check_success(self, client):
        """测试 API 健康检查"""
        response = client.get("/api/toskill/health")
        assert response.status_code == 200
        data = response.json()
        assert data["code"] == 200
        assert "tools_count" in data["data"]
        assert "available_tools" in data["data"]
    
    def test_api_health_check_tools_count_positive(self, client):
        """测试 API 健康检查工具数量为正"""
        response = client.get("/api/toskill/health")
        data = response.json()
        assert data["data"]["tools_count"] > 0
    
    def test_api_health_check_available_tools_is_list(self, client):
        """测试 API 健康检查可用工具为列表"""
        response = client.get("/api/toskill/health")
        data = response.json()
        assert isinstance(data["data"]["available_tools"], list)


@pytest.mark.api
class TestToolsEndpoints:
    """工具端点测试"""
    
    @pytest.fixture(scope="class")
    def client(self):
        from TOSKill.main import app
        return TestClient(app)
    
    def test_list_tools_success(self, client):
        """测试获取工具列表成功"""
        response = client.get("/api/toskill/tools")
        assert response.status_code == 200
        data = response.json()
        assert data["code"] == 200
        assert "tools" in data["data"]
        assert "count" in data["data"]
    
    def test_list_tools_count_matches(self, client):
        """测试工具数量与列表匹配"""
        response = client.get("/api/toskill/tools")
        data = response.json()
        assert len(data["data"]["tools"]) == data["data"]["count"]
    
    def test_list_tools_structure(self, client):
        """测试工具列表结构"""
        response = client.get("/api/toskill/tools")
        data = response.json()
        tools = data["data"]["tools"]
        assert len(tools) > 0
        
        for tool in tools:
            assert "name" in tool
            assert "description" in tool
            assert "category" in tool
    
    def test_list_tools_by_category_success(self, client):
        """测试按类别获取工具列表"""
        response = client.get("/api/toskill/tools/categories")
        assert response.status_code == 200
        data = response.json()
        assert data["code"] == 200
        assert "info_collection" in data["data"]
        assert "vuln_scan" in data["data"]
        assert "poc" in data["data"]
        assert "all" in data["data"]
    
    def test_list_tools_by_category_types(self, client):
        """测试类别工具列表类型"""
        response = client.get("/api/toskill/tools/categories")
        data = response.json()
        
        assert isinstance(data["data"]["info_collection"], list)
        assert isinstance(data["data"]["vuln_scan"], list)
        assert isinstance(data["data"]["poc"], list)
        assert isinstance(data["data"]["all"], list)
    
    def test_get_tool_info_success(self, client):
        """测试获取单个工具详情"""
        response = client.get("/api/toskill/tools/baseinfo_scan")
        assert response.status_code == 200
        data = response.json()
        assert data["code"] == 200
        assert "name" in data["data"]
        assert "description" in data["data"]
        assert "category" in data["data"]
    
    def test_get_tool_info_not_found(self, client):
        """测试获取不存在的工具"""
        response = client.get("/api/toskill/tools/nonexistent_tool_xyz")
        assert response.status_code == 404
    
    def test_get_tool_info_invalid_name(self, client):
        """测试获取无效工具名"""
        response = client.get("/api/toskill/tools/")
        assert response.status_code in [404, 405]


@pytest.mark.api
class TestToolExecution:
    """工具执行测试"""
    
    @pytest.fixture(scope="class")
    def client(self):
        from TOSKill.main import app
        return TestClient(app)
    
    def test_execute_single_tool_success(self, client):
        """测试执行单个工具成功"""
        response = client.post("/api/toskill/tools/execute", json={
            "tool_name": "baseinfo_scan",
            "target": "example.com"
        })
        assert response.status_code == 200
        data = response.json()
        assert data["code"] == 200
        assert "result" in data["data"]
    
    def test_execute_single_tool_with_result_structure(self, client):
        """测试执行工具返回结构"""
        response = client.post("/api/toskill/tools/execute", json={
            "tool_name": "baseinfo_scan",
            "target": "example.com"
        })
        data = response.json()
        result = data["data"]
        assert "tool_name" in result
        assert "success" in result
        assert "timestamp" in result
    
    def test_execute_nonexistent_tool(self, client):
        """测试执行不存在的工具"""
        response = client.post("/api/toskill/tools/execute", json={
            "tool_name": "nonexistent_tool_xyz",
            "target": "example.com"
        })
        assert response.status_code == 404
    
    def test_execute_tool_empty_target(self, client):
        """测试空目标执行工具"""
        response = client.post("/api/toskill/tools/execute", json={
            "tool_name": "baseinfo_scan",
            "target": ""
        })
        assert response.status_code == 400
    
    def test_execute_tool_missing_target(self, client):
        """测试缺少目标参数"""
        response = client.post("/api/toskill/tools/execute", json={
            "tool_name": "baseinfo_scan"
        })
        assert response.status_code == 422
    
    def test_execute_tool_missing_tool_name(self, client):
        """测试缺少工具名参数"""
        response = client.post("/api/toskill/tools/execute", json={
            "target": "example.com"
        })
        assert response.status_code == 422
    
    def test_execute_tool_with_params(self, client):
        """测试带参数执行工具"""
        response = client.post("/api/toskill/tools/execute", json={
            "tool_name": "baseinfo_scan",
            "target": "example.com",
            "params": {"timeout": 10}
        })
        assert response.status_code == 200


@pytest.mark.api
class TestBatchToolExecution:
    """批量工具执行测试"""
    
    @pytest.fixture(scope="class")
    def client(self):
        from TOSKill.main import app
        return TestClient(app)
    
    def test_batch_execute_tools_success(self, client):
        """测试批量执行工具成功"""
        response = client.post("/api/toskill/tools/execute/batch", json={
            "tool_names": ["baseinfo_scan"],
            "target": "example.com",
            "parallel": True
        })
        assert response.status_code == 200
        data = response.json()
        assert data["code"] == 200
        assert "results" in data["data"]
    
    def test_batch_execute_tools_sequential(self, client):
        """测试顺序批量执行工具"""
        response = client.post("/api/toskill/tools/execute/batch", json={
            "tool_names": ["baseinfo_scan"],
            "target": "example.com",
            "parallel": False
        })
        assert response.status_code == 200
        data = response.json()
        assert data["code"] == 200
    
    def test_batch_execute_empty_tool_list(self, client):
        """测试空工具列表批量执行"""
        response = client.post("/api/toskill/tools/execute/batch", json={
            "tool_names": [],
            "target": "example.com",
            "parallel": True
        })
        assert response.status_code == 400
    
    def test_batch_execute_empty_target(self, client):
        """测试空目标批量执行"""
        response = client.post("/api/toskill/tools/execute/batch", json={
            "tool_names": ["baseinfo_scan"],
            "target": "",
            "parallel": True
        })
        assert response.status_code == 400
    
    def test_batch_execute_nonexistent_tool(self, client):
        """测试批量执行包含不存在的工具"""
        response = client.post("/api/toskill/tools/execute/batch", json={
            "tool_names": ["nonexistent_tool_xyz"],
            "target": "example.com",
            "parallel": True
        })
        assert response.status_code == 400
    
    def test_batch_execute_multiple_tools(self, client):
        """测试批量执行多个工具"""
        response = client.post("/api/toskill/tools/execute/batch", json={
            "tool_names": ["baseinfo_scan", "port_scan"],
            "target": "example.com",
            "parallel": True
        })
        assert response.status_code == 200
        data = response.json()
        assert data["data"]["total"] == 2


@pytest.mark.api
class TestScanEndpoints:
    """扫描端点测试"""
    
    @pytest.fixture(scope="class")
    def client(self):
        from TOSKill.main import app
        return TestClient(app)
    
    def test_info_scan_success(self, client):
        """测试信息收集扫描成功"""
        response = client.post("/api/toskill/scan/info", json={
            "target": "example.com"
        })
        assert response.status_code == 200
        data = response.json()
        assert data["code"] == 200
        assert "results" in data["data"]
    
    def test_info_scan_with_custom_tools(self, client):
        """测试带自定义工具的信息收集扫描"""
        response = client.post("/api/toskill/scan/info", json={
            "target": "example.com",
            "tools": ["baseinfo_scan", "port_scan"]
        })
        assert response.status_code == 200
        data = response.json()
        assert "tools_used" in data["data"]
    
    def test_vuln_scan_success(self, client):
        """测试漏洞扫描成功"""
        response = client.post("/api/toskill/scan/vuln", json={
            "target": "example.com"
        })
        assert response.status_code == 200
        data = response.json()
        assert data["code"] == 200
        assert "results" in data["data"]
    
    def test_vuln_scan_with_custom_tools(self, client):
        """测试带自定义工具的漏洞扫描"""
        response = client.post("/api/toskill/scan/vuln", json={
            "target": "example.com",
            "tools": ["sqli_scan", "xss_scan"]
        })
        assert response.status_code == 200
    
    def test_full_scan_success(self, client):
        """测试完整扫描成功"""
        response = client.post("/api/toskill/scan/full", json={
            "target": "example.com",
            "generate_report": False
        })
        assert response.status_code == 200
        data = response.json()
        assert data["code"] == 200
        assert "session_id" in data["data"]
    
    def test_full_scan_with_report(self, client):
        """测试带报告的完整扫描"""
        response = client.post("/api/toskill/scan/full", json={
            "target": "example.com",
            "generate_report": True
        })
        assert response.status_code == 200
        data = response.json()
        assert "session_id" in data["data"]
    
    def test_scan_with_empty_target(self, client):
        """测试空目标扫描"""
        response = client.post("/api/toskill/scan/info", json={
            "target": ""
        })
        assert response.status_code == 400
    
    def test_scan_with_invalid_tool(self, client):
        """测试无效工具扫描"""
        response = client.post("/api/toskill/scan/info", json={
            "target": "example.com",
            "tools": ["invalid_tool_xyz"]
        })
        assert response.status_code == 400
    
    def test_scan_response_structure(self, client):
        """测试扫描响应结构"""
        response = client.post("/api/toskill/scan/info", json={
            "target": "example.com"
        })
        data = response.json()
        assert "target" in data["data"]
        assert "scan_type" in data["data"]
        assert "timestamp" in data["data"]


@pytest.mark.api
class TestSessionEndpoints:
    """会话端点测试"""
    
    @pytest.fixture(scope="class")
    def client(self):
        from TOSKill.main import app
        return TestClient(app)
    
    def test_create_session_success(self, client):
        """测试创建会话成功"""
        response = client.post("/api/toskill/sessions", json={
            "target": "example.com"
        })
        assert response.status_code == 200
        data = response.json()
        assert data["code"] == 200
        assert "session_id" in data["data"]
    
    def test_create_session_with_tools(self, client):
        """测试带工具列表创建会话"""
        response = client.post("/api/toskill/sessions", json={
            "target": "example.com",
            "tools": ["baseinfo_scan", "port_scan"]
        })
        assert response.status_code == 200
        data = response.json()
        assert "session_id" in data["data"]
    
    def test_create_session_empty_target(self, client):
        """测试空目标创建会话"""
        response = client.post("/api/toskill/sessions", json={
            "target": ""
        })
        assert response.status_code == 200
    
    def test_get_session_success(self, client):
        """测试获取会话成功"""
        create_response = client.post("/api/toskill/sessions", json={
            "target": "test.example.com"
        })
        session_id = create_response.json()["data"]["session_id"]
        
        response = client.get(f"/api/toskill/sessions/{session_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["code"] == 200
        assert data["data"]["target"] == "test.example.com"
    
    def test_get_session_not_found(self, client):
        """测试获取不存在的会话"""
        response = client.get("/api/toskill/sessions/nonexistent_session_xyz")
        assert response.status_code == 404
    
    def test_delete_session_success(self, client):
        """测试删除会话成功"""
        create_response = client.post("/api/toskill/sessions", json={
            "target": "delete-test.example.com"
        })
        session_id = create_response.json()["data"]["session_id"]
        
        response = client.delete(f"/api/toskill/sessions/{session_id}")
        assert response.status_code == 200
        
        get_response = client.get(f"/api/toskill/sessions/{session_id}")
        assert get_response.status_code == 404
    
    def test_delete_session_not_found(self, client):
        """测试删除不存在的会话"""
        response = client.delete("/api/toskill/sessions/nonexistent_session_xyz")
        assert response.status_code == 404


@pytest.mark.api
class TestReportEndpoints:
    """报告端点测试"""
    
    @pytest.fixture(scope="class")
    def client(self):
        from TOSKill.main import app
        return TestClient(app)
    
    def test_list_reports_success(self, client):
        """测试获取报告列表成功"""
        response = client.get("/api/reports/list")
        assert response.status_code == 200
        data = response.json()
        assert "success" in data
        assert "reports" in data
        assert "total" in data
    
    def test_list_reports_structure(self, client):
        """测试报告列表结构"""
        response = client.get("/api/reports/list")
        data = response.json()
        assert isinstance(data["reports"], list)
        assert isinstance(data["total"], int)
    
    def test_get_report_by_session_not_found(self, client):
        """测试获取不存在的会话报告"""
        response = client.get("/api/reports/session/nonexistent_session_xyz")
        assert response.status_code == 404
    
    def test_download_report_not_found(self, client):
        """测试下载不存在的报告"""
        response = client.get("/api/reports/download/nonexistent_report.md")
        assert response.status_code == 404
    
    def test_delete_report_not_found(self, client):
        """测试删除不存在的报告"""
        response = client.delete("/api/reports/nonexistent_report.md")
        assert response.status_code == 404
    
    def test_get_report_content_not_found(self, client):
        """测试获取不存在的报告内容"""
        response = client.get("/api/reports/nonexistent_report.md/content")
        assert response.status_code == 404


@pytest.mark.api
class TestVulnScanTools:
    """漏洞扫描工具测试"""
    
    @pytest.fixture(scope="class")
    def client(self):
        from TOSKill.main import app
        return TestClient(app)
    
    def test_sqli_scan_tool(self, client):
        """测试SQL注入扫描工具"""
        response = client.post("/api/toskill/tools/execute", json={
            "tool_name": "sqli_scan",
            "target": "http://example.com/page?id=1"
        })
        assert response.status_code == 200
        data = response.json()
        assert "result" in data["data"]
        result = data["data"]["result"]
        assert "success" in result
    
    def test_xss_scan_tool(self, client):
        """测试XSS扫描工具"""
        response = client.post("/api/toskill/tools/execute", json={
            "tool_name": "xss_scan",
            "target": "http://example.com/search?q=test"
        })
        assert response.status_code == 200
        data = response.json()
        assert "result" in data["data"]
    
    def test_lfi_scan_tool(self, client):
        """测试LFI扫描工具"""
        response = client.post("/api/toskill/tools/execute", json={
            "tool_name": "lfi_scan",
            "target": "http://example.com/page?file=test"
        })
        assert response.status_code == 200
        data = response.json()
        assert "result" in data["data"]
    
    def test_ssrf_scan_tool(self, client):
        """测试SSRF扫描工具"""
        response = client.post("/api/toskill/tools/execute", json={
            "tool_name": "ssrf_scan",
            "target": "http://example.com/fetch?url=test"
        })
        assert response.status_code == 200
        data = response.json()
        assert "result" in data["data"]
    
    def test_cmdi_scan_tool(self, client):
        """测试命令注入扫描工具"""
        response = client.post("/api/toskill/tools/execute", json={
            "tool_name": "cmdi_scan",
            "target": "http://example.com/exec?cmd=test"
        })
        assert response.status_code == 200
        data = response.json()
        assert "result" in data["data"]
    
    def test_csrf_scan_tool(self, client):
        """测试CSRF扫描工具"""
        response = client.post("/api/toskill/tools/execute", json={
            "tool_name": "csrf_scan",
            "target": "http://example.com/form"
        })
        assert response.status_code == 200
    
    def test_fileupload_scan_tool(self, client):
        """测试文件上传扫描工具"""
        response = client.post("/api/toskill/tools/execute", json={
            "tool_name": "fileupload_scan",
            "target": "http://example.com/upload"
        })
        assert response.status_code == 200
    
    def test_weakpass_scan_tool(self, client):
        """测试弱口令扫描工具"""
        response = client.post("/api/toskill/tools/execute", json={
            "tool_name": "weakpass_scan",
            "target": "http://example.com/login"
        })
        assert response.status_code == 200


@pytest.mark.api
class TestInfoCollectionTools:
    """信息收集工具测试"""
    
    @pytest.fixture(scope="class")
    def client(self):
        from TOSKill.main import app
        return TestClient(app)
    
    def test_base_info_scan(self, client):
        """测试基础信息扫描"""
        response = client.post("/api/toskill/tools/execute", json={
            "tool_name": "baseinfo_scan",
            "target": "example.com"
        })
        assert response.status_code == 200
        data = response.json()
        assert data["data"]["success"] == True
    
    def test_subdomain_scan(self, client):
        """测试子域名扫描"""
        response = client.post("/api/toskill/tools/execute", json={
            "tool_name": "subdomain_scan",
            "target": "example.com"
        })
        assert response.status_code == 200
    
    def test_port_scan(self, client):
        """测试端口扫描"""
        response = client.post("/api/toskill/tools/execute", json={
            "tool_name": "port_scan",
            "target": "example.com"
        })
        assert response.status_code == 200
    
    def test_dir_brute(self, client):
        """测试目录扫描"""
        response = client.post("/api/toskill/tools/execute", json={
            "tool_name": "dir_brute",
            "target": "http://example.com"
        })
        assert response.status_code == 200
    
    def test_waf_detect_scan(self, client):
        """测试WAF检测"""
        response = client.post("/api/toskill/tools/execute", json={
            "tool_name": "waf_detect_scan",
            "target": "http://example.com"
        })
        assert response.status_code == 200
    
    def test_cdn_detect_scan(self, client):
        """测试CDN检测"""
        response = client.post("/api/toskill/tools/execute", json={
            "tool_name": "cdn_detect_scan",
            "target": "example.com"
        })
        assert response.status_code == 200
    
    def test_cms_detect_scan(self, client):
        """测试CMS识别"""
        response = client.post("/api/toskill/tools/execute", json={
            "tool_name": "cms_detect_scan",
            "target": "http://example.com"
        })
        assert response.status_code == 200
    
    def test_infoleak_scan(self, client):
        """测试信息泄露扫描"""
        response = client.post("/api/toskill/tools/execute", json={
            "tool_name": "infoleak_scan",
            "target": "http://example.com"
        })
        assert response.status_code == 200


@pytest.mark.api
class TestPOCTools:
    """POC工具测试"""
    
    @pytest.fixture(scope="class")
    def client(self):
        from TOSKill.main import app
        return TestClient(app)
    
    def test_thinkphp_rce_scan(self, client):
        """测试ThinkPHP RCE检测"""
        response = client.post("/api/toskill/tools/execute", json={
            "tool_name": "thinkphp_rce_scan",
            "target": "http://example.com"
        })
        assert response.status_code == 200
    
    def test_struts2_scan(self, client):
        """测试Struts2漏洞检测"""
        response = client.post("/api/toskill/tools/execute", json={
            "tool_name": "struts2_scan",
            "target": "http://example.com"
        })
        assert response.status_code == 200
    
    def test_weblogic_scan(self, client):
        """测试WebLogic漏洞检测"""
        response = client.post("/api/toskill/tools/execute", json={
            "tool_name": "weblogic_scan",
            "target": "http://example.com:7001"
        })
        assert response.status_code == 200


@pytest.mark.api
class TestToolWrappers:
    """工具封装测试"""
    
    def test_sqli_wrapper_structure(self):
        """测试SQL注入工具封装返回结构"""
        from TOSKill.tools.vuln_scan.sqli import sqli_scan
        
        result = sqli_scan.invoke({"target": "http://example.com?id=1"})
        
        assert "success" in result
        assert "data" in result
        assert "error" in result
        assert "metadata" in result
    
    def test_xss_wrapper_structure(self):
        """测试XSS工具封装返回结构"""
        from TOSKill.tools.vuln_scan.xss import xss_scan
        
        result = xss_scan.invoke({"target": "http://example.com?q=test"})
        
        assert "success" in result
        assert "data" in result
        assert "error" in result
        assert "metadata" in result
    
    def test_weakpass_wrapper_structure(self):
        """测试弱口令工具封装返回结构"""
        from TOSKill.tools.vuln_scan.weakpass import weakpass_scan
        
        result = weakpass_scan.invoke({"target": "http://example.com/login"})
        
        assert "success" in result
        assert "data" in result
        assert "error" in result
        assert "metadata" in result


@pytest.mark.api
class TestEdgeCases:
    """边界条件测试"""
    
    @pytest.fixture(scope="class")
    def client(self):
        from TOSKill.main import app
        return TestClient(app)
    
    def test_scan_with_very_long_target(self, client):
        """测试超长目标地址"""
        long_target = "a" * 1000 + ".com"
        response = client.post("/api/toskill/scan/info", json={
            "target": long_target
        })
        assert response.status_code in [200, 400]
    
    def test_scan_with_special_characters_target(self, client):
        """测试特殊字符目标"""
        response = client.post("/api/toskill/scan/info", json={
            "target": "test<script>.com"
        })
        assert response.status_code in [200, 400]
    
    def test_scan_with_unicode_target(self, client):
        """测试Unicode目标"""
        response = client.post("/api/toskill/scan/info", json={
            "target": "测试.中国"
        })
        assert response.status_code in [200, 400]
    
    def test_tool_execute_with_null_params(self, client):
        """测试空参数执行工具"""
        response = client.post("/api/toskill/tools/execute", json={
            "tool_name": "baseinfo_scan",
            "target": "example.com",
            "params": None
        })
        assert response.status_code == 200
    
    def test_batch_execute_with_mixed_valid_invalid_tools(self, client):
        """测试混合有效和无效工具的批量执行"""
        response = client.post("/api/toskill/tools/execute/batch", json={
            "tool_names": ["baseinfo_scan", "invalid_tool_xyz"],
            "target": "example.com",
            "parallel": True
        })
        assert response.status_code == 400
    
    def test_session_operations_concurrent(self, client):
        """测试并发会话操作"""
        import concurrent.futures
        
        def create_and_get_session():
            create_response = client.post("/api/toskill/sessions", json={
                "target": "concurrent-test.com"
            })
            if create_response.status_code == 200:
                session_id = create_response.json()["data"]["session_id"]
                return client.get(f"/api/toskill/sessions/{session_id}")
            return create_response
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(create_and_get_session) for _ in range(3)]
            results = [f.result() for f in futures]
        
        for result in results:
            assert result.status_code in [200, 404]


@pytest.mark.api
class TestErrorHandling:
    """错误处理测试"""
    
    @pytest.fixture(scope="class")
    def client(self):
        from TOSKill.main import app
        return TestClient(app)
    
    def test_invalid_json_request(self, client):
        """测试无效JSON请求"""
        response = client.post(
            "/api/toskill/tools/execute",
            content="invalid json",
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 422
    
    def test_missing_content_type(self, client):
        """测试缺少Content-Type"""
        response = client.post(
            "/api/toskill/tools/execute",
            content='{"tool_name": "test", "target": "test.com"}'
        )
        assert response.status_code in [200, 422]
    
    def test_wrong_http_method(self, client):
        """测试错误的HTTP方法"""
        response = client.delete("/api/toskill/tools")
        assert response.status_code == 405
    
    def test_nonexistent_endpoint(self, client):
        """测试不存在的端点"""
        response = client.get("/api/toskill/nonexistent")
        assert response.status_code == 404


@pytest.mark.parametrize(
    ("tool_name", "expected_message"),
    [
        ("subdomain_scan", "不适用公网子域名枚举"),
        ("cdn_detect_scan", "不经过公共 CDN"),
        ("web_weight_scan", "没有公开搜索权重"),
    ],
)
def test_local_target_public_data_tools_are_not_applicable(tool_name, expected_message):
    from TOSKill.AI.tools import get_tool_by_name

    result = get_tool_by_name(tool_name).invoke("http://localhost:88")

    assert result["success"] is True
    assert result["error"] is None
    assert result["data"]["result_status"] == "not_applicable"
    assert expected_message in result["data"]["status_message"]


def test_local_target_ip_location_skips_public_provider():
    from TOSKill.AI.tools import ip_locate_scan

    with patch("TOSKill.AI.tools.ip_locate") as locate:
        result = ip_locate_scan.invoke("http://localhost:88")

    locate.assert_not_called()
    assert result["success"] is True
    assert result["data"]["result_status"] == "not_applicable"
    assert result["data"]["ip"] == "127.0.0.1"


def test_local_target_baseinfo_preserves_url_and_runs_scanner():
    from TOSKill.AI.tools import baseinfo_scan

    scanner_result = {
        "success": True,
        "data": {"domain": "localhost", "server": "test-server"},
        "error": None,
    }
    with patch("TOSKill.AI.tools.baseinfo", return_value=scanner_result) as scanner:
        result = baseinfo_scan.invoke("http://localhost:88")

    scanner.assert_called_once_with("http://localhost:88")
    assert result["success"] is True
    assert result["data"]["domain"] == "localhost"


def test_local_target_waf_preserves_url_and_runs_scanner():
    from TOSKill.AI.tools import waf_detect_scan

    scanner_result = {
        "success": True,
        "data": {"has_waf": "no", "message": "未检测到已知WAF特征"},
        "error": None,
    }
    with patch("TOSKill.AI.tools.waf_detect", return_value=scanner_result) as scanner:
        result = waf_detect_scan.invoke("http://localhost:88")

    scanner.assert_called_once_with("http://localhost:88")
    assert result["success"] is True


def test_local_target_legacy_baseinfo_accepts_port():
    from backend.plugins.baseinfo.baseinfo import getbaseinfo

    response = MagicMock()
    response.headers = {"Server": "local-test", "X-Powered-By": "python"}
    with patch("backend.plugins.baseinfo.baseinfo.SESSION.get", return_value=response) as request, patch(
        "backend.plugins.baseinfo.baseinfo.get_ip_list",
        return_value=["127.0.0.1 (本地/内网地址，无公网归属信息)"],
    ), patch("backend.plugins.baseinfo.baseinfo.get_ua", return_value={"User-Agent": "test"}):
        result = getbaseinfo("http://localhost:88")

    request.assert_called_once()
    assert request.call_args.args[0] == "http://localhost:88"
    assert result["code"] == 200
    assert result["domain"] == "localhost"
    assert result["register"] is None


def test_local_target_waf_url_validation_accepts_port():
    from backend.plugins.waf.waf import is_valid_url

    assert is_valid_url("http://localhost:88") is True
    assert is_valid_url("http://127.0.0.1:88") is True
    assert is_valid_url("http://") is False


def test_local_target_detection_does_not_misclassify_public_ipv6():
    from TOSKill.utils.target import is_non_public_target

    assert is_non_public_target("http://[::1]:88") is True
    assert is_non_public_target("https://[2001:4860:4860::8888]") is False


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-m", "api"])
