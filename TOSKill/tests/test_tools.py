"""
TOSKill 工具注册与执行测试
验证22个工具的注册状态、参数验证
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


class TestToolRegistry:
    """工具注册表测试"""

    def test_all_tools_count(self):
        """全部工具至少22个"""
        from TOSKill.AI.tools import ALL_TOOLS
        assert len(ALL_TOOLS) >= 22, f"期望22+工具，实际{len(ALL_TOOLS)}"

    def test_info_tools_count(self):
        """信息收集工具至少11个"""
        from TOSKill.AI.tools import INFO_COLLECTION_TOOLS
        assert len(INFO_COLLECTION_TOOLS) >= 11

    def test_vuln_tools_count(self):
        """漏洞扫描工具至少8个"""
        from TOSKill.AI.tools import VULN_SCAN_TOOLS
        assert len(VULN_SCAN_TOOLS) >= 8

    def test_get_tool_by_name(self):
        """按名查找工具"""
        from TOSKill.AI.tools import get_tool_by_name
        tool = get_tool_by_name("baseinfo_scan")
        assert tool is not None

    def test_get_nonexistent_tool(self):
        """查找不存在的工具返回None"""
        from TOSKill.AI.tools import get_tool_by_name
        tool = get_tool_by_name("nonexistent_tool")
        assert tool is None

    def test_get_tool_sequence(self):
        """获取工具序列"""
        from TOSKill.AI.tools import get_tool_sequence
        seq = get_tool_sequence("info_collection")
        assert len(seq) > 0

    def test_get_all_tool_names(self):
        """获取全部工具名"""
        from TOSKill.AI.tools import get_all_tool_names
        names = get_all_tool_names()
        assert "baseinfo_scan" in names
        assert len(names) >= 22

    def test_clean_target_url(self):
        """目标URL清理 - URL输入"""
        from TOSKill.AI.tools import clean_target
        result = clean_target("https://example.com/")
        assert "example.com" in result

    def test_clean_target_ip(self):
        """目标URL清理 - IP输入"""
        from TOSKill.AI.tools import clean_target
        result = clean_target("http://192.168.1.1:8080/admin")
        assert "192.168.1.1" in result

    def test_clean_target_blank(self):
        """目标URL清理 - 空输入"""
        from TOSKill.AI.tools import clean_target
        result = clean_target("")
        assert result == ""

    @pytest.mark.parametrize("tool_name", [
        "sqli_scan", "xss_scan", "waf_detect_scan", "tls_certificate_scan", "http_methods_scan",
        "public_metadata_scan", "http_security_headers_scan", "cookie_security_scan",
        "cors_misconfiguration_scan",
    ])
    def test_clean_target_for_url_preserving_tool(self, tool_name):
        from TOSKill.AI.tools import clean_target_for_tool

        target = "https://example.com/search?q=test"
        assert clean_target_for_tool(tool_name, target) == target

    def test_clean_target_for_host_only_tool(self):
        from TOSKill.AI.tools import clean_target_for_tool

        assert clean_target_for_tool(
            "baseinfo_scan",
            "https://example.com/search?q=test",
        ) == "example.com"

    def test_clean_target_for_custom_tool_preserves_url(self, monkeypatch):
        import TOSKill.AI.tools as tools_module

        monkeypatch.setattr(
            tools_module.script_manager,
            "get_registered_scripts",
            lambda: {"custom_http_probe": {"category": "info_collection"}},
        )
        target = "https://example.com/search?q=test"
        assert tools_module.clean_target_for_tool("custom_http_probe", target) == target

    def test_webside_query_uses_structured_tool_invoke(self):
        from TOSKill.AI.tools import webside_query_scan

        raw_result = {
            "success": True,
            "data": {"side_sites": [], "total_count": 0},
            "error": None,
        }
        mock_tool = MagicMock()
        mock_tool.invoke.return_value = raw_result
        with patch("TOSKill.AI.tools.resolve_target_ip", return_value="44.238.29.244") as resolver:
            with patch("TOSKill.AI.tools.webside_query", mock_tool):
                result = webside_query_scan.invoke({"target": "http://testasp.vulnweb.com"})

        resolver.assert_called_once_with("http://testasp.vulnweb.com")
        mock_tool.invoke.assert_called_once_with({"ip": "44.238.29.244"})
        assert result["success"] is True
        assert result["data"]["total_count"] == 0

    def test_webside_query_returns_neutral_result_when_provider_is_unavailable(self):
        from TOSKill.AI.tools import webside_query_scan

        raw_result = {
            "success": False,
            "data": {},
            "error": "query failed",
        }
        mock_tool = MagicMock()
        mock_tool.invoke.return_value = raw_result
        with patch("TOSKill.AI.tools.resolve_target_ip", return_value="44.238.29.244"):
            with patch("TOSKill.AI.tools.webside_query", mock_tool):
                result = webside_query_scan.invoke({"target": "http://testasp.vulnweb.com"})

        assert result["success"] is True
        assert result["error"] is None
        assert result["data"]["query_status"] == "provider_unavailable"
        assert result["data"]["provider_error"] == "query failed"

    def test_waf_preserves_url_and_propagates_scanner_failure(self):
        from TOSKill.AI.tools import waf_detect_scan

        with patch("TOSKill.AI.tools.waf_detect", return_value={
            "success": False,
            "data": {"has_waf": "unknown"},
            "error": "WAF 请求失败",
            "metadata": {"tool": "waf_detect"},
        }) as scanner:
            result = waf_detect_scan.invoke({"target": "http://testasp.vulnweb.com"})

        scanner.assert_called_once_with("http://testasp.vulnweb.com")
        assert result["success"] is False
        assert result["error"] == "WAF 请求失败"
        assert result["data"]["has_waf"] == "unknown"

    def test_ip_locate_resolves_domain_and_propagates_failure(self):
        from TOSKill.AI.tools import ip_locate_scan

        with patch("TOSKill.AI.tools.resolve_target_ip", return_value="44.238.29.244") as resolver, \
             patch("TOSKill.AI.tools.ip_locate", return_value={
                 "success": False,
                 "data": {"ip": "44.238.29.244"},
                 "error": "IP 查询服务不可用",
             }) as scanner:
            result = ip_locate_scan.invoke({"target": "http://testasp.vulnweb.com"})

        resolver.assert_called_once_with("http://testasp.vulnweb.com")
        scanner.assert_called_once_with("44.238.29.244")
        assert result["success"] is False
        assert result["error"] == "IP 查询服务不可用"

    def test_web_weight_propagates_multilevel_domain_result(self):
        from TOSKill.AI.tools import web_weight_scan

        with patch("TOSKill.AI.tools.web_weight", return_value={
            "success": True,
            "data": {"lookup_domain": "vulnweb.com", "result": "PC权重(1)"},
            "error": None,
        }) as scanner:
            result = web_weight_scan.invoke({"target": "http://testasp.vulnweb.com"})

        scanner.assert_called_once_with("testasp.vulnweb.com")
        assert result["success"] is True
        assert result["data"]["lookup_domain"] == "vulnweb.com"

    def test_nested_scanner_failure_is_flattened(self):
        from TOSKill.AI.tools import normalize_scanner_result

        result = normalize_scanner_result({
            "success": True,
            "data": {
                "success": False,
                "data": {"result": "failed"},
                "error": "inner failure",
            },
            "error": None,
        })

        assert result["success"] is False
        assert result["data"] == {"result": "failed"}
        assert result["error"] == "inner failure"

    def test_unified_invocation_flattens_legacy_nested_failure(self):
        from TOSKill.AI.tools import invoke_tool_with_auth

        mock_tool = MagicMock()
        mock_tool.name = "legacy_info_tool"
        mock_tool.invoke.return_value = {
            "success": True,
            "data": {
                "success": False,
                "data": {"result": "failed"},
                "error": "inner failure",
            },
            "error": None,
            "auth_info": None,
            "timestamp": "2026-08-13T00:00:00",
        }

        result = invoke_tool_with_auth(mock_tool, "example.com")

        assert result["success"] is False
        assert result["error"] == "inner failure"

    def test_tls_timeout_returns_a_classified_tool_result(self, monkeypatch):
        import socket
        from TOSKill.tools.info_collection.tls_certificate import tls_certificate_scan

        monkeypatch.setattr(
            "TOSKill.tools.info_collection.tls_certificate.socket.create_connection",
            lambda *args, **kwargs: (_ for _ in ()).throw(socket.timeout()),
        )

        result = tls_certificate_scan("https://example.test")

        assert result["success"] is False
        assert result["data"]["tls_available"] is False
        assert result["data"]["failure_type"] == "connection_timeout"
        assert "TLS 服务连接超时" in result["error"]

    def test_tls_scan_returns_neutral_result_when_tls_is_unavailable(self):
        from TOSKill.AI.tools import tls_certificate_scan

        with patch("TOSKill.AI.tools.tls_certificate", return_value={
            "success": False,
            "data": {"tls_available": False, "host": "example.test", "port": 443, "failure_type": "connection_timeout"},
            "error": "TLS 服务连接超时: example.test:443",
        }):
            result = tls_certificate_scan.invoke({"target": "https://example.test"})

        assert result["success"] is True
        assert result["error"] is None
        assert result["data"]["tls_available"] is False
        assert result["data"]["collection_status"] == "connection_timeout"
        assert result["data"]["status_message"] == "未检测到可访问的 TLS 服务。"

    def test_subdomain_scan_preserves_no_public_records_as_success(self):
        from TOSKill.AI.tools import subdomain_scan

        with patch("TOSKill.AI.tools.subdomain", return_value={
            "success": True,
            "data": {
                "subdomains": [],
                "total_count": 0,
                "collection_status": "no_public_records",
                "status_message": "未发现公开证书记录中的子域名",
                "provider": "crt.sh",
            },
            "error": None,
        }):
            result = subdomain_scan.invoke({"target": "example.test"})

        assert result["success"] is True
        assert result["data"]["total_count"] == 0
        assert result["data"]["collection_status"] == "no_public_records"

    def test_subdomain_provider_timeout_is_a_neutral_collection_result(self, monkeypatch):
        import importlib
        from urllib.error import URLError
        subdomain_module = importlib.import_module("TOSKill.tools.info_collection.subdomain")

        monkeypatch.setattr(
            subdomain_module,
            "urlopen",
            lambda *args, **kwargs: (_ for _ in ()).throw(URLError("The read operation timed out")),
        )

        result = subdomain_module.subdomain("example.test")

        assert result["success"] is True
        assert result["error"] is None
        assert result["data"]["collection_status"] == "provider_unavailable"
        assert result["data"]["status_message"] == "子域名公开数据源暂不可用，本次未获得可展示结果。"
        assert "timed out" in result["data"]["provider_error"]

    def test_web_weight_accepts_multilevel_domain(self):
        from TOSKill.tools.info_collection.webweight import _registrable_domain

        assert _registrable_domain("http://testasp.vulnweb.com/path") == "vulnweb.com"
        assert _registrable_domain("https://shop.example.com.cn") == "example.com.cn"


class TestToolIntegrity:
    """工具完整性检查"""

    REQUIRED_INFO_TOOLS = ["baseinfo_scan", "port_scan", "subdomain_scan", "dir_brute",
                           "waf_detect_scan", "cdn_detect_scan", "cms_detect_scan",
                           "infoleak_scan", "ip_locate_scan", "webside_query_scan",
                           "web_weight_scan"]
    REQUIRED_VULN_TOOLS = ["sqli_scan", "xss_scan", "csrf_scan", "fileupload_scan",
                           "cmdi_scan", "ssrf_scan", "lfi_scan", "weakpass_scan"]

    def test_all_required_info_tools_exist(self):
        """检查必需信息收集工具"""
        from TOSKill.AI.tools import get_tool_by_name
        missing = [t for t in self.REQUIRED_INFO_TOOLS if get_tool_by_name(t) is None]
        assert len(missing) == 0, f"信息收集工具缺失: {missing}"

    def test_all_required_vuln_tools_exist(self):
        """检查必需漏洞扫描工具"""
        from TOSKill.AI.tools import get_tool_by_name
        missing = [t for t in self.REQUIRED_VULN_TOOLS if get_tool_by_name(t) is None]
        assert len(missing) == 0, f"漏洞扫描工具缺失: {missing}"


class TestToolDescriptions:
    """工具描述测试"""

    def test_tools_have_descriptions(self):
        """所有工具应有描述"""
        from TOSKill.AI.tools import ALL_TOOLS
        for tool in ALL_TOOLS:
            assert hasattr(tool, 'description'), f"工具 {tool.name} 缺失description"
            assert len(tool.description) > 10, f"工具 {tool.name} description太短"


class TestScriptManager:
    """脚本管理器测试"""

    def test_script_manager_import(self):
        """ScriptManager应可导入"""
        from TOSKill.AI.tools import ScriptManager, script_manager
        assert script_manager is not None

    @pytest.mark.asyncio
    async def test_generate_script_uses_unified_async_maas_client(self):
        from TOSKill.AI.tools import script_manager
        from TOSKill.config import settings

        maas_client = MagicMock()
        maas_client.complete = AsyncMock(return_value=(
            "```python\n"
            "def run(target: str):\n"
            "    return {'success': True, 'data': {}, 'error': None, "
            "'auth_info': None, 'timestamp': 'test'}\n"
            "```"
        ))

        with patch("TOSKill.AI.maas_client.get_maas_client", return_value=maas_client):
            code = await script_manager.generate_script_with_ai("收集页面标题")

        assert code.startswith("def run(target: str):")
        request = maas_client.complete.await_args.kwargs
        assert request["max_tokens"] == settings.SCRIPT_GENERATION_MAX_TOKENS
        assert request["timeout"] == settings.SCRIPT_GENERATION_TIMEOUT
        assert request["max_retries"] == settings.SCRIPT_GENERATION_MAX_RETRIES
        assert request["messages"][0]["role"] == "system"

    def test_list_registered_scripts(self):
        """get_registered_scripts返回数据"""
        from TOSKill.AI.tools import script_manager
        scripts = script_manager.get_registered_scripts()
        assert isinstance(scripts, dict)
