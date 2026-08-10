"""
TOSKill 工具注册与执行测试
验证22个工具的注册状态、参数验证
"""
import pytest
from unittest.mock import MagicMock, patch


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

    @pytest.mark.parametrize("tool_name", ["sqli_scan", "xss_scan"])
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

    def test_webside_query_propagates_tool_error(self):
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

        assert result["success"] is False
        assert result["error"] == "query failed"


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

    def test_list_registered_scripts(self):
        """get_registered_scripts返回数据"""
        from TOSKill.AI.tools import script_manager
        scripts = script_manager.get_registered_scripts()
        assert isinstance(scripts, dict)
