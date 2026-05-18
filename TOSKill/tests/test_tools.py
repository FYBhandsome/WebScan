"""
TOSKill 工具注册与执行测试
验证22个工具的注册状态、参数验证
"""
import pytest
from unittest.mock import MagicMock, patch


class TestToolRegistry:
    """工具注册表测试"""

    def test_all_tools_count(self):
        """全部工具至少有22个"""
        from TOSKill.AI.tools import ALL_TOOLS
        assert len(ALL_TOOLS) >= 22, f"期望22+工具，实际{len(ALL_TOOLS)}"

    def test_info_tools_count(self):
        """信息收集工具至少有11个"""
        from TOSKill.AI.tools import INFO_COLLECTION_TOOLS
        assert len(INFO_COLLECTION_TOOLS) >= 11

    def test_vuln_tools_count(self):
        """漏洞扫描工具至少有11个"""
        from TOSKill.AI.tools import VULN_SCAN_TOOLS
        assert len(VULN_SCAN_TOOLS) >= 11

    def test_get_tool_by_name(self):
        """按名查找工具"""
        from TOSKill.AI.tools import get_tool_by_name
        tool = get_tool_by_name("baseinfo")
        assert tool is not None

    def test_get_nonexistent_tool(self):
        """查找不存在的工具返回None"""
        from TOSKill.AI.tools import get_tool_by_name
        tool = get_tool_by_name("nonexistent_tool")
        assert tool is None

    def test_get_tool_sequence(self):
        """获取工具序列"""
        from TOSKill.AI.tools import get_tool_sequence
        seq = get_tool_sequence("info")
        assert len(seq) > 0

    def test_get_all_tool_names(self):
        """获取全部工具名"""
        from TOSKill.AI.tools import get_all_tool_names
        names = get_all_tool_names()
        assert "baseinfo" in names
        assert len(names) >= 22

    def test_clean_target_basic(self):
        """目标URL清理"""
        from TOSKill.AI.tools import clean_target
        assert clean_target("https://example.com/") == "example.com"
        assert clean_target("http://test.com:8080/") == "test.com"


class TestToolIntegrity:
    """工具完整性检查"""

    REQUIRED_INFO_TOOLS = ["baseinfo", "portscan", "subdomain", "dirscan", "waf_detect",
                           "cdn_detect", "cms_detect", "infoleak", "ip_locate",
                           "webside_query", "web_weight"]
    REQUIRED_VULN_TOOLS = ["sqli", "xss", "csrf", "fileupload", "cmdi",
                           "ssrf", "path_traversal", "auth_bypass", "rce", "xxe",
                           "idor"]

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


class TestTargetClean:
    """URL清理测试"""

    def test_clean_with_http(self):
        from TOSKill.AI.tools import clean_target
        assert "example.com" == clean_target("http://example.com")

    def test_clean_with_https_port(self):
        from TOSKill.AI.tools import clean_target
        result = clean_target("https://test.com:8443/")
        assert "test.com" in result

    def test_clean_ip(self):
        from TOSKill.AI.tools import clean_target
        result = clean_target("http://192.168.1.1:8080/admin")
        assert "192.168.1.1" in result

    def test_clean_blank(self):
        from TOSKill.AI.tools import clean_target
        result = clean_target("")
        assert result == ""


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
        assert isinstance(scripts, list)

    def test_register_script_valid(self, sample_script_content):
        """注册有效脚本"""
        from TOSKill.AI.tools import script_manager
        with patch.object(script_manager, 'analyze_script_with_ai',
                          return_value={"name": "test_script", "description": "测试脚本", "success": True}):
            with patch('TOSKill.AI.script_safety.validate_script_full') as mock_val:
                mock_val.return_value = MagicMock(passed=True, warnings=[])
                result = script_manager.register_script(
                    script_content=sample_script_content,
                    script_name="test_script",
                    user_id="test_user"
                )
                assert result is not None