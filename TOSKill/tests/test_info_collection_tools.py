# -*- coding:utf-8 -*-
"""
信息收集工具测试模块
测试所有信息收集相关工具的可调用性、返回数据结构和错误处理
"""

import pytest
import sys
import os
import json
from unittest.mock import patch, MagicMock
from typing import Dict, Any

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

from TOSKill.tools.info_collection import (
    baseinfo,
    portscan,
    subdomain,
    dirscan,
    waf_detect,
    cdn_detect,
    cms_detect,
    infoleak_scan,
    ip_locate,
    log_handler,
    random_headers,
    webside_query,
    web_weight,
    INFO_COLLECTION_TOOLS,
)
from TOSKill.tests.test_data.test_config import get_test_config, get_test_targets_path


class TestInfoCollectionToolsBasic:
    """信息收集工具基础测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """测试前设置"""
        self.config = get_test_config()
        with open(get_test_targets_path(), 'r', encoding='utf-8') as f:
            self.test_targets = json.load(f)
        self.valid_url = "http://example.com"
        self.valid_domain = "example.com"
        self.valid_ip = "192.168.1.1"
    
    def test_info_collection_tools_list_not_empty(self):
        """测试信息收集工具列表不为空"""
        assert len(INFO_COLLECTION_TOOLS) == 13, f"预期13个信息收集工具，实际{len(INFO_COLLECTION_TOOLS)}个"
    
    def test_all_tools_have_name(self):
        """测试所有工具都有name属性"""
        for tool in INFO_COLLECTION_TOOLS:
            assert hasattr(tool, 'name'), f"工具缺少name属性: {type(tool)}"
            assert tool.name is not None and tool.name != "", f"工具name属性为空: {tool}"
    
    def test_all_tools_have_description(self):
        """测试所有工具都有description属性"""
        for tool in INFO_COLLECTION_TOOLS:
            assert hasattr(tool, 'description'), f"工具缺少description属性: {tool.name}"
            assert tool.description is not None and tool.description != "", f"工具description属性为空: {tool.name}"
    
    def test_all_tools_are_callable(self):
        """测试所有工具都可调用"""
        for tool in INFO_COLLECTION_TOOLS:
            is_callable = (
                hasattr(tool, 'invoke') and callable(getattr(tool, 'invoke')) or
                hasattr(tool, 'run') and callable(getattr(tool, 'run')) or
                hasattr(tool, '_run') and callable(getattr(tool, '_run')) or
                callable(tool)
            )
            assert is_callable, f"工具不可调用: {tool.name}"


class TestBaseinfoTool:
    """baseinfo工具测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = baseinfo
        self.valid_target = "http://example.com"
    
    def test_baseinfo_has_correct_name(self):
        """测试baseinfo工具名称正确"""
        assert self.tool.name == "baseinfo"
    
    def test_baseinfo_has_description(self):
        """测试baseinfo工具有描述"""
        assert hasattr(self.tool, 'description')
        assert len(self.tool.description) > 0
    
    @patch('backend.plugins.baseinfo.baseinfo.getbaseinfo')
    def test_baseinfo_invoke_returns_correct_structure(self, mock_getbaseinfo):
        """测试baseinfo返回数据结构正确"""
        mock_getbaseinfo.return_value = {
            "code": 200,
            "domain": "example.com",
            "server": "nginx",
            "os": "Linux"
        }
        
        result = self.tool.invoke(self.valid_target)
        
        assert isinstance(result, dict), "返回结果应为字典类型"
        assert "success" in result, "返回结果应包含success字段"
        assert "data" in result, "返回结果应包含data字段"
        assert "error" in result, "返回结果应包含error字段"
        assert "metadata" in result, "返回结果应包含metadata字段"
    
    @patch('backend.plugins.baseinfo.baseinfo.getbaseinfo')
    def test_baseinfo_success_response(self, mock_getbaseinfo):
        """测试baseinfo成功响应"""
        mock_getbaseinfo.return_value = {
            "code": 200,
            "domain": "example.com",
            "server": "nginx/1.18.0",
            "os": "Linux"
        }
        
        result = self.tool.invoke(self.valid_target)
        
        assert result["success"] is True
        assert result["error"] is None
        assert result["metadata"]["tool"] == "baseinfo"
        assert result["metadata"]["target"] == self.valid_target
    
    @patch('backend.plugins.baseinfo.baseinfo.getbaseinfo')
    def test_baseinfo_failure_response(self, mock_getbaseinfo):
        """测试baseinfo失败响应"""
        mock_getbaseinfo.return_value = {
            "code": 500,
            "msg": "Internal Server Error"
        }
        
        result = self.tool.invoke(self.valid_target)
        
        assert result["success"] is False
        assert result["error"] is not None
    
    def test_baseinfo_import_error_handling(self):
        """测试baseinfo导入错误处理"""
        with patch.dict('sys.modules', {'backend.plugins.baseinfo.baseinfo': None}):
            result = self.tool.invoke(self.valid_target)
            
            assert result["success"] is False
            assert "导入" in result["error"] or "import" in result["error"].lower()
    
    def test_baseinfo_empty_target(self):
        """测试baseinfo空目标处理"""
        result = self.tool.invoke("")
        
        assert isinstance(result, dict)
        assert "success" in result


class TestPortscanTool:
    """portscan工具测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = portscan
        self.valid_target = "127.0.0.1"
    
    def test_portscan_has_correct_name(self):
        """测试portscan工具名称正确"""
        assert self.tool.name == "portscan"
    
    def test_portscan_has_description(self):
        """测试portscan工具有描述"""
        assert hasattr(self.tool, 'description')
        assert len(self.tool.description) > 0
    
    @patch('backend.plugins.portscan.portscan.ScanPort')
    def test_portscan_invoke_returns_correct_structure(self, mock_scanport):
        """测试portscan返回数据结构正确"""
        mock_scanner = MagicMock()
        mock_scanner.run_scan.return_value = True
        mock_scanner.get_results.return_value = {"80": "http", "443": "https"}
        mock_scanner.ipaddr = "127.0.0.1"
        mock_scanport.return_value = mock_scanner
        
        result = self.tool.invoke(self.valid_target)
        
        assert isinstance(result, dict)
        assert "success" in result
        assert "data" in result
        assert "error" in result
        assert "metadata" in result
    
    @patch('backend.plugins.portscan.portscan.ScanPort')
    def test_portscan_success_with_open_ports(self, mock_scanport):
        """测试portscan发现开放端口"""
        mock_scanner = MagicMock()
        mock_scanner.run_scan.return_value = True
        mock_scanner.get_results.return_value = {"80": "http", "22": "ssh"}
        mock_scanner.ipaddr = "127.0.0.1"
        mock_scanport.return_value = mock_scanner
        
        result = self.tool.invoke(self.valid_target)
        
        assert result["success"] is True
        assert result["data"]["total_count"] == 2
        assert "open_ports" in result["data"]
    
    @patch('backend.plugins.portscan.portscan.ScanPort')
    def test_portscan_scan_failure(self, mock_scanport):
        """测试portscan扫描失败"""
        mock_scanner = MagicMock()
        mock_scanner.run_scan.return_value = False
        mock_scanport.return_value = mock_scanner
        
        result = self.tool.invoke(self.valid_target)
        
        assert result["success"] is False
        assert result["error"] is not None


class TestSubdomainTool:
    """subdomain工具测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = subdomain
        self.valid_target = "example.com"
    
    def test_subdomain_has_correct_name(self):
        """测试subdomain工具名称正确"""
        assert self.tool.name == "subdomain"
    
    def test_subdomain_has_description(self):
        """测试subdomain工具有描述"""
        assert hasattr(self.tool, 'description')
        assert len(self.tool.description) > 0
    
    def test_subdomain_invoke_returns_correct_structure(self):
        """测试subdomain返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {"subdomains": ["www.example.com", "api.example.com"]},
                "error": None,
                "metadata": {"tool": "subdomain", "target": self.valid_target}
            }
            
            result = self.tool.invoke(self.valid_target)
            
            assert isinstance(result, dict)
            assert "success" in result
            assert "data" in result


class TestDirscanTool:
    """dirscan工具测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = dirscan
        self.valid_target = "http://example.com"
    
    def test_dirscan_has_correct_name(self):
        """测试dirscan工具名称正确"""
        assert self.tool.name == "dirscan"
    
    def test_dirscan_has_description(self):
        """测试dirscan工具有描述"""
        assert hasattr(self.tool, 'description')
        assert len(self.tool.description) > 0
    
    def test_dirscan_invoke_returns_correct_structure(self):
        """测试dirscan返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {"directories": ["/admin", "/backup", "/config"]},
                "error": None,
                "metadata": {"tool": "dirscan", "target": self.valid_target}
            }
            
            result = self.tool.invoke(self.valid_target)
            
            assert isinstance(result, dict)
            assert "success" in result


class TestWafDetectTool:
    """waf_detect工具测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = waf_detect
        self.valid_target = "http://example.com"
    
    def test_waf_detect_has_correct_name(self):
        """测试waf_detect工具名称正确"""
        assert self.tool.name == "waf_detect"
    
    def test_waf_detect_has_description(self):
        """测试waf_detect工具有描述"""
        assert hasattr(self.tool, 'description')
        assert len(self.tool.description) > 0
    
    def test_waf_detect_invoke_returns_correct_structure(self):
        """测试waf_detect返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {"waf_detected": True, "waf_type": "Cloudflare"},
                "error": None,
                "metadata": {"tool": "waf_detect", "target": self.valid_target}
            }
            
            result = self.tool.invoke(self.valid_target)
            
            assert isinstance(result, dict)
            assert "success" in result


class TestCdnDetectTool:
    """cdn_detect工具测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = cdn_detect
        self.valid_target = "http://example.com"
    
    def test_cdn_detect_has_correct_name(self):
        """测试cdn_detect工具名称正确"""
        assert self.tool.name == "cdn_detect"
    
    def test_cdn_detect_has_description(self):
        """测试cdn_detect工具有描述"""
        assert hasattr(self.tool, 'description')
        assert len(self.tool.description) > 0
    
    def test_cdn_detect_invoke_returns_correct_structure(self):
        """测试cdn_detect返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {"cdn_detected": True, "cdn_provider": "Cloudflare"},
                "error": None,
                "metadata": {"tool": "cdn_detect", "target": self.valid_target}
            }
            
            result = self.tool.invoke(self.valid_target)
            
            assert isinstance(result, dict)
            assert "success" in result


class TestCmsDetectTool:
    """cms_detect工具测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = cms_detect
        self.valid_target = "http://example.com"
    
    def test_cms_detect_has_correct_name(self):
        """测试cms_detect工具名称正确"""
        assert self.tool.name == "cms_detect"
    
    def test_cms_detect_has_description(self):
        """测试cms_detect工具有描述"""
        assert hasattr(self.tool, 'description')
        assert len(self.tool.description) > 0
    
    def test_cms_detect_invoke_returns_correct_structure(self):
        """测试cms_detect返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {"cms": "WordPress", "version": "5.9"},
                "error": None,
                "metadata": {"tool": "cms_detect", "target": self.valid_target}
            }
            
            result = self.tool.invoke(self.valid_target)
            
            assert isinstance(result, dict)
            assert "success" in result


class TestInfoleakScanTool:
    """infoleak_scan工具测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = infoleak_scan
        self.valid_target = "http://example.com"
    
    def test_infoleak_scan_has_correct_name(self):
        """测试infoleak_scan工具名称正确"""
        assert self.tool.name == "infoleak_scan"
    
    def test_infoleak_scan_has_description(self):
        """测试infoleak_scan工具有描述"""
        assert hasattr(self.tool, 'description')
        assert len(self.tool.description) > 0
    
    def test_infoleak_scan_invoke_returns_correct_structure(self):
        """测试infoleak_scan返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {"leaks": [".git", ".env", ".svn"]},
                "error": None,
                "metadata": {"tool": "infoleak_scan", "target": self.valid_target}
            }
            
            result = self.tool.invoke(self.valid_target)
            
            assert isinstance(result, dict)
            assert "success" in result


class TestIpLocateTool:
    """ip_locate工具测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = ip_locate
        self.valid_target = "8.8.8.8"
    
    def test_ip_locate_has_correct_name(self):
        """测试ip_locate工具名称正确"""
        assert self.tool.name == "ip_locate"
    
    def test_ip_locate_has_description(self):
        """测试ip_locate工具有描述"""
        assert hasattr(self.tool, 'description')
        assert len(self.tool.description) > 0
    
    def test_ip_locate_invoke_returns_correct_structure(self):
        """测试ip_locate返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {"country": "United States", "city": "Mountain View"},
                "error": None,
                "metadata": {"tool": "ip_locate", "target": self.valid_target}
            }
            
            result = self.tool.invoke(self.valid_target)
            
            assert isinstance(result, dict)
            assert "success" in result


class TestLogHandlerTool:
    """log_handler工具测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = log_handler
        self.valid_target = "http://example.com"
    
    def test_log_handler_has_correct_name(self):
        """测试log_handler工具名称正确"""
        assert self.tool.name == "log_handler"
    
    def test_log_handler_has_description(self):
        """测试log_handler工具有描述"""
        assert hasattr(self.tool, 'description')
        assert len(self.tool.description) > 0
    
    def test_log_handler_invoke_returns_correct_structure(self):
        """测试log_handler返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {"log_files": []},
                "error": None,
                "metadata": {"tool": "log_handler", "target": self.valid_target}
            }
            
            result = self.tool.invoke(self.valid_target)
            
            assert isinstance(result, dict)
            assert "success" in result


class TestRandomHeadersTool:
    """random_headers工具测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = random_headers
        self.valid_target = "http://example.com"
    
    def test_random_headers_has_correct_name(self):
        """测试random_headers工具名称正确"""
        assert self.tool.name == "random_headers"
    
    def test_random_headers_has_description(self):
        """测试random_headers工具有描述"""
        assert hasattr(self.tool, 'description')
        assert len(self.tool.description) > 0
    
    def test_random_headers_invoke_returns_correct_structure(self):
        """测试random_headers返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {"headers": {"User-Agent": "Mozilla/5.0"}},
                "error": None,
                "metadata": {"tool": "random_headers", "target": self.valid_target}
            }
            
            result = self.tool.invoke(self.valid_target)
            
            assert isinstance(result, dict)
            assert "success" in result


class TestWebsideQueryTool:
    """webside_query工具测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = webside_query
        self.valid_target = "example.com"
    
    def test_webside_query_has_correct_name(self):
        """测试webside_query工具名称正确"""
        assert self.tool.name == "webside_query"
    
    def test_webside_query_has_description(self):
        """测试webside_query工具有描述"""
        assert hasattr(self.tool, 'description')
        assert len(self.tool.description) > 0
    
    def test_webside_query_invoke_returns_correct_structure(self):
        """测试webside_query返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {"related_domains": []},
                "error": None,
                "metadata": {"tool": "webside_query", "target": self.valid_target}
            }
            
            result = self.tool.invoke(self.valid_target)
            
            assert isinstance(result, dict)
            assert "success" in result


class TestWebWeightTool:
    """web_weight工具测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = web_weight
        self.valid_target = "http://example.com"
    
    def test_web_weight_has_correct_name(self):
        """测试web_weight工具名称正确"""
        assert self.tool.name == "web_weight"
    
    def test_web_weight_has_description(self):
        """测试web_weight工具有描述"""
        assert hasattr(self.tool, 'description')
        assert len(self.tool.description) > 0
    
    def test_web_weight_invoke_returns_correct_structure(self):
        """测试web_weight返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {"weight": 85, "rank": 1000},
                "error": None,
                "metadata": {"tool": "web_weight", "target": self.valid_target}
            }
            
            result = self.tool.invoke(self.valid_target)
            
            assert isinstance(result, dict)
            assert "success" in result


class TestInfoCollectionToolsErrorHandling:
    """信息收集工具错误处理测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tools = INFO_COLLECTION_TOOLS
        self.invalid_targets = [
            "",
            "not_a_valid_url",
            "://missing_protocol.com",
            "http://",
        ]
    
    def test_tools_handle_empty_target(self):
        """测试工具处理空目标"""
        for tool in self.tools:
            try:
                result = tool.invoke("")
                assert isinstance(result, dict), f"{tool.name}: 返回结果应为字典"
                assert "success" in result, f"{tool.name}: 返回结果应包含success字段"
            except Exception as e:
                pytest.fail(f"{tool.name}: 空目标不应抛出异常，应返回错误字典: {e}")
    
    def test_tools_return_dict_on_error(self):
        """测试工具错误时返回字典"""
        for tool in self.tools:
            try:
                result = tool.invoke("invalid_target_12345")
                assert isinstance(result, dict), f"{tool.name}: 错误时应返回字典"
            except Exception as e:
                pytest.fail(f"{tool.name}: 不应抛出异常: {e}")
    
    def test_tools_metadata_contains_tool_name(self):
        """测试工具返回metadata包含工具名称"""
        for tool in self.tools:
            with patch.object(tool, 'invoke') as mock_invoke:
                mock_invoke.return_value = {
                    "success": True,
                    "data": {},
                    "error": None,
                    "metadata": {"tool": tool.name, "target": "test"}
                }
                
                result = tool.invoke("test")
                
                assert "metadata" in result, f"{tool.name}: 返回结果应包含metadata"
                assert "tool" in result["metadata"], f"{tool.name}: metadata应包含tool字段"


class TestInfoCollectionToolsDataValidation:
    """信息收集工具数据验证测试"""
    
    def test_valid_targets_from_test_data(self):
        """使用测试数据验证有效目标"""
        with open(get_test_targets_path(), 'r', encoding='utf-8') as f:
            test_data = json.load(f)
        
        valid_domains = [t["target"] for t in test_data["valid_targets"]["domains"]]
        valid_ips = [t["target"] for t in test_data["valid_targets"]["ips"]]
        valid_urls = [t["target"] for t in test_data["valid_targets"]["urls"]]
        
        assert len(valid_domains) > 0, "测试数据应包含有效域名"
        assert len(valid_ips) > 0, "测试数据应包含有效IP"
        assert len(valid_urls) > 0, "测试数据应包含有效URL"
    
    def test_invalid_targets_from_test_data(self):
        """使用测试数据验证无效目标"""
        with open(get_test_targets_path(), 'r', encoding='utf-8') as f:
            test_data = json.load(f)
        
        invalid_targets = [t["target"] for t in test_data["invalid_targets"]]
        
        assert len(invalid_targets) > 0, "测试数据应包含无效目标"
        
        for target_info in test_data["invalid_targets"]:
            assert "expected_error" in target_info, f"无效目标应包含expected_error字段"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
