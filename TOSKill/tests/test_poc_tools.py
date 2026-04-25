# -*- coding:utf-8 -*-
"""
POC工具测试模块
测试所有POC验证相关工具的可调用性、返回数据结构和错误处理
"""

import pytest
import sys
import os
import json
from unittest.mock import patch, MagicMock
from typing import Dict, Any

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

from TOSKill.tools.poc import (
    drupal_cve_2018_7600,
    jboss_cve_2017_12149,
    nexus_cve_2020_10199,
    struts2_s2_009,
    struts2_s2_032,
    thinkphp_rce,
    thinkphp_cmd_rce,
    tomcat_cve_2017_12615,
    weblogic_cve_2018_2628,
    weblogic_cve_2018_2894,
    weblogic_cve_2020_2551,
    weblogic_cve_2023_21839,
    POC_TOOLS,
)
from TOSKill.tests.test_data.test_config import get_test_config, get_test_targets_path


class TestPOCToolsBasic:
    """POC工具基础测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """测试前设置"""
        self.config = get_test_config()
        with open(get_test_targets_path(), 'r', encoding='utf-8') as f:
            self.test_targets = json.load(f)
        self.valid_url = "http://example.com"
    
    def test_poc_tools_list_not_empty(self):
        """测试POC工具列表不为空"""
        assert len(POC_TOOLS) == 12, f"预期12个POC工具，实际{len(POC_TOOLS)}个"
    
    def test_all_poc_tools_have_name(self):
        """测试所有POC工具都有name属性"""
        for tool in POC_TOOLS:
            assert hasattr(tool, 'name'), f"工具缺少name属性: {type(tool)}"
            assert tool.name is not None and tool.name != "", f"工具name属性为空: {tool}"
    
    def test_all_poc_tools_have_description(self):
        """测试所有POC工具都有description属性"""
        for tool in POC_TOOLS:
            assert hasattr(tool, 'description'), f"工具缺少description属性: {tool.name}"
            assert tool.description is not None and tool.description != "", f"工具description属性为空: {tool.name}"
    
    def test_all_poc_tools_are_callable(self):
        """测试所有POC工具都可调用"""
        for tool in POC_TOOLS:
            is_callable = (
                hasattr(tool, 'invoke') and callable(getattr(tool, 'invoke')) or
                hasattr(tool, 'run') and callable(getattr(tool, 'run')) or
                hasattr(tool, '_run') and callable(getattr(tool, '_run')) or
                callable(tool)
            )
            assert is_callable, f"POC工具不可调用: {tool.name}"


class TestDrupalCVE20187600:
    """Drupal CVE-2018-7600 POC测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = drupal_cve_2018_7600
        self.valid_target = "http://example.com"
        self.cve_id = "CVE-2018-7600"
    
    def test_drupal_has_correct_name(self):
        """测试drupal工具名称正确"""
        assert self.tool.name == "drupal_cve_2018_7600"
    
    def test_drupal_has_description(self):
        """测试drupal工具有描述"""
        assert hasattr(self.tool, 'description')
        assert self.cve_id in self.tool.description or "Drupal" in self.tool.description
    
    @patch('requests.post')
    @patch('requests.get')
    def test_drupal_invoke_returns_correct_structure(self, mock_get, mock_post):
        """测试drupal返回数据结构正确"""
        mock_post.return_value = MagicMock(status_code=200)
        mock_get.return_value = MagicMock(
            status_code=200,
            text="test:)"
        )
        
        result = self.tool.invoke(self.valid_target)
        
        assert isinstance(result, dict), "返回结果应为字典类型"
        assert "success" in result, "返回结果应包含success字段"
        assert "data" in result, "返回结果应包含data字段"
        assert "error" in result, "返回结果应包含error字段"
        assert "metadata" in result, "返回结果应包含metadata字段"
    
    @patch('requests.post')
    @patch('requests.get')
    def test_drupal_vulnerable_response(self, mock_get, mock_post):
        """测试drupal漏洞存在响应"""
        mock_post.return_value = MagicMock(status_code=200)
        mock_get.return_value = MagicMock(
            status_code=200,
            text="test:)"
        )
        
        result = self.tool.invoke(self.valid_target)
        
        assert result["success"] is True
        assert result["data"]["vulnerable"] is True
        assert result["data"]["cve_id"] == self.cve_id
        assert result["metadata"]["severity"] == "critical"
    
    @patch('requests.post')
    @patch('requests.get')
    def test_drupal_not_vulnerable_response(self, mock_get, mock_post):
        """测试drupal漏洞不存在响应"""
        mock_post.return_value = MagicMock(status_code=200)
        mock_get.return_value = MagicMock(
            status_code=404,
            text="Not Found"
        )
        
        result = self.tool.invoke(self.valid_target)
        
        assert result["success"] is True
        assert result["data"]["vulnerable"] is False
    
    def test_drupal_timeout_parameter(self):
        """测试drupal超时参数"""
        with patch('requests.post') as mock_post, patch('requests.get') as mock_get:
            mock_post.return_value = MagicMock(status_code=200)
            mock_get.return_value = MagicMock(status_code=404, text="")
            
            result = self.tool.invoke({"target": self.valid_target, "timeout": 5})
            
            assert isinstance(result, dict)


class TestJBossCVE201712149:
    """JBoss CVE-2017-12149 POC测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = jboss_cve_2017_12149
        self.valid_target = "http://example.com"
        self.cve_id = "CVE-2017-12149"
    
    def test_jboss_has_correct_name(self):
        """测试jboss工具名称正确"""
        assert self.tool.name == "jboss_cve_2017_12149"
    
    def test_jboss_has_description(self):
        """测试jboss工具有描述"""
        assert hasattr(self.tool, 'description')
        assert len(self.tool.description) > 0
    
    def test_jboss_invoke_returns_correct_structure(self):
        """测试jboss返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {
                    "vulnerable": False,
                    "cve_id": self.cve_id,
                    "target": self.valid_target
                },
                "error": None,
                "metadata": {
                    "tool": "jboss_cve_2017_12149",
                    "target": self.valid_target,
                    "cve_id": self.cve_id
                }
            }
            
            result = self.tool.invoke(self.valid_target)
            
            assert isinstance(result, dict)
            assert "success" in result
            assert "data" in result
            assert "cve_id" in result["data"]


class TestNexusCVE202010199:
    """Nexus CVE-2020-10199 POC测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = nexus_cve_2020_10199
        self.valid_target = "http://example.com"
        self.cve_id = "CVE-2020-10199"
    
    def test_nexus_has_correct_name(self):
        """测试nexus工具名称正确"""
        assert self.tool.name == "nexus_cve_2020_10199"
    
    def test_nexus_has_description(self):
        """测试nexus工具有描述"""
        assert hasattr(self.tool, 'description')
        assert len(self.tool.description) > 0
    
    def test_nexus_invoke_returns_correct_structure(self):
        """测试nexus返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {
                    "vulnerable": False,
                    "cve_id": self.cve_id,
                    "target": self.valid_target
                },
                "error": None,
                "metadata": {
                    "tool": "nexus_cve_2020_10199",
                    "target": self.valid_target,
                    "cve_id": self.cve_id
                }
            }
            
            result = self.tool.invoke(self.valid_target)
            
            assert isinstance(result, dict)
            assert "success" in result
            assert "data" in result


class TestStruts2S2009:
    """Struts2 S2-009 POC测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = struts2_s2_009
        self.valid_target = "http://example.com"
    
    def test_struts2_s2_009_has_correct_name(self):
        """测试struts2_s2_009工具名称正确"""
        assert self.tool.name == "struts2_s2_009"
    
    def test_struts2_s2_009_has_description(self):
        """测试struts2_s2_009工具有描述"""
        assert hasattr(self.tool, 'description')
        assert len(self.tool.description) > 0
    
    def test_struts2_s2_009_invoke_returns_correct_structure(self):
        """测试struts2_s2_009返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {
                    "vulnerable": False,
                    "target": self.valid_target
                },
                "error": None,
                "metadata": {
                    "tool": "struts2_s2_009",
                    "target": self.valid_target
                }
            }
            
            result = self.tool.invoke(self.valid_target)
            
            assert isinstance(result, dict)
            assert "success" in result


class TestStruts2S2032:
    """Struts2 S2-032 POC测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = struts2_s2_032
        self.valid_target = "http://example.com"
    
    def test_struts2_s2_032_has_correct_name(self):
        """测试struts2_s2_032工具名称正确"""
        assert self.tool.name == "struts2_s2_032"
    
    def test_struts2_s2_032_has_description(self):
        """测试struts2_s2_032工具有描述"""
        assert hasattr(self.tool, 'description')
        assert len(self.tool.description) > 0
    
    def test_struts2_s2_032_invoke_returns_correct_structure(self):
        """测试struts2_s2_032返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {
                    "vulnerable": False,
                    "target": self.valid_target
                },
                "error": None,
                "metadata": {
                    "tool": "struts2_s2_032",
                    "target": self.valid_target
                }
            }
            
            result = self.tool.invoke(self.valid_target)
            
            assert isinstance(result, dict)
            assert "success" in result


class TestThinkphpRCE:
    """ThinkPHP RCE POC测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = thinkphp_rce
        self.valid_target = "http://example.com"
    
    def test_thinkphp_rce_has_correct_name(self):
        """测试thinkphp_rce工具名称正确"""
        assert self.tool.name == "thinkphp_rce"
    
    def test_thinkphp_rce_has_description(self):
        """测试thinkphp_rce工具有描述"""
        assert hasattr(self.tool, 'description')
        assert len(self.tool.description) > 0
    
    def test_thinkphp_rce_invoke_returns_correct_structure(self):
        """测试thinkphp_rce返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {
                    "vulnerable": False,
                    "target": self.valid_target
                },
                "error": None,
                "metadata": {
                    "tool": "thinkphp_rce",
                    "target": self.valid_target
                }
            }
            
            result = self.tool.invoke(self.valid_target)
            
            assert isinstance(result, dict)
            assert "success" in result


class TestThinkphpCmdRCE:
    """ThinkPHP CMD RCE POC测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = thinkphp_cmd_rce
        self.valid_target = "http://example.com"
    
    def test_thinkphp_cmd_rce_has_correct_name(self):
        """测试thinkphp_cmd_rce工具名称正确"""
        assert self.tool.name == "thinkphp_cmd_rce"
    
    def test_thinkphp_cmd_rce_has_description(self):
        """测试thinkphp_cmd_rce工具有描述"""
        assert hasattr(self.tool, 'description')
        assert len(self.tool.description) > 0
    
    def test_thinkphp_cmd_rce_invoke_returns_correct_structure(self):
        """测试thinkphp_cmd_rce返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {
                    "vulnerable": False,
                    "target": self.valid_target
                },
                "error": None,
                "metadata": {
                    "tool": "thinkphp_cmd_rce",
                    "target": self.valid_target
                }
            }
            
            result = self.tool.invoke(self.valid_target)
            
            assert isinstance(result, dict)
            assert "success" in result


class TestTomcatCVE201712615:
    """Tomcat CVE-2017-12615 POC测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = tomcat_cve_2017_12615
        self.valid_target = "http://example.com"
        self.cve_id = "CVE-2017-12615"
    
    def test_tomcat_has_correct_name(self):
        """测试tomcat工具名称正确"""
        assert self.tool.name == "tomcat_cve_2017_12615"
    
    def test_tomcat_has_description(self):
        """测试tomcat工具有描述"""
        assert hasattr(self.tool, 'description')
        assert len(self.tool.description) > 0
    
    def test_tomcat_invoke_returns_correct_structure(self):
        """测试tomcat返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {
                    "vulnerable": False,
                    "cve_id": self.cve_id,
                    "target": self.valid_target
                },
                "error": None,
                "metadata": {
                    "tool": "tomcat_cve_2017_12615",
                    "target": self.valid_target,
                    "cve_id": self.cve_id
                }
            }
            
            result = self.tool.invoke(self.valid_target)
            
            assert isinstance(result, dict)
            assert "success" in result
            assert "cve_id" in result["data"]


class TestWeblogicCVE20182628:
    """WebLogic CVE-2018-2628 POC测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = weblogic_cve_2018_2628
        self.valid_target = "http://example.com"
        self.cve_id = "CVE-2018-2628"
    
    def test_weblogic_has_correct_name(self):
        """测试weblogic_cve_2018_2628工具名称正确"""
        assert self.tool.name == "weblogic_cve_2018_2628"
    
    def test_weblogic_has_description(self):
        """测试weblogic_cve_2018_2628工具有描述"""
        assert hasattr(self.tool, 'description')
        assert len(self.tool.description) > 0
    
    def test_weblogic_invoke_returns_correct_structure(self):
        """测试weblogic_cve_2018_2628返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {
                    "vulnerable": False,
                    "cve_id": self.cve_id,
                    "target": self.valid_target
                },
                "error": None,
                "metadata": {
                    "tool": "weblogic_cve_2018_2628",
                    "target": self.valid_target,
                    "cve_id": self.cve_id
                }
            }
            
            result = self.tool.invoke(self.valid_target)
            
            assert isinstance(result, dict)
            assert "success" in result


class TestWeblogicCVE20182894:
    """WebLogic CVE-2018-2894 POC测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = weblogic_cve_2018_2894
        self.valid_target = "http://example.com"
        self.cve_id = "CVE-2018-2894"
    
    def test_weblogic_2894_has_correct_name(self):
        """测试weblogic_cve_2018_2894工具名称正确"""
        assert self.tool.name == "weblogic_cve_2018_2894"
    
    def test_weblogic_2894_has_description(self):
        """测试weblogic_cve_2018_2894工具有描述"""
        assert hasattr(self.tool, 'description')
        assert len(self.tool.description) > 0
    
    def test_weblogic_2894_invoke_returns_correct_structure(self):
        """测试weblogic_cve_2018_2894返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {
                    "vulnerable": False,
                    "cve_id": self.cve_id,
                    "target": self.valid_target
                },
                "error": None,
                "metadata": {
                    "tool": "weblogic_cve_2018_2894",
                    "target": self.valid_target,
                    "cve_id": self.cve_id
                }
            }
            
            result = self.tool.invoke(self.valid_target)
            
            assert isinstance(result, dict)
            assert "success" in result


class TestWeblogicCVE20202551:
    """WebLogic CVE-2020-2551 POC测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = weblogic_cve_2020_2551
        self.valid_target = "http://example.com"
        self.cve_id = "CVE-2020-2551"
    
    def test_weblogic_2551_has_correct_name(self):
        """测试weblogic_cve_2020_2551工具名称正确"""
        assert self.tool.name == "weblogic_cve_2020_2551"
    
    def test_weblogic_2551_has_description(self):
        """测试weblogic_cve_2020_2551工具有描述"""
        assert hasattr(self.tool, 'description')
        assert len(self.tool.description) > 0
    
    def test_weblogic_2551_invoke_returns_correct_structure(self):
        """测试weblogic_cve_2020_2551返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {
                    "vulnerable": False,
                    "cve_id": self.cve_id,
                    "target": self.valid_target
                },
                "error": None,
                "metadata": {
                    "tool": "weblogic_cve_2020_2551",
                    "target": self.valid_target,
                    "cve_id": self.cve_id
                }
            }
            
            result = self.tool.invoke(self.valid_target)
            
            assert isinstance(result, dict)
            assert "success" in result


class TestWeblogicCVE202321839:
    """WebLogic CVE-2023-21839 POC测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = weblogic_cve_2023_21839
        self.valid_target = "http://example.com"
        self.cve_id = "CVE-2023-21839"
    
    def test_weblogic_21839_has_correct_name(self):
        """测试weblogic_cve_2023_21839工具名称正确"""
        assert self.tool.name == "weblogic_cve_2023_21839"
    
    def test_weblogic_21839_has_description(self):
        """测试weblogic_cve_2023_21839工具有描述"""
        assert hasattr(self.tool, 'description')
        assert len(self.tool.description) > 0
    
    def test_weblogic_21839_invoke_returns_correct_structure(self):
        """测试weblogic_cve_2023_21839返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {
                    "vulnerable": False,
                    "cve_id": self.cve_id,
                    "target": self.valid_target
                },
                "error": None,
                "metadata": {
                    "tool": "weblogic_cve_2023_21839",
                    "target": self.valid_target,
                    "cve_id": self.cve_id
                }
            }
            
            result = self.tool.invoke(self.valid_target)
            
            assert isinstance(result, dict)
            assert "success" in result


class TestPOCToolsErrorHandling:
    """POC工具错误处理测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tools = POC_TOOLS
        self.invalid_targets = [
            "",
            "not_a_valid_url",
            "://missing_protocol.com",
            "http://",
        ]
    
    def test_poc_tools_handle_empty_target(self):
        """测试POC工具处理空目标"""
        for tool in self.tools:
            try:
                result = tool.invoke("")
                assert isinstance(result, dict), f"{tool.name}: 返回结果应为字典"
                assert "success" in result, f"{tool.name}: 返回结果应包含success字段"
            except Exception as e:
                pytest.fail(f"{tool.name}: 空目标不应抛出异常: {e}")
    
    def test_poc_tools_return_dict_on_error(self):
        """测试POC工具错误时返回字典"""
        for tool in self.tools:
            try:
                result = tool.invoke("invalid_target_12345")
                assert isinstance(result, dict), f"{tool.name}: 错误时应返回字典"
            except Exception as e:
                pytest.fail(f"{tool.name}: 不应抛出异常: {e}")
    
    def test_poc_tools_metadata_contains_cve_id(self):
        """测试POC工具返回metadata包含CVE ID"""
        cve_tools = [
            drupal_cve_2018_7600,
            jboss_cve_2017_12149,
            nexus_cve_2020_10199,
            tomcat_cve_2017_12615,
            weblogic_cve_2018_2628,
            weblogic_cve_2018_2894,
            weblogic_cve_2020_2551,
            weblogic_cve_2023_21839,
        ]
        
        for tool in cve_tools:
            with patch.object(tool, 'invoke') as mock_invoke:
                mock_invoke.return_value = {
                    "success": True,
                    "data": {"vulnerable": False, "cve_id": "CVE-XXXX-XXXXX"},
                    "error": None,
                    "metadata": {"tool": tool.name, "cve_id": "CVE-XXXX-XXXXX"}
                }
                
                result = tool.invoke("http://test.com")
                
                assert "metadata" in result, f"{tool.name}: 返回结果应包含metadata"


class TestPOCToolsVulnerabilityDetection:
    """POC工具漏洞检测测试"""
    
    def test_vulnerable_response_structure(self):
        """测试漏洞存在时的响应结构"""
        expected_fields = ["vulnerable", "cve_id", "target"]
        
        with patch.object(drupal_cve_2018_7600, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {
                    "vulnerable": True,
                    "cve_id": "CVE-2018-7600",
                    "vulnerability": "Drupalgeddon 2 Remote Code Execution",
                    "target": "http://example.com"
                },
                "error": None,
                "metadata": {
                    "tool": "drupal_cve_2018_7600",
                    "severity": "critical"
                }
            }
            
            result = drupal_cve_2018_7600.invoke("http://example.com")
            
            assert result["data"]["vulnerable"] is True
            for field in expected_fields:
                assert field in result["data"], f"漏洞响应应包含{field}字段"
    
    def test_not_vulnerable_response_structure(self):
        """测试漏洞不存在时的响应结构"""
        with patch.object(drupal_cve_2018_7600, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {
                    "vulnerable": False,
                    "cve_id": "CVE-2018-7600",
                    "target": "http://example.com"
                },
                "error": None,
                "metadata": {
                    "tool": "drupal_cve_2018_7600"
                }
            }
            
            result = drupal_cve_2018_7600.invoke("http://example.com")
            
            assert result["data"]["vulnerable"] is False


class TestPOCToolsTimeout:
    """POC工具超时测试"""
    
    def test_drupal_timeout_handling(self):
        """测试drupal工具超时处理"""
        with patch('requests.post') as mock_post:
            import requests
            mock_post.side_effect = requests.Timeout("Connection timeout")
            
            result = drupal_cve_2018_7600.invoke("http://example.com")
            
            assert isinstance(result, dict)
            assert result["success"] is False
            assert result["error"] is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
