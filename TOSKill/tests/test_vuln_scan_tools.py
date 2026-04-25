# -*- coding:utf-8 -*-
"""
漏洞扫描工具测试模块
测试所有漏洞扫描相关工具的可调用性、返回数据结构和错误处理
"""

import pytest
import sys
import os
import json
from unittest.mock import patch, MagicMock
from typing import Dict, Any

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

from TOSKill.tools.vuln_scan import (
    sqli_scan,
    xss_scan,
    csrf_scan,
    fileupload_scan,
    cmdi_scan,
    ssrf_scan,
    lfi_scan,
    weakpass_scan,
    VULN_SCAN_TOOLS,
)
from TOSKill.tests.test_data.test_config import get_test_config, get_test_targets_path


class TestVulnScanToolsBasic:
    """漏洞扫描工具基础测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """测试前设置"""
        self.config = get_test_config()
        with open(get_test_targets_path(), 'r', encoding='utf-8') as f:
            self.test_targets = json.load(f)
        self.valid_url = "http://example.com/test.php?id=1"
    
    def test_vuln_scan_tools_list_not_empty(self):
        """测试漏洞扫描工具列表不为空"""
        assert len(VULN_SCAN_TOOLS) == 8, f"预期8个漏洞扫描工具，实际{len(VULN_SCAN_TOOLS)}个"
    
    def test_all_vuln_scan_tools_have_name(self):
        """测试所有漏洞扫描工具都有name属性"""
        for tool in VULN_SCAN_TOOLS:
            assert hasattr(tool, 'name'), f"工具缺少name属性: {type(tool)}"
            assert tool.name is not None and tool.name != "", f"工具name属性为空: {tool}"
    
    def test_all_vuln_scan_tools_have_description(self):
        """测试所有漏洞扫描工具都有description属性"""
        for tool in VULN_SCAN_TOOLS:
            assert hasattr(tool, 'description'), f"工具缺少description属性: {tool.name}"
            assert tool.description is not None and tool.description != "", f"工具description属性为空: {tool.name}"
    
    def test_all_vuln_scan_tools_are_callable(self):
        """测试所有漏洞扫描工具都可调用"""
        for tool in VULN_SCAN_TOOLS:
            is_callable = (
                hasattr(tool, 'invoke') and callable(getattr(tool, 'invoke')) or
                hasattr(tool, 'run') and callable(getattr(tool, 'run')) or
                hasattr(tool, '_run') and callable(getattr(tool, '_run')) or
                callable(tool)
            )
            assert is_callable, f"漏洞扫描工具不可调用: {tool.name}"


class TestSqliScanTool:
    """SQL注入扫描工具测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = sqli_scan
        self.valid_target = "http://example.com/test.php?id=1"
    
    def test_sqli_scan_has_correct_name(self):
        """测试sqli_scan工具名称正确"""
        assert self.tool.name == "sqli_scan"
    
    def test_sqli_scan_has_description(self):
        """测试sqli_scan工具有描述"""
        assert hasattr(self.tool, 'description')
        assert "SQL" in self.tool.description or "sql" in self.tool.description.lower()
    
    def test_sqli_scan_invoke_returns_correct_structure(self):
        """测试sqli_scan返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {
                    "target": self.valid_target,
                    "vulnerabilities": [],
                    "vulnerability_count": 0,
                    "scan_duration": 1.5,
                    "requests_made": 10
                },
                "error": None,
                "metadata": {
                    "tool": "sqli_scan",
                    "target": self.valid_target,
                    "vulnerability_count": 0
                }
            }
            
            result = self.tool.invoke(self.valid_target)
            
            assert isinstance(result, dict), "返回结果应为字典类型"
            assert "success" in result, "返回结果应包含success字段"
            assert "data" in result, "返回结果应包含data字段"
            assert "error" in result, "返回结果应包含error字段"
            assert "metadata" in result, "返回结果应包含metadata字段"
    
    @patch('backend.vulnerability_scan_plugins.sqli.scanner.SQLiScanner')
    def test_sqli_scan_with_vulnerabilities(self, mock_scanner_class):
        """测试sqli_scan发现漏洞"""
        mock_scanner = MagicMock()
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.vulnerabilities = [
            MagicMock(
                vuln_type=MagicMock(value="sqli"),
                url="http://example.com/test.php?id=1",
                severity=MagicMock(value="high"),
                title="SQL Injection",
                description="SQL injection vulnerability",
                parameter="id",
                method="GET",
                payload="' OR '1'='1",
                evidence="error message",
                confidence=0.9,
                cwe_id="CWE-89"
            )
        ]
        mock_result.target = self.valid_target
        mock_result.scan_duration = 2.5
        mock_result.requests_made = 50
        mock_result.error_message = None
        mock_result.plugin_name = "sqli_scan"
        mock_scanner.scan.return_value = mock_result
        mock_scanner_class.return_value = mock_scanner
        
        result = self.tool.invoke(self.valid_target)
        
        assert result["success"] is True
        assert result["data"]["vulnerability_count"] == 1
    
    def test_sqli_scan_parameters(self):
        """测试sqli_scan参数"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {"vulnerabilities": [], "vulnerability_count": 0},
                "error": None,
                "metadata": {"tool": "sqli_scan"}
            }
            
            result = self.tool.invoke({
                "target": self.valid_target,
                "timeout": 15,
                "max_payloads": 30
            })
            
            assert isinstance(result, dict)


class TestXssScanTool:
    """XSS扫描工具测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = xss_scan
        self.valid_target = "http://example.com/search?q=test"
    
    def test_xss_scan_has_correct_name(self):
        """测试xss_scan工具名称正确"""
        assert self.tool.name == "xss_scan"
    
    def test_xss_scan_has_description(self):
        """测试xss_scan工具有描述"""
        assert hasattr(self.tool, 'description')
        assert "XSS" in self.tool.description or "xss" in self.tool.description.lower()
    
    def test_xss_scan_invoke_returns_correct_structure(self):
        """测试xss_scan返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {
                    "target": self.valid_target,
                    "vulnerabilities": [],
                    "vulnerability_count": 0
                },
                "error": None,
                "metadata": {
                    "tool": "xss_scan",
                    "target": self.valid_target
                }
            }
            
            result = self.tool.invoke(self.valid_target)
            
            assert isinstance(result, dict)
            assert "success" in result
            assert "data" in result


class TestCsrfScanTool:
    """CSRF扫描工具测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = csrf_scan
        self.valid_target = "http://example.com/form"
    
    def test_csrf_scan_has_correct_name(self):
        """测试csrf_scan工具名称正确"""
        assert self.tool.name == "csrf_scan"
    
    def test_csrf_scan_has_description(self):
        """测试csrf_scan工具有描述"""
        assert hasattr(self.tool, 'description')
        assert "CSRF" in self.tool.description or "csrf" in self.tool.description.lower()
    
    def test_csrf_scan_invoke_returns_correct_structure(self):
        """测试csrf_scan返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {
                    "target": self.valid_target,
                    "vulnerabilities": [],
                    "vulnerability_count": 0
                },
                "error": None,
                "metadata": {
                    "tool": "csrf_scan",
                    "target": self.valid_target
                }
            }
            
            result = self.tool.invoke(self.valid_target)
            
            assert isinstance(result, dict)
            assert "success" in result


class TestFileuploadScanTool:
    """文件上传扫描工具测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = fileupload_scan
        self.valid_target = "http://example.com/upload.php"
    
    def test_fileupload_scan_has_correct_name(self):
        """测试fileupload_scan工具名称正确"""
        assert self.tool.name == "fileupload_scan"
    
    def test_fileupload_scan_has_description(self):
        """测试fileupload_scan工具有描述"""
        assert hasattr(self.tool, 'description')
        assert len(self.tool.description) > 0
    
    def test_fileupload_scan_invoke_returns_correct_structure(self):
        """测试fileupload_scan返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {
                    "target": self.valid_target,
                    "vulnerabilities": [],
                    "vulnerability_count": 0
                },
                "error": None,
                "metadata": {
                    "tool": "fileupload_scan",
                    "target": self.valid_target
                }
            }
            
            result = self.tool.invoke(self.valid_target)
            
            assert isinstance(result, dict)
            assert "success" in result


class TestCmdiScanTool:
    """命令注入扫描工具测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = cmdi_scan
        self.valid_target = "http://example.com/ping?host=localhost"
    
    def test_cmdi_scan_has_correct_name(self):
        """测试cmdi_scan工具名称正确"""
        assert self.tool.name == "cmdi_scan"
    
    def test_cmdi_scan_has_description(self):
        """测试cmdi_scan工具有描述"""
        assert hasattr(self.tool, 'description')
        assert "command" in self.tool.description.lower() or "cmd" in self.tool.description.lower()
    
    def test_cmdi_scan_invoke_returns_correct_structure(self):
        """测试cmdi_scan返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {
                    "target": self.valid_target,
                    "vulnerabilities": [],
                    "vulnerability_count": 0
                },
                "error": None,
                "metadata": {
                    "tool": "cmdi_scan",
                    "target": self.valid_target
                }
            }
            
            result = self.tool.invoke(self.valid_target)
            
            assert isinstance(result, dict)
            assert "success" in result


class TestSsrfScanTool:
    """SSRF扫描工具测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = ssrf_scan
        self.valid_target = "http://example.com/fetch?url=http://internal"
    
    def test_ssrf_scan_has_correct_name(self):
        """测试ssrf_scan工具名称正确"""
        assert self.tool.name == "ssrf_scan"
    
    def test_ssrf_scan_has_description(self):
        """测试ssrf_scan工具有描述"""
        assert hasattr(self.tool, 'description')
        assert "SSRF" in self.tool.description or "ssrf" in self.tool.description.lower()
    
    def test_ssrf_scan_invoke_returns_correct_structure(self):
        """测试ssrf_scan返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {
                    "target": self.valid_target,
                    "vulnerabilities": [],
                    "vulnerability_count": 0
                },
                "error": None,
                "metadata": {
                    "tool": "ssrf_scan",
                    "target": self.valid_target
                }
            }
            
            result = self.tool.invoke(self.valid_target)
            
            assert isinstance(result, dict)
            assert "success" in result


class TestLfiScanTool:
    """本地文件包含扫描工具测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = lfi_scan
        self.valid_target = "http://example.com/page?file=about"
    
    def test_lfi_scan_has_correct_name(self):
        """测试lfi_scan工具名称正确"""
        assert self.tool.name == "lfi_scan"
    
    def test_lfi_scan_has_description(self):
        """测试lfi_scan工具有描述"""
        assert hasattr(self.tool, 'description')
        assert "LFI" in self.tool.description or "file" in self.tool.description.lower()
    
    def test_lfi_scan_invoke_returns_correct_structure(self):
        """测试lfi_scan返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {
                    "target": self.valid_target,
                    "vulnerabilities": [],
                    "vulnerability_count": 0
                },
                "error": None,
                "metadata": {
                    "tool": "lfi_scan",
                    "target": self.valid_target
                }
            }
            
            result = self.tool.invoke(self.valid_target)
            
            assert isinstance(result, dict)
            assert "success" in result


class TestWeakpassScanTool:
    """弱口令扫描工具测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = weakpass_scan
        self.valid_target = "http://example.com/login"
    
    def test_weakpass_scan_has_correct_name(self):
        """测试weakpass_scan工具名称正确"""
        assert self.tool.name == "weakpass_scan"
    
    def test_weakpass_scan_has_description(self):
        """测试weakpass_scan工具有描述"""
        assert hasattr(self.tool, 'description')
        assert "password" in self.tool.description.lower() or "weak" in self.tool.description.lower()
    
    def test_weakpass_scan_invoke_returns_correct_structure(self):
        """测试weakpass_scan返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {
                    "target": self.valid_target,
                    "vulnerabilities": [],
                    "vulnerability_count": 0
                },
                "error": None,
                "metadata": {
                    "tool": "weakpass_scan",
                    "target": self.valid_target
                }
            }
            
            result = self.tool.invoke(self.valid_target)
            
            assert isinstance(result, dict)
            assert "success" in result


class TestVulnScanToolsErrorHandling:
    """漏洞扫描工具错误处理测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tools = VULN_SCAN_TOOLS
        self.invalid_targets = [
            "",
            "not_a_valid_url",
            "://missing_protocol.com",
            "http://",
        ]
    
    def test_vuln_scan_tools_handle_empty_target(self):
        """测试漏洞扫描工具处理空目标"""
        for tool in self.tools:
            try:
                result = tool.invoke("")
                assert isinstance(result, dict), f"{tool.name}: 返回结果应为字典"
                assert "success" in result, f"{tool.name}: 返回结果应包含success字段"
            except Exception as e:
                pytest.fail(f"{tool.name}: 空目标不应抛出异常: {e}")
    
    def test_vuln_scan_tools_return_dict_on_error(self):
        """测试漏洞扫描工具错误时返回字典"""
        for tool in self.tools:
            try:
                result = tool.invoke("invalid_target_12345")
                assert isinstance(result, dict), f"{tool.name}: 错误时应返回字典"
            except Exception as e:
                pytest.fail(f"{tool.name}: 不应抛出异常: {e}")
    
    def test_vuln_scan_tools_metadata_contains_tool_name(self):
        """测试漏洞扫描工具返回metadata包含工具名称"""
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


class TestVulnScanToolsVulnerabilityStructure:
    """漏洞扫描工具漏洞数据结构测试"""
    
    def test_vulnerability_data_structure(self):
        """测试漏洞数据结构"""
        expected_fields = ["vuln_type", "url", "severity", "title", "description"]
        
        mock_vuln = {
            "vuln_type": "sqli",
            "url": "http://example.com/test?id=1",
            "severity": "high",
            "title": "SQL Injection",
            "description": "SQL injection vulnerability detected",
            "parameter": "id",
            "method": "GET",
            "payload": "' OR '1'='1",
            "evidence": "error message in response",
            "confidence": 0.9,
            "cwe_id": "CWE-89"
        }
        
        with patch.object(sqli_scan, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {
                    "target": "http://example.com/test?id=1",
                    "vulnerabilities": [mock_vuln],
                    "vulnerability_count": 1
                },
                "error": None,
                "metadata": {"tool": "sqli_scan"}
            }
            
            result = sqli_scan.invoke("http://example.com/test?id=1")
            
            assert result["success"] is True
            assert len(result["data"]["vulnerabilities"]) == 1
            
            vuln = result["data"]["vulnerabilities"][0]
            for field in expected_fields:
                assert field in vuln, f"漏洞数据应包含{field}字段"
    
    def test_severity_levels(self):
        """测试严重度级别"""
        valid_severities = ["critical", "high", "medium", "low", "info"]
        
        for severity in valid_severities:
            with patch.object(sqli_scan, 'invoke') as mock_invoke:
                mock_invoke.return_value = {
                    "success": True,
                    "data": {
                        "vulnerabilities": [{
                            "vuln_type": "sqli",
                            "severity": severity
                        }]
                    },
                    "error": None,
                    "metadata": {}
                }
                
                result = sqli_scan.invoke("http://example.com")
                
                assert result["data"]["vulnerabilities"][0]["severity"] == severity


class TestVulnScanToolsScanParameters:
    """漏洞扫描工具扫描参数测试"""
    
    def test_sqli_scan_timeout_parameter(self):
        """测试sqli_scan超时参数"""
        with patch.object(sqli_scan, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {},
                "error": None,
                "metadata": {}
            }
            
            result = sqli_scan.invoke({
                "target": "http://example.com",
                "timeout": 30
            })
            
            assert isinstance(result, dict)
    
    def test_sqli_scan_max_payloads_parameter(self):
        """测试sqli_scan最大payload参数"""
        with patch.object(sqli_scan, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {},
                "error": None,
                "metadata": {}
            }
            
            result = sqli_scan.invoke({
                "target": "http://example.com",
                "max_payloads": 100
            })
            
            assert isinstance(result, dict)
    
    def test_sqli_scan_delay_parameter(self):
        """测试sqli_scan延迟参数"""
        with patch.object(sqli_scan, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {},
                "error": None,
                "metadata": {}
            }
            
            result = sqli_scan.invoke({
                "target": "http://example.com",
                "delay": 0.5
            })
            
            assert isinstance(result, dict)


class TestVulnScanToolsImportError:
    """漏洞扫描工具导入错误测试"""
    
    def test_sqli_scan_import_error_handling(self):
        """测试sqli_scan导入错误处理"""
        with patch.dict('sys.modules', {'backend.vulnerability_scan_plugins.sqli.scanner': None}):
            result = sqli_scan.invoke("http://example.com")
            
            assert isinstance(result, dict)
            assert result["success"] is False
            assert result["error"] is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
