# -*- coding:utf-8 -*-
"""
漏洞扫描插件单元测试

测试所有漏洞扫描器的功能
"""

import pytest
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))


class TestBaseScanner:
    """扫描器基类测试"""
    
    def test_import_base_module(self):
        """测试导入基类模块"""
        from backend.vulnerability_scan_plugins.base import (
            VulnerabilityScannerBase,
            ScanResult,
            PluginMetadata,
            VulnerabilityInfo,
            VulnerabilityType,
            VulnerabilitySeverity
        )
        assert VulnerabilityScannerBase is not None
        assert ScanResult is not None
    
    def test_scan_result_structure(self):
        """测试扫描结果数据结构"""
        from backend.vulnerability_scan_plugins.base import ScanResult
        
        result = ScanResult(
            success=True,
            plugin_name="test_scanner",
            target="http://example.com"
        )
        
        assert result.success == True
        assert result.plugin_name == "test_scanner"
        assert result.target == "http://example.com"
        assert result.vulnerabilities == []
        assert result.authentication_used == False
    
    def test_scan_result_to_dict(self):
        """测试扫描结果转换为字典"""
        from backend.vulnerability_scan_plugins.base import ScanResult
        
        result = ScanResult(
            success=True,
            plugin_name="test_scanner",
            target="http://example.com"
        )
        
        result_dict = result.to_dict()
        
        assert isinstance(result_dict, dict)
        assert "success" in result_dict
        assert "plugin_name" in result_dict
        assert "target" in result_dict
        assert "vulnerabilities" in result_dict
        assert "request_response_log" in result_dict
    
    def test_vulnerability_info_structure(self):
        """测试漏洞信息数据结构"""
        from backend.vulnerability_scan_plugins.base import (
            VulnerabilityInfo,
            VulnerabilityType,
            VulnerabilitySeverity
        )
        
        vuln = VulnerabilityInfo(
            vuln_type=VulnerabilityType.SQL_INJECTION,
            url="http://example.com?id=1",
            severity=VulnerabilitySeverity.HIGH,
            title="SQL注入漏洞"
        )
        
        assert vuln.vuln_type == VulnerabilityType.SQL_INJECTION
        assert vuln.severity == VulnerabilitySeverity.HIGH
        assert vuln.title == "SQL注入漏洞"
    
    def test_authentication_methods(self):
        """测试认证方法"""
        from backend.vulnerability_scan_plugins.sqli.scanner import SQLiScanner
        
        scanner = SQLiScanner("http://example.com")
        
        scanner.set_authentication(
            cookies={"session": "test123"},
            headers={"X-Custom": "value"},
            auth_token="Bearer token123"
        )
        
        assert scanner.cookies == {"session": "test123"}
        assert scanner.headers == {"X-Custom": "value"}
        assert scanner.auth_token == "Bearer token123"
        assert scanner.is_authenticated() == True
    
    def test_request_response_logging(self):
        """测试请求响应日志记录"""
        from backend.vulnerability_scan_plugins.sqli.scanner import SQLiScanner
        
        scanner = SQLiScanner("http://example.com")
        
        log_entry = scanner.record_request_response(
            method="GET",
            url="http://example.com/test",
            request_headers={"User-Agent": "Test"},
            response_status=200,
            duration=0.5
        )
        
        assert log_entry["method"] == "GET"
        assert log_entry["url"] == "http://example.com/test"
        assert log_entry["response_status"] == 200
        
        logs = scanner.get_request_response_logs()
        assert len(logs) == 1


class TestSQLiScanner:
    """SQL注入扫描器测试"""
    
    def test_import_sqli_scanner(self):
        """测试导入SQL注入扫描器"""
        from backend.vulnerability_scan_plugins.sqli.scanner import SQLiScanner
        assert SQLiScanner is not None
    
    def test_sqli_scanner_init(self):
        """测试SQL注入扫描器初始化"""
        from backend.vulnerability_scan_plugins.sqli.scanner import SQLiScanner
        
        scanner = SQLiScanner("http://example.com?id=1")
        
        assert scanner.target == "http://example.com?id=1"
        assert scanner.timeout == 10
        assert scanner.max_payloads == 50
    
    def test_sqli_scanner_metadata(self):
        """测试SQL注入扫描器元数据"""
        from backend.vulnerability_scan_plugins.sqli.scanner import SQLiScanner
        
        scanner = SQLiScanner("http://example.com")
        metadata = scanner.metadata
        
        assert metadata.name == "sqli_scanner"
        assert metadata.version == "2.0.0"
    
    def test_sqli_payloads_loaded(self):
        """测试SQL注入Payload加载"""
        from backend.vulnerability_scan_plugins.sqli.scanner import (
            DATABASE_ERROR_PATTERNS,
            TIME_BASED_PAYLOADS,
            BOOLEAN_PAYLOADS
        )
        
        assert len(DATABASE_ERROR_PATTERNS) >= 9
        assert "mysql" in DATABASE_ERROR_PATTERNS
        assert "postgresql" in DATABASE_ERROR_PATTERNS
        assert "mssql" in DATABASE_ERROR_PATTERNS
        assert "oracle" in DATABASE_ERROR_PATTERNS
        
        assert len(TIME_BASED_PAYLOADS) >= 5
        assert "mysql" in TIME_BASED_PAYLOADS
        
        assert "true" in BOOLEAN_PAYLOADS
        assert "false" in BOOLEAN_PAYLOADS


class TestXSSScanner:
    """XSS扫描器测试"""
    
    def test_import_xss_scanner(self):
        """测试导入XSS扫描器"""
        from backend.vulnerability_scan_plugins.xss.scanner import XSSScanner
        assert XSSScanner is not None
    
    def test_xss_scanner_init(self):
        """测试XSS扫描器初始化"""
        from backend.vulnerability_scan_plugins.xss.scanner import XSSScanner
        
        scanner = XSSScanner("http://example.com?q=test")
        
        assert scanner.target == "http://example.com?q=test"
        assert scanner.timeout == 10
        assert scanner.max_payloads == 30
    
    def test_xss_payloads_loaded(self):
        """测试XSS Payload加载"""
        from backend.vulnerability_scan_plugins.xss.scanner import (
            ENCODED_PAYLOADS,
            EVENT_HANDLER_PAYLOADS,
            SVG_MATHML_PAYLOADS,
            DOM_XSS_SINKS,
            DOM_XSS_SOURCES
        )
        
        assert len(ENCODED_PAYLOADS) > 0
        assert len(EVENT_HANDLER_PAYLOADS) >= 20
        assert len(SVG_MATHML_PAYLOADS) > 0
        assert len(DOM_XSS_SINKS) > 0
        assert len(DOM_XSS_SOURCES) > 0
    
    def test_encoding_methods(self):
        """测试编码方法"""
        from backend.vulnerability_scan_plugins.xss.scanner import XSSScanner
        
        scanner = XSSScanner("http://example.com")
        
        html_decimal = scanner._encode_html_decimal("<script>")
        assert "&#" in html_decimal
        
        html_hex = scanner._encode_html_hex("<script>")
        assert "&#x" in html_hex


class TestLfiScanner:
    """LFI扫描器测试"""
    
    def test_import_lfi_scanner(self):
        """测试导入LFI扫描器"""
        from backend.vulnerability_scan_plugins.lfi.scanner import LfiScanner
        assert LfiScanner is not None
    
    def test_lfi_scanner_init(self):
        """测试LFI扫描器初始化"""
        from backend.vulnerability_scan_plugins.lfi.scanner import LfiScanner
        
        scanner = LfiScanner("http://example.com?file=test")
        
        assert scanner.target == "http://example.com?file=test"


class TestSsrfScanner:
    """SSRF扫描器测试"""
    
    def test_import_ssrf_scanner(self):
        """测试导入SSRF扫描器"""
        from backend.vulnerability_scan_plugins.ssrf.scanner import SsrfScanner
        assert SsrfScanner is not None
    
    def test_ssrf_payloads_loaded(self):
        """测试SSRF Payload加载"""
        from backend.vulnerability_scan_plugins.ssrf.scanner import (
            CLOUD_METADATA_PAYLOADS,
            INTERNAL_NETWORK_PAYLOADS,
            BYPASS_TECHNIQUES
        )
        
        assert len(CLOUD_METADATA_PAYLOADS) > 0
        assert len(INTERNAL_NETWORK_PAYLOADS) > 0
        assert len(BYPASS_TECHNIQUES) > 0


class TestCmdiScanner:
    """命令注入扫描器测试"""
    
    def test_import_cmdi_scanner(self):
        """测试导入命令注入扫描器"""
        from backend.vulnerability_scan_plugins.cmdi.scanner import CmdiScanner
        assert CmdiScanner is not None
    
    def test_cmdi_payloads_loaded(self):
        """测试命令注入Payload加载"""
        from backend.vulnerability_scan_plugins.cmdi.scanner import COMMAND_INJECTION_PAYLOADS
        
        assert "linux_basic" in COMMAND_INJECTION_PAYLOADS
        assert "windows_basic" in COMMAND_INJECTION_PAYLOADS
        assert len(COMMAND_INJECTION_PAYLOADS["linux_basic"]) > 0


class TestWeakPassScanner:
    """弱口令扫描器测试"""
    
    def test_import_weakpass_scanner(self):
        """测试导入弱口令扫描器"""
        from backend.vulnerability_scan_plugins.weakpass.scanner import WeakPassScanner
        assert WeakPassScanner is not None
    
    def test_weakpass_scanner_init(self):
        """测试弱口令扫描器初始化"""
        from backend.vulnerability_scan_plugins.weakpass.scanner import WeakPassScanner
        
        scanner = WeakPassScanner("http://example.com/login")
        
        assert scanner.target == "http://example.com/login"


class TestCsrfScanner:
    """CSRF扫描器测试"""
    
    def test_import_csrf_scanner(self):
        """测试导入CSRF扫描器"""
        from backend.vulnerability_scan_plugins.csrf.scanner import CSRFScanner
        assert CSRFScanner is not None


class TestFileUploadScanner:
    """文件上传扫描器测试"""
    
    def test_import_fileupload_scanner(self):
        """测试导入文件上传扫描器"""
        from backend.vulnerability_scan_plugins.fileupload.scanner import FileUploadScanner
        assert FileUploadScanner is not None


class TestInfoLeakScanner:
    """信息泄露扫描器测试"""
    
    def test_import_infoleak_scanner(self):
        """测试导入信息泄露扫描器"""
        from backend.vulnerability_scan_plugins.infoleak.scanner import InfoLeakScanner
        assert InfoLeakScanner is not None
    
    def test_infoleak_patterns_loaded(self):
        """测试信息泄露模式加载"""
        from backend.vulnerability_scan_plugins.infoleak.scanner import SENSITIVE_PATTERNS
        
        assert len(SENSITIVE_PATTERNS) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
