# -*- coding:utf-8 -*-
"""
漏洞扫描插件单元测试

测试所有漏洞扫描器的功能
"""

import pytest
import asyncio
import sys
import importlib.util
from email.message import Message
from pathlib import Path
from unittest.mock import AsyncMock

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

    def test_union_detection_requires_reflected_marker(self):
        from backend.vulnerability_scan_plugins.sqli.scanner import SQLiScanner

        scanner = SQLiScanner("http://example.com")
        marker = "TOSKILL_UNION_TEST"

        assert scanner._check_union_success("normal login page", marker) is False
        assert scanner._check_union_success(f"result: {marker}", marker) is True

    def test_union_payload_places_marker_in_requested_column(self):
        from backend.vulnerability_scan_plugins.sqli.scanner import SQLiScanner

        scanner = SQLiScanner("http://example.com")
        payload = scanner._generate_union_payload(3, marker="MARKER", marker_column=1)

        assert payload == "' UNION SELECT NULL,'MARKER',NULL--"


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

    def test_page_image_name_is_not_lfi_evidence(self):
        from backend.vulnerability_scan_plugins.lfi.scanner import LfiScanner

        scanner = LfiScanner("http://example.com?file=test")
        login_page = '<img src="images/login_logo.png">'

        assert scanner._check_lfi_signature(login_page, "/etc/passwd", login_page) is None
        assert scanner._check_lfi_signature(login_page, "/etc/passwd", "") is None

    def test_new_passwd_signature_is_lfi_evidence(self):
        from backend.vulnerability_scan_plugins.lfi.scanner import LfiScanner

        scanner = LfiScanner("http://example.com?file=test")
        signature = scanner._check_lfi_signature(
            "root:x:0:0:root:/root:/bin/bash",
            "/etc/passwd",
            "normal page",
        )

        assert signature and signature.startswith("linux_passwd:")


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

    def test_ssrf_requires_target_response_signature(self):
        from backend.vulnerability_scan_plugins.ssrf.scanner import SsrfScanner

        scanner = SsrfScanner("http://example.com")
        expected = [r"instance-id", r"ami-[a-z0-9]+"]

        assert scanner._check_ssrf_signature("normal 200 login page", expected) is None
        assert scanner._check_ssrf_signature("instance-id\ni-123456", expected) == "instance-id"


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

    def test_samesite_is_read_from_raw_set_cookie_header(self):
        from backend.vulnerability_scan_plugins.csrf.scanner import CSRFScanner

        attributes = CSRFScanner._parse_set_cookie_headers([
            "PHPSESSID=abc123; Path=/; HttpOnly; SameSite=Strict"
        ])

        assert attributes["phpsessid"]["httponly"] == "true"
        assert attributes["phpsessid"]["samesite"] == "Strict"

    def test_strict_samesite_cookie_is_not_reported(self):
        from backend.vulnerability_scan_plugins.csrf.scanner import CSRFScanner

        scanner = CSRFScanner("http://example.com")
        scanner._cookie_analysis = {
            "cookies": [{
                "name": "PHPSESSID",
                "domain": "example.com",
                "path": "/",
                "secure": True,
                "has_httponly": True,
                "samesite": "Strict",
            }]
        }
        result = scanner._create_result()

        scanner._check_samesite_protection(result)

        assert result.vulnerabilities == []


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


class TestScanResultAccuracy:
    """扫描结果计数与底层HTTP证据测试。"""

    def test_header_maps_does_not_duplicate_repeated_header_values(self):
        module_path = project_root / "TOSKill" / "tools" / "http_probe.py"
        spec = importlib.util.spec_from_file_location("toskill_http_probe_test", module_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)

        headers = Message()
        headers.add_header("Set-Cookie", "security=impossible; Path=/; HttpOnly")
        headers.add_header("Set-Cookie", "PHPSESSID=abc; Path=/; HttpOnly; SameSite=Strict")

        flattened, values = module._header_maps(headers)

        assert len(values["set-cookie"]) == 2
        assert flattened["set-cookie"].count("PHPSESSID") == 1

    def test_completion_payload_separates_result_counts(self):
        from TOSKill.api.ai_chat_websocket import AIChatManager

        duplicate = {
            "source_tool": "lfi_scan",
            "vuln_type": "lfi",
            "title": "文件包含漏洞 - file (basic)",
            "url": "http://example.com",
            "method": "GET",
            "parameter": "file",
            "payload": "/etc/passwd",
        }
        second_payload = {**duplicate, "payload": "../etc/passwd"}
        verified_header = {
            "source_tool": "http_security_headers_scan",
            "vuln_type": "HTTP Security Headers",
            "title": "缺少内容安全策略",
            "url": "http://example.com",
            "parameter": "Content-Security-Policy",
            "verified": True,
            "verification_status": "verified",
        }

        payload = AIChatManager._build_scan_result_payload(
            {
                "task_id": "scan-1",
                "vulnerabilities": [duplicate, second_payload, verified_header],
                "completed_tasks": ["lfi_scan", "http_security_headers_scan"],
            },
            "http://example.com",
            "automatic",
        )

        assert payload["raw_vulnerabilities_count"] == 3
        assert payload["vulnerabilities_count"] == 2
        assert payload["verified_vulnerabilities_count"] == 1
        assert len(payload["vulnerabilities"]) == 2

    @pytest.mark.asyncio
    async def test_unresponsive_websocket_does_not_block_scan_events(self, monkeypatch):
        from TOSKill.api import ai_chat_websocket

        manager = ai_chat_websocket.AIChatManager()
        websocket = AsyncMock()

        async def never_finishes(_message):
            await asyncio.Future()

        websocket.send_json.side_effect = never_finishes
        manager.connections["session-1"] = websocket
        manager._ws_to_client[websocket] = "client-1"
        manager._subscriptions["client-1"] = {"session-1"}
        monkeypatch.setattr(ai_chat_websocket, "WEBSOCKET_SEND_TIMEOUT", 0.01)

        await asyncio.wait_for(
            manager._send_multi("session-1", {
                "type": "task_completed",
                "payload": {"tool": "slow_scan"},
            }),
            timeout=0.2,
        )

        assert "session-1" not in manager.connections
        assert websocket not in manager._ws_to_client

    @pytest.mark.asyncio
    async def test_websocket_ping_receives_pong(self):
        from TOSKill.api.ai_chat_websocket import AIChatManager

        manager = AIChatManager()
        websocket = AsyncMock()
        manager.connections["session-1"] = websocket

        await manager.handle_message("session-1", {
            "type": "ping",
            "payload": {"timestamp": 12345},
        })

        sent = websocket.send_json.call_args.args[0]
        assert sent["type"] == "pong"
        assert sent["payload"]["timestamp"] == 12345


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
