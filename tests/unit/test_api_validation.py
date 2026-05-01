"""测试 API 请求参数校验"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import pytest
from pydantic import ValidationError
from TOSKill.api.scan_api import ScanRequest, ToolExecuteRequest

class TestScanRequestValidation:
    def test_valid_target(self):
        req = ScanRequest(target="https://test.com")
        assert req.target == "https://test.com"

    def test_valid_http_target(self):
        req = ScanRequest(target="http://test.com")
        assert req.target == "http://test.com"

    def test_ftp_target_rejected(self):
        with pytest.raises(ValidationError):
            ScanRequest(target="ftp://test.com")

    def test_empty_target_rejected(self):
        with pytest.raises(ValidationError):
            ScanRequest(target="")

    def test_no_protocol_rejected(self):
        with pytest.raises(ValidationError):
            ScanRequest(target="test.com")

class TestToolExecuteRequestValidation:
    def test_valid_tool(self):
        req = ToolExecuteRequest(tool_name="xss", target="https://test.com")
        assert req.tool_name == "xss"

    def test_invalid_tool_rejected(self):
        with pytest.raises(ValidationError):
            ToolExecuteRequest(tool_name="invalid_tool_xyz", target="https://test.com")

    def test_ftp_target_rejected(self):
        with pytest.raises(ValidationError):
            ToolExecuteRequest(tool_name="xss", target="ftp://test.com")
