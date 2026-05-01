"""测试 API 响应格式标准化"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import pytest
from datetime import datetime
from TOSKill.api.scan_api import APIResponse

class TestAPIResponseFormat:
    def test_default_response(self):
        resp = APIResponse()
        data = resp.model_dump()
        assert data["code"] == 200
        assert data["message"] == "success"
        assert data["data"] is None
        assert "timestamp" in data
        datetime.fromisoformat(data["timestamp"])

    def test_error_response(self):
        resp = APIResponse(code=500, message="error", data={"reason": "test"})
        data = resp.model_dump()
        assert data["code"] == 500
        assert data["message"] == "error"
        assert data["data"] == {"reason": "test"}
        assert "timestamp" in data
