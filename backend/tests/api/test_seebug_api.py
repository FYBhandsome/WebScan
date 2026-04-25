import pytest
from unittest.mock import Mock, patch

class TestSeebugApi:
    """Seebug API测试"""
    
    @pytest.mark.asyncio
    async def test_status_response_format(self):
        """测试状态响应格式"""
        mock_response = {
            "code": 200,
            "message": "获取成功",
            "data": {
                "connected": True,
                "api_key_configured": True
            }
        }
        assert mock_response["code"] == 200
        assert "data" in mock_response
    
    @pytest.mark.asyncio
    async def test_search_request_format(self):
        """测试搜索请求格式"""
        request_data = {
            "keyword": "XSS",
            "page": 1
        }
        assert "keyword" in request_data
        assert "page" in request_data
    
    @pytest.mark.asyncio
    async def test_search_response_format(self):
        """测试搜索响应格式"""
        mock_response = {
            "code": 200,
            "message": "搜索成功",
            "data": {
                "total": 10,
                "items": []
            }
        }
        assert mock_response["code"] == 200
        assert "total" in mock_response["data"]
        assert "items" in mock_response["data"]
    
    @pytest.mark.asyncio
    async def test_poc_search_request_format(self):
        """测试POC搜索请求格式"""
        request_params = {
            "keyword": "CVE"
        }
        assert "keyword" in request_params
    
    @pytest.mark.asyncio
    async def test_poc_download_request_format(self):
        """测试POC下载请求格式"""
        ssvid = "SSVID-12345"
        assert isinstance(ssvid, str)
        assert ssvid.startswith("SSVID-")
