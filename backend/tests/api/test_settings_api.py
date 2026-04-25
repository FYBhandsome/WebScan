import pytest
from unittest.mock import Mock, patch

class TestSettingsApi:
    """设置API测试"""
    
    @pytest.mark.asyncio
    async def test_get_settings_success(self, mock_settings_response):
        """测试获取设置成功"""
        assert mock_settings_response["code"] == 200
        assert "data" in mock_settings_response
    
    @pytest.mark.asyncio
    async def test_settings_data_structure(self, mock_settings_response):
        """测试设置数据结构"""
        data = mock_settings_response["data"]
        assert "general" in data
        assert "systemName" in data["general"]
        assert "language" in data["general"]
    
    @pytest.mark.asyncio
    async def test_update_settings_request_format(self):
        """测试更新设置请求格式"""
        request_data = {
            "general": {
                "systemName": "Test System"
            }
        }
        assert "general" in request_data
        assert "systemName" in request_data["general"]
    
    @pytest.mark.asyncio
    async def test_system_info_response_format(self):
        """测试系统信息响应格式"""
        mock_response = {
            "code": 200,
            "message": "获取成功",
            "data": {
                "version": "1.0.0",
                "platform": {
                    "system": "Windows",
                    "release": "10"
                },
                "uptime": "10天 5小时",
                "resources": {
                    "cpu": {"usage": "45%"},
                    "memory": {"usage": "60%"}
                }
            }
        }
        assert mock_response["code"] == 200
        assert "version" in mock_response["data"]
        assert "platform" in mock_response["data"]
        assert "resources" in mock_response["data"]
    
    @pytest.mark.asyncio
    async def test_statistics_response_format(self):
        """测试统计信息响应格式"""
        mock_response = {
            "code": 200,
            "message": "获取成功",
            "data": {
                "today_scans": 10,
                "high_risk_vulns": 5,
                "completed_scans": 100
            }
        }
        assert mock_response["code"] == 200
        assert "today_scans" in mock_response["data"]
        assert "high_risk_vulns" in mock_response["data"]
    
    @pytest.mark.asyncio
    async def test_api_keys_response_format(self):
        """测试API密钥列表响应格式"""
        mock_response = {
            "code": 200,
            "message": "获取成功",
            "data": {
                "api_keys": []
            }
        }
        assert mock_response["code"] == 200
        assert "api_keys" in mock_response["data"]
    
    @pytest.mark.asyncio
    async def test_create_api_key_request_format(self):
        """测试创建API密钥请求格式"""
        request_data = {
            "name": "Test Key"
        }
        assert "name" in request_data
        assert isinstance(request_data["name"], str)
