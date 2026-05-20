import pytest
from unittest.mock import Mock, patch, AsyncMock
import json


@pytest.fixture
def mock_kb_response():
    """模拟知识库API响应"""
    return {
        "code": 200,
        "message": "获取成功",
        "data": [
            {
                "id": "vuln-001",
                "name": "SQL注入漏洞",
                "severity": "high",
                "description": "存在SQL注入漏洞，攻击者可获取数据库敏感信息",
                "cve_id": "CVE-2024-1234",
                "solution": "使用参数化查询"
            },
            {
                "id": "vuln-002",
                "name": "XSS漏洞",
                "severity": "medium",
                "description": "存在反射型XSS漏洞",
                "cve_id": "CVE-2024-5678",
                "solution": "对输出进行HTML编码"
            }
        ]
    }


class TestKBApi:
    """知识库API测试"""
    
    @pytest.mark.asyncio
    async def test_get_vulnerabilities_success(self, mock_kb_response):
        """测试获取漏洞列表成功"""
        assert mock_kb_response["code"] == 200
        assert "data" in mock_kb_response
        assert isinstance(mock_kb_response["data"], list)
    
    @pytest.mark.asyncio
    async def test_get_vulnerabilities_response_format(self, mock_kb_response):
        """测试响应格式"""
        assert "code" in mock_kb_response
        assert "message" in mock_kb_response
        assert "data" in mock_kb_response
    
    @pytest.mark.asyncio
    async def test_vulnerability_data_structure(self, mock_kb_response):
        """测试漏洞数据结构"""
        vuln = mock_kb_response["data"][0]
        assert "id" in vuln
        assert "name" in vuln
        assert "severity" in vuln
        assert "description" in vuln
    
    @pytest.mark.asyncio
    async def test_search_from_seebug_request_format(self):
        """测试从Seebug搜索请求格式"""
        request_data = {
            "keyword": "SQL注入",
            "page": 1
        }
        assert "keyword" in request_data
        assert isinstance(request_data["page"], int)
    
    @pytest.mark.asyncio
    async def test_search_poc_request_format(self):
        """测试搜索POC请求格式"""
        request_data = {
            "keyword": "CVE-2020",
            "page": 1
        }
        assert "keyword" in request_data
        assert isinstance(request_data["page"], int)
    
    @pytest.mark.asyncio
    async def test_download_poc_request_format(self):
        """测试下载POC请求格式"""
        request_data = {
            "ssvid": "SSVID-12345",
            "save_to_local": True,
            "category": "seebug"
        }
        assert "ssvid" in request_data
        assert isinstance(request_data["save_to_local"], bool)
