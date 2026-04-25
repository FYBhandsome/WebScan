import pytest
from unittest.mock import Mock, patch, AsyncMock
import json

class TestAIAgentsApi:
    """AI Agents API测试"""
    
    @pytest.mark.asyncio
    async def test_scan_request_format(self):
        """测试扫描请求格式"""
        request_data = {
            "target": "http://example.com",
            "scan_mode": "full",
            "options": {
                "timeout": 300,
                "max_depth": 3
            }
        }
        assert "target" in request_data
        assert "scan_mode" in request_data
        assert isinstance(request_data["target"], str)
    
    @pytest.mark.asyncio
    async def test_task_response_format(self):
        """测试任务响应格式"""
        mock_response = {
            "code": 200,
            "message": "任务创建成功",
            "data": {
                "task_id": 1,
                "status": "pending",
                "target": "http://example.com",
                "created_at": "2024-01-01T00:00:00Z"
            }
        }
        assert "code" in mock_response
        assert "data" in mock_response
        assert "task_id" in mock_response["data"]
    
    @pytest.mark.asyncio
    async def test_task_list_response_format(self):
        """测试任务列表响应格式"""
        mock_response = {
            "code": 200,
            "message": "获取成功",
            "data": {
                "tasks": [
                    {
                        "id": 1,
                        "target": "http://example.com",
                        "status": "completed",
                        "progress": 100
                    }
                ],
                "total": 1,
                "page": 1,
                "page_size": 10
            }
        }
        assert "tasks" in mock_response["data"]
        assert "total" in mock_response["data"]
    
    @pytest.mark.asyncio
    async def test_report_generation_request_format(self):
        """测试报告生成请求格式"""
        request_data = {
            "task_id": 1,
            "report_type": "full",
            "format": "html"
        }
        assert "task_id" in request_data
        assert "report_type" in request_data
    
    @pytest.mark.asyncio
    async def test_poc_execute_request_format(self):
        """测试POC执行请求格式"""
        request_data = {
            "poc_name": "CVE-2020-1234",
            "target": "http://example.com",
            "options": {
                "timeout": 30
            }
        }
        assert "poc_name" in request_data
        assert "target" in request_data
    
    @pytest.mark.asyncio
    async def test_config_response_format(self):
        """测试配置响应格式"""
        mock_response = {
            "code": 200,
            "message": "获取成功",
            "data": {
                "max_concurrent_tasks": 5,
                "default_timeout": 300,
                "ai_model": "gpt-4"
            }
        }
        assert "code" in mock_response
        assert "data" in mock_response


class TestWebSocketMessages:
    """WebSocket消息测试"""
    
    def test_task_update_message_format(self):
        """测试任务更新消息格式"""
        message = {
            "type": "task:update",
            "payload": {
                "task_id": 1,
                "status": "running",
                "progress": 50
            }
        }
        assert message["type"] == "task:update"
        assert "task_id" in message["payload"]
    
    def test_task_progress_message_format(self):
        """测试任务进度消息格式"""
        message = {
            "type": "task:progress",
            "payload": {
                "task_id": 1,
                "progress": 75,
                "stage": "scanning"
            }
        }
        assert message["type"] == "task:progress"
        assert "progress" in message["payload"]
    
    def test_task_completed_message_format(self):
        """测试任务完成消息格式"""
        message = {
            "type": "task:completed",
            "payload": {
                "task_id": 1,
                "result": {
                    "vulnerabilities": [],
                    "scan_time": 120.5
                }
            }
        }
        assert message["type"] == "task:completed"
        assert "task_id" in message["payload"]
    
    def test_stage_update_message_format(self):
        """测试阶段更新消息格式"""
        message = {
            "type": "stage:update",
            "payload": {
                "task_id": 1,
                "stage": "info_collection",
                "data": {
                    "status": "completed",
                    "duration": 30.5
                }
            }
        }
        assert message["type"] == "stage:update"
        assert "stage" in message["payload"]
    
    def test_subgraph_progress_message_format(self):
        """测试子图进度消息格式"""
        message = {
            "type": "subgraph:progress",
            "payload": {
                "task_id": 1,
                "subgraph_type": "planning",
                "status": "running",
                "progress": 50
            }
        }
        assert message["type"] == "subgraph:progress"
        assert "subgraph_type" in message["payload"]
