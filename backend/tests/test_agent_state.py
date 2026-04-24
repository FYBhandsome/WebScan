"""
AgentState 测试
"""
import pytest
import asyncio
from datetime import datetime
from TOSKill.AI.state import AgentState


class TestAgentState:
    """AgentState 测试"""
    
    def test_create_state(self):
        """测试创建状态"""
        state = AgentState(
            target="http://example.com",
            task_id="task_123"
        )
        
        assert state.target == "http://example.com"
        assert state.task_id == "task_123"
        assert state.workflow_status == "idle"
        assert state.is_complete is False
    
    def test_update_stage_status(self):
        """测试更新阶段状态"""
        state = AgentState(target="http://example.com", task_id="task_123")
        
        state.update_stage_status("planning", "running", "info_collection", 50, "开始信息收集")
        
        assert state.stage_status["planning"]["status"] == "running"
        assert state.stage_status["planning"]["progress"] == 50
        assert len(state.stage_status["planning"]["logs"]) == 1
    
    def test_get_progress(self):
        """测试获取进度"""
        state = AgentState(target="http://example.com", task_id="task_123")
        
        state.update_stage_status("planning", "completed", None, 100)
        state.update_stage_status("tool_execution", "running", None, 50)
        state.update_stage_status("report", "pending", None, 0)
        
        progress = state.get_progress()
        
        assert progress == 50
    
    def test_add_execution_step(self):
        """测试添加执行步骤"""
        state = AgentState(target="http://example.com", task_id="task_123")
        
        state.add_execution_step("baseinfo", {"status": "success"}, "success")
        
        assert len(state.execution_history) == 1
        assert state.execution_history[0]["task"] == "baseinfo"
    
    def test_add_vulnerability(self):
        """测试添加漏洞"""
        state = AgentState(target="http://example.com", task_id="task_123")
        
        vuln = {
            "name": "SQL Injection",
            "severity": "high",
            "url": "http://example.com/vuln?id=1"
        }
        state.add_vulnerability(vuln)
        
        assert len(state.vulnerabilities) == 1
        assert state.vulnerabilities[0]["name"] == "SQL Injection"
    
    def test_add_error(self):
        """测试添加错误"""
        state = AgentState(target="http://example.com", task_id="task_123")
        
        state.add_error("Connection timeout")
        
        assert len(state.errors) == 1
        assert state.errors[0] == "Connection timeout"
    
    def test_mark_complete(self):
        """测试标记完成"""
        state = AgentState(target="http://example.com", task_id="task_123")
        
        state.mark_complete()
        
        assert state.is_complete is True
        assert state.should_continue is False
    
    def test_append_chat_history(self):
        """测试追加聊天历史"""
        state = AgentState(target="http://example.com", task_id="task_123")
        
        state.append_chat_history("user", "开始扫描")
        state.append_chat_history("assistant", "好的，正在开始扫描...")
        
        assert len(state.chat_history) == 2
        assert state.chat_history[0]["role"] == "user"
    
    def test_pause_and_resume_workflow(self):
        """测试暂停和恢复工作流"""
        state = AgentState(target="http://example.com", task_id="task_123")
        
        state.pause_workflow("等待用户确认")
        
        assert state.workflow_paused is True
        assert state.workflow_status == "paused"
        assert state.persistence_metadata["pause_reason"] == "等待用户确认"
        
        state.resume_workflow()
        
        assert state.workflow_paused is False
        assert state.workflow_status == "running"
    
    def test_update_websocket_status(self):
        """测试更新WebSocket状态"""
        state = AgentState(target="http://example.com", task_id="task_123")
        
        state.update_websocket_status(True, "session_123")
        
        assert state.websocket_connected is True
        assert state.websocket_session_id == "session_123"
        assert state.last_heartbeat is not None
    
    def test_set_workflow_running(self):
        """测试设置工作流运行状态"""
        state = AgentState(target="http://example.com", task_id="task_123")
        
        state.set_workflow_running()
        
        assert state.workflow_status == "running"
        assert state.workflow_paused is False
    
    def test_set_workflow_completed(self):
        """测试设置工作流完成状态"""
        state = AgentState(target="http://example.com", task_id="task_123")
        
        state.set_workflow_completed()
        
        assert state.workflow_status == "completed"
        assert state.is_complete is True
    
    def test_set_workflow_failed(self):
        """测试设置工作流失败状态"""
        state = AgentState(target="http://example.com", task_id="task_123")
        
        state.set_workflow_failed("Connection error")
        
        assert state.workflow_status == "failed"
        assert "Connection error" in state.errors
    
    def test_to_dict(self):
        """测试转换为字典"""
        state = AgentState(
            target="http://example.com",
            task_id="task_123",
            user_id="user_001"
        )
        state.add_vulnerability({"name": "XSS"})
        
        data = state.to_dict()
        
        assert data["target"] == "http://example.com"
        assert data["task_id"] == "task_123"
        assert data["user_id"] == "user_001"
        assert len(data["vulnerabilities"]) == 1
    
    def test_from_dict(self):
        """测试从字典创建实例"""
        data = {
            "target": "http://example.com",
            "task_id": "task_123",
            "user_id": "user_001",
            "workflow_status": "running",
            "vulnerabilities": [{"name": "SQLi"}],
            "completed_tasks": ["baseinfo"]
        }
        
        state = AgentState.from_dict(data)
        
        assert state.target == "http://example.com"
        assert state.task_id == "task_123"
        assert state.workflow_status == "running"
        assert len(state.vulnerabilities) == 1
        assert len(state.completed_tasks) == 1


class TestAgentStateWebSocket:
    """AgentState WebSocket功能测试"""
    
    @pytest.mark.asyncio
    async def test_set_websocket_callback(self):
        """测试设置WebSocket回调"""
        state = AgentState(target="http://example.com", task_id="task_123")
        
        messages = []
        
        async def callback(msg):
            messages.append(msg)
        
        state.set_websocket_callback(callback)
        
        assert state._websocket_callback is not None
    
    @pytest.mark.asyncio
    async def test_send_message_to_frontend(self):
        """测试发送消息到前端"""
        state = AgentState(target="http://example.com", task_id="task_123")
        
        messages = []
        
        async def callback(msg):
            messages.append(msg)
        
        state.set_websocket_callback(callback)
        
        await state.send_message_to_frontend("test_message", {"data": "test"})
        
        assert len(messages) == 1
        assert messages[0]["type"] == "test_message"
        assert messages[0]["payload"]["data"] == "test"
    
    @pytest.mark.asyncio
    async def test_send_ai_message(self):
        """测试发送AI消息"""
        state = AgentState(target="http://example.com", task_id="task_123")
        
        messages = []
        
        async def callback(msg):
            messages.append(msg)
        
        state.set_websocket_callback(callback)
        
        await state.send_ai_message("正在分析目标...")
        
        assert len(messages) == 1
        assert messages[0]["type"] == "ai_message"
        assert len(state.chat_history) == 1
    
    @pytest.mark.asyncio
    async def test_send_decision(self):
        """测试发送决策"""
        state = AgentState(target="http://example.com", task_id="task_123")
        
        messages = []
        
        async def callback(msg):
            messages.append(msg)
        
        state.set_websocket_callback(callback)
        
        await state.send_decision("execute_tools", "建议执行扫描工具", ["baseinfo", "portscan"])
        
        assert len(messages) == 1
        assert messages[0]["type"] == "decision"
        assert len(state.decision_history) == 1
    
    @pytest.mark.asyncio
    async def test_broadcast_progress(self):
        """测试广播进度"""
        state = AgentState(target="http://example.com", task_id="task_123")
        
        messages = []
        
        async def callback(msg):
            messages.append(msg)
        
        state.set_websocket_callback(callback)
        
        await state.broadcast_progress("planning", 50, "信息收集中", "info_collection")
        
        assert len(messages) == 1
        assert messages[0]["type"] == "progress"
        assert state.stage_status["planning"]["progress"] == 50
    
    @pytest.mark.asyncio
    async def test_request_user_confirmation(self):
        """测试请求用户确认"""
        state = AgentState(target="http://example.com", task_id="task_123")
        
        messages = []
        
        async def callback(msg):
            messages.append(msg)
        
        state.set_websocket_callback(callback)
        
        task = asyncio.create_task(
            state.request_user_confirmation("是否继续执行？", ["confirm", "cancel"])
        )
        
        await asyncio.sleep(0.1)
        
        assert state._pending_confirmation is True
        assert state.workflow_paused is True
        
        state.set_user_confirmation_result("confirm")
        
        result = await task
        
        assert result == "confirm"
        assert state._pending_confirmation is False
    
    @pytest.mark.asyncio
    async def test_send_tool_execution_start(self):
        """测试发送工具执行开始通知"""
        state = AgentState(target="http://example.com", task_id="task_123")
        
        messages = []
        
        async def callback(msg):
            messages.append(msg)
        
        state.set_websocket_callback(callback)
        
        await state.send_tool_execution_start("baseinfo", "基础信息收集")
        
        assert len(messages) == 1
        assert messages[0]["payload"]["tool_name"] == "baseinfo"
        assert messages[0]["payload"]["status"] == "started"
    
    @pytest.mark.asyncio
    async def test_send_tool_execution_result(self):
        """测试发送工具执行结果"""
        state = AgentState(target="http://example.com", task_id="task_123")
        
        messages = []
        
        async def callback(msg):
            messages.append(msg)
        
        state.set_websocket_callback(callback)
        
        await state.send_tool_execution_result("baseinfo", True, {"ip": "192.168.1.1"})
        
        assert len(messages) == 1
        assert messages[0]["payload"]["status"] == "completed"
    
    @pytest.mark.asyncio
    async def test_send_report_ready(self):
        """测试发送报告就绪通知"""
        state = AgentState(target="http://example.com", task_id="task_123")
        
        messages = []
        
        async def callback(msg):
            messages.append(msg)
        
        state.set_websocket_callback(callback)
        
        await state.send_report_ready("report_123", "扫描报告", "/api/reports/download/report.md")
        
        assert len(messages) == 1
        assert messages[0]["type"] == "report_ready"
        assert state.report_file_path == "/api/reports/download/report.md"
    
    @pytest.mark.asyncio
    async def test_send_error(self):
        """测试发送错误通知"""
        state = AgentState(target="http://example.com", task_id="task_123")
        
        messages = []
        
        async def callback(msg):
            messages.append(msg)
        
        state.set_websocket_callback(callback)
        
        await state.send_error("连接超时", "network")
        
        assert len(messages) == 1
        assert messages[0]["type"] == "error"
        assert len(state.errors) == 1
