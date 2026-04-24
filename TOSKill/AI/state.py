"""
Agent 状态管理

定义Agent的状态结构,用于LangGraph的状态传递。
支持子图模式切换、全局记忆存储、WebSocket实时通信
"""
from typing import Dict, List, Optional, Any, Callable, Awaitable
from dataclasses import dataclass, field
from datetime import datetime
import asyncio
import logging
import json
import time
import os
import hashlib

logger = logging.getLogger(__name__)


class DataIntegrityError(Exception):
    """数据完整性错误"""
    pass


class StatePersistenceError(Exception):
    """状态持久化错误"""
    pass


@dataclass
class AgentState:
    """Agent状态类 - 支持多子图模式、WebSocket交互和记忆管理"""
    
    target: str
    task_id: str
    
    chat_instance_id: str = ""
    user_id: Optional[str] = None
    
    workflow_status: str = "idle"
    workflow_paused: bool = False
    workflow_paused_at: Optional[str] = None
    workflow_resume_from: Optional[str] = None
    
    websocket_connected: bool = False
    websocket_session_id: Optional[str] = None
    last_heartbeat: Optional[str] = None
    
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    persistence_metadata: Dict[str, Any] = field(default_factory=dict)
    
    planned_tasks: List[str] = field(default_factory=list)
    current_task: Optional[str] = None
    completed_tasks: List[str] = field(default_factory=list)
    tool_results: Dict[str, Any] = field(default_factory=dict)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    target_context: Dict[str, Any] = field(default_factory=dict)
    execution_history: List[Dict[str, Any]] = field(default_factory=list)
    is_complete: bool = False
    should_continue: bool = True
    next_action: str = ""
    decision_history: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    stage_status: Dict[str, Dict[str, Any]] = field(default_factory=lambda: {
        "planning": {"status": "pending", "sub_status": "pending", "progress": 0, "logs": []},
        "tool_execution": {"status": "pending", "sub_status": "pending", "progress": 0, "logs": []},
        "report": {"status": "pending", "sub_status": "pending", "progress": 0, "logs": []}
    })
    vuln_scan_results: Dict[str, Any] = field(default_factory=dict)
    scan_summary: Dict[str, Any] = field(default_factory=dict)
    report: str = ""
    report_file_path: Optional[str] = None
    
    user_choice: str = ""
    chat_history: List[Dict] = field(default_factory=list)
    chat_summary: str = "无"
    user_name: str = "用户"
    need_generate_script: bool = False
    uploaded_script_path: Optional[str] = None
    
    next_mode: str = "info"
    task_history: List[str] = field(default_factory=list)
    
    _websocket_callback: Optional[Callable[[Dict[str, Any]], Awaitable[None]]] = field(default=None, repr=False)
    _user_confirmation_event: Optional[asyncio.Event] = field(default=None, repr=False)
    _user_confirmation_result: Optional[str] = field(default=None, repr=False)
    _pending_confirmation: bool = field(default=False, repr=False)
    
    def set_websocket_callback(self, callback: Callable[[Dict[str, Any]], Awaitable[None]]):
        """设置WebSocket消息发送回调"""
        self._websocket_callback = callback
    
    async def send_message_to_frontend(self, message_type: str, payload: Dict[str, Any]):
        """
        发送消息到前端
        
        Args:
            message_type: 消息类型
            payload: 消息内容
        """
        if self._websocket_callback:
            try:
                message = {
                    "type": message_type,
                    "payload": {
                        "task_id": self.task_id,
                        "timestamp": datetime.now().isoformat(),
                        **payload
                    }
                }
                await self._websocket_callback(message)
                logger.debug(f"发送WebSocket消息: {message_type}")
            except Exception as e:
                logger.error(f"发送WebSocket消息失败: {e}")
    
    async def broadcast_progress(self, stage: str, progress: int, message: str, sub_status: str = None):
        """
        广播进度更新
        
        Args:
            stage: 阶段名称
            progress: 进度百分比
            message: 进度消息
            sub_status: 子状态
        """
        self.update_stage_status(stage, "running", sub_status, progress, message)
        
        await self.send_message_to_frontend("progress", {
            "stage": stage,
            "progress": progress,
            "message": message,
            "sub_status": sub_status
        })
    
    async def send_ai_message(self, content: str, message_type: str = "text"):
        """
        发送AI消息到前端
        
        Args:
            content: 消息内容
            message_type: 消息类型
        """
        self.append_chat_history("assistant", content)
        
        await self.send_message_to_frontend("ai_message", {
            "content": content,
            "message_type": message_type
        })
    
    async def send_decision(self, action: str, reason: str, tools: List[str] = None):
        """
        发送决策结果到前端
        
        Args:
            action: 决策动作
            reason: 决策原因
            tools: 相关工具列表
        """
        decision = {
            "action": action,
            "reason": reason,
            "tools": tools or []
        }
        
        self.decision_history.append({
            "action": action,
            "reason": reason,
            "tools": tools,
            "timestamp": datetime.now().isoformat()
        })
        
        await self.send_message_to_frontend("decision", {
            "decision": decision
        })
    
    async def request_user_confirmation(self, prompt: str, options: List[str] = None) -> str:
        """
        请求用户确认
        
        Args:
            prompt: 提示信息
            options: 可选项列表
            
        Returns:
            str: 用户选择结果
        """
        self._pending_confirmation = True
        self._user_confirmation_result = None
        self._user_confirmation_event = asyncio.Event()
        
        await self.send_message_to_frontend("confirmation_required", {
            "prompt": prompt,
            "options": options or ["confirm", "cancel", "skip"]
        })
        
        self.pause_workflow("等待用户确认")
        
        try:
            await self._user_confirmation_event.wait()
        except asyncio.CancelledError:
            logger.warning(f"用户确认等待被取消: {self.task_id}")
            return "cancel"
        finally:
            self._pending_confirmation = False
            self._user_confirmation_event = None
        
        result = self._user_confirmation_result or "cancel"
        logger.info(f"用户确认结果: {result}")
        
        if result == "confirm":
            self.resume_workflow()
        
        return result
    
    def set_user_confirmation_result(self, result: str):
        """
        设置用户确认结果
        
        Args:
            result: 用户选择结果
        """
        self._user_confirmation_result = result
        if self._user_confirmation_event:
            self._user_confirmation_event.set()
    
    async def send_tool_execution_start(self, tool_name: str, description: str = ""):
        """发送工具执行开始通知"""
        await self.send_message_to_frontend("tool_execution", {
            "tool_name": tool_name,
            "status": "started",
            "description": description
        })
    
    async def send_tool_execution_result(self, tool_name: str, success: bool, result: Any = None, error: str = None):
        """发送工具执行结果"""
        await self.send_message_to_frontend("tool_execution", {
            "tool_name": tool_name,
            "status": "completed" if success else "failed",
            "result": result,
            "error": error
        })
    
    async def send_report_ready(self, report_id: str, report_name: str, download_url: str):
        """发送报告就绪通知"""
        self.report_file_path = download_url
        
        await self.send_message_to_frontend("report_ready", {
            "report": {
                "id": report_id,
                "name": report_name,
                "download_url": download_url
            }
        })
    
    async def send_error(self, error_message: str, error_type: str = "general"):
        """发送错误通知"""
        self.add_error(error_message)
        
        await self.send_message_to_frontend("error", {
            "error": error_message,
            "error_type": error_type
        })
    
    def update_stage_status(self, stage: str, status: str = None, sub_status: str = None, progress: int = None, log: str = None):
        """更新阶段状态"""
        if stage in self.stage_status:
            if status:
                self.stage_status[stage]["status"] = status
            if sub_status:
                self.stage_status[stage]["sub_status"] = sub_status
            if progress is not None:
                self.stage_status[stage]["progress"] = progress
            if log:
                self.stage_status[stage]["logs"].append({
                    "timestamp": datetime.now().isoformat(),
                    "message": log,
                    "sub_status": sub_status or self.stage_status[stage]["sub_status"]
                })
    
    def get_progress(self) -> int:
        """获取总进度"""
        total = sum(s["progress"] for s in self.stage_status.values())
        count = len(self.stage_status)
        return int(total / count) if count > 0 else 0
    
    def add_execution_step(self, task: str, result: Any, status: str = "success", step_type: str = "tool_execution"):
        """添加执行步骤"""
        step = {
            "step_number": len(self.execution_history) + 1,
            "task": task,
            "step_type": step_type,
            "status": status,
            "timestamp": time.time(),
            "timestamp_iso": datetime.now().isoformat(),
            "result": result
        }
        self.execution_history.append(step)
    
    def add_execution_step_start(self, task: str, step_type: str = "tool_execution", input_params: Dict[str, Any] = None, processing_logic: str = ""):
        """记录执行步骤开始"""
        step_number = len(self.execution_history) + 1
        step = {
            "step_number": step_number,
            "task": task,
            "step_type": step_type,
            "status": "running",
            "timestamp": time.time(),
            "timestamp_iso": datetime.now().isoformat(),
            "input_params": input_params or {},
            "start_time": time.time()
        }
        self.execution_history.append(step)
        return step_number
    
    def update_execution_step(self, step_number: int, result: Any = None, status: str = None, state_transitions: List[str] = None):
        """更新执行步骤"""
        if step_number <= len(self.execution_history):
            step = self.execution_history[step_number - 1]
            if result is not None:
                step["result"] = result
            if status is not None:
                step["status"] = status
                if status in ["success", "failed"] and "start_time" in step:
                    step["execution_time"] = time.time() - step["start_time"]
            if state_transitions:
                step["state_transitions"] = state_transitions
    
    def update_context(self, key: str, value: Any):
        """更新目标上下文"""
        self.target_context[key] = value
    
    def add_vulnerability(self, vuln: Dict[str, Any]):
        """添加漏洞"""
        self.vulnerabilities.append(vuln)
    
    def add_error(self, error: str):
        """添加错误"""
        self.errors.append(error)
    
    def mark_complete(self):
        """标记任务完成"""
        self.is_complete = True
        self.should_continue = False
    
    def append_chat_history(self, role: str, content: str):
        """统一追加聊天历史"""
        self.chat_history.append({
            "role": role, 
            "content": content,
            "timestamp": datetime.now().isoformat()
        })
    
    def pause_workflow(self, reason: str = ""):
        """暂停工作流"""
        self.workflow_paused = True
        self.workflow_status = "paused"
        self.workflow_paused_at = datetime.now().isoformat()
        self.updated_at = datetime.now().isoformat()
        if reason:
            self.persistence_metadata["pause_reason"] = reason
    
    def resume_workflow(self):
        """恢复工作流"""
        self.workflow_paused = False
        self.workflow_status = "running"
        self.workflow_resume_from = datetime.now().isoformat()
        self.updated_at = datetime.now().isoformat()
    
    def update_websocket_status(self, connected: bool, session_id: str = None):
        """更新WebSocket连接状态"""
        self.websocket_connected = connected
        if session_id:
            self.websocket_session_id = session_id
        self.last_heartbeat = datetime.now().isoformat()
        self.updated_at = datetime.now().isoformat()
    
    def update_timestamp(self):
        """更新时间戳"""
        self.updated_at = datetime.now().isoformat()
    
    def set_workflow_running(self):
        """设置工作流运行状态"""
        self.workflow_status = "running"
        self.workflow_paused = False
        self.updated_at = datetime.now().isoformat()
    
    def set_workflow_completed(self):
        """设置工作流完成状态"""
        self.workflow_status = "completed"
        self.workflow_paused = False
        self.is_complete = True
        self.updated_at = datetime.now().isoformat()
    
    def set_workflow_failed(self, error: str = ""):
        """设置工作流失败状态"""
        self.workflow_status = "failed"
        self.workflow_paused = False
        if error:
            self.add_error(error)
        self.updated_at = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "target": self.target,
            "task_id": self.task_id,
            "chat_instance_id": self.chat_instance_id,
            "user_id": self.user_id,
            "workflow_status": self.workflow_status,
            "workflow_paused": self.workflow_paused,
            "workflow_paused_at": self.workflow_paused_at,
            "workflow_resume_from": self.workflow_resume_from,
            "websocket_connected": self.websocket_connected,
            "websocket_session_id": self.websocket_session_id,
            "last_heartbeat": self.last_heartbeat,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "persistence_metadata": self.persistence_metadata,
            "planned_tasks": self.planned_tasks,
            "current_task": self.current_task,
            "completed_tasks": self.completed_tasks,
            "tool_results": self.tool_results,
            "vulnerabilities": self.vulnerabilities,
            "target_context": self.target_context,
            "execution_history": self.execution_history,
            "errors": self.errors,
            "is_complete": self.is_complete,
            "should_continue": self.should_continue,
            "next_action": self.next_action,
            "decision_history": self.decision_history,
            "progress": self.get_progress(),
            "vuln_scan_results": self.vuln_scan_results,
            "scan_summary": self.scan_summary,
            "report": self.report,
            "report_file_path": self.report_file_path,
            "user_choice": self.user_choice,
            "chat_history": self.chat_history,
            "chat_summary": self.chat_summary,
            "user_name": self.user_name,
            "need_generate_script": self.need_generate_script,
            "uploaded_script_path": self.uploaded_script_path,
            "next_mode": self.next_mode,
            "task_history": self.task_history,
            "stage_status": self.stage_status
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentState":
        """从字典创建实例"""
        instance = cls(
            target=data.get("target", ""),
            task_id=data.get("task_id", ""),
            chat_instance_id=data.get("chat_instance_id", ""),
            user_id=data.get("user_id"),
            workflow_status=data.get("workflow_status", "idle"),
            workflow_paused=data.get("workflow_paused", False),
            workflow_paused_at=data.get("workflow_paused_at"),
            workflow_resume_from=data.get("workflow_resume_from"),
            websocket_connected=data.get("websocket_connected", False),
            websocket_session_id=data.get("websocket_session_id"),
            last_heartbeat=data.get("last_heartbeat"),
            created_at=data.get("created_at", datetime.now().isoformat()),
            updated_at=data.get("updated_at", datetime.now().isoformat()),
            persistence_metadata=data.get("persistence_metadata", {}),
            planned_tasks=data.get("planned_tasks", []),
            current_task=data.get("current_task"),
            completed_tasks=data.get("completed_tasks", []),
            tool_results=data.get("tool_results", {}),
            vulnerabilities=data.get("vulnerabilities", []),
            target_context=data.get("target_context", {}),
            execution_history=data.get("execution_history", []),
            errors=data.get("errors", []),
            is_complete=data.get("is_complete", False),
            should_continue=data.get("should_continue", True),
            next_action=data.get("next_action", ""),
            decision_history=data.get("decision_history", []),
            vuln_scan_results=data.get("vuln_scan_results", {}),
            scan_summary=data.get("scan_summary", {}),
            report=data.get("report", ""),
            report_file_path=data.get("report_file_path"),
            user_choice=data.get("user_choice", ""),
            chat_history=data.get("chat_history", []),
            chat_summary=data.get("chat_summary", "无"),
            user_name=data.get("user_name", "用户"),
            need_generate_script=data.get("need_generate_script", False),
            uploaded_script_path=data.get("uploaded_script_path"),
            next_mode=data.get("next_mode", "info"),
            task_history=data.get("task_history", [])
        )
        
        if "stage_status" in data:
            instance.stage_status = data["stage_status"]
        
        return instance
    
    def validate_data_integrity(self) -> Dict[str, Any]:
        """
        验证数据完整性
        
        Returns:
            Dict包含验证结果和详细信息
        """
        validation_result = {
            "is_valid": True,
            "errors": [],
            "warnings": [],
            "field_status": {}
        }
        
        required_fields = {
            "target": (str, False),
            "task_id": (str, False),
            "execution_history": (list, True),
            "tool_results": (dict, True),
            "vulnerabilities": (list, True),
            "chat_history": (list, True),
            "scan_summary": (dict, True),
            "report": (str, True),
            "completed_tasks": (list, True),
            "errors": (list, True)
        }
        
        for field_name, (expected_type, allow_empty) in required_fields.items():
            value = getattr(self, field_name, None)
            
            if value is None:
                validation_result["errors"].append(f"字段 {field_name} 未初始化")
                validation_result["field_status"][field_name] = "missing"
                validation_result["is_valid"] = False
            elif not isinstance(value, expected_type):
                validation_result["errors"].append(
                    f"字段 {field_name} 类型错误: 期望 {expected_type.__name__}, 实际 {type(value).__name__}"
                )
                validation_result["field_status"][field_name] = "type_error"
                validation_result["is_valid"] = False
            elif not allow_empty and not value and field_name not in ["report"]:
                validation_result["warnings"].append(f"字段 {field_name} 为空")
                validation_result["field_status"][field_name] = "empty"
            else:
                validation_result["field_status"][field_name] = "valid"
        
        for i, step in enumerate(self.execution_history):
            if not isinstance(step, dict):
                validation_result["errors"].append(f"execution_history[{i}] 不是字典类型")
                validation_result["is_valid"] = False
            else:
                required_keys = ["task", "timestamp"]
                for key in required_keys:
                    if key not in step:
                        validation_result["warnings"].append(f"execution_history[{i}] 缺少 {key} 字段")
        
        for vuln in self.vulnerabilities:
            if not isinstance(vuln, dict):
                validation_result["errors"].append(f"vulnerabilities 包含非字典元素")
                validation_result["is_valid"] = False
                break
        
        for msg in self.chat_history:
            if not isinstance(msg, dict):
                validation_result["errors"].append(f"chat_history 包含非字典元素")
                validation_result["is_valid"] = False
                break
            if "role" not in msg or "content" not in msg:
                validation_result["warnings"].append(f"chat_history 消息缺少 role 或 content 字段")
        
        return validation_result
    
    def ensure_data_integrity(self) -> None:
        """
        确保数据完整性，自动修复可修复的问题
        
        Raises:
            DataIntegrityError: 当数据完整性无法修复时抛出
        """
        if not isinstance(self.execution_history, list):
            logger.warning("execution_history 不是列表，正在重置为空列表")
            self.execution_history = []
        
        if not isinstance(self.tool_results, dict):
            logger.warning("tool_results 不是字典，正在重置为空字典")
            self.tool_results = {}
        
        if not isinstance(self.vulnerabilities, list):
            logger.warning("vulnerabilities 不是列表，正在重置为空列表")
            self.vulnerabilities = []
        
        if not isinstance(self.chat_history, list):
            logger.warning("chat_history 不是列表，正在重置为空列表")
            self.chat_history = []
        
        if not isinstance(self.scan_summary, dict):
            logger.warning("scan_summary 不是字典，正在重置为空字典")
            self.scan_summary = {}
        
        if not isinstance(self.completed_tasks, list):
            logger.warning("completed_tasks 不是列表，正在重置为空列表")
            self.completed_tasks = []
        
        if not isinstance(self.errors, list):
            logger.warning("errors 不是列表，正在重置为空列表")
            self.errors = []
        
        if not isinstance(self.report, str):
            self.report = ""
        
        validation = self.validate_data_integrity()
        if not validation["is_valid"]:
            raise DataIntegrityError(f"数据完整性验证失败: {validation['errors']}")
        
        logger.info("数据完整性检查通过")
    
    def save_to_file(self, file_path: Optional[str] = None) -> str:
        """
        保存状态到文件
        
        Args:
            file_path: 保存路径，如果为None则使用默认路径
            
        Returns:
            实际保存的文件路径
        """
        if file_path is None:
            save_dir = "state_persistence"
            os.makedirs(save_dir, exist_ok=True)
            file_path = os.path.join(save_dir, f"state_{self.task_id}.json")
        
        try:
            state_dict = self.to_dict()
            state_dict["_metadata"] = {
                "saved_at": datetime.now().isoformat(),
                "version": "1.0",
                "checksum": self._calculate_checksum()
            }
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(state_dict, f, ensure_ascii=False, indent=2)
            
            logger.info(f"状态已保存到: {file_path}")
            return file_path
            
        except Exception as e:
            raise StatePersistenceError(f"保存状态失败: {e}")
    
    @classmethod
    def load_from_file(cls, file_path: str) -> "AgentState":
        """
        从文件加载状态
        
        Args:
            file_path: 状态文件路径
            
        Returns:
            AgentState 实例
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            instance = cls.from_dict(data)
            
            if "_metadata" in data:
                instance.persistence_metadata = data["_metadata"]
                logger.info(f"从文件加载状态: {file_path}, 保存时间: {data['_metadata'].get('saved_at')}")
            
            return instance
            
        except Exception as e:
            raise StatePersistenceError(f"加载状态失败: {e}")
    
    def _calculate_checksum(self) -> str:
        """计算状态数据的校验和"""
        state_str = json.dumps(self.to_dict(), sort_keys=True, ensure_ascii=False)
        return hashlib.md5(state_str.encode()).hexdigest()
    
    def merge_tool_results(self, new_results: Dict[str, Any], overwrite: bool = False) -> None:
        """
        合并工具结果
        
        Args:
            new_results: 新的工具结果字典
            overwrite: 是否覆盖已存在的结果
        """
        for tool_name, result in new_results.items():
            if overwrite or tool_name not in self.tool_results:
                self.tool_results[tool_name] = result
                logger.debug(f"合并工具结果: {tool_name}")
            else:
                logger.debug(f"跳过已存在的工具结果: {tool_name}")
        
        self.update_timestamp()
    
    def add_scan_result(self, tool_name: str, result: Dict[str, Any], 
                        execution_time: float = 0, success: bool = True) -> None:
        """
        添加扫描结果（完整版）
        
        Args:
            tool_name: 工具名称
            result: 扫描结果数据
            execution_time: 执行时间
            success: 是否成功
        """
        timestamp = datetime.now().isoformat()
        
        scan_record = {
            "tool_name": tool_name,
            "target": self.target,
            "result": result,
            "success": success,
            "execution_time": execution_time,
            "timestamp": timestamp,
            "task_id": self.task_id
        }
        
        self.tool_results[tool_name] = result
        
        self.execution_history.append(scan_record)
        
        if success and isinstance(result, dict):
            if "vulnerabilities" in result:
                vulns = result["vulnerabilities"]
                if isinstance(vulns, list):
                    for vuln in vulns:
                        vuln["_source_tool"] = tool_name
                        vuln["_detected_at"] = timestamp
                    self.vulnerabilities.extend(vulns)
                    logger.info(f"从 {tool_name} 发现 {len(vulns)} 个漏洞")
            
            if "ports" in result:
                self.target_context.setdefault("open_ports", []).extend(result["ports"])
            if "subdomains" in result:
                self.target_context.setdefault("subdomains", []).extend(result["subdomains"])
            if "directories" in result:
                self.target_context.setdefault("directories", []).extend(result["directories"])
        
        self.update_timestamp()
        logger.info(f"已添加扫描结果: {tool_name}, 成功: {success}")
    
    def get_execution_summary(self) -> Dict[str, Any]:
        """
        获取执行摘要
        
        Returns:
            执行摘要字典
        """
        total_tools = len(self.tool_results)
        successful_tools = sum(
            1 for step in self.execution_history 
            if isinstance(step, dict) and step.get("success", False)
        )
        
        return {
            "task_id": self.task_id,
            "target": self.target,
            "total_tools_executed": total_tools,
            "successful_executions": successful_tools,
            "total_vulnerabilities": len(self.vulnerabilities),
            "total_errors": len(self.errors),
            "execution_history_count": len(self.execution_history),
            "completed_tasks": self.completed_tasks,
            "workflow_status": self.workflow_status,
            "is_complete": self.is_complete,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "scan_summary": self.scan_summary
        }
    
    def track_data_flow(self, from_atom: str, to_atom: str, data_keys: List[str] = None) -> Dict[str, Any]:
        """
        追踪数据流转
        
        Args:
            from_atom: 源原子名称
            to_atom: 目标原子名称
            data_keys: 追踪的数据键列表
            
        Returns:
            数据流转记录
        """
        if data_keys is None:
            data_keys = ["tool_results", "vulnerabilities", "execution_history", "scan_summary"]
        
        flow_record = {
            "from": from_atom,
            "to": to_atom,
            "timestamp": datetime.now().isoformat(),
            "data_snapshot": {}
        }
        
        for key in data_keys:
            value = getattr(self, key, None)
            if value is not None:
                if isinstance(value, (list, dict)):
                    flow_record["data_snapshot"][key] = {
                        "type": type(value).__name__,
                        "size": len(value),
                        "preview": str(value)[:200] if value else None
                    }
                else:
                    flow_record["data_snapshot"][key] = {
                        "type": type(value).__name__,
                        "value": str(value)[:200]
                    }
        
        self.persistence_metadata.setdefault("data_flow_history", []).append(flow_record)
        
        logger.debug(f"数据流转追踪: {from_atom} -> {to_atom}")
        return flow_record
    
    def get_all_scan_data(self) -> Dict[str, Any]:
        """
        获取所有扫描数据（用于传递给下一个子图）
        
        Returns:
            包含所有扫描数据的字典
        """
        return {
            "task_id": self.task_id,
            "target": self.target,
            "tool_results": self.tool_results.copy(),
            "vulnerabilities": self.vulnerabilities.copy(),
            "execution_history": self.execution_history.copy(),
            "scan_summary": self.scan_summary.copy(),
            "target_context": self.target_context.copy(),
            "completed_tasks": self.completed_tasks.copy(),
            "errors": self.errors.copy(),
            "chat_history": self.chat_history.copy(),
            "report": self.report
        }
    
    def import_scan_data(self, scan_data: Dict[str, Any], merge: bool = True) -> None:
        """
        导入扫描数据（从上一个子图接收）
        
        Args:
            scan_data: 扫描数据字典
            merge: 是否合并（True）或覆盖（False）
        """
        if merge:
            if "tool_results" in scan_data:
                self.merge_tool_results(scan_data["tool_results"])
            if "vulnerabilities" in scan_data:
                existing_ids = {v.get("id") for v in self.vulnerabilities if v.get("id")}
                for vuln in scan_data["vulnerabilities"]:
                    if vuln.get("id") not in existing_ids:
                        self.vulnerabilities.append(vuln)
            if "execution_history" in scan_data:
                self.execution_history.extend(scan_data["execution_history"])
            if "target_context" in scan_data:
                self.target_context.update(scan_data["target_context"])
            if "completed_tasks" in scan_data:
                for task in scan_data["completed_tasks"]:
                    if task not in self.completed_tasks:
                        self.completed_tasks.append(task)
        else:
            if "tool_results" in scan_data:
                self.tool_results = scan_data["tool_results"].copy()
            if "vulnerabilities" in scan_data:
                self.vulnerabilities = scan_data["vulnerabilities"].copy()
            if "execution_history" in scan_data:
                self.execution_history = scan_data["execution_history"].copy()
            if "target_context" in scan_data:
                self.target_context = scan_data["target_context"].copy()
            if "completed_tasks" in scan_data:
                self.completed_tasks = scan_data["completed_tasks"].copy()
        
        self.update_timestamp()
        logger.info(f"已导入扫描数据，合并模式: {merge}")
