"""
Agent 状态管理

定义Agent的状态结构,用于LangGraph的状态传递。
支持子图模式切换、全局记忆存储
"""
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import asyncio
import logging
import json
import time

logger = logging.getLogger(__name__)


@dataclass
class AgentState:
    """Agent状态类 - 支持多子图模式"""
    
    target: str
    task_id: str
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
    
    # 全局记忆字段
    user_choice: str = ""
    chat_history: List[Dict] = field(default_factory=list)
    chat_summary: str = "无"
    user_name: str = "用户"
    need_generate_script: bool = False
    
    # 子图模式字段
    next_mode: str = "info"  # info / vuln / report
    task_history: List[str] = field(default_factory=list)
    
    def update_stage_status(self, stage: str, status: str = None, sub_status: str = None, progress: int = None, log: str = None):
        """更新阶段状态"""
        try:
            from backend.api.websocket import manager
        except ImportError:
            from api.websocket import manager
        
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
            
            try:
                loop = asyncio.get_running_loop()
                if loop.is_running():
                    asyncio.create_task(manager.broadcast({
                        "type": "stage_update",
                        "payload": {"task_id": self.task_id, "stage": stage, "data": self.stage_status[stage]}
                    }))
            except RuntimeError:
                pass

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
        self.chat_history.append({"role": role, "content": content})
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "target": self.target,
            "task_id": self.task_id,
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
            # 记忆字段
            "user_choice": self.user_choice,
            "chat_history": self.chat_history,
            "chat_summary": self.chat_summary,
            "user_name": self.user_name,
            "need_generate_script": self.need_generate_script,
            # 子图模式
            "next_mode": self.next_mode,
            "task_history": self.task_history
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentState":
        """从字典创建实例"""
        return cls(
            target=data.get("target", ""),
            task_id=data.get("task_id", ""),
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
            # 记忆字段
            user_choice=data.get("user_choice", ""),
            chat_history=data.get("chat_history", []),
            chat_summary=data.get("chat_summary", "无"),
            user_name=data.get("user_name", "用户"),
            need_generate_script=data.get("need_generate_script", False),
            # 子图模式
            next_mode=data.get("next_mode", "info"),
            task_history=data.get("task_history", [])
        )