"""
AI对话与TOSKill对接API

提供AI对话与TOSKill扫描系统的对接功能，包括：
- 自然语言指令解析
- 扫描任务创建、查询、执行
- 报告生成和查询
- 系统状态查询
- WebSocket实时通信
- 对话上下文管理

特性：
- 支持自然语言指令解析
- 支持扫描任务创建、查询、执行等指令
- 支持报告生成和查询指令
- 支持系统状态查询指令
- 添加对话上下文管理
- 添加错误处理和日志记录
- 支持流式响应
"""
from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Callable, AsyncGenerator
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field
import logging
import asyncio
import json
import re
import uuid

from backend.api.common import APIResponse
from backend.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["AI对话TOSKill"])


class IntentType(str, Enum):
    """用户意图类型枚举"""
    CREATE_SCAN = "create_scan"
    QUERY_TASK = "query_task"
    LIST_TASKS = "list_tasks"
    CANCEL_TASK = "cancel_task"
    DELETE_TASK = "delete_task"
    GENERATE_REPORT = "generate_report"
    QUERY_REPORT = "query_report"
    SYSTEM_STATUS = "system_status"
    HEALTH_CHECK = "health_check"
    HELP = "help"
    UNKNOWN = "unknown"
    CHAT = "chat"


class ScanMode(str, Enum):
    """扫描模式枚举"""
    INFO = "info"
    VULN = "vuln"
    FULL = "full"


@dataclass
class ParsedIntent:
    """解析后的意图"""
    intent: IntentType
    confidence: float
    parameters: Dict[str, Any] = field(default_factory=dict)
    raw_message: str = ""
    explanation: str = ""


@dataclass
class ConversationContext:
    """对话上下文"""
    session_id: str
    created_at: datetime
    last_active: datetime
    history: List[Dict[str, Any]] = field(default_factory=list)
    current_task_id: Optional[str] = None
    pending_action: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class AIChatRequest(BaseModel):
    """AI对话请求模型"""
    message: str = Field(..., description="用户消息", min_length=1)
    session_id: Optional[str] = Field(None, description="会话ID")
    context: Optional[Dict[str, Any]] = Field(None, description="额外上下文")


class AIChatResponse(BaseModel):
    """AI对话响应模型"""
    session_id: str
    response: str
    intent: str
    confidence: float
    action_taken: bool
    data: Optional[Dict[str, Any]] = None
    suggestions: List[str] = Field(default_factory=list)


class StreamingChatResponse(BaseModel):
    """流式对话响应模型"""
    type: str
    content: str
    is_final: bool = False
    data: Optional[Dict[str, Any]] = None


class IntentParser:
    """自然语言意图解析器"""
    
    PATTERNS = {
        IntentType.CREATE_SCAN: [
            r"(扫描|scan|检测|分析|测试)\s*(https?://[^\s]+|[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)",
            r"(创建|新建|开始|启动)\s*(扫描|任务|scan)",
            r"(对|针对)\s*(https?://[^\s]+|[\w\.-]+)\s*(进行|执行)?\s*(扫描|检测|分析)",
            r"(帮我|请|想要)\s*(扫描|检测|分析)\s*(https?://[^\s]+|[\w\.-]+)",
            r"目标\s*[是为]?\s*(https?://[^\s]+|[\w\.-]+)",
        ],
        IntentType.QUERY_TASK: [
            r"(查询|查看|获取|显示|show|get)\s*(任务|扫描|scan|task)",
            r"任务\s*(状态|进度|详情|结果)",
            r"(任务|扫描)\s*([a-f0-9\-]{36}|[a-f0-9]{8,})",
            r"task[_\s]*id\s*[是为]?\s*([a-f0-9\-]{36}|[a-f0-9]{8,})",
        ],
        IntentType.LIST_TASKS: [
            r"(列出|显示|查看|获取|list|show)\s*(所有|全部)?\s*(任务|扫描|tasks)",
            r"(任务|扫描)\s*(列表|清单)",
            r"(正在运行|运行中|进行中)\s*(的)?\s*(任务|扫描)",
        ],
        IntentType.CANCEL_TASK: [
            r"(取消|停止|终止|cancel|stop)\s*(任务|扫描)",
            r"(任务|扫描)\s*([a-f0-9\-]{36}|[a-f0-9]{8,})\s*(取消|停止|终止)",
        ],
        IntentType.DELETE_TASK: [
            r"(删除|移除|delete|remove)\s*(任务|扫描)",
            r"(任务|扫描)\s*([a-f0-9\-]{36}|[a-f0-9]{8,})\s*(删除|移除)",
        ],
        IntentType.GENERATE_REPORT: [
            r"(生成|创建|导出|generate|create)\s*(报告|报表|report)",
            r"(任务|扫描)\s*([a-f0-9\-]{36}|[a-f0-9]{8,})\s*(的)?\s*(报告|报表)",
            r"(报告|报表)\s*(格式)?\s*(json|html|markdown|md)",
        ],
        IntentType.QUERY_REPORT: [
            r"(查询|查看|获取|显示|show|get)\s*(报告|报表|report)",
            r"报告\s*(详情|内容|结果)",
        ],
        IntentType.SYSTEM_STATUS: [
            r"(系统|服务|服务状态)\s*(状态|情况|信息|status)",
            r"(统计|统计数据|statistics|stats)",
            r"(运行|运行情况)\s*(状态|情况)",
        ],
        IntentType.HEALTH_CHECK: [
            r"(健康|健康检查|health)\s*(检查|状态|check)",
            r"(检查|检测)\s*(健康|服务状态)",
        ],
        IntentType.HELP: [
            r"(帮助|help|使用说明|使用指南|怎么用)",
            r"(能做什么|功能|支持什么)",
            r"(指令|命令)\s*(列表|说明)",
        ],
    }
    
    SCAN_MODE_KEYWORDS = {
        ScanMode.INFO: ["信息收集", "信息", "info", "基础信息", "信息探测"],
        ScanMode.VULN: ["漏洞扫描", "漏洞", "vuln", "漏洞检测", "安全检测"],
        ScanMode.FULL: ["完整扫描", "全部扫描", "full", "全面扫描", "深度扫描"],
    }
    
    def __init__(self):
        self._compiled_patterns = {}
        for intent, patterns in self.PATTERNS.items():
            self._compiled_patterns[intent] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]
    
    def parse(self, message: str) -> ParsedIntent:
        """
        解析用户消息，识别意图
        
        Args:
            message: 用户消息
            
        Returns:
            ParsedIntent: 解析后的意图
        """
        message = message.strip()
        
        for intent, patterns in self._compiled_patterns.items():
            for pattern in patterns:
                match = pattern.search(message)
                if match:
                    params = self._extract_parameters(intent, message, match)
                    return ParsedIntent(
                        intent=intent,
                        confidence=0.85,
                        parameters=params,
                        raw_message=message,
                        explanation=f"识别到{intent.value}意图"
                    )
        
        return ParsedIntent(
            intent=IntentType.CHAT,
            confidence=0.5,
            parameters={},
            raw_message=message,
            explanation="未识别到明确指令，将作为普通对话处理"
        )
    
    def _extract_parameters(self, intent: IntentType, message: str, match: re.Match) -> Dict[str, Any]:
        """提取意图参数"""
        params = {}
        
        if intent == IntentType.CREATE_SCAN:
            url_pattern = r'(https?://[^\s]+|[\w\.-]+\.[\w\.-]+)'
            url_match = re.search(url_pattern, message)
            if url_match:
                params["target"] = url_match.group(1)
                if not params["target"].startswith(("http://", "https://")):
                    params["target"] = f"https://{params['target']}"
            
            for mode, keywords in self.SCAN_MODE_KEYWORDS.items():
                if any(kw in message.lower() for kw in keywords):
                    params["scan_mode"] = mode.value
                    break
            
            if "scan_mode" not in params:
                params["scan_mode"] = ScanMode.FULL.value
            
            task_name_match = re.search(r'(?:任务名|名称)[叫是为]?\s*["\']?([^"\']+)["\']?', message)
            if task_name_match:
                params["task_name"] = task_name_match.group(1).strip()
            else:
                params["task_name"] = f"扫描任务_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        elif intent in [IntentType.QUERY_TASK, IntentType.CANCEL_TASK, IntentType.DELETE_TASK]:
            task_id_pattern = r'([a-f0-9\-]{36}|[a-f0-9]{8,})'
            task_id_match = re.search(task_id_pattern, message)
            if task_id_match:
                params["task_id"] = task_id_match.group(1)
        
        elif intent == IntentType.GENERATE_REPORT:
            task_id_pattern = r'([a-f0-9\-]{36}|[a-f0-9]{8,})'
            task_id_match = re.search(task_id_pattern, message)
            if task_id_match:
                params["task_id"] = task_id_match.group(1)
            
            if "json" in message.lower():
                params["report_format"] = "json"
            elif "html" in message.lower():
                params["report_format"] = "html"
            elif "markdown" in message.lower() or "md" in message.lower():
                params["report_format"] = "markdown"
            else:
                params["report_format"] = "json"
        
        elif intent == IntentType.LIST_TASKS:
            if "运行" in message or "running" in message.lower():
                params["status"] = "running"
            elif "完成" in message or "completed" in message.lower():
                params["status"] = "completed"
            elif "失败" in message or "failed" in message.lower():
                params["status"] = "failed"
        
        return params


class ConversationManager:
    """对话上下文管理器"""
    
    def __init__(self, max_sessions: int = 1000, session_timeout: int = 3600):
        self._sessions: Dict[str, ConversationContext] = {}
        self._max_sessions = max_sessions
        self._session_timeout = session_timeout
        self._lock = asyncio.Lock()
    
    async def get_or_create_session(self, session_id: Optional[str] = None) -> ConversationContext:
        """获取或创建会话"""
        async with self._lock:
            if session_id and session_id in self._sessions:
                session = self._sessions[session_id]
                session.last_active = datetime.now()
                return session
            
            new_session_id = session_id or str(uuid.uuid4())
            now = datetime.now()
            session = ConversationContext(
                session_id=new_session_id,
                created_at=now,
                last_active=now
            )
            self._sessions[new_session_id] = session
            
            if len(self._sessions) > self._max_sessions:
                await self._cleanup_expired_sessions()
            
            return session
    
    async def update_session(self, session_id: str, updates: Dict[str, Any]):
        """更新会话"""
        async with self._lock:
            if session_id in self._sessions:
                session = self._sessions[session_id]
                for key, value in updates.items():
                    if hasattr(session, key):
                        setattr(session, key, value)
                session.last_active = datetime.now()
    
    async def add_message(self, session_id: str, role: str, content: str):
        """添加消息到历史"""
        async with self._lock:
            if session_id in self._sessions:
                self._sessions[session_id].history.append({
                    "role": role,
                    "content": content,
                    "timestamp": datetime.now().isoformat()
                })
                self._sessions[session_id].last_active = datetime.now()
    
    async def _cleanup_expired_sessions(self):
        """清理过期会话"""
        now = datetime.now()
        expired = [
            sid for sid, session in self._sessions.items()
            if (now - session.last_active).total_seconds() > self._session_timeout
        ]
        for sid in expired:
            del self._sessions[sid]
        if expired:
            logger.info(f"清理了 {len(expired)} 个过期会话")


class TOSKillCommandExecutor:
    """TOSKill命令执行器"""
    
    def __init__(self):
        self.intent_parser = IntentParser()
    
    async def execute(self, intent: ParsedIntent, context: ConversationContext) -> Dict[str, Any]:
        """
        执行意图对应的操作
        
        Args:
            intent: 解析后的意图
            context: 对话上下文
            
        Returns:
            Dict: 执行结果
        """
        handlers = {
            IntentType.CREATE_SCAN: self._handle_create_scan,
            IntentType.QUERY_TASK: self._handle_query_task,
            IntentType.LIST_TASKS: self._handle_list_tasks,
            IntentType.CANCEL_TASK: self._handle_cancel_task,
            IntentType.DELETE_TASK: self._handle_delete_task,
            IntentType.GENERATE_REPORT: self._handle_generate_report,
            IntentType.QUERY_REPORT: self._handle_query_report,
            IntentType.SYSTEM_STATUS: self._handle_system_status,
            IntentType.HEALTH_CHECK: self._handle_health_check,
            IntentType.HELP: self._handle_help,
            IntentType.CHAT: self._handle_chat,
        }
        
        handler = handlers.get(intent.intent, self._handle_unknown)
        return await handler(intent, context)
    
    async def _handle_create_scan(self, intent: ParsedIntent, context: ConversationContext) -> Dict[str, Any]:
        """处理创建扫描任务"""
        from backend.api.toskill import task_manager, execute_toskill_workflow, TOSKillTaskStatus
        
        params = intent.parameters
        target = params.get("target")
        
        if not target:
            return {
                "success": False,
                "message": "请提供扫描目标，例如：扫描 https://example.com",
                "suggestions": ["扫描 https://example.com", "对 example.com 进行漏洞扫描"]
            }
        
        try:
            task_id = await task_manager.create_task(
                task_name=params.get("task_name", f"扫描_{target}"),
                target=target,
                scan_mode=params.get("scan_mode", "full"),
                config=params.get("config", {}),
                timeout=params.get("timeout", 3600),
                auto_report=params.get("auto_report", True)
            )
            
            async_task = asyncio.create_task(
                execute_toskill_workflow(
                    task_id=task_id,
                    target=target,
                    scan_mode=params.get("scan_mode", "full"),
                    config=params.get("config", {}),
                    timeout=params.get("timeout", 3600),
                    auto_report=params.get("auto_report", True)
                )
            )
            
            task_manager.register_running_task(task_id, async_task)
            
            context.current_task_id = task_id
            
            return {
                "success": True,
                "message": f"扫描任务已创建并启动\n目标: {target}\n任务ID: {task_id}\n扫描模式: {params.get('scan_mode', 'full')}",
                "data": {
                    "task_id": task_id,
                    "target": target,
                    "status": TOSKillTaskStatus.PENDING.value
                }
            }
        except Exception as e:
            logger.error(f"创建扫描任务失败: {e}")
            return {
                "success": False,
                "message": f"创建扫描任务失败: {str(e)}",
                "suggestions": ["请检查目标格式是否正确", "稍后重试"]
            }
    
    async def _handle_query_task(self, intent: ParsedIntent, context: ConversationContext) -> Dict[str, Any]:
        """处理查询任务"""
        from backend.api.toskill import task_manager, _format_datetime
        
        task_id = intent.parameters.get("task_id") or context.current_task_id
        
        if not task_id:
            return {
                "success": False,
                "message": "请提供任务ID，或先创建一个扫描任务",
                "suggestions": ["查询任务 <task_id>", "列出所有任务"]
            }
        
        try:
            task = await task_manager.get_task(task_id)
            
            if not task:
                return {
                    "success": False,
                    "message": f"未找到任务: {task_id}",
                    "suggestions": ["列出所有任务", "创建新扫描"]
                }
            
            duration = None
            if task["started_at"]:
                end_time = task["finished_at"] or datetime.now()
                duration = (end_time - task["started_at"]).total_seconds()
            
            return {
                "success": True,
                "message": f"任务状态:\n"
                          f"任务ID: {task['task_id']}\n"
                          f"任务名称: {task['task_name']}\n"
                          f"目标: {task['target']}\n"
                          f"状态: {task['status'].value}\n"
                          f"进度: {task['progress']}%\n"
                          f"当前阶段: {task['current_stage'].value}\n"
                          f"漏洞数量: {len(task['vulnerabilities'])}\n"
                          f"运行时长: {duration:.1f}秒" if duration else "",
                "data": {
                    "task_id": task["task_id"],
                    "task_name": task["task_name"],
                    "target": task["target"],
                    "status": task["status"].value,
                    "progress": task["progress"],
                    "current_stage": task["current_stage"].value,
                    "vulnerabilities_count": len(task["vulnerabilities"]),
                    "duration": duration
                }
            }
        except Exception as e:
            logger.error(f"查询任务失败: {e}")
            return {
                "success": False,
                "message": f"查询任务失败: {str(e)}"
            }
    
    async def _handle_list_tasks(self, intent: ParsedIntent, context: ConversationContext) -> Dict[str, Any]:
        """处理列出任务"""
        from backend.api.toskill import task_manager, _format_datetime, TOSKillTaskStatus
        
        try:
            status = intent.parameters.get("status")
            status_enum = TOSKillTaskStatus(status) if status else None
            
            tasks = await task_manager.list_tasks(status=status_enum)
            
            if not tasks:
                return {
                    "success": True,
                    "message": "当前没有任务记录",
                    "data": {"tasks": [], "total": 0}
                }
            
            task_list = []
            for task in tasks[:10]:
                task_list.append({
                    "task_id": task["task_id"],
                    "task_name": task["task_name"],
                    "target": task["target"],
                    "status": task["status"].value,
                    "progress": task["progress"]
                })
            
            message = f"共找到 {len(tasks)} 个任务:\n"
            for i, t in enumerate(task_list, 1):
                message += f"{i}. [{t['status']}] {t['task_name']} - {t['target']} ({t['progress']}%)\n"
            
            return {
                "success": True,
                "message": message,
                "data": {"tasks": task_list, "total": len(tasks)}
            }
        except Exception as e:
            logger.error(f"列出任务失败: {e}")
            return {
                "success": False,
                "message": f"列出任务失败: {str(e)}"
            }
    
    async def _handle_cancel_task(self, intent: ParsedIntent, context: ConversationContext) -> Dict[str, Any]:
        """处理取消任务"""
        from backend.api.toskill import task_manager, TOSKillTaskStatus
        
        task_id = intent.parameters.get("task_id") or context.current_task_id
        
        if not task_id:
            return {
                "success": False,
                "message": "请提供要取消的任务ID",
                "suggestions": ["取消任务 <task_id>", "列出所有任务"]
            }
        
        try:
            success = await task_manager.cancel_task(task_id)
            
            if success:
                return {
                    "success": True,
                    "message": f"任务已取消: {task_id}",
                    "data": {"task_id": task_id, "status": TOSKillTaskStatus.CANCELLED.value}
                }
            else:
                task = await task_manager.get_task(task_id)
                if not task:
                    return {
                        "success": False,
                        "message": f"未找到任务: {task_id}"
                    }
                return {
                    "success": False,
                    "message": f"任务无法取消，当前状态: {task['status'].value}"
                }
        except Exception as e:
            logger.error(f"取消任务失败: {e}")
            return {
                "success": False,
                "message": f"取消任务失败: {str(e)}"
            }
    
    async def _handle_delete_task(self, intent: ParsedIntent, context: ConversationContext) -> Dict[str, Any]:
        """处理删除任务"""
        from backend.api.toskill import task_manager
        
        task_id = intent.parameters.get("task_id") or context.current_task_id
        
        if not task_id:
            return {
                "success": False,
                "message": "请提供要删除的任务ID",
                "suggestions": ["删除任务 <task_id>", "列出所有任务"]
            }
        
        try:
            success = await task_manager.delete_task(task_id)
            
            if success:
                if context.current_task_id == task_id:
                    context.current_task_id = None
                return {
                    "success": True,
                    "message": f"任务已删除: {task_id}",
                    "data": {"task_id": task_id}
                }
            else:
                return {
                    "success": False,
                    "message": f"未找到任务: {task_id}"
                }
        except Exception as e:
            logger.error(f"删除任务失败: {e}")
            return {
                "success": False,
                "message": f"删除任务失败: {str(e)}"
            }
    
    async def _handle_generate_report(self, intent: ParsedIntent, context: ConversationContext) -> Dict[str, Any]:
        """处理生成报告"""
        from backend.api.toskill import task_manager, _generate_markdown_report, _generate_html_report, _generate_remediation_recommendations, TOSKillTaskStatus
        
        task_id = intent.parameters.get("task_id") or context.current_task_id
        
        if not task_id:
            return {
                "success": False,
                "message": "请提供任务ID以生成报告",
                "suggestions": ["生成报告 <task_id>", "列出所有任务"]
            }
        
        try:
            task = await task_manager.get_task(task_id)
            
            if not task:
                return {
                    "success": False,
                    "message": f"未找到任务: {task_id}"
                }
            
            if task["status"] != TOSKillTaskStatus.COMPLETED:
                return {
                    "success": False,
                    "message": f"任务尚未完成，当前状态: {task['status'].value}",
                    "data": {
                        "task_id": task_id,
                        "status": task["status"].value,
                        "progress": task["progress"]
                    }
                }
            
            result = task.get("result", {})
            vulnerabilities = result.get("vulnerabilities", [])
            report_format = intent.parameters.get("report_format", "json")
            
            report = {
                "report_id": str(uuid.uuid4()),
                "task_id": task_id,
                "task_name": task["task_name"],
                "target": task["target"],
                "generated_at": datetime.now().isoformat(),
                "vulnerabilities": vulnerabilities,
                "summary": {
                    "total_vulnerabilities": len(vulnerabilities),
                    "completed_tasks": len(result.get("completed_tasks", []))
                }
            }
            
            if report_format == "markdown":
                report_content = _generate_markdown_report(report)
                return {
                    "success": True,
                    "message": "报告已生成(Markdown格式)",
                    "data": {"report": report_content, "format": "markdown", "task_id": task_id}
                }
            elif report_format == "html":
                report_content = _generate_html_report(report)
                return {
                    "success": True,
                    "message": "报告已生成(HTML格式)",
                    "data": {"report": report_content, "format": "html", "task_id": task_id}
                }
            else:
                return {
                    "success": True,
                    "message": f"报告已生成(JSON格式)\n发现漏洞: {len(vulnerabilities)} 个",
                    "data": {"report": report, "format": "json", "task_id": task_id}
                }
        except Exception as e:
            logger.error(f"生成报告失败: {e}")
            return {
                "success": False,
                "message": f"生成报告失败: {str(e)}"
            }
    
    async def _handle_query_report(self, intent: ParsedIntent, context: ConversationContext) -> Dict[str, Any]:
        """处理查询报告"""
        return await self._handle_generate_report(intent, context)
    
    async def _handle_system_status(self, intent: ParsedIntent, context: ConversationContext) -> Dict[str, Any]:
        """处理系统状态查询"""
        from backend.api.toskill import task_manager
        
        try:
            stats = await task_manager.get_statistics()
            
            return {
                "success": True,
                "message": f"系统状态:\n"
                          f"总任务数: {stats['total']}\n"
                          f"运行中: {stats['active']}\n"
                          f"已完成: {stats['completed']}\n"
                          f"已失败: {stats['failed']}\n"
                          f"运行时长: {stats['uptime']:.0f}秒",
                "data": stats
            }
        except Exception as e:
            logger.error(f"查询系统状态失败: {e}")
            return {
                "success": False,
                "message": f"查询系统状态失败: {str(e)}"
            }
    
    async def _handle_health_check(self, intent: ParsedIntent, context: ConversationContext) -> Dict[str, Any]:
        """处理健康检查"""
        from backend.api.toskill import task_manager
        
        try:
            stats = await task_manager.get_statistics()
            
            components = {
                "task_manager": {"status": "healthy", "active_tasks": stats["active"]},
                "agent_graph": {"status": "healthy"},
                "tools_registry": {"status": "healthy"}
            }
            
            try:
                from TOSKill.AI.graph import ScanAgentGraph
                components["agent_graph"]["status"] = "healthy"
            except Exception as e:
                components["agent_graph"]["status"] = "degraded"
                components["agent_graph"]["message"] = str(e)
            
            try:
                from TOSKill.AI.tools.registry import registry
                components["tools_registry"]["tools_count"] = len(registry.tools)
            except Exception as e:
                components["tools_registry"]["status"] = "degraded"
                components["tools_registry"]["message"] = str(e)
            
            overall_status = "healthy"
            for comp in components.values():
                if comp.get("status") == "degraded":
                    overall_status = "degraded"
                    break
            
            return {
                "success": True,
                "message": f"健康检查完成\n状态: {overall_status}",
                "data": {
                    "status": overall_status,
                    "components": components,
                    "uptime": stats["uptime"]
                }
            }
        except Exception as e:
            logger.error(f"健康检查失败: {e}")
            return {
                "success": False,
                "message": f"健康检查失败: {str(e)}"
            }
    
    async def _handle_help(self, intent: ParsedIntent, context: ConversationContext) -> Dict[str, Any]:
        """处理帮助请求"""
        help_text = """
TOSKill AI对话助手 - 使用指南

【扫描任务】
• 扫描 https://example.com - 创建扫描任务
• 对 example.com 进行漏洞扫描 - 漏洞扫描模式
• 对 example.com 进行信息收集 - 信息收集模式

【任务管理】
• 列出所有任务 - 查看任务列表
• 查询任务 <task_id> - 查看任务详情
• 取消任务 <task_id> - 取消运行中的任务
• 删除任务 <task_id> - 删除任务

【报告生成】
• 生成报告 <task_id> - 生成JSON报告
• 生成HTML报告 <task_id> - 生成HTML格式报告
• 生成Markdown报告 <task_id> - 生成Markdown格式报告

【系统状态】
• 系统状态 - 查看系统运行状态
• 健康检查 - 检查系统健康状态

【其他】
• 帮助 - 显示此帮助信息
"""
        return {
            "success": True,
            "message": help_text,
            "data": {"commands": [
                "扫描 <目标>",
                "列出所有任务",
                "查询任务 <task_id>",
                "取消任务 <task_id>",
                "生成报告 <task_id>",
                "系统状态",
                "健康检查",
                "帮助"
            ]}
        }
    
    async def _handle_chat(self, intent: ParsedIntent, context: ConversationContext) -> Dict[str, Any]:
        """处理普通对话"""
        try:
            from langchain_openai import ChatOpenAI
            from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
            
            if not settings.OPENAI_API_KEY:
                return {
                    "success": False,
                    "message": "AI对话功能未配置，请设置OPENAI_API_KEY",
                    "suggestions": ["使用帮助命令查看可用指令", "系统状态"]
                }
            
            llm = ChatOpenAI(
                model=settings.MODEL_ID,
                temperature=0.7,
                openai_api_key=settings.OPENAI_API_KEY,
                base_url=settings.OPENAI_BASE_URL
            )
            
            system_prompt = """你是TOSKill安全扫描平台的AI助手。你可以帮助用户：
1. 创建和管理扫描任务
2. 查询任务状态和结果
3. 生成安全报告
4. 回答Web安全相关问题

如果用户想要执行扫描或管理任务，请引导他们使用相应的命令。
保持回答简洁、专业、友好。"""
            
            messages = [SystemMessage(content=system_prompt)]
            
            for msg in context.history[-5:]:
                if msg["role"] == "user":
                    messages.append(HumanMessage(content=msg["content"]))
                elif msg["role"] == "assistant":
                    messages.append(AIMessage(content=msg["content"]))
            
            messages.append(HumanMessage(content=intent.raw_message))
            
            response = await llm.ainvoke(messages)
            
            return {
                "success": True,
                "message": response.content,
                "data": {"model": settings.MODEL_ID}
            }
        except Exception as e:
            logger.error(f"AI对话失败: {e}")
            return {
                "success": False,
                "message": f"AI对话暂时不可用: {str(e)}",
                "suggestions": ["使用帮助命令查看可用指令"]
            }
    
    async def _handle_unknown(self, intent: ParsedIntent, context: ConversationContext) -> Dict[str, Any]:
        """处理未知意图"""
        return {
            "success": False,
            "message": "抱歉，我没有理解您的意思。请使用'帮助'命令查看可用指令。",
            "suggestions": ["帮助", "系统状态", "列出所有任务"]
        }


conversation_manager = ConversationManager()
command_executor = TOSKillCommandExecutor()


@router.post("/chat", response_model=APIResponse)
async def ai_chat(request: AIChatRequest):
    """
    AI对话接口
    
    处理用户消息，解析意图并执行相应操作。
    
    Args:
        request: 对话请求，包含用户消息和可选的会话ID
        
    Returns:
        APIResponse: 包含AI响应的回复
        
    Examples:
        >>> 创建扫描任务
        >>> POST /api/ai-chat/chat
        >>> {
        ...     "message": "扫描 https://example.com"
        ... }
    """
    try:
        session = await conversation_manager.get_or_create_session(request.session_id)
        
        await conversation_manager.add_message(
            session.session_id, 
            "user", 
            request.message
        )
        
        intent = command_executor.intent_parser.parse(request.message)
        
        result = await command_executor.execute(intent, session)
        
        await conversation_manager.add_message(
            session.session_id,
            "assistant",
            result.get("message", "")
        )
        
        if result.get("data", {}).get("task_id"):
            await conversation_manager.update_session(
                session.session_id,
                {"current_task_id": result["data"]["task_id"]}
            )
        
        return APIResponse(
            code=200,
            message="处理成功",
            data={
                "session_id": session.session_id,
                "response": result.get("message", ""),
                "intent": intent.intent.value,
                "confidence": intent.confidence,
                "action_taken": result.get("success", False),
                "data": result.get("data"),
                "suggestions": result.get("suggestions", [])
            }
        )
        
    except Exception as e:
        logger.error(f"AI对话处理失败: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"处理失败: {str(e)}")


@router.post("/chat/stream", response_model=APIResponse)
async def ai_chat_stream(request: AIChatRequest):
    """
    流式AI对话接口
    
    支持流式返回响应内容，适用于长时间操作。
    
    Args:
        request: 对话请求
        
    Returns:
        APIResponse: 包含流式响应信息
    """
    try:
        session = await conversation_manager.get_or_create_session(request.session_id)
        
        intent = command_executor.intent_parser.parse(request.message)
        
        return APIResponse(
            code=200,
            message="流式处理已启动",
            data={
                "session_id": session.session_id,
                "intent": intent.intent.value,
                "confidence": intent.confidence,
                "stream_url": f"/api/ai-chat/ws/{session.session_id}"
            }
        )
        
    except Exception as e:
        logger.error(f"启动流式对话失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"启动失败: {str(e)}")


@router.websocket("/ws/{session_id}")
async def websocket_ai_chat(websocket: WebSocket, session_id: str):
    """
    WebSocket AI对话端点
    
    支持实时双向通信，用于流式响应和实时更新。
    
    Args:
        websocket: WebSocket连接
        session_id: 会话ID
    """
    from backend.api.websocket import manager
    
    client_host = websocket.client.host if websocket.client else None
    connected = await manager.connect(websocket, client_host)
    
    if not connected:
        return
    
    session = await conversation_manager.get_or_create_session(session_id)
    
    try:
        await websocket.send_json({
            "type": "connected",
            "session_id": session.session_id,
            "message": "WebSocket连接已建立"
        })
        
        while True:
            data = await websocket.receive_text()
            
            try:
                message = json.loads(data)
                message_type = message.get("type")
                
                if message_type == "ping":
                    await websocket.send_json({"type": "pong"})
                
                elif message_type == "chat":
                    user_message = message.get("message", "")
                    
                    await conversation_manager.add_message(
                        session.session_id,
                        "user",
                        user_message
                    )
                    
                    await websocket.send_json({
                        "type": "status",
                        "content": "正在处理您的消息..."
                    })
                    
                    intent = command_executor.intent_parser.parse(user_message)
                    
                    await websocket.send_json({
                        "type": "intent",
                        "intent": intent.intent.value,
                        "confidence": intent.confidence,
                        "explanation": intent.explanation
                    })
                    
                    result = await command_executor.execute(intent, session)
                    
                    await websocket.send_json({
                        "type": "response",
                        "content": result.get("message", ""),
                        "success": result.get("success", False),
                        "data": result.get("data"),
                        "suggestions": result.get("suggestions", []),
                        "is_final": True
                    })
                    
                    await conversation_manager.add_message(
                        session.session_id,
                        "assistant",
                        result.get("message", "")
                    )
                    
                    if result.get("data", {}).get("task_id"):
                        await conversation_manager.update_session(
                            session.session_id,
                            {"current_task_id": result["data"]["task_id"]}
                        )
                
                elif message_type == "get_history":
                    history = session.history[-20:]
                    await websocket.send_json({
                        "type": "history",
                        "history": history
                    })
                
                elif message_type == "get_context":
                    await websocket.send_json({
                        "type": "context",
                        "current_task_id": session.current_task_id,
                        "pending_action": session.pending_action
                    })
                
            except json.JSONDecodeError:
                if data == "ping":
                    await websocket.send_json({"type": "pong"})
                    
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket AI对话错误: {e}")
        await manager.disconnect(websocket)


@router.get("/sessions/{session_id}", response_model=APIResponse)
async def get_session_info(session_id: str):
    """
    获取会话信息
    
    Args:
        session_id: 会话ID
        
    Returns:
        APIResponse: 会话信息
    """
    session = await conversation_manager.get_or_create_session(session_id)
    
    return APIResponse(
        code=200,
        message="获取成功",
        data={
            "session_id": session.session_id,
            "created_at": session.created_at.isoformat(),
            "last_active": session.last_active.isoformat(),
            "message_count": len(session.history),
            "current_task_id": session.current_task_id
        }
    )


@router.get("/intents", response_model=APIResponse)
async def list_intents():
    """
    获取支持的意图列表
    
    Returns:
        APIResponse: 意图列表
    """
    intents = [
        {"name": "create_scan", "description": "创建扫描任务", "examples": ["扫描 https://example.com", "对 example.com 进行漏洞扫描"]},
        {"name": "query_task", "description": "查询任务状态", "examples": ["查询任务状态", "显示任务 <task_id>"]},
        {"name": "list_tasks", "description": "列出所有任务", "examples": ["列出所有任务", "显示任务列表"]},
        {"name": "cancel_task", "description": "取消任务", "examples": ["取消任务 <task_id>", "停止扫描"]},
        {"name": "delete_task", "description": "删除任务", "examples": ["删除任务 <task_id>"]},
        {"name": "generate_report", "description": "生成报告", "examples": ["生成报告 <task_id>", "导出HTML报告"]},
        {"name": "system_status", "description": "系统状态", "examples": ["系统状态", "统计信息"]},
        {"name": "health_check", "description": "健康检查", "examples": ["健康检查", "检查服务状态"]},
        {"name": "help", "description": "帮助信息", "examples": ["帮助", "怎么用"]},
    ]
    
    return APIResponse(
        code=200,
        message="获取成功",
        data={"intents": intents}
    )


@router.post("/parse", response_model=APIResponse)
async def parse_intent(message: str):
    """
    解析用户消息意图
    
    Args:
        message: 用户消息
        
    Returns:
        APIResponse: 解析结果
    """
    intent = command_executor.intent_parser.parse(message)
    
    return APIResponse(
        code=200,
        message="解析成功",
        data={
            "intent": intent.intent.value,
            "confidence": intent.confidence,
            "parameters": intent.parameters,
            "explanation": intent.explanation
        }
    )
