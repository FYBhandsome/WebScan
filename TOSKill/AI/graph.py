"""
TOSKill AI 工作流图定义

类比 demo.py，使用 LangGraph 构建三个子图：
1. 信息收集子图 (InfoCollectionGraph)
2. 漏洞扫描子图 (VulnScanGraph)
3. 报告生成子图 (ReportGraph)

使用 LangGraph interrupt 机制实现用户交互暂停/恢复。
"""
import logging
import asyncio
import sys
import base64
import json
from typing import Dict, Optional, Callable, List, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, field
import threading

from langgraph.graph import StateGraph, END
from langgraph.types import interrupt, Command
from langgraph.checkpoint.memory import MemorySaver
from langchain_openai import ChatOpenAI

from .state import ScanState, create_initial_state, append_chat, update_state
from .tools import get_tool_by_name, get_tool_sequence, is_auth_expired, get_auth_remaining_time
from ..config import settings

logger = logging.getLogger(__name__)

AUTH_MAX_RETRY_COUNT = 3
AUTH_ENCRYPTION_KEY = "toskill_auth_encryption_key_v1"


def encrypt_auth_info(auth_data: Dict[str, Any]) -> str:
    """
    加密认证信息（使用 base64 编码）
    
    Args:
        auth_data: 认证信息字典
        
    Returns:
        str: 加密后的字符串
    """
    try:
        json_str = json.dumps(auth_data, ensure_ascii=False)
        encoded = base64.b64encode(json_str.encode('utf-8')).decode('utf-8')
        return f"enc:{encoded}"
    except Exception as e:
        logger.error(f"加密认证信息失败: {e}")
        return ""


def decrypt_auth_info(encrypted_data: str) -> Dict[str, Any]:
    """
    解密认证信息
    
    Args:
        encrypted_data: 加密的认证信息字符串
        
    Returns:
        Dict: 解密后的认证信息字典
    """
    try:
        if not encrypted_data or not encrypted_data.startswith("enc:"):
            return {}
        
        encoded = encrypted_data[4:]
        json_str = base64.b64decode(encoded.encode('utf-8')).decode('utf-8')
        return json.loads(json_str)
    except Exception as e:
        logger.error(f"解密认证信息失败: {e}")
        return {}


def is_auth_failure_response(response: Any) -> bool:
    """
    检测响应是否为认证失败
    
    Args:
        response: 工具执行响应
        
    Returns:
        bool: 是否为认证失败响应
    """
    if isinstance(response, dict):
        status_code = response.get("status_code", 0)
        if status_code in [401, 403]:
            return True
        
        error = response.get("error", "").lower()
        auth_errors = [
            "unauthorized", "forbidden", "authentication failed",
            "token expired", "session expired", "invalid token",
            "access denied", "未授权", "认证失败", "token过期"
        ]
        if any(err in error for err in auth_errors):
            return True
        
        if response.get("data"):
            data = response.get("data", {})
            if isinstance(data, dict):
                if data.get("status_code") in [401, 403]:
                    return True
                error_msg = str(data.get("error", "")).lower()
                if any(err in error_msg for err in auth_errors):
                    return True
    
    return False


class AuthRetryManager:
    """认证重试管理器"""
    
    def __init__(self, max_retries: int = AUTH_MAX_RETRY_COUNT):
        self._retry_counts: Dict[str, int] = {}
        self._max_retries = max_retries
        self._retry_history: Dict[str, List[Dict]] = {}
    
    def get_retry_count(self, session_id: str) -> int:
        """获取重试次数"""
        return self._retry_counts.get(session_id, 0)
    
    def increment_retry(self, session_id: str) -> int:
        """增加重试次数并返回新值"""
        if session_id not in self._retry_counts:
            self._retry_counts[session_id] = 0
        
        self._retry_counts[session_id] += 1
        
        if session_id not in self._retry_history:
            self._retry_history[session_id] = []
        
        self._retry_history[session_id].append({
            "timestamp": datetime.now().isoformat(),
            "retry_count": self._retry_counts[session_id]
        })
        
        return self._retry_counts[session_id]
    
    def can_retry(self, session_id: str) -> bool:
        """检查是否可以重试"""
        return self.get_retry_count(session_id) < self._max_retries
    
    def reset_retry(self, session_id: str):
        """重置重试计数"""
        self._retry_counts.pop(session_id, None)
        self._retry_history.pop(session_id, None)
    
    def get_retry_history(self, session_id: str) -> List[Dict]:
        """获取重试历史"""
        return self._retry_history.get(session_id, [])
    
    def should_trigger_reauth(self, session_id: str, response: Any) -> bool:
        """
        判断是否需要触发重新认证
        
        Args:
            session_id: 会话ID
            response: 工具响应
            
        Returns:
            bool: 是否需要重新认证
        """
        if not is_auth_failure_response(response):
            return False
        
        return self.can_retry(session_id)


auth_retry_manager = AuthRetryManager()


def get_llm():
    """获取LLM实例"""
    return ChatOpenAI(
        model=settings.MODEL_ID,
        temperature=0.1,
        api_key=settings.OPENAI_API_KEY,
        base_url=settings.OPENAI_BASE_URL
    )


@dataclass
class SessionMetadata:
    """会话元数据"""
    version: int = 1
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    last_activity: datetime = field(default_factory=datetime.now)


class MemoryStore:
    """记忆化存储 - 类比 demo.py 的 chat_history
    
    功能特性:
    - TTL过期清理（默认1小时）
    - 定时清理任务（每10分钟检查一次）
    - 聊天历史自动清理（最多保留100条）
    - 数据冗余检测与合并
    - 存储状态监控
    - 状态版本号管理
    """
    
    _instance = None
    _sessions: Dict[str, ScanState] = {}
    _chat_histories: Dict[str, List[Dict]] = {}
    _pending_interactions: Dict[str, Dict] = {}
    _websocket_callbacks: Dict[str, Callable] = {}
    _session_timestamps: Dict[str, datetime] = {}
    _session_metadata: Dict[str, SessionMetadata] = {}
    
    _session_ttl: int = 3600
    _cleanup_interval: int = 600
    _max_chat_history: int = 100
    _cleanup_task: Optional[asyncio.Task] = None
    _cleanup_thread: Optional[threading.Thread] = None
    _stop_cleanup: bool = False
    _lock: threading.Lock = field(default_factory=threading.Lock)
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
            cls._instance._start_cleanup_task()
        return cls._instance
    
    def _start_cleanup_task(self):
        """启动定时清理任务"""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                self._cleanup_task = asyncio.create_task(self._periodic_cleanup())
                logger.info("定时清理任务已启动（异步模式）")
            else:
                raise RuntimeError("事件循环未运行")
        except RuntimeError:
            self._stop_cleanup = False
            self._cleanup_thread = threading.Thread(target=self._periodic_cleanup_sync, daemon=True)
            self._cleanup_thread.start()
            logger.info("定时清理任务已启动（线程模式）")
    
    async def _periodic_cleanup(self):
        """异步定时清理任务"""
        while not self._stop_cleanup:
            try:
                await asyncio.sleep(self._cleanup_interval)
                self._cleanup_expired_sessions()
                self._cleanup_chat_histories()
            except asyncio.CancelledError:
                logger.info("定时清理任务被取消")
                break
            except Exception as e:
                logger.error(f"定时清理任务异常: {e}")
    
    def _periodic_cleanup_sync(self):
        """同步定时清理任务（用于线程模式）"""
        import time
        while not self._stop_cleanup:
            try:
                time.sleep(self._cleanup_interval)
                self._cleanup_expired_sessions()
                self._cleanup_chat_histories()
            except Exception as e:
                logger.error(f"定时清理任务异常: {e}")
    
    def stop_cleanup_task(self):
        """停止定时清理任务"""
        self._stop_cleanup = True
        if self._cleanup_task:
            self._cleanup_task.cancel()
        logger.info("定时清理任务已停止")
    
    def save_session(self, session_id: str, state: ScanState) -> int:
        """保存会话状态（带时间戳和版本号）
        
        Returns:
            新的版本号
        """
        with self._lock:
            now = datetime.now()
            
            if session_id in self._session_metadata:
                metadata = self._session_metadata[session_id]
                metadata.version += 1
                metadata.updated_at = now
                metadata.last_activity = now
            else:
                metadata = SessionMetadata(
                    version=1,
                    created_at=now,
                    updated_at=now,
                    last_activity=now
                )
                self._session_metadata[session_id] = metadata
            
            self._sessions[session_id] = state
            self._session_timestamps[session_id] = now
            
            logger.debug(f"保存会话状态: {session_id}, 版本: {metadata.version}")
            return metadata.version
    
    def get_session(self, session_id: str) -> Optional[ScanState]:
        """获取会话状态"""
        return self._sessions.get(session_id)
    
    def get_session_version(self, session_id: str) -> int:
        """获取会话版本号"""
        metadata = self._session_metadata.get(session_id)
        return metadata.version if metadata else 0
    
    def update_session(self, session_id: str, **kwargs) -> Optional[ScanState]:
        """更新会话状态的部分字段（带版本控制）"""
        with self._lock:
            state = self.get_session(session_id)
            if state:
                now = datetime.now()
                state = {**state, **kwargs}
                self._sessions[session_id] = state
                self._session_timestamps[session_id] = now
                
                if session_id in self._session_metadata:
                    metadata = self._session_metadata[session_id]
                    metadata.version += 1
                    metadata.updated_at = now
                    metadata.last_activity = now
                
                logger.debug(f"更新会话状态: {session_id}, 版本: {self._session_metadata[session_id].version}")
            return state
    
    def delete_session(self, session_id: str):
        """删除会话"""
        with self._lock:
            self._sessions.pop(session_id, None)
            self._chat_histories.pop(session_id, None)
            self._pending_interactions.pop(session_id, None)
            self._websocket_callbacks.pop(session_id, None)
            self._session_timestamps.pop(session_id, None)
            self._session_metadata.pop(session_id, None)
            logger.info(f"删除会话: {session_id}")
    
    def _cleanup_expired_sessions(self):
        """清理过期会话（带日志记录）"""
        now = datetime.now()
        expired_count = 0
        
        with self._lock:
            expired = [
                sid for sid, ts in self._session_timestamps.items()
                if (now - ts).total_seconds() > self._session_ttl
            ]
            
            for sid in expired:
                expired_count += 1
                logger.info(f"[清理] 过期会话: {sid}, 空闲时间: {(now - self._session_timestamps[sid]).total_seconds():.0f}秒")
                self._sessions.pop(sid, None)
                self._chat_histories.pop(sid, None)
                self._pending_interactions.pop(sid, None)
                self._websocket_callbacks.pop(sid, None)
                self._session_timestamps.pop(sid, None)
                self._session_metadata.pop(sid, None)
        
        if expired_count > 0:
            logger.info(f"[清理] 本次清理过期会话数: {expired_count}, 剩余活跃会话: {len(self._sessions)}")
    
    def _cleanup_chat_histories(self):
        """清理超出限制的聊天历史"""
        cleaned_count = 0
        
        with self._lock:
            for session_id, history in self._chat_histories.items():
                if len(history) > self._max_chat_history:
                    removed = len(history) - self._max_chat_history
                    self._chat_histories[session_id] = history[-self._max_chat_history:]
                    cleaned_count += removed
                    logger.debug(f"[清理] 会话 {session_id} 聊天历史清理: 移除 {removed} 条旧记录")
        
        if cleaned_count > 0:
            logger.info(f"[清理] 本次清理聊天记录数: {cleaned_count}")
    
    def append_chat(self, session_id: str, role: str, content: str):
        """追加聊天历史（自动清理超出限制的记录）"""
        with self._lock:
            if session_id not in self._chat_histories:
                self._chat_histories[session_id] = []
            
            self._chat_histories[session_id].append({
                "role": role,
                "content": content,
                "timestamp": datetime.now().isoformat()
            })
            
            if len(self._chat_histories[session_id]) > self._max_chat_history:
                removed = len(self._chat_histories[session_id]) - self._max_chat_history
                self._chat_histories[session_id] = self._chat_histories[session_id][-self._max_chat_history:]
                logger.debug(f"聊天历史自动清理: 移除 {removed} 条旧记录")
    
    def get_chat_history(self, session_id: str) -> List[Dict]:
        """获取聊天历史"""
        return self._chat_histories.get(session_id, [])
    
    def sync_chat_history_from_state(self, session_id: str, state: ScanState) -> ScanState:
        """从状态同步聊天历史到 memory_store（带冗余检测与合并）
        
        去重策略：
        1. 按时间戳去重，保留最新数据
        2. 相同时间戳的消息按内容去重
        3. 合并后按时间戳排序
        """
        with self._lock:
            state_history = state.get("chat_history", [])
            store_history = self._chat_histories.get(session_id, [])
            
            all_messages = {}
            duplicate_count = 0
            
            for msg in state_history + store_history:
                timestamp = msg.get("timestamp", "")
                content_key = f"{msg.get('role', '')}:{msg.get('content', '')[:50]}"
                unique_key = f"{timestamp}:{content_key}"
                
                if unique_key in all_messages:
                    duplicate_count += 1
                    if msg.get("timestamp", "") > all_messages[unique_key].get("timestamp", ""):
                        all_messages[unique_key] = msg
                else:
                    all_messages[unique_key] = msg
            
            timestamp_map = {}
            for msg in all_messages.values():
                ts = msg.get("timestamp", "")
                if ts in timestamp_map:
                    if msg.get("timestamp", "") > timestamp_map[ts].get("timestamp", ""):
                        timestamp_map[ts] = msg
                else:
                    timestamp_map[ts] = msg
            
            merged = sorted(timestamp_map.values(), key=lambda x: x.get("timestamp", ""))
            
            if len(merged) > self._max_chat_history:
                merged = merged[-self._max_chat_history:]
            
            self._chat_histories[session_id] = merged
            
            if duplicate_count > 0:
                logger.info(f"[同步] 会话 {session_id} 去重: 移除 {duplicate_count} 条重复消息")
            
            return {**state, "chat_history": merged}
    
    def set_pending_interaction(self, session_id: str, interaction_data: Dict):
        """设置待处理的交互请求"""
        self._pending_interactions[session_id] = interaction_data
    
    def get_pending_interaction(self, session_id: str) -> Optional[Dict]:
        """获取待处理的交互请求"""
        return self._pending_interactions.get(session_id)
    
    def clear_pending_interaction(self, session_id: str):
        """清除待处理的交互请求"""
        self._pending_interactions.pop(session_id, None)
    
    def set_websocket_callback(self, session_id: str, callback: Callable):
        """设置 WebSocket 回调函数"""
        self._websocket_callbacks[session_id] = callback
        self._session_timestamps[session_id] = datetime.now()
        
        if session_id in self._session_metadata:
            self._session_metadata[session_id].last_activity = datetime.now()
    
    def get_websocket_callback(self, session_id: str) -> Optional[Callable]:
        """获取 WebSocket 回调函数"""
        return self._websocket_callbacks.get(session_id)
    
    def is_websocket_active(self, session_id: str) -> bool:
        """检查WebSocket连接是否活跃"""
        return session_id in self._websocket_callbacks and self._websocket_callbacks[session_id] is not None
    
    def clear_websocket_callback(self, session_id: str):
        """清除 WebSocket 回调"""
        self._websocket_callbacks.pop(session_id, None)
    
    def has_pending_interaction(self, session_id: str) -> bool:
        """检查是否有待处理的交互"""
        return session_id in self._pending_interactions
    
    def get_active_session_count(self) -> int:
        """获取活跃会话数量"""
        return len(self._sessions)
    
    def get_session_info(self, session_id: str) -> Dict[str, Any]:
        """获取会话信息"""
        state = self.get_session(session_id)
        if not state:
            return {"exists": False}
        
        metadata = self._session_metadata.get(session_id)
        
        return {
            "exists": True,
            "target": state.get("target", ""),
            "mode": state.get("mode", ""),
            "completed_tasks": len(state.get("completed_tasks", [])),
            "chat_history_count": len(state.get("chat_history", [])),
            "last_activity": self._session_timestamps.get(session_id, "").isoformat() if session_id in self._session_timestamps else None,
            "has_websocket": self.is_websocket_active(session_id),
            "version": metadata.version if metadata else 0,
            "created_at": metadata.created_at.isoformat() if metadata else None,
            "updated_at": metadata.updated_at.isoformat() if metadata else None
        }
    
    def get_storage_stats(self) -> Dict[str, Any]:
        """获取存储统计信息
        
        Returns:
            包含会话数量、聊天记录数量、内存使用估算等信息的字典
        """
        total_chat_messages = sum(len(history) for history in self._chat_histories.values())
        
        session_size = sys.getsizeof(self._sessions) + sum(
            sys.getsizeof(k) + sys.getsizeof(v) 
            for k, v in self._sessions.items()
        )
        
        chat_size = sys.getsizeof(self._chat_histories) + sum(
            sys.getsizeof(k) + sys.getsizeof(v) + sum(
                sys.getsizeof(msg) for msg in v
            ) for k, v in self._chat_histories.items()
        )
        
        metadata_size = sys.getsizeof(self._session_metadata) + sum(
            sys.getsizeof(k) + sys.getsizeof(v) 
            for k, v in self._session_metadata.items()
        )
        
        pending_size = sys.getsizeof(self._pending_interactions)
        ws_size = sys.getsizeof(self._websocket_callbacks)
        timestamps_size = sys.getsizeof(self._session_timestamps)
        
        total_memory = session_size + chat_size + metadata_size + pending_size + ws_size + timestamps_size
        
        oldest_session = None
        newest_session = None
        if self._session_timestamps:
            oldest_ts = min(self._session_timestamps.values())
            newest_ts = max(self._session_timestamps.values())
            for sid, ts in self._session_timestamps.items():
                if ts == oldest_ts:
                    oldest_session = sid
                if ts == newest_ts:
                    newest_session = sid
        
        return {
            "sessions": {
                "total_count": len(self._sessions),
                "active_websocket_count": len([c for c in self._websocket_callbacks.values() if c is not None]),
                "pending_interaction_count": len(self._pending_interactions),
                "oldest_session": oldest_session,
                "newest_session": newest_session
            },
            "chat_history": {
                "total_messages": total_chat_messages,
                "sessions_with_history": len(self._chat_histories),
                "max_history_limit": self._max_chat_history,
                "average_messages_per_session": round(total_chat_messages / max(len(self._chat_histories), 1), 2)
            },
            "memory": {
                "estimated_total_bytes": total_memory,
                "estimated_total_mb": round(total_memory / (1024 * 1024), 2),
                "sessions_bytes": session_size,
                "chat_history_bytes": chat_size,
                "metadata_bytes": metadata_size
            },
            "config": {
                "session_ttl_seconds": self._session_ttl,
                "cleanup_interval_seconds": self._cleanup_interval,
                "max_chat_history_per_session": self._max_chat_history
            },
            "cleanup_status": {
                "cleanup_task_running": self._cleanup_task is not None and not self._cleanup_task.done() if self._cleanup_task else False,
                "cleanup_thread_running": self._cleanup_thread is not None and self._cleanup_thread.is_alive() if self._cleanup_thread else False,
                "stop_requested": self._stop_cleanup
            }
        }
    
    def set_config(self, session_ttl: int = None, cleanup_interval: int = None, max_chat_history: int = None):
        """动态配置存储参数
        
        Args:
            session_ttl: 会话过期时间（秒）
            cleanup_interval: 清理检查间隔（秒）
            max_chat_history: 每个会话最大聊天记录数
        """
        if session_ttl is not None:
            self._session_ttl = session_ttl
            logger.info(f"会话TTL已更新: {session_ttl}秒")
        
        if cleanup_interval is not None:
            self._cleanup_interval = cleanup_interval
            logger.info(f"清理检查间隔已更新: {cleanup_interval}秒")
        
        if max_chat_history is not None:
            self._max_chat_history = max_chat_history
            logger.info(f"最大聊天记录数已更新: {max_chat_history}")


memory_store = MemoryStore.get_instance()


async def safe_ws_send(session_id: str, message: Dict) -> bool:
    """安全发送WebSocket消息"""
    ws_callback = memory_store.get_websocket_callback(session_id)
    if ws_callback is None:
        logger.warning(f"[{session_id}] WebSocket回调不存在")
        return False
    
    try:
        await ws_callback(message)
        return True
    except Exception as e:
        logger.error(f"[{session_id}] WebSocket发送失败: {e}")
        memory_store.clear_websocket_callback(session_id)
        return False


def format_tool_result(tool_name: str, target: str, result: Any) -> str:
    """格式化工具结果 - 生成友好易读的反馈"""
    
    if "port" in tool_name or "nmap" in tool_name:
        ports = []
        if isinstance(result, dict) and "ports" in result:
            ports = result["ports"]
        elif isinstance(result, dict) and "open_ports" in result:
            ports = result["open_ports"]
        return f"【端口扫描结果】\n目标: {target}\n开放端口: {', '.join(map(str, ports)) if ports else '无'}"
    
    elif "sqli" in tool_name or "sqlmap" in tool_name:
        vulnerable = isinstance(result, dict) and result.get("vulnerable", False)
        if vulnerable:
            inj_point = result.get("injection_point", result.get("parameter", "未知"))
            return f"【SQL注入检测结果】\n目标: {target}\n⚠️ 检测到SQL注入漏洞（高危）\n注入点: {inj_point}"
        return f"【SQL注入检测结果】\n目标: {target}\n✅ 未检测到SQL注入漏洞"
    
    elif "dir" in tool_name or "directory" in tool_name:
        dirs = []
        if isinstance(result, dict) and "directories" in result:
            dirs = result["directories"]
        elif isinstance(result, dict) and "found_paths" in result:
            dirs = result["found_paths"]
        return f"【目录扫描结果】\n目标: {target}\n发现目录: {len(dirs)} 个\n敏感目录: {', '.join(dirs[:5]) if dirs else '无'}"
    
    elif "xss" in tool_name:
        vulnerable = isinstance(result, dict) and result.get("vulnerable", False)
        if vulnerable:
            xss_type = result.get("xss_type", result.get("type", "未知"))
            return f"【XSS检测结果】\n目标: {target}\n⚠️ 检测到XSS漏洞\n类型: {xss_type}"
        return f"【XSS检测结果】\n目标: {target}\n✅ 未检测到XSS漏洞"
    
    elif "subdomain" in tool_name:
        subs = []
        if isinstance(result, dict) and "subdomains" in result:
            subs = result["subdomains"]
        elif isinstance(result, list):
            subs = result
        return f"【子域名扫描结果】\n目标: {target}\n发现子域名: {len(subs)} 个\n{', '.join(subs[:5]) if subs else '无'}"
    
    elif "waf" in tool_name:
        waf = "未知"
        if isinstance(result, dict) and "waf" in result:
            waf = result["waf"]
        elif isinstance(result, dict) and "detected" in result:
            waf = result.get("name", "已检测")
        return f"【WAF检测结果】\n目标: {target}\nWAF: {waf}"
    
    elif "cms" in tool_name:
        cms = "未知"
        if isinstance(result, dict) and "cms" in result:
            cms = result["cms"]
        return f"【CMS检测结果】\n目标: {target}\nCMS: {cms}"
    
    else:
        if isinstance(result, dict):
            status = "⚠️ 发现问题" if result.get("vulnerable") or result.get("found") else "✅ 正常"
            return f"【{tool_name} 结果】\n目标: {target}\n状态: {status}"
        return f"【{tool_name} 结果】\n目标: {target}\n结果: {str(result)[:200]}"


async def intent_recognition(state: ScanState) -> ScanState:
    """意图识别节点 - 使用LLM分析用户输入意图"""
    import json
    import re
    from .tools import get_all_tool_names, get_tools_description
    
    user_input = state.get("user_input", "")
    session_id = state.get("websocket_session_id") or state.get("task_id")
    ws_callback = memory_store.get_websocket_callback(session_id)
    
    logger.info(f"[{session_id}] 意图识别: {user_input[:50]}...")
    
    available_tools = get_all_tool_names()
    tools_desc = get_tools_description()[:1500]
    
    prompt = f"""分析用户输入，识别意图类型并提取关键信息。

用户输入: {user_input}

当前可用工具列表:
{tools_desc}

请严格按以下JSON格式回复，不要添加其他内容:
{{"intent_type": "scan", "tool_name": "", "target": "目标地址", "confidence": 0.9}}
或
{{"intent_type": "tool", "tool_name": "工具名", "target": "目标地址", "confidence": 0.9}}
或
{{"intent_type": "chat", "tool_name": "", "target": "", "confidence": 0.9}}
或
{{"intent_type": "upload_script", "tool_name": "", "target": "", "confidence": 0.9}}
或
{{"intent_type": "generate_script", "tool_name": "", "target": "", "confidence": 0.9}}

意图分类规则:
1. scan: 包含"扫描""漏洞""渗透""检测""安全检查"等关键词，需要完整扫描流程
2. tool: 明确提及"调用""执行""使用"某工具，或直接指定工具名（参考上述工具列表）
3. chat: 咨询、问答、闲聊、询问概念或用法
4. upload_script: 上传脚本、自定义脚本、导入脚本、添加脚本
5. generate_script: 生成脚本、AI写脚本、创建脚本、帮我写个脚本

注意:
- 如果用户提到具体工具名，intent_type必须是"tool"
- 如果用户想上传或添加自己的脚本，intent_type是"upload_script"
- 如果用户想让AI生成脚本，intent_type是"generate_script"
- 提取目标地址时，优先提取URL、IP地址或域名
"""
    
    llm = get_llm()
    response = llm.invoke(prompt).content
    
    intent_type = "chat"
    direct_tool = ""
    target = state.get("target", "")
    confidence = 0.5
    
    try:
        json_match = re.search(r'\{[^{}]*\}', response, re.DOTALL)
        if json_match:
            result = json.loads(json_match.group())
            intent_type = result.get("intent_type", "chat")
            direct_tool = result.get("tool_name", "")
            extracted_target = result.get("target", "")
            confidence = float(result.get("confidence", 0.5))
            
            if extracted_target:
                target = extracted_target
    except Exception as e:
        logger.warning(f"解析意图识别结果失败: {e}, 原始响应: {response[:100]}")
        scan_keywords = ["扫描", "漏洞", "渗透", "检测", "安全检查", "scan"]
        tool_keywords = ["调用", "执行", "使用", "nmap", "sqlmap", "dirsearch", "工具"]
        upload_keywords = ["上传脚本", "自定义脚本", "导入脚本", "添加脚本", "upload script"]
        generate_keywords = ["生成脚本", "AI写脚本", "创建脚本", "帮我写个脚本", "generate script", "写个脚本"]
        
        if any(kw in user_input.lower() for kw in upload_keywords):
            intent_type = "upload_script"
        elif any(kw in user_input.lower() for kw in generate_keywords):
            intent_type = "generate_script"
        elif any(kw in user_input.lower() for kw in tool_keywords):
            intent_type = "tool"
            for tool_hint in ["nmap", "sqlmap", "dirsearch", "port_scan", "sqli_scan", "xss_scan"]:
                if tool_hint in user_input.lower():
                    direct_tool = tool_hint
                    break
        elif any(kw in user_input.lower() for kw in scan_keywords):
            intent_type = "scan"
    
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+|[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}|[\w\-]+\.[\w\-]+\.[\w\-]+'
    if not target:
        url_match = re.search(url_pattern, user_input)
        if url_match:
            target = url_match.group()
    
    if ws_callback:
        try:
            await ws_callback({
                "type": "intent_recognized",
                "payload": {
                    "intent_type": intent_type,
                    "tool_name": direct_tool,
                    "target": target,
                    "confidence": confidence
                }
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    logger.info(f"🎯 意图识别结果: {intent_type}, 工具: {direct_tool}, 目标: {target}, 置信度: {confidence}")
    
    return update_state(state, 
        intent_type=intent_type,
        direct_tool=direct_tool,
        direct_target=target,
        intent_confidence=confidence,
        target=target or state.get("target", ""),
        user_input=user_input,
        intent_context={
            "original_input": user_input,
            "extracted_target": target,
            "extracted_tool": direct_tool,
            "recognition_time": datetime.now().isoformat()
        },
        last_activity_time=datetime.now().isoformat()
    )


async def intent_validation(state: ScanState) -> ScanState:
    """意图校验节点 - 校验意图合法性，缺失数据时请求用户输入"""
    from .validators import InputValidator, DataInputRequest
    
    intent_type = state.get("intent_type", "chat")
    direct_tool = state.get("direct_tool", "")
    target = state.get("target", "")
    session_id = state.get("websocket_session_id") or state.get("task_id")
    ws_callback = memory_store.get_websocket_callback(session_id)
    
    validation_result = {"valid": True, "error": "", "needs_input": False, "input_field": ""}
    
    if intent_type == "tool":
        tool = get_tool_by_name(direct_tool)
        if not tool:
            validation_result = {"valid": False, "error": f"工具 '{direct_tool}' 不存在，请检查工具名称"}
        elif not target:
            validation_result = {"valid": False, "error": "请提供扫描目标地址", "needs_input": True, "input_field": "target"}
    
    elif intent_type == "scan":
        if not target:
            validation_result = {"valid": False, "error": "请提供扫描目标地址", "needs_input": True, "input_field": "target"}
    
    if validation_result["needs_input"] and ws_callback:
        input_request = DataInputRequest.build_request(
            validation_result["input_field"],
            validation_result["error"]
        )
        try:
            await ws_callback(input_request)
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    elif not validation_result["valid"]:
        logger.warning(f"意图校验失败: {validation_result['error']}")
        if ws_callback:
            try:
                await ws_callback({
                    "type": "intent_validation_error",
                    "payload": {"error": validation_result["error"]}
                })
            except Exception as e:
                logger.error(f"WebSocket推送失败: {e}")
    
    return update_state(state, 
        intent_valid=validation_result["valid"],
        intent_error=validation_result["error"],
        needs_input=validation_result.get("needs_input", False),
        input_field=validation_result.get("input_field", "")
    )


async def input_validation(state: ScanState) -> ScanState:
    """用户输入数据审核节点 - AI智能审核用户输入"""
    from .validators import get_ai_validator, ValidationStatus
    
    user_input = state.get("user_input", "")
    intent_type = state.get("intent_type", "chat")
    session_id = state.get("websocket_session_id") or state.get("task_id")
    ws_callback = memory_store.get_websocket_callback(session_id)
    
    logger.info(f"[{session_id}] 输入数据审核: {user_input[:50]}...")
    
    if ws_callback:
        try:
            await ws_callback({
                "type": "validation_started",
                "payload": {"message": "正在分析您的请求..."}
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    ai_validator = get_ai_validator()
    result = await ai_validator.validate_and_extract(user_input, intent_type)
    
    if not result.is_complete:
        logger.warning(f"输入数据不完整: {result.missing_fields}")
        if ws_callback:
            missing_field = result.missing_fields[0] if result.missing_fields else "target"
            from .validators import DataInputRequest
            input_request = DataInputRequest.build_request(missing_field, result.message)
            try:
                await ws_callback(input_request)
            except Exception as e:
                logger.error(f"WebSocket推送失败: {e}")
        
        return update_state(state,
            validation_status="incomplete",
            missing_fields=result.missing_fields,
            validation_message=result.message
        )
    
    extracted_target = result.params.get("target", "")
    
    if ws_callback:
        try:
            await ws_callback({
                "type": "validation_completed",
                "payload": {
                    "status": "valid",
                    "extracted_params": result.params,
                    "confidence": result.confidence
                }
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    return update_state(state,
        validation_status="complete",
        target=extracted_target or state.get("target", ""),
        direct_tool=result.params.get("tool_name", state.get("direct_tool", "")),
        extracted_params=result.params,
        validation_message=result.message
    )


def intent_router(state: ScanState) -> str:
    """意图路由 - 根据意图类型分流"""
    intent_valid = state.get("intent_valid", True)
    if not intent_valid:
        return "intent_recognition"
    
    intent_type = state.get("intent_type", "chat")
    
    if intent_type == "scan":
        return "start_scan"
    elif intent_type == "tool":
        return "tool_existence_check"
    elif intent_type == "upload_script":
        return "script_upload_process"
    elif intent_type == "generate_script":
        return "script_generate_process"
    else:
        return "chat"


async def tool_existence_check(state: ScanState) -> ScanState:
    """工具存在性校验节点 - 使用AI判断工具是否存在"""
    from .tools import get_all_tool_names, get_tools_description, is_tool_exists
    
    direct_tool = state.get("direct_tool", "")
    user_input = state.get("user_input", "")
    session_id = state.get("websocket_session_id") or state.get("task_id")
    ws_callback = memory_store.get_websocket_callback(session_id)
    
    logger.info(f"[{session_id}] 工具存在性校验: {direct_tool}")
    
    available_tools = get_all_tool_names()
    tools_desc = get_tools_description()
    
    if is_tool_exists(direct_tool):
        logger.info(f"工具 '{direct_tool}' 存在，准备执行")
        return update_state(state, tool_exists=True)
    
    llm = get_llm()
    prompt = f"""用户想执行工具: "{direct_tool}"

当前可用的工具列表:
{tools_desc[:2000]}

请判断用户提到的工具名是否匹配列表中的某个工具（支持模糊匹配）。
如果匹配，返回正确的工具名；如果不匹配，返回空。

请严格按以下JSON格式回复:
{{"exists": true, "matched_tool": "正确的工具名"}}
或
{{"exists": false, "matched_tool": ""}}
"""
    
    try:
        response = llm.invoke(prompt).content
        json_match = re.search(r'\{[^{}]*\}', response, re.DOTALL)
        if json_match:
            result = json.loads(json_match.group())
            if result.get("exists") and result.get("matched_tool"):
                matched_tool = result["matched_tool"]
                if is_tool_exists(matched_tool):
                    logger.info(f"AI模糊匹配: '{direct_tool}' -> '{matched_tool}'")
                    return update_state(state, tool_exists=True, direct_tool=matched_tool)
    except Exception as e:
        logger.warning(f"AI工具匹配失败: {e}")
    
    error_msg = f"工具 '{direct_tool}' 不存在。您可以选择上传自定义脚本或让AI生成脚本。"
    
    if ws_callback:
        try:
            await ws_callback({
                "type": "tool_not_found",
                "payload": {
                    "tool_name": direct_tool,
                    "available_tools": available_tools,
                    "message": error_msg,
                    "options": [
                        {"key": "upload", "label": "上传脚本"},
                        {"key": "generate", "label": "AI生成脚本"},
                        {"key": "other", "label": "使用其他工具"}
                    ]
                }
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    return update_state(state, tool_exists=False, intent_error=error_msg)


def tool_check_router(state: ScanState) -> str:
    """工具校验路由"""
    tool_exists = state.get("tool_exists", True)
    
    if tool_exists:
        return "direct_tool_execute"
    else:
        return "intent_recognition"


async def direct_tool_execute(state: ScanState) -> ScanState:
    """工具直调节点 - 直接执行指定工具"""
    tool_name = state.get("direct_tool", "")
    target = state.get("target", "")
    session_id = state.get("websocket_session_id") or state.get("task_id")
    ws_callback = memory_store.get_websocket_callback(session_id)
    
    logger.info(f"[{session_id}] 工具直调: {tool_name} -> {target}")
    
    if is_auth_expired(state):
        logger.warning(f"[{session_id}] 认证信息已过期")
        if ws_callback:
            try:
                remaining = get_auth_remaining_time(state)
                await ws_callback({
                    "type": "auth_expired",
                    "payload": {
                        "session_id": session_id,
                        "remaining_seconds": remaining,
                        "message": "认证信息已过期，请重新认证"
                    }
                })
            except Exception as e:
                logger.error(f"WebSocket推送失败: {e}")
    
    if ws_callback:
        try:
            await ws_callback({
                "type": "direct_tool_started",
                "payload": {"tool": tool_name, "target": target}
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    tool = get_tool_by_name(tool_name)
    if not tool:
        error_msg = f"工具 {tool_name} 不存在"
        if ws_callback:
            await ws_callback({
                "type": "direct_tool_error",
                "payload": {"tool": tool_name, "error": error_msg}
            })
        return update_state(state, errors=state.get("errors", []) + [error_msg], is_complete=True)
    
    try:
        from .tools import invoke_tool_with_auth, extract_auth_from_result
        
        result = invoke_tool_with_auth(tool, target, state)
        
        if auth_retry_manager.should_trigger_reauth(session_id, result):
            retry_count = auth_retry_manager.increment_retry(session_id)
            logger.warning(f"[{session_id}] 检测到认证失败，触发重试 ({retry_count}/{AUTH_MAX_RETRY_COUNT})")
            
            if ws_callback:
                try:
                    await ws_callback({
                        "type": "auth_refresh_required",
                        "payload": {
                            "session_id": session_id,
                            "retry_count": retry_count,
                            "max_retries": AUTH_MAX_RETRY_COUNT,
                            "reason": "检测到401/403响应，需要重新认证",
                            "tool": tool_name
                        }
                    })
                except Exception as e:
                    logger.error(f"WebSocket推送失败: {e}")
            
            if retry_count >= AUTH_MAX_RETRY_COUNT:
                logger.error(f"[{session_id}] 认证重试次数已达上限")
                if ws_callback:
                    try:
                        await ws_callback({
                            "type": "auth_retry_exhausted",
                            "payload": {
                                "session_id": session_id,
                                "retry_count": retry_count,
                                "message": "认证重试次数已达上限，请手动重新认证"
                            }
                        })
                    except Exception as e:
                        logger.error(f"WebSocket推送失败: {e}")
                
                return update_state(state, 
                    errors=state.get("errors", []) + ["认证重试次数已达上限"],
                    is_complete=True,
                    auth_retry_count=retry_count
                )
        
        if not is_auth_failure_response(result):
            auth_retry_manager.reset_retry(session_id)
        
        logger.info(f"📊 【{tool_name}】结果：{str(result)[:200]}...")
        
        auth_info = extract_auth_from_result(result)
        if auth_info:
            logger.info(f"🔐 从 {tool_name} 提取到认证信息: {list(auth_info.keys())}")
            
            encrypted_auth = encrypt_auth_info(auth_info.get("auth_info", {}))
            if encrypted_auth:
                auth_info["encrypted_auth_info"] = encrypted_auth
            
            state = update_state(state, **auth_info, credentials_obtained=True)
            
            if ws_callback:
                try:
                    await ws_callback({
                        "type": "auth_refresh_success",
                        "payload": {
                            "session_id": session_id,
                            "source_tool": tool_name,
                            "auth_type": auth_info.get("auth_info", {}).get("type", "unknown"),
                            "has_cookies": bool(auth_info.get("auth_info", {}).get("cookies")),
                            "has_token": bool(auth_info.get("auth_info", {}).get("token")),
                            "has_headers": bool(auth_info.get("auth_info", {}).get("headers")),
                            "timestamp": auth_info.get("auth_timestamp", ""),
                            "expires_at": auth_info.get("auth_expires_at", ""),
                            "message": f"已从 {tool_name} 获取认证信息，后续扫描将自动使用"
                        }
                    })
                except Exception as e:
                    logger.error(f"WebSocket推送认证通知失败: {e}")
        
        formatted_result = format_tool_result(tool_name, target, result)
        
        if ws_callback:
            try:
                await ws_callback({
                    "type": "direct_tool_completed",
                    "payload": {
                        "tool": tool_name,
                        "target": target,
                        "formatted_result": formatted_result,
                        "raw_result": result if isinstance(result, dict) else {"data": str(result)},
                        "analysis": formatted_result,
                        "vulnerable": isinstance(result, dict) and result.get("vulnerable", False),
                        "auth_obtained": bool(auth_info),
                        "timestamp": datetime.now().isoformat()
                    }
                })
            except Exception as e:
                logger.error(f"WebSocket推送失败: {e}")
        
        tool_results = state.get("tool_results", {}).copy()
        tool_results[tool_name] = result
        
        completed_tasks = state.get("completed_tasks", []).copy()
        if tool_name not in completed_tasks:
            completed_tasks.append(tool_name)
        
        task_history = state.get("task_history", []).copy()
        task_history.append(f"{tool_name}: {str(result)[:100]}")
        
        update_kwargs = dict(
            tool_results=tool_results,
            completed_tasks=completed_tasks,
            task_history=task_history,
            tool_formatted_result=formatted_result,
            task_result={"tool": tool_name, "result": result},
            last_activity_time=datetime.now().isoformat(),
            is_complete=True
        )
        
        if auth_info:
            update_kwargs["authentication_used"] = True
        
        return update_state(state, **update_kwargs)
        
    except Exception as e:
        logger.error(f"工具执行失败: {e}")
        if ws_callback:
            try:
                await ws_callback({
                    "type": "direct_tool_error",
                    "payload": {"tool": tool_name, "error": str(e)}
                })
            except Exception as we:
                logger.error(f"WebSocket推送失败: {we}")
        return update_state(state, errors=state.get("errors", []) + [f"{tool_name}: {str(e)}"], is_complete=True)


async def start_scan_node(state: ScanState) -> ScanState:
    """扫描启动节点 - 标记开始扫描"""
    session_id = state.get("websocket_session_id") or state.get("task_id")
    ws_callback = memory_store.get_websocket_callback(session_id)
    
    logger.info(f"[{session_id}] 开始扫描流程")
    
    mode = "full_scan"
    planned_tasks = get_tool_sequence(mode)
    
    if ws_callback:
        try:
            await ws_callback({
                "type": "scan_flow_started",
                "payload": {
                    "target": state.get("target", ""),
                    "mode": mode,
                    "planned_tasks": planned_tasks,
                    "total_tasks": len(planned_tasks)
                }
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    return update_state(state, 
        mode=mode, 
        next_action="run_full_scan",
        planned_tasks=planned_tasks,
        last_activity_time=datetime.now().isoformat()
    )


async def script_upload_process(state: ScanState) -> ScanState:
    """脚本上传处理节点"""
    from .tools import script_manager
    from datetime import datetime
    
    session_id = state.get("websocket_session_id") or state.get("task_id")
    ws_callback = memory_store.get_websocket_callback(session_id)
    
    logger.info(f"[{session_id}] 脚本上传处理")
    
    if ws_callback:
        try:
            await ws_callback({
                "type": "script_upload_request",
                "payload": {"message": "请上传您的脚本文件或粘贴脚本内容"}
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    upload_data = interrupt({"type": "waiting_for_script_upload"})
    
    script_content = upload_data.get("script_content", "")
    script_name = upload_data.get("script_name", f"custom_{datetime.now().strftime('%Y%m%d%H%M%S')}")
    
    if not script_content:
        if ws_callback:
            await ws_callback({
                "type": "script_error",
                "payload": {"error": "脚本内容为空"}
            })
        return update_state(state, is_complete=True)
    
    if ws_callback:
        try:
            await ws_callback({
                "type": "script_analyzing",
                "payload": {"message": "AI正在分析脚本..."}
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    analysis = await script_manager.analyze_script_with_ai(script_content)
    
    result = script_manager.register_script_as_tool(
        script_content=script_content,
        script_name=analysis.get("tool_name", script_name),
        description=analysis.get("description", "自定义扫描脚本"),
        category=analysis.get("category", "custom")
    )
    
    if ws_callback:
        try:
            if result.get("success"):
                await ws_callback({
                    "type": "script_registered",
                    "payload": {
                        "tool_name": result["tool_name"],
                        "description": analysis.get("description"),
                        "message": f"脚本已注册为工具: {result['tool_name']}"
                    }
                })
            else:
                await ws_callback({
                    "type": "script_error",
                    "payload": {"error": result.get("error", "注册失败")}
                })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    return update_state(state, 
        registered_tool_name=result.get("tool_name", ""),
        script_description=analysis.get("description", ""),
        script_content=script_content,
        is_complete=True
    )


async def script_generate_process(state: ScanState) -> ScanState:
    """AI脚本生成处理节点"""
    from .tools import script_manager
    from datetime import datetime
    
    session_id = state.get("websocket_session_id") or state.get("task_id")
    ws_callback = memory_store.get_websocket_callback(session_id)
    
    logger.info(f"[{session_id}] AI脚本生成处理")
    
    if ws_callback:
        try:
            await ws_callback({
                "type": "script_generate_request",
                "payload": {"message": "请描述您需要的扫描脚本功能"}
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    desc_data = interrupt({"type": "waiting_for_script_description"})
    description = desc_data.get("description", "")
    
    if not description:
        if ws_callback:
            await ws_callback({
                "type": "script_error",
                "payload": {"error": "请提供脚本功能描述"}
            })
        return update_state(state, is_complete=True)
    
    if ws_callback:
        try:
            await ws_callback({
                "type": "script_generating",
                "payload": {"message": "AI正在生成脚本..."}
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    script_code = await script_manager.generate_script_with_ai(description)
    
    if not script_code:
        if ws_callback:
            await ws_callback({
                "type": "script_error",
                "payload": {"error": "AI生成脚本失败"}
            })
        return update_state(state, is_complete=True)
    
    analysis = await script_manager.analyze_script_with_ai(script_code)
    
    result = script_manager.register_script_as_tool(
        script_content=script_code,
        script_name=analysis.get("tool_name", f"ai_gen_{datetime.now().strftime('%Y%m%d%H%M%S')}"),
        description=analysis.get("description", description),
        category=analysis.get("category", "custom")
    )
    
    if ws_callback:
        try:
            if result.get("success"):
                await ws_callback({
                    "type": "script_generated",
                    "payload": {
                        "tool_name": result["tool_name"],
                        "script_code": script_code,
                        "description": analysis.get("description"),
                        "message": f"AI脚本已生成并注册: {result['tool_name']}"
                    }
                })
            else:
                await ws_callback({
                    "type": "script_error",
                    "payload": {"error": result.get("error", "注册失败")}
                })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    return update_state(state,
        script_content=script_code,
        registered_tool_name=result.get("tool_name", ""),
        script_description=analysis.get("description", ""),
        is_complete=True
    )


async def ai_decision(state: ScanState) -> ScanState:
    """原子1: AI智能决策"""
    logger.info(f"[{state.get('task_id')}] AI决策节点开始执行")
    
    session_id = state.get("websocket_session_id") or state.get("task_id")
    done = list(state.get("tool_results", {}).keys())
    mode = state.get("mode", "full_scan")
    tool_sequence = get_tool_sequence(mode)
    ws_callback = memory_store.get_websocket_callback(session_id)
    
    progress_percent = round((len(done) / len(tool_sequence)) * 100, 1) if tool_sequence else 0
    
    if ws_callback:
        try:
            await ws_callback({
                "type": "workflow_progress",
                "payload": {
                    "stage": mode,
                    "status": "running",
                    "completed": len(done),
                    "total": len(tool_sequence),
                    "progress_percent": progress_percent
                }
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    for t in tool_sequence:
        if t not in done:
            logger.info(f"✅ 分配任务：{t}")
            
            decision_history = state.get("decision_history", []).copy()
            decision_history.append({
                "timestamp": datetime.now().isoformat(),
                "next_task": t,
                "completed_count": len(done),
                "total_count": len(tool_sequence)
            })
            
            if ws_callback:
                try:
                    await ws_callback({
                        "type": "ai_decision",
                        "payload": {
                            "next_task": t,
                            "completed_tasks": done,
                            "total_tasks": len(tool_sequence),
                            "progress": f"{len(done)}/{len(tool_sequence)}",
                            "progress_percent": progress_percent
                        }
                    })
                except Exception as e:
                    logger.error(f"WebSocket推送失败: {e}")
            
            return update_state(state, 
                next_task=t, 
                need_generate_script=False,
                decision_history=decision_history,
                last_activity_time=datetime.now().isoformat()
            )
    
    logger.info("✅ 所有扫描任务已完成！")
    
    if ws_callback:
        try:
            await ws_callback({
                "type": "workflow_progress",
                "payload": {
                    "stage": mode,
                    "status": "completed",
                    "completed": len(done),
                    "total": len(tool_sequence),
                    "progress_percent": 100
                }
            })
            await ws_callback({
                "type": "ai_decision_complete",
                "payload": {
                    "completed_tasks": done,
                    "total_tasks": len(tool_sequence)
                }
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    return update_state(state, next_task="end", need_generate_script=False)


async def user_interact(state: ScanState) -> ScanState:
    """原子2: 用户交互 - 使用 interrupt 实现暂停等待"""
    logger.info(f"[{state.get('task_id')}] 用户交互节点")
    
    next_task = state.get("next_task", "")
    mode = state.get("mode", "full_scan")
    target = state.get("target", "")
    session_id = state.get("websocket_session_id") or state.get("task_id")
    
    if next_task == "end":
        return state
    
    interaction_data = {
        "type": "interaction_required",
        "session_id": session_id,
        "next_task": next_task,
        "target": target,
        "mode": mode,
        "completed_tasks": state.get("completed_tasks", []),
        "options": [
            {"key": "1", "label": "执行", "description": f"执行任务: {next_task}"},
            {"key": "2", "label": "停止", "description": "停止扫描并生成报告"},
            {"key": "3", "label": "聊天", "description": "与 AI 助手对话"},
            {"key": "4", "label": "上传脚本", "description": "上传自定义扫描脚本"},
            {"key": "5", "label": "生成脚本", "description": "AI生成专属扫描脚本"}
        ]
    }
    
    logger.info(f"🎯 目标：{target} | 模式：{mode} | 下一个任务：{next_task}")
    logger.info("[1]执行 [2]停止 [3]聊天 [4]上传脚本 [5]生成脚本")
    
    memory_store.set_pending_interaction(session_id, interaction_data)
    
    ws_callback = memory_store.get_websocket_callback(session_id)
    if ws_callback:
        try:
            await ws_callback(interaction_data)
        except Exception as e:
            logger.error(f"WebSocket 回调失败: {e}")
    
    user_choice = interrupt(interaction_data)
    
    memory_store.clear_pending_interaction(session_id)
    
    logger.info(f"👤 用户选择: {user_choice}")
    
    return update_state(state, user_choice=user_choice)


async def execute_task(state: ScanState) -> ScanState:
    """原子3: 执行任务"""
    logger.info(f"[{state.get('task_id')}] 执行任务节点")
    
    task = state.get("next_task", "")
    if task == "end" or task == "":
        return state
    
    target = state.get("target", "")
    session_id = state.get("websocket_session_id") or state.get("task_id")
    ws_callback = memory_store.get_websocket_callback(session_id)
    
    if is_auth_expired(state):
        logger.warning(f"[{session_id}] 认证信息已过期")
        if ws_callback:
            try:
                remaining = get_auth_remaining_time(state)
                await ws_callback({
                    "type": "auth_expired",
                    "payload": {
                        "session_id": session_id,
                        "remaining_seconds": remaining,
                        "message": "认证信息已过期，请重新认证"
                    }
                })
            except Exception as e:
                logger.error(f"WebSocket推送失败: {e}")
    
    tool = get_tool_by_name(task)
    
    if not tool:
        logger.warning(f"工具 {task} 不存在")
        if ws_callback:
            await ws_callback({
                "type": "task_error",
                "payload": {"tool": task, "error": f"工具 {task} 不存在"}
            })
        return update_state(state, errors=state.get("errors", []) + [f"工具 {task} 不存在"])
    
    if ws_callback:
        try:
            await ws_callback({
                "type": "task_started",
                "payload": {"tool": task, "target": target}
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    try:
        from .tools import invoke_tool_with_auth, extract_auth_from_result
        
        res = invoke_tool_with_auth(tool, target, state)
        
        if auth_retry_manager.should_trigger_reauth(session_id, res):
            retry_count = auth_retry_manager.increment_retry(session_id)
            logger.warning(f"[{session_id}] 检测到认证失败，触发重试 ({retry_count}/{AUTH_MAX_RETRY_COUNT})")
            
            if ws_callback:
                try:
                    await ws_callback({
                        "type": "auth_refresh_required",
                        "payload": {
                            "session_id": session_id,
                            "retry_count": retry_count,
                            "max_retries": AUTH_MAX_RETRY_COUNT,
                            "reason": "检测到401/403响应，需要重新认证",
                            "tool": task
                        }
                    })
                except Exception as e:
                    logger.error(f"WebSocket推送失败: {e}")
            
            if retry_count < AUTH_MAX_RETRY_COUNT:
                state = update_state(state, need_reauth=True, auth_retry_count=retry_count)
                return state
            else:
                logger.error(f"[{session_id}] 认证重试次数已达上限")
                if ws_callback:
                    try:
                        await ws_callback({
                            "type": "auth_retry_exhausted",
                            "payload": {
                                "session_id": session_id,
                                "retry_count": retry_count,
                                "message": "认证重试次数已达上限，请手动重新认证"
                            }
                        })
                    except Exception as e:
                        logger.error(f"WebSocket推送失败: {e}")
        
        if not is_auth_failure_response(res):
            auth_retry_manager.reset_retry(session_id)
        
        logger.info(f"📊 【{task}】结果：{res}")
        
        auth_info = extract_auth_from_result(res)
        if auth_info:
            logger.info(f"🔐 从 {task} 提取到认证信息: {list(auth_info.keys())}")
            
            encrypted_auth = encrypt_auth_info(auth_info.get("auth_info", {}))
            if encrypted_auth:
                auth_info["encrypted_auth_info"] = encrypted_auth
            
            state = update_state(state, **auth_info, credentials_obtained=True)
            
            if ws_callback:
                try:
                    await ws_callback({
                        "type": "auth_info_obtained",
                        "payload": {
                            "source_tool": task,
                            "auth_type": auth_info.get("auth_info", {}).get("type", "unknown"),
                            "has_cookies": bool(auth_info.get("auth_info", {}).get("cookies")),
                            "has_token": bool(auth_info.get("auth_info", {}).get("token")),
                            "has_headers": bool(auth_info.get("auth_info", {}).get("headers")),
                            "timestamp": auth_info.get("auth_timestamp", ""),
                            "expires_at": auth_info.get("auth_expires_at", ""),
                            "message": f"已从 {task} 获取认证信息，后续扫描将自动使用"
                        }
                    })
                except Exception as e:
                    logger.error(f"WebSocket推送认证通知失败: {e}")
        
        llm = get_llm()
        analysis = llm.invoke(f"用1-2句话简要分析这个扫描结果的关键发现：{str(res)[:500]}").content
        logger.info(f"🧾 分析：{analysis}")
        
        if ws_callback:
            try:
                await ws_callback({
                    "type": "task_completed",
                    "payload": {
                        "tool": task,
                        "target": target,
                        "raw_result": res if isinstance(res, dict) else {"data": str(res)},
                        "analysis": analysis,
                        "vulnerable": isinstance(res, dict) and res.get("vulnerable", False),
                        "auth_obtained": bool(auth_info),
                        "timestamp": datetime.now().isoformat()
                    }
                })
            except Exception as e:
                logger.error(f"WebSocket推送失败: {e}")
        
        new_state = append_chat(state, "system", f"任务：{task}\n结果：{res}\n分析：{analysis}")
        tool_results = state.get("tool_results", {}).copy()
        tool_results[task] = res
        
        completed_tasks = state.get("completed_tasks", []).copy()
        completed_tasks.append(task)
        
        task_history = state.get("task_history", []).copy()
        task_history.append(f"{task}: {str(res)[:100]}")
        
        planned_tasks = state.get("planned_tasks", [])
        stage_status = state.get("stage_status", {}).copy()
        stage_status["tool_execution"] = {
            "status": "running",
            "current_task": task,
            "progress": round(len(completed_tasks) / max(len(planned_tasks), 1) * 100, 1),
            "completed": len(completed_tasks),
            "total": len(planned_tasks) if planned_tasks else 1
        }
        
        update_kwargs = dict(
            tool_results=tool_results, 
            completed_tasks=completed_tasks,
            task_history=task_history,
            stage_status=stage_status,
            task_result={"tool": task, "result": res},
            last_activity_time=datetime.now().isoformat()
        )
        
        if auth_info:
            update_kwargs["authentication_used"] = True
        
        return update_state(new_state, **update_kwargs)
        
    except Exception as e:
        logger.error(f"执行任务失败: {e}")
        if ws_callback:
            try:
                await ws_callback({
                    "type": "task_error",
                    "payload": {"tool": task, "error": str(e)}
                })
            except Exception as we:
                logger.error(f"WebSocket推送失败: {we}")
        return update_state(state, errors=state.get("errors", []) + [f"{task}: {str(e)}"])


async def chat(state: ScanState) -> ScanState:
    """原子4: 聊天"""
    logger.info(f"[{state.get('task_id')}] 聊天节点")
    
    session_id = state.get("websocket_session_id") or state.get("task_id")
    ws_callback = memory_store.get_websocket_callback(session_id)
    
    llm = get_llm()
    user_name = state.get("user_name", "用户")
    chat_summary = state.get("chat_summary", "无")
    task_history = state.get("completed_tasks", [])
    target = state.get("target", "")
    user_input = state.get("user_input", "")
    conversation_turn = state.get("conversation_turn", 0) + 1
    
    prompt = f"""你是安全助手，用户：{user_name}
聊天总结：{chat_summary}
任务历史：{task_history}
目标：{target}
自然简洁回复。"""
    
    ai_msg = llm.invoke(prompt).content
    logger.info(f"🤖 AI：{ai_msg}")
    
    if ws_callback:
        try:
            await ws_callback({
                "type": "ai_chat",
                "payload": {"content": ai_msg, "context": "scan_assistant"}
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    new_state = append_chat(state, "assistant", ai_msg)
    
    memory_store.append_chat(session_id, "user", user_input)
    memory_store.append_chat(session_id, "assistant", ai_msg)
    
    return update_state(new_state, 
        chat_summary=ai_msg[:200],
        conversation_turn=conversation_turn,
        last_activity_time=datetime.now().isoformat()
    )


async def script_manager(state: ScanState) -> ScanState:
    """原子5: 脚本管理"""
    logger.info(f"[{state.get('task_id')}] 脚本管理节点")
    
    user_choice = state.get("user_choice", "")
    
    if user_choice == "4":
        logger.info("📁 脚本上传功能")
    elif user_choice == "5":
        logger.info("🔧 脚本生成功能")
    
    return update_state(state, need_generate_script=False)


async def report_generation(state: ScanState) -> ScanState:
    """原子6: 报告生成 - 使用AI分析并保存报告到文件"""
    logger.info(f"[{state.get('task_id')}] 报告生成节点")
    
    tool_results = state.get("tool_results", {})
    vulnerabilities = state.get("vulnerabilities", [])
    target = state.get("target", "")
    session_id = state.get("websocket_session_id") or state.get("task_id", "unknown")
    ws_callback = memory_store.get_websocket_callback(session_id)
    
    if not tool_results:
        if ws_callback:
            await ws_callback({
                "type": "report_error",
                "payload": {"error": "无扫描结果"}
            })
        return update_state(state, is_complete=True, report="无扫描结果")
    
    scan_summary = {
        "timestamp": datetime.now().isoformat(),
        "tool_count": len(tool_results),
        "vulnerability_count": len(vulnerabilities)
    }
    
    if ws_callback:
        try:
            await ws_callback({
                "type": "report_generation_started",
                "payload": {
                    "session_id": session_id,
                    "tool_count": len(tool_results),
                    "vulnerability_count": len(vulnerabilities)
                }
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    try:
        from ..tools.report.report_manager import get_report_manager
        report_manager = get_report_manager()
        
        chat_history = memory_store.get_chat_history(session_id)
        task_history = [
            {
                "tool": task, 
                "result_summary": str(state.get("tool_results", {}).get(task, ""))[:200]
            }
            for task in state.get("completed_tasks", [])
        ]
        
        report = await report_manager.generate_ai_report_content_async(
            tool_results=tool_results,
            vulnerabilities=vulnerabilities,
            target=target,
            chat_history=chat_history,
            task_history=task_history
        )
        
        report_info = report_manager.save_report(
            session_id=session_id,
            content=report,
            metadata={
                "target": target,
                "tool_results": tool_results,
                "vulnerabilities": vulnerabilities,
                "scan_summary": scan_summary,
                "chat_history_count": len(chat_history),
                "task_history_count": len(task_history)
            }
        )
        
        logger.info(f"报告已保存: {report_info.get('download_url')}")
        
        if ws_callback:
            try:
                await ws_callback({
                    "type": "report_generated",
                    "payload": {
                        "report_url": report_info.get("download_url", ""),
                        "report_id": report_info.get("report_id", ""),
                        "report_preview": report[:500] if report else ""
                    }
                })
            except Exception as e:
                logger.error(f"WebSocket推送失败: {e}")
        
        return update_state(
            state, 
            is_complete=True, 
            report=report, 
            scan_summary=scan_summary,
            report_url=report_info.get("download_url", ""),
            report_id=report_info.get("report_id", "")
        )
    except Exception as e:
        logger.error(f"保存报告失败: {e}")
        if ws_callback:
            try:
                await ws_callback({
                    "type": "report_error",
                    "payload": {"error": str(e)}
                })
            except Exception as we:
                logger.error(f"WebSocket推送失败: {we}")
        return update_state(state, is_complete=True, report="报告生成失败", scan_summary=scan_summary)


def router(state: ScanState) -> str:
    """路由决策"""
    next_task = state.get("next_task", "")
    need_generate_script = state.get("need_generate_script", False)
    user_choice = state.get("user_choice", "")
    
    if next_task == "end":
        return "report_generation"
    
    if need_generate_script:
        return "script_manager"
    
    c = user_choice
    if c == "1":
        return "execute_task"
    if c == "2":
        return "report_generation"
    if c == "3":
        return "chat"
    if c == "4":
        return "script_upload_process"
    if c == "5":
        return "script_generate_process"
    
    return "user_interact"


class IntentRecognitionGraph:
    """用户意图识别子图 - 系统总入口"""
    
    @staticmethod
    def build() -> StateGraph:
        workflow = StateGraph(ScanState)
        
        workflow.add_node("intent_recognition", intent_recognition)
        workflow.add_node("intent_validation", intent_validation)
        workflow.add_node("tool_existence_check", tool_existence_check)
        workflow.add_node("direct_tool_execute", direct_tool_execute)
        workflow.add_node("chat", chat)
        workflow.add_node("start_scan", start_scan_node)
        workflow.add_node("script_upload_process", script_upload_process)
        workflow.add_node("script_generate_process", script_generate_process)
        
        workflow.set_entry_point("intent_recognition")
        workflow.add_edge("intent_recognition", "intent_validation")
        workflow.add_conditional_edges("intent_validation", intent_router)
        
        workflow.add_conditional_edges("tool_existence_check", tool_check_router)
        workflow.add_edge("direct_tool_execute", END)
        workflow.add_edge("chat", END)
        workflow.add_edge("start_scan", END)
        workflow.add_edge("script_upload_process", END)
        workflow.add_edge("script_generate_process", END)
        
        return workflow.compile(checkpointer=MemorySaver())


class InfoCollectionGraph:
    """信息收集子图"""
    
    @staticmethod
    def build() -> StateGraph:
        workflow = StateGraph(ScanState)
        
        workflow.add_node("ai_decision", ai_decision)
        workflow.add_node("user_interact", user_interact)
        workflow.add_node("execute_task", execute_task)
        workflow.add_node("chat", chat)
        workflow.add_node("script_manager", script_manager)
        workflow.add_node("report_generation", report_generation)
        
        workflow.set_entry_point("ai_decision")
        workflow.add_edge("ai_decision", "user_interact")
        workflow.add_conditional_edges("user_interact", router)
        workflow.add_edge("execute_task", "ai_decision")
        workflow.add_edge("chat", "ai_decision")
        workflow.add_edge("script_manager", "ai_decision")
        workflow.add_edge("report_generation", END)
        
        return workflow.compile(checkpointer=MemorySaver())


class VulnScanGraph:
    """漏洞扫描子图"""
    
    @staticmethod
    def build() -> StateGraph:
        workflow = StateGraph(ScanState)
        
        workflow.add_node("ai_decision", ai_decision)
        workflow.add_node("user_interact", user_interact)
        workflow.add_node("execute_task", execute_task)
        workflow.add_node("chat", chat)
        workflow.add_node("report_generation", report_generation)
        
        workflow.set_entry_point("ai_decision")
        workflow.add_edge("ai_decision", "user_interact")
        workflow.add_conditional_edges("user_interact", router)
        workflow.add_edge("execute_task", "ai_decision")
        workflow.add_edge("chat", "ai_decision")
        workflow.add_edge("report_generation", END)
        
        return workflow.compile(checkpointer=MemorySaver())


class ReportGraph:
    """报告生成子图"""
    
    @staticmethod
    def build() -> StateGraph:
        workflow = StateGraph(ScanState)
        
        workflow.add_node("report_generation", report_generation)
        
        workflow.set_entry_point("report_generation")
        workflow.add_edge("report_generation", END)
        
        return workflow.compile()


class AgentOrchestrator:
    """Agent编排器 - 管理多个子图的执行，支持暂停/恢复"""
    
    def __init__(self):
        self.intent_graph = IntentRecognitionGraph.build()
        self.info_graph = InfoCollectionGraph.build()
        self.vuln_graph = VulnScanGraph.build()
        self.report_graph = ReportGraph.build()
        self._running_tasks: Dict[str, asyncio.Task] = {}
        logger.info("Agent编排器初始化完成")
    
    def set_websocket_callback(self, session_id: str, callback: Callable):
        """设置 WebSocket 回调"""
        memory_store.set_websocket_callback(session_id, callback)
    
    def resume_workflow(self, session_id: str, user_choice: str) -> bool:
        """恢复暂停的工作流"""
        state = memory_store.get_session(session_id)
        if not state:
            logger.warning(f"会话 {session_id} 不存在")
            return False
        
        state = update_state(state, user_choice=user_choice)
        memory_store.save_session(session_id, state)
        
        logger.info(f"工作流 {session_id} 已恢复，用户选择: {user_choice}")
        return True
    
    def get_pending_interaction(self, session_id: str) -> Optional[Dict]:
        """获取待处理的交互请求"""
        return memory_store.get_pending_interaction(session_id)
    
    def has_pending_interaction(self, session_id: str) -> bool:
        """检查是否有待处理的交互"""
        return memory_store.has_pending_interaction(session_id)
    
    async def run_intent_recognition(self, state: ScanState, websocket_callback: Callable = None) -> ScanState:
        """运行意图识别流程"""
        session_id = state.get("websocket_session_id") or state.get("task_id")
        
        if websocket_callback:
            memory_store.set_websocket_callback(session_id, websocket_callback)
        
        memory_store.save_session(session_id, state)
        
        result = await self.intent_graph.ainvoke(
            state,
            config={"configurable": {"thread_id": session_id}}
        )
        
        if result.get("next_action") == "run_full_scan":
            logger.info(f"[{session_id}] 意图识别完成，开始扫描流程")
            result = await self.run_full_scan(result, websocket_callback)
        
        memory_store.save_session(session_id, result)
        return result
    
    async def run_direct_tool(self, tool_name: str, target: str, session_id: str, websocket_callback: Callable = None) -> Dict[str, Any]:
        """直接执行工具"""
        if websocket_callback:
            memory_store.set_websocket_callback(session_id, websocket_callback)
        
        tool = get_tool_by_name(tool_name)
        if not tool:
            raise ValueError(f"工具 {tool_name} 不存在")
        
        if websocket_callback:
            try:
                await websocket_callback({
                    "type": "direct_tool_started",
                    "payload": {"tool": tool_name, "target": target}
                })
            except Exception as e:
                logger.error(f"WebSocket推送失败: {e}")
        
        try:
            result = tool.invoke(target)
            formatted = format_tool_result(tool_name, target, result)
            
            if websocket_callback:
                try:
                    await websocket_callback({
                        "type": "direct_tool_completed",
                        "payload": {
                            "tool": tool_name,
                            "target": target,
                            "formatted_result": formatted
                        }
                    })
                except Exception as e:
                    logger.error(f"WebSocket推送失败: {e}")
            
            return {
                "tool": tool_name,
                "target": target,
                "result": result,
                "formatted_result": formatted
            }
        except Exception as e:
            if websocket_callback:
                try:
                    await websocket_callback({
                        "type": "direct_tool_error",
                        "payload": {"tool": tool_name, "error": str(e)}
                    })
                except Exception as we:
                    logger.error(f"WebSocket推送失败: {we}")
            raise
    
    async def run_full_scan(self, state: ScanState, websocket_callback: Callable = None) -> ScanState:
        """运行完整扫描流程"""
        logger.info(f"[{state.get('task_id')}] 开始完整扫描流程")
        
        session_id = state.get("websocket_session_id") or state.get("task_id")
        memory_store.save_session(session_id, state)
        
        if websocket_callback:
            memory_store.set_websocket_callback(session_id, websocket_callback)
        
        try:
            state = update_state(state, mode="info_collection")
            state = await self.info_graph.ainvoke(
                state,
                config={"configurable": {"thread_id": session_id}}
            )
            memory_store.save_session(session_id, state)
            
            state = update_state(state, mode="vuln_scan")
            state = await self.vuln_graph.ainvoke(
                state,
                config={"configurable": {"thread_id": session_id}}
            )
            memory_store.save_session(session_id, state)
            
            state = await self.report_graph.ainvoke(state)
            memory_store.save_session(session_id, state)
            
            logger.info(f"[{state.get('task_id')}] 完整扫描流程完成")
            return state
            
        except Exception as e:
            logger.error(f"完整扫描流程失败: {e}")
            raise
    
    async def run_info_collection(self, state: ScanState, websocket_callback: Callable = None) -> ScanState:
        """仅运行信息收集"""
        session_id = state.get("websocket_session_id") or state.get("task_id")
        
        if websocket_callback:
            memory_store.set_websocket_callback(session_id, websocket_callback)
        
        state = update_state(state, mode="info_collection")
        return await self.info_graph.ainvoke(
            state,
            config={"configurable": {"thread_id": session_id}}
        )
    
    async def run_vuln_scan(self, state: ScanState, websocket_callback: Callable = None) -> ScanState:
        """仅运行漏洞扫描"""
        session_id = state.get("websocket_session_id") or state.get("task_id")
        
        if websocket_callback:
            memory_store.set_websocket_callback(session_id, websocket_callback)
        
        state = update_state(state, mode="vuln_scan")
        return await self.vuln_graph.ainvoke(
            state,
            config={"configurable": {"thread_id": session_id}}
        )
    
    async def run_report(self, state: ScanState) -> ScanState:
        """仅生成报告"""
        return await self.report_graph.ainvoke(state)


agent_orchestrator = AgentOrchestrator()


def get_agent_orchestrator() -> AgentOrchestrator:
    """获取Agent编排器实例"""
    return agent_orchestrator
