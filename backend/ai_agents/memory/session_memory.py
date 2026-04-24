"""
会话记忆管理模块

使用 LangGraph 的 MemorySaver 实现会话级别的记忆存储。
不使用数据库，所有数据存储在内存中。
"""
import logging
import threading
import time
from typing import Dict, Any, Optional, List
from datetime import datetime
from uuid import uuid4
import json

logger = logging.getLogger(__name__)


class SessionCheckpoint:
    """会话检查点"""
    
    def __init__(self, session_id: str, thread_id: str):
        self.session_id = session_id
        self.thread_id = thread_id
        self.channel_values: Dict[str, Any] = {}
        self.created_at = time.time()
        self.updated_at = time.time()
        self.message_history: List[Dict[str, Any]] = []
    
    def update(self, values: Dict[str, Any]):
        self.channel_values.update(values)
        self.updated_at = time.time()
    
    def add_message(self, role: str, content: str, metadata: Dict[str, Any] = None):
        self.message_history.append({
            "role": role,
            "content": content,
            "timestamp": datetime.now().isoformat(),
            "metadata": metadata or {}
        })
        self.updated_at = time.time()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "thread_id": self.thread_id,
            "channel_values": self.channel_values,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "message_history": self.message_history
        }


class SessionMemoryManager:
    """
    会话记忆管理器
    
    使用内存存储会话状态，支持：
    - 会话创建和恢复
    - 消息历史记录
    - 状态持久化
    - 会话清理
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not hasattr(self, '_initialized'):
            self._sessions: Dict[str, SessionCheckpoint] = {}
            self._session_threads: Dict[str, str] = {}
            self._max_sessions = 1000
            self._session_timeout = 3600 * 24
            self._cleanup_interval = 3600
            self._last_cleanup = time.time()
            self._initialized = True
            logger.info("SessionMemoryManager 初始化完成")
    
    def create_session(self, session_id: str = None) -> str:
        """
        创建新会话
        
        Args:
            session_id: 可选的会话ID，不提供则自动生成
            
        Returns:
            str: 会话ID
        """
        if session_id is None:
            session_id = str(uuid4())
        
        thread_id = str(uuid4())
        checkpoint = SessionCheckpoint(session_id, thread_id)
        
        self._sessions[session_id] = checkpoint
        self._session_threads[thread_id] = session_id
        
        logger.info(f"创建新会话: {session_id}")
        return session_id
    
    def save_session(self, session_id: str, state_data: Dict[str, Any]) -> bool:
        """
        保存会话状态
        
        Args:
            session_id: 会话ID
            state_data: 状态数据
            
        Returns:
            bool: 是否保存成功
        """
        if session_id not in self._sessions:
            self.create_session(session_id)
        
        checkpoint = self._sessions[session_id]
        checkpoint.update(state_data)
        
        logger.debug(f"保存会话状态: {session_id}")
        return True
    
    def load_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        加载会话状态
        
        Args:
            session_id: 会话ID
            
        Returns:
            Optional[Dict[str, Any]]: 状态数据，不存在返回None
        """
        checkpoint = self._sessions.get(session_id)
        if checkpoint:
            return checkpoint.channel_values.copy()
        return None
    
    def get_session(self, session_id: str) -> Optional[SessionCheckpoint]:
        """
        获取会话检查点
        
        Args:
            session_id: 会话ID
            
        Returns:
            Optional[SessionCheckpoint]: 会话检查点
        """
        return self._sessions.get(session_id)
    
    def delete_session(self, session_id: str) -> bool:
        """
        删除会话
        
        Args:
            session_id: 会话ID
            
        Returns:
            bool: 是否删除成功
        """
        if session_id in self._sessions:
            checkpoint = self._sessions[session_id]
            if checkpoint.thread_id in self._session_threads:
                del self._session_threads[checkpoint.thread_id]
            del self._sessions[session_id]
            logger.info(f"删除会话: {session_id}")
            return True
        return False
    
    def add_message(self, session_id: str, role: str, content: str, metadata: Dict[str, Any] = None) -> bool:
        """
        添加消息到会话历史
        
        Args:
            session_id: 会话ID
            role: 角色 (user/assistant/system)
            content: 消息内容
            metadata: 元数据
            
        Returns:
            bool: 是否添加成功
        """
        checkpoint = self._sessions.get(session_id)
        if checkpoint:
            checkpoint.add_message(role, content, metadata)
            return True
        return False
    
    def get_message_history(self, session_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """
        获取消息历史
        
        Args:
            session_id: 会话ID
            limit: 最大返回数量
            
        Returns:
            List[Dict[str, Any]]: 消息历史列表
        """
        checkpoint = self._sessions.get(session_id)
        if checkpoint:
            return checkpoint.message_history[-limit:]
        return []
    
    def get_all_sessions(self) -> List[Dict[str, Any]]:
        """
        获取所有会话信息
        
        Returns:
            List[Dict[str, Any]]: 会话列表
        """
        return [
            {
                "session_id": cp.session_id,
                "created_at": datetime.fromtimestamp(cp.created_at).isoformat(),
                "updated_at": datetime.fromtimestamp(cp.updated_at).isoformat(),
                "message_count": len(cp.message_history)
            }
            for cp in self._sessions.values()
        ]
    
    def cleanup_expired_sessions(self) -> int:
        """
        清理过期会话
        
        Returns:
            int: 清理的会话数量
        """
        current_time = time.time()
        expired_sessions = []
        
        for session_id, checkpoint in self._sessions.items():
            if current_time - checkpoint.updated_at > self._session_timeout:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            self.delete_session(session_id)
        
        self._last_cleanup = current_time
        logger.info(f"清理过期会话: {len(expired_sessions)} 个")
        return len(expired_sessions)
    
    def get_session_count(self) -> int:
        """获取当前会话数量"""
        return len(self._sessions)
    
    def search_messages(self, session_id: str, query: str) -> List[Dict[str, Any]]:
        """
        搜索消息历史
        
        Args:
            session_id: 会话ID
            query: 搜索关键词
            
        Returns:
            List[Dict[str, Any]]: 匹配的消息列表
        """
        checkpoint = self._sessions.get(session_id)
        if not checkpoint:
            return []
        
        results = []
        query_lower = query.lower()
        
        for msg in checkpoint.message_history:
            if query_lower in msg.get("content", "").lower():
                results.append(msg)
        
        return results


session_memory = SessionMemoryManager()


def get_memory_manager() -> SessionMemoryManager:
    """获取会话记忆管理器实例"""
    return session_memory
