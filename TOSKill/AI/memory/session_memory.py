"""
会话记忆管理模块

提供会话级别的记忆存储功能。
"""
import logging
import threading
import time
from typing import Dict, Any, Optional, List
from datetime import datetime
from uuid import uuid4

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


class SessionMemoryManager:
    """
    会话记忆管理器
    
    使用内存存储会话状态，支持：
    - 会话创建和删除
    - 消息历史记录
    - 状态保存
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
            self._initialized = True
            logger.info("SessionMemoryManager 初始化完成")
    
    def create_session(self, session_id: str = None) -> str:
        """创建新会话"""
        if session_id is None:
            session_id = str(uuid4())
        
        thread_id = str(uuid4())
        checkpoint = SessionCheckpoint(session_id, thread_id)
        
        self._sessions[session_id] = checkpoint
        self._session_threads[thread_id] = session_id
        
        logger.info(f"创建新会话: {session_id}")
        return session_id
    
    def delete_session(self, session_id: str) -> bool:
        """删除会话"""
        if session_id in self._sessions:
            checkpoint = self._sessions[session_id]
            if checkpoint.thread_id in self._session_threads:
                del self._session_threads[checkpoint.thread_id]
            del self._sessions[session_id]
            logger.info(f"删除会话: {session_id}")
            return True
        return False
    
    def save_session(self, session_id: str, state_data: Dict[str, Any]) -> bool:
        """保存会话状态"""
        if session_id not in self._sessions:
            self.create_session(session_id)
        
        checkpoint = self._sessions[session_id]
        checkpoint.update(state_data)
        
        logger.debug(f"保存会话状态: {session_id}")
        return True
    
    def add_message(self, session_id: str, role: str, content: str, metadata: Dict[str, Any] = None) -> bool:
        """添加消息到会话历史"""
        checkpoint = self._sessions.get(session_id)
        if checkpoint:
            checkpoint.add_message(role, content, metadata)
            return True
        return False
    
    def get_message_history(self, session_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """获取消息历史"""
        checkpoint = self._sessions.get(session_id)
        if checkpoint:
            return checkpoint.message_history[-limit:]
        return []



session_memory = SessionMemoryManager()


def get_memory_manager() -> SessionMemoryManager:
    """获取会话记忆管理器实例"""
    return session_memory
