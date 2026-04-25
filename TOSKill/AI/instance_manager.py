"""
对话实例管理模块

提供独立的对话实例管理，确保数据隔离和内存安全。
支持实例创建、销毁、内存监控和自动清理。
"""
import gc
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, Any, Optional, List
from uuid import uuid4
import logging

logger = logging.getLogger(__name__)


class InstanceStatus(Enum):
    """实例状态枚举"""
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    EXPIRED = "expired"
    ERROR = "error"


@dataclass
class ChatInstance:
    """独立对话实例"""
    instance_id: str
    target: str
    agent_state: Any
    created_at: datetime = field(default_factory=datetime.now)
    last_active: datetime = field(default_factory=datetime.now)
    memory_usage: int = 0
    status: InstanceStatus = InstanceStatus.ACTIVE
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def update_activity(self):
        """更新活动时间"""
        self.last_active = datetime.now()
    
    def calculate_memory_size(self) -> int:
        """计算实例内存大小"""
        try:
            total = 0
            if self.agent_state:
                if hasattr(self.agent_state, 'get_data_size'):
                    total = self.agent_state.get_data_size()
                else:
                    total = sys.getsizeof(self.agent_state)
            return total
        except Exception as e:
            logger.debug(f"计算内存大小失败: {e}")
            return 0
    
    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            "instance_id": self.instance_id,
            "target": self.target,
            "created_at": self.created_at.isoformat(),
            "last_active": self.last_active.isoformat(),
            "memory_usage": self.memory_usage,
            "status": self.status.value,
            "metadata": self.metadata
        }


class MemoryMonitor:
    """内存使用监控器"""
    
    def __init__(self, warning_threshold_mb: int = 500, critical_threshold_mb: int = 1000):
        self._tracked_instances: Dict[str, int] = {}
        self._warning_threshold = warning_threshold_mb * 1024 * 1024
        self._critical_threshold = critical_threshold_mb * 1024 * 1024
        self._lock = threading.Lock()
        self._peak_usage = 0
    
    def track_instance(self, instance_id: str, size: int) -> None:
        """追踪实例内存"""
        with self._lock:
            self._tracked_instances[instance_id] = size
            total = sum(self._tracked_instances.values())
            if total > self._peak_usage:
                self._peak_usage = total
    
    def untrack_instance(self, instance_id: str) -> None:
        """取消追踪"""
        with self._lock:
            self._tracked_instances.pop(instance_id, None)
    
    def update_instance_size(self, instance_id: str, size: int) -> None:
        """更新实例大小"""
        with self._lock:
            if instance_id in self._tracked_instances:
                self._tracked_instances[instance_id] = size
    
    def get_total_tracked_size(self) -> int:
        """获取总追踪大小"""
        with self._lock:
            return sum(self._tracked_instances.values())
    
    def get_peak_usage(self) -> int:
        """获取峰值使用"""
        return self._peak_usage
    
    def check_threshold(self) -> Dict[str, Any]:
        """检查内存阈值"""
        total = self.get_total_tracked_size()
        return {
            "total_bytes": total,
            "total_mb": round(total / (1024 * 1024), 2),
            "warning": total >= self._warning_threshold,
            "critical": total >= self._critical_threshold,
            "instance_count": len(self._tracked_instances),
            "peak_mb": round(self._peak_usage / (1024 * 1024), 2)
        }
    
    def get_memory_report(self) -> Dict[str, Any]:
        """获取内存报告"""
        threshold_status = self.check_threshold()
        return {
            **threshold_status,
            "instances": dict(self._tracked_instances),
            "system_memory": self._get_system_memory()
        }
    
    def _get_system_memory(self) -> Dict[str, Any]:
        """获取系统内存信息"""
        try:
            import psutil
            mem = psutil.virtual_memory()
            return {
                "total_gb": round(mem.total / (1024**3), 2),
                "available_gb": round(mem.available / (1024**3), 2),
                "used_percent": mem.percent
            }
        except ImportError:
            return {"error": "psutil not installed"}


class ChatInstanceManager:
    """
    对话实例管理器
    
    单例模式，管理所有对话实例的生命周期。
    确保实例间数据隔离，防止内存泄漏。
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
            self._instances: Dict[str, ChatInstance] = {}
            self._memory_monitor = MemoryMonitor()
            self._max_instances = 100
            self._instance_timeout = 3600
            self._cleanup_interval = 300
            self._last_cleanup = time.time()
            self._initialized = True
            logger.info("ChatInstanceManager 初始化完成")
    
    def create_instance(self, target: str, config: Dict[str, Any] = None) -> str:
        """
        创建新的对话实例
        
        Args:
            target: 扫描目标
            config: 配置参数
            
        Returns:
            str: 实例ID
        """
        from TOSKill.AI.state import AgentState
        
        if len(self._instances) >= self._max_instances:
            self.cleanup_expired_instances()
            if len(self._instances) >= self._max_instances:
                oldest_id = min(self._instances.keys(), 
                               key=lambda x: self._instances[x].last_active)
                self.destroy_instance(oldest_id)
                logger.warning(f"达到最大实例数，清理最旧实例: {oldest_id}")
        
        instance_id = str(uuid4())
        task_id = config.get("task_id", instance_id) if config else instance_id
        
        agent_state = AgentState(
            target=target,
            task_id=task_id,
            chat_instance_id=instance_id
        )
        
        instance = ChatInstance(
            instance_id=instance_id,
            target=target,
            agent_state=agent_state,
            metadata=config or {}
        )
        
        instance.memory_usage = instance.calculate_memory_size()
        
        self._instances[instance_id] = instance
        self._memory_monitor.track_instance(instance_id, instance.memory_usage)
        
        self._check_cleanup()
        
        logger.info(f"创建对话实例: {instance_id} | 目标: {target} | 当前实例数: {len(self._instances)}")
        return instance_id
    
    def get_instance(self, instance_id: str) -> Optional[ChatInstance]:
        """获取对话实例"""
        instance = self._instances.get(instance_id)
        if instance:
            instance.update_activity()
        return instance
    
    def get_agent_state(self, instance_id: str) -> Optional[Any]:
        """获取实例的 AgentState"""
        instance = self.get_instance(instance_id)
        return instance.agent_state if instance else None
    
    def destroy_instance(self, instance_id: str) -> bool:
        """
        销毁对话实例
        
        Args:
            instance_id: 实例ID
            
        Returns:
            bool: 是否销毁成功
        """
        if instance_id not in self._instances:
            logger.warning(f"实例不存在: {instance_id}")
            return False
        
        instance = self._instances[instance_id]
        
        if instance.agent_state:
            self._cleanup_agent_state(instance.agent_state)
        
        self._memory_monitor.untrack_instance(instance_id)
        
        del self._instances[instance_id]
        
        gc.collect()
        
        logger.info(f"销毁对话实例: {instance_id} | 剩余实例数: {len(self._instances)}")
        return True
    
    def _cleanup_agent_state(self, agent_state: Any) -> None:
        """清理 AgentState 数据"""
        cleanup_count = 0
        
        if hasattr(agent_state, 'chat_history'):
            cleanup_count += len(agent_state.chat_history)
            agent_state.chat_history.clear()
        
        if hasattr(agent_state, 'execution_history'):
            cleanup_count += len(agent_state.execution_history)
            agent_state.execution_history.clear()
        
        if hasattr(agent_state, 'tool_results'):
            cleanup_count += len(agent_state.tool_results)
            agent_state.tool_results.clear()
        
        if hasattr(agent_state, 'vulnerabilities'):
            cleanup_count += len(agent_state.vulnerabilities)
            agent_state.vulnerabilities.clear()
        
        if hasattr(agent_state, 'errors'):
            cleanup_count += len(agent_state.errors)
            agent_state.errors.clear()
        
        if hasattr(agent_state, 'decision_history'):
            cleanup_count += len(agent_state.decision_history)
            agent_state.decision_history.clear()
        
        if hasattr(agent_state, '_websocket_callback'):
            agent_state._websocket_callback = None
        
        logger.debug(f"清理 AgentState 数据: {cleanup_count} 项")
    
    def pause_instance(self, instance_id: str) -> bool:
        """暂停实例"""
        instance = self._instances.get(instance_id)
        if instance:
            instance.status = InstanceStatus.PAUSED
            logger.info(f"暂停实例: {instance_id}")
            return True
        return False
    
    def resume_instance(self, instance_id: str) -> bool:
        """恢复实例"""
        instance = self._instances.get(instance_id)
        if instance and instance.status == InstanceStatus.PAUSED:
            instance.status = InstanceStatus.ACTIVE
            instance.update_activity()
            logger.info(f"恢复实例: {instance_id}")
            return True
        return False
    
    def complete_instance(self, instance_id: str) -> bool:
        """标记实例完成"""
        instance = self._instances.get(instance_id)
        if instance:
            instance.status = InstanceStatus.COMPLETED
            logger.info(f"实例完成: {instance_id}")
            return True
        return False
    
    def error_instance(self, instance_id: str, error_msg: str = "") -> bool:
        """标记实例错误"""
        instance = self._instances.get(instance_id)
        if instance:
            instance.status = InstanceStatus.ERROR
            instance.metadata["error"] = error_msg
            logger.error(f"实例错误: {instance_id} | {error_msg}")
            return True
        return False
    
    def get_memory_usage(self, instance_id: str) -> int:
        """获取实例内存使用"""
        instance = self._instances.get(instance_id)
        return instance.memory_usage if instance else 0
    
    def get_total_memory_usage(self) -> int:
        """获取总内存使用"""
        return self._memory_monitor.get_total_tracked_size()
    
    def get_memory_report(self) -> Dict[str, Any]:
        """获取内存报告"""
        return self._memory_monitor.get_memory_report()
    
    def check_memory_leak(self) -> List[str]:
        """检查内存泄漏"""
        leaked = []
        for instance_id, instance in self._instances.items():
            current_size = instance.calculate_memory_size()
            if current_size > instance.memory_usage * 2 and current_size > 1024 * 1024:
                leaked.append(instance_id)
                logger.warning(f"疑似内存泄漏: {instance_id}, 初始: {instance.memory_usage}, 当前: {current_size}")
        return leaked
    
    def _check_cleanup(self) -> None:
        """检查是否需要清理"""
        current_time = time.time()
        if current_time - self._last_cleanup > self._cleanup_interval:
            self.cleanup_expired_instances()
    
    def cleanup_expired_instances(self) -> int:
        """清理过期实例"""
        current_time = time.time()
        expired = []
        
        for instance_id, instance in self._instances.items():
            age = current_time - instance.last_active.timestamp()
            if age > self._instance_timeout or instance.status in [InstanceStatus.EXPIRED, InstanceStatus.COMPLETED]:
                expired.append(instance_id)
        
        for instance_id in expired:
            self.destroy_instance(instance_id)
        
        self._last_cleanup = current_time
        
        if expired:
            logger.info(f"清理过期实例: {len(expired)} 个")
        
        return len(expired)
    
    def cleanup_completed_instances(self) -> int:
        """清理已完成实例"""
        completed = [
            instance_id for instance_id, instance in self._instances.items()
            if instance.status == InstanceStatus.COMPLETED
        ]
        
        for instance_id in completed:
            self.destroy_instance(instance_id)
        
        return len(completed)
    
    def force_cleanup_all(self) -> int:
        """强制清理所有实例"""
        count = len(self._instances)
        instance_ids = list(self._instances.keys())
        for instance_id in instance_ids:
            self.destroy_instance(instance_id)
        logger.warning(f"强制清理所有实例: {count} 个")
        return count
    
    def get_instance_count(self) -> int:
        """获取实例数量"""
        return len(self._instances)
    
    def get_active_instance_count(self) -> int:
        """获取活跃实例数量"""
        return sum(1 for i in self._instances.values() if i.status == InstanceStatus.ACTIVE)
    
    def get_all_instances(self) -> List[Dict[str, Any]]:
        """获取所有实例信息"""
        return [instance.to_dict() for instance in self._instances.values()]
    
    def get_instances_by_status(self, status: InstanceStatus) -> List[ChatInstance]:
        """按状态获取实例"""
        return [instance for instance in self._instances.values() if instance.status == status]
    
    def update_instance_memory(self, instance_id: str) -> None:
        """更新实例内存使用"""
        instance = self._instances.get(instance_id)
        if instance:
            instance.memory_usage = instance.calculate_memory_size()
            self._memory_monitor.update_instance_size(instance_id, instance.memory_usage)


chat_instance_manager = ChatInstanceManager()


def get_instance_manager() -> ChatInstanceManager:
    """获取对话实例管理器"""
    return chat_instance_manager
