"""
通知服务层

提供通知创建和广播的统一封装，整合数据库持久化和WebSocket实时推送。

功能:
1. 创建通知并持久化到数据库
2. 通过WebSocket实时广播通知
3. 支持多种通知类型
4. 统一错误处理和日志记录
"""
import logging
from typing import Optional, Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class NotificationService:
    """
    通知服务类
    
    封装通知创建和广播逻辑，提供统一的通知管理接口。
    """
    
    NOTIFICATION_TYPES = {
        'scan-complete': '扫描完成',
        'scan-failed': '扫描失败',
        'high-vulnerability': '高危漏洞',
        'medium-vulnerability': '中危漏洞',
        'low-vulnerability': '低危漏洞',
        'system': '系统通知',
        'info': '信息通知',
        'warning': '警告通知',
        'error': '错误通知',
    }
    
    def __init__(self, websocket_manager=None):
        """
        初始化通知服务
        
        Args:
            websocket_manager: WebSocket连接管理器实例
        """
        self._websocket_manager = websocket_manager
    
    @property
    def websocket_manager(self):
        """
        延迟获取WebSocket管理器，避免循环导入
        """
        if self._websocket_manager is None:
            from backend.api.websocket import manager
            self._websocket_manager = manager
        return self._websocket_manager
    
    async def create_notification(
        self,
        user_id: int,
        title: str,
        message: str,
        notification_type: str = 'system',
        save_to_db: bool = True
    ) -> Optional[Dict[str, Any]]:
        """
        创建通知
        
        Args:
            user_id: 用户ID
            title: 通知标题
            message: 通知内容
            notification_type: 通知类型
            save_to_db: 是否保存到数据库
            
        Returns:
            创建的通知字典，失败返回None
        """
        try:
            from backend.models import Notification, User
            
            user = await User.get_or_none(id=user_id)
            if not user:
                logger.warning(f"[NotificationService] 用户不存在: user_id={user_id}")
                return None
            
            notification = await Notification.create(
                user=user,
                title=title,
                message=message,
                type=notification_type,
                read=False
            )
            
            logger.info(
                f"[NotificationService] 通知创建成功: "
                f"id={notification.id}, title={title}, type={notification_type}"
            )
            
            return {
                "id": notification.id,
                "title": notification.title,
                "message": notification.message,
                "type": notification.type,
                "created_at": notification.created_at.isoformat() if notification.created_at else None,
                "read": notification.read
            }
            
        except Exception as e:
            logger.error(f"[NotificationService] 创建通知失败: {e}", exc_info=True)
            return None
    
    async def broadcast_notification(self, notification_data: Dict[str, Any]) -> bool:
        """
        广播通知到WebSocket
        
        Args:
            notification_data: 通知数据字典
            
        Returns:
            是否广播成功
        """
        try:
            if not notification_data:
                logger.warning("[NotificationService] 通知数据为空，跳过广播")
                return False
            
            await self.websocket_manager.broadcast({
                "type": "new_notification",
                "payload": notification_data
            })
            
            logger.info(
                f"[NotificationService] 通知已广播: "
                f"id={notification_data.get('id')}, title={notification_data.get('title')}"
            )
            return True
            
        except Exception as e:
            logger.error(f"[NotificationService] 广播通知失败: {e}", exc_info=True)
            return False
    
    async def create_and_broadcast_notification(
        self,
        user_id: int,
        title: str,
        message: str,
        notification_type: str = 'system',
        broadcast: bool = True
    ) -> Optional[Dict[str, Any]]:
        """
        创建通知并广播
        
        整合通知创建和WebSocket广播，提供一站式通知服务。
        
        Args:
            user_id: 用户ID
            title: 通知标题
            message: 通知内容
            notification_type: 通知类型
            broadcast: 是否广播到WebSocket
            
        Returns:
            创建的通知字典，失败返回None
        """
        notification_data = await self.create_notification(
            user_id=user_id,
            title=title,
            message=message,
            notification_type=notification_type
        )
        
        if notification_data and broadcast:
            await self.broadcast_notification(notification_data)
        
        return notification_data
    
    async def create_task_notification(
        self,
        task_id: int,
        task_name: str,
        task_type: str,
        status: str,
        target: str = '',
        vuln_count: int = 0,
        error: str = '',
        user_id: int = 1
    ) -> Optional[Dict[str, Any]]:
        """
        创建任务相关通知
        
        根据任务状态自动生成合适的通知内容和类型。
        
        Args:
            task_id: 任务ID
            task_name: 任务名称
            task_type: 任务类型
            status: 任务状态 (completed/failed)
            target: 扫描目标
            vuln_count: 漏洞数量
            error: 错误信息
            user_id: 用户ID
            
        Returns:
            创建的通知字典，失败返回None
        """
        if status not in ['completed', 'failed']:
            logger.info(
                f"[NotificationService] 跳过创建通知: "
                f"status={status} 不是 completed 或 failed"
            )
            return None
        
        if status == 'completed':
            title = f"任务完成: {task_name}"
            if vuln_count > 0:
                message = f"扫描任务 {task_name} 已完成，目标: {target}，发现 {vuln_count} 个漏洞。"
                notification_type = 'scan-complete'
            else:
                message = f"扫描任务 {task_name} 已完成，目标: {target}，未发现漏洞。"
                notification_type = 'scan-complete'
        else:
            title = f"任务失败: {task_name}"
            message = f"扫描任务 {task_name} 执行失败，目标: {target}。错误: {error}"
            notification_type = 'scan-failed'
        
        return await self.create_and_broadcast_notification(
            user_id=user_id,
            title=title,
            message=message,
            notification_type=notification_type
        )
    
    async def create_vulnerability_notification(
        self,
        user_id: int,
        vuln_title: str,
        vuln_severity: str,
        target: str,
        task_name: str = ''
    ) -> Optional[Dict[str, Any]]:
        """
        创建漏洞发现通知
        
        Args:
            user_id: 用户ID
            vuln_title: 漏洞标题
            vuln_severity: 漏洞严重程度
            target: 目标地址
            task_name: 关联任务名称
            
        Returns:
            创建的通知字典，失败返回None
        """
        severity_map = {
            'critical': ('critical-vulnerability', '严重'),
            'high': ('high-vulnerability', '高危'),
            'medium': ('medium-vulnerability', '中危'),
            'low': ('low-vulnerability', '低危'),
            'info': ('info', '信息')
        }
        
        notif_type, severity_cn = severity_map.get(
            vuln_severity.lower(), 
            ('system', vuln_severity)
        )
        
        title = f"发现{severity_cn}漏洞: {vuln_title}"
        message = f"在目标 {target} 发现{severity_cn}漏洞: {vuln_title}"
        if task_name:
            message += f" (任务: {task_name})"
        
        return await self.create_and_broadcast_notification(
            user_id=user_id,
            title=title,
            message=message,
            notification_type=notif_type
        )
    
    async def create_system_notification(
        self,
        user_id: int,
        title: str,
        message: str,
        notification_type: str = 'system'
    ) -> Optional[Dict[str, Any]]:
        """
        创建系统通知
        
        Args:
            user_id: 用户ID
            title: 通知标题
            message: 通知内容
            notification_type: 通知类型
            
        Returns:
            创建的通知字典，失败返回None
        """
        return await self.create_and_broadcast_notification(
            user_id=user_id,
            title=title,
            message=message,
            notification_type=notification_type
        )


notification_service = NotificationService()
