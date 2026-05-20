"""
通知 API

提供通知管理功能,包括:
- 获取通知列表
- 创建通知
- 标记通知为已读
- 删除通知
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List, Any
from datetime import datetime
import logging
from backend.api.common import APIResponse
from backend.models import Notification, User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/notifications", tags=["通知管理"])


class NotificationResponse(BaseModel):
    """通知响应模型"""
    id: int = Field(..., description="通知ID")
    title: str = Field(..., description="通知标题")
    message: str = Field(..., description="通知内容")
    type: str = Field(..., description="通知类型")
    time: str = Field(..., description="通知时间")
    read: bool = Field(default=False, description="是否已读")


class CreateNotification(BaseModel):
    """创建通知模型"""
    title: str = Field(..., description="通知标题")
    message: str = Field(..., description="通知内容")
    type: str = Field(..., description="通知类型")


def format_time(dt: datetime) -> str:
    """格式化时间为相对时间"""
    if not dt:
        return "未知时间"
    
    # 确保dt是naive datetime
    if dt.tzinfo is not None:
        dt = dt.replace(tzinfo=None)
    
    now = datetime.now()
    delta = now - dt
    
    if delta.total_seconds() < 60:
        return "刚刚"
    elif delta.total_seconds() < 3600:
        minutes = int(delta.total_seconds() / 60)
        return f"{minutes}分钟前"
    elif delta.total_seconds() < 86400:
        hours = int(delta.total_seconds() / 3600)
        return f"{hours}小时前"
    elif delta.days < 7:
        days = delta.days
        return f"{days}天前"
    else:
        return dt.strftime("%Y-%m-%d")


def notification_to_dict(notification) -> dict:
    """将Notification模型转换为字典"""
    return {
        "id": notification.id,
        "title": notification.title,
        "message": notification.message,
        "type": notification.type,
        "time": format_time(notification.created_at),
        "read": notification.read
    }


@router.get("/", response_model=APIResponse, summary="获取通知列表")
async def get_notifications(skip: int = 0, limit: int = 50, unread_only: bool = False, user_id: int = 1):
    """
    获取通知列表
    
    Args:
        skip: 跳过的记录数
        limit: 返回的记录数
        unread_only: 是否只返回未读通知
        user_id: 用户ID,默认为1
        
    Returns:
        APIResponse: 包含通知列表的响应
        
    Examples:
        >>> GET /api/notifications/
        >>> {
        ...     "code": 200,
        ...     "message": "获取通知列表成功",
        ...     "data": {
        ...         "notifications": [...],
        ...         "total": 3,
        ...         "unread_count": 2
        ...     }
        ... }
    """
    try:
        query = Notification.filter(user_id=user_id)
        
        if unread_only:
            query = query.filter(read=False)
        
        total = await query.count()
        notifications = await query.order_by("-created_at").offset(skip).limit(limit)
        
        unread_count = await Notification.filter(user_id=user_id, read=False).count()
        
        notification_list = [notification_to_dict(n) for n in notifications]
        
        logger.info(f"获取通知列表成功: 共 {total} 条通知,{unread_count} 条未读")
        
        return APIResponse(
            code=200,
            message="获取通知列表成功",
            data={
                "notifications": notification_list,
                "total": total,
                "unread_count": unread_count
            }
        )
    except Exception as e:
        logger.error(f"获取通知列表失败: {e}")
        raise HTTPException(status_code=500, detail=f"获取通知列表失败: {str(e)}")


@router.get("/{notification_id}", response_model=APIResponse, summary="获取通知详情")
async def get_notification(notification_id: int, user_id: int = 1):
    """
    获取单个通知的详细信息
    
    Args:
        notification_id: 通知ID
        user_id: 用户ID,默认为1
        
    Returns:
        APIResponse: 包含通知详情的响应
        
    Raises:
        HTTPException: 当通知不存在时抛出404错误
        
    Examples:
        >>> GET /api/notifications/1
        >>> {
        ...     "code": 200,
        ...     "message": "获取通知详情成功",
        ...     "data": {...}
        ... }
    """
    try:
        notification = await Notification.get_or_none(id=notification_id, user_id=user_id)
        if not notification:
            raise HTTPException(status_code=404, detail="通知不存在")
        
        logger.info(f"获取通知详情成功: {notification_id}")
        
        return APIResponse(
            code=200,
            message="获取通知详情成功",
            data=notification_to_dict(notification)
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"获取通知详情失败: {e}")
        raise HTTPException(status_code=500, detail=f"获取通知详情失败: {str(e)}")


@router.post("/", response_model=APIResponse, summary="创建通知")
async def create_notification(notification_data: CreateNotification, user_id: int = 1):
    """
    创建新通知
    
    Args:
        notification_data: 通知数据
        user_id: 用户ID,默认为1
        
    Returns:
        APIResponse: 包含创建的通知的响应
        
    Examples:
        >>> POST /api/notifications/
        >>> {
        ...     "title": "新通知",
        ...     "message": "通知内容",
        ...     "type": "info"
        ... }
        >>> {
        ...     "code": 200,
        ...     "message": "创建通知成功",
        ...     "data": {...}
        ... }
    """
    try:
        user = await User.get_or_none(id=user_id)
        if not user:
            raise HTTPException(status_code=404, detail="用户不存在")
        
        new_notification = await Notification.create(
            user=user,
            title=notification_data.title,
            message=notification_data.message,
            type=notification_data.type,
            read=False
        )
        
        logger.info(f"创建通知成功: {notification_data.title}")
        
        return APIResponse(
            code=200,
            message="创建通知成功",
            data=notification_to_dict(new_notification)
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"创建通知失败: {e}")
        raise HTTPException(status_code=500, detail=f"创建通知失败: {str(e)}")


@router.put("/{notification_id}/read", response_model=APIResponse, summary="标记通知为已读")
async def mark_as_read(notification_id: int, user_id: int = 1):
    """
    标记通知为已读
    
    Args:
        notification_id: 通知ID
        user_id: 用户ID,默认为1
        
    Returns:
        APIResponse: 包含更新后通知的响应
        
    Raises:
        HTTPException: 当通知不存在时抛出404错误
        
    Examples:
        >>> PUT /api/notifications/1/read
        >>> {
        ...     "code": 200,
        ...     "message": "标记为已读成功",
        ...     "data": {...}
        ... }
    """
    try:
        notification = await Notification.get_or_none(id=notification_id, user_id=user_id)
        if not notification:
            raise HTTPException(status_code=404, detail="通知不存在")
        
        notification.read = True
        await notification.save()
        
        logger.info(f"标记通知为已读成功: {notification_id}")
        
        return APIResponse(
            code=200,
            message="标记为已读成功",
            data=notification_to_dict(notification)
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"标记通知为已读失败: {e}")
        raise HTTPException(status_code=500, detail=f"标记通知为已读失败: {str(e)}")


@router.put("/read-all", response_model=APIResponse, summary="标记所有通知为已读")
async def mark_all_as_read(user_id: int = 1):
    """
    标记所有通知为已读
    
    Args:
        user_id: 用户ID,默认为1
        
    Returns:
        APIResponse: 包含更新后通知列表的响应
        
    Examples:
        >>> PUT /api/notifications/read-all
        >>> {
        ...     "code": 200,
        ...     "message": "标记所有通知为已读成功",
        ...     "data": {...}
        ... }
    """
    try:
        updated_count = await Notification.filter(user_id=user_id, read=False).update(read=True)
        
        logger.info("标记所有通知为已读成功")
        
        return APIResponse(
            code=200,
            message="标记所有通知为已读成功",
            data={"updated_count": updated_count}
        )
    except Exception as e:
        logger.error(f"标记所有通知为已读失败: {e}")
        raise HTTPException(status_code=500, detail=f"标记所有通知为已读失败: {str(e)}")


@router.delete("/{notification_id}", response_model=APIResponse, summary="删除通知")
async def delete_notification(notification_id: int, user_id: int = 1):
    """
    删除通知
    
    Args:
        notification_id: 通知ID
        user_id: 用户ID,默认为1
        
    Returns:
        APIResponse: 删除成功的响应
        
    Raises:
        HTTPException: 当通知不存在时抛出404错误
        
    Examples:
        >>> DELETE /api/notifications/1
        >>> {
        ...     "code": 200,
        ...     "message": "删除通知成功",
        ...     "data": null
        ... }
    """
    try:
        notification = await Notification.get_or_none(id=notification_id, user_id=user_id)
        if not notification:
            raise HTTPException(status_code=404, detail="通知不存在")
        
        await notification.delete()
        
        logger.info(f"删除通知成功: {notification_id}")
        
        return APIResponse(
            code=200,
            message="删除通知成功",
            data=None
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"删除通知失败: {e}")
        raise HTTPException(status_code=500, detail=f"删除通知失败: {str(e)}")


@router.delete("/", response_model=APIResponse, summary="删除所有已读通知")
async def delete_read_notifications(user_id: int = 1):
    """
    删除所有已读通知
    
    Args:
        user_id: 用户ID,默认为1
        
    Returns:
        APIResponse: 删除成功的响应
        
    Examples:
        >>> DELETE /api/notifications/
        >>> {
        ...     "code": 200,
        ...     "message": "删除已读通知成功",
        ...     "data": {"deleted_count": 2}
        ... }
    """
    try:
        deleted_count = await Notification.filter(user_id=user_id, read=True).delete()
        
        logger.info(f"删除已读通知成功: 共删除 {deleted_count} 条通知")
        
        return APIResponse(
            code=200,
            message="删除已读通知成功",
            data={"deleted_count": deleted_count}
        )
    except Exception as e:
        logger.error(f"删除已读通知失败: {e}")
        raise HTTPException(status_code=500, detail=f"删除已读通知失败: {str(e)}")


@router.get("/count/unread", response_model=APIResponse, summary="获取未读通知数量")
async def get_unread_count(user_id: int = 1):
    """
    获取未读通知数量
    
    Args:
        user_id: 用户ID,默认为1
        
    Returns:
        APIResponse: 包含未读通知数量的响应
        
    Examples:
        >>> GET /api/notifications/count/unread
        >>> {
        ...     "code": 200,
        ...     "message": "获取未读通知数量成功",
        ...     "data": {"unread_count": 2}
        ... }
    """
    try:
        unread_count = await Notification.filter(user_id=user_id, read=False).count()
        
        logger.info(f"获取未读通知数量成功: {unread_count}")
        
        return APIResponse(
            code=200,
            message="获取未读通知数量成功",
            data={"unread_count": unread_count}
        )
    except Exception as e:
        logger.error(f"获取未读通知数量失败: {e}")
        raise HTTPException(status_code=500, detail=f"获取未读通知数量失败: {str(e)}")
