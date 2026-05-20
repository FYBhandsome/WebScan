"""
系统设置相关的 API 路由

提供系统配置管理、系统信息查询、统计数据等功能。
所有设置通过数据库持久化，支持动态配置管理。
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, field_validator
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import logging
import psutil
import platform
import json
from tortoise.functions import Count
from backend.models import Task, Vulnerability, SystemSettings, Report, SystemLog, AIChatInstance
from backend.api.common import APIResponse

logger = logging.getLogger(__name__)

router = APIRouter()


# ====================== 请求/响应模型 ======================

class SettingItem(BaseModel):
    """单个设置项模型"""
    key: str = Field(..., description="设置键名")
    value: Any = Field(..., description="设置值")
    value_type: str = Field("string", description="值类型：string, number, boolean, object, array")
    description: Optional[str] = Field(None, description="设置描述")


class SettingsUpdateRequest(BaseModel):
    """设置更新请求模型"""
    general: Optional[Dict[str, Any]] = Field(None, description="通用设置")
    scan: Optional[Dict[str, Any]] = Field(None, description="扫描设置")
    notification: Optional[Dict[str, Any]] = Field(None, description="通知设置")
    security: Optional[Dict[str, Any]] = Field(None, description="安全设置")
    
    @field_validator('*', mode='before')
    @classmethod
    def validate_settings(cls, v):
        """验证设置值"""
        if v is None:
            return v
        if not isinstance(v, dict):
            raise ValueError("设置值必须是字典类型")
        return v


class SettingUpdateItem(BaseModel):
    """单个设置项更新模型"""
    category: str = Field(..., description="设置分类")
    key: str = Field(..., description="设置键名")
    value: Any = Field(..., description="设置值")
    value_type: str = Field("string", description="值类型")


class ApiKeyCreate(BaseModel):
    """创建API密钥请求模型"""
    name: str = Field(..., description="API密钥名称")


class ApiKeyResponse(BaseModel):
    """API密钥响应模型"""
    id: int = Field(..., description="密钥ID")
    name: str = Field(..., description="密钥名称")
    key: str = Field(..., description="API密钥（仅创建时返回完整值）")
    masked: str = Field(..., description="掩码显示的密钥")
    created_at: str = Field(..., description="创建时间")


# ====================== 辅助函数 ======================

def get_default_settings() -> Dict[str, Any]:
    """获取默认设置配置"""
    return {
        "general": {
            "systemName": "WebScan AI",
            "language": "zh-CN",
            "timezone": "Asia/Shanghai",
            "autoUpdate": True,
            "theme": "dark"
        },
        "scan": {
            "defaultDepth": 2,
            "defaultConcurrency": 5,
            "requestTimeout": 30,
            "maxRetries": 3,
            "enableProxy": False
        },
        "notification": {
            "emailEnabled": False,
            "smtpServer": "",
            "smtpPort": 587,
            "smtpUser": "",
            "events": ["high-vulnerability", "scan-completed"]
        },
        "security": {
            "sessionTimeout": 120,
            "requireHttps": True,
            "maxLoginAttempts": 5,
            "enableTwoFactor": False
        }
    }


async def get_settings_from_db() -> Dict[str, Any]:
    """从数据库获取设置"""
    try:
        settings_records = await SystemSettings.all()
        settings_data = get_default_settings()
        
        for record in settings_records:
            if record.category not in settings_data:
                settings_data[record.category] = {}
            settings_data[record.category][record.key] = record.get_parsed_value()
        
        return settings_data
    except Exception as e:
        logger.error(f"从数据库获取设置失败: {str(e)}")
        return get_default_settings()


async def save_setting_to_db(category: str, key: str, value: Any, value_type: str = "string", description: str = None, is_public: bool = True):
    """保存单个设置到数据库"""
    try:
        value_str = json.dumps(value) if value_type in ["object", "array"] else str(value)
        
        setting = await SystemSettings.filter(category=category, key=key).first()
        if setting:
            setting.value = value_str
            setting.value_type = value_type
            if description:
                setting.description = description
            await setting.save()
        else:
            await SystemSettings.create(
                category=category,
                key=key,
                value=value_str,
                value_type=value_type,
                description=description,
                is_public=is_public
            )
    except Exception as e:
        logger.error(f"保存设置到数据库失败: {str(e)}")
        raise


def get_value_type(value: Any) -> str:
    """根据值类型返回类型字符串"""
    if isinstance(value, bool):
        return "boolean"
    elif isinstance(value, (int, float)):
        return "number"
    elif isinstance(value, dict):
        return "object"
    elif isinstance(value, list):
        return "array"
    else:
        return "string"


# ====================== 路由定义 ======================

@router.get("/", response_model=APIResponse)
async def get_settings():
    """
    获取系统设置
    
    从数据库读取系统配置，如果数据库中没有配置则返回默认值。
    设置分为以下分类：
    - general: 通用设置（系统名称、语言、时区等）
    - scan: 扫描设置（默认深度、并发数、超时等）
    - notification: 通知设置（邮件、事件通知等）
    - security: 安全设置（会话超时、HTTPS等）
    
    Returns:
        APIResponse: 包含所有系统设置的响应
    """
    try:
        settings_data = await get_settings_from_db()
        
        return APIResponse(
            code=200,
            message="获取成功",
            data=settings_data
        )
    except Exception as e:
        logger.error(f"获取系统设置失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/", response_model=APIResponse)
async def update_settings(request: SettingsUpdateRequest):
    """
    更新系统设置
    
    批量更新系统配置，支持部分更新（只更新提供的分类）。
    所有更新会持久化到数据库中。
    
    Args:
        request: 设置更新请求，包含需要更新的分类和值
    
    Returns:
        APIResponse: 更新结果
    """
    try:
        settings_data = await get_settings_from_db()
        
        if request.general:
            for key, value in request.general.items():
                await save_setting_to_db(
                    category="general",
                    key=key,
                    value=value,
                    value_type=get_value_type(value),
                    is_public=True
                )
            settings_data["general"].update(request.general)
        
        if request.scan:
            for key, value in request.scan.items():
                await save_setting_to_db(
                    category="scan",
                    key=key,
                    value=value,
                    value_type=get_value_type(value),
                    is_public=True
                )
            settings_data["scan"].update(request.scan)
        
        if request.notification:
            for key, value in request.notification.items():
                await save_setting_to_db(
                    category="notification",
                    key=key,
                    value=value,
                    value_type=get_value_type(value),
                    is_public=True
                )
            settings_data["notification"].update(request.notification)
        
        if request.security:
            for key, value in request.security.items():
                await save_setting_to_db(
                    category="security",
                    key=key,
                    value=value,
                    value_type=get_value_type(value),
                    is_public=False
                )
            settings_data["security"].update(request.security)
        
        logger.info(f"更新系统设置成功: {request.dict(exclude_none=True)}")
        
        return APIResponse(
            code=200,
            message="更新成功",
            data=settings_data
        )
    except Exception as e:
        logger.error(f"更新系统设置失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/item/{category}/{key}", response_model=APIResponse)
async def get_setting_item(category: str, key: str):
    """
    获取单个设置项
    
    Args:
        category: 设置分类
        key: 设置键名
    
    Returns:
        APIResponse: 单个设置项的值
    """
    try:
        setting = await SystemSettings.filter(category=category, key=key).first()
        if not setting:
            default_settings = get_default_settings()
            if category in default_settings and key in default_settings[category]:
                return APIResponse(
                    code=200,
                    message="获取成功",
                    data={
                        "category": category,
                        "key": key,
                        "value": default_settings[category][key],
                        "is_default": True
                    }
                )
            else:
                raise HTTPException(status_code=404, detail="设置项不存在")
        
        return APIResponse(
            code=200,
            message="获取成功",
            data={
                "category": setting.category,
                "key": setting.key,
                "value": setting.get_parsed_value(),
                "value_type": setting.value_type,
                "description": setting.description,
                "is_public": setting.is_public
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"获取设置项失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/item", response_model=APIResponse)
async def update_setting_item(request: SettingUpdateItem):
    """
    更新单个设置项
    
    Args:
        request: 设置项更新请求
    
    Returns:
        APIResponse: 更新结果
    """
    try:
        await save_setting_to_db(
            category=request.category,
            key=request.key,
            value=request.value,
            value_type=request.value_type,
            is_public=True
        )
        
        return APIResponse(
            code=200,
            message="更新成功",
            data={
                "category": request.category,
                "key": request.key,
                "value": request.value
            }
        )
    except Exception as e:
        logger.error(f"更新设置项失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/item/{category}/{key}", response_model=APIResponse)
async def delete_setting_item(category: str, key: str):
    """
    删除单个设置项（恢复为默认值）
    
    Args:
        category: 设置分类
        key: 设置键名
    
    Returns:
        APIResponse: 删除结果
    """
    try:
        deleted_count = await SystemSettings.filter(category=category, key=key).delete()
        
        if deleted_count == 0:
            raise HTTPException(status_code=404, detail="设置项不存在")
        
        return APIResponse(
            code=200,
            message="删除成功，已恢复为默认值",
            data={"category": category, "key": key}
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"删除设置项失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/system-info", response_model=APIResponse)
async def get_system_info():
    """
    获取系统信息
    
    返回服务器运行状态、资源使用情况等系统信息。
    
    Returns:
        APIResponse: 系统信息
    """
    try:
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.now() - boot_time
        
        days = uptime.days
        hours, remainder = divmod(uptime.seconds, 3600)
        minutes, _ = divmod(remainder, 60)
        
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        process_count = len(psutil.pids())
        
        system_info = {
            "version": "1.0.0",
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "python": platform.python_version()
            },
            "uptime": f"{days}天 {hours}小时 {minutes}分钟",
            "uptime_seconds": uptime.total_seconds(),
            "resources": {
                "cpu": {
                    "usage": f"{cpu_percent}%",
                    "cores": psutil.cpu_count(logical=True),
                    "physicalCores": psutil.cpu_count(logical=False)
                },
                "memory": {
                    "usage": f"{memory.percent}%",
                    "total": f"{memory.total / (1024**3):.2f}GB",
                    "used": f"{memory.used / (1024**3):.2f}GB",
                    "available": f"{memory.available / (1024**3):.2f}GB"
                },
                "disk": {
                    "usage": f"{disk.percent}%",
                    "total": f"{disk.total / (1024**3):.2f}GB",
                    "used": f"{disk.used / (1024**3):.2f}GB",
                    "free": f"{disk.free / (1024**3):.2f}GB"
                }
            },
            "processes": {
                "count": process_count
            },
            "network": {
                "connections": len(psutil.net_connections())
            }
        }
        
        return APIResponse(
            code=200,
            message="获取成功",
            data=system_info
        )
    except Exception as e:
        logger.error(f"获取系统信息失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/statistics", response_model=APIResponse)
async def get_statistics(period: int = 7):
    """
    获取统计信息
    
    返回扫描任务、漏洞发现、系统运行等统计数据。
    
    Args:
        period: 统计周期（天数），默认7天
    
    Returns:
        APIResponse: 统计数据
    """
    try:
        today = datetime.now().date()
        
        today_start = datetime.combine(today, datetime.min.time())
        week_ago = today_start - timedelta(days=period)
        
        today_scans = await Task.filter(
            created_at__gte=today_start
        ).count()
        
        high_risk_vulns = await Vulnerability.filter(
            severity__in=['Critical', 'High'],
            status='open'
        ).count()
        
        completed_scans = await Task.filter(status='completed').count()
        
        failed_scans = await Task.filter(status='failed').count()
        
        total_vulns = await Vulnerability.all().count()
        
        total_reports = await Report.all().count()
        
        total_chats = await AIChatInstance.all().count()
        
        trend_data = []
        for i in range(period - 1, -1, -1):
            date = today - timedelta(days=i)
            next_date = date + timedelta(days=1)
            
            daily_vulns = await Vulnerability.filter(
                created_at__gte=datetime.combine(date, datetime.min.time()),
                created_at__lt=datetime.combine(next_date, datetime.min.time())
            ).group_by('severity').annotate(count=Count('id')).values('severity', 'count')
            
            daily_scans_count = await Task.filter(
                created_at__gte=datetime.combine(date, datetime.min.time()),
                created_at__lt=datetime.combine(next_date, datetime.min.time())
            ).count()
            
            day_stats = {
                'date': date.strftime("%m/%d"),
                'scans': daily_scans_count,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
            
            for item in daily_vulns:
                sev = str(item['severity']).lower()
                if sev in day_stats:
                    day_stats[sev] += item['count']
            
            trend_data.append(day_stats)
        
        severity_stats = await Vulnerability.all().group_by('severity').annotate(
            count=Count('id')
        ).values('severity', 'count')
        
        severity_distribution = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        for item in severity_stats:
            sev = str(item['severity']).lower()
            if sev in severity_distribution:
                severity_distribution[sev] = item['count']
        
        task_status_stats = await Task.all().group_by('status').annotate(
            count=Count('id')
        ).values('status', 'count')
        
        task_status_distribution = {}
        for item in task_status_stats:
            task_status_distribution[item['status']] = item['count']
        
        recent_logs = await SystemLog.filter(
            created_at__gte=week_ago
        ).order_by('-created_at').limit(10).values('level', 'message', 'created_at')
        
        recent_logs_list = []
        for log in recent_logs:
            recent_logs_list.append({
                'level': log['level'],
                'message': log['message'][:100] + '...' if len(log['message']) > 100 else log['message'],
                'time': log['created_at'].strftime("%Y-%m-%d %H:%M:%S")
            })
        
        return APIResponse(
            code=200,
            message="获取成功",
            data={
                "today_scans": today_scans,
                "high_risk_vulns": high_risk_vulns,
                "completed_scans": completed_scans,
                "failed_scans": failed_scans,
                "total_vulns": total_vulns,
                "total_reports": total_reports,
                "total_chats": total_chats,
                "success_rate": round(completed_scans / (completed_scans + failed_scans) * 100, 2) if (completed_scans + failed_scans) > 0 else 0,
                "trend_data": trend_data,
                "severity_distribution": severity_distribution,
                "task_status_distribution": task_status_distribution,
                "recent_logs": recent_logs_list
            }
        )
    except Exception as e:
        logger.error(f"获取统计数据失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/categories", response_model=APIResponse)
async def get_setting_categories():
    """
    获取所有设置分类
    
    Returns:
        APIResponse: 设置分类列表
    """
    try:
        categories = await SystemSettings.all().distinct().values('category')
        category_list = [c['category'] for c in categories]
        
        default_categories = list(get_default_settings().keys())
        
        all_categories = sorted(list(set(category_list + default_categories)))
        
        return APIResponse(
            code=200,
            message="获取成功",
            data={
                "categories": all_categories,
                "default_categories": default_categories
            }
        )
    except Exception as e:
        logger.error(f"获取设置分类失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/category/{category}", response_model=APIResponse)
async def get_category_settings(category: str):
    """
    获取指定分类的所有设置
    
    Args:
        category: 设置分类名称
    
    Returns:
        APIResponse: 该分类下的所有设置
    """
    try:
        settings_records = await SystemSettings.filter(category=category).all()
        
        default_settings = get_default_settings()
        category_defaults = default_settings.get(category, {})
        
        settings_dict = {}
        for record in settings_records:
            settings_dict[record.key] = {
                "value": record.get_parsed_value(),
                "value_type": record.value_type,
                "description": record.description,
                "is_public": record.is_public
            }
        
        for key, value in category_defaults.items():
            if key not in settings_dict:
                settings_dict[key] = {
                    "value": value,
                    "value_type": get_value_type(value),
                    "description": None,
                    "is_public": True,
                    "is_default": True
                }
        
        return APIResponse(
            code=200,
            message="获取成功",
            data={
                "category": category,
                "settings": settings_dict
            }
        )
    except Exception as e:
        logger.error(f"获取分类设置失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/reset", response_model=APIResponse)
async def reset_settings():
    """
    重置所有设置为默认值
    
    Returns:
        APIResponse: 重置结果
    """
    try:
        await SystemSettings.all().delete()
        
        default_settings = get_default_settings()
        
        for category, settings in default_settings.items():
            for key, value in settings.items():
                await save_setting_to_db(
                    category=category,
                    key=key,
                    value=value,
                    value_type=get_value_type(value),
                    is_public=True
                )
        
        logger.info("重置所有设置为默认值")
        
        return APIResponse(
            code=200,
            message="重置成功",
            data=default_settings
        )
    except Exception as e:
        logger.error(f"重置设置失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/reset/{category}", response_model=APIResponse)
async def reset_category_settings(category: str):
    """
    重置指定分类的设置为默认值
    
    Args:
        category: 设置分类名称
    
    Returns:
        APIResponse: 重置结果
    """
    try:
        await SystemSettings.filter(category=category).delete()
        
        default_settings = get_default_settings()
        if category not in default_settings:
            raise HTTPException(status_code=404, detail="分类不存在")
        
        category_settings = default_settings[category]
        for key, value in category_settings.items():
            await save_setting_to_db(
                category=category,
                key=key,
                value=value,
                value_type=get_value_type(value),
                is_public=True
            )
        
        logger.info(f"重置分类 {category} 的设置为默认值")
        
        return APIResponse(
            code=200,
            message="重置成功",
            data={
                "category": category,
                "settings": category_settings
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"重置分类设置失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ====================== API密钥管理 ======================

def generate_api_key() -> str:
    """生成API密钥"""
    import secrets
    return f"wsa_{secrets.token_urlsafe(32)}"


def mask_api_key(key: str) -> str:
    """掩码显示API密钥"""
    if len(key) <= 12:
        return key[:4] + "****"
    return key[:4] + "****************************" + key[-8:]


@router.get("/api-keys", response_model=APIResponse)
async def get_api_keys():
    """
    获取API密钥列表
    
    Returns:
        APIResponse: API密钥列表
    """
    try:
        settings_records = await SystemSettings.filter(category="api_keys").all()
        
        api_keys = []
        for record in settings_records:
            try:
                key_data = json.loads(record.value)
                key_id = record.key.replace("key_", "")
                api_keys.append({
                    "id": key_id,
                    "name": key_data.get("name", record.key),
                    "masked": mask_api_key(key_data.get("key", "")),
                    "created_at": record.created_at.strftime("%Y-%m-%d %H:%M:%S")
                })
            except (json.JSONDecodeError, ValueError):
                continue
        
        return APIResponse(
            code=200,
            message="获取成功",
            data={"api_keys": api_keys}
        )
    except Exception as e:
        logger.error(f"获取API密钥失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api-keys", response_model=APIResponse)
async def create_api_key(request: ApiKeyCreate):
    """
    创建API密钥
    
    Args:
        request: 创建API密钥请求
    
    Returns:
        APIResponse: 创建的API密钥信息
    """
    try:
        key = generate_api_key()
        key_id = int(datetime.now().timestamp())
        
        key_data = {
            "name": request.name,
            "key": key,
            "created_at": datetime.now().isoformat()
        }
        
        await SystemSettings.create(
            category="api_keys",
            key=f"key_{key_id}",
            value=json.dumps(key_data),
            value_type="object",
            description=f"API密钥: {request.name}",
            is_public=False
        )
        
        logger.info(f"创建API密钥成功: {request.name}")
        
        return APIResponse(
            code=200,
            message="创建成功",
            data={
                "id": key_id,
                "name": request.name,
                "key": key,
                "masked": mask_api_key(key),
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        )
    except Exception as e:
        logger.error(f"创建API密钥失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/api-keys/{key_id}", response_model=APIResponse)
async def delete_api_key(key_id: int):
    """
    删除API密钥
    
    Args:
        key_id: API密钥ID
    
    Returns:
        APIResponse: 删除结果
    """
    try:
        deleted_count = await SystemSettings.filter(
            category="api_keys",
            key=f"key_{key_id}"
        ).delete()
        
        if deleted_count == 0:
            raise HTTPException(status_code=404, detail="API密钥不存在")
        
        logger.info(f"删除API密钥成功: {key_id}")
        
        return APIResponse(
            code=200,
            message="删除成功",
            data={"key_id": key_id}
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"删除API密钥失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/api-keys/{key_id}/regenerate", response_model=APIResponse)
async def regenerate_api_key(key_id: int):
    """
    重新生成API密钥
    
    Args:
        key_id: API密钥ID
    
    Returns:
        APIResponse: 新的API密钥信息
    """
    try:
        setting = await SystemSettings.filter(
            category="api_keys",
            key=f"key_{key_id}"
        ).first()
        
        if not setting:
            raise HTTPException(status_code=404, detail="API密钥不存在")
        
        key_data = json.loads(setting.value)
        new_key = generate_api_key()
        
        key_data["key"] = new_key
        key_data["regenerated_at"] = datetime.now().isoformat()
        
        setting.value = json.dumps(key_data)
        await setting.save()
        
        logger.info(f"重新生成API密钥成功: {key_id}")
        
        return APIResponse(
            code=200,
            message="重新生成成功",
            data={
                "id": key_id,
                "name": key_data.get("name"),
                "key": new_key,
                "masked": mask_api_key(new_key),
                "created_at": key_data.get("created_at"),
                "regenerated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"重新生成API密钥失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
