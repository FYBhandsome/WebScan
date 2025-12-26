"""
数据库连接和会话管理 - 使用 Tortoise-ORM
"""
from tortoise import Tortoise, connections
from config import settings
import logging

logger = logging.getLogger(__name__)


async def init_db():
    """初始化数据库连接"""
    try:
        await Tortoise.init(
            db_url=settings.DATABASE_URL,
            modules={"models": ["models"]},
            _create_db=True
        )
        await Tortoise.generate_schemas()
        logger.info("数据库初始化成功")
    except Exception as e:
        logger.error(f"数据库初始化失败: {str(e)}")
        raise


async def close_db():
    """关闭数据库连接"""
    try:
        await Tortoise.close_connections()
        logger.info("数据库连接已关闭")
    except Exception as e:
        logger.error(f"关闭数据库连接失败: {str(e)}")
        raise


async def get_db_connection():
    """获取数据库连接"""
    conn = connections.get("default")
    return conn


async def health_check():
    """数据库健康检查"""
    try:
        conn = connections.get("default")
        await conn.execute_query("SELECT 1")
        return True
    except Exception as e:
        logger.error(f"数据库健康检查失败: {str(e)}")
        return False
