"""
数据库连接和会话管理 - 使用 Tortoise-ORM
适配 FastAPI 框架的异步资源管理规范
"""
import os
from pathlib import Path
from tortoise import Tortoise, connections
from backend.config import settings, PROJECT_ROOT
import logging

logger = logging.getLogger("backend.database")

_DB_INITIALIZED = False


def get_db_url() -> str:
    db_url = getattr(settings, "DATABASE_URL", "sqlite://./data/db.sqlite3")
    
    if db_url.startswith("sqlite://"):
        db_path_str = db_url[9:]
        if not db_path_str:
            db_path = PROJECT_ROOT / "data" / "db.sqlite3"
        else:
            db_path = Path(db_path_str) if os.path.isabs(db_path_str) else PROJECT_ROOT / db_path_str
        
        db_path = db_path.resolve()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        db_url = f"sqlite://{db_path}"
    
    return db_url


async def init_db() -> None:
    global _DB_INITIALIZED
    if _DB_INITIALIZED:
        logger.info("ℹ️  数据库已初始化，跳过重复执行")
        return
    
    db_url = get_db_url()
    logger.info(f"🔍 开始初始化Tortoise-ORM，数据库URL: {db_url}")
    
    if db_url.startswith("sqlite://"):
        db_path_str = db_url[9:]
        db_path = Path(db_path_str) if os.path.isabs(db_path_str) else PROJECT_ROOT / db_path_str
        db_path.parent.mkdir(parents=True, exist_ok=True)
        if not db_path.exists():
            db_path.touch()
    
    await Tortoise.init(
        db_url=db_url,
        modules={"models": ["backend.models"]},
        _create_db=False,
        use_tz=False
    )
    await Tortoise.generate_schemas(safe=True)
    
    _DB_INITIALIZED = True
    logger.info("✅ Tortoise-ORM初始化完成")


async def init_database() -> None:
    logger.info("=" * 50)
    logger.info("🔍 开始执行数据库完整初始化流程")
    
    await init_db()
    
    from backend.models import User
    
    if not await User.filter(username="admin").exists():
        await User.create(
            username="admin",
            password_hash="admin123",
            role="administrator",
            email="admin@example.com"
        )
        logger.warning("✅ 默认管理员账户已创建：用户名=admin，密码=admin123（请立即修改！）")
    else:
        logger.info("ℹ️  管理员账户已存在，跳过创建")
    
    logger.info("=" * 50)
    logger.info("✅ 数据库完整初始化完成")


async def reset_database() -> None:
    if getattr(settings, 'ENVIRONMENT', 'development') == "production":
        raise RuntimeError("❌ 生产环境禁止执行数据库重置操作！")
    
    await init_db()
    
    from backend.models import (
        User, Task, ScanResult, Vulnerability,
        POCScanResult, Report, SystemSettings
    )
    
    logger.warning("⚠️  开始重置数据库（所有数据将被删除！）")
    
    for model in [POCScanResult, Vulnerability, ScanResult, Report, Task, SystemSettings, User]:
        await model.all().delete()
        logger.info(f"✅ 已清空 {model.__name__} 表")
    
    logger.info("✅ 数据库重置完成")


async def close_db() -> None:
    global _DB_INITIALIZED
    if not _DB_INITIALIZED:
        return
    
    await Tortoise.close_connections()
    _DB_INITIALIZED = False
    logger.info("✅ 数据库连接已关闭")


async def health_check() -> bool:
    if not _DB_INITIALIZED:
        return False
    try:
        conn = connections.get("default")
        await conn.execute_query("SELECT 1")
        return True
    except Exception:
        return False


def register_db_events(app):
    @app.on_event("startup")
    async def startup_db():
        await init_database()
    
    @app.on_event("shutdown")
    async def shutdown_db():
        await close_db()
