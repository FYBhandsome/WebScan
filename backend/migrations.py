"""
数据库迁移管理器 - 使用Tortoise-ORM管理数据库版本变更

支持平滑升级，自动记录迁移历史。
每次模型变更只需要添加新的迁移函数即可。
"""
import logging
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Callable
from dataclasses import dataclass, field

from tortoise import Tortoise
from backend.config import TORTOISE_ORM, PROJECT_ROOT

logger = logging.getLogger("backend.migrations")

MIGRATION_LOCK_FILE = PROJECT_ROOT / "data" / ".migration_lock"


@dataclass
class MigrationRecord:
    version: str
    name: str
    applied_at: str = ""
    description: str = ""


def get_db_url() -> str:
    return TORTOISE_ORM["connections"]["default"]


async def create_migration_table() -> None:
    conn = Tortoise.get_connection("default")
    await conn.execute_script("""
        CREATE TABLE IF NOT EXISTS _migrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            version VARCHAR(100) NOT NULL,
            name VARCHAR(255) NOT NULL,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            description TEXT,
            UNIQUE(version)
        )
    """)


async def get_applied_migrations() -> List[str]:
    conn = Tortoise.get_connection("default")
    rows = await conn.execute_query_dict("SELECT version FROM _migrations ORDER BY version")
    return [row["version"] for row in rows]


async def record_migration(version: str, name: str, description: str = "") -> None:
    conn = Tortoise.get_connection("default")
    await conn.execute_insert(
        "INSERT INTO _migrations (version, name, description) VALUES (?, ?, ?)",
        [version, name, description]
    )


async def apply_migration_v1() -> None:
    """V1: 初始数据库结构 - 使用 aerich 模型追踪表"""
    conn = Tortoise.get_connection("default")
    await conn.execute_script("""
        CREATE TABLE IF NOT EXISTS aerich (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            version VARCHAR(255) NOT NULL,
            app VARCHAR(100) NOT NULL,
            content JSON NOT NULL,
            UNIQUE(version, app)
        )
    """)
    logger.info("V1迁移完成: 创建 aerich 模型追踪表")


async def apply_migration_v2() -> None:
    """V2: 添加索引优化"""
    conn = Tortoise.get_connection("default")
    await conn.execute_script("""
        CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
        CREATE INDEX IF NOT EXISTS idx_tasks_created_at ON tasks(created_at);
        CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
        CREATE INDEX IF NOT EXISTS idx_vulnerabilities_task_id ON vulnerabilities(task_id);
        CREATE INDEX IF NOT EXISTS idx_reports_task_id ON reports(task_id);
        CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id);
        CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(read);
    """)
    logger.info("V2迁移完成: 添加性能索引")


MIGRATIONS: List[Dict[str, Any]] = [
    {
        "version": "1",
        "name": "init_aerich_tracking",
        "description": "创建 aerich 模型追踪表用于记录数据库版本",
        "apply": apply_migration_v1,
    },
    {
        "version": "2",
        "name": "add_performance_indexes",
        "description": "为核心表添加索引以提升查询性能",
        "apply": apply_migration_v2,
    },
]


async def run_migrations() -> List[str]:
    """
    执行所有未应用的迁移
    
    Returns:
        已应用的迁移版本列表
    """
    db_url = get_db_url()
    logger.info(f"开始数据库迁移检查: {db_url}")

    await Tortoise.init(
        db_url=db_url,
        modules={"models": ["backend.models"]},
        _create_db=False,
        use_tz=False
    )

    await Tortoise.generate_schemas(safe=True)

    await create_migration_table()

    applied = await get_applied_migrations()
    if applied:
        logger.info(f"已应用的迁移: {applied}")

    newly_applied = []

    for migration in MIGRATIONS:
        if migration["version"] in applied:
            continue

        logger.info(f"应用迁移 {migration['version']}: {migration['name']}")

        try:
            await migration["apply"]()
            await record_migration(
                migration["version"],
                migration["name"],
                migration.get("description", "")
            )
            newly_applied.append(migration["version"])
            logger.info(f"迁移 {migration['version']} 应用成功")
        except Exception as e:
            logger.error(f"迁移 {migration['version']} 失败: {e}")
            raise

    if newly_applied:
        logger.info(f"本轮新应用迁移: {newly_applied}")
    else:
        logger.info("数据库已是最新版本，无需迁移")

    await Tortoise.close_connections()
    return newly_applied


async def check_migration_status() -> Dict[str, Any]:
    """检查当前迁移状态"""
    db_url = get_db_url()
    await Tortoise.init(
        db_url=db_url,
        modules={"models": ["backend.models"]},
        _create_db=False,
        use_tz=False
    )

    try:
        applied = await get_applied_migrations()
    except Exception:
        applied = []

    await Tortoise.close_connections()

    return {
        "total_migrations": len(MIGRATIONS),
        "applied_count": len(applied),
        "pending_count": len(MIGRATIONS) - len(applied),
        "applied": applied,
        "pending": [m["version"] for m in MIGRATIONS if m["version"] not in applied],
        "is_up_to_date": len(applied) >= len(MIGRATIONS),
    }


async def ensure_migrations_applied() -> None:
    """确保所有迁移已应用（在应用启动时调用）"""
    try:
        applied = await run_migrations()
        if applied:
            logger.info(f"数据库迁移完成，新迁移: {applied}")
    except Exception as e:
        logger.error(f"数据库迁移检查失败: {e}")
        logger.warning("将继续启动，但数据库可能不是最新版本")


def generate_migration_changelog() -> str:
    """生成迁移变更日志"""
    lines = [
        "# 数据库迁移变更日志",
        "",
        f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## 迁移列表",
        "",
    ]

    for m in MIGRATIONS:
        lines.append(f"### V{m['version']}: {m['name']}")
        lines.append(f"- 描述: {m.get('description', 'N/A')}")
        lines.append("")

    return "\n".join(lines)


if __name__ == "__main__":
    import asyncio
    asyncio.run(run_migrations())