"""
TaskStatusStore —— 扫描任务状态存储（内存 + sqlite 持久化）

为前后端任务轮询机制提供统一状态读写：
- 内存 dict 缓存，读优先内存，保证轮询端点高性能
- sqlite 持久化双写，进程重启后可从 sqlite 恢复
- 线程安全（threading.Lock 保护 sqlite 写入）
- 容错：sqlite 操作失败只记日志，不影响内存读写
"""
import json
import logging
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from TOSKill.config import settings

logger = logging.getLogger(__name__)

# ── 状态枚举常量 ──────────────────────────────────────────
STATUS_QUEUED = "queued"
STATUS_PLANNING = "planning"
STATUS_WAITING_USER_INPUT = "waiting_user_input"
STATUS_WAITING_USER_CHOICE = "waiting_user_choice"
STATUS_WAITING_SCRIPT_UPLOAD = "waiting_script_upload"
STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_EXCEPTION = "exception"

VALID_STATUSES = frozenset({
    STATUS_QUEUED,
    STATUS_PLANNING,
    STATUS_WAITING_USER_INPUT,
    STATUS_WAITING_USER_CHOICE,
    STATUS_WAITING_SCRIPT_UPLOAD,
    STATUS_RUNNING,
    STATUS_COMPLETED,
    STATUS_EXCEPTION,
})

# ── 建表 SQL ─────────────────────────────────────────────
_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS task_statuses (
    task_id   TEXT PRIMARY KEY,
    status    TEXT NOT NULL,
    progress  INTEGER DEFAULT 0,
    stage     TEXT,
    payload   TEXT,
    updated_at TEXT NOT NULL
)
"""


def _utcnow_iso() -> str:
    """返回 UTC 时间 ISO 格式字符串"""
    return datetime.now(timezone.utc).isoformat()


class TaskStatusStore:
    """扫描任务状态存储（单例）

    内存 dict 缓存 + sqlite 持久化双写。
    通过 get_task_status_store() 工厂函数获取单例。
    """

    _instance: Optional["TaskStatusStore"] = None
    _init_flag: bool = False

    def __new__(cls) -> "TaskStatusStore":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if self._init_flag:
            return
        self._init_flag = True

        self._cache: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._db_path = str(settings.DATABASE_PATH)

        # 确保父目录存在
        settings.DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

        # 初始化建表
        try:
            with sqlite3.connect(self._db_path) as conn:
                conn.execute(_CREATE_TABLE_SQL)
                conn.commit()
            logger.info("TaskStatusStore initialized, db=%s", self._db_path)
        except Exception:
            logger.warning("TaskStatusStore sqlite init failed, db=%s", self._db_path, exc_info=True)

    # ── 公共方法 ────────────────────────────────────────────

    def set_status(
        self,
        task_id: str,
        status: str,
        progress: Optional[int] = None,
        stage: Optional[str] = None,
        **extra: Any,
    ) -> None:
        """更新任务状态（内存 + sqlite 双写）

        Args:
            task_id: 任务 ID
            status: 状态枚举值（queued / planning / ...）
            progress: 进度百分比 0-100，None 表示不更新
            stage: 当前阶段描述
            **extra: 额外数据，合并到 payload JSON。
                     支持: waiting_input, waiting_script, result, error 等
        """
        if status not in VALID_STATUSES:
            logger.warning("Invalid status '%s' for task %s, ignoring", status, task_id)
            return

        now = _utcnow_iso()

        # 从现有缓存读取旧值，用于合并
        existing = self._cache.get(task_id, {})
        payload: Dict[str, Any] = dict(existing.get("payload", {}))

        # 合并 extra 到 payload
        for key, value in extra.items():
            if value is not None:
                payload[key] = value
            else:
                payload.pop(key, None)  # None 值表示删除该 key

        record: Dict[str, Any] = {
            "task_id": task_id,
            "status": status,
            "progress": progress if progress is not None else existing.get("progress", 0),
            "stage": stage if stage is not None else existing.get("stage"),
            "payload": payload,
            "updated_at": now,
        }

        # 内存写
        self._cache[task_id] = record

        # sqlite 写
        self._persist_to_sqlite(task_id, record)

    def get_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """获取任务状态，优先内存，其次 sqlite

        Returns:
            状态字典，格式:
            {
                "task_id": str,
                "status": str,
                "progress": int,
                "stage": str | None,
                "updated_at": str,
                // payload 内的 key 被展开到顶层
                "waiting_input": dict | None,
                "waiting_script": dict | None,
                "result": Any | None,
                "error": str | None,
            }
            若任务不存在返回 None
        """
        # 优先内存
        record = self._cache.get(task_id)
        if record is not None:
            return self._flatten_record(record)

        # 内存没有则查 sqlite
        record = self._load_from_sqlite(task_id)
        if record is not None:
            # 回填内存
            self._cache[task_id] = record
            return self._flatten_record(record)

        return None

    def delete_status(self, task_id: str) -> None:
        """删除任务状态（内存 + sqlite）"""
        self._cache.pop(task_id, None)
        try:
            with self._lock:
                with sqlite3.connect(self._db_path) as conn:
                    conn.execute("DELETE FROM task_statuses WHERE task_id = ?", (task_id,))
                    conn.commit()
        except Exception:
            logger.warning("Failed to delete status from sqlite for task %s", task_id, exc_info=True)

    # ── 内部方法 ────────────────────────────────────────────

    def _persist_to_sqlite(self, task_id: str, record: Dict[str, Any]) -> None:
        """将状态持久化到 sqlite（UPSERT）"""
        try:
            payload_json = json.dumps(record["payload"], ensure_ascii=False)
            with self._lock:
                with sqlite3.connect(self._db_path) as conn:
                    conn.execute(
                        """INSERT INTO task_statuses (task_id, status, progress, stage, payload, updated_at)
                           VALUES (?, ?, ?, ?, ?, ?)
                           ON CONFLICT(task_id) DO UPDATE SET
                               status=excluded.status,
                               progress=excluded.progress,
                               stage=excluded.stage,
                               payload=excluded.payload,
                               updated_at=excluded.updated_at
                        """,
                        (
                            task_id,
                            record["status"],
                            record["progress"],
                            record["stage"],
                            payload_json,
                            record["updated_at"],
                        ),
                    )
                    conn.commit()
        except Exception:
            logger.warning("Failed to persist status to sqlite for task %s", task_id, exc_info=True)

    def _load_from_sqlite(self, task_id: str) -> Optional[Dict[str, Any]]:
        """从 sqlite 加载状态"""
        try:
            with sqlite3.connect(self._db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(
                    "SELECT task_id, status, progress, stage, payload, updated_at FROM task_statuses WHERE task_id = ?",
                    (task_id,),
                )
                row = cursor.fetchone()
                if row is None:
                    return None
                payload = json.loads(row["payload"]) if row["payload"] else {}
                return {
                    "task_id": row["task_id"],
                    "status": row["status"],
                    "progress": row["progress"],
                    "stage": row["stage"],
                    "payload": payload,
                    "updated_at": row["updated_at"],
                }
        except Exception:
            logger.warning("Failed to load status from sqlite for task %s", task_id, exc_info=True)
            return None

    @staticmethod
    def _flatten_record(record: Dict[str, Any]) -> Dict[str, Any]:
        """将内部 record 展开为 API 返回格式

        payload 中的 waiting_input / waiting_script / result / error
        被展开到顶层，其他 payload key 也展开。
        """
        result: Dict[str, Any] = {
            "task_id": record["task_id"],
            "status": record["status"],
            "progress": record["progress"],
            "stage": record.get("stage"),
            "updated_at": record["updated_at"],
        }
        # 展开 payload
        payload = record.get("payload", {})
        for key, value in payload.items():
            result[key] = value
        return result

    @classmethod
    def _reset_singleton(cls) -> None:
        """重置单例（仅供测试使用）"""
        cls._instance = None
        cls._init_flag = False


# ── 单例工厂 ─────────────────────────────────────────────

def get_task_status_store() -> TaskStatusStore:
    """获取 TaskStatusStore 单例"""
    return TaskStatusStore()
