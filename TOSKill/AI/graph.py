"""
TOSKill AI 工作流图定义

类比 demo.py，使用 LangGraph 构建三个子图：
1. 信息收集子图 (InfoCollectionGraph)
2. 漏洞扫描子图 (VulnScanGraph)
3. 报告生成子图 (ReportGraph)

使用 LangGraph interrupt 机制实现用户交互暂停/恢复。
"""
import logging
import asyncio
import os
import sys
import base64
import json
from typing import Dict, Optional, Callable, List, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, field
import threading
import sqlite3
from uuid import uuid4

from langgraph.graph import StateGraph, END
from langgraph.types import interrupt, Command
from langgraph.checkpoint.memory import MemorySaver
try:
    from langgraph.checkpoint.sqlite import SqliteSaver
except ImportError:  # pragma: no cover - optional until runtime dependencies are installed
    SqliteSaver = None
try:
    import aiosqlite
    from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
except ImportError:  # pragma: no cover - optional until runtime dependencies are installed
    aiosqlite = None
    AsyncSqliteSaver = None
from langchain_core.messages import SystemMessage, HumanMessage

from .state import ScanState, create_initial_state, append_chat, update_state
from .tools import get_tool_by_name, get_tool_sequence, is_auth_expired, get_auth_remaining_time
from .llm_client import get_llm, invoke_llm, is_llm_available
from .log_collector import log_collector
from .progress_events import scanner_progress_context
from ..config import settings
from ..RAG.retriever import get_scan_strategy
from ..utils.log_writer import log_info, log_warn, log_error, log_success, log_debug

logger = logging.getLogger(__name__)

AUTH_MAX_RETRY_COUNT = 3

TOOL_MAPPING_MATRIX = {
    "fast": ["xss_scan", "sqli_scan"],
    "deep": ["xss_scan", "sqli_scan", "cmdi_scan", "fileupload_scan", "weakpass_scan", "ssrf_scan", "csrf_scan", "lfi_scan"],
    "full": ["port_scan", "dir_brute", "subdomain_scan", "waf_detect_scan", "baseinfo_scan", "cdn_detect_scan", "cms_detect_scan", "infoleak_scan",
             "xss_scan", "sqli_scan", "cmdi_scan", "fileupload_scan", "weakpass_scan", "ssrf_scan", "csrf_scan", "lfi_scan"],
}

CONTEXT_TOOL_RULES = {
    "3306": ["sqli_scan", "weakpass_scan"],
    "1433": ["sqli_scan", "weakpass_scan"],
    "6379": ["weakpass_scan"],
    "27017": ["weakpass_scan"],
    "22": ["weakpass_scan"],
    "21": ["weakpass_scan"],
    "3389": ["weakpass_scan"],
    "80": ["xss_scan", "sqli_scan", "dir_brute"],
    "443": ["xss_scan", "sqli_scan", "dir_brute"],
    "8080": ["xss_scan", "sqli_scan", "dir_brute"],
    "8443": ["xss_scan", "sqli_scan", "dir_brute"],
}

FALLBACK_TOOL_MAP = {
    "sqli_scan": ["xss_scan", "cmdi_scan"],
    "xss_scan": ["csrf_scan"],
    "cmdi_scan": ["lfi_scan"],
    "fileupload_scan": ["dir_brute"],
    "weakpass_scan": ["baseinfo_scan"],
    "ssrf_scan": ["csrf_scan"],
    "csrf_scan": ["xss_scan"],
    "lfi_scan": ["cmdi_scan"],
}

DEFAULT_FALLBACK_TOOLS = ["xss_scan", "sqli_scan"]


def get_tools_by_context(port_results: dict) -> list:
    """
    根据端口扫描结果匹配推荐工具。

    Args:
        port_results: 端口扫描结果字典，如 {"open_ports": [80, 3306]} 或 {"ports": [80, 22]}

    Returns:
        list: 去重后的推荐工具名列表
    """
    try:
        if not port_results or not isinstance(port_results, dict):
            return []

        open_ports = port_results.get("open_ports") or port_results.get("ports") or []
        if not open_ports:
            return []

        tools = set()
        for port in open_ports:
            port_str = str(port)
            if port_str in CONTEXT_TOOL_RULES:
                tools.update(CONTEXT_TOOL_RULES[port_str])

        return sorted(tools)
    except Exception:
        return []


def get_fallback_tools(failed_tool: str) -> list:
    """
    根据失败的工具名返回备选工具列表。

    Args:
        failed_tool: 失败的工具名

    Returns:
        list: 备选工具名列表，若无匹配则返回默认兜底工具
    """
    if not failed_tool:
        return list(DEFAULT_FALLBACK_TOOLS)

    fallback = FALLBACK_TOOL_MAP.get(failed_tool)
    if fallback:
        return list(fallback)

    return list(DEFAULT_FALLBACK_TOOLS)


def encrypt_auth_info(auth_data: Dict[str, Any]) -> str:
    """
    加密认证信息（使用 base64 编码）
    
    Args:
        auth_data: 认证信息字典
        
    Returns:
        str: 加密后的字符串
    """
    try:
        json_str = json.dumps(auth_data, ensure_ascii=False)
        encoded = base64.b64encode(json_str.encode('utf-8')).decode('utf-8')
        return f"enc:{encoded}"
    except Exception as e:
        logger.error(f"加密认证信息失败: {e}")
        return ""


def decrypt_auth_info(encrypted_data: str) -> Dict[str, Any]:
    """
    解密认证信息
    
    Args:
        encrypted_data: 加密的认证信息字符串
        
    Returns:
        Dict: 解密后的认证信息字典
    """
    try:
        if not encrypted_data or not encrypted_data.startswith("enc:"):
            return {}
        
        encoded = encrypted_data[4:]
        json_str = base64.b64decode(encoded.encode('utf-8')).decode('utf-8')
        return json.loads(json_str)
    except Exception as e:
        logger.error(f"解密认证信息失败: {e}")
        return {}


def is_auth_failure_response(response: Any) -> bool:
    """
    检测响应是否为认证失败
    
    Args:
        response: 工具执行响应
        
    Returns:
        bool: 是否为认证失败响应
    """
    if isinstance(response, dict):
        status_code = response.get("status_code", 0)
        if status_code in [401, 403]:
            return True
        
        error = str(response.get("error") or "").lower()
        auth_errors = [
            "unauthorized", "forbidden", "authentication failed",
            "token expired", "session expired", "invalid token",
            "access denied", "未授权", "认证失败", "token过期"
        ]
        if any(err in error for err in auth_errors):
            return True
        
        if response.get("data"):
            data = response.get("data", {})
            if isinstance(data, dict):
                if data.get("status_code") in [401, 403]:
                    return True
                error_msg = str(data.get("error", "")).lower()
                if any(err in error_msg for err in auth_errors):
                    return True
    
    return False


class AuthRetryManager:
    """认证重试管理器"""
    
    def __init__(self, max_retries: int = AUTH_MAX_RETRY_COUNT):
        self._retry_counts: Dict[str, int] = {}
        self._max_retries = max_retries
        self._retry_history: Dict[str, List[Dict]] = {}
    
    def get_retry_count(self, session_id: str) -> int:
        """获取重试次数"""
        return self._retry_counts.get(session_id, 0)
    
    def increment_retry(self, session_id: str) -> int:
        """增加重试次数并返回新值"""
        if session_id not in self._retry_counts:
            self._retry_counts[session_id] = 0
        
        self._retry_counts[session_id] += 1
        
        if session_id not in self._retry_history:
            self._retry_history[session_id] = []
        
        self._retry_history[session_id].append({
            "timestamp": datetime.now().isoformat(),
            "retry_count": self._retry_counts[session_id]
        })
        
        return self._retry_counts[session_id]
    
    def can_retry(self, session_id: str) -> bool:
        """检查是否可以重试"""
        return self.get_retry_count(session_id) < self._max_retries
    
    def reset_retry(self, session_id: str):
        """重置重试计数"""
        self._retry_counts.pop(session_id, None)
        self._retry_history.pop(session_id, None)
    
    def get_retry_history(self, session_id: str) -> List[Dict]:
        """获取重试历史"""
        return self._retry_history.get(session_id, [])
    
    def should_trigger_reauth(self, session_id: str, response: Any) -> bool:
        """
        判断是否需要触发重新认证
        
        Args:
            session_id: 会话ID
            response: 工具响应
            
        Returns:
            bool: 是否需要重新认证
        """
        if not is_auth_failure_response(response):
            return False
        
        return self.can_retry(session_id)


auth_retry_manager = AuthRetryManager()


def _match_tool_via_llm(prompt: str, tools_list: list) -> str:
    """统一工具匹配函数，消除重复代码
    使用LLM选择最匹配的工具
    返回: 工具名称，如果匹配失败返回空字符串
    """
    from langchain_core.messages import SystemMessage, HumanMessage
    
    try:
        llm_with_tools = get_llm().bind_tools(tools_list)
        messages = [
            SystemMessage(content=prompt),
            HumanMessage(content=prompt)
        ]
        response_with_tc = llm_with_tools.invoke(messages, timeout=30)
        llm_tool_calls = getattr(response_with_tc, 'tool_calls', [])
        
        tool_name = ""
        if llm_tool_calls:
            for tool_call in llm_tool_calls:
                tool_name = tool_call.get("name", "") or tool_call.name
                if tool_name:
                    break
        return tool_name
    except Exception as e:
        logger.warning(f"LLM工具匹配失败: {e}，回退到原始工具名")
        return ""


def safe_llm_invoke(llm, prompt, timeout=None, system_prompt=None):
    if isinstance(prompt, list):
        messages = prompt
    else:
        messages = []
        if system_prompt:
            messages.append(SystemMessage(content=system_prompt))
        messages.append(HumanMessage(content=str(prompt)))
    try:
        if timeout:
            return llm.invoke(messages, timeout=timeout)
        return llm.invoke(messages)
    except Exception as e:
        logger.error(f"LLM call failed: {e}")
        raise


def summarize_tool_result(tool_name: str, result: Any) -> str:
    """不依赖外部模型的即时工具摘要。"""
    if not isinstance(result, dict):
        return f"{tool_name} 执行完成，原始结果已保留。"

    data = result.get("data") if isinstance(result.get("data"), dict) else {}
    vulnerabilities = data.get("vulnerabilities") if isinstance(data.get("vulnerabilities"), list) else []
    count = len(vulnerabilities)
    if not count:
        try:
            count = int(data.get("vulnerability_count") or 0)
        except (TypeError, ValueError):
            count = 0
    if not count:
        return f"{tool_name} 执行完成，未发现漏洞。"

    severity_counts: Dict[str, int] = {}
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            continue
        severity = str(vulnerability.get("severity") or "unknown").lower()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    severity_text = "、".join(f"{level.upper()} {amount}" for level, amount in severity_counts.items())
    suffix = f"（{severity_text}）" if severity_text else ""
    return f"{tool_name} 执行完成，发现 {count} 个漏洞{suffix}。"


_background_tasks = set()


async def _enhance_tool_result_analysis(
    session_id: str,
    tool_name: str,
    target: str,
    result: Dict[str, Any],
    ws_callback: Callable,
) -> None:
    try:
        data = result.get("data") if isinstance(result.get("data"), dict) else {}
        vulnerabilities = data.get("vulnerabilities") if isinstance(data.get("vulnerabilities"), list) else []
        compact_vulnerabilities = [
            {
                "title": item.get("title"),
                "type": item.get("vuln_type") or item.get("type"),
                "severity": item.get("severity"),
            }
            for item in vulnerabilities[:10]
            if isinstance(item, dict)
        ]
        prompt = (
            "请用1-2句话简要分析安全扫描结果，不要重复工具名称。"
            f"目标：{target}；漏洞数量：{len(vulnerabilities)}；"
            f"关键漏洞：{compact_vulnerabilities}"
        )
        response = await asyncio.wait_for(
            asyncio.to_thread(invoke_llm, [HumanMessage(content=prompt)], 30),
            timeout=35,
        )
        analysis = response.content if hasattr(response, "content") else str(response)
        if analysis.strip():
            await ws_callback({
                "type": "task_analysis_updated",
                "payload": {
                    "tool": tool_name,
                    "target": target,
                    "analysis": analysis.strip(),
                    "timestamp": datetime.now().isoformat(),
                },
            })
    except Exception as exc:
        logger.warning(f"[{session_id}] LLM结果增强失败，已使用本地摘要: {exc}")


def schedule_tool_result_analysis(
    session_id: str,
    tool_name: str,
    target: str,
    result: Dict[str, Any],
    ws_callback: Optional[Callable],
) -> None:
    if ws_callback is None:
        return
    task = asyncio.create_task(
        _enhance_tool_result_analysis(session_id, tool_name, target, result, ws_callback)
    )
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)


async def _enhance_tool_error_analysis(
    session_id: str,
    tool_name: str,
    target: str,
    error: str,
    ws_callback: Callable,
) -> None:
    try:
        prompt = f"请用1-2句话用中文分析安全扫描工具失败原因并给出建议。工具：{tool_name}；错误：{error[:500]}"
        response = await asyncio.wait_for(
            asyncio.to_thread(invoke_llm, [HumanMessage(content=prompt)], 30),
            timeout=35,
        )
        analysis = response.content if hasattr(response, "content") else str(response)
        if analysis.strip():
            await ws_callback({
                "type": "task_analysis_updated",
                "payload": {
                    "tool": tool_name,
                    "target": target,
                    "analysis": analysis.strip(),
                    "timestamp": datetime.now().isoformat(),
                },
            })
    except Exception as exc:
        logger.warning(f"[{session_id}] LLM错误增强失败，已保留原始错误: {exc}")


def schedule_tool_error_analysis(
    session_id: str,
    tool_name: str,
    target: str,
    error: str,
    ws_callback: Optional[Callable],
) -> None:
    if ws_callback is None:
        return
    task = asyncio.create_task(
        _enhance_tool_error_analysis(session_id, tool_name, target, error, ws_callback)
    )
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)


async def safe_llm_astream(llm, prompt, system_prompt=None):
    if isinstance(prompt, list):
        messages = prompt
    else:
        messages = []
        if system_prompt:
            messages.append(SystemMessage(content=system_prompt))
        messages.append(HumanMessage(content=str(prompt)))
    try:
        async for chunk in llm.astream(messages):
            yield chunk
    except Exception as e:
        logger.error(f"LLM stream call failed: {e}")
        raise


def with_node_retry(max_retries=3, base_delay=1.0):
    """
    节点重试装饰器 - 异步版本
    
    捕获节点执行异常后自动重试，使用指数退避策略。
    
    Args:
        max_retries: 最大重试次数，默认3次
        base_delay: 基础延迟秒数，指数退避基值，默认1秒
        
    Returns:
        装饰后的异步节点函数
    """
    import functools
    
    def decorator(node_func):
        @functools.wraps(node_func)
        async def wrapper(state, *args, **kwargs):
            last_exception = None
            session_id = state.get("websocket_session_id") or state.get("task_id", "unknown")
            
            for attempt in range(max_retries + 1):
                try:
                    return await node_func(state, *args, **kwargs)
                except Exception as e:
                    from langgraph.errors import GraphInterrupt
                    if isinstance(e, GraphInterrupt) or type(e).__name__ == 'GraphInterrupt':
                        raise e
                    last_exception = e
                    if attempt < max_retries:
                        delay = base_delay * (2 ** attempt)
                        logger.warning(
                            f"[{session_id}] 节点 {node_func.__name__} 执行异常 "
                            f"(尝试 {attempt + 1}/{max_retries + 1}): {e}，"
                            f"{delay:.1f}秒后重试"
                        )
                        
                        ws_callback = memory_store.get_websocket_callback(session_id)
                        if ws_callback:
                            try:
                                await ws_callback({
                                    "type": "node_retry",
                                    "payload": {
                                        "node": node_func.__name__,
                                        "attempt": attempt + 1,
                                        "max_retries": max_retries,
                                        "error": str(e),
                                        "next_retry_in": delay
                                    }
                                })
                            except Exception:
                                pass
                        
                        await asyncio.sleep(delay)
                    else:
                        logger.error(
                            f"[{session_id}] 节点 {node_func.__name__} 重试 {max_retries} 次后仍失败: {e}"
                        )
            
            errors = state.get("errors", []).copy()
            errors.append(f"{node_func.__name__}: {str(last_exception)}")
            return update_state(state, errors=errors, is_complete=True)
        
        return wrapper
    return decorator


@dataclass
class SessionMetadata:
    """会话元数据"""
    version: int = 1
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    last_activity: datetime = field(default_factory=datetime.now)


class MemoryStore:
    """记忆化存储 - 类比 demo.py 的 chat_history
    
    功能特性:
    - TTL过期清理（默认1小时）
    - 定时清理任务（每10分钟检查一次）
    - 聊天历史自动清理（最多保留100条）
    - 数据冗余检测与合并
    - 存储状态监控
    - 状态版本号管理
    """
    
    _instance = None
    
    def __init__(self):
        self._sessions: Dict[str, ScanState] = {}
        self._chat_histories: Dict[str, List[Dict]] = {}
        self._pending_interactions: Dict[str, Dict] = {}
        self._websocket_callbacks: Dict[str, Callable] = {}
        self._session_timestamps: Dict[str, datetime] = {}
        self._session_metadata: Dict[str, SessionMetadata] = {}
        self._session_ttl: int = 3600
        self._cleanup_interval: int = 600
        self._max_chat_history: int = 100
        self._cleanup_task: Optional[asyncio.Task] = None
        self._cleanup_thread: Optional[threading.Thread] = None
        self._stop_cleanup: bool = False
        self._lock: threading.Lock = threading.Lock()
        self._db_path = None
        self._db_connections: Dict[int, sqlite3.Connection] = {}
        self._init_sqlite()
    
    def _get_db_conn(self) -> Optional[sqlite3.Connection]:
        """获取当前线程的数据库连接（线程安全）"""
        if not self._db_path:
            return None
        
        thread_id = threading.get_ident()
        
        if thread_id not in self._db_connections:
            try:
                conn = sqlite3.connect(self._db_path, check_same_thread=False)
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
                conn.execute("PRAGMA foreign_keys=ON")
                conn.execute("PRAGMA busy_timeout=30000")
                self._db_connections[thread_id] = conn
            except Exception as e:
                logger.error(f"创建数据库连接失败: {e}")
                return None
        
        return self._db_connections[thread_id]
    
    def _close_all_db_connections(self):
        """关闭所有数据库连接"""
        for thread_id, conn in list(self._db_connections.items()):
            try:
                conn.close()
            except Exception:
                pass
        self._db_connections.clear()
        logger.info("所有数据库连接已关闭")
    
    def _init_sqlite(self):
        try:
            from ..config import settings
            db_path = getattr(settings, 'DB_PATH', 'data/toskill.db')
            db_dir = os.path.dirname(db_path)
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)
            
            self._db_path = db_path
            
            conn = self._get_db_conn()
            if not conn:
                raise Exception("无法创建数据库连接")
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    state_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    version INTEGER DEFAULT 1
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS chat_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS decision_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    decision_json TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS pending_interactions (
                    session_id TEXT PRIMARY KEY,
                    interaction_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_pauses (
                    pause_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    interaction_id TEXT NOT NULL,
                    state_version INTEGER NOT NULL,
                    source_node TEXT NOT NULL,
                    next_task TEXT,
                    status TEXT NOT NULL,
                    pause_json TEXT NOT NULL,
                    paused_at TEXT NOT NULL,
                    resumed_at TEXT,
                    expires_at TEXT,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS script_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tool_name TEXT NOT NULL,
                    script_content TEXT NOT NULL,
                    description TEXT,
                    source TEXT DEFAULT 'upload',
                    created_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS user_preferences (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_chat_session ON chat_history(session_id, timestamp)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_decision_session ON decision_history(session_id, timestamp)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scan_pause_session ON scan_pauses(session_id, status)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_script_history ON script_history(tool_name, created_at)
            """)
            conn.commit()
            
            self._load_from_sqlite()
            
            logger.info(f"SQLite 持久化已初始化: {db_path}")
        except Exception as e:
            logger.warning(f"SQLite 初始化失败（将使用纯内存模式）: {e}")
            self._db_path = None
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
            cls._instance._start_cleanup_task()
        return cls._instance
    
    def _start_cleanup_task(self):
        """启动定时清理任务"""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                self._cleanup_task = asyncio.create_task(self._periodic_cleanup())
                logger.info("定时清理任务已启动（异步模式）")
            else:
                raise RuntimeError("事件循环未运行")
        except RuntimeError:
            self._stop_cleanup = False
            self._cleanup_thread = threading.Thread(target=self._periodic_cleanup_sync, daemon=True)
            self._cleanup_thread.start()
            logger.info("定时清理任务已启动（线程模式）")
    
    async def _periodic_cleanup(self):
        """异步定时清理任务"""
        while not self._stop_cleanup:
            try:
                await asyncio.sleep(self._cleanup_interval)
                self._cleanup_expired_sessions()
                self._cleanup_chat_histories()
            except asyncio.CancelledError:
                logger.info("定时清理任务被取消")
                break
            except Exception as e:
                logger.error(f"定时清理任务异常: {e}")
    
    def _periodic_cleanup_sync(self):
        """同步定时清理任务（用于线程模式）"""
        import time
        while not self._stop_cleanup:
            try:
                time.sleep(self._cleanup_interval)
                self._cleanup_expired_sessions()
                self._cleanup_chat_histories()
            except Exception as e:
                logger.error(f"定时清理任务异常: {e}")
    
    def stop_cleanup_task(self):
        """停止定时清理任务并关闭数据库连接"""
        self._stop_cleanup = True
        if self._cleanup_task:
            self._cleanup_task.cancel()
        self._close_all_db_connections()
        logger.info("定时清理任务已停止")
    
    def save_session(self, session_id: str, state: ScanState) -> int:
        """保存会话状态（带时间戳和版本号）
        
        Returns:
            新的版本号，失败返回0
        """
        with self._lock:
            now = datetime.now()
            
            if session_id in self._session_metadata:
                metadata = self._session_metadata[session_id]
                metadata.version += 1
                metadata.updated_at = now
                metadata.last_activity = now
            else:
                metadata = SessionMetadata(
                    version=1,
                    created_at=now,
                    updated_at=now,
                    last_activity=now
                )
                self._session_metadata[session_id] = metadata
            
            state = dict(state)
            state["state_version"] = metadata.version
            
            try:
                state_json = json.dumps(state, ensure_ascii=False, default=str)
            except Exception as e:
                logger.error(f"JSON序列化失败: {e}")
                return 0
            
            conn = self._get_db_conn()
            if conn:
                try:
                    with conn:
                        conn.execute(
                            """INSERT INTO sessions (session_id, state_json, created_at, updated_at, version)
                               VALUES (?, ?, ?, ?, ?)
                               ON CONFLICT(session_id) DO UPDATE SET
                                   state_json = excluded.state_json,
                                   updated_at = excluded.updated_at,
                                   version = excluded.version""",
                            (session_id, state_json, metadata.created_at.isoformat(), 
                             metadata.updated_at.isoformat(), metadata.version)
                        )
                except Exception as e:
                    logger.error(f"SQLite 保存会话失败: {e}")
                    return 0
            
            self._sessions[session_id] = state
            self._session_timestamps[session_id] = now
            
            logger.debug(f"保存会话状态: {session_id}, 版本: {metadata.version}")
            return metadata.version
    
    def get_session(self, session_id: str) -> Optional[ScanState]:
        """获取会话状态"""
        return self._sessions.get(session_id)
    
    def get_session_version(self, session_id: str) -> int:
        """获取会话版本号"""
        metadata = self._session_metadata.get(session_id)
        return metadata.version if metadata else 0

    def save_scan_pause(self, session_id: str, pause_info: Dict[str, Any]) -> bool:
        """持久化一次扫描暂停快照。"""
        pause_id = pause_info.get("pause_id")
        if not pause_id:
            return False

        conn = self._get_db_conn()
        if not conn:
            return False

        try:
            with conn:
                conn.execute(
                    """INSERT INTO scan_pauses
                       (pause_id, session_id, interaction_id, state_version, source_node,
                        next_task, status, pause_json, paused_at, resumed_at, expires_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(pause_id) DO UPDATE SET
                           status = excluded.status,
                           pause_json = excluded.pause_json,
                           resumed_at = excluded.resumed_at,
                           expires_at = excluded.expires_at""",
                    (
                        pause_id,
                        session_id,
                        pause_info.get("interaction_id", ""),
                        int(pause_info.get("state_version", 0) or 0),
                        pause_info.get("source_node", "user_interact"),
                        pause_info.get("next_task", ""),
                        pause_info.get("status", "paused"),
                        json.dumps(pause_info, ensure_ascii=False, default=str),
                        pause_info.get("paused_at", datetime.now().isoformat()),
                        pause_info.get("resumed_at"),
                        pause_info.get("expires_at"),
                    ),
                )
            return True
        except Exception as e:
            logger.error(f"保存扫描暂停记录失败: {e}")
            return False

    def get_scan_pause(self, pause_id: str) -> Optional[Dict[str, Any]]:
        """读取扫描暂停记录。"""
        conn = self._get_db_conn()
        if not conn or not pause_id:
            return None
        try:
            row = conn.execute(
                "SELECT pause_json FROM scan_pauses WHERE pause_id = ?",
                (pause_id,),
            ).fetchone()
            return json.loads(row[0]) if row else None
        except Exception as e:
            logger.error(f"读取扫描暂停记录失败: {e}")
            return None

    def update_scan_pause(self, pause_id: str, **updates) -> Optional[Dict[str, Any]]:
        """更新扫描暂停记录并返回最新快照。"""
        current = self.get_scan_pause(pause_id)
        if not current:
            return None
        current = {**current, **updates}
        return current if self.save_scan_pause(current.get("session_id", ""), current) else None
    
    def update_session(self, session_id: str, **kwargs) -> Optional[ScanState]:
        """更新会话状态的部分字段（带版本控制）"""
        with self._lock:
            state = self.get_session(session_id)
            if state is not None:
                now = datetime.now()
                state = {**state, **kwargs}
                metadata = self._session_metadata.get(session_id)
                if metadata:
                    metadata.version += 1
                    metadata.updated_at = now
                    metadata.last_activity = now
                else:
                    metadata = SessionMetadata(created_at=now, updated_at=now, last_activity=now)
                    self._session_metadata[session_id] = metadata

                state["state_version"] = metadata.version

                try:
                    state_json = json.dumps(state, ensure_ascii=False, default=str)
                except Exception as e:
                    logger.error(f"JSON序列化失败: {e}")
                    return None

                conn = self._get_db_conn()
                if conn:
                    try:
                        with conn:
                            conn.execute(
                                """INSERT INTO sessions
                                   (session_id, state_json, created_at, updated_at, version)
                                   VALUES (?, ?, ?, ?, ?)
                                   ON CONFLICT(session_id) DO UPDATE SET
                                       state_json = excluded.state_json,
                                       updated_at = excluded.updated_at,
                                       version = excluded.version""",
                                (session_id, state_json, metadata.created_at.isoformat(),
                                 metadata.updated_at.isoformat(), metadata.version)
                            )
                    except Exception as e:
                        logger.error(f"SQLite 更新会话失败: {e}")
                        return None

                self._sessions[session_id] = state
                self._session_timestamps[session_id] = now
                logger.debug(f"更新会话状态: {session_id}, 版本: {metadata.version}")
            return state
    
    def delete_session(self, session_id: str):
        """删除会话"""
        with self._lock:
            conn = self._get_db_conn()
            if conn:
                try:
                    with conn:
                        conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
                except Exception as e:
                    logger.error(f"SQLite 删除会话失败: {e}")
            
            self._sessions.pop(session_id, None)
            self._chat_histories.pop(session_id, None)
            self._pending_interactions.pop(session_id, None)
            self._websocket_callbacks.pop(session_id, None)
            self._session_timestamps.pop(session_id, None)
            self._session_metadata.pop(session_id, None)
            
            logger.info(f"删除会话: {session_id}")
    
    def _cleanup_expired_sessions(self):
        """清理过期会话（带日志记录）"""
        now = datetime.now()
        expired_count = 0
        
        with self._lock:
            pause_ttl = int(getattr(settings, "SCAN_PAUSE_TTL", 86400))
            expired = []
            for sid, ts in self._session_timestamps.items():
                state = self._sessions.get(sid, {})
                ttl = pause_ttl if state.get("scan_status") == "paused_for_chat" else self._session_ttl
                if (now - ts).total_seconds() > ttl:
                    expired.append(sid)
            
            for sid in expired:
                expired_count += 1
                logger.info(f"[清理] 过期会话: {sid}, 空闲时间: {(now - self._session_timestamps[sid]).total_seconds():.0f}秒")
                self._sessions.pop(sid, None)
                self._chat_histories.pop(sid, None)
                self._pending_interactions.pop(sid, None)
                self._websocket_callbacks.pop(sid, None)
                self._session_timestamps.pop(sid, None)
                self._session_metadata.pop(sid, None)

            conn = self._get_db_conn()
            if conn and expired:
                try:
                    with conn:
                        conn.executemany("DELETE FROM sessions WHERE session_id = ?", [(sid,) for sid in expired])
                except Exception as e:
                    logger.error(f"SQLite 清理过期会话失败: {e}")
        
        if expired_count > 0:
            logger.info(f"[清理] 本次清理过期会话数: {expired_count}, 剩余活跃会话: {len(self._sessions)}")
    
    def _cleanup_chat_histories(self):
        """清理超出限制的聊天历史"""
        cleaned_count = 0
        
        with self._lock:
            for session_id, history in self._chat_histories.items():
                if len(history) > self._max_chat_history:
                    removed = len(history) - self._max_chat_history
                    self._chat_histories[session_id] = history[-self._max_chat_history:]
                    cleaned_count += removed
                    logger.debug(f"[清理] 会话 {session_id} 聊天历史清理: 移除 {removed} 条旧记录")
        
        if cleaned_count > 0:
            logger.info(f"[清理] 本次清理聊天记录数: {cleaned_count}")
    
    def _cleanup_expired_data_on_startup(self, max_age_hours: float = 2.0):
        """启动时清理超过指定时间的数据
        
        Args:
            max_age_hours: 最大保留时间（小时），默认2小时
        """
        conn = self._get_db_conn()
        if not conn:
            return
        
        try:
            now = datetime.now()
            cutoff_time = now - timedelta(hours=max_age_hours)
            
            cursor = conn.execute(
                "SELECT session_id, updated_at FROM sessions"
            )
            expired_sessions = []
            
            for row in cursor.fetchall():
                session_id, updated_at_str = row
                try:
                    updated_at = datetime.fromisoformat(updated_at_str)
                    if updated_at < cutoff_time:
                        expired_sessions.append(session_id)
                except Exception:
                    expired_sessions.append(session_id)
            
            if expired_sessions:
                with conn:
                    for sid in expired_sessions:
                        conn.execute("DELETE FROM sessions WHERE session_id = ?", (sid,))
                logger.info(f"[启动清理] 清理了 {len(expired_sessions)} 个超过 {max_age_hours} 小时的过期会话")
            else:
                logger.info(f"[启动清理] 没有发现超过 {max_age_hours} 小时的过期会话")
                
        except Exception as e:
            logger.error(f"启动时清理过期数据失败: {e}")
    
    def _load_from_sqlite(self):
        conn = self._get_db_conn()
        if not conn:
            return
        
        try:
            startup_retention = max(2.0, float(getattr(settings, "SCAN_PAUSE_TTL", 86400)) / 3600.0)
            self._cleanup_expired_data_on_startup(max_age_hours=startup_retention)
            
            cursor = conn.execute(
                "SELECT session_id, state_json, created_at, updated_at, version FROM sessions"
            )
            loaded_count = 0
            now = datetime.now()
            
            for row in cursor.fetchall():
                session_id, state_json, created_at_str, updated_at_str, version = row
                try:
                    state = json.loads(state_json)
                    
                    if session_id in self._session_metadata:
                        continue
                    
                    try:
                        updated_at = datetime.fromisoformat(updated_at_str)
                    except Exception:
                        updated_at = now

                    try:
                        created_at = datetime.fromisoformat(created_at_str)
                    except Exception:
                        created_at = updated_at
                    
                    self._sessions[session_id] = state
                    self._session_timestamps[session_id] = updated_at
                    self._session_metadata[session_id] = SessionMetadata(
                        version=version or 1,
                        created_at=created_at,
                        updated_at=updated_at,
                        last_activity=updated_at
                    )
                    loaded_count += 1
                except Exception as e:
                    logger.warning(f"恢复会话 {session_id} 失败: {e}")
            
            chat_cursor = conn.execute(
                "SELECT session_id, role, content, timestamp FROM chat_history ORDER BY timestamp"
            )
            for row in chat_cursor.fetchall():
                sid, role, content, ts = row
                if sid not in self._chat_histories:
                    self._chat_histories[sid] = []
                self._chat_histories[sid].append({
                    "role": role, "content": content, "timestamp": ts
                })

            pending_cursor = conn.execute(
                "SELECT session_id, interaction_json FROM pending_interactions"
            )
            for sid, interaction_json in pending_cursor.fetchall():
                if sid in self._sessions:
                    try:
                        self._pending_interactions[sid] = json.loads(interaction_json)
                    except Exception as e:
                        logger.warning(f"恢复待交互状态 {sid} 失败: {e}")
            
            if loaded_count > 0:
                logger.info(f"从 SQLite 恢复了 {loaded_count} 个会话")
        except Exception as e:
            logger.error(f"从 SQLite 加载会话失败: {e}")
    
    def append_chat(self, session_id: str, role: str, content: str):
        """追加聊天历史（自动清理超出限制的记录）"""
        with self._lock:
            if session_id not in self._chat_histories:
                self._chat_histories[session_id] = []
            
            timestamp = datetime.now().isoformat()
            
            conn = self._get_db_conn()
            if conn:
                try:
                    with conn:
                        conn.execute(
                            "INSERT INTO chat_history (session_id, role, content, timestamp) VALUES (?, ?, ?, ?)",
                            (session_id, role, content, timestamp)
                        )
                except Exception as e:
                    logger.error(f"SQLite 保存聊天历史失败: {e}")
            
            self._chat_histories[session_id].append({
                "role": role,
                "content": content,
                "timestamp": timestamp
            })
            
            if len(self._chat_histories[session_id]) > self._max_chat_history:
                removed = len(self._chat_histories[session_id]) - self._max_chat_history
                self._chat_histories[session_id] = self._chat_histories[session_id][-self._max_chat_history:]
                logger.debug(f"聊天历史自动清理: 移除 {removed} 条旧记录")
    
    def get_chat_history(self, session_id: str) -> List[Dict]:
        """获取聊天历史"""
        return self._chat_histories.get(session_id, [])
    
    def save_script_history(self, tool_name: str, script_content: str, description: str = "", source: str = "upload"):
        """保存脚本历史"""
        conn = self._get_db_conn()
        if not conn:
            return False
        
        try:
            with conn:
                conn.execute(
                    """INSERT INTO script_history (tool_name, script_content, description, source, created_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (tool_name, script_content, description, source, datetime.now().isoformat())
                )
            logger.info(f"保存脚本历史: {tool_name}")
            return True
        except Exception as e:
            logger.error(f"保存脚本历史失败: {e}")
            return False
    
    def get_script_history(self, limit: int = 50) -> List[Dict]:
        """获取脚本历史"""
        conn = self._get_db_conn()
        if not conn:
            return []
        
        try:
            cursor = conn.execute(
                """SELECT tool_name, script_content, description, source, created_at 
                   FROM script_history ORDER BY created_at DESC LIMIT ?""",
                (limit,)
            )
            return [
                {
                    "tool_name": row[0],
                    "script_content": row[1],
                    "description": row[2],
                    "source": row[3],
                    "created_at": row[4]
                }
                for row in cursor.fetchall()
            ]
        except Exception as e:
            logger.error(f"获取脚本历史失败: {e}")
            return []
    
    def get_script_by_name(self, tool_name: str) -> Optional[Dict]:
        """根据工具名获取脚本"""
        conn = self._get_db_conn()
        if not conn:
            return None
        
        try:
            cursor = conn.execute(
                """SELECT tool_name, script_content, description, source, created_at 
                   FROM script_history WHERE tool_name = ? ORDER BY created_at DESC LIMIT 1""",
                (tool_name,)
            )
            row = cursor.fetchone()
            if row:
                return {
                    "tool_name": row[0],
                    "script_content": row[1],
                    "description": row[2],
                    "source": row[3],
                    "created_at": row[4]
                }
            return None
        except Exception as e:
            logger.error(f"获取脚本失败: {e}")
            return None
    
    def delete_script_history(self, tool_name: str):
        """删除脚本历史"""
        conn = self._get_db_conn()
        if not conn:
            return False
        
        try:
            with conn:
                conn.execute("DELETE FROM script_history WHERE tool_name = ?", (tool_name,))
            logger.info(f"删除脚本历史: {tool_name}")
            return True
        except Exception as e:
            logger.error(f"删除脚本历史失败: {e}")
            return False
    
    def get_preference(self, key: str, default: str = None) -> Optional[str]:
        """获取用户偏好"""
        conn = self._get_db_conn()
        if not conn:
            return default
        
        try:
            cursor = conn.execute("SELECT value FROM user_preferences WHERE key = ?", (key,))
            row = cursor.fetchone()
            return row[0] if row else default
        except Exception as e:
            logger.error(f"获取用户偏好失败: {e}")
            return default
    
    def set_preference(self, key: str, value: str):
        """设置用户偏好"""
        conn = self._get_db_conn()
        if not conn:
            return False
        
        try:
            with conn:
                conn.execute(
                    """INSERT OR REPLACE INTO user_preferences (key, value, updated_at)
                       VALUES (?, ?, ?)""",
                    (key, value, datetime.now().isoformat())
                )
            return True
        except Exception as e:
            logger.error(f"设置用户偏好失败: {e}")
            return False
    
    def sync_chat_history_from_state(self, session_id: str, state: ScanState) -> ScanState:
        """从状态同步聊天历史到 memory_store（带冗余检测与合并）
        
        去重策略：
        1. 先按内容（role + content）去重，相同内容只保留最新时间戳的版本
        2. 合并后按时间戳排序
        """
        with self._lock:
            state_history = state.get("chat_history", [])
            store_history = self._chat_histories.get(session_id, [])
            
            content_map = {}
            duplicate_count = 0
            
            for msg in state_history + store_history:
                content_key = f"{msg.get('role', '')}:{msg.get('content', '')}"
                timestamp = msg.get("timestamp", "")
                
                if content_key in content_map:
                    duplicate_count += 1
                    existing_ts = content_map[content_key].get("timestamp", "")
                    if timestamp > existing_ts:
                        content_map[content_key] = msg
                else:
                    content_map[content_key] = msg
            
            merged = sorted(content_map.values(), key=lambda x: x.get("timestamp", ""))
            
            if len(merged) > self._max_chat_history:
                merged = merged[-self._max_chat_history:]
            
            self._chat_histories[session_id] = merged
            
            if duplicate_count > 0:
                logger.info(f"[同步] 会话 {session_id} 去重: 移除 {duplicate_count} 条重复消息")
            
            return {**state, "chat_history": merged}
    
    def set_pending_interaction(self, session_id: str, interaction_data: Dict):
        """设置待处理的交互请求"""
        self._pending_interactions[session_id] = interaction_data
        conn = self._get_db_conn()
        if conn:
            try:
                with conn:
                    conn.execute(
                        """INSERT OR REPLACE INTO pending_interactions
                           (session_id, interaction_json, updated_at) VALUES (?, ?, ?)""",
                        (session_id, json.dumps(interaction_data, ensure_ascii=False, default=str),
                         datetime.now().isoformat())
                    )
            except Exception as e:
                logger.error(f"SQLite 保存待交互状态失败: {e}")
    
    def get_pending_interaction(self, session_id: str) -> Optional[Dict]:
        """获取待处理的交互请求"""
        return self._pending_interactions.get(session_id)
    
    def clear_pending_interaction(self, session_id: str):
        """清除待处理的交互请求"""
        self._pending_interactions.pop(session_id, None)
        conn = self._get_db_conn()
        if conn:
            try:
                with conn:
                    conn.execute("DELETE FROM pending_interactions WHERE session_id = ?", (session_id,))
            except Exception as e:
                logger.error(f"SQLite 清除待交互状态失败: {e}")
    
    def set_websocket_callback(self, session_id: str, callback: Callable):
        """设置 WebSocket 回调函数"""
        self._websocket_callbacks[session_id] = callback
        self._session_timestamps[session_id] = datetime.now()
        
        if session_id in self._session_metadata:
            self._session_metadata[session_id].last_activity = datetime.now()
    
    def get_websocket_callback(self, session_id: str) -> Optional[Callable]:
        """获取 WebSocket 回调函数"""
        return self._websocket_callbacks.get(session_id)
    
    def is_websocket_active(self, session_id: str) -> bool:
        """检查WebSocket连接是否活跃"""
        return session_id in self._websocket_callbacks and self._websocket_callbacks[session_id] is not None
    
    def clear_websocket_callback(self, session_id: str):
        """清除 WebSocket 回调"""
        self._websocket_callbacks.pop(session_id, None)
    
    def has_pending_interaction(self, session_id: str) -> bool:
        """检查是否有待处理的交互"""
        return session_id in self._pending_interactions
    
    def get_active_session_count(self) -> int:
        """获取活跃会话数量"""
        return len(self._sessions)
    
    def get_session_info(self, session_id: str) -> Dict[str, Any]:
        """获取会话信息"""
        state = self.get_session(session_id)
        if not state:
            return {"exists": False}
        
        metadata = self._session_metadata.get(session_id)
        
        return {
            "exists": True,
            "target": state.get("target", ""),
            "mode": state.get("mode", ""),
            "completed_tasks": len(state.get("completed_tasks", [])),
            "chat_history_count": len(state.get("chat_history", [])),
            "last_activity": self._session_timestamps.get(session_id, "").isoformat() if session_id in self._session_timestamps else None,
            "has_websocket": self.is_websocket_active(session_id),
            "version": metadata.version if metadata else 0,
            "created_at": metadata.created_at.isoformat() if metadata else None,
            "updated_at": metadata.updated_at.isoformat() if metadata else None
        }
    
    def get_storage_stats(self) -> Dict[str, Any]:
        """获取存储统计信息
        
        Returns:
            包含会话数量、聊天记录数量、内存使用估算等信息的字典
        """
        total_chat_messages = sum(len(history) for history in self._chat_histories.values())
        
        session_size = sys.getsizeof(self._sessions) + sum(
            sys.getsizeof(k) + sys.getsizeof(v) 
            for k, v in self._sessions.items()
        )
        
        chat_size = sys.getsizeof(self._chat_histories) + sum(
            sys.getsizeof(k) + sys.getsizeof(v) + sum(
                sys.getsizeof(msg) for msg in v
            ) for k, v in self._chat_histories.items()
        )
        
        metadata_size = sys.getsizeof(self._session_metadata) + sum(
            sys.getsizeof(k) + sys.getsizeof(v) 
            for k, v in self._session_metadata.items()
        )
        
        pending_size = sys.getsizeof(self._pending_interactions)
        ws_size = sys.getsizeof(self._websocket_callbacks)
        timestamps_size = sys.getsizeof(self._session_timestamps)
        
        total_memory = session_size + chat_size + metadata_size + pending_size + ws_size + timestamps_size
        
        oldest_session = None
        newest_session = None
        if self._session_timestamps:
            oldest_ts = min(self._session_timestamps.values())
            newest_ts = max(self._session_timestamps.values())
            for sid, ts in self._session_timestamps.items():
                if ts == oldest_ts:
                    oldest_session = sid
                if ts == newest_ts:
                    newest_session = sid
        
        return {
            "sessions": {
                "total_count": len(self._sessions),
                "active_websocket_count": len([c for c in self._websocket_callbacks.values() if c is not None]),
                "pending_interaction_count": len(self._pending_interactions),
                "oldest_session": oldest_session,
                "newest_session": newest_session
            },
            "chat_history": {
                "total_messages": total_chat_messages,
                "sessions_with_history": len(self._chat_histories),
                "max_history_limit": self._max_chat_history,
                "average_messages_per_session": round(total_chat_messages / max(len(self._chat_histories), 1), 2)
            },
            "memory": {
                "estimated_total_bytes": total_memory,
                "estimated_total_mb": round(total_memory / (1024 * 1024), 2),
                "sessions_bytes": session_size,
                "chat_history_bytes": chat_size,
                "metadata_bytes": metadata_size
            },
            "config": {
                "session_ttl_seconds": self._session_ttl,
                "cleanup_interval_seconds": self._cleanup_interval,
                "max_chat_history_per_session": self._max_chat_history
            },
            "cleanup_status": {
                "cleanup_task_running": self._cleanup_task is not None and not self._cleanup_task.done() if self._cleanup_task else False,
                "cleanup_thread_running": self._cleanup_thread is not None and self._cleanup_thread.is_alive() if self._cleanup_thread else False,
                "stop_requested": self._stop_cleanup
            }
        }
    
    def set_config(self, session_ttl: int = None, cleanup_interval: int = None, max_chat_history: int = None):
        """动态配置存储参数
        
        Args:
            session_ttl: 会话过期时间（秒）
            cleanup_interval: 清理检查间隔（秒）
            max_chat_history: 每个会话最大聊天记录数
        """
        if session_ttl is not None:
            self._session_ttl = session_ttl
            logger.info(f"会话TTL已更新: {session_ttl}秒")
        
        if cleanup_interval is not None:
            self._cleanup_interval = cleanup_interval
            logger.info(f"清理检查间隔已更新: {cleanup_interval}秒")
        
        if max_chat_history is not None:
            self._max_chat_history = max_chat_history
            logger.info(f"最大聊天记录数已更新: {max_chat_history}")


memory_store = MemoryStore.get_instance()


async def safe_ws_send(session_id: str, message: Dict) -> bool:
    """安全发送WebSocket消息"""
    ws_callback = memory_store.get_websocket_callback(session_id)
    if ws_callback is None:
        logger.warning(f"[{session_id}] WebSocket回调不存在")
        return False
    
    try:
        await ws_callback(message)
        return True
    except Exception as e:
        logger.error(f"[{session_id}] WebSocket发送失败: {e}")
        memory_store.clear_websocket_callback(session_id)
        return False


async def send_thinking_token(session_id: str, token: str):
    """推送单个思考 token 到前端"""
    await safe_ws_send(session_id, {
        "type": "ai_thinking",
        "payload": {"token": token}
    })


def format_tool_result(tool_name: str, target: str, result: Any) -> str:
    """格式化工具结果 - 生成友好易读的反馈"""
    
    if "port" in tool_name or "nmap" in tool_name:
        ports = []
        if isinstance(result, dict) and "ports" in result:
            ports = result["ports"]
        elif isinstance(result, dict) and "open_ports" in result:
            ports = result["open_ports"]
        return f"【端口扫描结果】\n目标: {target}\n开放端口: {', '.join(map(str, ports)) if ports else '无'}"
    
    elif "sqli" in tool_name or "sqlmap" in tool_name:
        vulnerable = isinstance(result, dict) and result.get("vulnerable", False)
        if vulnerable:
            inj_point = result.get("injection_point", result.get("parameter", "未知"))
            return f"【SQL注入检测结果】\n目标: {target}\n⚠️ 检测到SQL注入漏洞（高危）\n注入点: {inj_point}"
        return f"【SQL注入检测结果】\n目标: {target}\n✅ 未检测到SQL注入漏洞"
    
    elif "dir" in tool_name or "directory" in tool_name:
        dirs = []
        if isinstance(result, dict) and "directories" in result:
            dirs = result["directories"]
        elif isinstance(result, dict) and "found_paths" in result:
            dirs = result["found_paths"]
        return f"【目录扫描结果】\n目标: {target}\n发现目录: {len(dirs)} 个\n敏感目录: {', '.join(dirs[:5]) if dirs else '无'}"
    
    elif "xss" in tool_name:
        vulnerable = isinstance(result, dict) and result.get("vulnerable", False)
        if vulnerable:
            xss_type = result.get("xss_type", result.get("type", "未知"))
            return f"【XSS检测结果】\n目标: {target}\n⚠️ 检测到XSS漏洞\n类型: {xss_type}"
        return f"【XSS检测结果】\n目标: {target}\n✅ 未检测到XSS漏洞"
    
    elif "subdomain" in tool_name:
        subs = []
        if isinstance(result, dict) and "subdomains" in result:
            subs = result["subdomains"]
        elif isinstance(result, list):
            subs = result
        return f"【子域名扫描结果】\n目标: {target}\n发现子域名: {len(subs)} 个\n{', '.join(subs[:5]) if subs else '无'}"
    
    elif "waf" in tool_name:
        waf = "未知"
        if isinstance(result, dict) and "waf" in result:
            waf = result["waf"]
        elif isinstance(result, dict) and "detected" in result:
            waf = result.get("name", "已检测")
        return f"【WAF检测结果】\n目标: {target}\nWAF: {waf}"
    
    elif "cms" in tool_name:
        cms = "未知"
        if isinstance(result, dict) and "cms" in result:
            cms = result["cms"]
        return f"【CMS检测结果】\n目标: {target}\nCMS: {cms}"
    
    else:
        if isinstance(result, dict):
            status = "⚠️ 发现问题" if result.get("vulnerable") or result.get("found") else "✅ 正常"
            return f"【{tool_name} 结果】\n目标: {target}\n状态: {status}"
        return f"【{tool_name} 结果】\n目标: {target}\n结果: {str(result)[:200]}"


async def intent_recognition(state: ScanState) -> ScanState:
    """意图识别节点 - 使用LLM Function Calling分析用户输入意图"""
    import re
    from .tools import INTENT_TOOLS, map_tool_call_to_intent
    from langchain_core.messages import SystemMessage, HumanMessage
    
    user_input = state.get("user_input", "")
    session_id = state.get("websocket_session_id") or state.get("task_id")
    ws_callback = memory_store.get_websocket_callback(session_id)
    
    logger.info(f"[{session_id}] 意图识别: {user_input[:50]}...")
    
    llm = get_llm().bind_tools(INTENT_TOOLS)
    messages = [
        SystemMessage(content="你是一个安全助手意图分析器。根据用户输入，选择合适的工具函数来标识用户意图。"),
        HumanMessage(content=user_input)
    ]
    response = llm.invoke(messages)
    
    tool_calls = getattr(response, 'tool_calls', [])
    
    intent_type = "chat"
    direct_tool = ""
    target = state.get("target", "")
    confidence = 0.9
    
    if tool_calls:
        tc = tool_calls[0]
        intent_type = map_tool_call_to_intent(tc['name'])
        args = tc.get('args', {})
        
        if intent_type == "scan":
            target = args.get("target", target)
        elif intent_type == "tool":
            direct_tool = args.get("tool_name", "")
            target = args.get("target", target)
    
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+|[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}|[\w\-]+\.[\w\-]+\.[\w\-]+'
    if not target:
        url_match = re.search(url_pattern, user_input)
        if url_match:
            target = url_match.group()
    
    if ws_callback:
        try:
            await ws_callback({
                "type": "intent_recognized",
                "payload": {
                    "intent_type": intent_type,
                    "tool_name": direct_tool,
                    "target": target,
                    "confidence": confidence
                }
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    logger.info(f"🎯 意图识别结果: {intent_type}, 工具: {direct_tool}, 目标: {target}, 置信度: {confidence}")
    
    return update_state(state, 
        intent_type=intent_type,
        direct_tool=direct_tool,
        direct_target=target,
        intent_confidence=confidence,
        target=target or state.get("target", ""),
        user_input=user_input,
        intent_context={
            "original_input": user_input,
            "extracted_target": target,
            "extracted_tool": direct_tool,
            "recognition_time": datetime.now().isoformat()
        },
        last_activity_time=datetime.now().isoformat()
    )


async def intent_validation(state: ScanState) -> ScanState:
    """意图校验节点 - 校验意图合法性，缺失数据时请求用户输入"""
    from .validators import InputValidator, DataInputRequest
    
    intent_type = state.get("intent_type", "chat")
    direct_tool = state.get("direct_tool", "")
    target = state.get("target", "")
    session_id = state.get("websocket_session_id") or state.get("task_id")
    ws_callback = memory_store.get_websocket_callback(session_id)
    
    validation_result = {"valid": True, "error": "", "needs_input": False, "input_field": "", "tool_exists": True}
    
    if intent_type == "tool":
        if not direct_tool:
            validation_result = {"valid": False, "error": "请提供工具名称", "needs_input": True, "input_field": "tool_name", "tool_exists": False}
        elif not target:
            validation_result = {"valid": False, "error": "请提供扫描目标地址", "needs_input": True, "input_field": "target", "tool_exists": True}
        else:
            tool = get_tool_by_name(direct_tool)
            if not tool:
                validation_result = {"valid": False, "error": f"工具 '{direct_tool}' 不存在，请检查工具名称或使用其他工具", "needs_input": False, "tool_exists": False}
    
    elif intent_type == "scan":
        if not target:
            validation_result = {"valid": False, "error": "请提供扫描目标地址", "needs_input": True, "input_field": "target", "tool_exists": True}
    
    if validation_result["needs_input"] and ws_callback:
        input_request = DataInputRequest.build_request(
            validation_result["input_field"],
            validation_result["error"]
        )
        try:
            await ws_callback(input_request)
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    elif not validation_result["valid"]:
        logger.warning(f"意图校验失败: {validation_result['error']}")
        if ws_callback:
            try:
                await ws_callback({
                    "type": "intent_validation_error",
                    "payload": {"error": validation_result["error"], "tool_exists": validation_result.get("tool_exists", True)}
                })
            except Exception as e:
                logger.error(f"WebSocket推送失败: {e}")
    
    return update_state(state, 
        intent_valid=validation_result["valid"],
        intent_error=validation_result["error"],
        needs_input=validation_result.get("needs_input", False),
        input_field=validation_result.get("input_field", ""),
        tool_exists=validation_result.get("tool_exists", True)
    )


def intent_router(state: ScanState) -> str:
    """意图路由 - 根据意图类型分流"""
    intent_valid = state.get("intent_valid", True)
    if not intent_valid:
        needs_input = state.get("needs_input", False)
        if needs_input:
            return "intent_recognition"
        tool_exists = state.get("tool_exists", True)
        if not tool_exists:
            return "chat"
        return "intent_recognition"
    
    intent_type = state.get("intent_type", "chat")
    
    if intent_type == "scan":
        return "start_scan"
    elif intent_type == "tool":
        tool_exists = state.get("tool_exists", True)
        if tool_exists:
            return "tool_existence_check"
        else:
            return "chat"
    elif intent_type == "upload_script":
        return "script_upload_process"
    elif intent_type == "generate_script":
        return "script_generate_process"
    else:
        return "chat"


async def tool_existence_check(state: ScanState) -> ScanState:
    """工具存在性校验节点 - 使用LLM Function Calling进行模糊匹配"""
    from .tools import get_all_tool_names, is_tool_exists, ALL_TOOLS
    from langchain_core.messages import SystemMessage, HumanMessage
    
    direct_tool = state.get("direct_tool", "")
    user_input = state.get("user_input", "")
    session_id = state.get("websocket_session_id") or state.get("task_id")
    ws_callback = memory_store.get_websocket_callback(session_id)
    
    logger.info(f"[{session_id}] 工具存在性校验: {direct_tool}")
    
    available_tools = get_all_tool_names()
    
    if is_tool_exists(direct_tool):
        logger.info(f"工具 '{direct_tool}' 存在，准备执行")
        return update_state(state, tool_exists=True)
    
    llm = get_llm().bind_tools(ALL_TOOLS)
    messages = [
        SystemMessage(content=f"用户想执行工具: \"{direct_tool}\"。请从可用工具中选择最匹配的工具。"),
        HumanMessage(content=f"用户原始输入: {user_input}\n用户指定的工具名: {direct_tool}")
    ]
    response = llm.invoke(messages)
    
    tool_calls = getattr(response, 'tool_calls', [])
    
    if tool_calls:
        matched_tool = tool_calls[0]['name']
        if is_tool_exists(matched_tool):
            logger.info(f"AI模糊匹配: '{direct_tool}' -> '{matched_tool}'")
            return update_state(state, tool_exists=True, direct_tool=matched_tool)
    
    error_msg = f"工具 '{direct_tool}' 不存在。您可以选择上传自定义脚本或让AI生成脚本。"
    
    if ws_callback:
        try:
            await ws_callback({
                "type": "tool_not_found",
                "payload": {
                    "tool_name": direct_tool,
                    "available_tools": available_tools,
                    "message": error_msg,
                    "options": [
                        {"key": "upload", "label": "上传脚本"},
                        {"key": "generate", "label": "AI生成脚本"},
                        {"key": "other", "label": "使用其他工具"}
                    ]
                }
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    return update_state(state, tool_exists=False, intent_error=error_msg)


def tool_check_router(state: ScanState) -> str:
    """工具校验路由"""
    tool_exists = state.get("tool_exists", True)
    
    if tool_exists:
        return "direct_tool_execute"
    else:
        return "intent_recognition"


@with_node_retry(max_retries=3)
async def direct_tool_execute(state: ScanState) -> ScanState:
    """工具直调节点 - 直接执行指定工具"""
    tool_name = state.get("direct_tool", "")
    target = state.get("target", "")
    session_id = state.get("websocket_session_id") or state.get("task_id")
    ws_callback = memory_store.get_websocket_callback(session_id)
    
    confirm_message = {
        "type": "tool_confirm_required",
        "payload": {
            "tool_name": tool_name,
            "target": target,
            "description": f"即将直接执行工具 {tool_name} 对 {target} 进行扫描",
            "rejection_count": 0
        }
    }
    
    memory_store.set_pending_interaction(session_id, confirm_message)
    
    if ws_callback:
        try:
            await ws_callback(confirm_message)
        except Exception as e:
            logger.error(f"WebSocket 发送确认请求失败: {e}")
    
    confirm_result = interrupt(confirm_message)
    memory_store.clear_pending_interaction(session_id)
    
    if isinstance(confirm_result, dict):
        confirmed = confirm_result.get("confirmed", False)
        if not confirmed:
            choice = confirm_result.get("choice", "")
            confirmed = str(choice) in ("1", "confirm", "true", "yes")
    else:
        confirmed = str(confirm_result).lower() in ("true", "yes", "1", "confirm")
    
    if not confirmed:
        logger.info(f"[{session_id}] 用户拒绝执行工具: {tool_name}")
        return update_state(state, 
            pending_action_type="rejection",
            rejection_count=1,
            confirm_tool=tool_name,
            confirm_target=target
        )
    else:
        logger.info(f"[{session_id}] 用户确认执行工具: {tool_name}")
    
    logger.info(f"[{session_id}] 工具直调: {tool_name} -> {target}")
    
    if is_auth_expired(state):
        logger.warning(f"[{session_id}] 未能获取有效认证信息，将以未认证模式继续执行")
        state = update_state(state, auth_status="expired_no_auth_mode")
        if ws_callback:
            try:
                remaining = get_auth_remaining_time(state)
                await ws_callback({
                    "type": "auth_unavailable",
                    "payload": {
                        "session_id": session_id,
                        "remaining_seconds": remaining,
                        "message": "未能获取有效认证信息，将以未认证模式继续执行",
                        "continue_execution": True
                    }
                })
            except Exception as e:
                logger.error(f"WebSocket推送失败: {e}")
    
    if ws_callback:
        try:
            await ws_callback({
                "type": "direct_tool_started",
                "payload": {"tool": tool_name, "target": target}
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    from .tools import ALL_TOOLS
    
    tool = get_tool_by_name(tool_name)
    if not tool:
        prompt = f"用户想执行工具: {tool_name}。请从可用工具中选择最匹配的工具。目标: {target}\n工具名: {tool_name}"
        matched_name = _match_tool_via_llm(prompt, ALL_TOOLS)
        if matched_name:
            tool = get_tool_by_name(matched_name)
            if tool:
                logger.info(f"LLM工具匹配: '{tool_name}' -> '{matched_name}'")
    
    if not tool:
        error_msg = f"工具 {tool_name} 不存在"
        if ws_callback:
            await ws_callback({
                "type": "direct_tool_error",
                "payload": {"tool": tool_name, "error": error_msg}
            })
        return update_state(state, errors=state.get("errors", []) + [error_msg], is_complete=True)
    
    try:
        from .tools import invoke_tool_with_auth, extract_auth_from_result
        
        with scanner_progress_context(session_id, tool_name, target, ws_callback):
            result = await asyncio.to_thread(invoke_tool_with_auth, tool, target, state)
        
        if auth_retry_manager.should_trigger_reauth(session_id, result):
            retry_count = auth_retry_manager.increment_retry(session_id)
            logger.warning(f"[{session_id}] 检测到认证失败，触发重试 ({retry_count}/{AUTH_MAX_RETRY_COUNT})")
            
            if ws_callback:
                try:
                    await ws_callback({
                        "type": "auth_refresh_required",
                        "payload": {
                            "session_id": session_id,
                            "retry_count": retry_count,
                            "max_retries": AUTH_MAX_RETRY_COUNT,
                            "reason": "检测到401/403响应，需要重新认证",
                            "tool": tool_name
                        }
                    })
                except Exception as e:
                    logger.error(f"WebSocket推送失败: {e}")
            
            if retry_count >= AUTH_MAX_RETRY_COUNT:
                logger.error(f"[{session_id}] 认证重试次数已达上限")
                if ws_callback:
                    try:
                        await ws_callback({
                            "type": "auth_retry_exhausted",
                            "payload": {
                                "session_id": session_id,
                                "retry_count": retry_count,
                                "message": "认证重试次数已达上限，请手动重新认证"
                            }
                        })
                    except Exception as e:
                        logger.error(f"WebSocket推送失败: {e}")
                
                return update_state(state, 
                    errors=state.get("errors", []) + ["认证重试次数已达上限"],
                    is_complete=True,
                    auth_retry_count=retry_count
                )
        
        if not is_auth_failure_response(result):
            auth_retry_manager.reset_retry(session_id)
        
        logger.info(f"📊 【{tool_name}】结果：{str(result)[:200]}...")
        
        auth_info = extract_auth_from_result(result)
        if auth_info:
            logger.info(f"🔐 从 {tool_name} 提取到认证信息: {list(auth_info.keys())}")
            
            encrypted_auth = encrypt_auth_info(auth_info.get("auth_info", {}))
            if encrypted_auth:
                auth_info["encrypted_auth_info"] = encrypted_auth
            
            state = update_state(state, **auth_info, credentials_obtained=True)
            
            if ws_callback:
                try:
                    await ws_callback({
                        "type": "auth_refresh_success",
                        "payload": {
                            "session_id": session_id,
                            "source_tool": tool_name,
                            "auth_type": auth_info.get("auth_info", {}).get("type", "unknown"),
                            "has_cookies": bool(auth_info.get("auth_info", {}).get("cookies")),
                            "has_token": bool(auth_info.get("auth_info", {}).get("token")),
                            "has_headers": bool(auth_info.get("auth_info", {}).get("headers")),
                            "timestamp": auth_info.get("auth_timestamp", ""),
                            "expires_at": auth_info.get("auth_expires_at", ""),
                            "message": f"已从 {tool_name} 获取认证信息，后续扫描将自动使用"
                        }
                    })
                except Exception as e:
                    logger.error(f"WebSocket推送认证通知失败: {e}")
        
        formatted_result = format_tool_result(tool_name, target, result)
        
        if ws_callback:
            try:
                await ws_callback({
                    "type": "direct_tool_completed",
                    "payload": {
                        "tool": tool_name,
                        "target": target,
                        "formatted_result": formatted_result,
                        "raw_result": result if isinstance(result, dict) else {"data": str(result)},
                        "analysis": formatted_result,
                        "vulnerable": isinstance(result, dict) and result.get("vulnerable", False),
                        "auth_obtained": bool(auth_info),
                        "timestamp": datetime.now().isoformat()
                    }
                })
            except Exception as e:
                logger.error(f"WebSocket推送失败: {e}")
        
        tool_results = state.get("tool_results", {}).copy()
        tool_results[tool_name] = result
        
        completed_tasks = state.get("completed_tasks", []).copy()
        if tool_name not in completed_tasks:
            completed_tasks.append(tool_name)
        
        task_history = state.get("task_history", []).copy()
        task_history.append(f"{tool_name}: {str(result)[:100]}")
        
        update_kwargs = dict(
            tool_results=tool_results,
            completed_tasks=completed_tasks,
            task_history=task_history,
            tool_formatted_result=formatted_result,
            task_result={"tool": tool_name, "result": result},
            last_activity_time=datetime.now().isoformat(),
            is_complete=True
        )
        
        if auth_info:
            update_kwargs["authentication_used"] = True
        
        return update_state(state, **update_kwargs)
        
    except Exception as e:
        logger.error(f"工具执行失败: {e}")
        if ws_callback:
            try:
                await ws_callback({
                    "type": "direct_tool_error",
                    "payload": {"tool": tool_name, "error": str(e)}
                })
            except Exception as we:
                logger.error(f"WebSocket推送失败: {we}")
        return update_state(state, errors=state.get("errors", []) + [f"{tool_name}: {str(e)}"], is_complete=True)


async def start_scan_node(state: ScanState) -> ScanState:
    """扫描启动节点 - 标记开始扫描"""
    session_id = state.get("websocket_session_id") or state.get("task_id")
    ws_callback = memory_store.get_websocket_callback(session_id)
    
    logger.info(f"[{session_id}] 开始扫描流程")
    log_info(f"扫描流程启动", category="workflow", node="start_scan", session_id=session_id, 
             details={"target": state.get("target", ""), "mode": "full_scan"})
    
    mode = "full_scan"
    planned_tasks = get_tool_sequence(mode)
    
    if ws_callback:
        try:
            await ws_callback({
                "type": "scan_flow_started",
                "payload": {
                    "target": state.get("target", ""),
                    "mode": mode,
                    "planned_tasks": planned_tasks,
                    "total_tasks": len(planned_tasks)
                }
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    return update_state(state, 
        mode=mode, 
        next_action="run_full_scan",
        planned_tasks=planned_tasks,
        last_activity_time=datetime.now().isoformat()
    )


def _restore_after_script_failure(state: ScanState, error: str) -> ScanState:
    """Return a failed script operation to the original task confirmation."""
    origin = state.get("script_origin", {}) or {}
    errors = list(state.get("errors", []))
    if error:
        errors.append(error)
    return update_state(
        state,
        next_task=origin.get("next_task") or state.get("next_task", ""),
        current_task=origin.get("next_task") or state.get("current_task", ""),
        planned_tasks=list(origin.get("planned_tasks") or state.get("planned_tasks", [])),
        user_choice="",
        authorized_task="",
        pending_action_type="",
        script_origin={},
        script_operation="",
        script_operation_status="failed",
        workflow_node="user_interact",
        scan_status="waiting_user",
        is_complete=False,
        errors=errors,
        last_activity_time=datetime.now().isoformat(),
    )


def _queue_registered_script(state: ScanState, tool_name: str, script_content: str,
                            description: str) -> ScanState:
    """Insert a registered custom tool before the original pending task."""
    origin = state.get("script_origin", {}) or {}
    planned_tasks = list(origin.get("planned_tasks") or state.get("planned_tasks", []))
    if tool_name and tool_name not in planned_tasks:
        original_task = origin.get("next_task") or state.get("next_task", "")
        try:
            insert_at = planned_tasks.index(original_task)
        except ValueError:
            insert_at = len(planned_tasks)
        planned_tasks.insert(insert_at, tool_name)

    return update_state(
        state,
        planned_tasks=planned_tasks,
        next_task=tool_name or origin.get("next_task") or state.get("next_task", ""),
        current_task=tool_name or origin.get("next_task") or state.get("current_task", ""),
        registered_tool_name=tool_name,
        script_content=script_content,
        script_description=description,
        user_choice="",
        authorized_task="",
        pending_action_type="",
        script_origin={},
        script_operation_status="registered",
        workflow_node="user_interact",
        scan_status="waiting_user",
        is_complete=False,
        last_activity_time=datetime.now().isoformat(),
    )


async def script_upload_process(state: ScanState) -> ScanState:
    """脚本上传处理节点"""
    from .tools import script_manager
    from .script_safety import validate_script_safety, sanitize_script_name
    from datetime import datetime
    
    session_id = state.get("websocket_session_id") or state.get("task_id")
    ws_callback = memory_store.get_websocket_callback(session_id)
    interaction_id = f"{session_id}:script_upload:{uuid4().hex}"
    interaction_data = {
        "type": "script_upload_request",
        "interaction_id": interaction_id,
        "payload": {
            "interaction_id": interaction_id,
            "message": "请上传您的脚本文件或粘贴脚本内容",
        },
    }
    
    logger.info(f"[{session_id}] 脚本上传处理")
    
    # This is a second, workflow-level interaction.  Persist it before the
    # interrupt so the WebSocket handler can verify and resume this exact
    # interrupt when the user submits the form.
    state = update_state(
        state,
        scan_status="waiting_user",
        workflow_node="script_upload_process",
        last_activity_time=datetime.now().isoformat(),
    )
    memory_store.save_session(session_id, state)
    memory_store.set_pending_interaction(session_id, interaction_data)

    if ws_callback:
        try:
            await ws_callback(interaction_data)
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    upload_data = interrupt({
        "type": "waiting_for_script_upload",
        "interaction_id": interaction_id,
    })
    memory_store.clear_pending_interaction(session_id)
    
    script_content = upload_data.get("script_content", "")
    script_name = upload_data.get("script_name", f"custom_{datetime.now().strftime('%Y%m%d%H%M%S')}")
    
    safe_name, name_err = sanitize_script_name(script_name)
    if name_err:
        if ws_callback:
            await ws_callback({
                "type": "script_error",
                "payload": {"error": f"脚本名称不合法: {name_err}"}
            })
        return _restore_after_script_failure(state, f"脚本名称不合法: {name_err}")
    script_name = safe_name
    
    if not script_content:
        if ws_callback:
            await ws_callback({
                "type": "script_error",
                "payload": {"error": "脚本内容为空"}
            })
        return _restore_after_script_failure(state, "脚本内容为空")
    
    is_safe, safety_err = validate_script_safety(script_content)
    if not is_safe:
        logger.warning(f"[{session_id}] 脚本安全审查未通过: {safety_err}")
        if ws_callback:
            await ws_callback({
                "type": "script_error",
                "payload": {"error": f"脚本安全审查未通过: {safety_err}"}
            })
        return _restore_after_script_failure(state, f"安全审查未通过: {safety_err}")
    
    if ws_callback:
        try:
            await ws_callback({
                "type": "script_analyzing",
                "payload": {"message": "AI正在分析脚本..."}
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    analysis = await script_manager.analyze_script_with_ai(script_content)
    
    # 用户填写的名称是脚本的稳定标识。AI 分析结果中的 tool_name 只能作为
    # 未填写名称时的兜底，不能覆盖用户输入，否则后续执行会变成随机 custom_xxx。
    registered_name = script_name or analysis.get("tool_name", "")
    result = script_manager.register_script_as_tool(
        script_content=script_content,
        script_name=registered_name,
        description=analysis.get("description", "自定义扫描脚本"),
        category=analysis.get("category", "custom")
    )
    
    if not result.get("success"):
        error = result.get("error", "脚本注册失败")
        if ws_callback:
            try:
                await ws_callback({
                    "type": "script_error",
                    "payload": {"error": error, "error_code": result.get("error_code", "SCRIPT_REGISTER_FAILED")}
                })
            except Exception as e:
                logger.error(f"WebSocket推送失败: {e}")
        return _restore_after_script_failure(state, error)

    if ws_callback:
        try:
            await ws_callback({
                "type": "script_registered",
                "payload": {
                    "tool_name": result["tool_name"],
                    "description": analysis.get("description"),
                    "script_content": script_content,
                    "message": f"脚本已注册为工具: {result['tool_name']}"
                }
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    return _queue_registered_script(
        state,
        result.get("tool_name", ""),
        script_content,
        analysis.get("description", ""),
    )


async def script_generate_process(state: ScanState) -> ScanState:
    """AI脚本生成处理节点"""
    from .tools import script_manager
    from .script_safety import validate_script_safety, sanitize_script_name
    from datetime import datetime
    
    session_id = state.get("websocket_session_id") or state.get("task_id")
    ws_callback = memory_store.get_websocket_callback(session_id)
    interaction_id = f"{session_id}:script_generate:{uuid4().hex}"
    interaction_data = {
        "type": "script_generate_request",
        "interaction_id": interaction_id,
        "payload": {
            "interaction_id": interaction_id,
            "message": "请描述您需要的扫描脚本功能",
        },
    }
    
    logger.info(f"[{session_id}] AI脚本生成处理")
    
    state = update_state(
        state,
        scan_status="waiting_user",
        workflow_node="script_generate_process",
        last_activity_time=datetime.now().isoformat(),
    )
    memory_store.save_session(session_id, state)
    memory_store.set_pending_interaction(session_id, interaction_data)

    if ws_callback:
        try:
            await ws_callback(interaction_data)
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    desc_data = interrupt({
        "type": "waiting_for_script_description",
        "interaction_id": interaction_id,
    })
    memory_store.clear_pending_interaction(session_id)
    description = desc_data.get("description", "")
    
    if not description:
        if ws_callback:
            await ws_callback({
                "type": "script_error",
                "payload": {"error": "请提供脚本功能描述"}
            })
        return _restore_after_script_failure(state, "请提供脚本功能描述")
    
    if ws_callback:
        try:
            await ws_callback({
                "type": "script_generating",
                "payload": {"message": "AI正在生成脚本..."}
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    script_code = await script_manager.generate_script_with_ai(description)

    if ws_callback:
        try:
            await ws_callback({
                "type": "script_generation_progress",
                "payload": {"stage": "validating", "progress": 60, "message": "正在进行安全审查..."},
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    if not script_code:
        if ws_callback:
            await ws_callback({
                "type": "script_error",
                "payload": {"error": "AI生成脚本失败"}
            })
        return _restore_after_script_failure(state, "AI生成脚本失败")
    
    is_safe, safety_err = validate_script_safety(script_code)
    if not is_safe:
        logger.warning(f"[{session_id}] AI生成脚本安全审查未通过: {safety_err}")
        if ws_callback:
            await ws_callback({
                "type": "script_error",
                "payload": {"error": f"AI生成脚本安全审查未通过: {safety_err}"}
            })
        return _restore_after_script_failure(state, f"AI生成脚本安全审查未通过: {safety_err}")
    
    analysis = await script_manager.analyze_script_with_ai(script_code)

    if ws_callback:
        try:
            await ws_callback({
                "type": "script_generation_progress",
                "payload": {"stage": "registering", "progress": 80, "message": "正在注册生成的脚本..."},
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    default_name = f"ai_gen_{datetime.now().strftime('%Y%m%d%H%M%S')}"
    tool_name = analysis.get("tool_name", default_name)
    safe_name, name_err = sanitize_script_name(tool_name)
    if name_err:
        safe_name = default_name
    tool_name = safe_name or default_name
    
    result = script_manager.register_script_as_tool(
        script_content=script_code,
        script_name=tool_name,
        description=analysis.get("description", description),
        category=analysis.get("category", "custom")
    )
    
    if not result.get("success"):
        error = result.get("error", "脚本注册失败")
        if ws_callback:
            try:
                await ws_callback({
                    "type": "script_error",
                    "payload": {"error": error, "error_code": result.get("error_code", "SCRIPT_REGISTER_FAILED")}
                })
            except Exception as e:
                logger.error(f"WebSocket推送失败: {e}")
        return _restore_after_script_failure(state, error)

    if ws_callback:
        try:
            await ws_callback({
                "type": "script_generated",
                "payload": {
                    "tool_name": result["tool_name"],
                    "script_code": script_code,
                    "description": analysis.get("description"),
                    "message": f"AI脚本已生成并注册: {result['tool_name']}"
                }
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    return _queue_registered_script(
        state,
        result.get("tool_name", ""),
        script_code,
        analysis.get("description", description),
    )


def _context_task_names(items: Any) -> List[str]:
    """Normalize legacy string tasks and structured task records."""
    names = []
    for item in items or []:
        if isinstance(item, dict):
            name = item.get("task") or item.get("name") or item.get("tool")
        else:
            name = item
        if name:
            names.append(str(name).strip())
    return names


def _unique_tasks(tasks: List[str]) -> List[str]:
    return list(dict.fromkeys(task for task in tasks if task))


def _build_decision_plan(
    state: ScanState,
    tool_sequence: List[str],
    done: List[str],
    failed: List[str],
) -> Dict[str, Any]:
    """Build the safe candidate set used by both prompt and task assignment.

    The decision context is treated as a policy layer around the LLM:
    excluded tasks are never candidates, explicit requested/priority tasks are
    placed first, and the normal scan sequence is only used as a fallback.
    """
    decision_context = state.get("decision_context", {}) or {}
    done_set = set(done)
    failed_set = set(failed)
    skipped_set = set(state.get("skipped_tasks", []) or [])
    excluded = set(_context_task_names(decision_context.get("excluded_tasks")))
    requested = _context_task_names(decision_context.get("requested_tasks"))
    priority = _context_task_names(decision_context.get("priority_tasks"))

    remaining = [
        task for task in tool_sequence
        if task not in done_set and task not in failed_set and task not in skipped_set
    ]
    eligible = [task for task in remaining if task not in excluded]
    explicit = _unique_tasks(
        [task for task in priority + requested if task in eligible]
    )
    ordered_candidates = _unique_tasks(explicit + eligible)
    newly_skipped = [task for task in remaining if task in excluded]

    return {
        "remaining": remaining,
        "eligible": eligible,
        "explicit": explicit,
        "ordered_candidates": ordered_candidates,
        "excluded": sorted(excluded),
        "newly_skipped": newly_skipped,
        "is_replanning": bool(
            state.get("user_choice") in ("resume_after_chat", "__resume_after_chat__")
            or state.get("pending_action_type") == "resume_after_chat"
        ),
    }


def _merge_skipped_tasks(state: ScanState, tasks: List[str]) -> List[str]:
    return _unique_tasks(list(state.get("skipped_tasks", []) or []) + list(tasks or []))


def build_react_prompt(state: dict, rag_strategy: str) -> str:
    """构建 ReACT 格式的提示词"""
    target = state.get("target", "")
    mode = state.get("mode", "full_scan")
    done = list(state.get("tool_results", {}).keys())
    failed = state.get("failed_tasks", [])
    tool_sequence = get_tool_sequence(mode)
    decision_plan = _build_decision_plan(state, tool_sequence, done, failed)
    remaining = decision_plan["eligible"]
    decision_candidates = decision_plan["ordered_candidates"]
    
    max_rag_length = 2000 if len(remaining) > 3 else 1500
    decision_context = state.get("decision_context", {}) or {}
    recent_chat = [
        item for item in state.get("chat_history", [])[-12:]
        if item.get("role") == "user"
    ]
    recent_chat_text = "\n".join(
        f"- {item.get('content', '')[:500]}" for item in recent_chat
    ) or "none"
    task_result = state.get("task_result", {}) or {}
    decision_messages = []
    for item in list(decision_context.get("messages") or [])[-12:]:
        if not isinstance(item, dict):
            continue
        decision_messages.append({
            "role": item.get("role", "user"),
            "content": str(item.get("content", ""))[:1200],
            "timestamp": item.get("timestamp", ""),
        })
    prompt_decision_context = {
        **decision_context,
        "messages": decision_messages,
    }
    structured_decision_factors = {
        "requested_tasks": list(decision_context.get("requested_tasks") or []),
        "excluded_tasks": list(decision_context.get("excluded_tasks") or []),
        "priority_tasks": list(decision_context.get("priority_tasks") or []),
        "user_constraints": list(decision_context.get("user_constraints") or []),
        "risk_tolerance": decision_context.get("risk_tolerance", ""),
        "latest_request": decision_context.get("latest_request", ""),
    }
    task_result_json = json.dumps(task_result, ensure_ascii=False, default=str)[:4000]
    decision_context_json = json.dumps(
        prompt_decision_context, ensure_ascii=False, default=str
    )[:8000]
    rag_content = rag_strategy[:max_rag_length] if rag_strategy else '暂无专业知识参考'

    prompt = f"""你是一名Web安全扫描专家，使用ReACT框架进行决策。

## 当前状态
- 目标: {target}
- 扫描模式: {mode}
- 已完成任务: {done if done else '无'}
- 已失败任务: {failed if failed else '无'}
- 可执行剩余任务: {remaining[:10]}
- 结构化上下文优先候选: {decision_candidates[:10]}
- 明确排除任务: {decision_plan['excluded'][:10]}
- 上一步任务结果: {task_result_json or '无'}

## 暂停聊天后的决策上下文
{decision_context_json or '{}'}
- 结构化决策因素: {json.dumps(structured_decision_factors, ensure_ascii=False, default=str)[:5000]}
- 最近用户需求：{recent_chat_text}

## 决策规则
- 用户在暂停期间的最新需求和明确排除项优先级最高。
- requested_tasks 表示用户明确要求优先考虑的任务；如果任务仍在剩余任务中，应优先选择。
- excluded_tasks 表示用户明确要求跳过或禁止的任务；不得选择其中的任务。
- priority_tasks 和 user_constraints 用于调整任务顺序、执行方式和风险边界。
- 只能从剩余任务中选择 Action；如果用户要求跳过某任务，不要选择该工具。

## 专业知识参考 (RAG)
{rag_content}

## 指令
请按以下格式输出，不要输出其他内容：

Thought: [分析当前状态，判断下一步应执行什么工具]
Action: [工具名称，必须是可执行剩余任务或结构化上下文优先候选中的一个]
Reason: [选择该工具的简短理由]
"""
    return prompt


def parse_react_response(response_text: str) -> dict:
    """解析 ReACT 格式的 LLM 回复，提取 Thought/Action/Reason"""
    result = {"thought": "", "action": "", "reason": ""}
    for line in response_text.split("\n"):
        line = line.strip()
        if line.lower().startswith("thought:"):
            result["thought"] = line.split(":", 1)[1].strip()
        elif line.lower().startswith("action:"):
            result["action"] = line.split(":", 1)[1].strip().strip("`[]{} \t")
        elif line.lower().startswith("reason:"):
            result["reason"] = line.split(":", 1)[1].strip()
    return result


@with_node_retry(max_retries=3)
async def ai_decision(state: ScanState) -> ScanState:
    """原子1: AI智能决策（RAG增强版）"""
    logger.info(f"[{state.get('task_id')}] AI决策节点开始执行（RAG增强版）")
    
    session_id = state.get("websocket_session_id") or state.get("task_id")
    log_info("AI决策节点开始执行", category="workflow", node="ai_decision", session_id=session_id,
             details={"target": state.get("target", ""), "mode": state.get("mode", "full_scan")})
    
    # 检查是否需要跳过剩余任务（高危漏洞确认后用户选择停止）
    if state.get("skip_remaining_tasks"):
        logger.info(f"[{session_id}] 跳过剩余任务，直接生成报告")
        return update_state(
            state,
            next_task="end",
            need_generate_script=False,
            workflow_node="ai_decision",
            scan_status="reporting",
        )
    
    done = list(state.get("tool_results", {}).keys())
    failed = state.get("failed_tasks", [])
    mode = state.get("mode", "full_scan")
    tool_sequence = get_tool_sequence(mode)
    # Interactive info/vulnerability scans do not pass through start_scan_node,
    # so persist their base queue before a custom script is inserted. This
    # keeps the progress denominator at 11/8 plus any custom tools.
    planned_tasks = list(state.get("planned_tasks") or tool_sequence)
    if list(state.get("planned_tasks") or []) != planned_tasks:
        state = update_state(state, planned_tasks=planned_tasks)
    progress_total = len(planned_tasks)
    ws_callback = memory_store.get_websocket_callback(session_id)
    decision_plan = _build_decision_plan(state, tool_sequence, done, failed)
    remaining_tasks = decision_plan["eligible"]
    decision_candidates = decision_plan["ordered_candidates"]
    explicit_candidates = decision_plan["explicit"]
    context_skipped_tasks = decision_plan["newly_skipped"]
    next_candidate = decision_candidates[0] if decision_candidates else ""
    
    # =================== RAG 知识库检索（强制） ===================
    target = state.get("target", "")
    last_result = state.get("tool_result", {}) or state.get("task_result", {})
    rag_strategy = ""
    rag_sources = []
    try:
        rag_strategy = get_scan_strategy(
            target=target,
            current_task=next_candidate,
            completed_tasks=done,
            last_result=last_result
        )
        if rag_strategy:
            import re
            source_matches = re.findall(r'来源: ([^\|]+)', rag_strategy)
            rag_sources = source_matches[:3]
            logger.info(f"RAG 策略检索成功: 来源={rag_sources}, 内容长度={len(rag_strategy)}")
        else:
            logger.warning(f"[{session_id}] RAG检索返回空结果，使用默认策略")
    except Exception as e:
        logger.warning(f"[{session_id}] RAG 检索异常: {e}，使用默认策略")
    # =====================================================
    
    # =================== ReACT 推理决策 ===================
    react_decision = None
    try:
        llm = get_llm()
        react_prompt = build_react_prompt(state, rag_strategy)
        react_response = safe_llm_invoke(llm, react_prompt, timeout=30)
        react_text = react_response.content if hasattr(react_response, 'content') else str(react_response)
        react_decision = parse_react_response(react_text)
        logger.info(f"ReACT 决策: Action={react_decision.get('action')} Reason={react_decision.get('reason', '')[:50]}")
    except Exception as e:
        logger.warning(f"ReACT 决策失败（回退到默认序列）: {e}")
        react_decision = None
    # ========================================================
    
    skipped_tasks = _merge_skipped_tasks(state, context_skipped_tasks)
    progress_count = len(set(done) | set(skipped_tasks))
    progress_percent = round((progress_count / progress_total) * 100, 1) if progress_total else 0
    
    if ws_callback:
        try:
            await ws_callback({
                "type": "workflow_progress",
                "payload": {
                    "stage": mode,
                    "status": "running",
                    "completed": len(done),
                    "total": progress_total,
                    "progress_percent": progress_percent,
                    "rag_enabled": True,
                    "rag_strategy": rag_strategy
                }
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    # =================== 任务分配（ReACT 优先） ===================
    next_task_assigned = None
    is_react_selected = False
    decision_source = "default_sequence"
    react_action = (react_decision or {}).get("action", "")

    if explicit_candidates:
        # Explicit user requests are a hard preference during replanning. The
        # model can choose among them, but cannot silently replace them with
        # the old sequence or with an excluded task.
        if react_action in explicit_candidates:
            next_task_assigned = react_action
            is_react_selected = True
            decision_source = "structured_context+react"
            logger.info(f"ReACT 在结构化优先候选中选择任务：{react_action}")
        else:
            next_task_assigned = explicit_candidates[0]
            decision_source = "structured_context"
            if react_action:
                logger.info(
                    f"结构化上下文覆盖 ReACT 任务选择：{react_action} -> {next_task_assigned}"
                )
    elif react_action in remaining_tasks:
        next_task_assigned = react_action
        is_react_selected = True
        decision_source = "react"
        logger.info(f"ReACT 决策分配任务：{react_action}")
    elif remaining_tasks:
        next_task_assigned = remaining_tasks[0]
        logger.warning(
            f"ReACT 决策未选出可执行任务，回退到安全候选：{remaining_tasks}"
        )

    if next_task_assigned is None:
        logger.info(
            f"没有可执行的剩余任务，排除任务={decision_plan['excluded']}，结束扫描"
        )
        if ws_callback:
            try:
                await ws_callback({
                    "type": "workflow_progress",
                    "payload": {
                        "stage": mode,
                        "status": "completed",
                        "completed": progress_count,
                        "total": progress_total,
                        "progress_percent": 100 if progress_total else 0,
                        "skipped_tasks": skipped_tasks,
                        "reason": "decision_context_excluded_remaining_tasks",
                    },
                })
                await ws_callback({
                    "type": "ai_decision_complete",
                    "payload": {
                        "completed_tasks": done,
                        "skipped_tasks": skipped_tasks,
                        "total_tasks": progress_total,
                        "reason": "decision_context_excluded_remaining_tasks",
                    },
                })
            except Exception as e:
                logger.error(f"WebSocket 回调失败: {e}")
        return update_state(
            state,
            next_task="end",
            skipped_tasks=skipped_tasks,
            need_generate_script=False,
            rag_last_strategy=rag_strategy,
            workflow_node="ai_decision",
            scan_status="reporting",
            chat_mode=False,
        )

    if next_task_assigned:
        t = next_task_assigned

        decision_history = state.get("decision_history", []).copy()
        decision_entry = {
            "timestamp": datetime.now().isoformat(),
            "next_task": t,
            "completed_count": len(done),
            "total_count": progress_total,
            "decision_source": decision_source,
            "decision_context_version": (state.get("decision_context") or {}).get("version", 0),
            "excluded_tasks": decision_plan["excluded"],
            "skipped_tasks": skipped_tasks,
            "rag_reference": rag_strategy[:500] if rag_strategy else "",
            "rag_sources": rag_sources,
            "rag_used": len(rag_strategy) > 0,
            "react_chain": {
                "thought": react_decision.get("thought", "") if react_decision else "",
                "action": react_decision.get("action", "") if react_decision else "",
                "reason": react_decision.get("reason", "") if react_decision else ""
            } if is_react_selected else None
        }
        decision_history.append(decision_entry)

        if ws_callback:
            try:
                await ws_callback({
                    "type": "ai_decision",
                    "payload": {
                        "next_task": t,
                        "completed_tasks": done,
                        "skipped_tasks": skipped_tasks,
                        "total_tasks": progress_total,
                        "progress": f"{len(done)}/{progress_total}",
                        "progress_percent": progress_percent,
                        "rag_enabled": True,
                        "rag_reference": rag_strategy,
                        "react_selected": is_react_selected,
                        "decision_source": decision_source,
                        "decision_context_version": (state.get("decision_context") or {}).get("version", 0),
                        "react_thought": react_decision.get("thought", "") if react_decision else ""
                    }
                })
            except Exception as e:
                logger.error(f"WebSocket推送失败: {e}")

        return update_state(state,
            next_task=t,
            need_generate_script=False,
            skipped_tasks=skipped_tasks,
            decision_history=decision_history,
            rag_last_strategy=rag_strategy,
            workflow_node="ai_decision",
            scan_status="waiting_user",
            chat_mode=False,
            last_activity_time=datetime.now().isoformat()
        )
    # ================================================================
    
    logger.info("✅ 所有扫描任务已完成！")
    
    if ws_callback:
        try:
            await ws_callback({
                "type": "workflow_progress",
                "payload": {
                    "stage": mode,
                    "status": "completed",
                    "completed": len(done),
                    "total": progress_total,
                    "progress_percent": 100,
                    "rag_enabled": True,
                    "rag_strategy": rag_strategy
                }
            })
            await ws_callback({
                "type": "ai_decision_complete",
                "payload": {
                    "completed_tasks": done,
                    "total_tasks": progress_total,
                    "rag_reference": rag_strategy
                }
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    return update_state(state, next_task="end", need_generate_script=False,
        rag_last_strategy=rag_strategy,
        workflow_node="ai_decision",
        scan_status="reporting")


async def user_interact(state: ScanState) -> ScanState:
    """原子2: 用户交互 - 使用 interrupt 实现暂停等待"""
    logger.info(f"[{state.get('task_id')}] 用户交互节点")
    
    next_task = state.get("next_task", "")
    mode = state.get("mode", "full_scan")
    target = state.get("target", "")
    session_id = state.get("websocket_session_id") or state.get("task_id")
    
    if next_task == "end":
        return state
    
    interaction_id = f"{session_id}:interaction:{next_task}:{len(state.get('completed_tasks', []))}"
    interaction_data = {
        "type": "interaction_required",
        "session_id": session_id,
        "interaction_id": interaction_id,
        "payload": {
            "interaction_id": interaction_id,
            "next_task": next_task,
            "target": target,
            "mode": mode,
            "completed_tasks": state.get("completed_tasks", []),
            # planned_tasks includes custom scripts inserted by the upload or
            # generate flow, so the client can update the progress denominator
            # before the next tool starts.
            "total_tasks": len(state.get("planned_tasks", [])),
            "options": [
                {"key": "1", "label": "执行", "description": f"执行任务: {next_task}"},
                {"key": "2", "label": "停止", "description": "停止扫描并生成报告"},
                {"key": "3", "label": "聊天", "description": "与 AI 助手对话"},
                {"key": "4", "label": "上传脚本", "description": "上传自定义扫描脚本"},
                {"key": "5", "label": "生成脚本", "description": "AI生成专属扫描脚本"}
            ]
        }
    }
    
    logger.info(f"🎯 目标：{target} | 模式：{mode} | 下一个任务：{next_task}")
    logger.info("[1]执行 [2]停止 [3]聊天 [4]上传脚本 [5]生成脚本")

    state = update_state(
        state,
        scan_status="waiting_user",
        workflow_node="user_interact",
        current_task=next_task,
        chat_mode=False,
        last_activity_time=datetime.now().isoformat(),
    )
    memory_store.save_session(session_id, state)
    
    ws_callback = memory_store.get_websocket_callback(session_id)
    logger.info(f"获取到 WebSocket 回调: {ws_callback}")
    logger.info(f"发送交互数据: {interaction_data}")
    
    pending_interaction = memory_store.get_pending_interaction(session_id)
    is_replayed_interaction = (
        pending_interaction
        and pending_interaction.get("interaction_id") == interaction_id
    )
    if not is_replayed_interaction:
        memory_store.set_pending_interaction(session_id, interaction_data)

    if ws_callback and not is_replayed_interaction:
        try:
            await ws_callback(interaction_data)
        except Exception as e:
            logger.error(f"WebSocket 回调失败: {e}")
    
    logger.info(f"等待用户选择...")
    user_choice = interrupt(interaction_data)
    logger.info(f"用户选择: {user_choice}")

    memory_store.clear_pending_interaction(session_id)
    
    control_action = ""
    if isinstance(user_choice, dict):
        control_action = str(user_choice.get("action", "") or "")
        if control_action == "resume_after_chat":
            resume_context = {
                key: user_choice[key]
                for key in (
                    "decision_context",
                    "decision_context_version",
                    "chat_history",
                )
                if key in user_choice
            }
            if resume_context:
                state = update_state(state, **resume_context)
        user_choice = user_choice.get("choice", "1")
    
    logger.info(f"👤 用户选择: {user_choice}")
    
    choice = str(user_choice)
    is_replanning = control_action == "resume_after_chat"
    script_origin = {}
    if choice in ("4", "5"):
        # Preserve the task that was being confirmed before entering the
        # script flow.  The script is an addition to this scan, not a new
        # standalone workflow.
        script_origin = {
            "source_node": "user_interact",
            "interaction_id": interaction_id,
            "next_task": next_task,
            "target": target,
            "mode": mode,
            "planned_tasks": list(state.get("planned_tasks", [])),
            "completed_tasks": list(state.get("completed_tasks", [])),
        }
    return update_state(
        state,
        user_choice=choice,
        authorized_task=next_task if choice == "1" else "",
        workflow_node="ai_decision" if is_replanning else "router",
        pending_action_type=control_action,
        script_origin=script_origin,
        script_operation=("upload" if choice == "4" else "generate" if choice == "5" else ""),
        script_operation_status="waiting" if choice in ("4", "5") else "",
        scan_status=(
            "running" if is_replanning
            else
            "running" if choice == "1"
            else "reporting" if choice == "2"
            else state.get("scan_status", "waiting_user")
        ),
        chat_mode=False if is_replanning else state.get("chat_mode", False),
    )


@with_node_retry(max_retries=3)
async def execute_task(state: ScanState) -> ScanState:
    """原子3: 执行任务"""
    logger.info(f"[{state.get('task_id')}] 执行任务节点")
    
    task = state.get("next_task", "")
    if task == "end" or task == "":
        return state
    
    target = state.get("target", "")
    session_id = state.get("websocket_session_id") or state.get("task_id")
    state = update_state(
        state,
        current_tool=task,
        current_task=task,
        workflow_node="execute_task",
        scan_status="running",
        last_activity_time=datetime.now().isoformat(),
    )
    memory_store.save_session(session_id, state)
    log_collector.add_log(session_id, "execute_task", "info", f"任务开始: {task}, 目标={target}")
    ws_callback = memory_store.get_websocket_callback(session_id)
    
    task_is_authorized = state.get("authorized_task") == task
    if task not in ("end", "") and not task_is_authorized:
        rejection_count = state.get("rejection_count", 0)
        skipped = state.get("skipped_tasks", [])

        interaction_id = f"{session_id}:tool_confirm:{task}:{len(state.get('completed_tasks', []))}"
        confirm_message = {
            "type": "tool_confirm_required",
            "interaction_id": interaction_id,
            "payload": {
                "interaction_id": interaction_id,
                "tool_name": task,
                "target": target,
                "description": f"即将执行 {task} 对 {target} 进行扫描",
                "rejection_count": rejection_count
            }
        }
        
        pending_interaction = memory_store.get_pending_interaction(session_id)
        is_replayed_interaction = (
            pending_interaction
            and pending_interaction.get("interaction_id") == interaction_id
        )
        if not is_replayed_interaction:
            memory_store.set_pending_interaction(session_id, confirm_message)

        if ws_callback and not is_replayed_interaction:
            try:
                await ws_callback(confirm_message)
            except Exception as e:
                logger.error(f"WebSocket 发送确认请求失败: {e}")
        
        confirm_result = interrupt(confirm_message)
        memory_store.clear_pending_interaction(session_id)
        
        if isinstance(confirm_result, dict):
            confirmed = confirm_result.get("confirmed", False)
            if not confirmed:
                choice = confirm_result.get("choice", "")
                confirmed = str(choice) in ("1", "confirm", "true", "yes")
        else:
            confirmed = str(confirm_result).lower() in ("true", "yes", "1", "confirm")
        
        if not confirmed:
            logger.info(f"[{session_id}] 用户拒绝执行工具: {task}")
            new_count = rejection_count + 1
            return update_state(state, 
                pending_action_type="rejection",
                rejection_count=new_count,
                confirm_tool=task,
                confirm_target=target,
                user_choice="rejected"
            )
        else:
            logger.info(f"[{session_id}] 用户确认执行工具: {task}")
            state = update_state(state, rejection_count=0)

    state = update_state(state, authorized_task="")
    
    if is_auth_expired(state):
        logger.warning(f"[{session_id}] 未能获取有效认证信息，将以未认证模式继续执行")
        state = update_state(state, auth_status="expired_no_auth_mode")
        if ws_callback:
            try:
                remaining = get_auth_remaining_time(state)
                await ws_callback({
                    "type": "auth_unavailable",
                    "payload": {
                        "session_id": session_id,
                        "remaining_seconds": remaining,
                        "message": "未能获取有效认证信息，将以未认证模式继续执行",
                        "continue_execution": True
                    }
                })
            except Exception as e:
                logger.error(f"WebSocket推送失败: {e}")
    
    if ws_callback:
        try:
            await ws_callback({
                "type": "task_started",
                "payload": {"tool": task, "target": target}
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    from .tools import get_tools_by_mode
    
    scan_mode = state.get("mode", "info_collection")
    tools_list = get_tools_by_mode(scan_mode)
    
    tool = get_tool_by_name(task)
    if not tool:
        prompt = f"当前需要执行的安全任务: {task}。请从可用工具中选择最匹配的工具来执行此任务。任务名称: {task}\n目标: {target}"
        matched_name = _match_tool_via_llm(prompt, tools_list)
        if matched_name:
            tool = get_tool_by_name(matched_name)
            if tool:
                logger.info(f"LLM工具匹配: '{task}' -> '{matched_name}'")

    if not tool:
        logger.warning(f"工具 {task} 不存在，跳过并继续下一个任务")

        if ws_callback:
            try:
                await ws_callback({
                    "type": "task_skipped",
                    "payload": {"tool": task, "reason": f"工具 {task} 不存在，已跳过"}
                })
            except Exception as e:
                logger.error(f"WebSocket推送失败: {e}")
        completed_tasks = state.get("completed_tasks", []).copy()
        if task not in completed_tasks:
            completed_tasks.append(task)
        return update_state(state, 
            errors=state.get("errors", []) + [f"工具 {task} 不存在，已跳过"],
            completed_tasks=completed_tasks,
            next_task="continue",
            current_tool="",
            workflow_node="ai_decision",
            last_activity_time=datetime.now().isoformat())
    
    try:
        from .tools import invoke_tool_with_auth, extract_auth_from_result
        
        with scanner_progress_context(session_id, task, target, ws_callback):
            res = await asyncio.to_thread(invoke_tool_with_auth, tool, target, state)
        
        if auth_retry_manager.should_trigger_reauth(session_id, res):
            retry_count = auth_retry_manager.increment_retry(session_id)
            logger.warning(f"[{session_id}] 检测到认证失败，触发重试 ({retry_count}/{AUTH_MAX_RETRY_COUNT})")
            
            if ws_callback:
                try:
                    await ws_callback({
                        "type": "auth_refresh_required",
                        "payload": {
                            "session_id": session_id,
                            "retry_count": retry_count,
                            "max_retries": AUTH_MAX_RETRY_COUNT,
                            "reason": "检测到401/403响应，需要重新认证",
                            "tool": task
                        }
                    })
                except Exception as e:
                    logger.error(f"WebSocket推送失败: {e}")
            
            if retry_count < AUTH_MAX_RETRY_COUNT:
                state = update_state(
                    state,
                    need_reauth=True,
                    auth_retry_count=retry_count,
                    current_tool="",
                    workflow_node="user_interact",
                    scan_status="waiting_user",
                )
                return state
            else:
                logger.error(f"[{session_id}] 认证重试次数已达上限")
                if ws_callback:
                    try:
                        await ws_callback({
                            "type": "auth_retry_exhausted",
                            "payload": {
                                "session_id": session_id,
                                "retry_count": retry_count,
                                "message": "认证重试次数已达上限，请手动重新认证"
                            }
                        })
                    except Exception as e:
                        logger.error(f"WebSocket推送失败: {e}")
        
        if not is_auth_failure_response(res):
            auth_retry_manager.reset_retry(session_id)
        
        logger.info(f"📊 【{task}】结果：{res}")

        if isinstance(res, dict) and res.get("success") is False:
            raise RuntimeError(res.get("error") or f"{task} 执行失败")
        
        auth_info = extract_auth_from_result(res)
        if auth_info:
            logger.info(f"🔐 从 {task} 提取到认证信息: {list(auth_info.keys())}")
            
            encrypted_auth = encrypt_auth_info(auth_info.get("auth_info", {}))
            if encrypted_auth:
                auth_info["encrypted_auth_info"] = encrypted_auth
            
            state = update_state(state, **auth_info, credentials_obtained=True)
            
            if ws_callback:
                try:
                    await ws_callback({
                        "type": "auth_info_obtained",
                        "payload": {
                            "source_tool": task,
                            "auth_type": auth_info.get("auth_info", {}).get("type", "unknown"),
                            "has_cookies": bool(auth_info.get("auth_info", {}).get("cookies")),
                            "has_token": bool(auth_info.get("auth_info", {}).get("token")),
                            "has_headers": bool(auth_info.get("auth_info", {}).get("headers")),
                            "timestamp": auth_info.get("auth_timestamp", ""),
                            "expires_at": auth_info.get("auth_expires_at", ""),
                            "message": f"已从 {task} 获取认证信息，后续扫描将自动使用"
                        }
                    })
                except Exception as e:
                    logger.error(f"WebSocket推送认证通知失败: {e}")
        
        analysis = summarize_tool_result(task, res)

        result_data = res.get("data", {}) if isinstance(res, dict) else {}
        is_vulnerable = bool(
            isinstance(res, dict) and (
                res.get("vulnerable") or
                (isinstance(result_data, dict) and result_data.get("vulnerabilities"))
            )
        )
        
        if ws_callback:
            try:
                await ws_callback({
                    "type": "task_completed",
                    "payload": {
                        "tool": task,
                        "target": target,
                        "raw_result": res if isinstance(res, dict) else {"data": str(res)},
                        "analysis": analysis,
                        "vulnerable": is_vulnerable,
                        "auth_obtained": bool(auth_info),
                        "timestamp": datetime.now().isoformat()
                    }
                })
            except Exception as e:
                logger.error(f"WebSocket推送失败: {e}")

            schedule_tool_result_analysis(session_id, task, target, res, ws_callback)
        
        log_collector.add_log(session_id, "execute_task", "info", f"任务完成: {task}")
        
        new_state = append_chat(state, "system", f"任务：{task}\n结果：{res}\n分析：{analysis}")
        tool_results = state.get("tool_results", {}).copy()
        tool_results[task] = res
        
        completed_tasks = state.get("completed_tasks", []).copy()
        completed_tasks.append(task)
        
        all_vulns = state.get("vulnerabilities", []).copy()
        current_vulns = []
        current_mode = state.get("mode", "")
        if current_mode in ("vuln_scan", "full_scan") and isinstance(res, dict):
            result_data = res.get("data", {})
            vuln_data = result_data.get("vulnerabilities", []) if isinstance(result_data, dict) else []
            current_vulns = vuln_data if isinstance(vuln_data, list) else []
            if vuln_data:
                for v in vuln_data:
                    if isinstance(v, dict):
                        v = {**v, "source_tool": task}
                    all_vulns.append(v)
                logger.info(f"[{session_id}] 从工具 {task} 提取到 {len(vuln_data)} 个漏洞")
        
        task_history = state.get("task_history", []).copy()
        task_history.append(f"{task}: {str(res)[:100]}")
        
        planned_tasks = state.get("planned_tasks", [])
        stage_status = state.get("stage_status", {}).copy()
        stage_status["tool_execution"] = {
            "status": "running",
            "current_task": task,
            "progress": round(len(completed_tasks) / max(len(planned_tasks), 1) * 100, 1),
            "completed": len(completed_tasks),
            "total": len(planned_tasks) if planned_tasks else 1
        }
        
        update_kwargs = dict(
            tool_results=tool_results, 
            completed_tasks=completed_tasks,
            vulnerabilities=all_vulns,
            current_task_vulnerabilities=current_vulns,
            task_history=task_history,
            stage_status=stage_status,
            task_result={"tool": task, "result": res},
            current_tool="",
            workflow_node="vulnerability_check",
            scan_status="running",
            last_activity_time=datetime.now().isoformat()
        )
        
        if auth_info:
            update_kwargs["authentication_used"] = True
        
        return update_state(new_state, **update_kwargs)
        
    except Exception as e:
        logger.error(f"执行任务失败: {e}")
        log_collector.add_log(session_id, "execute_task", "error", f"任务失败: {task}, 错误: {str(e)}")
        
        from TOSKill.utils.error_handler import format_tool_error
        error_response = format_tool_error(task, e)
        
        ai_analysis = error_response.get("payload", {}).get("suggestion") or str(e)
        
        if ws_callback:
            try:
                await ws_callback({
                    "type": "task_error",
                    "payload": {
                        "tool": task,
                        "target": target,
                        "error": str(e),
                        "code": error_response.get("payload", {}).get("code"),
                        "source": error_response.get("payload", {}).get("source"),
                        "suggestion": error_response.get("payload", {}).get("suggestion"),
                        "details": error_response.get("payload", {}).get("details", {}),
                        "ai_analysis": ai_analysis
                    }
                })
            except Exception as we:
                logger.error(f"WebSocket推送失败: {we}")
            schedule_tool_error_analysis(session_id, task, target, str(e), ws_callback)
        failed_tasks = state.get("failed_tasks", []).copy()
        if task not in failed_tasks:
            failed_tasks.append(task)

        return update_state(
            state,
            errors=state.get("errors", []) + [f"{task}: {str(e)}"],
            failed_tasks=failed_tasks,
            current_task_vulnerabilities=[],
            authorized_task="",
            next_task="continue",
            current_tool="",
            workflow_node="ai_decision",
            scan_status="running",
            last_activity_time=datetime.now().isoformat(),
        )


def _parse_response(full_response: str):
    """从LLM完整响应中分离思考过程和最终回复"""
    import re
    thought = ""
    content = full_response
    match = re.match(
        r'(?:思考[：:]\s*|分析[：:]\s*|Thought:\s*)(.*?)(?=回复[：:]|回答[：:]|Response:|$)',
        full_response, re.DOTALL
    )
    if match:
        thought = match.group(1).strip()
        remaining = full_response[match.end():].strip()
        remaining = re.sub(r'^(?:回复[：:]|回答[：:]|Response:)\s*', '', remaining)
        content = remaining if remaining else content
    return thought, content


async def chat(state: ScanState) -> ScanState:
    """原子4: 聊天（流式思考）"""
    logger.info(f"[{state.get('task_id')}] 聊天节点")
    
    session_id = state.get("websocket_session_id") or state.get("task_id")
    ws_callback = memory_store.get_websocket_callback(session_id)
    
    llm = get_llm()
    user_name = state.get("user_name", "用户")
    chat_summary = state.get("chat_summary", "无")
    task_history = state.get("completed_tasks", [])
    target = state.get("target", "")
    user_input = state.get("user_input", "")
    conversation_turn = state.get("conversation_turn", 0) + 1
    
    prompt = f"""你是安全助手，用户：{user_name}
聊天总结：{chat_summary}
任务历史：{task_history}
目标：{target}
自然简洁回复。"""
    
    await safe_ws_send(session_id, {
        "type": "ai_thinking_start",
        "payload": {}
    })
    
    full_response = ""
    async for chunk in safe_llm_astream(llm, prompt):
        token = chunk.content if hasattr(chunk, 'content') else str(chunk)
        if token:
            full_response += token
            await send_thinking_token(session_id, token)
    
    thought, content = _parse_response(full_response)
    
    if ws_callback:
        try:
            await ws_callback({
                "type": "ai_chat",
                "payload": {"thought": thought, "content": content}
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    new_state = append_chat(state, "assistant", content)
    
    memory_store.append_chat(session_id, "user", user_input)
    memory_store.append_chat(session_id, "assistant", content)
    
    return update_state(new_state, 
        chat_summary=content[:200],
        conversation_turn=conversation_turn,
        last_activity_time=datetime.now().isoformat()
    )


async def script_manager(state: ScanState) -> ScanState:
    return update_state(state, need_generate_script=False)


async def vulnerability_check(state: ScanState) -> ScanState:
    """
    漏洞风险检查节点
    
    检测到高危/严重漏洞时：
    1. 暂停工作流（interrupt）
    2. 通过 WebSocket 通知前端
    3. 等待用户确认
    4. 根据用户决策更新状态
    """
    vulnerabilities = state.get("vulnerabilities", [])
    current_vulnerabilities = state.get("current_task_vulnerabilities", [])
    session_id = state.get("websocket_session_id") or state.get("task_id")
    
    risk_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for vuln in vulnerabilities:
        severity = str(vuln.get("severity") or "info").lower()
        if severity in risk_summary:
            risk_summary[severity] += 1

    current_risk_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for vuln in current_vulnerabilities:
        severity = str(vuln.get("severity") or "info").lower()
        if severity in current_risk_summary:
            current_risk_summary[severity] += 1

    state = update_state(state, risk_summary=risk_summary)

    if current_risk_summary["critical"] > 0 or current_risk_summary["high"] > 0:
        highest_risk = "critical" if current_risk_summary["critical"] > 0 else "high"
        task_name = state.get("task_result", {}).get("tool", "unknown")
        interaction_id = f"{session_id}:high_risk:{task_name}:{len(current_vulnerabilities)}"

        interrupt_data = {
            "type": "high_risk_vulnerability_detected",
            "interaction_id": interaction_id,
            "highest_risk_level": highest_risk,
            "risk_summary": current_risk_summary,
            "vulnerabilities": [
                v for v in current_vulnerabilities
                if str(v.get("severity") or "").lower() in ("critical", "high")
            ],
            "message": f"检测到 {current_risk_summary['critical']} 个严重漏洞, {current_risk_summary['high']} 个高危漏洞",
            "options": [
                {"key": "continue", "label": "继续扫描", "description": "继续执行剩余扫描任务"},
                {"key": "stop", "label": "停止并报告", "description": "立即停止扫描并生成报告"},
                {"key": "poc_verify", "label": "POC验证", "description": "对已发现漏洞进行POC验证"}
            ]
        }
        
        interaction_message = {
            "type": "high_risk_vulnerability_detected",
            "interaction_id": interaction_id,
            "payload": interrupt_data
        }
        pending_interaction = memory_store.get_pending_interaction(session_id)
        is_replayed_interaction = (
            pending_interaction
            and pending_interaction.get("interaction_id") == interaction_id
        )
        if not is_replayed_interaction:
            memory_store.set_pending_interaction(session_id, interaction_message)

        ws_callback = memory_store.get_websocket_callback(session_id)
        if ws_callback and not is_replayed_interaction:
            await ws_callback(interaction_message)
        
        user_decision = interrupt(interrupt_data)
        memory_store.clear_pending_interaction(session_id)

        decision = user_decision.get("choice", "continue") if isinstance(user_decision, dict) else str(user_decision or "continue")
        
        logger.info(f"[{session_id}] 高危漏洞确认 - 用户决策: {decision}")
        
        if decision == "stop":
            state = update_state(
                state,
                skip_remaining_tasks=True,
                confirmed=True,
                current_task_vulnerabilities=[]
            )
            return update_state(state, next_task="end", need_generate_script=False)
        elif decision == "poc_verify":
            state = update_state(
                state,
                next_task="poc_verification",
                confirmed=True,
                current_task_vulnerabilities=[]
            )
        else:
            state = update_state(state, confirmed=True, current_task_vulnerabilities=[])
    
    return state


@with_node_retry(max_retries=3)
async def report_generation(state: ScanState) -> ScanState:
    """原子6: 报告生成 - 使用AI分析并保存报告到文件"""
    logger.info(f"[{state.get('task_id')}] 报告生成节点")
    
    tool_results = state.get("tool_results", {})
    vulnerabilities = state.get("vulnerabilities", [])
    target = state.get("target", "")
    session_id = state.get("websocket_session_id") or state.get("task_id", "unknown")
    log_collector.add_log(session_id, "report_generation", "info", "报告生成开始")
    ws_callback = memory_store.get_websocket_callback(session_id)
    
    if not tool_results:
        log_collector.add_log(session_id, "report_generation", "warning", "无扫描结果，报告生成跳过")
        if ws_callback:
            await ws_callback({
                "type": "report_error",
                "payload": {"error": "无扫描结果"}
            })
        return update_state(state, is_complete=True, report="无扫描结果")
    
    scan_summary = {
        "timestamp": datetime.now().isoformat(),
        "tool_count": len(tool_results),
        "vulnerability_count": len(vulnerabilities)
    }
    
    if ws_callback:
        try:
            await ws_callback({
                "type": "report_generation_started",
                "payload": {
                    "session_id": session_id,
                    "tool_count": len(tool_results),
                    "vulnerability_count": len(vulnerabilities)
                }
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    try:
        from ..tools.report.report_manager import get_report_manager
        report_manager = get_report_manager()
        
        chat_history = memory_store.get_chat_history(session_id)
        task_history = [
            {
                "tool": task, 
                "result_summary": str(state.get("tool_results", {}).get(task, ""))[:200]
            }
            for task in state.get("completed_tasks", [])
        ]
        
        report = await report_manager.generate_ai_report_content_async(
            tool_results=tool_results,
            vulnerabilities=vulnerabilities,
            target=target,
            chat_history=chat_history,
            task_history=task_history
        )
        
        report_info = report_manager.save_report(
            session_id=session_id,
            content=report,
            metadata={
                "target": target,
                "tool_results": tool_results,
                "vulnerabilities": vulnerabilities,
                "scan_summary": scan_summary,
                "chat_history_count": len(chat_history),
                "task_history_count": len(task_history)
            }
        )
        
        logger.info(f"Markdown报告已保存: {report_info.get('download_url')}")
        
        log_collector.add_log(session_id, "report_generation", "info", "报告摘要已完成，正在生成HTML报告")

        ai_analysis = report_manager.generate_html_analysis(
            vulnerabilities=vulnerabilities,
            target=target,
            report_content=report,
        )
        logger.info(f"HTML分析数据已生成: 风险等级={ai_analysis.get('risk_assessment', {}).get('overall_risk', 'unknown')}")

        # AI等保评估置信度（独立try/except，失败不中断报告生成）
        confidence = None
        try:
            scan_mode = state.get("scan_mode", "人机交互")
            logger.info(f"[置信度诊断] 开始评估: vulns={len(vulnerabilities)}, tools={len(tool_results)}, mode={scan_mode}")
            if vulnerabilities:
                logger.info(f"[置信度诊断] 首个漏洞: {vulnerabilities[0]}")
            confidence = await report_manager.generate_confidence_async(
                vulnerabilities=vulnerabilities,
                tool_results=tool_results,
                target=target,
                scan_mode=scan_mode
            )
            if confidence:
                logger.info(f"置信度评估完成: {confidence.get('overall_score', 0):.0f}% ({confidence.get('level', 'info')})")
            else:
                logger.info("置信度评估未生成数据，报告将显示占位")
        except Exception as e:
            logger.warning(f"置信度评估失败，降级为占位: {e}")
            confidence = None

        html_report_info = report_manager.save_html_report(
            session_id=session_id,
            target=target,
            scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            vulnerabilities=vulnerabilities,
            tool_results=tool_results,
            ai_analysis=ai_analysis,
            confidence=confidence
        )
        
        html_download_url = html_report_info.get("download_url", "")
        logger.info(f"HTML报告已保存: {html_download_url}")
        
        if ws_callback:
            try:
                await ws_callback({
                    "type": "report_generated",
                    "payload": {
                        "report_url": report_info.get("download_url", ""),
                        "report_id": report_info.get("report_id", ""),
                        "report_preview": report[:500] if report else "",
                        "html_report_url": html_download_url,
                        "html_report_id": html_report_info.get("report_id", "")
                    }
                })
            except Exception as e:
                logger.error(f"WebSocket推送失败: {e}")
        
        log_collector.add_log(session_id, "report_generation", "info", "报告生成完成")
        
        return update_state(
            state, 
            is_complete=True, 
            report=report, 
            scan_summary=scan_summary,
            report_url=report_info.get("download_url", ""),
            report_id=report_info.get("report_id", ""),
            html_report_url=html_download_url
        )
    except Exception as e:
        logger.error(f"保存报告失败: {e}")
        log_collector.add_log(session_id, "report_generation", "error", f"报告生成失败: {str(e)}")
        if ws_callback:
            try:
                await ws_callback({
                    "type": "report_error",
                    "payload": {"error": str(e)}
                })
            except Exception as we:
                logger.error(f"WebSocket推送失败: {we}")
        return update_state(state, is_complete=True, report="报告生成失败", scan_summary=scan_summary)


def execute_task_router(state: ScanState) -> str:
    """execute_task 后的路由：确认通过→漏洞检查，拒绝→否决处理"""
    if state.get("pending_action_type") == "rejection":
        return "rejection_handler"
    return "vulnerability_check"


async def rejection_handler(state: ScanState) -> ScanState:
    """否决处理节点 - 用户拒绝当前方案后生成替代方案"""
    session_id = state.get("websocket_session_id") or state.get("task_id")
    rejection_count = state.get("rejection_count", 1)
    rejected_tool = state.get("confirm_tool", "")
    target = state.get("target", "")
    ws_callback = memory_store.get_websocket_callback(session_id)
    
    logger.info(f"[{session_id}] 否决处理 - 第{rejection_count}次拒绝, 被拒工具: {rejected_tool}")
    
    if rejection_count >= 3:
        logger.warning(f"[{session_id}] 连续拒绝超过3次，终止扫描")
        if ws_callback:
            try:
                await ws_callback({
                    "type": "scan_terminated",
                    "payload": {
                        "reason": "连续拒绝超过3次",
                        "suggestion": "建议手动指定扫描方向或生成已有结果的报告",
                        "rejection_count": rejection_count
                    }
                })
            except Exception as e:
                logger.error(f"WebSocket 推送失败: {e}")
        
        memory_store.append_chat(session_id, "system", 
            f"用户连续拒绝 {rejection_count} 次，扫描已终止。建议手动指定方向或生成报告。")
        
        return update_state(state, 
            next_task="end", 
            pending_action_type="terminated",
            is_complete=False
        )
    
    done = state.get("completed_tasks", [])
    skipped = state.get("skipped_tasks", [])
    mode = state.get("mode", "full_scan")
    tool_sequence = get_tool_sequence(mode)
    remaining = [t for t in tool_sequence if t not in done and t not in skipped]
    
    chat_context = memory_store.get_chat_history(session_id)
    chat_summary = "\n".join([
        f"{m['role']}: {m['content'][:100]}" 
        for m in chat_context[-8:]
    ]) if chat_context else ""
    
    try:
        llm = get_llm()
        alt_prompt = f"""用户拒绝了执行工具 "{rejected_tool}" 对 "{target}" 的扫描请求（第{rejection_count}次拒绝）。

你是安全扫描专家，请生成替代方案：
- 已完成任务: {done if done else '无'}
- 剩余可执行任务: {remaining if remaining else '无'}
- 已跳过任务: {skipped if skipped else '无'}
- 对话上下文: {chat_summary[:500]}

请按以下JSON格式回复（不要输出其他内容）：
```json
[
  {{"label": "方案名称(简短)", "action": "工具名称", "description": "方案说明(一句话)"}}
]
```
要求：
1. 生成2-4个替换方案
2. 每个方案的action必须是剩余任务列表或备选工具列表中的有效工具名
3. 至少一个方案是从剩余任务中顺序选择下一个
4. 如果剩余任务为0，建议 "skip" 跳过或 "report" 生成报告
"""

        alt_response = safe_llm_invoke(llm, alt_prompt, timeout=30)
        alt_text = alt_response.content if hasattr(alt_response, 'content') else str(alt_response)
        
        import re
        json_match = re.search(r'```json\s*([\s\S]*?)\s*```', alt_text)
        if json_match:
            alternatives = json.loads(json_match.group(1))
        else:
            json_match = re.search(r'\[[\s\S]*\]', alt_text)
            if json_match:
                alternatives = json.loads(json_match.group(0))
            else:
                alternatives = []
        
        if not alternatives:
            raise ValueError("无法解析替代方案")
            
    except Exception as e:
        logger.warning(f"[{session_id}] AI 生成替代方案失败: {e}，使用默认方案")
        alternatives = [
            {"label": "跳过当前工具", "action": "skip", "description": f"跳过 {rejected_tool}，继续下一个任务"},
            {"label": "重试当前工具", "action": rejected_tool, "description": f"重新尝试执行 {rejected_tool}"},
        ]
        if remaining:
            alt = remaining[0]
            if alt != rejected_tool:
                alternatives.append({"label": f"执行 {alt}", "action": alt, "description": f"改为执行剩余任务: {alt}"})
        alternatives.append({"label": "停止扫描", "action": "stop", "description": "停止扫描并生成已有结果的报告"})
    
    alt_message = {
        "type": "alternative_options",
        "payload": {
            "rejected_tool": rejected_tool,
            "rejection_count": rejection_count,
            "alternatives": alternatives
        }
    }
    
    memory_store.set_pending_interaction(session_id, alt_message)
    
    if ws_callback:
        try:
            await ws_callback(alt_message)
        except Exception as e:
            logger.error(f"WebSocket 发送替代方案失败: {e}")
    
    user_choice = interrupt(alt_message)
    memory_store.clear_pending_interaction(session_id)
    
    if isinstance(user_choice, dict):
        chosen = user_choice
    else:
        chosen = {"choice_index": int(user_choice) if str(user_choice).isdigit() else 0}
    
    choice_idx = chosen.get("choice_index", chosen.get("index", 0))
    if isinstance(choice_idx, str) and choice_idx.isdigit():
        choice_idx = int(choice_idx)
    
    if 0 <= choice_idx < len(alternatives):
        selected = alternatives[choice_idx]
    else:
        selected = alternatives[0] if alternatives else {"action": "skip", "label": "跳过"}
    
    action = selected.get("action", "skip")
    
    logger.info(f"[{session_id}] 用户选择替代方案: {selected.get('label')} -> {action}")
    
    memory_store.append_chat(session_id, "system", 
        f"用户选择替代方案: {selected.get('label', '')} ({action})")
    
    if action == "stop":
        return update_state(state, next_task="end", pending_action_type="")
    elif action == "skip":
        new_skipped = skipped.copy()
        if rejected_tool and rejected_tool not in new_skipped:
            new_skipped.append(rejected_tool)
        if rejected_tool not in done:
            done_copy = done.copy()
            done_copy.append(rejected_tool)
        else:
            done_copy = done
        return update_state(state,
            pending_action_type="",
            next_task="continue",
            skipped_tasks=new_skipped,
            completed_tasks=done_copy,
            confirm_tool="",
            confirm_target=""
        )
    elif action == "report":
        return update_state(state, next_task="end", pending_action_type="")
    else:
        return update_state(state,
            pending_action_type="",
            next_task=action,
            confirm_tool=action,
            confirm_target=target,
            rejection_count=rejection_count
        )


def router(state: ScanState) -> str:
    """路由决策"""
    next_task = state.get("next_task", "")
    need_generate_script = state.get("need_generate_script", False)
    user_choice = state.get("user_choice", "")
    
    if next_task == "end":
        return "report_generation"
    
    if next_task == "continue":
        return "ai_decision"
    
    if need_generate_script:
        return "script_manager"
    
    c = user_choice
    if c in ("resume_after_chat", "__resume_after_chat__"):
        return "ai_decision"
    if c == "1":
        return "execute_task"
    if c == "2":
        return "report_generation"
    if c == "3":
        return "chat"
    if c == "4":
        return "script_upload_process"
    if c == "5":
        return "script_generate_process"
    
    if state.get("pending_action_type") == "rejection":
        return "rejection_handler"
    
    return "user_interact"


def create_checkpointer(db_path: str = None):
    """创建持久化 SQLite 检查点器。

    LangGraph 的业务状态保存在 MemoryStore 中，工作流游标则由该
    checkpointer 保存。两者必须同时存在，才能在服务重启后恢复 interrupt。
    """
    if SqliteSaver is None:
        raise RuntimeError(
            "缺少 langgraph-checkpoint-sqlite，请先安装项目 requirements.txt 中的依赖"
        )

    db_path = db_path or getattr(settings, "CHECKPOINT_DB_PATH", "data/langgraph_checkpoints.db")
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=30000")
    checkpointer = SqliteSaver(conn)
    checkpointer.setup()
    # 保存连接引用，便于应用关闭时释放资源。
    setattr(checkpointer, "_toskill_connection", conn)
    logger.info(f"LangGraph SQLite Checkpointer 已启用: {db_path}")
    return checkpointer


async def create_async_checkpointer(db_path: str = None):
    """Create and initialize the async SQLite checkpointer used by ainvoke."""
    if AsyncSqliteSaver is None or aiosqlite is None:
        raise RuntimeError(
            "缺少 langgraph-checkpoint-sqlite 或 aiosqlite，请先安装 TOSKill/requirements.txt 中的依赖"
        )

    db_path = db_path or getattr(settings, "CHECKPOINT_DB_PATH", "data/langgraph_checkpoints.db")
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    conn = await aiosqlite.connect(db_path)
    try:
        await conn.execute("PRAGMA synchronous=NORMAL")
        await conn.execute("PRAGMA busy_timeout=30000")
        await conn.commit()
        checkpointer = AsyncSqliteSaver(conn)
        await checkpointer.setup()
    except Exception:
        await conn.close()
        raise

    setattr(checkpointer, "_toskill_connection", conn)
    logger.info(f"LangGraph Async SQLite Checkpointer 已启用: {db_path}")
    return checkpointer


class IntentRecognitionGraph:
    """用户意图识别子图 - 系统总入口"""
    
    @staticmethod
    def build(checkpointer: MemorySaver = None) -> StateGraph:
        workflow = StateGraph(ScanState)
        
        workflow.add_node("intent_recognition", intent_recognition)
        workflow.add_node("intent_validation", intent_validation)
        workflow.add_node("tool_existence_check", tool_existence_check)
        workflow.add_node("direct_tool_execute", direct_tool_execute)
        workflow.add_node("chat", chat)
        workflow.add_node("start_scan", start_scan_node)
        workflow.add_node("script_upload_process", script_upload_process)
        workflow.add_node("script_generate_process", script_generate_process)
        
        workflow.set_entry_point("intent_recognition")
        workflow.add_edge("intent_recognition", "intent_validation")
        workflow.add_conditional_edges("intent_validation", intent_router)
        
        workflow.add_conditional_edges("tool_existence_check", tool_check_router)
        workflow.add_edge("direct_tool_execute", END)
        workflow.add_edge("chat", END)
        workflow.add_edge("start_scan", END)
        workflow.add_edge("script_upload_process", END)
        workflow.add_edge("script_generate_process", END)
        
        if checkpointer is None:
            checkpointer = MemorySaver()
        return workflow.compile(checkpointer=checkpointer)


class InfoCollectionGraph:
    """信息收集子图"""
    
    @staticmethod
    def build(checkpointer: MemorySaver = None) -> StateGraph:
        workflow = StateGraph(ScanState)
        
        workflow.add_node("ai_decision", ai_decision)
        workflow.add_node("user_interact", user_interact)
        workflow.add_node("execute_task", execute_task)
        workflow.add_node("vulnerability_check", vulnerability_check)
        workflow.add_node("rejection_handler", rejection_handler)
        workflow.add_node("chat", chat)
        workflow.add_node("script_manager", script_manager)
        workflow.add_node("script_upload_process", script_upload_process)
        workflow.add_node("script_generate_process", script_generate_process)
        workflow.add_node("report_generation", report_generation)
        
        workflow.set_entry_point("ai_decision")
        workflow.add_edge("ai_decision", "user_interact")
        workflow.add_conditional_edges("user_interact", router)
        workflow.add_conditional_edges("execute_task", execute_task_router)
        workflow.add_edge("vulnerability_check", "ai_decision")
        workflow.add_edge("rejection_handler", "user_interact")
        workflow.add_edge("chat", "ai_decision")
        workflow.add_edge("script_manager", "ai_decision")
        # A custom script is inserted into the active scan queue.  Both a
        # successful registration and a recoverable failure must return to a
        # user confirmation for the current task, not start a fresh AI plan.
        workflow.add_edge("script_upload_process", "user_interact")
        workflow.add_edge("script_generate_process", "user_interact")
        workflow.add_edge("report_generation", END)
        
        if checkpointer is None:
            checkpointer = MemorySaver()
        return workflow.compile(checkpointer=checkpointer)


class VulnScanGraph:
    """漏洞扫描子图"""
    
    @staticmethod
    def build(checkpointer: MemorySaver = None) -> StateGraph:
        workflow = StateGraph(ScanState)
        
        workflow.add_node("ai_decision", ai_decision)
        workflow.add_node("user_interact", user_interact)
        workflow.add_node("execute_task", execute_task)
        workflow.add_node("vulnerability_check", vulnerability_check)
        workflow.add_node("rejection_handler", rejection_handler)
        workflow.add_node("chat", chat)
        workflow.add_node("script_manager", script_manager)
        workflow.add_node("script_upload_process", script_upload_process)
        workflow.add_node("script_generate_process", script_generate_process)
        workflow.add_node("report_generation", report_generation)
        
        workflow.set_entry_point("ai_decision")
        workflow.add_edge("ai_decision", "user_interact")
        workflow.add_conditional_edges("user_interact", router)
        workflow.add_conditional_edges("execute_task", execute_task_router)
        workflow.add_edge("vulnerability_check", "ai_decision")
        workflow.add_edge("rejection_handler", "user_interact")
        workflow.add_edge("chat", "ai_decision")
        workflow.add_edge("script_manager", "ai_decision")
        workflow.add_edge("script_upload_process", "user_interact")
        workflow.add_edge("script_generate_process", "user_interact")
        workflow.add_edge("report_generation", END)
        
        if checkpointer is None:
            checkpointer = MemorySaver()
        return workflow.compile(checkpointer=checkpointer)


class ReportGraph:
    """报告生成子图"""
    
    @staticmethod
    def build(checkpointer: MemorySaver = None) -> StateGraph:
        workflow = StateGraph(ScanState)
        
        workflow.add_node("report_generation", report_generation)
        
        workflow.set_entry_point("report_generation")
        workflow.add_edge("report_generation", END)
        
        if checkpointer is None:
            checkpointer = MemorySaver()
        return workflow.compile(checkpointer=checkpointer)

class AgentOrchestrator:
    """Agent 编排器 - 管理多个子图的执行，支持暂停/恢复"""
    
    def __init__(self):
        self._checkpointer = None  # 延迟初始化
        self.intent_graph = None
        self.info_graph = None
        self.vuln_graph = None
        self.report_graph = None
        self._running_tasks: Dict[str, asyncio.Task] = {}
        self._initialized = False
        self._initialization_lock = asyncio.Lock()
        logger.info("Agent 编排器初始化完成")
    
    async def _ensure_initialized(self):
        """确保异步初始化完成"""
        if self._initialized:
            return
        async with self._initialization_lock:
            if self._initialized:
                return
            self._checkpointer = await create_async_checkpointer()
            try:
                self.intent_graph = IntentRecognitionGraph.build(checkpointer=self._checkpointer)
                self.info_graph = InfoCollectionGraph.build(checkpointer=self._checkpointer)
                self.vuln_graph = VulnScanGraph.build(checkpointer=self._checkpointer)
                self.report_graph = ReportGraph.build(checkpointer=self._checkpointer)
                self._initialized = True
            except Exception:
                conn = getattr(self._checkpointer, "_toskill_connection", None)
                if conn is not None:
                    await conn.close()
                self._checkpointer = None
                raise
            logger.info("Agent 编排器异步初始化完成")
    
    def set_websocket_callback(self, session_id: str, callback: Callable):
        """设置 WebSocket 回调"""
        memory_store.set_websocket_callback(session_id, callback)

    async def aclose(self):
        """关闭持久化检查点连接。"""
        if self._checkpointer is not None:
            conn = getattr(self._checkpointer, "_toskill_connection", None)
            if conn is not None:
                try:
                    await conn.close()
                except Exception as exc:
                    logger.warning(f"关闭 LangGraph Checkpointer 失败: {exc}")
        self._checkpointer = None
        self.intent_graph = None
        self.info_graph = None
        self.vuln_graph = None
        self.report_graph = None
        self._initialized = False

    def close(self):
        """Backward-compatible close wrapper for sync callers."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.aclose())
        return loop.create_task(self.aclose())

    @staticmethod
    def _merge_workflow_result(session_id: str, result: Optional[Dict[str, Any]]):
        """Merge graph output with MemoryStore fields updated during chat.

        Chat messages and decision context are intentionally written outside
        LangGraph while a scan is paused.  A resumed checkpoint may therefore
        contain an older copy of those fields; the durable session copy wins.
        The interrupt envelope is returned to callers but is not written into
        the ScanState JSON record.
        """
        if not result:
            return result, None
        result = dict(result)
        interrupt_envelope = result.pop("__interrupt__", None)
        stored = memory_store.get_session(session_id) or {}
        merged = {**stored, **result}
        for key in (
            "chat_history",
            "decision_context",
            "decision_context_version",
        ):
            if key in stored:
                merged[key] = stored[key]
        return merged, interrupt_envelope
    
    async def resume_workflow(self, session_id: str, user_choice: str) -> Optional[ScanState]:
        """恢复暂停的工作流 - 使用 Command(resume=...) 恢复 interrupt
        添加状态校验和超时保护：超过30分钟未响应自动结束
        """
        await self._ensure_initialized()
        config = {"configurable": {"thread_id": session_id}}
        
        if isinstance(user_choice, dict):
            resume_value = dict(user_choice)
        else:
            resume_value = {"choice": user_choice}

        if resume_value.get("action") == "resume_after_chat":
            stored_state = memory_store.get_session(session_id) or {}
            for key in ("decision_context", "decision_context_version", "chat_history"):
                if key in stored_state:
                    resume_value.setdefault(key, stored_state[key])
        
        try:
            checkpoint = await self.info_graph.aget_state(config)
            if not checkpoint or not checkpoint.values:
                checkpoint = await self.vuln_graph.aget_state(config)
            if not checkpoint or not checkpoint.values:
                checkpoint = await self.intent_graph.aget_state(config)
            mode = "full_scan"
            if checkpoint and checkpoint.values:
                state_data = checkpoint.values
                mode = state_data.get("mode", "full_scan")
                
                updated_at = state_data.get("updated_at")
                if updated_at:
                    if isinstance(updated_at, str):
                        updated_at = datetime.fromisoformat(updated_at.replace("Z", "+00:00").replace("+00:00", ""))
                    elapsed = (datetime.now() - updated_at.replace(tzinfo=None)).total_seconds()
                    if elapsed > 1800:
                        logger.warning(f"[{session_id}] 工作流超时({elapsed}s > 1800s)，自动终止")
                        ws_callback = memory_store.get_websocket_callback(session_id)
                        if ws_callback:
                            try:
                                await ws_callback({
                                    "type": "workflow_timeout",
                                    "payload": {
                                        "session_id": session_id,
                                        "elapsed_seconds": elapsed,
                                        "message": "工作流已超过30分钟未响应，自动结束"
                                    }
                                })
                            except Exception:
                                pass
                        return update_state(
                            checkpoint.values or {},
                            is_complete=True,
                            errors=checkpoint.values.get("errors", []) + ["工作流超时自动终止"]
                        )
        except Exception:
            state = memory_store.get_session(session_id)
            mode = state.get("mode", "full_scan") if state else "full_scan"
        
        logger.info(f"[{session_id}] 恢复工作流，用户选择: {user_choice}, 模式: {mode}")
        
        try:
            if mode == "info_collection":
                result = await self.info_graph.ainvoke(
                    Command(resume=resume_value),
                    config=config
                )
            elif mode == "vuln_scan":
                result = await self.vuln_graph.ainvoke(
                    Command(resume=resume_value),
                    config=config
                )
            else:
                result = await self.intent_graph.ainvoke(
                    Command(resume=resume_value),
                    config=config
                )
            
            if result and not isinstance(result, dict):
                result = dict(result)

            result, interrupt_envelope = self._merge_workflow_result(session_id, result)
            if result:
                memory_store.save_session(session_id, result)
            if interrupt_envelope is not None:
                result = dict(result or {})
                result["__interrupt__"] = interrupt_envelope
            
            logger.info(f"工作流 {session_id} 已恢复完成")
            return result
            
        except Exception as e:
            logger.error(f"恢复工作流失败: {e}", exc_info=True)
            ws_callback = memory_store.get_websocket_callback(session_id)
            if ws_callback:
                try:
                    await ws_callback({
                        "type": "workflow_error",
                        "payload": {
                            "error": f"恢复工作流失败: {str(e)}",
                            "suggestion": "请尝试重新发起扫描或刷新页面",
                            "code": "RESUME_FAILED",
                            "session_id": session_id
                        }
                    })
                except Exception:
                    pass
            state = memory_store.get_session(session_id)
            if state:
                state = update_state(state, user_choice=user_choice)
                memory_store.save_session(session_id, state)
            return state
    
    def get_pending_interaction(self, session_id: str) -> Optional[Dict]:
        """获取待处理的交互请求"""
        return memory_store.get_pending_interaction(session_id)
    
    def has_pending_interaction(self, session_id: str) -> bool:
        """检查是否有待处理的交互"""
        return memory_store.has_pending_interaction(session_id)
    
    async def run_intent_recognition(self, state: ScanState, websocket_callback: Callable = None) -> ScanState:
        """运行意图识别流程"""
        await self._ensure_initialized()
        session_id = state.get("websocket_session_id") or state.get("task_id")
        
        if websocket_callback:
            memory_store.set_websocket_callback(session_id, websocket_callback)
        
        result = await self.intent_graph.ainvoke(
            state,
            config={"configurable": {"thread_id": session_id}}
        )
        
        if result.get("next_action") == "run_full_scan":
            logger.info(f"[{session_id}] 意图识别完成，开始扫描流程")
            result = await self.run_full_scan(result, websocket_callback)
        
        return result
    
    async def run_direct_tool(self, tool_name: str, target: str, session_id: str, websocket_callback: Callable = None) -> Dict[str, Any]:
        """直接执行工具"""
        if websocket_callback:
            memory_store.set_websocket_callback(session_id, websocket_callback)
        
        tool = get_tool_by_name(tool_name)
        if not tool:
            raise ValueError(f"工具 {tool_name} 不存在")
        
        if websocket_callback:
            try:
                await websocket_callback({
                    "type": "direct_tool_started",
                    "payload": {"tool": tool_name, "target": target}
                })
            except Exception as e:
                logger.error(f"WebSocket推送失败: {e}")
        
        try:
            with scanner_progress_context(session_id, tool_name, target, websocket_callback):
                result = await asyncio.to_thread(tool.invoke, target)
            formatted = format_tool_result(tool_name, target, result)
            
            if websocket_callback:
                try:
                    await websocket_callback({
                        "type": "direct_tool_completed",
                        "payload": {
                            "tool": tool_name,
                            "target": target,
                            "formatted_result": formatted
                        }
                    })
                except Exception as e:
                    logger.error(f"WebSocket推送失败: {e}")
            
            return {
                "tool": tool_name,
                "target": target,
                "result": result,
                "formatted_result": formatted
            }
        except Exception as e:
            if websocket_callback:
                try:
                    await websocket_callback({
                        "type": "direct_tool_error",
                        "payload": {"tool": tool_name, "error": str(e)}
                    })
                except Exception as we:
                    logger.error(f"WebSocket推送失败: {we}")
            raise
    
    async def run_full_scan(self, state: ScanState, websocket_callback: Callable = None) -> ScanState:
        """运行完整扫描流程"""
        await self._ensure_initialized()
        logger.info(f"[{state.get('task_id')}] 开始完整扫描流程")
        
        session_id = state.get("websocket_session_id") or state.get("task_id")
        
        if websocket_callback:
            memory_store.set_websocket_callback(session_id, websocket_callback)
        
        try:
            state = update_state(state, mode="info_collection")
            state = await self.info_graph.ainvoke(
                state,
                config={"configurable": {"thread_id": session_id}}
            )
            if state.get("__interrupt__"):
                return state
            
            state = update_state(state, mode="vuln_scan")
            state = await self.vuln_graph.ainvoke(
                state,
                config={"configurable": {"thread_id": session_id}}
            )
            if state.get("__interrupt__"):
                return state
            
            state = await self.report_graph.ainvoke(
                state,
                config={"configurable": {"thread_id": session_id}}
            )
            memory_store.save_session(session_id, state)
            
            logger.info(f"[{state.get('task_id')}] 完整扫描流程完成")
            return state
            
        except Exception as e:
            logger.error(f"完整扫描流程失败: {e}")
            raise
    
    async def run_info_collection(self, state: ScanState, websocket_callback: Callable = None) -> ScanState:
        """仅运行信息收集"""
        await self._ensure_initialized()
        session_id = state.get("websocket_session_id") or state.get("task_id")
        
        if websocket_callback:
            memory_store.set_websocket_callback(session_id, websocket_callback)
        
        state = update_state(state, mode="info_collection")
        return await self.info_graph.ainvoke(
            state,
            config={"configurable": {"thread_id": session_id}}
        )
    
    async def run_vuln_scan(self, state: ScanState, websocket_callback: Callable = None) -> ScanState:
        """仅运行漏洞扫描"""
        await self._ensure_initialized()
        session_id = state.get("websocket_session_id") or state.get("task_id")
        
        if websocket_callback:
            memory_store.set_websocket_callback(session_id, websocket_callback)
        
        state = update_state(state, mode="vuln_scan")
        return await self.vuln_graph.ainvoke(
            state,
            config={"configurable": {"thread_id": session_id}}
        )
    
    async def run_report(self, state: ScanState) -> ScanState:
        """仅生成报告"""
        await self._ensure_initialized()
        session_id = state.get("websocket_session_id") or state.get("task_id")
        return await self.report_graph.ainvoke(
            state,
            config={"configurable": {"thread_id": session_id}}
        )


agent_orchestrator = AgentOrchestrator()


def get_agent_orchestrator() -> AgentOrchestrator:
    """获取Agent编排器实例"""
    return agent_orchestrator
