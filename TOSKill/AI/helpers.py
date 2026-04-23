"""
辅助工具模块

定义上下文更新器、进度计算器和状态持久化函数。
"""
import logging
import json
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class TargetContextUpdater:
    """目标上下文更新器"""
    
    CONTEXT_MAPPINGS = {
        "baseinfo": {"server": "server", "os": "os", "ip": "ip", "domain": "domain", "title": "title", "headers": "headers"},
        "cms_identify": {"cms": "cms"},
        "portscan": {"open_ports": "open_ports"},
        "waf_detect": {"waf": "waf"},
        "cdn_detect": {"cdn": "is_cdn", "has_cdn": "has_cdn"},
        "subdomain_scan": {"subdomains": "subdomains"},
        "webside_scan": {"side_domains": "side_domains"},
        "iplocating": {"location": "location"},
        "infoleak_scan": {"leaks": "leaks"},
        "dirscan": {"directories": "directories"}
    }
    
    @classmethod
    def update_context(cls, state, tool_name: str, data: Dict[str, Any]) -> None:
        if not data or not isinstance(data, dict):
            return
        if tool_name not in cls.CONTEXT_MAPPINGS:
            return
        mapping = cls.CONTEXT_MAPPINGS[tool_name]
        for state_key, data_key in mapping.items():
            value = data.get(data_key)
            if value is not None:
                state.update_context(state_key, value)


class ProgressCalculator:
    """进度计算器"""
    
    @staticmethod
    def calculate_progress(completed: int, total: int) -> int:
        if total <= 0:
            return 0
        return min(100, int((completed / total) * 100))
    
    @staticmethod
    def calculate_stage_progress(completed_tasks: List[str], planned_tasks: List[str], current_task: Optional[str] = None) -> int:
        completed = len(completed_tasks)
        remaining = len(planned_tasks)
        total = completed + remaining
        return ProgressCalculator.calculate_progress(completed, total)


async def persist_task_state(task_id: str, stage_status: Dict, progress: int):
    """持久化任务状态到数据库"""
    try:
        from backend.models import Task
        tid = int(task_id)
        task = await Task.get(id=tid)
        task.progress = progress
        current_result = json.loads(task.result) if task.result else {}
        current_result['stages'] = stage_status
        current_result.setdefault('scan_summary', {})
        current_result.setdefault('vulnerabilities', [])
        current_result.setdefault('report', "")
        current_result.setdefault('execution_history', [])
        task.result = json.dumps(current_result, default=str)
        await task.save()
    except Exception as e:
        logger.error(f"持久化任务状态失败: {task_id} - {e}")
