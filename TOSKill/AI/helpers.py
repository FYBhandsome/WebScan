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
        "dirscan": {"directories": "directories"},
        "port_scan": {"open_ports": "open_ports", "services": "services", "ip": "ip"},
        "subdomain_enum": {"subdomains": "subdomains", "subdomain_ips": "subdomain_ips"},
        "dir_scan": {"directories": "directories", "sensitive_files": "sensitive_files"},
        "ssl_certificate": {"certificate": "certificate", "days_remaining": "ssl_days_remaining"},
        "sensitive_info_leak": {"leaks": "sensitive_leaks"},
        "sqli_deep_scan": {"injection_points": "sqli_injection_points"},
        "xss_deep_scan": {"xss_points": "xss_points"},
        "ssrf_scan": {"ssrf_points": "ssrf_points"},
        "file_upload_scan": {"upload_points": "upload_points"}
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


class NodeExecutionLogger:
    """节点执行日志记录器"""
    
    @staticmethod
    def log_start(task_id: str, node_name: str, target: str) -> None:
        logger.info(f"[{task_id}] 🚀 [{node_name}] 开始执行 | 目标: {target}")
    
    @staticmethod
    def log_success(task_id: str, node_name: str, execution_time: float, vuln_count: int = 0) -> None:
        logger.info(
            f"[{task_id}] ✅ [{node_name}] 执行成功 | "
            f"耗时: {execution_time:.2f}s | "
            f"漏洞数: {vuln_count}"
        )
    
    @staticmethod
    def log_failure(task_id: str, node_name: str, error: str) -> None:
        logger.error(f"[{task_id}] ❌ [{node_name}] 执行失败: {error}")
    
    @staticmethod
    def log_warning(task_id: str, node_name: str, message: str) -> None:
        logger.warning(f"[{task_id}] ⚠️ [{node_name}] {message}")


class DataFlowHelper:
    """数据流辅助工具"""
    
    @staticmethod
    def merge_results(base_result: Dict[str, Any], new_result: Dict[str, Any]) -> Dict[str, Any]:
        """合并两个结果字典"""
        merged = base_result.copy()
        for key, value in new_result.items():
            if key in merged and isinstance(merged[key], list) and isinstance(value, list):
                merged[key].extend(value)
            elif key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
                merged[key].update(value)
            else:
                merged[key] = value
        return merged
    
    @staticmethod
    def extract_vulnerabilities(result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """从结果中提取漏洞列表"""
        vulns = []
        vuln_keys = ["vulnerabilities", "vulns", "issues", "findings"]
        for key in vuln_keys:
            if key in result and isinstance(result[key], list):
                vulns.extend(result[key])
        return vulns
