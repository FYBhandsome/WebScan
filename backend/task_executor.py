"""
任务执行器 - 负责执行扫描任务并实时更新进度

功能:
1. 任务队列管理 (串行执行)
2. 幂等性检查 (防止重复提交)
3. 全局超时控制
4. 统一异常处理
5. 多进程插件执行与管理
6. 任务状态持久化
7. 任务恢复功能
8. 任务超时处理
9. 支持所有插件类型的执行 (plugins, vulnerability_scan_plugins, poc)
10. 漏洞扫描插件并发执行
11. POC 验证批量执行
"""
import asyncio
import logging
import multiprocessing
import signal
import time
import os
import json
import traceback
from typing import Dict, Any, Set, Optional, Union, List, Callable
from datetime import datetime
from pathlib import Path
from tortoise.expressions import Q
from backend.api.websocket import manager
from backend.config import settings
from backend.services.notification_service import notification_service
from backend.plugin_executor import run_plugin_process
from backend.ai_agents.poc_system.dynamic_engine import dynamic_engine
from backend.utils.logging_utils import (
    task_state_logger, 
    get_request_id, 
    set_request_id,
    StructuredLogger
)
from backend.api.task_type_registry import (
    task_type_registry, 
    TaskCategory, 
    ExecutorType,
    TaskPriority
)

logger = logging.getLogger(__name__)
structured_logger = StructuredLogger("task_executor")


from backend.utils.serializers import sanitize_json_data
from backend.services.report_service import report_service


TASK_STATE_FILE = "data/task_states.json"
TASK_TIMEOUT_CONFIG = {
    "port_scan": 15 * 60,
    "waf_check": 5 * 60,
    "awvs_scan": 5 * 60 * 60,
    "poc_scan": 60 * 60,
    "ai_agent_scan": 5 * 60 * 60,
    "default": 60 * 60,
}

PLUGIN_TYPE_MAPPING = {
    "portscan": {"module": "backend.plugins.portscan.portscan", "class": "ScanPort", "executor": "plugin"},
    "port_scan": {"module": "backend.plugins.portscan.portscan", "class": "ScanPort", "executor": "plugin"},
    "infoleak": {"module": "backend.plugins.infoleak.infoleak", "class": "get_infoleak", "executor": "plugin"},
    "info_leak": {"module": "backend.plugins.infoleak.infoleak", "class": "get_infoleak", "executor": "plugin"},
    "webside": {"module": "backend.plugins.webside.webside", "class": "get_side_info", "executor": "plugin"},
    "web_side": {"module": "backend.plugins.webside.webside", "class": "get_side_info", "executor": "plugin"},
    "baseinfo": {"module": "backend.plugins.baseinfo.baseinfo", "class": "getbaseinfo", "executor": "plugin"},
    "base_info": {"module": "backend.plugins.baseinfo.baseinfo", "class": "getbaseinfo", "executor": "plugin"},
    "webweight": {"module": "backend.plugins.webweight.webweight", "class": "get_web_weight", "executor": "plugin"},
    "web_weight": {"module": "backend.plugins.webweight.webweight", "class": "get_web_weight", "executor": "plugin"},
    "iplocating": {"module": "backend.plugins.iplocating.iplocating", "class": "get_locating", "executor": "plugin"},
    "ip_locating": {"module": "backend.plugins.iplocating.iplocating", "class": "get_locating", "executor": "plugin"},
    "cdnexist": {"module": "backend.plugins.cdnexist.cdnexist", "class": "iscdn", "executor": "plugin"},
    "cdn_check": {"module": "backend.plugins.cdnexist.cdnexist", "class": "iscdn", "executor": "plugin"},
    "waf": {"module": "backend.plugins.waf.waf", "class": "getwaf", "executor": "plugin"},
    "waf_check": {"module": "backend.plugins.waf.waf", "class": "getwaf", "executor": "plugin"},
    "whatcms": {"module": "backend.plugins.whatcms.whatcms", "class": "getwhatcms", "executor": "plugin"},
    "subdomain": {"module": "backend.plugins.subdomain.subdomain", "class": "get_subdomain", "executor": "plugin"},
    "dirscan": {"module": "backend.plugins.dirscan.dirscan", "class": "get_dirscan", "executor": "plugin"},
    "dir_scan": {"module": "backend.plugins.dirscan.dirscan", "class": "get_dirscan", "executor": "plugin"},
    "crawler": {"module": "backend.plugins.crawler.crawler", "class": "Crawler", "executor": "plugin"},
    "loginfo": {"module": "backend.plugins.loginfo.loginfo", "class": "get_loginfo", "executor": "plugin"},
    "randheader": {"module": "backend.plugins.randheader.randheader", "class": "get_randheader", "executor": "plugin"},
    "common": {"module": "backend.plugins.common.common", "class": "CommonPlugin", "executor": "plugin"},
}

VULN_SCAN_PLUGIN_MAPPING = {
    "sqli": {"module": "backend.vulnerability_scan_plugins.sqli.scanner", "class": "SQLiScanner", "executor": "vuln_scan"},
    "xss": {"module": "backend.vulnerability_scan_plugins.xss.scanner", "class": "XSSScanner", "executor": "vuln_scan"},
    "csrf": {"module": "backend.vulnerability_scan_plugins.csrf.scanner", "class": "CSRFScanner", "executor": "vuln_scan"},
    "ssrf": {"module": "backend.vulnerability_scan_plugins.ssrf.scanner", "class": "SSRFScanner", "executor": "vuln_scan"},
    "lfi": {"module": "backend.vulnerability_scan_plugins.lfi.scanner", "class": "LFIScanner", "executor": "vuln_scan"},
    "cmdi": {"module": "backend.vulnerability_scan_plugins.cmdi.scanner", "class": "CmdiScanner", "executor": "vuln_scan"},
    "fileupload": {"module": "backend.vulnerability_scan_plugins.fileupload.scanner", "class": "FileUploadScanner", "executor": "vuln_scan"},
    "weakpass": {"module": "backend.vulnerability_scan_plugins.weakpass.scanner", "class": "WeakPassScanner", "executor": "vuln_scan"},
    "infoleak_vuln": {"module": "backend.vulnerability_scan_plugins.infoleak.scanner", "class": "InfoLeakScanner", "executor": "vuln_scan"},
}

POC_PLUGIN_MAPPING = {
    "weblogic_cve_2020_2551": {"module": "backend.poc.weblogic.cve_2020_2551_poc", "class": "poc", "executor": "poc"},
    "weblogic_cve_2018_2628": {"module": "backend.poc.weblogic.cve_2018_2628_poc", "class": "poc", "executor": "poc"},
    "weblogic_cve_2018_2894": {"module": "backend.poc.weblogic.cve_2018_2894_poc", "class": "poc", "executor": "poc"},
    "weblogic_cve_2020_14756": {"module": "backend.poc.weblogic.cve_2020_14756_poc", "class": "poc", "executor": "poc"},
    "weblogic_cve_2023_21839": {"module": "backend.poc.weblogic.cve_2023_21839_poc", "class": "poc", "executor": "poc"},
    "struts2_009": {"module": "backend.poc.struts2.struts2_009_poc", "class": "poc", "executor": "poc"},
    "struts2_032": {"module": "backend.poc.struts2.struts2_032_poc", "class": "poc", "executor": "poc"},
    "tomcat_cve_2017_12615": {"module": "backend.poc.tomcat.cve_2017_12615_poc", "class": "poc", "executor": "poc"},
    "tomcat_cve_2022_22965": {"module": "backend.poc.tomcat.CVE-2022-22965", "class": "poc", "executor": "poc"},
    "tomcat_cve_2022_47986": {"module": "backend.poc.tomcat.CVE-2022-47986", "class": "poc", "executor": "poc"},
    "jboss_cve_2017_12149": {"module": "backend.poc.jboss.cve_2017_12149_poc", "class": "poc", "executor": "poc"},
    "nexus_cve_2020_10199": {"module": "backend.poc.nexus.cve_2020_10199_poc", "class": "poc", "executor": "poc"},
    "drupal_cve_2018_7600": {"module": "backend.poc.drupal.cve_2018_7600_poc", "class": "poc", "executor": "poc"},
    "thinkphp_99617": {"module": "backend.poc.thinkphp.poc_99617_ai", "class": "poc", "executor": "poc"},
}


class TaskExecutor:
    """
    任务执行器类
    
    功能:
    1. 任务队列管理 (串行执行)
    2. 幂等性检查 (防止重复提交)
    3. 全局超时控制
    4. 统一异常处理
    5. 多进程插件执行与管理
    6. 任务状态持久化
    7. 任务恢复功能
    8. 任务超时处理
    """
    
    def __init__(self):
        self.queue: asyncio.Queue = asyncio.Queue()
        self.queued_task_ids: Set[int] = set()
        self.cancelled_task_ids: Set[int] = set()
        self.running_task_id: Optional[int] = None
        self.task_processes: Dict[int, multiprocessing.Process] = {}
        self.task_heartbeats: Dict[int, float] = {}
        self.task_start_times: Dict[int, float] = {}
        self.task_timeouts: Dict[int, int] = {}
        
        self.is_running = True
        self.is_shutting_down = False
        self.worker_task = None
        self.current_execution_task = None
        
        self._ensure_state_dir()
        self._persisted_tasks: Dict[int, Dict] = self._load_task_states()
        
        logger.info(f"TaskExecutor initialized with {len(self._persisted_tasks)} persisted task states")

    def _ensure_state_dir(self):
        """确保状态目录存在"""
        state_dir = Path(TASK_STATE_FILE).parent
        state_dir.mkdir(parents=True, exist_ok=True)

    def _load_task_states(self) -> Dict[int, Dict]:
        """从文件加载任务状态"""
        try:
            if os.path.exists(TASK_STATE_FILE):
                with open(TASK_STATE_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return {int(k): v for k, v in data.items()}
        except Exception as e:
            logger.error(f"Failed to load task states: {e}")
        return {}

    def _save_task_states(self):
        """保存任务状态到文件"""
        try:
            with open(TASK_STATE_FILE, 'w', encoding='utf-8') as f:
                json.dump(self._persisted_tasks, f, ensure_ascii=False, default=str)
        except Exception as e:
            logger.error(f"Failed to save task states: {e}")

    def _persist_task_state(self, task_id: int, state: Dict):
        """持久化单个任务状态"""
        self._persisted_tasks[task_id] = {
            **state,
            "updated_at": datetime.utcnow().isoformat()
        }
        self._save_task_states()

    def _remove_task_state(self, task_id: int):
        """移除任务状态"""
        if task_id in self._persisted_tasks:
            del self._persisted_tasks[task_id]
            self._save_task_states()

    def _get_task_timeout(self, task_type: str, scan_config: Dict = None) -> int:
        """
        获取任务超时时间
        
        优先级:
        1. scan_config 中配置的超时时间
        2. task_type_registry 中注册的超时时间
        3. TASK_TIMEOUT_CONFIG 中的默认超时时间
        
        设置最小超时限制为 300 秒 (5分钟)
        """
        if scan_config and 'timeout' in scan_config:
            timeout = scan_config['timeout']
            if timeout < 300:
                logger.warning(f"[Timeout] 任务配置的超时时间 {timeout}秒太短，自动调整为 300秒")
                return max(timeout, 300)
            return timeout
        if scan_config and 'global_timeout' in scan_config:
            timeout = scan_config['global_timeout']
            if timeout < 300:
                logger.warning(f"[Timeout] 任务配置的全局超时时间 {timeout}秒太短，自动调整为 300秒")
                return max(timeout, 300)
            return timeout
        
        registry_timeout = task_type_registry.get_task_type_timeout(task_type)
        if registry_timeout and registry_timeout != 300:
            return registry_timeout
            
        return TASK_TIMEOUT_CONFIG.get(task_type, TASK_TIMEOUT_CONFIG['default'])

    async def reset_scan_data(self):
        """
        重置扫描数据 - 项目启动时清空所有扫描相关数据
        
        清空内容:
        - 所有任务记录
        - 所有扫描结果
        - 所有漏洞记录
        - 所有POC扫描结果
        - 所有报告记录
        """
        from backend.models import Task, ScanResult, Vulnerability, POCScanResult, Report
        
        logger.info("=" * 50)
        logger.info("开始重置扫描数据...")
        
        try:
            task_count = await Task.all().count()
            scan_result_count = await ScanResult.all().count()
            vuln_count = await Vulnerability.all().count()
            poc_count = await POCScanResult.all().count()
            report_count = await Report.all().count()
            
            logger.info(f"当前数据统计: 任务={task_count}, 扫描结果={scan_result_count}, 漏洞={vuln_count}, POC结果={poc_count}, 报告={report_count}")
            
            await POCScanResult.all().delete()
            logger.info("已清空 POC 扫描结果表")
            
            await Vulnerability.all().delete()
            logger.info("已清空漏洞表")
            
            await ScanResult.all().delete()
            logger.info("已清空扫描结果表")
            
            await Report.all().delete()
            logger.info("已清空报告表")
            
            await Task.all().delete()
            logger.info("已清空任务表")
            
            self.queued_task_ids.clear()
            self.cancelled_task_ids.clear()
            self.running_task_id = None
            self.task_processes.clear()
            self.task_heartbeats.clear()
            self.task_start_times.clear()
            self.task_timeouts.clear()
            self._persisted_tasks.clear()
            self._save_task_states()
            logger.info("已清空内存中的任务状态")
            
            while not self.queue.empty():
                try:
                    self.queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
            logger.info("已清空任务队列")
            
            logger.info("扫描数据重置完成")
            logger.info("=" * 50)
            
        except Exception as e:
            logger.error(f"重置扫描数据失败: {e}", exc_info=True)
            raise

    async def recover_pending_tasks(self):
        """
        恢复未完成的任务
        
        应用重启后，检查数据库中处于 pending/running 状态的任务，
        将其重新加入执行队列。
        """
        from backend.models import Task
        
        logger.info("=" * 50)
        logger.info("开始恢复未完成任务...")
        
        try:
            pending_tasks = await Task.filter(
                status__in=['pending', 'running', 'queued']
            ).order_by('created_at')
            
            recovered_count = 0
            for task in pending_tasks:
                try:
                    scan_config = json.loads(task.config) if task.config else {}
                    
                    task_state_logger.log_task_recovery(
                        task_id=task.id,
                        task_type=task.task_type,
                        status=task.status
                    )
                    
                    if task.status == 'running':
                        task.status = 'pending'
                        task.progress = 0
                        task.error_message = "Task interrupted by system restart, retrying..."
                        await task.save()
                    
                    await self.start_task(task.id, task.target, scan_config)
                    recovered_count += 1
                    
                except Exception as e:
                    logger.error(f"Failed to recover task {task.id}: {e}")
                    structured_logger.error(
                        "Task recovery failed",
                        task_id=task.id,
                        exc=e
                    )
            
            logger.info(f"任务恢复完成，共恢复 {recovered_count} 个任务")
            logger.info("=" * 50)
            
        except Exception as e:
            logger.error(f"任务恢复过程出错: {e}", exc_info=True)

    async def _publish_state_change(self, task_id: int, status: str, details: Dict = None):
        """
        发布状态变更消息 (MySQL + MQ + WebSocket)
        Requirement 3.3
        """
        # 1. MySQL is updated by caller usually, but we ensure consistency here if needed
        # (Caller handles DB save for now to avoid async race in critical paths)
        
        # 2. WebSocket
        payload = {
            "task_id": task_id,
            "status": status
        }
        if details:
            payload.update(details)
            
        await manager.broadcast({
            "type": "task_update",
            "payload": payload
        })

    def start_worker(self):
        """启动后台工作协程"""
        if self.worker_task is None or self.worker_task.done():
            self.worker_task = asyncio.create_task(self._worker())
            logger.info("任务执行器Worker已启动")

    async def start_task(self, task_id: Union[int, str], target: str, scan_config: Dict):
        """
        提交任务到执行队列
        
        Args:
            task_id: 任务ID
            target: 目标地址
            scan_config: 扫描配置
        """
        logger.info(f"[任务提交] 开始处理 | 任务ID: {task_id} | 目标: {target} | 配置: {scan_config}")
        
        if task_id in self.queued_task_ids:
            logger.warning(f"[任务提交] 任务已在队列中,忽略重复提交 | 任务ID: {task_id}")
            return
            
        if task_id == self.running_task_id:
            logger.warning(f"[任务提交] 任务正在执行中,忽略重复提交 | 任务ID: {task_id}")
            return

        task_info = {
            'task_id': task_id,
            'target': target,
            'scan_config': scan_config or {}
        }
        
        self.queued_task_ids.add(task_id)
        await self.queue.put(task_info)
        
        self._persist_task_state(task_id, {
            "status": "queued",
            "target": target,
            "scan_config": scan_config or {}
        })
        
        task_state_logger.log_task_created(
            task_id=task_id,
            task_type=scan_config.get('task_type', 'unknown') if scan_config else 'unknown',
            target=target
        )
        
        logger.info(f"[任务提交] 任务已添加到队列 | 任务ID: {task_id} | 队列位置: {self.queue.qsize()}")
        
        await manager.broadcast({
            "type": "task_update",
            "payload": {
                "task_id": task_id,
                "status": "queued",
                "queue_position": self.queue.qsize()
            }
        })
        
        self.start_worker()

    async def cancel_task(self, task_id: Union[int, str]) -> bool:
        """
        取消任务 (已废弃，请使用 abort_task)
        """
        self.abort_task(task_id)
        return True

    async def _worker(self):
        """后台工作协程: 串行消费队列"""
        while self.is_running:
            try:
                task_info = await self.queue.get()
                task_id = task_info['task_id']
                target = task_info.get('target', 'unknown')
                scan_config = task_info.get('scan_config', {})
                
                logger.info(f"[Worker] 获取到任务 | 任务ID: {task_id} | 目标: {target} | 队列剩余: {self.queue.qsize()}")
                
                if task_id in self.cancelled_task_ids:
                    logger.info(f"[Worker] 任务已被取消,跳过执行 | 任务ID: {task_id}")
                    self.cancelled_task_ids.discard(task_id)
                    self.queued_task_ids.discard(task_id)
                    self._remove_task_state(task_id)
                    self.queue.task_done()
                    continue

                self.queued_task_ids.discard(task_id)
                self.running_task_id = task_id
                self.task_start_times[task_id] = time.time()
                
                try:
                    from backend.models import Task
                    task = await Task.get(id=task_id)
                    task_type = task.task_type
                    timeout = self._get_task_timeout(task_type, scan_config)
                    self.task_timeouts[task_id] = timeout
                except:
                    timeout = self._get_task_timeout('default', scan_config)
                    self.task_timeouts[task_id] = timeout
                    task_type = 'unknown'
                
                self._persist_task_state(task_id, {
                    "status": "running",
                    "target": target,
                    "task_type": task_type if 'task_type' in dir() else 'unknown',
                    "timeout": timeout,
                    "started_at": datetime.utcnow().isoformat()
                })
                
                task_state_logger.log_task_started(
                    task_id=task_id,
                    task_type=task_type if 'task_type' in dir() else 'unknown',
                    target=target
                )
                
                try:
                    logger.info(f"[Worker] 开始处理任务 | 任务ID: {task_id} | 目标: {target} | 超时: {timeout}s")
                    
                    await manager.broadcast({
                        "type": "task_update",
                        "payload": {
                            "task_id": task_id,
                            "status": "running",
                            "progress": 0,
                            "timeout": timeout
                        }
                    })
                    logger.info(f"[Worker] 任务开始执行 | 任务ID: {task_id} | 目标: {target} | 超时: {timeout}s")
                    self.current_execution_task = asyncio.create_task(self._execute_wrapper(task_info))
                    
                    await asyncio.wait_for(
                        self.current_execution_task,
                        timeout=timeout
                    )
                    
                    duration = time.time() - self.task_start_times.get(task_id, time.time())
                    logger.info(f"[Worker] 任务执行成功 | 任务ID: {task_id} | 目标: {target} | 耗时: {duration:.2f}s")
                    task_state_logger.log_task_completed(
                        task_id=task_id,
                        duration=duration
                    )
                    
                    try:
                        from backend.models import Task
                        task = await Task.get(id=task_id)
                        result_data = {}
                        try:
                            result_data = json.loads(task.result) if task.result else {}
                        except:
                            pass
                        
                        await manager.broadcast({
                            "type": "task_completed",
                            "payload": {
                                "task_id": task_id,
                                "status": "completed",
                                "progress": 100,
                                "result": result_data,
                                "duration": duration
                            }
                        })
                    except Exception as e:
                        logger.error(f"Failed to broadcast task completion: {e}")
                    
                    self._remove_task_state(task_id)
                    
                except asyncio.TimeoutError:
                    duration = time.time() - self.task_start_times.get(task_id, time.time())
                    logger.error(f"[Worker] 任务执行超时 | 任务ID: {task_id} | 超时限制: {timeout}s | 实际耗时: {duration:.2f}s")
                    
                    task_state_logger.log_task_timeout(
                        task_id=task_id,
                        timeout_seconds=timeout
                    )
                    
                    if self.current_execution_task and not self.current_execution_task.done():
                        self.current_execution_task.cancel()
                        try:
                            await asyncio.wait_for(self.current_execution_task, timeout=5)
                        except:
                            pass
                    
                    await self._handle_task_timeout(task_id, timeout)
                    
                except asyncio.CancelledError:
                    logger.warning(f"[Worker] 任务被取消 | 任务ID: {task_id}")
                    
                    if task_id in self.cancelled_task_ids:
                        logger.info(f"[Worker] 确认任务已响应取消信号 | 任务ID: {task_id}")
                        self.cancelled_task_ids.discard(task_id)
                        task_state_logger.log_task_cancelled(task_id=task_id, reason="User requested")
                        self._remove_task_state(task_id)
                        try:
                            from backend.models import Task
                            task = await Task.get(id=task_id)
                            task.status = 'cancelled'
                            await task.save()
                        except:
                            pass
                    else:
                        raise
                        
                except Exception as e:
                    logger.error(f"[Worker] 任务执行发生未捕获异常 | 任务ID: {task_id} | 错误: {e}", exc_info=True)
                    structured_logger.error(
                        "Task execution error",
                        task_id=task_id,
                        exc=e
                    )
                    await self._handle_task_failure(task_id, f"System Error: {str(e)}")
                    self._remove_task_state(task_id)
                finally:
                    logger.info(f"[Worker] 任务处理完成,清理状态 | 任务ID: {task_id}")
                    self.running_task_id = None
                    self.current_execution_task = None
                    if task_id in self.task_start_times:
                        del self.task_start_times[task_id]
                    if task_id in self.task_timeouts:
                        del self.task_timeouts[task_id]
                    self.queue.task_done()
                    logger.info(f"[Worker] 任务状态已更新,任务完成 | 任务ID: {task_id} | 状态: completed")
                    
            except asyncio.CancelledError:
                logger.info("Worker被取消,停止运行")
                break
            except Exception as e:
                logger.error(f"Worker循环异常: {e}", exc_info=True)
                await asyncio.sleep(1)

    async def _handle_task_timeout(self, task_id: int, timeout_seconds: int):
        """处理任务超时"""
        try:
            from backend.models import Task
            task = await Task.get(id=task_id)
            task.status = 'failed'
            task.progress = task.progress or 0
            
            try:
                current_result = json.loads(task.result) if task.result else {}
            except:
                current_result = {}
                
            current_result['error'] = f"Task execution timed out after {timeout_seconds} seconds"
            current_result['timeout'] = True
            current_result['timeout_seconds'] = timeout_seconds
            task.result = json.dumps(current_result)
            
            await task.save()
            
            await manager.broadcast({
                "type": "task_completed",
                "payload": {
                    "task_id": task_id,
                    "status": "failed",
                    "error": f"Task timed out after {timeout_seconds}s",
                    "timeout": True
                }
            })
        except Exception as e:
            logger.error(f"更新任务 {task_id} 超时状态出错: {e}")

    async def _execute_wrapper(self, task_info: Dict):
        """
        任务执行分发包装器
        
        根据任务类型和执行器类型分发到对应的执行方法:
        - PLUGIN_EXECUTOR: execute_plugin_task
        - VULN_SCAN_MANAGER: execute_vuln_scan_task
        - POC_EXECUTOR: execute_poc_task
        - AWVS_EXECUTOR: execute_scan_task
        - AI_AGENT_EXECUTOR: execute_agent_task
        """
        task_id = task_info['task_id']
        target = task_info['target']
        scan_config = task_info['scan_config']
        
        try:
            from backend.models import Task
            task = await Task.get(id=task_id)
            task_type = task.task_type
            
            executor_type = task_type_registry.get_executor_type(task_type)
            
            logger.info(f"[TaskDispatcher] 任务 {task_id} 类型: {task_type}, 执行器: {executor_type}")
            
            if executor_type == ExecutorType.POC_EXECUTOR:
                await self.execute_poc_task(task_id, target, scan_config)
            elif executor_type == ExecutorType.AWVS_EXECUTOR:
                await self.execute_scan_task(task_id, target, scan_config)
            elif executor_type == ExecutorType.AI_AGENT_EXECUTOR:
                await self.execute_agent_task(task_id, target, scan_config)
            elif executor_type == ExecutorType.VULN_SCAN_MANAGER:
                await self.execute_vuln_scan_task(task_id, target, scan_config, task_type)
            elif executor_type == ExecutorType.PLUGIN_EXECUTOR:
                await self.execute_plugin_task(task_id, target, scan_config, task_type)
            elif executor_type == ExecutorType.CUSTOM_EXECUTOR:
                custom_executor = task_type_registry.get_executor_for_task_type(task_type)
                if custom_executor:
                    await custom_executor(task_id, target, scan_config)
                else:
                    logger.warning(f"任务类型 {task_type} 未注册自定义执行器，使用默认插件执行")
                    await self.execute_plugin_task(task_id, target, scan_config, task_type)
            else:
                if task_type in PLUGIN_TYPE_MAPPING:
                    await self.execute_plugin_task(task_id, target, scan_config, task_type)
                elif task_type in VULN_SCAN_PLUGIN_MAPPING:
                    await self.execute_vuln_scan_task(task_id, target, scan_config, task_type)
                elif task_type in POC_PLUGIN_MAPPING:
                    await self.execute_poc_task(task_id, target, scan_config)
                else:
                    logger.warning(f"未知任务类型 {task_type}, 任务ID: {task_id}，尝试使用默认插件执行")
                    await self.execute_plugin_task(task_id, target, scan_config, task_type)
        except Exception as e:
            logger.error(f"任务分发失败: {e}", exc_info=True)
            raise

    async def _handle_task_failure(self, task_id: int, error_msg: str, exc: Exception = None):
        """统一失败处理"""
        try:
            from backend.models import Task
            task = await Task.get(id=task_id)
            task.status = 'failed'
            task.progress = task.progress or 0
            
            try:
                current_result = json.loads(task.result) if task.result else {}
            except:
                current_result = {}
                
            current_result['error'] = error_msg
            if exc:
                current_result['error_type'] = type(exc).__name__
            task.result = json.dumps(current_result)
            
            await task.save()
            
            task_state_logger.log_task_failed(
                task_id=task_id,
                error=error_msg,
                exc=exc
            )
            
            await manager.broadcast({
                "type": "task_completed",
                "payload": {
                    "task_id": task_id,
                    "status": "failed",
                    "error": error_msg
                }
            })
        except Exception as e:
            logger.error(f"更新任务 {task_id} 失败状态出错: {e}")

    async def execute_agent_task(self, task_id: int, target: str, scan_config: Dict):
        """
        执行AI Agent扫描任务
        """
        from backend.models import Task, Vulnerability, Report
        from backend.ai_agents.core.state import AgentState
        from backend.ai_agents.core.graph import ScanAgentGraph
        
        task = await Task.get(id=task_id)
        task.status = 'running'
        task.progress = 5
        await task.save()
        
        logger.info(f"AI Agent任务 {task_id} 开始执行: {target}")

        async def broadcast_subgraph_progress(subgraph_type: str, status: str, progress: int, execution_time: float = 0):
            """广播子图进度更新"""
            await manager.broadcast({
                "type": "subgraph:progress",
                "payload": {
                    "task_id": task_id,
                    "subgraph_type": subgraph_type,
                    "status": status,
                    "progress": progress,
                    "execution_time": execution_time
                }
            })
        
        user_tools = scan_config.get('user_tools', [])
        user_requirement = scan_config.get('user_requirement', '')
        memory_info = scan_config.get('memory_info', '')
        strategy = scan_config.get('strategy', 'standard')
        concurrency = scan_config.get('concurrency', 5)
        timeout = scan_config.get('timeout', 300)
        selected_tools = scan_config.get('selected_tools', [])
        
        strategy_config = {
            'quick': {'max_depth': 2, 'timeout_per_stage': 60, 'max_tools': 3},
            'standard': {'max_depth': 3, 'timeout_per_stage': 120, 'max_tools': 5},
            'deep': {'max_depth': 5, 'timeout_per_stage': 300, 'max_tools': 10}
        }
        
        scan_params = strategy_config.get(strategy, strategy_config['standard'])
        logger.info(f"扫描策略: {strategy}, 并发数: {concurrency}, 超时: {timeout}s, 参数: {scan_params}")
        
        initial_state = AgentState(
            target=target,
            task_id=str(task_id),
            target_context={
                **scan_config,
                'strategy': strategy,
                'concurrency': concurrency,
                'timeout': timeout,
                'selected_tools': selected_tools,
                **scan_params
            },
            user_tools=user_tools or selected_tools,
            user_requirement=user_requirement,
            memory_info=memory_info
        )
        
        if scan_config and "custom_tasks" in scan_config and scan_config["custom_tasks"]:
            initial_state.planned_tasks = scan_config["custom_tasks"]
        
        agent_graph = ScanAgentGraph()
        
        await broadcast_subgraph_progress('planning', 'running', 0, 0)
        
        try:
            import time
            start_time = time.time()
            
            await broadcast_subgraph_progress('planning', 'running', 10, 0)
            
            state1 = await agent_graph.invoke_info_collection(initial_state)
            planning_time = time.time() - start_time
            await broadcast_subgraph_progress('planning', 'completed', 100, planning_time)
            logger.info(f"[Task {task_id}] 信息收集子图完成, 耗时: {planning_time:.2f}s")
            
            task.progress = 30
            await task.save()
            await manager.broadcast({
                "type": "task_progress",
                "payload": {"task_id": task_id, "progress": 30, "status": "running"}
            })
            
            await broadcast_subgraph_progress('tool_execution', 'running', 0, 0)
            vuln_scan_start = time.time()
            
            state2 = await agent_graph.invoke_vuln_scan(state1)
            vuln_scan_time = time.time() - vuln_scan_start
            await broadcast_subgraph_progress('tool_execution', 'completed', 100, vuln_scan_time)
            logger.info(f"[Task {task_id}] 漏洞扫描子图完成, 耗时: {vuln_scan_time:.2f}s")
            
            task.progress = 60
            await task.save()
            await manager.broadcast({
                "type": "task_progress",
                "payload": {"task_id": task_id, "progress": 60, "status": "running"}
            })
            
            await broadcast_subgraph_progress('poc_verification', 'running', 0, 0)
            poc_start = time.time()
            
            state3 = await agent_graph.invoke_poc_verification(state2)
            poc_time = time.time() - poc_start
            await broadcast_subgraph_progress('poc_verification', 'completed', 100, poc_time)
            logger.info(f"[Task {task_id}] POC验证子图完成, 耗时: {poc_time:.2f}s")
            
            task.progress = 80
            await task.save()
            await manager.broadcast({
                "type": "task_progress",
                "payload": {"task_id": task_id, "progress": 80, "status": "running"}
            })
            
            await broadcast_subgraph_progress('report', 'running', 0, 0)
            report_start = time.time()
            
            final_state = await agent_graph.invoke_result_analysis(state3)
            report_time = time.time() - report_start
            await broadcast_subgraph_progress('report', 'completed', 100, report_time)
            logger.info(f"[Task {task_id}] 报告生成子图完成, 耗时: {report_time:.2f}s")
            
        except Exception as e:
            logger.error(f"[Task {task_id}] Agent执行失败: {e}", exc_info=True)
            await broadcast_subgraph_progress('planning', 'failed', 0, 0)
            raise
        
        task.status = 'completed'
        task.progress = 100
        
        def get_state_value(state, key, default):
            if state is None:
                return default
            if isinstance(state, dict):
                return state.get(key, default)
            return getattr(state, key, default)

        scan_summary = get_state_value(final_state, 'scan_summary', {})
        vulnerabilities = get_state_value(final_state, 'vulnerabilities', [])
        report_content = get_state_value(final_state, 'report', "")
        
        history_data = get_state_value(final_state, 'execution_history', [])
        execution_history = [
            {
                "node": h.get("node", "") if isinstance(h, dict) else getattr(h, "node", ""),
                "action": h.get("action", "") if isinstance(h, dict) else getattr(h, "action", ""),
                "result": sanitize_json_data(h.get("result", "") if isinstance(h, dict) else getattr(h, "result", "")),
                "timestamp": h.get("timestamp", "") if isinstance(h, dict) else getattr(h, "timestamp", "")
            } for h in history_data
        ]
        
        tool_results = get_state_value(final_state, 'tool_results', {})
        target_context = get_state_value(final_state, 'target_context', {})
        stage_status = get_state_value(final_state, 'stage_status', {})

        logger.info(f"[Task {task_id}] 开始生成完整报告，使用 report_service...")
        
        try:
            report_data = await report_service.generate_report(
                task_id=str(task_id),
                task_name=task.task_name,
                target=target,
                vulnerabilities=vulnerabilities,
                execution_history=execution_history,
                tool_results=tool_results,
                target_context=target_context,
                include_ai_analysis=True,
                scan_time=str(task.created_at)
            )
            
            report_id = await report_service.save_report_to_db(
                report_data=report_data,
                task_id=task_id,
                report_name=f"Scan Report - {target}",
                report_type="json"
            )
            
            logger.info(f"[Task {task_id}] 报告生成完成 | 报告ID: {report_id} | 风险评分: {report_data.risk_assessment.score}")
            
        except Exception as e:
            logger.error(f"[Task {task_id}] 报告生成失败: {e}", exc_info=True)
            report_id = None
            report_data = None

        result_data = {
            "report_id": report_id,
            "scan_summary": scan_summary,
            "vulnerabilities": vulnerabilities,
            "report": report_content,
            "execution_history": execution_history,
            "tool_results": tool_results,
            "stages": stage_status
        }
        
        if report_data:
            result_data["risk_assessment"] = report_data.risk_assessment.to_dict()
            result_data["summary"] = report_data.summary.to_dict()
            if report_data.ai_analysis:
                result_data["ai_analysis"] = report_data.ai_analysis.to_dict()
        
        result_data = sanitize_json_data(result_data)
        
        task.result = json.dumps(result_data, default=str)
        await task.save()
        
        for vuln in vulnerabilities:
            try:
                await Vulnerability.create(
                    task=task,
                    vuln_type=vuln.get('type', 'Unknown'),
                    severity=self.standardize_severity(vuln.get('severity', 'Info')),
                    title=vuln.get('title', 'Unknown Vulnerability'),
                    description=vuln.get('description', ''),
                    url=vuln.get('url', target),
                    payload=vuln.get('payload', ''),
                    evidence=vuln.get('evidence', ''),
                    remediation=vuln.get('remediation', ''),
                    source='ai_agent'
                )
            except Exception as e:
                logger.error(f"Failed to save vulnerability: {e}")

        if report_content and not report_id:
            try:
                await Report.create(
                    task=task,
                    report_name=f"Scan Report - {target}",
                    report_type="markdown",
                    content=report_content
                )
            except Exception as e:
                logger.error(f"Failed to save report: {e}")
        
        logger.info(f"AI Agent任务 {task_id} 执行完成")
        
        await self._create_task_notification(
            task_id=task_id,
            task_name=task.task_name,
            task_type='ai_agent_scan',
            status='completed',
            target=target,
            vuln_count=len(vulnerabilities)
        )
        
        execution_time = time.time() - start_time
        
        broadcast_payload = {
            "task_id": task_id,
            "status": "completed",
            "progress": 100,
            "result": result_data,
            "stages": stage_status,
            "scan_summary": scan_summary,
            "final_output": result_data,
            "vulnerabilities": vulnerabilities,
            "report": report_content,
            "target_context": initial_state.target_context if hasattr(initial_state, 'target_context') else scan_config,
            "execution_history": execution_history,
            "execution_time": execution_time
        }
        
        if report_data:
            broadcast_payload["report_data"] = {
                "id": report_id,
                "summary": report_data.summary.to_dict(),
                "risk_assessment": report_data.risk_assessment.to_dict(),
                "ai_analysis": report_data.ai_analysis.to_dict() if report_data.ai_analysis else None
            }
        
        await manager.broadcast({
            "type": "task_completed",
            "payload": broadcast_payload
        })

    def standardize_severity(self, severity_val) -> str:
        """标准化严重程度 (Title Case)"""
        if isinstance(severity_val, int):
            if severity_val >= 4: return 'Critical'
            if severity_val == 3: return 'High'
            if severity_val == 2: return 'Medium'
            if severity_val == 1: return 'Low'
            return 'Info'
        
        if isinstance(severity_val, str):
            s = severity_val.lower()
            if s == 'critical': return 'Critical'
            if s == 'high': return 'High'
            if s == 'medium': return 'Medium'
            if s == 'low': return 'Low'
            if s == 'info': return 'Info'
            return severity_val.capitalize()
        
        return 'Info'

    async def _generate_and_save_report(
        self,
        task_id: int,
        task_name: str,
        target: str,
        task_type: str,
        scan_result: Dict[str, Any],
        scan_config: Dict[str, Any] = None,
        include_ai_analysis: bool = True
    ) -> Optional[int]:
        """
        统一的报告生成和保存方法
        
        Args:
            task_id: 任务ID
            task_name: 任务名称
            target: 目标地址
            task_type: 任务类型
            scan_result: 扫描结果
            scan_config: 扫描配置
            include_ai_analysis: 是否包含AI分析
            
        Returns:
            Optional[int]: 报告ID，失败返回None
        """
        try:
            logger.info(f"[Report] 开始为任务 {task_id} 生成报告...")
            
            vulnerabilities = []
            if scan_result:
                if 'vulnerabilities' in scan_result:
                    vulns_data = scan_result.get('vulnerabilities', [])
                    for vuln in vulns_data:
                        if isinstance(vuln, dict):
                            vulnerabilities.append({
                                'type': vuln.get('vuln_type', vuln.get('type', 'Unknown')),
                                'severity': self.standardize_severity(vuln.get('severity', 'info')),
                                'title': vuln.get('title', vuln.get('name', 'Unknown Vulnerability')),
                                'description': vuln.get('description', ''),
                                'url': vuln.get('url', target),
                                'payload': vuln.get('payload', ''),
                                'evidence': vuln.get('evidence', ''),
                                'remediation': vuln.get('remediation', vuln.get('solution', ''))
                            })
                elif 'details' in scan_result:
                    for detail in scan_result.get('details', []):
                        if detail.get('vulnerable'):
                            vulnerabilities.append({
                                'type': detail.get('poc_type', 'POC'),
                                'severity': self.standardize_severity(detail.get('severity', 'high')),
                                'title': f"POC验证: {detail.get('poc_type', 'Unknown')}",
                                'description': detail.get('output', ''),
                                'url': target,
                                'payload': '',
                                'evidence': detail.get('output', ''),
                                'remediation': ''
                            })
            
            execution_history = []
            if scan_result and 'execution_history' in scan_result:
                execution_history = scan_result['execution_history']
            
            tool_results = {}
            if scan_result:
                tool_results = {
                    'scan_summary': scan_result.get('scan_summary', {}),
                    'scan_details': scan_result.get('scan_details', {}),
                    'total': scan_result.get('total', 0),
                    'vulnerable_count': scan_result.get('vulnerable_count', 0)
                }
            
            target_context = {
                'target': target,
                'task_type': task_type,
                'scan_config': scan_config or {},
                'vuln_types_scanned': scan_result.get('vuln_types_scanned', []) if scan_result else [],
                'poc_types': scan_result.get('scan_config', {}).get('poc_types', []) if scan_result else []
            }
            
            report_data = await report_service.generate_report(
                task_id=str(task_id),
                task_name=task_name,
                target=target,
                vulnerabilities=vulnerabilities,
                execution_history=execution_history,
                tool_results=tool_results,
                target_context=target_context,
                include_ai_analysis=include_ai_analysis,
                scan_time=datetime.utcnow().isoformat()
            )
            
            report_id = await report_service.save_report_to_db(
                report_data=report_data,
                task_id=task_id,
                report_name=f"{task_type.upper()} Report - {target}",
                report_type="json"
            )
            
            logger.info(f"[Report] 任务 {task_id} 报告生成成功 | 报告ID: {report_id} | 风险评分: {report_data.risk_assessment.score}")
            
            return report_id
            
        except Exception as e:
            logger.error(f"[Report] 任务 {task_id} 报告生成失败: {e}", exc_info=True)
            return None
    
    async def _create_task_notification(self, task_id: int, task_name: str, task_type: str, status: str, target: str = '', vuln_count: int = 0, error: str = ''):
        """创建任务完成/失败通知 (使用服务层封装)"""
        await notification_service.create_task_notification(
            task_id=task_id,
            task_name=task_name,
            task_type=task_type,
            status=status,
            target=target,
            vuln_count=vuln_count,
            error=error,
            user_id=1
        )
    
    async def execute_scan_task(self, task_id: int, target: str, scan_config: Dict):
        """
        执行AWVS扫描任务并实时更新进度
        """
        try:
            from backend.models import Task
            from AVWS.API.Target import Target
            from AVWS.API.Scan import Scan
            from backend.config import settings
            
            task = await Task.get(id=task_id)
            
            target_client = Target(settings.AWVS_API_URL, settings.AWVS_API_KEY)
            scan_client = Scan(settings.AWVS_API_URL, settings.AWVS_API_KEY)
            
            current_config = json.loads(task.config) if task.config else {}
            existing_scan_id = current_config.get('awvs_scan_id') or current_config.get('scan_id')
            existing_target_id = current_config.get('awvs_target_id') or current_config.get('target_id')
            
            if existing_scan_id:
                logger.info(f"任务 {task_id} 恢复监控现有AWVS扫描: {existing_scan_id}")
                task.status = 'running'
                await task.save()
                await self._monitor_scan_progress(task_id, existing_scan_id, scan_client)
                return
            
            task.status = 'running'
            task.progress = 5
            await task.save()
            logger.info(f"任务 {task_id} 开始执行: {target}")
            
            target_desc = f"Task {task_id}: {task.task_name}"
            target_id = target_client.add(target, target_desc)
            
            if not target_id:
                task.status = 'failed'
                task.progress = 0
                task.error_message = "Failed to create AWVS target"
                await task.save()
                logger.error(f"任务 {task_id} 创建目标失败")
                return
            
            logger.info(f"任务 {task_id} 创建AWVS目标成功: {target_id}")
            
            current_config['awvs_target_id'] = target_id
            current_config['target_id'] = target_id
            task.config = json.dumps(current_config)
            
            task.progress = 10
            await task.save()
            
            scan_profile = scan_config.get('profile', 'full_scan')
            scan_id = scan_client.add(target_id, scan_profile)
            
            if not scan_id:
                task.status = 'failed'
                task.progress = 0
                await task.save()
                logger.error(f"任务 {task_id} 启动扫描失败")
                return
            
            logger.info(f"任务 {task_id} 启动AWVS扫描成功, ID: {scan_id}")
            
            task.progress = 20
            
            current_config['awvs_scan_id'] = scan_id
            current_config['scan_id'] = scan_id
            task.config = json.dumps(current_config)
            await task.save()
            
            await self._monitor_scan_progress(task_id, scan_id, scan_client)
            
        except Exception as e:
            logger.error(f"任务 {task_id} 执行失败: {str(e)}", exc_info=True)
            try:
                from backend.models import Task
                task = await Task.get(id=task_id)
                task.status = 'failed'
                task.progress = 0
                await task.save()
            except:
                pass
    
    async def _monitor_scan_progress(self, task_id: int, scan_id: str, scan_client):
        """监控扫描进度"""
        from backend.models import Task
        
        last_progress = 20
        no_change_count = 0
        max_no_change = 360  # 30分钟无变化才超时 (360 * 5s = 1800s)
        consecutive_errors = 0
        max_consecutive_errors = 10
        
        while self.is_running:
            try:
                loop = asyncio.get_running_loop()
                # 使用 to_thread 避免阻塞事件循环
                scan_info = await loop.run_in_executor(None, scan_client.get, scan_id)
                
                if not scan_info:
                    consecutive_errors += 1
                    logger.warning(f"任务 {task_id} 获取扫描状态失败 ({consecutive_errors}/{max_consecutive_errors})")
                    if consecutive_errors >= max_consecutive_errors:
                        logger.error(f"任务 {task_id} 获取扫描状态连续失败, 停止监控")
                        break
                    await asyncio.sleep(5)
                    continue
                
                # 重置错误计数
                consecutive_errors = 0
                
                progress = self._calculate_progress(scan_info)
                
                if progress == last_progress:
                    no_change_count += 1
                else:
                    no_change_count = 0
                    last_progress = progress
                
                task = await Task.get(id=task_id)
                scan_status = scan_info.get('status', 'unknown')
                
                if scan_status == 'completed':
                    task.status = 'completed'
                    task.progress = 100
                    await task.save()
                    logger.info(f"任务 {task_id} 扫描完成")
                    await self._save_scan_results(task_id, scan_id, scan_client)
                    
                    vuln_count = scan_info.get('vulnerabilities_count', 0)
                    await self._create_task_notification(
                        task_id=task_id,
                        task_name=task.task_name,
                        task_type='awvs_scan',
                        status='completed',
                        target=task.target,
                        vuln_count=vuln_count
                    )

                    try:
                        result_data = json.loads(task.result) if task.result else {}
                        await self._generate_and_save_report(
                            task_id=task_id,
                            task_name=task.task_name,
                            target=task.target,
                            task_type='awvs_scan',
                            scan_result=result_data,
                            scan_config=json.loads(task.config) if task.config else {},
                            include_ai_analysis=True
                        )
                    except Exception as report_error:
                        logger.error(f"[AWVS] 任务 {task_id} 报告生成异常: {report_error}", exc_info=True)

                    await manager.broadcast({
                        "type": "task_completed",
                        "payload": {
                            "task_id": task_id,
                            "status": "completed",
                            "progress": 100,
                            "result": json.loads(task.result) if task.result else {}
                        }
                    })
                    break
                elif scan_status == 'failed':
                    task.status = 'failed'
                    task.progress = last_progress
                    await task.save()
                    logger.error(f"任务 {task_id} 扫描失败")
                    
                    await self._create_task_notification(
                        task_id=task_id,
                        task_name=task.task_name,
                        task_type='awvs_scan',
                        status='failed',
                        target=task.target,
                        error='AWVS扫描失败'
                    )
                    
                    await manager.broadcast({
                        "type": "task_completed",
                        "payload": {
                            "task_id": task_id,
                            "status": "failed",
                            "error": "Scan failed in AWVS"
                        }
                    })
                    break
                elif scan_status == 'processing':
                    task.progress = progress
                    await task.save()
                    logger.info(f"任务 {task_id} 进度: {progress}%")
                    
                    # 广播进度更新
                    await manager.broadcast({
                        "type": "task_progress",
                        "payload": {
                            "task_id": task_id,
                            "progress": progress,
                            "status": "running"
                        }
                    })
                elif scan_status == 'scheduled':
                    task.progress = 20
                    await task.save()
                    logger.info(f"任务 {task_id} 等待开始...")
                
                if no_change_count >= max_no_change:
                    # AWVS 可能会在某个进度停留很久, 30分钟无变化再判定为超时
                    # 即使超时, 也尝试保存结果
                    task.status = 'completed' # 或者 failed? 视业务逻辑而定,这里保持原逻辑但增加日志
                    task.progress = 100
                    await task.save()
                    logger.warning(f"任务 {task_id} 扫描进度长时间({max_no_change*5}s)无变化, 强制完成")
                    await self._save_scan_results(task_id, scan_id, scan_client)
                    
                    await manager.broadcast({
                        "type": "task_completed",
                        "payload": {
                            "task_id": task_id,
                            "status": "completed",
                            "progress": 100,
                            "note": "completed_by_timeout",
                            "result": json.loads(task.result) if task.result else {}
                        }
                    })
                    break
                
                await asyncio.sleep(5)
                
            except Exception as e:
                logger.error(f"任务 {task_id} 监控进度失败: {str(e)}", exc_info=True)
                await asyncio.sleep(5)

    def _calculate_progress(self, scan_info: Dict) -> int:
        status = scan_info.get('status', 'unknown')
        if status == 'scheduled':
            return 20
        elif status == 'processing':
            requests_count = scan_info.get('requests_count', 0)
            processed_requests = scan_info.get('processed_requests_count', 0)
            if requests_count > 0:
                progress = int((processed_requests / requests_count) * 80) + 20
                return min(progress, 95)
            else:
                return 30
        elif status == 'completed':
            return 100
        elif status == 'failed':
            return 0
        else:
            return 20

    # INSPECTION:检查扫描结果是否完整
    async def _save_scan_results(self, task_id: int, scan_id: str, scan_client):
        try:
            from backend.models import Task, Vulnerability
            from backend.api.tasks import standardize_severity

            scan_info = scan_client.get(scan_id)
            if not scan_info:
                return
            
            vulnerabilities_summary = []
            scan_session_id = scan_info.get('current_session', {}).get('scan_session_id')
            
            if scan_session_id:
                vulns = scan_client.get_vulns(scan_id, scan_session_id)
                if vulns:
                    # 获取现有漏洞记录以避免重复 (根据 vuln_id)
                    existing_vulns = await Vulnerability.filter(task_id=task_id).values_list('title', flat=True) # 使用title作为简单去重,实际应存vuln_id
                    # 由于Vulnerability模型目前没有 awvs_vuln_id 字段,我们暂时用 title 和 url 组合判断,或者直接清空重建
                    # 为了安全起见,我们先删除该任务的所有旧漏洞记录,重新保存
                    await Vulnerability.filter(task_id=task_id).delete()
                    
                    for vuln in vulns:
                        # 1. 保存到 vulnerabilities_summary 用于 task.result (保持兼容)
                        severity_val = vuln.get('severity')
                        severity_str = standardize_severity(severity_val)
                        
                        vulnerabilities_summary.append({
                            'severity': severity_str, # Use standardized severity string
                            'name': vuln.get('vt_name'),
                            'count': vuln.get('count', 0)
                        })
                        
                        # 2. 保存到 Vulnerability 表 (详细存储)
                        
                        # 处理标题前缀
                        vt_name = vuln.get('vt_name', 'Unknown')
                        if 'SQL Injection' in vt_name and not vt_name.startswith('[SQL'):
                            vt_name = f"[SQL Injection] {vt_name}"
                        elif 'XSS' in vt_name and not vt_name.startswith('[XSS'):
                            vt_name = f"[XSS] {vt_name}"
                        
                        # 确保 url 字段存在
                        affects_url = vuln.get('affects_url', '')
                        if not affects_url:
                            affects_url = task.target

                        await Vulnerability.create(
                            task_id=task_id,
                            vuln_type=vuln.get('vt_name'), # 原始类型
                            severity=severity_str,
                            title=vt_name,
                            description=vuln.get('description', ''),
                            url=affects_url,
                            status=vuln.get('status', 'open'),
                            source_id=vuln.get('vuln_id')
                        )

            result_data = {
                'scan_id': scan_id,
                'scan_status': scan_info.get('status'),
                'start_time': scan_info.get('start_time'),
                'end_time': scan_info.get('end_time'),
                'requests_count': scan_info.get('requests_count', 0),
                'vulnerabilities_count': scan_info.get('vulnerabilities_count', 0),
                'vulnerabilities': vulnerabilities_summary
            }
            
            task = await Task.get(id=task_id)
            task.result = json.dumps(result_data)
            await task.save()
            logger.info(f"任务 {task_id} 保存扫描结果成功 (包含详细漏洞记录)")
        except Exception as e:
            logger.error(f"任务 {task_id} 保存扫描结果失败: {str(e)}", exc_info=True)

    async def execute_poc_task(self, task_id: int, target: str, scan_config: Dict):
        """
        执行POC扫描任务 (Dynamic Engine Integrated)
        
        支持多种 POC 验证模式:
        1. 单个 POC 验证: scan_config 中指定单个 poc_type
        2. 批量 POC 验证: scan_config 中指定 poc_types 列表
        3. 漏洞列表验证: scan_config 中指定 vulnerabilities 列表
        4. 知识库 POC 验证: 从 VulnerabilityKB 加载 POC
        
        Args:
            task_id: 任务ID
            target: 目标URL
            scan_config: 扫描配置，支持以下字段:
                - poc_type: 单个POC类型 (如 'weblogic_cve_2020_2551')
                - poc_types: POC类型列表 (如 ['weblogic', 'struts2'])
                - vulnerabilities: 漏洞信息列表
                - use_dynamic_engine: 是否使用动态引擎 (默认True)
                - batch_size: 批量验证时的批次大小 (默认5)
        """
        try:
            from backend.models import Task, POCScanResult, VulnerabilityKB, Vulnerability
            from tortoise.expressions import Q
            
            task = await Task.get(id=task_id)
            task.status = 'running'
            task.progress = 5
            await task.save()
            
            start_time = time.time()
            use_dynamic_engine = scan_config.get('use_dynamic_engine', True)
            batch_size = scan_config.get('batch_size', 5)
            
            logger.info(f"[POC] 开始 POC 验证任务 {task_id}, 目标: {target}")
            
            vulns_to_verify = []
            poc_types_to_run = []
            
            if 'vulnerabilities' in scan_config and scan_config['vulnerabilities']:
                vulns_to_verify = scan_config['vulnerabilities']
                logger.info(f"[POC] 任务 {task_id}: 从漏洞列表加载 {len(vulns_to_verify)} 个漏洞")
            
            elif 'poc_type' in scan_config and scan_config['poc_type']:
                poc_type = scan_config['poc_type']
                if poc_type in POC_PLUGIN_MAPPING:
                    poc_types_to_run = [poc_type]
                else:
                    matching_types = [pt for pt in POC_PLUGIN_MAPPING.keys() if poc_type.lower() in pt.lower()]
                    poc_types_to_run = matching_types if matching_types else [poc_type]
                logger.info(f"[POC] 任务 {task_id}: 单个 POC 类型 {poc_types_to_run}")
            
            elif 'poc_types' in scan_config:
                requested_pocs = scan_config['poc_types']
                use_all = not requested_pocs or 'all' in requested_pocs
                
                if use_all:
                    poc_types_to_run = list(POC_PLUGIN_MAPPING.keys())
                    kb_pocs = await VulnerabilityKB.filter(has_poc=True).all()
                    for kb in kb_pocs:
                        vulns_to_verify.append({
                            "title": kb.name,
                            "cve_id": kb.cve_id,
                            "description": kb.description,
                            "severity": kb.severity,
                            "poc_code": kb.poc_code
                        })
                else:
                    for req in requested_pocs:
                        if req in POC_PLUGIN_MAPPING:
                            poc_types_to_run.append(req)
                        else:
                            matching_types = [pt for pt in POC_PLUGIN_MAPPING.keys() if req.lower() in pt.lower()]
                            poc_types_to_run.extend(matching_types)
                            
                            items = await VulnerabilityKB.filter(Q(name=req) | Q(cve_id=req)).all()
                            for kb in items:
                                vulns_to_verify.append({
                                    "title": kb.name,
                                    "cve_id": kb.cve_id,
                                    "description": kb.description,
                                    "severity": kb.severity,
                                    "poc_code": kb.poc_code
                                })
                
                logger.info(f"[POC] 任务 {task_id}: 批量 POC 类型 {poc_types_to_run}, 知识库 POC {len(vulns_to_verify)} 个")
            
            else:
                poc_types_to_run = list(POC_PLUGIN_MAPPING.keys())
                logger.info(f"[POC] 任务 {task_id}: 未指定 POC 类型，运行所有 {len(poc_types_to_run)} 个 POC")
            
            task.progress = 10
            await task.save()
            
            results_summary = []
            vulnerable_count = 0
            total_items = len(vulns_to_verify) + len(poc_types_to_run)
            completed_count = 0
            
            if poc_types_to_run:
                logger.info(f"[POC] 任务 {task_id}: 开始执行 {len(poc_types_to_run)} 个内置 POC")
                
                for i in range(0, len(poc_types_to_run), batch_size):
                    if not self.is_running:
                        break
                    
                    batch = poc_types_to_run[i:i+batch_size]
                    batch_tasks = []
                    
                    for poc_type in batch:
                        batch_tasks.append(self._execute_single_poc(poc_type, target, task))
                    
                    batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
                    
                    for result in batch_results:
                        if isinstance(result, Exception):
                            logger.error(f"[POC] 任务 {task_id} POC 执行异常: {result}")
                            continue
                        
                        results_summary.append(result)
                        if result.get('vulnerable'):
                            vulnerable_count += 1
                            try:
                                await POCScanResult.create(
                                    task=task,
                                    poc_type=result.get('poc_type', 'unknown'),
                                    target=target,
                                    vulnerable=True,
                                    message=str(result.get('output', ''))[:500],
                                    severity=result.get('severity', 'High'),
                                    cve_id=result.get('cve_id')
                                )
                            except Exception as e:
                                logger.error(f"[POC] 保存 POCScanResult 失败: {e}")
                    
                    completed_count += len(batch)
                    progress = 10 + int((completed_count / total_items) * 80) if total_items > 0 else 90
                    task.progress = min(progress, 90)
                    await task.save()
            
            if vulns_to_verify and use_dynamic_engine:
                logger.info(f"[POC] 任务 {task_id}: 开始使用动态引擎验证 {len(vulns_to_verify)} 个漏洞")
                
                for i in range(0, len(vulns_to_verify), batch_size):
                    if not self.is_running:
                        break
                    
                    batch = vulns_to_verify[i:i+batch_size]
                    batch_tasks = []
                    
                    for vuln in batch:
                        if isinstance(vuln, dict):
                            batch_tasks.append(dynamic_engine.verify_vulnerability(target, vuln))
                    
                    if not batch_tasks:
                        continue
                    
                    batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
                    
                    for result in batch_results:
                        if isinstance(result, Exception):
                            logger.error(f"[POC] 任务 {task_id} 动态验证异常: {result}")
                            continue
                        
                        results_summary.append(result)
                        if result.get('vulnerable'):
                            vulnerable_count += 1
                            try:
                                await POCScanResult.create(
                                    task=task,
                                    poc_type=result.get('poc_id', 'dynamic'),
                                    target=target,
                                    vulnerable=True,
                                    message=str(result.get('output', ''))[:500],
                                    severity='High',
                                    cve_id=result.get('cve_id')
                                )
                            except Exception as e:
                                logger.error(f"[POC] 保存动态验证结果失败: {e}")
                    
                    completed_count += len(batch)
                    progress = 10 + int((completed_count / total_items) * 80) if total_items > 0 else 90
                    task.progress = min(progress, 90)
                    await task.save()
            
            duration = time.time() - start_time
            
            result_data = {
                'total': total_items,
                'vulnerable_count': vulnerable_count,
                'safe_count': total_items - vulnerable_count,
                'details': results_summary,
                'duration_seconds': round(duration, 2),
                'scan_config': {
                    'target': target,
                    'poc_types': poc_types_to_run,
                    'use_dynamic_engine': use_dynamic_engine
                }
            }
            
            task.status = 'completed'
            task.progress = 100
            task.result = json.dumps(result_data, default=str)
            await task.save()
            
            logger.info(f"[POC] 任务 {task_id} 完成, 发现 {vulnerable_count} 个漏洞, 耗时 {duration:.2f}秒")
            
            await self._create_task_notification(
                task_id=task_id,
                task_name=task.task_name,
                task_type='poc_scan',
                status='completed',
                target=target,
                vuln_count=vulnerable_count
            )
            
            await manager.broadcast({
                "type": "task_completed",
                "payload": {
                    "task_id": task_id,
                    "status": "completed",
                    "progress": 100,
                    "result": result_data,
                    "duration": duration
                }
            })
            
            try:
                await self._generate_and_save_report(
                    task_id=task_id,
                    task_name=task.task_name,
                    target=target,
                    task_type='poc_scan',
                    scan_result=result_data,
                    scan_config=scan_config,
                    include_ai_analysis=True
                )
            except Exception as report_error:
                logger.error(f"[POC] 任务 {task_id} 报告生成异常: {report_error}", exc_info=True)
            
        except Exception as e:
            logger.error(f"[POC] 任务 {task_id} 执行失败: {e}", exc_info=True)
            await self._handle_task_failure(task_id, str(e), e)

    async def _execute_single_poc(self, poc_type: str, target: str, task) -> Dict:
        """
        执行单个 POC 验证
        
        Args:
            poc_type: POC 类型
            target: 目标 URL
            task: 任务对象
            
        Returns:
            Dict: 验证结果
        """
        import importlib
        
        result = {
            "poc_type": poc_type,
            "target": target,
            "vulnerable": False,
            "output": "",
            "error": None
        }
        
        try:
            if poc_type in POC_PLUGIN_MAPPING:
                poc_info = POC_PLUGIN_MAPPING[poc_type]
                module_path = poc_info['module']
                class_name = poc_info['class']
                
                module = importlib.import_module(module_path)
                poc_func = getattr(module, class_name)
                
                if callable(poc_func):
                    poc_result = poc_func(target)
                    
                    if isinstance(poc_result, tuple) and len(poc_result) == 2:
                        is_vuln, message = poc_result
                        result['vulnerable'] = bool(is_vuln)
                        result['output'] = str(message)
                    elif isinstance(poc_result, dict):
                        result['vulnerable'] = poc_result.get('vulnerable', False)
                        result['output'] = poc_result.get('output', '')
                        result['error'] = poc_result.get('error')
                    elif isinstance(poc_result, bool):
                        result['vulnerable'] = poc_result
                        result['output'] = "Vulnerable" if poc_result else "Safe"
                else:
                    result['error'] = f"POC {class_name} 不是可调用对象"
            else:
                result['error'] = f"未知的 POC 类型: {poc_type}"
                
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"[POC] 执行 POC {poc_type} 失败: {e}")
        
        return result

    async def execute_batch_poc_verification(self, task_id: int, targets: List[str], scan_config: Dict):
        """
        执行批量 POC 验证 (多目标)
        
        对多个目标执行相同的 POC 验证
        
        Args:
            task_id: 任务ID
            targets: 目标URL列表
            scan_config: 扫描配置
        """
        from backend.models import Task
        
        task = await Task.get(id=task_id)
        task.status = 'running'
        task.progress = 5
        await task.save()
        
        poc_types = scan_config.get('poc_types', list(POC_PLUGIN_MAPPING.keys()))
        max_concurrent = scan_config.get('max_concurrent', 3)
        
        logger.info(f"[BatchPOC] 任务 {task_id} 开始批量验证 {len(targets)} 个目标, POC 类型: {poc_types}")
        
        all_results = {}
        completed_count = 0
        total_count = len(targets)
        
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def verify_single_target(target: str):
            async with semaphore:
                try:
                    single_config = {**scan_config, 'poc_types': poc_types}
                    target_results = []
                    for poc_type in poc_types:
                        result = await self._execute_single_poc(poc_type, target, task)
                        target_results.append(result)
                    return target, target_results
                except Exception as e:
                    logger.error(f"[BatchPOC] 验证目标 {target} 失败: {e}")
                    return target, []
        
        tasks = [verify_single_target(t) for t in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"[BatchPOC] 任务异常: {result}")
                continue
            target, target_results = result
            all_results[target] = target_results
            completed_count += 1
            
            task.progress = int((completed_count / total_count) * 100)
            await task.save()
        
        vulnerable_targets = [t for t, results in all_results.items() if any(r.get('vulnerable') for r in results)]
        
        task.status = 'completed'
        task.progress = 100
        task.result = json.dumps({
            "batch_verification_summary": {
                "total_targets": total_count,
                "vulnerable_targets": len(vulnerable_targets),
                "poc_types_used": poc_types
            },
            "results": all_results
        }, default=str)
        await task.save()
        
        logger.info(f"[BatchPOC] 任务 {task_id} 批量验证完成, 发现 {len(vulnerable_targets)} 个易受攻击目标")

    async def execute_vuln_scan_task(self, task_id: int, target: str, scan_config: Dict, task_type: str):
        """
        执行漏洞扫描任务
        
        使用 vulnerability_scan_plugins/manager.py 中的 VulnScanManager
        支持并发扫描多个漏洞类型
        
        Args:
            task_id: 任务ID
            target: 扫描目标URL
            scan_config: 扫描配置
            task_type: 任务类型 (sqli, xss, csrf, ssrf, lfi, cmdi, fileupload, weakpass, infoleak)
        """
        from backend.models import Task, Vulnerability
        from backend.vulnerability_scan_plugins.manager import plugin_manager
        from backend.vulnerability_scan_plugins.base import VulnerabilitySeverity
        
        task = await Task.get(id=task_id)
        task.status = 'running'
        task.progress = 5
        await task.save()
        
        logger.info(f"[VulnScan] 漏洞扫描任务 {task_id} 开始执行: {target}, 类型: {task_type}")
        
        start_time = time.time()
        
        try:
            plugin_manager.load_plugins_from_directory()
            
            vuln_types_to_scan = scan_config.get('vuln_types', [])
            if task_type in VULN_SCAN_PLUGIN_MAPPING:
                vuln_types_to_scan = [task_type]
            elif not vuln_types_to_scan:
                vuln_types_to_scan = list(VULN_SCAN_PLUGIN_MAPPING.keys())
            
            max_concurrent = scan_config.get('max_concurrent', 3)
            
            logger.info(f"[VulScan] 任务 {task_id} 将扫描 {len(vuln_types_to_scan)} 个漏洞类型: {vuln_types_to_scan}")
            
            task.progress = 10
            await task.save()
            
            results = await plugin_manager.scan_all_async(
                target=target,
                plugin_names=vuln_types_to_scan,
                max_concurrent=max_concurrent
            )
            
            aggregated = plugin_manager.aggregate_results(results)
            
            task.progress = 80
            await task.save()
            
            saved_vulns = []
            for vuln_data in aggregated.get('vulnerabilities', []):
                try:
                    severity = vuln_data.get('severity', 'info')
                    if isinstance(severity, str):
                        severity = self.standardize_severity(severity)
                    
                    vuln = await Vulnerability.create(
                        task=task,
                        vuln_type=vuln_data.get('vuln_type', 'Unknown'),
                        severity=severity,
                        title=vuln_data.get('title', 'Unknown Vulnerability'),
                        description=vuln_data.get('description', ''),
                        url=vuln_data.get('url', target),
                        payload=vuln_data.get('payload', ''),
                        evidence=vuln_data.get('evidence', ''),
                        remediation=vuln_data.get('solution', ''),
                        source='vuln_scan_plugin'
                    )
                    saved_vulns.append(vuln)
                except Exception as e:
                    logger.error(f"[VulnScan] 保存漏洞失败: {e}")
            
            duration = time.time() - start_time
            
            result_data = {
                "scan_summary": {
                    "target": target,
                    "task_type": task_type,
                    "vuln_types_scanned": vuln_types_to_scan,
                    "total_vulnerabilities": aggregated.get('total_vulnerabilities', 0),
                    "unique_vulnerabilities": aggregated.get('unique_vulnerabilities', 0),
                    "severity_distribution": aggregated.get('severity_distribution', {}),
                    "duration_seconds": round(duration, 2)
                },
                "scan_details": {
                    "successful_plugins": aggregated.get('scan_summary', {}).get('successful_plugins', []),
                    "failed_plugins": aggregated.get('scan_summary', {}).get('failed_plugins', []),
                    "total_requests": aggregated.get('scan_summary', {}).get('total_requests', 0)
                },
                "vulnerabilities": aggregated.get('vulnerabilities', [])
            }
            
            task.status = 'completed'
            task.progress = 100
            task.result = json.dumps(result_data, default=str)
            await task.save()
            
            logger.info(f"[VulnScan] 任务 {task_id} 完成，发现 {len(saved_vulns)} 个漏洞，耗时 {duration:.2f}秒")
            
            await self._create_task_notification(
                task_id=task_id,
                task_name=task.task_name,
                task_type=task_type,
                status='completed',
                target=target,
                vuln_count=len(saved_vulns)
            )
            
            await manager.broadcast({
                "type": "task_completed",
                "payload": {
                    "task_id": task_id,
                    "status": "completed",
                    "progress": 100,
                    "result": result_data,
                    "vulnerabilities": saved_vulns,
                    "duration": duration
                }
            })
            
            try:
                await self._generate_and_save_report(
                    task_id=task_id,
                    task_name=task.task_name,
                    target=target,
                    task_type=task_type,
                    scan_result=result_data,
                    scan_config=scan_config,
                    include_ai_analysis=True
                )
            except Exception as report_error:
                logger.error(f"[VulnScan] 任务 {task_id} 报告生成异常: {report_error}", exc_info=True)
            
        except Exception as e:
            logger.error(f"[VulnScan] 任务 {task_id} 执行失败: {e}", exc_info=True)
            await self._handle_task_failure(task_id, str(e), e)

    async def execute_batch_vuln_scan(self, task_id: int, target: str, scan_config: Dict):
        """
        执行批量漏洞扫描
        
        同时运行多个漏洞扫描插件，支持自定义并发控制
        
        Args:
            task_id: 任务ID
            target: 扫描目标URL
            scan_config: 扫描配置，包含:
                - vuln_types: 要扫描的漏洞类型列表
                - max_concurrent: 最大并发数
                - timeout_per_scan: 每个扫描的超时时间
        """
        from backend.models import Task
        
        task = await Task.get(id=task_id)
        task.status = 'running'
        task.progress = 5
        await task.save()
        
        vuln_types = scan_config.get('vuln_types', list(VULN_SCAN_PLUGIN_MAPPING.keys()))
        max_concurrent = scan_config.get('max_concurrent', 3)
        
        logger.info(f"[BatchVulnScan] 任务 {task_id} 开始批量扫描: {target}, 漏洞类型: {vuln_types}")
        
        all_results = {}
        completed_count = 0
        total_count = len(vuln_types)
        
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def scan_single_vuln_type(vuln_type: str):
            async with semaphore:
                try:
                    single_scan_config = {**scan_config, 'vuln_types': [vuln_type]}
                    await self.execute_vuln_scan_task(task_id, target, single_scan_config, vuln_type)
                    return vuln_type, True, None
                except Exception as e:
                    logger.error(f"[BatchVulnScan] 扫描 {vuln_type} 失败: {e}")
                    return vuln_type, False, str(e)
        
        tasks = [scan_single_vuln_type(vt) for vt in vuln_types]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"[BatchVulnScan] 任务异常: {result}")
                continue
            vuln_type, success, error = result
            all_results[vuln_type] = {
                "success": success,
                "error": error
            }
            completed_count += 1
            
            task.progress = int((completed_count / total_count) * 100)
            await task.save()
        
        task.status = 'completed'
        task.progress = 100
        task.result = json.dumps({
            "batch_scan_summary": all_results,
            "total_scans": total_count,
            "successful_scans": sum(1 for r in all_results.values() if r['success'])
        })
        await task.save()
        
        logger.info(f"[BatchVulnScan] 任务 {task_id} 批量扫描完成")

    async def _run_kb_poc(self, kb_obj, target):
        """执行知识库 POC (基于 Pocsuite3)"""
        import tempfile
        import os
        from pocsuite3.api import init_pocsuite
        from pocsuite3.lib.core.data import logger as poc_logger
        
        # 禁用 pocsuite3 的控制台日志
        poc_logger.setLevel(logging.ERROR)
        
        try:
            # 将 POC 代码写入临时文件
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as tmp:
                tmp.write(kb_obj.poc_code)
                tmp_path = tmp.name
            
            try:
                # 配置 Pocsuite3
                config = {
                    'url': target,
                    'poc': tmp_path,
                    'quiet': True
                }
                
                # 在线程中运行 Pocsuite3，因为它是阻塞的
                loop = asyncio.get_running_loop()
                
                def run_pocsuite():
                    # 捕获 stdout
                    import io
                    import sys
                    capture = io.StringIO()
                    old_stdout = sys.stdout
                    sys.stdout = capture
                    
                    try:
                        init_pocsuite(config)
                    except Exception as e:
                        print(f"Error: {e}")
                    finally:
                        sys.stdout = old_stdout
                        
                    return capture.getvalue()

                output = await loop.run_in_executor(None, run_pocsuite)
                
                # 分析输出判断是否成功
                # Pocsuite3 输出通常包含 "success" 或 "vulnerable"
                is_vulnerable = "success" in output.lower() or "vulnerable" in output.lower()
                
                # 尝试提取输出中的有用信息
                msg = "Vulnerable" if is_vulnerable else "Not Vulnerable"
                if len(output) > 200:
                    msg += f" (Output truncated: {output[:200]}...)"
                else:
                    msg += f" ({output.strip()})"
                    
                return is_vulnerable, msg
                
            finally:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                    
        except Exception as e:
            logger.error(f"KB POC Execution Error: {e}")
            return False, str(e)

    def update_heartbeat(self, task_id: int):
        """更新任务心跳"""
        self.task_heartbeats[task_id] = time.time()

    async def execute_plugin_task(self, task_id: int, target: str, scan_config: Dict, task_type: str):
        """
        执行通用插件扫描任务 (多进程版)
        
        支持所有 plugins 目录下的插件类型，使用 task_type_registry 获取超时配置
        
        Args:
            task_id: 任务ID
            target: 扫描目标
            scan_config: 扫描配置
            task_type: 任务类型 (portscan, infoleak, webside, baseinfo, webweight, 
                                 iplocating, cdnexist, waf, whatcms, subdomain, dirscan, 
                                 crawler, loginfo, randheader, common)
        """
        try:
            from backend.models import Task
            task = await Task.get(id=task_id)
            task.status = 'running'
            task.progress = 10
            await task.save()
            
            logger.info(f"[Plugin] 插件任务 {task_id} ({task_type}) 开始执行: {target}")
            
            agent_url = f"http://{settings.HOST}:{settings.PORT}"
            
            self.task_heartbeats[task_id] = time.time()
            
            p = multiprocessing.Process(
                target=run_plugin_process,
                args=(task_id, task_type, target, scan_config, agent_url)
            )
            p.start()
            self.task_processes[task_id] = p
            self.running_task_id = task_id
            
            timeout_seconds = self._get_task_timeout(task_type, scan_config)
            
            heartbeat_timeout = scan_config.get('heartbeat_timeout', 90)
            
            logger.info(f"[Plugin] 任务 {task_id} 超时设置: {timeout_seconds}s, 心跳超时: {heartbeat_timeout}s")
            
            start_time = time.time()
            last_progress_update = start_time
            
            try:
                while p.is_alive():
                    if task_id in self.cancelled_task_ids:
                        logger.info(f"[Plugin] 检测到任务 {task_id} 取消信号，终止进程")
                        self._kill_process(p, task_id)
                        task = await Task.get(id=task_id)
                        task.status = 'aborted'
                        await task.save()
                        break
                    
                    elapsed_time = time.time() - start_time
                    if elapsed_time > timeout_seconds:
                        logger.warning(f"[Plugin] 任务 {task_id} 超时 ({timeout_seconds}s)，强制终止")
                        self._kill_process(p, task_id)
                        task = await Task.get(id=task_id)
                        task.status = 'failed'
                        task.result = json.dumps({
                            "error": "Task execution timed out",
                            "timeout_seconds": timeout_seconds,
                            "elapsed_seconds": round(elapsed_time, 2)
                        })
                        await task.save()
                        break
                    
                    last_hb = self.task_heartbeats.get(task_id, start_time)
                    hb_elapsed = time.time() - last_hb
                    if hb_elapsed > heartbeat_timeout:
                        logger.warning(f"[Plugin] 任务 {task_id} 心跳丢失 (>{heartbeat_timeout}s)，强制终止")
                        self._kill_process(p, task_id)
                        task = await Task.get(id=task_id)
                        task.status = 'aborted'
                        task.result = json.dumps({
                            "error": "Heartbeat lost",
                            "heartbeat_timeout": heartbeat_timeout,
                            "last_heartbeat_ago": round(hb_elapsed, 2)
                        })
                        await task.save()
                        break
                    
                    if time.time() - last_progress_update > 10:
                        task = await Task.get(id=task_id)
                        if task.progress < 90:
                            task.progress = min(10 + int((elapsed_time / timeout_seconds) * 80), 90)
                            await task.save()
                        last_progress_update = time.time()

                    await asyncio.sleep(1)
            except asyncio.CancelledError:
                logger.warning(f"[Plugin] 插件任务 {task_id} 协程被取消，正在终止进程...")
                if p.is_alive():
                    self._kill_process(p, task_id)
                raise
            
            if task_id in self.task_processes:
                del self.task_processes[task_id]
            if task_id in self.task_heartbeats:
                del self.task_heartbeats[task_id]
            if self.running_task_id == task_id:
                self.running_task_id = None
            
            logger.info(f"[Plugin] 插件任务 {task_id} 进程已退出 (ExitCode: {p.exitcode})")
            
            wait_start = time.time()
            callback_timeout = 30
            while time.time() - wait_start < callback_timeout:
                task = await Task.get(id=task_id)
                if task.status != 'running':
                    break
                await asyncio.sleep(1)
            
            task = await Task.get(id=task_id)
            if task.status == 'running':
                logger.warning(f"[Plugin] 任务 {task_id} 进程退出后 {callback_timeout}s 内未收到完成回调，标记为 FAILED")
                if p.exitcode == 0:
                     task.result = json.dumps({"error": "No result callback received (Timeout 30s)"})
                else:
                     task.result = json.dumps({"error": f"Process crashed with exit code {p.exitcode}"})
                task.status = 'failed'
                await task.save()

            if task.status == 'completed':
                try:
                    result_data = json.loads(task.result) if task.result else {}
                    await self._generate_and_save_report(
                        task_id=task_id,
                        task_name=task.task_name,
                        target=target,
                        task_type=task_type,
                        scan_result=result_data,
                        scan_config=scan_config,
                        include_ai_analysis=True
                    )
                except Exception as report_error:
                    logger.error(f"[Plugin] 任务 {task_id} 报告生成异常: {report_error}", exc_info=True)

        except Exception as e:
            logger.error(f"[Plugin] 插件任务 {task_id} 执行失败: {str(e)}", exc_info=True)
            try:
                from backend.models import Task
                task = await Task.get(id=task_id)
                task.status = 'failed'
                task.result = json.dumps({'error': str(e), 'traceback': traceback.format_exc()})
                await task.save()
            except:
                pass

    async def _kill_process(self, p, task_id):
        """辅助方法：强制终止进程"""
        p.terminate()
        for _ in range(5):
            if not p.is_alive(): return
            await asyncio.sleep(1)
        if p.is_alive():
            logger.warning(f"任务 {task_id} 未响应 SIGTERM，发送 SIGKILL")
            p.kill()

    def _log_execution_history(
        self, 
        task_id: int, 
        task_type: str, 
        status: str, 
        duration: float = 0,
        error: str = None,
        result_summary: Dict = None
    ):
        """
        记录任务执行历史
        
        Args:
            task_id: 任务ID
            task_type: 任务类型
            status: 执行状态 (started, completed, failed, timeout, cancelled)
            duration: 执行时长 (秒)
            error: 错误信息
            result_summary: 结果摘要
        """
        history_entry = {
            "task_id": task_id,
            "task_type": task_type,
            "status": status,
            "duration": round(duration, 2),
            "timestamp": datetime.utcnow().isoformat(),
            "error": error,
            "result_summary": result_summary
        }
        
        structured_logger.info(
            f"Task execution history: {task_type} - {status}",
            **history_entry
        )

    async def _handle_execution_error(
        self, 
        task_id: int, 
        error: Exception, 
        context: Dict = None
    ):
        """
        统一处理执行错误
        
        Args:
            task_id: 任务ID
            error: 异常对象
            context: 错误上下文信息
        """
        error_info = {
            "task_id": task_id,
            "error_type": type(error).__name__,
            "error_message": str(error),
            "traceback": traceback.format_exc(),
            "context": context or {},
            "timestamp": datetime.utcnow().isoformat()
        }
        
        logger.error(
            f"[ErrorHandler] 任务 {task_id} 执行错误: {error_info['error_type']} - {error_info['error_message']}",
            exc_info=True
        )
        
        structured_logger.error(
            f"Task execution error: {error_info['error_type']}",
            **error_info
        )
        
        await self._handle_task_failure(task_id, str(error), error)

    def get_supported_task_types(self) -> Dict[str, List[str]]:
        """
        获取支持的任务类型列表
        
        Returns:
            Dict: 按类别分组的任务类型列表
        """
        return {
            "plugins": list(PLUGIN_TYPE_MAPPING.keys()),
            "vulnerability_scan": list(VULN_SCAN_PLUGIN_MAPPING.keys()),
            "poc": list(POC_PLUGIN_MAPPING.keys()),
            "external": ["awvs_scan"],
            "ai_agent": ["ai_agent_scan"]
        }

    def get_task_executor_info(self, task_type: str) -> Dict:
        """
        获取任务执行器信息
        
        Args:
            task_type: 任务类型
            
        Returns:
            Dict: 执行器信息
        """
        metadata = task_type_registry.get_task_type_metadata(task_type)
        executor_type = task_type_registry.get_executor_type(task_type)
        timeout = task_type_registry.get_task_type_timeout(task_type)
        priority = task_type_registry.get_task_type_priority(task_type)
        
        return {
            "task_type": task_type,
            "executor_type": executor_type.value if executor_type else "unknown",
            "timeout": timeout,
            "priority": priority.value if priority else 3,
            "metadata": metadata.to_dict() if metadata else None,
            "supported": task_type in PLUGIN_TYPE_MAPPING or 
                        task_type in VULN_SCAN_PLUGIN_MAPPING or 
                        task_type in POC_PLUGIN_MAPPING or
                        task_type in ["awvs_scan", "ai_agent_scan", "poc_scan"]
        }

    def abort_task(self, task_id: int):
        """强制中止任务"""
        logger.info(f"收到强制中止请求: {task_id}")
        self.cancelled_task_ids.add(task_id)
        
        # 如果任务在队列中，标记为取消 (Worker取到时会跳过)
        if task_id in self.queued_task_ids:
            logger.info(f"任务 {task_id} 在队列中，已标记为取消")
            
        # 如果任务正在运行，强制取消协程
        if self.running_task_id == task_id and self.current_execution_task and not self.current_execution_task.done():
            logger.info(f"任务 {task_id} 正在运行，发送取消信号给协程")
            self.current_execution_task.cancel()
        
    async def cancel_task(self, task_id: int):
        """取消任务 (兼容接口)"""
        self.abort_task(task_id)

    async def shutdown(self):
        """
        关闭任务执行器
        
        执行完整的清理流程:
        1. 标记关闭状态
        2. 停止接收新任务
        3. 取消当前运行的任务
        4. 终止所有子进程
        5. 保存任务状态
        6. 清理资源
        """
        if self.is_shutting_down:
            logger.warning("关闭流程已在进行中，跳过重复调用")
            return
        
        self.is_shutting_down = True
        self.is_running = False
        
        logger.info("=" * 50)
        logger.info("开始关闭任务执行器...")
        logger.info(f"当前队列任务数: {self.queue.qsize()}")
        logger.info(f"当前运行任务ID: {self.running_task_id}")
        logger.info(f"当前活跃进程数: {len(self.task_processes)}")
        logger.info(f"持久化任务状态数: {len(self._persisted_tasks)}")
        logger.info("=" * 50)
        
        if self.worker_task and not self.worker_task.done():
            logger.info("[1/6] 正在取消Worker任务...")
            self.worker_task.cancel()
            try:
                await asyncio.wait_for(self.worker_task, timeout=5)
            except asyncio.CancelledError:
                pass
            except asyncio.TimeoutError:
                logger.warning("[1/6] Worker取消超时")
            logger.info("[1/6] Worker已取消")
        else:
            logger.info("[1/6] Worker未运行，跳过")
        
        if self.current_execution_task and not self.current_execution_task.done():
            logger.info("[2/6] 正在取消当前执行任务...")
            self.current_execution_task.cancel()
            try:
                await asyncio.wait_for(self.current_execution_task, timeout=5)
            except asyncio.CancelledError:
                pass
            except asyncio.TimeoutError:
                logger.warning("[2/6] 当前任务取消超时")
            logger.info("[2/6] 当前任务已取消")
        else:
            logger.info("[2/6] 无正在执行的任务，跳过")
        
        if self.task_processes:
            logger.info(f"[3/6] 正在终止 {len(self.task_processes)} 个子进程...")
            terminated_count = 0
            for task_id, process in list(self.task_processes.items()):
                if process.is_alive():
                    logger.info(f"  终止进程: Task {task_id} (PID: {process.pid})")
                    try:
                        process.terminate()
                        process.join(timeout=3)
                        if process.is_alive():
                            logger.warning(f"  进程 {process.pid} 未响应SIGTERM，发送SIGKILL")
                            process.kill()
                            process.join(timeout=2)
                            if process.is_alive():
                                logger.error(f"  进程 {process.pid} 仍然存活，强制关闭")
                                process.terminate()
                                process.join(timeout=1)
                        terminated_count += 1
                    except Exception as e:
                        logger.error(f"  终止进程 {process.pid} 时出错: {e}")
            self.task_processes.clear()
            logger.info(f"[3/6] 已终止 {terminated_count} 个子进程")
        else:
            logger.info("[3/6] 无活跃子进程，跳过")
        
        logger.info("[4/6] 正在保存任务状态...")
        self._save_task_states()
        logger.info(f"[4/6] 已保存 {len(self._persisted_tasks)} 个任务状态")
        
        self.queued_task_ids.clear()
        self.cancelled_task_ids.clear()
        self.task_heartbeats.clear()
        self.task_start_times.clear()
        self.task_timeouts.clear()
        self.running_task_id = None
        
        logger.info("[5/5] 正在清空任务队列...")
        while not self.queue.empty():
            try:
                self.queue.get_nowait()
            except asyncio.QueueEmpty:
                break
        logger.info("[5/5] 任务队列已清空")
        
        logger.info("=" * 50)
        logger.info("任务执行器关闭完成")
        logger.info("=" * 50)

task_executor = TaskExecutor()
