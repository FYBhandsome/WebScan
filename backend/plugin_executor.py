# -*- coding:utf-8 -*-
"""
插件执行器模块

负责管理和执行所有类型的插件，包括：
1. 基础插件（plugins目录）
2. 漏洞扫描插件（vulnerability_scan_plugins目录）
3. POC漏洞验证（poc目录）

功能：
- 插件动态加载和映射
- 统一的执行接口
- 结果格式化和回调
- 日志记录和心跳机制
"""

import os
import sys
import time
import json
import logging
import threading
import traceback
import requests
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


# ============================================================
# 插件导入 - 基础插件（plugins目录）
# ============================================================

PLUGIN_IMPORTS = {}

try:
    from backend.plugins.portscan.portscan import ScanPort
    PLUGIN_IMPORTS['port_scan'] = ScanPort
except ImportError as e:
    logger.warning(f"导入 portscan 插件失败: {e}")

try:
    from backend.plugins.infoleak.infoleak import get_infoleak
    PLUGIN_IMPORTS['info_leak'] = get_infoleak
except ImportError as e:
    logger.warning(f"导入 infoleak 插件失败: {e}")

try:
    from backend.plugins.webside.webside import get_side_info
    PLUGIN_IMPORTS['web_side'] = get_side_info
except ImportError as e:
    logger.warning(f"导入 webside 插件失败: {e}")

try:
    from backend.plugins.baseinfo.baseinfo import getbaseinfo
    PLUGIN_IMPORTS['base_info'] = getbaseinfo
except ImportError as e:
    logger.warning(f"导入 baseinfo 插件失败: {e}")

try:
    from backend.plugins.webweight.webweight import get_web_weight
    PLUGIN_IMPORTS['web_weight'] = get_web_weight
except ImportError as e:
    logger.warning(f"导入 webweight 插件失败: {e}")

try:
    from backend.plugins.iplocating.iplocating import get_locating
    PLUGIN_IMPORTS['ip_locating'] = get_locating
except ImportError as e:
    logger.warning(f"导入 iplocating 插件失败: {e}")

try:
    from backend.plugins.cdnexist.cdnexist import iscdn
    PLUGIN_IMPORTS['cdn_check'] = iscdn
except ImportError as e:
    logger.warning(f"导入 cdnexist 插件失败: {e}")

try:
    from backend.plugins.waf.waf import getwaf
    PLUGIN_IMPORTS['waf_check'] = getwaf
except ImportError as e:
    logger.warning(f"导入 waf 插件失败: {e}")

try:
    from backend.plugins.whatcms.whatcms import getwhatcms
    PLUGIN_IMPORTS['whatcms'] = getwhatcms
except ImportError as e:
    logger.warning(f"导入 whatcms 插件失败: {e}")

try:
    from backend.plugins.subdomain.subdomain import get_subdomain
    PLUGIN_IMPORTS['subdomain'] = get_subdomain
except ImportError as e:
    logger.warning(f"导入 subdomain 插件失败: {e}")

try:
    from backend.plugins.dirscan.dirscan import get_dirscan
    PLUGIN_IMPORTS['dir_scan'] = get_dirscan
    PLUGIN_IMPORTS['scan_dir'] = get_dirscan
except ImportError as e:
    logger.warning(f"导入 dirscan 插件失败: {e}")

try:
    from backend.plugins.crawler.crawler import crawl
    PLUGIN_IMPORTS['crawler'] = crawl
except ImportError as e:
    logger.warning(f"导入 crawler 插件失败: {e}")

try:
    from backend.plugins.loginfo.loginfo import LogHandler
    PLUGIN_IMPORTS['loginfo'] = LogHandler
except ImportError as e:
    logger.warning(f"导入 loginfo 插件失败: {e}")

try:
    from backend.plugins.randheader.randheader import get_random_headers, get_ua
    PLUGIN_IMPORTS['randheader'] = get_random_headers
    PLUGIN_IMPORTS['random_headers'] = get_random_headers
except ImportError as e:
    logger.warning(f"导入 randheader 插件失败: {e}")

try:
    from backend.plugins.common.common import (
        check_ip, check_url, get_domain_ip, get_domain,
        safe_addslashes, get_user_ip, success, error
    )
    PLUGIN_IMPORTS['common_check_ip'] = check_ip
    PLUGIN_IMPORTS['common_check_url'] = check_url
    PLUGIN_IMPORTS['common_get_domain_ip'] = get_domain_ip
except ImportError as e:
    logger.warning(f"导入 common 插件失败: {e}")


# ============================================================
# 插件导入 - 漏洞扫描插件（vulnerability_scan_plugins目录）
# ============================================================

VULN_SCAN_PLUGINS = {}

try:
    from backend.vulnerability_scan_plugins.manager import PluginManager, plugin_manager
    from backend.vulnerability_scan_plugins.base import (
        VulnerabilityScannerBase,
        AsyncVulnerabilityScannerBase,
        ScanResult,
        PluginMetadata,
        VulnerabilityInfo,
        VulnerabilityType,
        VulnerabilitySeverity
    )
    VULN_SCAN_MANAGER_AVAILABLE = True
except ImportError as e:
    logger.warning(f"导入漏洞扫描管理器失败: {e}")
    VULN_SCAN_MANAGER_AVAILABLE = False

try:
    from backend.vulnerability_scan_plugins.xss.scanner import XSSScanner, SCANNER_CLASS as XSS_SCANNER_CLASS
    VULN_SCAN_PLUGINS['xss'] = XSSScanner
    VULN_SCAN_PLUGINS['xss_scanner'] = XSSScanner
except ImportError as e:
    logger.warning(f"导入 XSS 扫描器失败: {e}")

try:
    from backend.vulnerability_scan_plugins.sqli.scanner import SQLiScanner, SCANNER_CLASS as SQLI_SCANNER_CLASS
    VULN_SCAN_PLUGINS['sqli'] = SQLiScanner
    VULN_SCAN_PLUGINS['sqli_scanner'] = SQLiScanner
    VULN_SCAN_PLUGINS['sql_injection'] = SQLiScanner
except ImportError as e:
    logger.warning(f"导入 SQL注入 扫描器失败: {e}")

try:
    from backend.vulnerability_scan_plugins.cmdi.scanner import CmdiScanner
    VULN_SCAN_PLUGINS['cmdi'] = CmdiScanner
    VULN_SCAN_PLUGINS['cmdi_scanner'] = CmdiScanner
    VULN_SCAN_PLUGINS['command_injection'] = CmdiScanner
except ImportError as e:
    logger.warning(f"导入命令注入 扫描器失败: {e}")

try:
    from backend.vulnerability_scan_plugins.csrf.scanner import CSRFScanner, SCANNER_CLASS as CSRF_SCANNER_CLASS
    VULN_SCAN_PLUGINS['csrf'] = CSRFScanner
    VULN_SCAN_PLUGINS['csrf_scanner'] = CSRFScanner
except ImportError as e:
    logger.warning(f"导入 CSRF 扫描器失败: {e}")

try:
    from backend.vulnerability_scan_plugins.fileupload.scanner import FileUploadScanner
    VULN_SCAN_PLUGINS['fileupload'] = FileUploadScanner
    VULN_SCAN_PLUGINS['file_upload'] = FileUploadScanner
    VULN_SCAN_PLUGINS['upload'] = FileUploadScanner
except ImportError as e:
    logger.warning(f"导入文件上传 扫描器失败: {e}")

try:
    from backend.vulnerability_scan_plugins.lfi.scanner import LfiScanner
    VULN_SCAN_PLUGINS['lfi'] = LfiScanner
    VULN_SCAN_PLUGINS['lfi_scanner'] = LfiScanner
    VULN_SCAN_PLUGINS['file_include'] = LfiScanner
    VULN_SCAN_PLUGINS['path_traversal'] = LfiScanner
except ImportError as e:
    logger.warning(f"导入文件包含 扫描器失败: {e}")

try:
    from backend.vulnerability_scan_plugins.ssrf.scanner import SsrfScanner
    VULN_SCAN_PLUGINS['ssrf'] = SsrfScanner
    VULN_SCAN_PLUGINS['ssrf_scanner'] = SsrfScanner
except ImportError as e:
    logger.warning(f"导入 SSRF 扫描器失败: {e}")

try:
    from backend.vulnerability_scan_plugins.weakpass.scanner import WeakPassScanner
    VULN_SCAN_PLUGINS['weakpass'] = WeakPassScanner
    VULN_SCAN_PLUGINS['weak_password'] = WeakPassScanner
    VULN_SCAN_PLUGINS['brute_force'] = WeakPassScanner
except ImportError as e:
    logger.warning(f"导入弱口令 扫描器失败: {e}")

try:
    from backend.vulnerability_scan_plugins.infoleak.scanner import InfoLeakScanner, SCANNER_CLASS as INFOLEAK_SCANNER_CLASS
    VULN_SCAN_PLUGINS['vuln_infoleak'] = InfoLeakScanner
    VULN_SCAN_PLUGINS['infoleak_scanner'] = InfoLeakScanner
    VULN_SCAN_PLUGINS['sensitive_info'] = InfoLeakScanner
except ImportError as e:
    logger.warning(f"导入敏感信息泄露 扫描器失败: {e}")


# ============================================================
# 插件导入 - POC漏洞验证（poc目录）
# ============================================================

POC_FUNCTIONS = {}

try:
    from backend.poc.weblogic.cve_2020_2551_poc import poc as cve_2020_2551_poc
    POC_FUNCTIONS['weblogic_cve_2020_2551'] = cve_2020_2551_poc
except ImportError as e:
    logger.warning(f"导入 weblogic_cve_2020_2551 POC失败: {e}")

try:
    from backend.poc.weblogic.cve_2018_2628_poc import poc as cve_2018_2628_poc
    POC_FUNCTIONS['weblogic_cve_2018_2628'] = cve_2018_2628_poc
except ImportError as e:
    logger.warning(f"导入 weblogic_cve_2018_2628 POC失败: {e}")

try:
    from backend.poc.weblogic.cve_2018_2894_poc import poc as cve_2018_2894_poc
    POC_FUNCTIONS['weblogic_cve_2018_2894'] = cve_2018_2894_poc
except ImportError as e:
    logger.warning(f"导入 weblogic_cve_2018_2894 POC失败: {e}")

try:
    from backend.poc.weblogic.cve_2020_14756_poc import poc as cve_2020_14756_poc
    POC_FUNCTIONS['weblogic_cve_2020_14756'] = cve_2020_14756_poc
except ImportError as e:
    logger.warning(f"导入 weblogic_cve_2020_14756 POC失败: {e}")

try:
    from backend.poc.weblogic.cve_2023_21839_poc import POC as WebLogic_2023_21839_POC
    POC_FUNCTIONS['weblogic_cve_2023_21839'] = WebLogic_2023_21839_POC
except ImportError as e:
    logger.warning(f"导入 weblogic_cve_2023_21839 POC失败: {e}")

try:
    from backend.poc.struts2.struts2_009_poc import poc as struts2_009_poc
    POC_FUNCTIONS['struts2_009'] = struts2_009_poc
except ImportError as e:
    logger.warning(f"导入 struts2_009 POC失败: {e}")

try:
    from backend.poc.struts2.struts2_032_poc import poc as struts2_032_poc
    POC_FUNCTIONS['struts2_032'] = struts2_032_poc
except ImportError as e:
    logger.warning(f"导入 struts2_032 POC失败: {e}")

try:
    from backend.poc.tomcat.cve_2017_12615_poc import poc as cve_2017_12615_poc
    POC_FUNCTIONS['tomcat_cve_2017_12615'] = cve_2017_12615_poc
except ImportError as e:
    logger.warning(f"导入 tomcat_cve_2017_12615 POC失败: {e}")

try:
    from backend.poc.tomcat.CVE_2022_22965 import Exploit as Spring4Shell_Exploit
    POC_FUNCTIONS['spring4shell_cve_2022_22965'] = Spring4Shell_Exploit
    POC_FUNCTIONS['tomcat_cve_2022_22965'] = Spring4Shell_Exploit
except ImportError as e:
    logger.warning(f"导入 spring4shell_cve_2022_22965 POC失败: {e}")

try:
    from backend.poc.tomcat.CVE_2022_47986 import poc as cve_2022_47986_poc
    POC_FUNCTIONS['tomcat_cve_2022_47986'] = cve_2022_47986_poc
except ImportError as e:
    logger.warning(f"导入 tomcat_cve_2022_47986 POC失败: {e}")

try:
    from backend.poc.jboss.cve_2017_12149_poc import poc as cve_2017_12149_poc
    POC_FUNCTIONS['jboss_cve_2017_12149'] = cve_2017_12149_poc
except ImportError as e:
    logger.warning(f"导入 jboss_cve_2017_12149 POC失败: {e}")

try:
    from backend.poc.nexus.cve_2020_10199_poc import poc as cve_2020_10199_poc
    POC_FUNCTIONS['nexus_cve_2020_10199'] = cve_2020_10199_poc
except ImportError as e:
    logger.warning(f"导入 nexus_cve_2020_10199 POC失败: {e}")

try:
    from backend.poc.drupal.cve_2018_7600_poc import poc as cve_2018_7600_poc
    POC_FUNCTIONS['drupal_cve_2018_7600'] = cve_2018_7600_poc
except ImportError as e:
    logger.warning(f"导入 drupal_cve_2018_7600 POC失败: {e}")

try:
    from backend.poc.thinkphp.poc_99617_ai import ThinkPHP_RCE_POC
    POC_FUNCTIONS['thinkphp_rce'] = ThinkPHP_RCE_POC
    POC_FUNCTIONS['thinkphp_99617'] = ThinkPHP_RCE_POC
except ImportError as e:
    logger.warning(f"导入 thinkphp_rce POC失败: {e}")

try:
    from backend.poc.thinkphp.poc_manual_thinkphp_ai import poc as thinkphp_manual_poc
    POC_FUNCTIONS['thinkphp_manual'] = thinkphp_manual_poc
except ImportError as e:
    logger.warning(f"导入 thinkphp_manual POC失败: {e}")


# ============================================================
# 数据类定义
# ============================================================

@dataclass
class ExecutionResult:
    """
    统一的执行结果数据类
    
    Attributes:
        success: 执行是否成功
        task_id: 任务ID
        task_type: 任务类型
        target: 目标地址
        data: 执行结果数据
        error: 错误信息
        start_time: 开始时间
        end_time: 结束时间
        duration: 执行耗时（秒）
        plugin_name: 插件名称
        vulnerabilities: 漏洞列表（仅漏洞扫描插件）
    """
    success: bool
    task_id: int
    task_type: str
    target: str
    data: Any = None
    error: Optional[str] = None
    start_time: str = ""
    end_time: str = ""
    duration: float = 0.0
    plugin_name: str = ""
    vulnerabilities: List[Dict] = None
    
    def __post_init__(self):
        if self.vulnerabilities is None:
            self.vulnerabilities = []
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        result = {
            "success": self.success,
            "task_id": self.task_id,
            "task_type": self.task_type,
            "target": self.target,
            "data": self._serialize_data(self.data),
            "error": self.error,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.duration,
            "plugin_name": self.plugin_name,
        }
        
        if self.vulnerabilities:
            result["vulnerabilities"] = self.vulnerabilities
            result["vulnerability_count"] = len(self.vulnerabilities)
        
        return result
    
    def _serialize_data(self, data: Any) -> Any:
        """序列化数据，处理不可JSON序列化的对象"""
        if data is None:
            return None
        
        if isinstance(data, (str, int, float, bool, list, dict)):
            return data
        
        if hasattr(data, 'to_dict'):
            return data.to_dict()
        
        if hasattr(data, '__dict__'):
            try:
                return json.loads(json.dumps(data.__dict__, default=str))
            except:
                return str(data)
        
        return str(data)


# ============================================================
# 插件日志处理器
# ============================================================

class PluginLogHandler(logging.Handler):
    """
    插件日志处理器
    
    功能：
    1. 格式化日志输出
    2. 自动注入上下文信息
    """
    
    def __init__(self, plugin_type: str, plugin_name: str, task_id: int):
        super().__init__()
        self.plugin_type = plugin_type
        self.plugin_name = plugin_name
        self.task_id = task_id
        self.formatter = logging.Formatter(
            '[Plugin][%(plugin_type)s][%(plugin_name)s][%(task_id)s] %(levelname)s %(message)s'
        )
    
    def emit(self, record):
        record.plugin_type = self.plugin_type
        record.plugin_name = self.plugin_name
        record.task_id = self.task_id
        
        msg = self.format(record)


# ============================================================
# 插件执行器主类
# ============================================================

class PluginExecutor:
    """
    插件执行器
    
    负责管理和执行所有类型的插件，提供统一的执行接口。
    
    Attributes:
        task_id: 任务ID
        task_type: 任务类型
        target: 目标地址
        config: 配置信息
        agent_url: Agent服务URL
        plugin_name: 插件名称
        stop_event: 停止事件
        logger: 日志记录器
    """
    
    PLUGIN_TYPE_MAP = {
        'port_scan': 'PortScan',
        'dir_scan': 'DirScan',
        'scan_dir': 'DirScan',
        'info_leak': 'InfoLeak',
        'web_side': 'WebSide',
        'base_info': 'BaseInfo',
        'web_weight': 'WebWeight',
        'ip_locating': 'IPLocating',
        'cdn_check': 'CDNCheck',
        'waf_check': 'WAFCheck',
        'whatcms': 'WhatCMS',
        'subdomain': 'SubDomain',
        'crawler': 'Crawler',
        'xss': 'XSSScanner',
        'sqli': 'SQLiScanner',
        'sql_injection': 'SQLiScanner',
        'cmdi': 'CmdiScanner',
        'command_injection': 'CmdiScanner',
        'csrf': 'CSRFScanner',
        'fileupload': 'FileUploadScanner',
        'file_upload': 'FileUploadScanner',
        'lfi': 'LfiScanner',
        'file_include': 'LfiScanner',
        'ssrf': 'SSRFScanner',
        'weakpass': 'WeakPassScanner',
        'weak_password': 'WeakPassScanner',
        'vuln_infoleak': 'InfoLeakScanner',
    }
    
    def __init__(self, task_id: int, task_type: str, target: str, 
                 config: Dict, agent_url: str):
        """
        初始化插件执行器
        
        Args:
            task_id: 任务ID
            task_type: 任务类型
            target: 目标地址
            config: 配置信息
            agent_url: Agent服务URL
        """
        self.task_id = task_id
        self.task_type = task_type
        self.target = target
        self.config = config or {}
        self.agent_url = agent_url.rstrip('/')
        self.plugin_name = self._get_plugin_name()
        
        self.stop_event = threading.Event()
        self.logger = None
        self._start_time = None
    
    def _get_plugin_name(self) -> str:
        """获取插件名称"""
        return self.PLUGIN_TYPE_MAP.get(self.task_type, self.task_type)
    
    def setup_logging(self):
        """设置日志"""
        log_dir = Path(f"logs/plugins/{datetime.now().strftime('%Y-%m-%d')}")
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / f"{self.task_id}.log"
        
        self.logger = logging.getLogger(f"plugin_{self.task_id}")
        self.logger.setLevel(logging.DEBUG)
        
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setFormatter(logging.Formatter(
            '[Plugin][%(plugin_type)s][%(plugin_name)s][%(task_id)s] %(levelname)s %(message)s'
        ))
        
        self.logger = logging.LoggerAdapter(self.logger, {
            'plugin_type': self.task_type,
            'plugin_name': self.plugin_name,
            'task_id': self.task_id
        })
        
        self.logger.logger.handlers = []
        self.logger.logger.addHandler(file_handler)
    
    def heartbeat_loop(self):
        """心跳循环"""
        while not self.stop_event.is_set():
            try:
                url = f"{self.agent_url}/agent/task/{self.task_id}/plugin/{self.task_type}/heartbeat"
                requests.put(url, json={"timestamp": time.time()}, timeout=5)
            except Exception:
                pass
            time.sleep(30)
    
    def run(self):
        """执行插件"""
        self.setup_logging()
        self.logger.info("Plugin started")
        
        hb_thread = threading.Thread(target=self.heartbeat_loop, daemon=True)
        hb_thread.start()
        
        self._start_time = time.time()
        start_time_str = datetime.now().isoformat()
        
        result = None
        error = None
        exit_code = 0
        
        try:
            result = self._execute_logic()
            self.logger.info("Plugin finished successfully")
        except Exception as e:
            error = str(e)
            exit_code = 1
            self.logger.error(f"Plugin execution failed: {e}")
            self.logger.error(traceback.format_exc())
            result = {"error": error}
        finally:
            self.stop_event.set()
            
            end_time = time.time()
            end_time_str = datetime.now().isoformat()
            duration = end_time - self._start_time
            
            execution_result = ExecutionResult(
                success=(exit_code == 0),
                task_id=self.task_id,
                task_type=self.task_type,
                target=self.target,
                data=result,
                error=error,
                start_time=start_time_str,
                end_time=end_time_str,
                duration=duration,
                plugin_name=self.plugin_name
            )
            
            if result and isinstance(result, dict):
                if 'vulnerabilities' in result:
                    execution_result.vulnerabilities = result['vulnerabilities']
                elif hasattr(result, 'vulnerabilities'):
                    vulns = result.vulnerabilities
                    execution_result.vulnerabilities = [
                        v.to_dict() if hasattr(v, 'to_dict') else v 
                        for v in vulns
                    ]
            
            self._report_finish(execution_result)
    
    def _execute_logic(self) -> Any:
        """
        执行插件逻辑
        
        Returns:
            Any: 插件执行结果
        """
        task_type = self.task_type
        target = self.target
        scan_config = self.config
        
        if task_type in PLUGIN_IMPORTS:
            return self._execute_basic_plugin(task_type, target, scan_config)
        
        if task_type in VULN_SCAN_PLUGINS:
            return self._execute_vuln_scan_plugin(task_type, target, scan_config)
        
        if task_type in POC_FUNCTIONS:
            return self._execute_poc(task_type, target, scan_config)
        
        if VULN_SCAN_MANAGER_AVAILABLE and task_type == 'vuln_scan_all':
            return self._execute_all_vuln_scans(target, scan_config)
        
        return {"error": f"Unknown task type: {task_type}"}
    
    def _execute_basic_plugin(self, task_type: str, target: str, config: Dict) -> Any:
        """
        执行基础插件
        
        Args:
            task_type: 任务类型
            target: 目标地址
            config: 配置信息
            
        Returns:
            Any: 执行结果
        """
        plugin_func = PLUGIN_IMPORTS[task_type]
        
        if task_type == 'port_scan':
            ports = config.get('ports', None)
            scanner = plugin_func(target, ports)
            return scanner.scan()
        
        elif task_type in ['dir_scan', 'scan_dir']:
            return plugin_func(target, config)
        
        elif task_type == 'cdn_check':
            return {'is_cdn': plugin_func(target)}
        
        elif task_type == 'waf_check':
            return {'waf': plugin_func(target)}
        
        elif task_type == 'crawler':
            return plugin_func(target, config)
        
        elif task_type in ['common_check_ip', 'common_check_url']:
            return {'result': plugin_func(target)}
        
        elif callable(plugin_func):
            try:
                return plugin_func(target)
            except TypeError:
                return plugin_func(target, config)
        
        return {"error": f"Cannot execute plugin: {task_type}"}
    
    def _execute_vuln_scan_plugin(self, task_type: str, target: str, config: Dict) -> Any:
        """
        执行漏洞扫描插件
        
        Args:
            task_type: 任务类型
            target: 目标地址
            config: 配置信息
            
        Returns:
            Any: 扫描结果
        """
        scanner_class = VULN_SCAN_PLUGINS[task_type]
        
        try:
            scanner = scanner_class(target=target, config=config)
            result = scanner.scan()
            
            if hasattr(result, 'to_dict'):
                return result.to_dict()
            
            return result
            
        except Exception as e:
            self.logger.error(f"Vulnerability scan failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "plugin_name": task_type,
                "target": target
            }
    
    def _execute_poc(self, task_type: str, target: str, config: Dict) -> Any:
        """
        执行POC验证
        
        Args:
            task_type: 任务类型
            target: 目标地址
            config: 配置信息
            
        Returns:
            Any: POC执行结果
        """
        poc_func = POC_FUNCTIONS[task_type]
        
        try:
            if callable(poc_func):
                try:
                    result = poc_func(target)
                except TypeError:
                    result = poc_func(target, config)
                
                if result is None:
                    return {"success": True, "message": "POC executed"}
                
                if hasattr(result, 'to_dict'):
                    return result.to_dict()
                
                if isinstance(result, dict):
                    return result
                
                return {"success": True, "result": str(result)}
            
        except Exception as e:
            self.logger.error(f"POC execution failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "poc_name": task_type,
                "target": target
            }
    
    def _execute_all_vuln_scans(self, target: str, config: Dict) -> Any:
        """
        执行所有漏洞扫描
        
        Args:
            target: 目标地址
            config: 配置信息
            
        Returns:
            Any: 汇总扫描结果
        """
        if not VULN_SCAN_MANAGER_AVAILABLE:
            return {"error": "Vulnerability scan manager not available"}
        
        try:
            plugin_names = config.get('plugins', None)
            max_concurrent = config.get('max_concurrent', 3)
            
            results = plugin_manager.scan_all(
                target=target,
                plugin_names=plugin_names,
                max_concurrent=max_concurrent
            )
            
            aggregated = plugin_manager.aggregate_results(results)
            return aggregated
            
        except Exception as e:
            self.logger.error(f"All vulnerability scan failed: {e}")
            return {"error": str(e)}
    
    def _report_finish(self, result: ExecutionResult):
        """
        报告执行完成
        
        Args:
            result: 执行结果
        """
        try:
            url = f"{self.agent_url}/agent/task/{self.task_id}/plugin/{self.task_type}/finish"
            
            payload = {
                "exitCode": 0 if result.success else 1,
                "stdout": json.dumps(result.to_dict(), ensure_ascii=False, default=str),
                "stderr": result.error or "",
                "duration": result.duration,
                "plugin_name": result.plugin_name,
                "task_type": result.task_type,
                "target": result.target,
                "timestamp": datetime.now().isoformat()
            }
            
            response = requests.post(url, json=payload, timeout=10)
            
            if response.status_code >= 400:
                self.logger.error(f"Report finish failed: HTTP {response.status_code}")
            
        except Exception as e:
            self.logger.error(f"Failed to report finish: {e}")


# ============================================================
# 辅助函数
# ============================================================

def format_scan_result(result: Any, task_type: str) -> Dict[str, Any]:
    """
    格式化扫描结果
    
    Args:
        result: 原始扫描结果
        task_type: 任务类型
        
    Returns:
        Dict: 格式化后的结果
    """
    formatted = {
        "task_type": task_type,
        "timestamp": datetime.now().isoformat(),
        "success": True
    }
    
    if result is None:
        formatted["data"] = None
        return formatted
    
    if isinstance(result, dict):
        formatted["data"] = result
        formatted["success"] = result.get("success", True)
        
        if "vulnerabilities" in result:
            formatted["vulnerability_count"] = len(result["vulnerabilities"])
        
        return formatted
    
    if hasattr(result, 'to_dict'):
        data = result.to_dict()
        formatted["data"] = data
        formatted["success"] = data.get("success", True)
        
        if "vulnerabilities" in data:
            formatted["vulnerability_count"] = len(data["vulnerabilities"])
        
        return formatted
    
    if hasattr(result, '__dict__'):
        try:
            formatted["data"] = json.loads(json.dumps(result.__dict__, default=str))
            return formatted
        except:
            pass
    
    formatted["data"] = str(result)
    return formatted


def get_available_plugins() -> Dict[str, List[str]]:
    """
    获取所有可用插件列表
    
    Returns:
        Dict: 分类后的插件列表
    """
    return {
        "basic_plugins": list(PLUGIN_IMPORTS.keys()),
        "vulnerability_scanners": list(VULN_SCAN_PLUGINS.keys()),
        "poc_modules": list(POC_FUNCTIONS.keys())
    }


def run_plugin_process(task_id: int, task_type: str, target: str, 
                       config: Dict, agent_url: str):
    """
    插件进程入口点
    
    Args:
        task_id: 任务ID
        task_type: 任务类型
        target: 目标地址
        config: 配置信息
        agent_url: Agent服务URL
    """
    executor = PluginExecutor(task_id, task_type, target, config, agent_url)
    executor.run()


# ============================================================
# 模块导出
# ============================================================

__all__ = [
    'PluginExecutor',
    'ExecutionResult',
    'PluginLogHandler',
    'PLUGIN_IMPORTS',
    'VULN_SCAN_PLUGINS',
    'POC_FUNCTIONS',
    'format_scan_result',
    'get_available_plugins',
    'run_plugin_process'
]
