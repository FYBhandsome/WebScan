"""
任务类型注册表系统

管理所有插件和 POC 的任务类型，提供统一的任务类型管理接口。

功能:
1. 注册所有插件类型(plugins, vulnerability_scan_plugins, poc)
2. 提供任务类型到执行器的映射
3. 提供任务类型验证功能
4. 支持动态扩展新的任务类型
5. 提供任务类型的元数据(名称、描述、类别、图标等)
"""

from enum import Enum
from typing import Dict, List, Optional, Any, Callable, Type
from dataclasses import dataclass, field
from datetime import datetime
import logging
import json
from pathlib import Path

logger = logging.getLogger(__name__)


class TaskCategory(Enum):
    """
    任务类型类别枚举
    
    定义任务类型的主要分类。
    """
    INFO_COLLECTION = "info_collection"
    VULNERABILITY_SCAN = "vulnerability_scan"
    POC_VERIFICATION = "poc_verification"
    COMPREHENSIVE_SCAN = "comprehensive_scan"
    EXTERNAL_SCAN = "external_scan"
    AI_AGENT = "ai_agent"
    OTHER = "other"


class TaskPriority(Enum):
    """
    任务优先级枚举
    
    定义任务执行的优先级。
    """
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    BACKGROUND = 5


class ExecutorType(Enum):
    """
    执行器类型枚举
    
    定义任务执行使用的执行器类型。
    """
    PLUGIN_EXECUTOR = "plugin_executor"
    VULN_SCAN_MANAGER = "vuln_scan_manager"
    POC_EXECUTOR = "poc_executor"
    AWVS_EXECUTOR = "awvs_executor"
    AI_AGENT_EXECUTOR = "ai_agent_executor"
    CUSTOM_EXECUTOR = "custom_executor"


@dataclass
class TaskTypeMetadata:
    """
    任务类型元数据
    
    存储任务类型的详细信息。
    
    Attributes:
        name: 任务类型名称（唯一标识符）
        display_name: 显示名称
        description: 任务描述
        category: 任务类别
        icon: 图标标识
        executor_type: 执行器类型
        priority: 默认优先级
        timeout: 默认超时时间（秒）
        enabled: 是否启用
        tags: 标签列表
        dependencies: 依赖的其他任务类型
        config_schema: 配置参数的 JSON Schema
        examples: 使用示例
        version: 版本号
        author: 作者
        created_at: 创建时间
        updated_at: 更新时间
    """
    name: str
    display_name: str
    description: str
    category: TaskCategory
    icon: str = "task"
    executor_type: ExecutorType = ExecutorType.PLUGIN_EXECUTOR
    priority: TaskPriority = TaskPriority.MEDIUM
    timeout: int = 300
    enabled: bool = True
    tags: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    config_schema: Optional[Dict[str, Any]] = None
    examples: List[Dict[str, Any]] = field(default_factory=list)
    version: str = "1.0.0"
    author: str = "system"
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "category": self.category.value,
            "icon": self.icon,
            "executor_type": self.executor_type.value,
            "priority": self.priority.value,
            "timeout": self.timeout,
            "enabled": self.enabled,
            "tags": self.tags,
            "dependencies": self.dependencies,
            "config_schema": self.config_schema,
            "examples": self.examples,
            "version": self.version,
            "author": self.author,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class TaskTypeRegistry:
    """
    任务类型注册表
    
    管理所有任务类型的注册、查询和验证。
    
    功能:
        - 注册新的任务类型
        - 获取任务类型元数据
        - 验证任务类型有效性
        - 获取所有任务类型列表
        - 按类别获取任务类型
        - 获取任务类型对应的执行器
        - 从配置文件动态加载任务类型
    
    Attributes:
        _task_types: 任务类型元数据字典
        _executors: 执行器映射字典
        _validators: 验证器字典
    """
    
    def __init__(self):
        """初始化任务类型注册表"""
        self._task_types: Dict[str, TaskTypeMetadata] = {}
        self._executors: Dict[str, Callable] = {}
        self._validators: Dict[str, Callable] = {}
        self._category_cache: Dict[TaskCategory, List[str]] = {}
        
        self._register_builtin_task_types()
        
        logger.info(f"TaskTypeRegistry 初始化完成，已注册 {len(self._task_types)} 个任务类型")
    
    def _register_builtin_task_types(self):
        """注册内置任务类型"""
        
        info_collection_tasks = [
            TaskTypeMetadata(
                name="portscan",
                display_name="端口扫描",
                description="扫描目标主机的开放端口和服务识别",
                category=TaskCategory.INFO_COLLECTION,
                icon="network_check",
                executor_type=ExecutorType.PLUGIN_EXECUTOR,
                priority=TaskPriority.HIGH,
                timeout=900,
                tags=["network", "port", "service"],
                config_schema={
                    "type": "object",
                    "properties": {
                        "ports": {"type": "string", "description": "端口范围，如 '1-1000' 或 '80,443,8080'"},
                        "timeout": {"type": "integer", "description": "连接超时时间(毫秒)"},
                    }
                }
            ),
            TaskTypeMetadata(
                name="baseinfo",
                display_name="基础信息收集",
                description="收集目标网站的基础信息，包括标题、服务器信息等",
                category=TaskCategory.INFO_COLLECTION,
                icon="info",
                executor_type=ExecutorType.PLUGIN_EXECUTOR,
                priority=TaskPriority.HIGH,
                timeout=120,
                tags=["info", "http", "header"],
            ),
            TaskTypeMetadata(
                name="webside",
                display_name="网站侧边信息",
                description="获取网站侧边栏和相关信息",
                category=TaskCategory.INFO_COLLECTION,
                icon="web",
                executor_type=ExecutorType.PLUGIN_EXECUTOR,
                priority=TaskPriority.MEDIUM,
                timeout=120,
                tags=["web", "info"],
            ),
            TaskTypeMetadata(
                name="webweight",
                display_name="网页权重检测",
                description="检测网页的权重和SEO相关信息",
                category=TaskCategory.INFO_COLLECTION,
                icon="scale",
                executor_type=ExecutorType.PLUGIN_EXECUTOR,
                priority=TaskPriority.LOW,
                timeout=120,
                tags=["seo", "weight"],
            ),
            TaskTypeMetadata(
                name="iplocating",
                display_name="IP地理位置定位",
                description="查询目标IP的地理位置信息",
                category=TaskCategory.INFO_COLLECTION,
                icon="location_on",
                executor_type=ExecutorType.PLUGIN_EXECUTOR,
                priority=TaskPriority.MEDIUM,
                timeout=60,
                tags=["ip", "geo", "location"],
            ),
            TaskTypeMetadata(
                name="cdnexist",
                display_name="CDN检测",
                description="检测目标是否使用CDN服务",
                category=TaskCategory.INFO_COLLECTION,
                icon="cloud",
                executor_type=ExecutorType.PLUGIN_EXECUTOR,
                priority=TaskPriority.MEDIUM,
                timeout=120,
                tags=["cdn", "network"],
            ),
            TaskTypeMetadata(
                name="whatcms",
                display_name="CMS识别",
                description="识别目标网站使用的CMS系统",
                category=TaskCategory.INFO_COLLECTION,
                icon="cms",
                executor_type=ExecutorType.PLUGIN_EXECUTOR,
                priority=TaskPriority.HIGH,
                timeout=180,
                tags=["cms", "fingerprint"],
            ),
            TaskTypeMetadata(
                name="subdomain",
                display_name="子域名扫描",
                description="扫描目标的子域名",
                category=TaskCategory.INFO_COLLECTION,
                icon="domain",
                executor_type=ExecutorType.PLUGIN_EXECUTOR,
                priority=TaskPriority.HIGH,
                timeout=600,
                tags=["domain", "subdomain", "dns"],
            ),
            TaskTypeMetadata(
                name="dirscan",
                display_name="目录扫描",
                description="扫描目标网站的目录和文件结构",
                category=TaskCategory.INFO_COLLECTION,
                icon="folder",
                executor_type=ExecutorType.PLUGIN_EXECUTOR,
                priority=TaskPriority.HIGH,
                timeout=600,
                tags=["directory", "path", "file"],
                config_schema={
                    "type": "object",
                    "properties": {
                        "wordlist": {"type": "string", "description": "字典文件路径"},
                        "extensions": {"type": "string", "description": "文件扩展名，如 'php,asp,jsp'"},
                        "threads": {"type": "integer", "description": "并发线程数"},
                    }
                }
            ),
            TaskTypeMetadata(
                name="crawler",
                display_name="网页爬虫",
                description="爬取目标网站的页面结构和链接",
                category=TaskCategory.INFO_COLLECTION,
                icon="bug_report",
                executor_type=ExecutorType.PLUGIN_EXECUTOR,
                priority=TaskPriority.MEDIUM,
                timeout=300,
                tags=["crawler", "spider", "link"],
            ),
            TaskTypeMetadata(
                name="loginfo",
                display_name="日志信息分析",
                description="分析目标网站的日志信息",
                category=TaskCategory.INFO_COLLECTION,
                icon="article",
                executor_type=ExecutorType.PLUGIN_EXECUTOR,
                priority=TaskPriority.MEDIUM,
                timeout=120,
                tags=["log", "info"],
            ),
        ]
        
        vulnerability_scan_tasks = [
            TaskTypeMetadata(
                name="sqli",
                display_name="SQL注入扫描",
                description="检测目标是否存在SQL注入漏洞",
                category=TaskCategory.VULNERABILITY_SCAN,
                icon="database",
                executor_type=ExecutorType.VULN_SCAN_MANAGER,
                priority=TaskPriority.CRITICAL,
                timeout=600,
                tags=["sqli", "injection", "database"],
                dependencies=["baseinfo"],
            ),
            TaskTypeMetadata(
                name="xss",
                display_name="XSS漏洞扫描",
                description="检测目标是否存在跨站脚本攻击(XSS)漏洞",
                category=TaskCategory.VULNERABILITY_SCAN,
                icon="code",
                executor_type=ExecutorType.VULN_SCAN_MANAGER,
                priority=TaskPriority.HIGH,
                timeout=600,
                tags=["xss", "script", "injection"],
                dependencies=["baseinfo"],
            ),
            TaskTypeMetadata(
                name="csrf",
                display_name="CSRF漏洞扫描",
                description="检测目标是否存在跨站请求伪造(CSRF)漏洞",
                category=TaskCategory.VULNERABILITY_SCAN,
                icon="security",
                executor_type=ExecutorType.VULN_SCAN_MANAGER,
                priority=TaskPriority.MEDIUM,
                timeout=300,
                tags=["csrf", "token"],
                dependencies=["crawler"],
            ),
            TaskTypeMetadata(
                name="ssrf",
                display_name="SSRF漏洞扫描",
                description="检测目标是否存在服务端请求伪造(SSRF)漏洞",
                category=TaskCategory.VULNERABILITY_SCAN,
                icon="cloud_sync",
                executor_type=ExecutorType.VULN_SCAN_MANAGER,
                priority=TaskPriority.HIGH,
                timeout=600,
                tags=["ssrf", "request", "injection"],
                dependencies=["baseinfo"],
            ),
            TaskTypeMetadata(
                name="lfi",
                display_name="本地文件包含扫描",
                description="检测目标是否存在本地文件包含(LFI)漏洞",
                category=TaskCategory.VULNERABILITY_SCAN,
                icon="folder_open",
                executor_type=ExecutorType.VULN_SCAN_MANAGER,
                priority=TaskPriority.HIGH,
                timeout=600,
                tags=["lfi", "file", "inclusion"],
                dependencies=["baseinfo"],
            ),
            TaskTypeMetadata(
                name="cmdi",
                display_name="命令注入扫描",
                description="检测目标是否存在命令注入漏洞",
                category=TaskCategory.VULNERABILITY_SCAN,
                icon="terminal",
                executor_type=ExecutorType.VULN_SCAN_MANAGER,
                priority=TaskPriority.CRITICAL,
                timeout=600,
                tags=["cmdi", "command", "injection", "rce"],
                dependencies=["baseinfo"],
            ),
            TaskTypeMetadata(
                name="fileupload",
                display_name="文件上传漏洞扫描",
                description="检测目标是否存在文件上传漏洞",
                category=TaskCategory.VULNERABILITY_SCAN,
                icon="upload_file",
                executor_type=ExecutorType.VULN_SCAN_MANAGER,
                priority=TaskPriority.HIGH,
                timeout=600,
                tags=["upload", "file", "rce"],
                dependencies=["crawler"],
            ),
            TaskTypeMetadata(
                name="weakpass",
                display_name="弱口令检测",
                description="检测目标是否存在弱口令",
                category=TaskCategory.VULNERABILITY_SCAN,
                icon="password",
                executor_type=ExecutorType.VULN_SCAN_MANAGER,
                priority=TaskPriority.HIGH,
                timeout=600,
                tags=["password", "brute", "weak"],
                dependencies=["baseinfo"],
            ),
            TaskTypeMetadata(
                name="infoleak",
                display_name="信息泄露检测",
                description="检测目标是否存在敏感信息泄露",
                category=TaskCategory.VULNERABILITY_SCAN,
                icon="leak",
                executor_type=ExecutorType.VULN_SCAN_MANAGER,
                priority=TaskPriority.MEDIUM,
                timeout=300,
                tags=["info", "leak", "sensitive"],
            ),
        ]
        
        poc_verification_tasks = [
            TaskTypeMetadata(
                name="weblogic_cve_2020_2551",
                display_name="WebLogic CVE-2020-2551",
                description="WebLogic IIOP反序列化远程代码执行漏洞(CVE-2020-2551)",
                category=TaskCategory.POC_VERIFICATION,
                icon="bug_report",
                executor_type=ExecutorType.POC_EXECUTOR,
                priority=TaskPriority.CRITICAL,
                timeout=300,
                tags=["weblogic", "cve", "rce", "deserialization"],
                examples=[{"target": "http://example.com:7001"}]
            ),
            TaskTypeMetadata(
                name="weblogic_cve_2018_2628",
                display_name="WebLogic CVE-2018-2628",
                description="WebLogic T3协议反序列化远程代码执行漏洞(CVE-2018-2628)",
                category=TaskCategory.POC_VERIFICATION,
                icon="bug_report",
                executor_type=ExecutorType.POC_EXECUTOR,
                priority=TaskPriority.CRITICAL,
                timeout=300,
                tags=["weblogic", "cve", "rce", "deserialization"],
            ),
            TaskTypeMetadata(
                name="weblogic_cve_2018_2894",
                display_name="WebLogic CVE-2018-2894",
                description="WebLogic 任意文件上传漏洞(CVE-2018-2894)",
                category=TaskCategory.POC_VERIFICATION,
                icon="bug_report",
                executor_type=ExecutorType.POC_EXECUTOR,
                priority=TaskPriority.CRITICAL,
                timeout=300,
                tags=["weblogic", "cve", "upload", "rce"],
            ),
            TaskTypeMetadata(
                name="struts2_009",
                display_name="Struts2 S2-009",
                description="Struts2 OGNL表达式注入漏洞(S2-009)",
                category=TaskCategory.POC_VERIFICATION,
                icon="bug_report",
                executor_type=ExecutorType.POC_EXECUTOR,
                priority=TaskPriority.CRITICAL,
                timeout=300,
                tags=["struts2", "ognl", "rce"],
            ),
            TaskTypeMetadata(
                name="struts2_032",
                display_name="Struts2 S2-032",
                description="Struts2 动态方法调用远程代码执行漏洞(S2-032)",
                category=TaskCategory.POC_VERIFICATION,
                icon="bug_report",
                executor_type=ExecutorType.POC_EXECUTOR,
                priority=TaskPriority.CRITICAL,
                timeout=300,
                tags=["struts2", "dmi", "rce"],
            ),
            TaskTypeMetadata(
                name="tomcat_cve_2017_12615",
                display_name="Tomcat CVE-2017-12615",
                description="Tomcat PUT方法任意文件写入漏洞(CVE-2017-12615)",
                category=TaskCategory.POC_VERIFICATION,
                icon="bug_report",
                executor_type=ExecutorType.POC_EXECUTOR,
                priority=TaskPriority.HIGH,
                timeout=300,
                tags=["tomcat", "cve", "upload", "put"],
            ),
            TaskTypeMetadata(
                name="jboss_cve_2017_12149",
                display_name="JBoss CVE-2017-12149",
                description="JBoss JMXInvokerServlet反序列化漏洞(CVE-2017-12149)",
                category=TaskCategory.POC_VERIFICATION,
                icon="bug_report",
                executor_type=ExecutorType.POC_EXECUTOR,
                priority=TaskPriority.CRITICAL,
                timeout=300,
                tags=["jboss", "cve", "deserialization", "rce"],
            ),
            TaskTypeMetadata(
                name="nexus_cve_2020_10199",
                display_name="Nexus CVE-2020-10199",
                description="Nexus Repository Manager EL表达式注入漏洞(CVE-2020-10199)",
                category=TaskCategory.POC_VERIFICATION,
                icon="bug_report",
                executor_type=ExecutorType.POC_EXECUTOR,
                priority=TaskPriority.HIGH,
                timeout=300,
                tags=["nexus", "cve", "el", "injection"],
            ),
            TaskTypeMetadata(
                name="drupal_cve_2018_7600",
                display_name="Drupal CVE-2018-7600",
                description="Drupal 远程代码执行漏洞(CVE-2018-7600)",
                category=TaskCategory.POC_VERIFICATION,
                icon="bug_report",
                executor_type=ExecutorType.POC_EXECUTOR,
                priority=TaskPriority.CRITICAL,
                timeout=300,
                tags=["drupal", "cve", "rce"],
            ),
            TaskTypeMetadata(
                name="thinkphp_99617",
                display_name="ThinkPHP 远程代码执行",
                description="ThinkPHP 5.x 远程代码执行漏洞",
                category=TaskCategory.POC_VERIFICATION,
                icon="bug_report",
                executor_type=ExecutorType.POC_EXECUTOR,
                priority=TaskPriority.CRITICAL,
                timeout=300,
                tags=["thinkphp", "rce", "php"],
            ),
        ]
        
        comprehensive_scan_tasks = [
            TaskTypeMetadata(
                name="comprehensive",
                display_name="综合扫描",
                description="执行全面的综合安全扫描",
                category=TaskCategory.COMPREHENSIVE_SCAN,
                icon="radar",
                executor_type=ExecutorType.PLUGIN_EXECUTOR,
                priority=TaskPriority.HIGH,
                timeout=1800,
                tags=["comprehensive", "full", "scan"],
                dependencies=["portscan", "baseinfo", "dirscan", "whatcms"],
            ),
            TaskTypeMetadata(
                name="waf",
                display_name="WAF检测",
                description="检测目标是否使用Web应用防火墙",
                category=TaskCategory.COMPREHENSIVE_SCAN,
                icon="shield",
                executor_type=ExecutorType.PLUGIN_EXECUTOR,
                priority=TaskPriority.MEDIUM,
                timeout=300,
                tags=["waf", "firewall", "detection"],
            ),
        ]
        
        external_scan_tasks = [
            TaskTypeMetadata(
                name="awvs_scan",
                display_name="AWVS扫描",
                description="使用AWVS进行专业漏洞扫描",
                category=TaskCategory.EXTERNAL_SCAN,
                icon="security",
                executor_type=ExecutorType.AWVS_EXECUTOR,
                priority=TaskPriority.HIGH,
                timeout=18000,
                tags=["awvs", "external", "professional"],
                config_schema={
                    "type": "object",
                    "properties": {
                        "profile": {"type": "string", "description": "扫描配置文件ID"},
                        "target_id": {"type": "string", "description": "目标ID"},
                    }
                }
            ),
            TaskTypeMetadata(
                name="poc_scan",
                display_name="POC批量扫描",
                description="使用POC进行批量漏洞验证",
                category=TaskCategory.POC_VERIFICATION,
                icon="verified",
                executor_type=ExecutorType.POC_EXECUTOR,
                priority=TaskPriority.HIGH,
                timeout=3600,
                tags=["poc", "batch", "verification"],
                config_schema={
                    "type": "object",
                    "properties": {
                        "poc_types": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "POC类型列表，如 ['weblogic', 'struts2']"
                        },
                        "vulnerabilities": {
                            "type": "array",
                            "description": "要验证的漏洞列表"
                        }
                    }
                }
            ),
        ]
        
        ai_agent_tasks = [
            TaskTypeMetadata(
                name="ai_agent_scan",
                display_name="AI Agent智能扫描",
                description="使用AI Agent进行智能化安全扫描和分析",
                category=TaskCategory.AI_AGENT,
                icon="smart_toy",
                executor_type=ExecutorType.AI_AGENT_EXECUTOR,
                priority=TaskPriority.HIGH,
                timeout=18000,
                tags=["ai", "agent", "intelligent", "scan"],
                config_schema={
                    "type": "object",
                    "properties": {
                        "strategy": {
                            "type": "string",
                            "enum": ["quick", "standard", "deep"],
                            "description": "扫描策略"
                        },
                        "selected_tools": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "选择的工具列表"
                        },
                        "user_requirement": {
                            "type": "string",
                            "description": "用户自定义需求"
                        }
                    }
                }
            ),
        ]
        
        legacy_task_types = [
            TaskTypeMetadata(
                name="port_scan",
                display_name="端口扫描(Legacy)",
                description="端口扫描任务(兼容旧版)",
                category=TaskCategory.INFO_COLLECTION,
                icon="network_check",
                executor_type=ExecutorType.PLUGIN_EXECUTOR,
                priority=TaskPriority.HIGH,
                timeout=900,
                tags=["legacy", "port"],
            ),
            TaskTypeMetadata(
                name="dir_scan",
                display_name="目录扫描(Legacy)",
                description="目录扫描任务(兼容旧版)",
                category=TaskCategory.INFO_COLLECTION,
                icon="folder",
                executor_type=ExecutorType.PLUGIN_EXECUTOR,
                priority=TaskPriority.HIGH,
                timeout=600,
                tags=["legacy", "directory"],
            ),
            TaskTypeMetadata(
                name="info_leak",
                display_name="信息泄露检测(Legacy)",
                description="信息泄露检测任务(兼容旧版)",
                category=TaskCategory.VULNERABILITY_SCAN,
                icon="leak",
                executor_type=ExecutorType.PLUGIN_EXECUTOR,
                priority=TaskPriority.MEDIUM,
                timeout=300,
                tags=["legacy", "info", "leak"],
            ),
            TaskTypeMetadata(
                name="web_side",
                display_name="网站侧边信息(Legacy)",
                description="网站侧边信息任务(兼容旧版)",
                category=TaskCategory.INFO_COLLECTION,
                icon="web",
                executor_type=ExecutorType.PLUGIN_EXECUTOR,
                priority=TaskPriority.MEDIUM,
                timeout=120,
                tags=["legacy", "web"],
            ),
            TaskTypeMetadata(
                name="base_info",
                display_name="基础信息收集(Legacy)",
                description="基础信息收集任务(兼容旧版)",
                category=TaskCategory.INFO_COLLECTION,
                icon="info",
                executor_type=ExecutorType.PLUGIN_EXECUTOR,
                priority=TaskPriority.HIGH,
                timeout=120,
                tags=["legacy", "info"],
            ),
            TaskTypeMetadata(
                name="cdn_check",
                display_name="CDN检测(Legacy)",
                description="CDN检测任务(兼容旧版)",
                category=TaskCategory.INFO_COLLECTION,
                icon="cloud",
                executor_type=ExecutorType.PLUGIN_EXECUTOR,
                priority=TaskPriority.MEDIUM,
                timeout=120,
                tags=["legacy", "cdn"],
            ),
            TaskTypeMetadata(
                name="waf_check",
                display_name="WAF检测(Legacy)",
                description="WAF检测任务(兼容旧版)",
                category=TaskCategory.COMPREHENSIVE_SCAN,
                icon="shield",
                executor_type=ExecutorType.PLUGIN_EXECUTOR,
                priority=TaskPriority.MEDIUM,
                timeout=300,
                tags=["legacy", "waf"],
            ),
            TaskTypeMetadata(
                name="ip_locating",
                display_name="IP地理位置定位(Legacy)",
                description="IP地理位置定位任务(兼容旧版)",
                category=TaskCategory.INFO_COLLECTION,
                icon="location_on",
                executor_type=ExecutorType.PLUGIN_EXECUTOR,
                priority=TaskPriority.MEDIUM,
                timeout=60,
                tags=["legacy", "ip", "geo"],
            ),
            TaskTypeMetadata(
                name="scan_dir",
                display_name="目录扫描(Legacy)",
                description="目录扫描任务(兼容旧版)",
                category=TaskCategory.INFO_COLLECTION,
                icon="folder",
                executor_type=ExecutorType.PLUGIN_EXECUTOR,
                priority=TaskPriority.HIGH,
                timeout=600,
                tags=["legacy", "directory"],
            ),
            TaskTypeMetadata(
                name="scan_webside",
                display_name="网站侧边扫描(Legacy)",
                description="网站侧边扫描任务(兼容旧版)",
                category=TaskCategory.INFO_COLLECTION,
                icon="web",
                executor_type=ExecutorType.PLUGIN_EXECUTOR,
                priority=TaskPriority.MEDIUM,
                timeout=120,
                tags=["legacy", "web"],
            ),
            TaskTypeMetadata(
                name="scan_port",
                display_name="端口扫描(Legacy)",
                description="端口扫描任务(兼容旧版)",
                category=TaskCategory.INFO_COLLECTION,
                icon="network_check",
                executor_type=ExecutorType.PLUGIN_EXECUTOR,
                priority=TaskPriority.HIGH,
                timeout=900,
                tags=["legacy", "port"],
            ),
            TaskTypeMetadata(
                name="scan_cms",
                display_name="CMS识别(Legacy)",
                description="CMS识别任务(兼容旧版)",
                category=TaskCategory.INFO_COLLECTION,
                icon="cms",
                executor_type=ExecutorType.PLUGIN_EXECUTOR,
                priority=TaskPriority.HIGH,
                timeout=180,
                tags=["legacy", "cms"],
            ),
            TaskTypeMetadata(
                name="scan_comprehensive",
                display_name="综合扫描(Legacy)",
                description="综合扫描任务(兼容旧版)",
                category=TaskCategory.COMPREHENSIVE_SCAN,
                icon="radar",
                executor_type=ExecutorType.PLUGIN_EXECUTOR,
                priority=TaskPriority.HIGH,
                timeout=1800,
                tags=["legacy", "comprehensive"],
            ),
        ]
        
        all_tasks = (
            info_collection_tasks +
            vulnerability_scan_tasks +
            poc_verification_tasks +
            comprehensive_scan_tasks +
            external_scan_tasks +
            ai_agent_tasks +
            legacy_task_types
        )
        
        for task_metadata in all_tasks:
            self._task_types[task_metadata.name] = task_metadata
        
        self._rebuild_category_cache()
    
    def _rebuild_category_cache(self):
        """重建类别缓存"""
        self._category_cache.clear()
        for name, metadata in self._task_types.items():
            if metadata.category not in self._category_cache:
                self._category_cache[metadata.category] = []
            self._category_cache[metadata.category].append(name)
    
    def register_task_type(
        self,
        name: str,
        display_name: str,
        description: str,
        category: TaskCategory,
        icon: str = "task",
        executor_type: ExecutorType = ExecutorType.PLUGIN_EXECUTOR,
        priority: TaskPriority = TaskPriority.MEDIUM,
        timeout: int = 300,
        enabled: bool = True,
        tags: Optional[List[str]] = None,
        dependencies: Optional[List[str]] = None,
        config_schema: Optional[Dict[str, Any]] = None,
        examples: Optional[List[Dict[str, Any]]] = None,
        version: str = "1.0.0",
        author: str = "custom",
    ) -> bool:
        """
        注册新的任务类型
        
        Args:
            name: 任务类型名称（唯一标识符）
            display_name: 显示名称
            description: 任务描述
            category: 任务类别
            icon: 图标标识
            executor_type: 执行器类型
            priority: 默认优先级
            timeout: 默认超时时间（秒）
            enabled: 是否启用
            tags: 标签列表
            dependencies: 依赖的其他任务类型
            config_schema: 配置参数的 JSON Schema
            examples: 使用示例
            version: 版本号
            author: 作者
            
        Returns:
            bool: 注册是否成功
        """
        if name in self._task_types:
            logger.warning(f"任务类型 {name} 已存在，将被覆盖")
        
        metadata = TaskTypeMetadata(
            name=name,
            display_name=display_name,
            description=description,
            category=category,
            icon=icon,
            executor_type=executor_type,
            priority=priority,
            timeout=timeout,
            enabled=enabled,
            tags=tags or [],
            dependencies=dependencies or [],
            config_schema=config_schema,
            examples=examples or [],
            version=version,
            author=author,
        )
        
        self._task_types[name] = metadata
        self._rebuild_category_cache()
        
        logger.info(f"成功注册任务类型: {name} ({category.value})")
        return True
    
    def register_task_type_from_dict(self, task_type_data: Dict[str, Any]) -> bool:
        """
        从字典注册任务类型
        
        Args:
            task_type_data: 任务类型数据字典
            
        Returns:
            bool: 注册是否成功
        """
        try:
            category_str = task_type_data.get("category", "other")
            category = TaskCategory(category_str) if category_str in [c.value for c in TaskCategory] else TaskCategory.OTHER
            
            executor_type_str = task_type_data.get("executor_type", "plugin_executor")
            executor_type = ExecutorType(executor_type_str) if executor_type_str in [e.value for e in ExecutorType] else ExecutorType.PLUGIN_EXECUTOR
            
            priority_val = task_type_data.get("priority", 3)
            priority = TaskPriority(priority_val) if isinstance(priority_val, int) else TaskPriority.MEDIUM
            
            return self.register_task_type(
                name=task_type_data["name"],
                display_name=task_type_data.get("display_name", task_type_data["name"]),
                description=task_type_data.get("description", ""),
                category=category,
                icon=task_type_data.get("icon", "task"),
                executor_type=executor_type,
                priority=priority,
                timeout=task_type_data.get("timeout", 300),
                enabled=task_type_data.get("enabled", True),
                tags=task_type_data.get("tags", []),
                dependencies=task_type_data.get("dependencies", []),
                config_schema=task_type_data.get("config_schema"),
                examples=task_type_data.get("examples", []),
                version=task_type_data.get("version", "1.0.0"),
                author=task_type_data.get("author", "custom"),
            )
        except Exception as e:
            logger.error(f"从字典注册任务类型失败: {e}")
            return False
    
    def unregister_task_type(self, name: str) -> bool:
        """
        注销任务类型
        
        Args:
            name: 任务类型名称
            
        Returns:
            bool: 注销是否成功
        """
        if name not in self._task_types:
            logger.warning(f"任务类型 {name} 不存在")
            return False
        
        del self._task_types[name]
        self._rebuild_category_cache()
        
        if name in self._executors:
            del self._executors[name]
        if name in self._validators:
            del self._validators[name]
        
        logger.info(f"成功注销任务类型: {name}")
        return True
    
    def get_task_type_metadata(self, name: str) -> Optional[TaskTypeMetadata]:
        """
        获取任务类型元数据
        
        Args:
            name: 任务类型名称
            
        Returns:
            Optional[TaskTypeMetadata]: 任务类型元数据，不存在则返回None
        """
        return self._task_types.get(name)
    
    def validate_task_type(self, name: str) -> bool:
        """
        验证任务类型是否有效
        
        Args:
            name: 任务类型名称
            
        Returns:
            bool: 是否有效
        """
        if name not in self._task_types:
            return False
        
        metadata = self._task_types[name]
        if not metadata.enabled:
            return False
        
        if name in self._validators:
            try:
                return self._validators[name](name)
            except Exception as e:
                logger.error(f"验证器执行失败: {e}")
                return False
        
        return True
    
    def get_all_task_types(self, enabled_only: bool = True) -> List[Dict[str, Any]]:
        """
        获取所有任务类型列表
        
        Args:
            enabled_only: 是否只返回启用的任务类型
            
        Returns:
            List[Dict[str, Any]]: 任务类型列表
        """
        result = []
        for name, metadata in self._task_types.items():
            if enabled_only and not metadata.enabled:
                continue
            result.append(metadata.to_dict())
        
        return sorted(result, key=lambda x: (x["category"], x["priority"]))
    
    def get_task_types_by_category(
        self,
        category: TaskCategory,
        enabled_only: bool = True
    ) -> List[Dict[str, Any]]:
        """
        按类别获取任务类型
        
        Args:
            category: 任务类别
            enabled_only: 是否只返回启用的任务类型
            
        Returns:
            List[Dict[str, Any]]: 任务类型列表
        """
        result = []
        task_names = self._category_cache.get(category, [])
        
        for name in task_names:
            metadata = self._task_types.get(name)
            if metadata:
                if enabled_only and not metadata.enabled:
                    continue
                result.append(metadata.to_dict())
        
        return sorted(result, key=lambda x: x["priority"])
    
    def get_task_types_by_tag(
        self,
        tag: str,
        enabled_only: bool = True
    ) -> List[Dict[str, Any]]:
        """
        按标签获取任务类型
        
        Args:
            tag: 标签名称
            enabled_only: 是否只返回启用的任务类型
            
        Returns:
            List[Dict[str, Any]]: 任务类型列表
        """
        result = []
        for name, metadata in self._task_types.items():
            if enabled_only and not metadata.enabled:
                continue
            if tag in metadata.tags:
                result.append(metadata.to_dict())
        
        return result
    
    def register_executor(self, task_type: str, executor: Callable) -> bool:
        """
        注册任务类型对应的执行器
        
        Args:
            task_type: 任务类型名称
            executor: 执行器函数
            
        Returns:
            bool: 注册是否成功
        """
        if task_type not in self._task_types:
            logger.warning(f"任务类型 {task_type} 不存在，无法注册执行器")
            return False
        
        self._executors[task_type] = executor
        logger.info(f"成功为任务类型 {task_type} 注册执行器")
        return True
    
    def get_executor_for_task_type(self, task_type: str) -> Optional[Callable]:
        """
        获取任务类型对应的执行器
        
        Args:
            task_type: 任务类型名称
            
        Returns:
            Optional[Callable]: 执行器函数，不存在则返回None
        """
        return self._executors.get(task_type)
    
    def get_executor_type(self, task_type: str) -> Optional[ExecutorType]:
        """
        获取任务类型的执行器类型
        
        Args:
            task_type: 任务类型名称
            
        Returns:
            Optional[ExecutorType]: 执行器类型
        """
        metadata = self.get_task_type_metadata(task_type)
        if metadata:
            return metadata.executor_type
        return None
    
    def register_validator(self, task_type: str, validator: Callable) -> bool:
        """
        注册任务类型验证器
        
        Args:
            task_type: 任务类型名称
            validator: 验证器函数
            
        Returns:
            bool: 注册是否成功
        """
        if task_type not in self._task_types:
            logger.warning(f"任务类型 {task_type} 不存在，无法注册验证器")
            return False
        
        self._validators[task_type] = validator
        logger.info(f"成功为任务类型 {task_type} 注册验证器")
        return True
    
    def get_task_type_timeout(self, task_type: str) -> int:
        """
        获取任务类型的默认超时时间
        
        Args:
            task_type: 任务类型名称
            
        Returns:
            int: 超时时间（秒）
        """
        metadata = self.get_task_type_metadata(task_type)
        if metadata:
            return metadata.timeout
        return 300
    
    def get_task_type_priority(self, task_type: str) -> TaskPriority:
        """
        获取任务类型的默认优先级
        
        Args:
            task_type: 任务类型名称
            
        Returns:
            TaskPriority: 优先级
        """
        metadata = self.get_task_type_metadata(task_type)
        if metadata:
            return metadata.priority
        return TaskPriority.MEDIUM
    
    def get_task_type_dependencies(self, task_type: str) -> List[str]:
        """
        获取任务类型的依赖
        
        Args:
            task_type: 任务类型名称
            
        Returns:
            List[str]: 依赖的任务类型列表
        """
        metadata = self.get_task_type_metadata(task_type)
        if metadata:
            return metadata.dependencies.copy()
        return []
    
    def search_task_types(
        self,
        keyword: str,
        enabled_only: bool = True
    ) -> List[Dict[str, Any]]:
        """
        搜索任务类型
        
        Args:
            keyword: 搜索关键词
            enabled_only: 是否只返回启用的任务类型
            
        Returns:
            List[Dict[str, Any]]: 匹配的任务类型列表
        """
        keyword_lower = keyword.lower()
        result = []
        
        for name, metadata in self._task_types.items():
            if enabled_only and not metadata.enabled:
                continue
            
            if (keyword_lower in name.lower() or
                keyword_lower in metadata.display_name.lower() or
                keyword_lower in metadata.description.lower() or
                any(keyword_lower in tag.lower() for tag in metadata.tags)):
                result.append(metadata.to_dict())
        
        return result
    
    def load_from_config_file(self, config_path: str) -> int:
        """
        从配置文件加载任务类型
        
        Args:
            config_path: 配置文件路径（JSON格式）
            
        Returns:
            int: 成功加载的任务类型数量
        """
        try:
            path = Path(config_path)
            if not path.exists():
                logger.error(f"配置文件不存在: {config_path}")
                return 0
            
            with open(path, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            
            if not isinstance(config_data, dict) or "task_types" not in config_data:
                logger.error(f"配置文件格式错误: {config_path}")
                return 0
            
            loaded_count = 0
            for task_type_data in config_data["task_types"]:
                if self.register_task_type_from_dict(task_type_data):
                    loaded_count += 1
            
            logger.info(f"从配置文件加载了 {loaded_count} 个任务类型")
            return loaded_count
            
        except Exception as e:
            logger.error(f"加载配置文件失败: {e}")
            return 0
    
    def export_to_config_file(self, config_path: str) -> bool:
        """
        导出任务类型到配置文件
        
        Args:
            config_path: 配置文件路径（JSON格式）
            
        Returns:
            bool: 导出是否成功
        """
        try:
            config_data = {
                "version": "1.0",
                "exported_at": datetime.now().isoformat(),
                "task_types": self.get_all_task_types(enabled_only=False)
            }
            
            path = Path(config_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, ensure_ascii=False, indent=2)
            
            logger.info(f"成功导出任务类型到: {config_path}")
            return True
            
        except Exception as e:
            logger.error(f"导出配置文件失败: {e}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        获取任务类型统计信息
        
        Returns:
            Dict[str, Any]: 统计信息
        """
        total_count = len(self._task_types)
        enabled_count = sum(1 for m in self._task_types.values() if m.enabled)
        
        category_counts = {}
        for category in TaskCategory:
            category_counts[category.value] = len(self._category_cache.get(category, []))
        
        executor_counts = {}
        for metadata in self._task_types.values():
            executor_type = metadata.executor_type.value
            executor_counts[executor_type] = executor_counts.get(executor_type, 0) + 1
        
        return {
            "total_count": total_count,
            "enabled_count": enabled_count,
            "disabled_count": total_count - enabled_count,
            "by_category": category_counts,
            "by_executor_type": executor_counts,
            "registered_executors": len(self._executors),
            "registered_validators": len(self._validators),
        }
    
    def enable_task_type(self, name: str) -> bool:
        """
        启用任务类型
        
        Args:
            name: 任务类型名称
            
        Returns:
            bool: 操作是否成功
        """
        metadata = self.get_task_type_metadata(name)
        if metadata:
            metadata.enabled = True
            metadata.updated_at = datetime.now().isoformat()
            logger.info(f"已启用任务类型: {name}")
            return True
        return False
    
    def disable_task_type(self, name: str) -> bool:
        """
        禁用任务类型
        
        Args:
            name: 任务类型名称
            
        Returns:
            bool: 操作是否成功
        """
        metadata = self.get_task_type_metadata(name)
        if metadata:
            metadata.enabled = False
            metadata.updated_at = datetime.now().isoformat()
            logger.info(f"已禁用任务类型: {name}")
            return True
        return False


task_type_registry = TaskTypeRegistry()
