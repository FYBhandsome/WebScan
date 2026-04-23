"""
LangGraph 图构建

构建支持自主规划、代码生成、环境感知的完整Agent工作流。

日志记录:
- 时间戳:所有日志包含时间戳
- 操作类型:节点进入/退出、状态变更、决策结果、错误信息
- 对象标识:任务ID、节点名称、状态键名
- 详细描述:操作的具体内容和结果
"""
import json
import logging
import time
from typing import Dict, Any, Literal, Optional, Union
from langgraph.graph import StateGraph, END

from .state import AgentState
from .nodes import (
    VulnerabilityAnalysisNode,
    ReportGenerationNode,
    EnvironmentAwarenessNode,
    AIDecisionNode,
    ToolExecutionNode
)
from .tools import initialize_tools
from .agent_config import agent_config

logger = logging.getLogger(__name__)


class ScanAgentGraph:
    """
    扫描Agent图类
    
    负责构建和编译LangGraph工作流。
    """
    
    def __init__(self):
        """
        初始化扫描Agent图
        """
        logger.info("🔧 初始化扫描Agent图")
        
        initialize_tools()
        
        self.env_awareness_node = EnvironmentAwarenessNode()
        self.ai_decision_node = AIDecisionNode()
        self.tool_execution_node = ToolExecutionNode()
        self.report_node = ReportGenerationNode()
        
        self.graph = self._build_graph()
        
        logger.info("✅ 扫描Agent图构建完成（AI决策驱动模式）")
    
    def _build_graph(self) -> StateGraph:
        """
        构建LangGraph图 (AI决策驱动版)

        实现简化的工作流:
        [START] → 环境感知 → AI决策节点 → 工具执行 → AI决策节点（循环）
                                            ↓
                                      报告生成 → END

        Returns:
            StateGraph: 编译后的图
        """

        workflow = StateGraph(AgentState)

        workflow.add_node("environment_awareness", self.env_awareness_node)
        workflow.add_node("ai_decide", self.ai_decision_node)
        workflow.add_node("tool_execution", self.tool_execution_node)
        workflow.add_node("report_generation", self.report_node)

        workflow.set_entry_point("environment_awareness")

        workflow.add_edge("environment_awareness", "ai_decide")

        workflow.add_conditional_edges(
            "ai_decide",
            self._route_ai_decision,
            {
                "tool": "tool_execution",
                "end": "report_generation"
            }
        )

        workflow.add_edge("tool_execution", "ai_decide")

        workflow.add_edge("report_generation", END)

        logger.info("📊 LangGraph图边定义完成（AI决策驱动模式）")
        return workflow
    
    def _route_ai_decision(self, state: AgentState) -> Literal["tool", "end"]:
        """
        根据AI决策路由到对应节点

        Args:
            state: Agent当前状态

        Returns:
            Literal["tool", "end"]: 下一步节点名称
        """
        next_action = state.target_context.get("next_action", "end")
        
        if next_action == "end" or not state.planned_tasks:
            logger.info(f"[{state.task_id}] 📋 AI决策路由: 结束扫描")
            return "end"
        
        logger.info(f"[{state.task_id}] 📋 AI决策路由: 执行工具")
        return "tool"

    def compile(self):
        """
        编译完整图
        
        Returns:
            编译后的可执行图
        """
        return self.graph.compile()
    
    async def invoke(self, initial_state: AgentState) -> AgentState:
        """
        执行Agent工作流(AI决策驱动版)
        
        Args:
            initial_state: 初始状态
            
        Returns:
            AgentState: 最终状态
        """
        logger.info(f"🚀 开始执行Agent工作流: {initial_state.task_id}")
        
        try:
            compiled_graph = self.compile()
            config = {"recursion_limit": 100}
            final_state = await compiled_graph.ainvoke(initial_state, config=config)
            
            if isinstance(final_state, dict):
                final_state = AgentState.from_dict(final_state)
            
            task_id = getattr(final_state, 'task_id', initial_state.task_id)
            completed_tasks = getattr(final_state, 'completed_tasks', [])
            vulnerabilities = getattr(final_state, 'vulnerabilities', [])
            
            logger.info(
                f"✅ Agent工作流执行完成: {task_id} | "
                f"完成任务: {len(completed_tasks)} | 发现漏洞: {len(vulnerabilities)}"
            )
            
            return final_state
        except Exception as e:
            logger.error(f"❌ Agent工作流执行失败: {initial_state.task_id}, 错误: {str(e)}")
            raise
    

def create_agent_graph() -> ScanAgentGraph:
    """
    创建Agent图实例
    
    Returns:
        ScanAgentGraph: Agent图实例
    """
    return ScanAgentGraph()


def initialize_tools():
    """
    初始化所有工具
    
    注册所有插件和POC到工具注册表。
    """
    from ..tools.registry import registry
    from ..tools.adapters import PluginAdapter, POCAdapter
    
    logger.info("🔧 开始初始化工具...")
    
    # 注册插件 - 注意：传递函数引用而不是调用结果
    registry.register(
        name="baseinfo",
        func=PluginAdapter.adapt_baseinfo,
        description="基础信息收集(域名、IP、服务器、OS等)",
        category="plugin",
        timeout=60,
        priority=3
    )
    
    registry.register(
        name="portscan",
        func=PluginAdapter.adapt_portscan,
        description="TCP端口扫描,识别开放端口和服务",
        category="plugin",
        timeout=120,
        priority=5
    )
    
    registry.register(
        name="waf_detect",
        func=PluginAdapter.adapt_waf_detect,
        description="WAF(Web应用防火墙)检测",
        category="plugin",
        timeout=60,
        priority=4
    )
    
    registry.register(
        name="cdn_detect",
        func=PluginAdapter.adapt_cdn_detect,
        description="CDN(内容分发网络)检测",
        category="plugin",
        timeout=30,
        priority=4
    )
    
    registry.register(
        name="cms_identify",
        func=PluginAdapter.adapt_cms_identify,
        description="CMS(内容管理系统)识别",
        category="plugin",
        timeout=15,
        priority=4
    )
    
    registry.register(
        name="infoleak_scan",
        func=PluginAdapter.adapt_infoleak_scan,
        description="信息泄露扫描",
        category="plugin",
        timeout=30,
        priority=3
    )
    
    registry.register(
        name="subdomain_scan",
        func=PluginAdapter.adapt_subdomain_scan,
        description="子域名枚举",
        category="plugin",
        timeout=60,
        priority=3
    )
    
    registry.register(
        name="webside_scan",
        func=PluginAdapter.adapt_webside_scan,
        description="站点信息收集",
        category="plugin",
        timeout=30,
        priority=3
    )
    
    registry.register(
        name="webweight_scan",
        func=PluginAdapter.adapt_webweight_scan,
        description="网站权重查询",
        category="plugin",
        timeout=30,
        priority=2
    )
    
    registry.register(
        name="iplocating",
        func=PluginAdapter.adapt_iplocating,
        description="IP地址定位",
        category="plugin",
        timeout=30,
        priority=3
    )
    
    registry.register(
        name="loginfo",
        func=PluginAdapter.adapt_loginfo,
        description="日志信息分析",
        category="plugin",
        timeout=30,
        priority=2
    )
    
    registry.register(
        name="randheader",
        func=PluginAdapter.adapt_randheader,
        description="随机HTTP请求头生成",
        category="plugin",
        timeout=30,
        priority=2
    )
    
    registry.register(
        name="dirscan",
        func=PluginAdapter.adapt_dirscan,
        description="目录扫描(敏感目录和文件爆破)",
        category="plugin",
        timeout=180,
        priority=5
    )
    
    logger.info(f"✅ 工具初始化完成,共注册 {len(registry.tools)} 个工具")
    
    logger.info("🔧 开始注册POC工具...")
    pocs = POCAdapter.get_all_pocs()
    for poc_name, poc_module in pocs.items():
        def create_poc_func(poc_name=poc_name, poc_module=poc_module):
            async def poc_func(target: str, timeout: Optional[float] = None, progress_callback=None, **kwargs):
                return await POCAdapter.adapt_poc(
                    target=target,
                    poc_name=poc_name,
                    poc_module=poc_module,
                    timeout=timeout,
                    progress_callback=progress_callback
                )
            return poc_func
        
        registry.register(
            name=poc_name,
            func=create_poc_func(),
            description=f"POC漏洞检测: {poc_name}",
            category="poc",
            timeout=POCAdapter.DEFAULT_POC_TIMEOUT,
            priority=6,
            tags=["poc", "vulnerability", "exploit"],
            enabled=True
        )
    
    logger.info(f"✅ POC工具初始化完成,共注册 {len(pocs)} 个POC工具")
    
    registry.register(
        name="sqli_scan",
        func=PluginAdapter.adapt_sqli_scan,
        description="SQL注入漏洞扫描(检测基于错误、时间盲注、布尔盲注等SQL注入)",
        category="vuln_scan",
        timeout=120,
        priority=7,
        tags=["vulnerability", "sqli", "injection", "security"]
    )
    
    registry.register(
        name="xss_scan",
        func=PluginAdapter.adapt_xss_scan,
        description="XSS漏洞扫描(检测反射型、存储型、DOM型XSS)",
        category="vuln_scan",
        timeout=120,
        priority=7,
        tags=["vulnerability", "xss", "security"]
    )
    
    registry.register(
        name="csrf_scan",
        func=PluginAdapter.adapt_csrf_scan,
        description="CSRF漏洞扫描(检测CSRF令牌缺失、Referer验证缺失)",
        category="vuln_scan",
        timeout=60,
        priority=6,
        tags=["vulnerability", "csrf", "security"]
    )
    
    registry.register(
        name="vuln_infoleak_scan",
        func=PluginAdapter.adapt_vuln_infoleak_scan,
        description="敏感信息泄露扫描(检测敏感文件、敏感信息模式)",
        category="vuln_scan",
        timeout=60,
        priority=5,
        tags=["vulnerability", "infoleak", "security"]
    )
    
    registry.register(
        name="crawler",
        func=PluginAdapter.adapt_crawler,
        description="Web爬虫(自动发现页面、链接、表单和参数)",
        category="plugin",
        timeout=300,
        priority=1,
        tags=["crawler", "spider", "discovery"]
    )
    
    registry.register(
        name="fileupload_scan",
        func=PluginAdapter.adapt_fileupload_scan,
        description="文件上传漏洞扫描(检测上传点、绕过技术)",
        category="vuln_scan",
        timeout=120,
        priority=8,
        tags=["vulnerability", "fileupload", "rce", "security"]
    )
    
    registry.register(
        name="cmdi_scan",
        func=PluginAdapter.adapt_cmdi_scan,
        description="命令注入漏洞扫描(检测OS命令执行漏洞)",
        category="vuln_scan",
        timeout=180,
        priority=9,
        tags=["vulnerability", "cmdi", "rce", "security"]
    )
    
    registry.register(
        name="weakpass_scan",
        func=PluginAdapter.adapt_weakpass_scan,
        description="弱口令扫描(检测常见用户名密码组合)",
        category="vuln_scan",
        timeout=300,
        priority=7,
        tags=["vulnerability", "weakpass", "brute-force", "security"]
    )
    
    registry.register(
        name="lfi_scan",
        func=PluginAdapter.adapt_lfi_scan,
        description="文件包含漏洞扫描(检测LFI/RFI/目录遍历)",
        category="vuln_scan",
        timeout=180,
        priority=8,
        tags=["vulnerability", "lfi", "rfi", "path-traversal", "security"]
    )
    
    registry.register(
        name="ssrf_scan",
        func=PluginAdapter.adapt_ssrf_scan,
        description="SSRF漏洞扫描(检测服务端请求伪造)",
        category="vuln_scan",
        timeout=180,
        priority=8,
        tags=["vulnerability", "ssrf", "security"]
    )
    
    logger.info(f"✅ 漏洞扫描工具初始化完成,共注册 10 个漏洞扫描工具")
