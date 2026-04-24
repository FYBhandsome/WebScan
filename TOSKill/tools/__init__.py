# -*- coding:utf-8 -*-
"""
TOSKill工具模块
整合所有安全测试工具，提供统一的工具注册和查找接口
"""

from TOSKill.tools.info_collection import INFO_COLLECTION_TOOLS
from TOSKill.tools.poc import POC_TOOLS
from TOSKill.tools.vuln_scan import VULN_SCAN_TOOLS
from TOSKill.tools.report import REPORT_TOOLS

from TOSKill.tools.info_collection import (
    baseinfo,
    portscan,
    subdomain,
    dirscan,
    waf_detect,
    cdn_detect,
    cms_detect,
    infoleak_scan,
    ip_locate,
    log_handler,
    random_headers,
    webside_query,
    web_weight,
)

from TOSKill.tools.poc import (
    drupal_cve_2018_7600,
    jboss_cve_2017_12149,
    nexus_cve_2020_10199,
    struts2_s2_009,
    struts2_s2_032,
    thinkphp_rce,
    thinkphp_cmd_rce,
    tomcat_cve_2017_12615,
    weblogic_cve_2018_2628,
    weblogic_cve_2018_2894,
    weblogic_cve_2020_2551,
    weblogic_cve_2023_21839,
)

from TOSKill.tools.vuln_scan import (
    sqli_scan,
    xss_scan,
    csrf_scan,
    fileupload_scan,
    cmdi_scan,
    ssrf_scan,
    lfi_scan,
    weakpass_scan,
)

from TOSKill.tools.report import (
    ai_analyzer,
    vuln_analyzer,
    vuln_analyzer_async,
    ReportSaver,
    save_report,
    generate_report,
    get_default_saver,
)

ALL_TOOLS = INFO_COLLECTION_TOOLS + POC_TOOLS + VULN_SCAN_TOOLS + REPORT_TOOLS

TOOLS_BY_CATEGORY = {
    "info_collection": INFO_COLLECTION_TOOLS,
    "poc": POC_TOOLS,
    "vuln_scan": VULN_SCAN_TOOLS,
    "report": REPORT_TOOLS,
}

TOOL_CATEGORIES = list(TOOLS_BY_CATEGORY.keys())

TOOL_COUNT = {
    "info_collection": len(INFO_COLLECTION_TOOLS),
    "poc": len(POC_TOOLS),
    "vuln_scan": len(VULN_SCAN_TOOLS),
    "report": len(REPORT_TOOLS),
    "total": len(ALL_TOOLS),
}


def get_tool_by_name(name: str):
    """根据名称获取工具
    
    Args:
        name: 工具名称
        
    Returns:
        找到的工具对象，如果未找到则返回None
    """
    for tool in ALL_TOOLS:
        if hasattr(tool, 'name') and tool.name == name:
            return tool
    return None


def get_tools_by_category(category: str):
    """根据类别获取工具列表
    
    Args:
        category: 工具类别，可选值: info_collection, poc, vuln_scan, report
        
    Returns:
        该类别的工具列表，如果类别不存在则返回空列表
    """
    return TOOLS_BY_CATEGORY.get(category, [])


def get_all_tool_names():
    """获取所有工具名称列表
    
    Returns:
        所有工具名称的列表
    """
    return [tool.name for tool in ALL_TOOLS if hasattr(tool, 'name')]


def get_tools_by_names(names: list):
    """根据名称列表获取多个工具
    
    Args:
        names: 工具名称列表
        
    Returns:
        找到的工具列表（跳过未找到的工具）
    """
    tools = []
    for name in names:
        tool = get_tool_by_name(name)
        if tool:
            tools.append(tool)
    return tools


def list_tools():
    """列出所有工具及其类别
    
    Returns:
        格式化的工具列表信息
    """
    result = {}
    for category, tools in TOOLS_BY_CATEGORY.items():
        result[category] = [tool.name for tool in tools if hasattr(tool, 'name')]
    return result


def register_dynamic_tool(tool, category: str = "custom"):
    """动态注册工具到全局工具列表
    
    Args:
        tool: LangChain Tool 对象
        category: 工具类别，默认为 "custom"
        
    Returns:
        bool: 注册是否成功
    """
    global ALL_TOOLS, TOOLS_BY_CATEGORY
    
    try:
        if not hasattr(tool, 'name'):
            logger.warning(f"工具缺少 name 属性，无法注册")
            return False
        
        if category not in TOOLS_BY_CATEGORY:
            TOOLS_BY_CATEGORY[category] = []
        
        existing_names = [t.name for t in ALL_TOOLS if hasattr(t, 'name')]
        if tool.name in existing_names:
            logger.warning(f"工具 {tool.name} 已存在，跳过注册")
            return False
        
        ALL_TOOLS.append(tool)
        TOOLS_BY_CATEGORY[category].append(tool)
        
        if category not in TOOL_CATEGORIES:
            TOOL_CATEGORIES.append(category)
        
        TOOL_COUNT[category] = len(TOOLS_BY_CATEGORY[category])
        TOOL_COUNT["total"] = len(ALL_TOOLS)
        
        logger.info(f"成功注册动态工具: {tool.name} (类别: {category})")
        return True
        
    except Exception as e:
        logger.error(f"注册动态工具失败: {str(e)}")
        return False


def create_tool_from_script(script_path: str, tool_name: str, description: str):
    """从脚本文件创建 LangChain Tool 对象
    
    Args:
        script_path: 脚本文件路径
        tool_name: 工具名称
        description: 工具描述
        
    Returns:
        LangChain Tool 对象，如果创建失败则返回 None
    """
    from langchain.tools import Tool
    import importlib.util
    
    try:
        spec = importlib.util.spec_from_file_location("custom_module", script_path)
        if not spec or not spec.loader:
            logger.error(f"无法加载脚本: {script_path}")
            return None
        
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        if not hasattr(module, 'run'):
            logger.error(f"脚本 {script_path} 缺少 run 函数")
            return None
        
        run_func = module.run
        
        def tool_func(target: str):
            try:
                import asyncio
                if asyncio.iscoroutinefunction(run_func):
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        import concurrent.futures
                        with concurrent.futures.ThreadPoolExecutor() as executor:
                            future = executor.submit(asyncio.run, run_func(target))
                            return future.result()
                    else:
                        return loop.run_until_complete(run_func(target))
                else:
                    return run_func(target)
            except Exception as e:
                return {
                    "success": False,
                    "error": str(e),
                    "data": None
                }
        
        tool = Tool(
            name=tool_name,
            description=description,
            func=tool_func
        )
        
        logger.info(f"成功从脚本创建工具: {tool_name}")
        return tool
        
    except Exception as e:
        logger.error(f"从脚本创建工具失败: {str(e)}")
        return None


import logging
logger = logging.getLogger(__name__)


__all__ = [
    "INFO_COLLECTION_TOOLS",
    "POC_TOOLS",
    "VULN_SCAN_TOOLS",
    "REPORT_TOOLS",
    "ALL_TOOLS",
    "TOOLS_BY_CATEGORY",
    "TOOL_CATEGORIES",
    "TOOL_COUNT",
    "get_tool_by_name",
    "get_tools_by_category",
    "get_all_tool_names",
    "get_tools_by_names",
    "list_tools",
    "register_dynamic_tool",
    "create_tool_from_script",
    "baseinfo",
    "portscan",
    "subdomain",
    "dirscan",
    "waf_detect",
    "cdn_detect",
    "cms_detect",
    "infoleak_scan",
    "ip_locate",
    "log_handler",
    "random_headers",
    "webside_query",
    "web_weight",
    "drupal_cve_2018_7600",
    "jboss_cve_2017_12149",
    "nexus_cve_2020_10199",
    "struts2_s2_009",
    "struts2_s2_032",
    "thinkphp_rce",
    "thinkphp_cmd_rce",
    "tomcat_cve_2017_12615",
    "weblogic_cve_2018_2628",
    "weblogic_cve_2018_2894",
    "weblogic_cve_2020_2551",
    "weblogic_cve_2023_21839",
    "sqli_scan",
    "xss_scan",
    "csrf_scan",
    "fileupload_scan",
    "cmdi_scan",
    "ssrf_scan",
    "lfi_scan",
    "weakpass_scan",
    "ai_analyzer",
    "vuln_analyzer",
    "vuln_analyzer_async",
    "ReportSaver",
    "save_report",
    "generate_report",
    "get_default_saver",
]
