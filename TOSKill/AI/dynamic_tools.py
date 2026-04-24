# -*- coding:utf-8 -*-
"""
动态工具注册管理器

提供动态工具的注册、注销和管理功能，支持从脚本代码创建工具并使用LLM分析脚本功能。
"""

import logging
import re
import hashlib
import asyncio
from typing import Dict, Any, List, Callable, Optional
from datetime import datetime

from langchain.tools import tool
from langchain_openai import ChatOpenAI

from TOSKill.AI.agent_config import agent_config

logger = logging.getLogger(__name__)


class DynamicToolRegistry:
    """动态工具注册管理器"""
    
    def __init__(self):
        self._dynamic_tools: Dict[str, Any] = {}
        self._tool_metadata: Dict[str, Dict[str, Any]] = {}
        self._llm = ChatOpenAI(
            model=agent_config.MODEL_ID,
            temperature=agent_config.TEMPERATURE,
            api_key=agent_config.OPENAI_API_KEY,
            base_url=agent_config.OPENAI_BASE_URL
        )
        logger.info("DynamicToolRegistry 初始化完成")
    
    def register_tool(self, name: str, func: Callable, description: str) -> bool:
        """注册动态工具
        
        Args:
            name: 工具名称，需唯一
            func: 工具执行函数
            description: 工具描述
            
        Returns:
            注册是否成功
        """
        if not name or not callable(func):
            logger.error(f"注册工具失败: 无效的名称或函数")
            return False
        
        if name in self._dynamic_tools:
            logger.warning(f"工具 {name} 已存在，将覆盖")
        
        try:
            tool_wrapper = _create_tool_wrapper(name, func, description)
            
            self._dynamic_tools[name] = tool_wrapper
            self._tool_metadata[name] = {
                "name": name,
                "description": description,
                "created_at": datetime.now().isoformat(),
                "type": "dynamic"
            }
            
            logger.info(f"成功注册动态工具: {name}")
            return True
            
        except Exception as e:
            logger.error(f"注册工具 {name} 失败: {str(e)}")
            return False
    
    def unregister_tool(self, name: str) -> bool:
        """注销动态工具
        
        Args:
            name: 要注销的工具名称
            
        Returns:
            注销是否成功
        """
        if name not in self._dynamic_tools:
            logger.warning(f"工具 {name} 不存在，无法注销")
            return False
        
        try:
            del self._dynamic_tools[name]
            del self._tool_metadata[name]
            logger.info(f"成功注销动态工具: {name}")
            return True
            
        except Exception as e:
            logger.error(f"注销工具 {name} 失败: {str(e)}")
            return False
    
    def get_all_tools(self) -> List[Any]:
        """获取所有工具（包括静态和动态）
        
        Returns:
            包含静态工具和动态工具的完整列表
        """
        from TOSKill.tools import ALL_TOOLS
        
        all_tools = list(ALL_TOOLS) + list(self._dynamic_tools.values())
        logger.debug(f"获取所有工具: {len(ALL_TOOLS)} 静态 + {len(self._dynamic_tools)} 动态 = {len(all_tools)} 总计")
        return all_tools
    
    def get_tool_names(self) -> List[str]:
        """获取所有工具名称
        
        Returns:
            所有工具名称列表
        """
        from TOSKill.tools import get_all_tool_names
        
        static_names = get_all_tool_names()
        dynamic_names = list(self._dynamic_tools.keys())
        return static_names + dynamic_names
    
    def get_dynamic_tools(self) -> List[Any]:
        """获取所有动态工具
        
        Returns:
            动态工具列表
        """
        return list(self._dynamic_tools.values())
    
    def get_dynamic_tool_names(self) -> List[str]:
        """获取所有动态工具名称
        
        Returns:
            动态工具名称列表
        """
        return list(self._dynamic_tools.keys())
    
    def get_tool_by_name(self, name: str) -> Optional[Any]:
        """根据名称获取工具
        
        Args:
            name: 工具名称
            
        Returns:
            工具对象，未找到返回None
        """
        if name in self._dynamic_tools:
            return self._dynamic_tools[name]
        
        from TOSKill.tools import get_tool_by_name
        return get_tool_by_name(name)
    
    def get_tool_metadata(self, name: str) -> Optional[Dict[str, Any]]:
        """获取工具元数据
        
        Args:
            name: 工具名称
            
        Returns:
            工具元数据字典，未找到返回None
        """
        return self._tool_metadata.get(name)
    
    def tool_exists(self, name: str) -> bool:
        """检查工具是否存在
        
        Args:
            name: 工具名称
            
        Returns:
            工具是否存在
        """
        if name in self._dynamic_tools:
            return True
        
        from TOSKill.tools import get_tool_by_name
        return get_tool_by_name(name) is not None
    
    def clear_all_dynamic_tools(self) -> int:
        """清除所有动态工具
        
        Returns:
            清除的工具数量
        """
        count = len(self._dynamic_tools)
        self._dynamic_tools.clear()
        self._tool_metadata.clear()
        logger.info(f"已清除 {count} 个动态工具")
        return count
    
    def get_tools_count(self) -> Dict[str, int]:
        """获取工具数量统计
        
        Returns:
            包含静态和动态工具数量的字典
        """
        from TOSKill.tools import TOOL_COUNT
        
        return {
            "static": TOOL_COUNT.get("total", 0),
            "dynamic": len(self._dynamic_tools),
            "total": TOOL_COUNT.get("total", 0) + len(self._dynamic_tools)
        }


dynamic_registry = DynamicToolRegistry()


def create_tool_from_script(
    script_code: str,
    name: Optional[str] = None,
    description: Optional[str] = None,
    auto_register: bool = True
) -> Dict[str, Any]:
    """从脚本代码创建工具
    
    Args:
        script_code: Python脚本代码
        name: 工具名称（可选，自动生成）
        description: 工具描述（可选，自动分析）
        auto_register: 是否自动注册到动态工具注册表
        
    Returns:
        包含创建结果的字典:
        - success: 是否成功
        - tool_name: 工具名称
        - tool: 创建的工具对象（成功时）
        - description: 工具描述
        - error: 错误信息（失败时）
    """
    result = {
        "success": False,
        "tool_name": None,
        "tool": None,
        "description": None,
        "error": None
    }
    
    if not script_code or not isinstance(script_code, str):
        result["error"] = "脚本代码不能为空"
        return result
    
    try:
        code_hash = hashlib.md5(script_code.encode()).hexdigest()[:8]
        
        if not name:
            name = f"custom_tool_{code_hash}"
        
        name = re.sub(r'[^a-zA-Z0-9_]', '_', name.lower())
        if not name[0].isalpha() and name[0] != '_':
            name = f"tool_{name}"
        
        local_vars: Dict[str, Any] = {}
        exec_globals = {
            "__builtins__": __builtins__,
            "asyncio": asyncio,
        }
        
        exec(script_code, exec_globals, local_vars)
        
        run_func = None
        for key, value in local_vars.items():
            if key == "run" and callable(value):
                run_func = value
                break
            if callable(value) and asyncio.iscoroutinefunction(value):
                run_func = value
                break
        
        if not run_func:
            result["error"] = "脚本中未找到有效的 run 函数或异步函数"
            return result
        
        if not description:
            description = f"动态创建的自定义工具: {name}"
        
        tool_wrapper = _create_tool_wrapper(name, run_func, description)
        
        result["success"] = True
        result["tool_name"] = name
        result["tool"] = tool_wrapper
        result["description"] = description
        
        if auto_register:
            dynamic_registry.register_tool(name, run_func, description)
        
        logger.info(f"成功从脚本创建工具: {name}")
        
    except SyntaxError as e:
        result["error"] = f"脚本语法错误: {str(e)}"
        logger.error(f"创建工具失败 - 语法错误: {str(e)}")
    except Exception as e:
        result["error"] = f"创建工具失败: {str(e)}"
        logger.error(f"创建工具失败: {str(e)}")
    
    return result


def _create_tool_wrapper(name: str, func: Callable, description: str) -> Any:
    """创建工具包装器
    
    Args:
        name: 工具名称
        func: 执行函数
        description: 工具描述
        
    Returns:
        包装后的工具对象
    """
    from langchain_core.tools import StructuredTool
    from pydantic import BaseModel, Field
    
    class ToolInput(BaseModel):
        target: str = Field(description="目标URL或IP地址")
    
    def tool_func(target: str) -> Dict[str, Any]:
        """动态工具包装器"""
        try:
            if asyncio.iscoroutinefunction(func):
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor() as executor:
                        future = executor.submit(asyncio.run, func(target))
                        result = future.result()
                else:
                    result = loop.run_until_complete(func(target))
            else:
                result = func(target)
            
            if isinstance(result, dict):
                return result
            return {
                "success": True,
                "data": result,
                "error": None,
                "metadata": {"tool": name, "target": target}
            }
        except Exception as e:
            return {
                "success": False,
                "data": None,
                "error": str(e),
                "metadata": {"tool": name, "target": target}
            }
    
    tool_wrapper = StructuredTool(
        name=name,
        description=description,
        func=tool_func,
        args_schema=ToolInput
    )
    
    return tool_wrapper


async def analyze_script_with_llm(script_code: str) -> Dict[str, Any]:
    """使用LLM分析脚本功能
    
    Args:
        script_code: Python脚本代码
        
    Returns:
        包含分析结果的字典:
        - success: 是否成功
        - name: 建议的工具名称
        - description: 工具功能描述
        - parameters: 参数说明
        - returns: 返回值说明
        - security_notes: 安全注意事项
        - error: 错误信息（失败时）
    """
    result = {
        "success": False,
        "name": None,
        "description": None,
        "parameters": None,
        "returns": None,
        "security_notes": None,
        "error": None
    }
    
    if not script_code or not isinstance(script_code, str):
        result["error"] = "脚本代码不能为空"
        return result
    
    try:
        llm = ChatOpenAI(
            model=agent_config.MODEL_ID,
            temperature=0.3,
            api_key=agent_config.OPENAI_API_KEY,
            base_url=agent_config.OPENAI_BASE_URL
        )
        
        prompt = f"""请分析以下Python脚本代码，并以JSON格式返回分析结果。

脚本代码:
```python
{script_code[:3000]}
```

请返回以下JSON格式（不要包含其他内容）:
{{
    "name": "建议的工具名称（英文，小写，下划线分隔）",
    "description": "工具功能描述（简洁明了，50字以内）",
    "parameters": "参数说明（如: target - 目标URL或IP地址）",
    "returns": "返回值说明",
    "security_notes": "安全注意事项（如有）"
}}
"""
        
        response = await llm.ainvoke(prompt)
        response_text = response.content.strip()
        
        if response_text.startswith("```"):
            lines = response_text.split("\n")
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            response_text = "\n".join(lines)
        
        import json
        analysis = json.loads(response_text)
        
        result["success"] = True
        result["name"] = analysis.get("name", "custom_tool")
        result["description"] = analysis.get("description", "自定义工具")
        result["parameters"] = analysis.get("parameters", "")
        result["returns"] = analysis.get("returns", "")
        result["security_notes"] = analysis.get("security_notes", "")
        
        logger.info(f"LLM分析脚本成功: {result['name']}")
        
    except json.JSONDecodeError as e:
        result["error"] = f"LLM响应解析失败: {str(e)}"
        logger.error(f"分析脚本失败 - JSON解析错误: {str(e)}")
    except Exception as e:
        result["error"] = f"LLM分析失败: {str(e)}"
        logger.error(f"分析脚本失败: {str(e)}")
    
    return result


def register_script_as_tool(
    script_code: str,
    name: Optional[str] = None,
    description: Optional[str] = None
) -> Dict[str, Any]:
    """将脚本注册为工具（同步版本）
    
    这是一个便捷函数，结合了分析脚本和创建工具的功能。
    
    Args:
        script_code: Python脚本代码
        name: 工具名称（可选）
        description: 工具描述（可选）
        
    Returns:
        注册结果字典
    """
    if not description:
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(
                        asyncio.run,
                        analyze_script_with_llm(script_code)
                    )
                    analysis = future.result()
            else:
                analysis = loop.run_until_complete(analyze_script_with_llm(script_code))
            
            if analysis["success"]:
                if not name and analysis.get("name"):
                    name = analysis["name"]
                if not description and analysis.get("description"):
                    description = analysis["description"]
        except Exception as e:
            logger.warning(f"LLM分析脚本失败，使用默认描述: {str(e)}")
    
    return create_tool_from_script(
        script_code=script_code,
        name=name,
        description=description,
        auto_register=True
    )


async def register_script_as_tool_async(
    script_code: str,
    name: Optional[str] = None,
    description: Optional[str] = None
) -> Dict[str, Any]:
    """将脚本注册为工具（异步版本）
    
    这是一个便捷函数，结合了分析脚本和创建工具的功能。
    
    Args:
        script_code: Python脚本代码
        name: 工具名称（可选）
        description: 工具描述（可选）
        
    Returns:
        注册结果字典
    """
    if not description:
        analysis = await analyze_script_with_llm(script_code)
        if analysis["success"]:
            if not name and analysis.get("name"):
                name = analysis["name"]
            if not description and analysis.get("description"):
                description = analysis["description"]
    
    return create_tool_from_script(
        script_code=script_code,
        name=name,
        description=description,
        auto_register=True
    )


__all__ = [
    "DynamicToolRegistry",
    "dynamic_registry",
    "create_tool_from_script",
    "analyze_script_with_llm",
    "register_script_as_tool",
    "register_script_as_tool_async",
]
