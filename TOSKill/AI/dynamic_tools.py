# -*- coding:utf-8 -*-
"""
动态工具创建模块

提供从脚本代码创建工具的功能，支持使用LLM分析脚本功能。
与 tools.py 配合使用，专注于动态脚本工具的创建和注册。
"""

import logging
import re
import hashlib
import asyncio
import json
from typing import Dict, Any, Callable, Optional
from datetime import datetime

from langchain_core.tools import StructuredTool
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

from backend.config import settings

logger = logging.getLogger(__name__)


def _get_llm():
    """获取LLM实例"""
    return ChatOpenAI(
        model=settings.MODEL_ID,
        temperature=0.3,
        api_key=settings.OPENAI_API_KEY,
        base_url=settings.OPENAI_BASE_URL
    )


class ToolInput(BaseModel):
    """工具输入模型"""
    target: str = Field(description="目标URL或IP地址")


def _create_tool_wrapper(name: str, func: Callable, description: str) -> Any:
    """创建工具包装器
    
    Args:
        name: 工具名称
        func: 执行函数
        description: 工具描述
        
    Returns:
        包装后的工具对象
    """
    def tool_func(target: str) -> Dict[str, Any]:
        """动态工具包装器"""
        try:
            if asyncio.iscoroutinefunction(func):
                try:
                    loop = asyncio.get_running_loop()
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor() as executor:
                        future = executor.submit(asyncio.run, func(target))
                        result = future.result()
                except RuntimeError:
                    result = asyncio.run(func(target))
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
            from .tools import TOOL_MAP
            TOOL_MAP[name] = tool_wrapper
            logger.info(f"动态工具已注册: {name}")
        
        logger.info(f"成功从脚本创建工具: {name}")
        
    except SyntaxError as e:
        result["error"] = f"脚本语法错误: {str(e)}"
        logger.error(f"创建工具失败 - 语法错误: {str(e)}")
    except Exception as e:
        result["error"] = f"创建工具失败: {str(e)}"
        logger.error(f"创建工具失败: {str(e)}")
    
    return result


def analyze_script_with_llm(script_code: str) -> Dict[str, Any]:
    """使用LLM分析脚本功能（同步版本）
    
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
        llm = _get_llm()
        
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
        
        response = llm.invoke(prompt)
        response_text = response.content.strip()
        
        if response_text.startswith("```"):
            lines = response_text.split("\n")
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            response_text = "\n".join(lines)
        
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
    """将脚本注册为工具
    
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
            analysis = analyze_script_with_llm(script_code)
            
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


__all__ = [
    "create_tool_from_script",
    "analyze_script_with_llm",
    "register_script_as_tool",
]
