"""
工具注册表

统一管理所有扫描工具的注册、查询和持久化。
"""
from typing import Dict, List, Optional, Callable, Any
import os
import json
import importlib
import inspect
import ast
import re
import logging
from .wrappers import AsyncToolWrapper
from .history_manager import HistoryManager

logger = logging.getLogger(__name__)


class Registry:
    """工具注册表，单例模式"""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self.tools: Dict[str, AsyncToolWrapper] = {}
        self.tool_metadata: Dict[str, Dict[str, Any]] = {}
        
        # 自定义脚本目录配置
        self.BASE_DIR = "custom_scripts"
        self.TOOL_CONFIG = "tool_registry.json"
        os.makedirs(self.BASE_DIR, exist_ok=True)
        os.makedirs(f"{self.BASE_DIR}/custom", exist_ok=True)
        os.makedirs(f"{self.BASE_DIR}/generated", exist_ok=True)
        
        # 加载已保存的自定义工具
        self._load_saved_tools()
        
        logger.info("🔧 工具注册表初始化完成")
    
    def _load_saved_tools(self):
        """加载持久化的自定义工具配置"""
        if os.path.exists(self.TOOL_CONFIG):
            try:
                with open(self.TOOL_CONFIG, 'r', encoding='utf-8') as f:
                    saved_tools = json.load(f)
                logger.info(f"📦 加载了 {len(saved_tools)} 个已保存的自定义工具")
            except Exception as e:
                logger.warning(f"加载自定义工具配置失败: {e}")
    
    def register(self, name: str, func: Callable, description: str, 
                 category: str = "custom", timeout: int = 60, 
                 priority: int = 5, enabled: bool = True,
                 tags: Optional[List[str]] = None) -> None:
        """
        注册一个工具
        
        Args:
            name: 工具名称
            func: 工具函数
            description: 工具描述
            category: 工具类别
            timeout: 超时时间
            priority: 优先级
            enabled: 是否启用
            tags: 标签
        """
        if name in self.tools:
            logger.warning(f"⚠️ 工具 {name} 已存在，将被覆盖")
        
        # 用异步包装器包装工具
        wrapper = AsyncToolWrapper(func, timeout=timeout)
        self.tools[name] = wrapper
        
        # 保存元数据
        self.tool_metadata[name] = {
            "name": name,
            "description": description,
            "category": category,
            "timeout": timeout,
            "priority": priority,
            "enabled": enabled,
            "tags": tags or []
        }
        
        # 自定义工具持久化
        if category == "custom":
            self._save_custom_tool(name, description)
        
        logger.info(f"✅ 工具注册成功: {name}")
    
    def _save_custom_tool(self, name: str, description: str):
        """保存自定义工具到持久化文件"""
        try:
            saved_tools = {}
            if os.path.exists(self.TOOL_CONFIG):
                with open(self.TOOL_CONFIG, 'r', encoding='utf-8') as f:
                    saved_tools = json.load(f)
            
            saved_tools[name] = description
            
            with open(self.TOOL_CONFIG, 'w', encoding='utf-8') as f:
                json.dump(saved_tools, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning(f"保存自定义工具配置失败: {e}")
    
    def get_tool(self, name: str) -> Optional[AsyncToolWrapper]:
        """获取工具实例"""
        return self.tools.get(name)
    
    def list_tools(self) -> List[Dict[str, Any]]:
        """列出所有工具的元数据"""
        return list(self.tool_metadata.values())
    
    def has_tool(self, name: str) -> bool:
        """检查工具是否存在"""
        return name in self.tools


def validate_script_code(code: str) -> tuple:
    """
    验证脚本代码是否有效
    检查是否包含正确的 run(target) 函数和语法
    """
    if not code or not code.strip():
        return False, "脚本代码为空"
    
    if "def run(" not in code:
        return False, "脚本缺少 run(target) 函数定义"
    
    run_func_pattern = r'def\s+run\s*\(\s*\w+\s*\)'
    if not re.search(run_func_pattern, code):
        return False, "run 函数签名不正确，应为 run(target)"
    
    try:
        ast.parse(code)
    except SyntaxError as e:
        return False, f"脚本语法错误: {e.msg} (行 {e.lineno})"
    
    return True, "脚本验证通过"


def load_and_test_script(script_path: str, target: str):
    """加载并测试自定义脚本"""
    try:
        if not os.path.exists(script_path):
            return None, f"脚本文件不存在: {script_path}"
        
        with open(script_path, 'r', encoding='utf-8') as f:
            code = f.read()
        
        is_valid, error_msg = validate_script_code(code)
        if not is_valid:
            return None, f"脚本验证失败: {error_msg}"
        
        spec = importlib.util.spec_from_file_location("task_module", script_path)
        if spec is None or spec.loader is None:
            return None, "无法加载脚本模块"
        
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        if not hasattr(module, "run"):
            return None, "脚本缺少 run 函数"
        
        run_func = getattr(module, "run")
        if not callable(run_func):
            return None, "run 不是可调用函数"
        
        sig = inspect.signature(run_func)
        params = list(sig.parameters.keys())
        if len(params) < 1:
            return None, "run 函数缺少参数，应为 run(target)"
        
        result = module.run(target)
        
        if result is None:
            return None, "run 函数返回值为 None，应返回字典类型结果"
        
        if not isinstance(result, dict):
            return None, f"run 函数返回类型错误: 期望 dict，实际 {type(result).__name__}"
        
        return result, "脚本执行成功"
        
    except SyntaxError as e:
        return None, f"语法错误: {e.msg} (文件 {e.filename}, 行 {e.lineno})"
    except ImportError as e:
        return None, f"导入错误: {str(e)}"
    except Exception as e:
        return None, f"脚本执行异常: {type(e).__name__}: {str(e)}"


# 全局单例实例
registry = Registry()
history_manager = HistoryManager()