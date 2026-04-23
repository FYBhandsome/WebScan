"""
工具包装器

提供统一的工具包装和异步执行接口。
"""
import asyncio
import logging
from typing import Callable, Any, Optional, Dict

logger = logging.getLogger(__name__)


class AsyncToolWrapper:
    """
    异步工具包装器
    
    将同步工具函数包装为异步执行，提供超时控制和错误处理。
    """
    
    def __init__(self, func: Callable, timeout: int = 60):
        """
        初始化包装器
        
        Args:
            func: 工具函数（同步或异步）
            timeout: 超时时间（秒）
        """
        self.func = func
        self.timeout = timeout
        self._is_async = asyncio.iscoroutinefunction(func)
    
    async def execute(self, target: str, **kwargs) -> Any:
        """
        异步执行工具
        
        Args:
            target: 目标地址
            **kwargs: 其他参数
            
        Returns:
            执行结果
        """
        try:
            if self._is_async:
                result = await asyncio.wait_for(
                    self.func(target, **kwargs),
                    timeout=self.timeout
                )
            else:
                result = await asyncio.wait_for(
                    asyncio.to_thread(self.func, target, **kwargs),
                    timeout=self.timeout
                )
            return result
        except asyncio.TimeoutError:
            logger.error(f"工具执行超时: {self.func.__name__}")
            raise
        except Exception as e:
            logger.error(f"工具执行失败: {self.func.__name__} - {str(e)}")
            raise


def wrap_async(func: Callable, timeout: int = 60) -> AsyncToolWrapper:
    """
    将函数包装为异步工具
    
    Args:
        func: 工具函数
        timeout: 超时时间
        
    Returns:
        AsyncToolWrapper: 包装后的工具
    """
    return AsyncToolWrapper(func, timeout=timeout)
