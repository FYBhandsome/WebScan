"""
工具异步封装模块

提供统一的工具包装机制，支持：
- 同步/异步函数统一封装
- 超时控制
- 错误处理
- 进度回调
- 执行统计

所有工具执行结果统一返回 PluginResult 类型。
"""
import asyncio
import functools
import logging
import time
from typing import Callable, Any, Optional, Dict, TypeVar, ParamSpec

from .result_types import PluginResult, ToolStatus, ProgressInfo

logger = logging.getLogger(__name__)

P = ParamSpec('P')
T = TypeVar('T')


class ProgressReporter:
    """
    进度报告器
    
    用于在工具执行过程中报告进度，支持回调函数和日志记录。
    
    Attributes:
        tool_name: 工具名称
        target: 目标地址
        callback: 进度回调函数
        start_time: 开始时间
    """
    
    def __init__(
        self,
        tool_name: str,
        target: str,
        callback: Optional[Callable[[ProgressInfo], None]] = None
    ):
        """
        初始化进度报告器
        
        Args:
            tool_name: 工具名称
            target: 目标地址
            callback: 进度回调函数，接收 ProgressInfo 参数
        """
        self.tool_name = tool_name
        self.target = target
        self.callback = callback
        self.start_time = time.time()
    
    def report(
        self,
        stage: str,
        progress: int,
        message: str = "",
        extra_data: Optional[Dict] = None
    ) -> None:
        """
        报告执行进度
        
        Args:
            stage: 当前阶段名称
            progress: 进度百分比 (0-100)
            message: 进度消息
            extra_data: 额外数据
        """
        elapsed = time.time() - self.start_time
        progress_info = ProgressInfo(
            tool_name=self.tool_name,
            target=self.target,
            stage=stage,
            progress=min(100, max(0, progress)),
            message=message,
            elapsed_time=elapsed,
            extra_data=extra_data or {}
        )
        
        logger.info(
            f"[{self.tool_name}] {self.target} - {stage}: "
            f"{progress_info.progress}% - {message}"
        )
        
        if self.callback:
            try:
                self.callback(progress_info)
            except Exception as e:
                logger.warning(f"进度回调执行失败: {str(e)}")


class AsyncToolWrapper:
    """
    异步工具包装器
    
    将同步/异步函数封装为统一的异步调用接口，提供：
    - 超时控制
    - 错误处理
    - 执行统计
    - 统一返回 PluginResult
    
    Attributes:
        func: 原始函数
        timeout: 超时时间(秒)
        tool_name: 工具名称
        is_async: 是否为异步函数
    """
    
    def __init__(
        self,
        func: Callable,
        timeout: float = 120.0,
        tool_name: str = ""
    ):
        """
        初始化工具包装器
        
        Args:
            func: 要封装的函数（同步或异步）
            timeout: 超时时间(秒)
            tool_name: 工具名称，默认使用函数名
        """
        self.func = func
        self.timeout = timeout
        self.tool_name = tool_name or getattr(func, '__name__', 'unknown')
        self.is_async = asyncio.iscoroutinefunction(func)
        
        logger.debug(
            f"创建工具包装器: {self.tool_name}, "
            f"异步: {self.is_async}, 超时: {timeout}s"
        )
    
    async def execute(
        self,
        target: str,
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable[[ProgressInfo], None]] = None,
        **kwargs
    ) -> PluginResult:
        """
        执行工具
        
        Args:
            target: 扫描目标
            timeout: 超时时间(秒)，None 使用默认值
            progress_callback: 进度回调函数
            **kwargs: 工具参数
            
        Returns:
            PluginResult: 统一格式的执行结果
        """
        actual_timeout = timeout if timeout is not None else self.timeout
        start_time = time.time()
        
        logger.info(
            f"[{self.tool_name}] 🚀 开始执行 | 目标: {target} | "
            f"超时: {actual_timeout}s"
        )
        
        try:
            if self.is_async:
                result = await asyncio.wait_for(
                    self.func(target, **kwargs),
                    timeout=actual_timeout
                )
            else:
                result = await asyncio.wait_for(
                    asyncio.to_thread(self.func, target, **kwargs),
                    timeout=actual_timeout
                )
            
            execution_time = time.time() - start_time
            
            if isinstance(result, PluginResult):
                result.execution_time = execution_time
                result.tool_name = self.tool_name
                result.target = target
                logger.info(
                    f"[{self.tool_name}] ✅ 执行成功 | "
                    f"耗时: {execution_time:.3f}s | 状态: {result.status}"
                )
                return result
            
            logger.info(
                f"[{self.tool_name}] ✅ 执行成功 | "
                f"耗时: {execution_time:.3f}s"
            )
            return PluginResult.success(
                data=result,
                execution_time=execution_time,
                tool_name=self.tool_name,
                target=target
            )
            
        except asyncio.TimeoutError:
            execution_time = time.time() - start_time
            logger.error(
                f"[{self.tool_name}] ⏱️ 执行超时 | "
                f"超时设置: {actual_timeout}s | 实际: {execution_time:.3f}s"
            )
            return PluginResult.timeout(
                timeout_seconds=actual_timeout,
                execution_time=execution_time,
                tool_name=self.tool_name,
                target=target
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"{type(e).__name__}: {str(e)}"
            logger.error(
                f"[{self.tool_name}] ❌ 执行异常 | "
                f"耗时: {execution_time:.3f}s | 错误: {error_msg}",
                exc_info=True
            )
            return PluginResult.failed(
                error=error_msg,
                execution_time=execution_time,
                tool_name=self.tool_name,
                target=target
            )
    
    def get_timeout(self) -> float:
        """获取超时时间"""
        return self.timeout
    
    def get_func_name(self) -> str:
        """获取函数名称"""
        return self.tool_name


def with_timeout_and_error_handling(
    default_timeout: float = 60.0,
    tool_name: str = ""
):
    """
    超时控制和异常捕获装饰器
    
    为工具函数添加统一的超时控制和异常处理，返回 PluginResult。
    
    Args:
        default_timeout: 默认超时时间(秒)
        tool_name: 工具名称，默认使用函数名
    
    Returns:
        装饰器函数
    
    Examples:
        >>> @with_timeout_and_error_handling(default_timeout=30, tool_name="portscan")
        ... async def scan_port(target: str, timeout: float = None):
        ...     return {"open_ports": [80, 443]}
        ...
        >>> result = await scan_port("example.com")
        >>> result.status
        'success'
    """
    def decorator(func: Callable[P, T]) -> Callable[P, PluginResult]:
        actual_tool_name = tool_name or func.__name__
        
        @functools.wraps(func)
        async def async_wrapper(
            *args,
            timeout: Optional[float] = None,
            progress_callback: Optional[Callable[[ProgressInfo], None]] = None,
            **kwargs
        ) -> PluginResult:
            actual_timeout = timeout if timeout is not None else default_timeout
            start_time = time.time()
            target = kwargs.get('target', args[0] if args else 'unknown')
            
            logger.info(
                f"[{actual_tool_name}] 🚀 开始执行 | 目标: {target} | "
                f"超时: {actual_timeout}s | 函数: {func.__name__}"
            )
            
            try:
                result = await asyncio.wait_for(
                    func(*args, timeout=actual_timeout, progress_callback=progress_callback, **kwargs),
                    timeout=actual_timeout
                )
                execution_time = time.time() - start_time
                
                if isinstance(result, PluginResult):
                    result.execution_time = execution_time
                    result.tool_name = actual_tool_name
                    result.target = target
                    logger.info(
                        f"[{actual_tool_name}] ✅ 执行成功 | "
                        f"耗时: {execution_time:.3f}s | 状态: {result.status}"
                    )
                    return result
                
                logger.info(
                    f"[{actual_tool_name}] ✅ 执行成功 | "
                    f"耗时: {execution_time:.3f}s"
                )
                return PluginResult.success(
                    data=result,
                    execution_time=execution_time,
                    tool_name=actual_tool_name,
                    target=target
                )
                
            except asyncio.TimeoutError:
                execution_time = time.time() - start_time
                logger.error(
                    f"[{actual_tool_name}] ⏱️ 执行超时 | "
                    f"超时: {actual_timeout}s | 实际: {execution_time:.3f}s"
                )
                return PluginResult.timeout(
                    timeout_seconds=actual_timeout,
                    execution_time=execution_time,
                    tool_name=actual_tool_name,
                    target=target
                )
                
            except Exception as e:
                execution_time = time.time() - start_time
                error_msg = f"{type(e).__name__}: {str(e)}"
                logger.error(
                    f"[{actual_tool_name}] ❌ 执行异常 | "
                    f"耗时: {execution_time:.3f}s | 错误: {error_msg}",
                    exc_info=True
                )
                return PluginResult.failed(
                    error=error_msg,
                    execution_time=execution_time,
                    tool_name=actual_tool_name,
                    target=target
                )
        
        @functools.wraps(func)
        def sync_wrapper(
            *args,
            timeout: Optional[float] = None,
            progress_callback: Optional[Callable[[ProgressInfo], None]] = None,
            **kwargs
        ) -> PluginResult:
            actual_timeout = timeout if timeout is not None else default_timeout
            start_time = time.time()
            target = kwargs.get('target', args[0] if args else 'unknown')
            
            logger.info(
                f"[{actual_tool_name}] 🚀 开始执行 | 目标: {target} | "
                f"超时: {actual_timeout}s | 函数: {func.__name__}"
            )
            
            try:
                if asyncio.iscoroutinefunction(func):
                    loop = asyncio.get_event_loop()
                    result = loop.run_until_complete(
                        asyncio.wait_for(
                            func(*args, timeout=actual_timeout, progress_callback=progress_callback, **kwargs),
                            timeout=actual_timeout
                        )
                    )
                else:
                    result = func(*args, timeout=actual_timeout, progress_callback=progress_callback, **kwargs)
                
                execution_time = time.time() - start_time
                
                if isinstance(result, PluginResult):
                    result.execution_time = execution_time
                    result.tool_name = actual_tool_name
                    result.target = target
                    logger.info(
                        f"[{actual_tool_name}] ✅ 执行成功 | "
                        f"耗时: {execution_time:.3f}s | 状态: {result.status}"
                    )
                    return result
                
                logger.info(
                    f"[{actual_tool_name}] ✅ 执行成功 | "
                    f"耗时: {execution_time:.3f}s"
                )
                return PluginResult.success(
                    data=result,
                    execution_time=execution_time,
                    tool_name=actual_tool_name,
                    target=target
                )
                
            except asyncio.TimeoutError:
                execution_time = time.time() - start_time
                logger.error(
                    f"[{actual_tool_name}] ⏱️ 执行超时 | "
                    f"超时: {actual_timeout}s | 实际: {execution_time:.3f}s"
                )
                return PluginResult.timeout(
                    timeout_seconds=actual_timeout,
                    execution_time=execution_time,
                    tool_name=actual_tool_name,
                    target=target
                )
                
            except Exception as e:
                execution_time = time.time() - start_time
                error_msg = f"{type(e).__name__}: {str(e)}"
                logger.error(
                    f"[{actual_tool_name}] ❌ 执行异常 | "
                    f"耗时: {execution_time:.3f}s | 错误: {error_msg}",
                    exc_info=True
                )
                return PluginResult.failed(
                    error=error_msg,
                    execution_time=execution_time,
                    tool_name=actual_tool_name,
                    target=target
                )
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper
    
    return decorator


def wrap_async(
    func: Callable,
    timeout: float = 120.0,
    tool_name: str = ""
) -> AsyncToolWrapper:
    """
    工具异步封装便捷函数
    
    快速创建工具包装器。
    
    Args:
        func: 要封装的函数
        timeout: 超时时间(秒)
        tool_name: 工具名称
        
    Returns:
        AsyncToolWrapper: 工具包装器实例
    
    Examples:
        >>> from plugins.baseinfo.baseinfo import getbaseinfo
        >>> wrapper = wrap_async(getbaseinfo, timeout=10, tool_name="baseinfo")
        >>> result = await wrapper.execute("https://example.com")
        >>> result.status
        'success'
    """
    return AsyncToolWrapper(func, timeout=timeout, tool_name=tool_name)


def create_progress_reporter(
    tool_name: str,
    target: str,
    callback: Optional[Callable[[ProgressInfo], None]] = None
) -> Optional[ProgressReporter]:
    """
    创建进度报告器
    
    Args:
        tool_name: 工具名称
        target: 目标地址
        callback: 用户提供的回调函数
    
    Returns:
        ProgressReporter 实例或 None
    """
    if callback is None:
        return None
    return ProgressReporter(tool_name, target, callback)
