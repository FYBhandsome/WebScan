"""
Pocsuite3Agent 模块

提供基于 Pocsuite3 的 POC 执行代理功能。
支持自动选择和执行 POC,并返回详细的漏洞检测结果。

主要功能:
- POC 自动发现和加载
- 目标扫描和漏洞验证
- 结果解析和报告生成
- 与 AI Agent 集成
"""
import logging
import os
import tempfile
import sys
import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Tuple

from backend.ai_agents.poc_system.utils import parse_pocsuite_output


logger = logging.getLogger(__name__)


class POCExecutionError(Exception):
    """POC 执行错误基类"""
    pass


class POCTimeoutError(POCExecutionError):
    """POC 执行超时错误"""
    pass


class POCNotFoundError(POCExecutionError):
    """POC 未找到错误"""
    pass


class POCValidationError(POCExecutionError):
    """POC 验证错误"""
    pass


class ErrorCode(Enum):
    """错误代码枚举"""
    SUCCESS = 0
    TIMEOUT = 1
    NOT_FOUND = 2
    VALIDATION_ERROR = 3
    EXECUTION_ERROR = 4
    UNKNOWN_ERROR = 99


@dataclass
class POCResult:
    """
    POC 执行结果
    
    Attributes:
        poc_name: POC 名称
        target: 扫描目标
        vulnerable: 是否存在漏洞
        message: 结果消息
        output: 完整输出
        error: 错误信息
        execution_time: 执行时间(秒)
        error_code: 错误代码
    """
    poc_name: str
    target: str
    vulnerable: bool
    message: str
    output: str
    error: Optional[str] = None
    execution_time: float = 0.0
    error_code: ErrorCode = ErrorCode.SUCCESS


@dataclass
class ScanResult:
    """
    扫描结果
    
    Attributes:
        target: 扫描目标
        total_pocs: 执行的 POC 总数
        vulnerable_count: 发现的漏洞数量
        results: POC 结果列表
        execution_time: 总执行时间(秒)
    """
    target: str
    total_pocs: int
    vulnerable_count: int
    results: List[POCResult] = field(default_factory=list)
    execution_time: float = 0.0


class Pocsuite3Agent:
    """
    Pocsuite3 代理类
    
    负责管理和执行 Pocsuite3 POC 脚本。
    
    优化内容:
    - 简化 POC 加载逻辑,使用统一的目录收集方法
    - 提取公共执行逻辑到 _execute_poc_command 方法
    - 增强错误处理,添加错误分类和超时机制
    """
    
    DEFAULT_TIMEOUT = 60
    
    def __init__(self, pocsuite_path: Optional[str] = None):
        """
        初始化 Pocsuite3 代理
        
        Args:
            pocsuite_path: Pocsuite3 安装路径,如果为 None 则使用系统默认路径
        """
        self.pocsuite_path = pocsuite_path
        self.poc_registry: Dict[str, str] = {}
        self._pocsuite_available = self._check_pocsuite_installation()
        self._load_pocs()
        
    def _check_pocsuite_installation(self) -> bool:
        """
        检查 Pocsuite3 是否已安装
        
        Returns:
            bool: 是否已安装
        """
        try:
            import pocsuite3
            logger.info("Pocsuite3 已安装")
            return True
        except (ImportError, OSError) as e:
            logger.warning(f"Pocsuite3 未安装或安装损坏: {e}, 部分功能将不可用")
            return False
    
    def _get_poc_directories(self) -> List[str]:
        """
        获取 POC 目录列表
        
        Returns:
            List[str]: POC 目录路径列表
        """
        poc_dirs = []
        
        try:
            from pocsuite3.lib.core.data import paths as pocsuite_paths
            if hasattr(pocsuite_paths, 'POCSUITE_ROOT_PATH') and pocsuite_paths.POCSUITE_ROOT_PATH:
                poc_dirs.append(pocsuite_paths.POCSUITE_ROOT_PATH)
        except ImportError:
            pass
        
        try:
            import pocsuite3
            pocsuite_module_path = os.path.dirname(pocsuite3.__file__)
            built_in_poc_dir = os.path.join(pocsuite_module_path, 'pocs')
            if os.path.isdir(built_in_poc_dir):
                poc_dirs.append(built_in_poc_dir)
        except ImportError:
            pass
        
        user_poc_dir = os.path.join(os.getcwd(), 'pocs')
        if os.path.isdir(user_poc_dir):
            poc_dirs.append(user_poc_dir)
            
        return poc_dirs
    
    def _load_pocs(self):
        """
        加载可用的 POC 脚本
        
        从 Pocsuite3 的 POC 目录和用户自定义目录加载所有可用的 POC 脚本。
        优化: 使用 _get_poc_directories 统一收集目录,简化加载逻辑
        """
        if not self._pocsuite_available:
            logger.warning("Pocsuite3 未安装,POC 自动加载功能不可用")
            return
            
        loaded_count = 0
        
        try:
            for poc_dir in self._get_poc_directories():
                if not os.path.isdir(poc_dir):
                    continue
                    
                for root, dirs, files in os.walk(poc_dir):
                    dirs[:] = [d for d in dirs if not d.startswith(('_', '.'))]
                    
                    for file in files:
                        if file.endswith('.py') and not file.startswith('_'):
                            poc_path = os.path.join(root, file)
                            poc_name = file[:-3]
                            
                            if poc_name not in self.poc_registry:
                                self.poc_registry[poc_name] = poc_path
                                loaded_count += 1
            
            logger.info(f"加载了 {loaded_count} 个 POC 脚本")
            
        except Exception as e:
            logger.error(f"加载 POC 脚本失败: {e}")

    def _resolve_poc_path(self, poc_name: str) -> Tuple[str, Optional[ErrorCode]]:
        """
        解析 POC 路径
        
        Args:
            poc_name: POC 名称或路径
            
        Returns:
            Tuple[str, Optional[ErrorCode]]: (POC路径, 错误代码)
        """
        poc_path = self.poc_registry.get(poc_name, poc_name)
        
        if os.path.isabs(poc_path) and os.path.exists(poc_path):
            return poc_path, None
            
        if os.path.exists(poc_path):
            return poc_path, None
            
        for registered_name, registered_path in self.poc_registry.items():
            if registered_name == poc_name or os.path.basename(registered_path) == f"{poc_name}.py":
                return registered_path, None
        
        if not os.path.exists(poc_path):
            return poc_path, ErrorCode.NOT_FOUND
            
        return poc_path, None

    async def _execute_poc_command(
        self,
        poc_path: str,
        target: str,
        verify: bool = True,
        timeout: Optional[float] = None
    ) -> Tuple[str, str, float, Optional[ErrorCode]]:
        """
        执行 POC 命令的公共方法
        
        优化: 提取公共执行逻辑,减少代码重复
        
        Args:
            poc_path: POC 文件路径
            target: 目标 URL 或 IP
            verify: 是否仅验证(不攻击)
            timeout: 超时时间(秒)
            
        Returns:
            Tuple[str, str, float, Optional[ErrorCode]]: (标准输出, 错误输出, 执行时间, 错误代码)
        """
        start_time = time.time()
        
        cmd = [
            sys.executable,
            "-m",
            "pocsuite3.cli",
            "-r", poc_path,
            "-u", target
        ]
        
        if verify:
            cmd.append("--verify")
        else:
            cmd.append("--attack")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            actual_timeout = timeout or self.DEFAULT_TIMEOUT
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=actual_timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                execution_time = time.time() - start_time
                return "", f"执行超时 ({actual_timeout}秒)", execution_time, ErrorCode.TIMEOUT
            
            output = stdout.decode('utf-8', errors='ignore')
            error = stderr.decode('utf-8', errors='ignore')
            execution_time = time.time() - start_time
            
            return output, error, execution_time, None
            
        except Exception as e:
            execution_time = time.time() - start_time
            return "", str(e), execution_time, ErrorCode.EXECUTION_ERROR

    async def execute_poc(
        self,
        poc_name: str,
        target: str,
        verify: bool = True,
        timeout: Optional[float] = None
    ) -> POCResult:
        """
        执行单个 POC
        
        Args:
            poc_name: POC 名称或 POC 文件路径
            target: 目标 URL 或 IP
            verify: 是否仅验证(不攻击)
            timeout: 超时时间(秒)
            
        Returns:
            POCResult: 执行结果
        """
        start_time = time.time()
        
        try:
            logger.info(f"执行 POC: {poc_name}, 目标: {target}")
            
            poc_path, error_code = self._resolve_poc_path(poc_name)
            
            if error_code == ErrorCode.NOT_FOUND:
                logger.warning(f"POC 文件不存在: {poc_name}")
            
            output, error, execution_time, cmd_error_code = await self._execute_poc_command(
                poc_path, target, verify, timeout
            )
            
            if cmd_error_code == ErrorCode.TIMEOUT:
                return POCResult(
                    poc_name=poc_name,
                    target=target,
                    vulnerable=False,
                    message=f"执行超时",
                    output=output,
                    error=error,
                    execution_time=execution_time,
                    error_code=ErrorCode.TIMEOUT
                )
            
            vulnerable = parse_pocsuite_output(output)
            message = "Vulnerable" if vulnerable else "Not Vulnerable"
            
            result = POCResult(
                poc_name=poc_name,
                target=target,
                vulnerable=vulnerable,
                message=message,
                output=output,
                error=error if error else None,
                execution_time=execution_time,
                error_code=ErrorCode.SUCCESS if not error else ErrorCode.EXECUTION_ERROR
            )
            
            logger.info(f"POC 执行完成: {poc_name}, 结果: {message}, 耗时: {execution_time:.2f}s")
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"POC 执行失败: {poc_name}, 错误: {e}")
            
            return POCResult(
                poc_name=poc_name,
                target=target,
                vulnerable=False,
                message=f"Execution failed: {str(e)}",
                output="",
                error=str(e),
                execution_time=execution_time,
                error_code=ErrorCode.UNKNOWN_ERROR
            )
    
    async def scan_target(
        self,
        target: str,
        poc_names: Optional[List[str]] = None,
        max_concurrent: int = 5,
        timeout: Optional[float] = None
    ) -> ScanResult:
        """
        扫描目标,执行多个 POC
        
        Args:
            target: 目标 URL 或 IP
            poc_names: 要执行的 POC 名称列表,如果为 None 则执行所有 POC
            max_concurrent: 最大并发数
            timeout: 单个 POC 超时时间(秒)
            
        Returns:
            ScanResult: 扫描结果
        """
        start_time = time.time()
        
        if poc_names is None:
            poc_names = list(self.poc_registry.keys())
        
        if not poc_names:
            logger.warning("没有可执行的 POC")
            return ScanResult(
                target=target,
                total_pocs=0,
                vulnerable_count=0,
                execution_time=0.0
            )
        
        logger.info(f"开始扫描目标: {target}, POC 数量: {len(poc_names)}")
        
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def execute_with_semaphore(poc_name: str) -> POCResult:
            async with semaphore:
                return await self.execute_poc(poc_name, target, timeout=timeout)
        
        results = await asyncio.gather(
            *[execute_with_semaphore(poc_name) for poc_name in poc_names],
            return_exceptions=True
        )
        
        valid_results = []
        vulnerable_count = 0
        
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"POC 执行异常: {result}")
                continue
            
            if isinstance(result, POCResult):
                valid_results.append(result)
                if result.vulnerable:
                    vulnerable_count += 1
        
        execution_time = time.time() - start_time
        
        scan_result = ScanResult(
            target=target,
            total_pocs=len(valid_results),
            vulnerable_count=vulnerable_count,
            results=valid_results,
            execution_time=execution_time
        )
        
        logger.info(
            f"扫描完成: {target}, "
            f"总 POC: {len(valid_results)}, "
            f"发现漏洞: {vulnerable_count}, "
            f"耗时: {execution_time:.2f}s"
        )
        
        return scan_result
    
    async def execute_custom_poc(
        self,
        poc_code: str,
        target: str,
        verify: bool = True,
        timeout: Optional[float] = None
    ) -> POCResult:
        """
        执行自定义 POC 代码
        
        Args:
            poc_code: POC 代码字符串
            target: 目标 URL 或 IP
            verify: 是否仅验证(不攻击)
            timeout: 超时时间(秒)
            
        Returns:
            POCResult: 执行结果
        """
        start_time = time.time()
        tmp_path = None
        
        try:
            with tempfile.NamedTemporaryFile(
                mode='w',
                suffix='.py',
                delete=False,
                encoding='utf-8'
            ) as tmp:
                tmp.write(poc_code)
                tmp_path = tmp.name
            
            logger.info(f"执行自定义 POC, 目标: {target}")
            
            output, error, execution_time, error_code = await self._execute_poc_command(
                tmp_path, target, verify, timeout
            )
            
            if error_code == ErrorCode.TIMEOUT:
                return POCResult(
                    poc_name="custom_poc",
                    target=target,
                    vulnerable=False,
                    message="执行超时",
                    output=output,
                    error=error,
                    execution_time=execution_time,
                    error_code=ErrorCode.TIMEOUT
                )
            
            vulnerable = parse_pocsuite_output(output)
            message = "Vulnerable" if vulnerable else "Not Vulnerable"
            
            result = POCResult(
                poc_name="custom_poc",
                target=target,
                vulnerable=vulnerable,
                message=message,
                output=output,
                error=error if error else None,
                execution_time=execution_time,
                error_code=ErrorCode.SUCCESS if not error else ErrorCode.EXECUTION_ERROR
            )
            
            logger.info(f"自定义 POC 执行完成, 结果: {message}, 耗时: {execution_time:.2f}s")
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"自定义 POC 执行失败: {e}")
            
            return POCResult(
                poc_name="custom_poc",
                target=target,
                vulnerable=False,
                message=f"Execution failed: {str(e)}",
                output="",
                error=str(e),
                execution_time=execution_time,
                error_code=ErrorCode.UNKNOWN_ERROR
            )
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError as e:
                    logger.warning(f"删除临时文件失败: {tmp_path}, 错误: {e}")
    
    def get_available_pocs(self) -> List[str]:
        """
        获取所有可用的 POC 列表
        
        Returns:
            List[str]: POC 名称列表
        """
        return list(self.poc_registry.keys())
    
    def search_pocs(self, keyword: str) -> List[str]:
        """
        搜索 POC
        
        Args:
            keyword: 搜索关键词
            
        Returns:
            List[str]: 匹配的 POC 名称列表
        """
        keyword_lower = keyword.lower()
        return [
            poc_name for poc_name in self.poc_registry.keys()
            if keyword_lower in poc_name.lower()
        ]
    
    def reload_pocs(self) -> int:
        """
        重新加载 POC 脚本
        
        Returns:
            int: 加载的 POC 数量
        """
        self.poc_registry.clear()
        self._load_pocs()
        return len(self.poc_registry)
    
    def is_pocsuite_available(self) -> bool:
        """
        检查 Pocsuite3 是否可用
        
        Returns:
            bool: 是否可用
        """
        return self._pocsuite_available


_pocsuite3_agent_instance: Optional[Pocsuite3Agent] = None


def get_pocsuite3_agent() -> Pocsuite3Agent:
    """
    获取 Pocsuite3 代理实例(单例模式)
    
    Returns:
        Pocsuite3Agent: 代理实例
    """
    global _pocsuite3_agent_instance
    
    if _pocsuite3_agent_instance is None:
        _pocsuite3_agent_instance = Pocsuite3Agent()
    
    return _pocsuite3_agent_instance
