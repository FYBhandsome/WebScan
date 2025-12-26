# -*- coding:utf-8 -*-
import os
import logging
from pathlib import Path
from typing import Optional, bool
from logging.handlers import TimedRotatingFileHandler

# ======================== 配置项（集中管理，便于修改） ========================
# 日志格式（抽离为公共常量，避免重复定义）
LOG_FORMAT = '%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s'
# 日志文件编码
LOG_FILE_ENCODING = 'utf-8'
# 日志回滚配置
LOG_ROTATE_WHEN = 'MIDNIGHT'  # 午夜触发日志切割（严格按天，而非启动后24小时）
LOG_ROTATE_INTERVAL = 1       # 切割间隔（天）
LOG_ROTATE_BACKUP_COUNT = 60  # 保留日志文件数量
# 日志默认级别
DEFAULT_LOG_LEVEL = logging.DEBUG

# ======================== 路径配置（使用Path优化，自动处理跨平台/冗余路径） ========================
# 当前脚本所在目录
CURRENT_PATH = Path(__file__).absolute().parent
# 项目根目录（当前脚本的父目录）
ROOT_PATH = CURRENT_PATH.parent
# 日志文件存储目录
LOG_PATH = ROOT_PATH / "loginfo" / "log"

class LogHandler(logging.Logger):
    """自定义日志处理器（优化版）"""
    # 类级缓存，实现单例（避免重复创建handler导致日志重复输出）
    _instance_cache = {}

    def __new__(cls, name: str, level: int = DEFAULT_LOG_LEVEL, 
                stream: bool = False, file: bool = True):
        """单例创建，同名日志器仅初始化一次"""
        key = (name, level)
        if key not in cls._instance_cache:
            cls._instance_cache[key] = super().__new__(cls)
        return cls._instance_cache[key]

    def __init__(self, name: str, level: int = DEFAULT_LOG_LEVEL, 
                 stream: bool = False, file: bool = True):
        # 单例防重复初始化
        if hasattr(self, '_initialized') and self._initialized:
            return
        
        super().__init__(name, level=level)
        self.name = name
        self.level = level
        self._initialized = True  # 标记已初始化
        self.file_handler: Optional[TimedRotatingFileHandler] = None  # 类型注解

        # 确保日志目录存在
        self._ensure_log_dir_exists()

        # 按需创建处理器
        if stream:
            self._set_stream_handler()
        if file:
            self._set_file_handler()

    def _ensure_log_dir_exists(self) -> None:
        """确保日志目录存在，不存在则创建"""
        try:
            LOG_PATH.mkdir(parents=True, exist_ok=True)  # parents=True：创建多级目录；exist_ok=True：已存在不报错
        except PermissionError:
            raise PermissionError(f"无权限创建日志目录：{LOG_PATH}")
        except Exception as e:
            raise RuntimeError(f"创建日志目录失败：{LOG_PATH} | 原因：{e}")

    def _set_file_handler(self, level: Optional[int] = None) -> None:
        """
        创建文件日志处理器（单下划线表示私有方法，避免名称改写）
        :param level: 日志级别，默认使用实例级别
        """
        try:
            # 日志文件路径（Path转字符串）
            file_name = str(LOG_PATH / f"{self.name}.log")
            
            # 创建按天回滚的文件处理器（改用MIDNIGHT，严格按自然天切割）
            file_handler = TimedRotatingFileHandler(
                filename=file_name,
                when=LOG_ROTATE_WHEN,
                interval=LOG_ROTATE_INTERVAL,
                backupCount=LOG_ROTATE_BACKUP_COUNT,
                encoding=LOG_FILE_ENCODING
            )
            # 日志文件后缀（适配MIDNIGHT，格式为YYYYMMDD.log）
            file_handler.suffix = '%Y%m%d.log'
            
            # 设置级别和格式
            file_handler.setLevel(level or self.level)
            formatter = logging.Formatter(LOG_FORMAT)
            file_handler.setFormatter(formatter)

            self.file_handler = file_handler
            self.addHandler(file_handler)
        except Exception as e:
            raise RuntimeError(f"创建文件日志处理器失败 | 日志文件：{file_name} | 原因：{e}")

    def _set_stream_handler(self, level: Optional[int] = None) -> None:
        """
        创建控制台日志处理器（单下划线私有方法）
        :param level: 日志级别，默认使用实例级别
        """
        stream_handler = logging.StreamHandler()
        # 复用公共日志格式
        formatter = logging.Formatter(LOG_FORMAT)
        stream_handler.setFormatter(formatter)
        stream_handler.setLevel(level or self.level)
        self.addHandler(stream_handler)

    def reset_name(self, new_name: str) -> None:
        """
        重置日志名称（优化命名+完整资源释放）
        :param new_name: 新的日志名称
        """
        if not new_name or new_name == self.name:
            return  # 空值/同名不处理

        # 移除并关闭旧文件处理器（释放文件句柄）
        if self.file_handler:
            self.removeHandler(self.file_handler)
            self.file_handler.close()  # 关闭handler，释放句柄
            self.file_handler = None

        # 更新名称并重建文件处理器
        self.name = new_name
        self._set_file_handler()

    def __del__(self):
        """析构函数，确保关闭所有handler"""
        for handler in self.handlers:
            handler.close()
            self.removeHandler(handler)

if __name__ == '__main__':
    # 测试1：创建test日志器，输出控制台+文件日志
    log = LogHandler('test', level=logging.INFO, stream=True, file=True)
    log.info('这是一个测试日志（控制台+文件）')
    
    # 测试2：重置日志名称为test_new
    log.reset_name('test_new')
    log.warning('这是重置名称后的测试日志')
    
    # 测试3：创建同名日志器，验证单例（不会重复添加handler）
    log2 = LogHandler('test', level=logging.INFO, stream=True, file=True)
    log2.error('验证单例：同名日志器仅初始化一次')