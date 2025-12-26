# 从portscan.py中导出核心类和函数，对外暴露简洁的接口
from .portscan import ScanPort  # .portscan 表示当前包下的portscan.py模块
from .portscan import main as portscan_main  # 给main函数起别名，避免冲突

# 定义__all__：指定用「from my_portscan import *」时，能导入的内容（可选，但规范）
__all__ = ["ScanPort", "portscan_main"]