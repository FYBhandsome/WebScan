# -*- coding:utf-8 -*-
"""
目录扫描工具
封装backend.plugins.dirscan模块
"""

from typing import Dict, Any, Optional


def dirscan(target: str, dict_path: Optional[str] = None) -> Dict[str, Any]:
    """目录扫描工具，对目标URL进行目录和文件爆破
    
    对目标URL进行目录和文件扫描：
    - 支持多线程并发扫描
    - 支持自定义字典文件
    - 智能判断有效响应(200、301、302、403等)
    - 支持扩展名模糊匹配
    
    Args:
        target: 目标URL
        dict_path: 可选的自定义字典文件路径
        
    Returns:
        包含扫描结果的字典，包括：
        - success: 执行状态(True/False)
        - data: 发现的有效路径列表
        - error: 错误信息(成功时为None)
        - metadata: 元数据(工具名称、目标、发现数量等)
    """
    try:
        from backend.plugins.dirscan.dirscan import get_dirscan
        
        result = get_dirscan(target, dict_path=dict_path)
        
        return {
            "success": result.get("code") == 200,
            "data": {
                "results": result.get("results", []),
                "total_scanned": result.get("total_scanned", 0),
                "found_count": result.get("found_count", 0)
            },
            "error": None if result.get("code") == 200 else result.get("msg"),
            "metadata": {
                "tool": "dirscan",
                "target": target,
                "dict_path": dict_path,
                "found_count": result.get("found_count", 0)
            }
        }
    except ImportError as e:
        return {
            "success": False,
            "data": None,
            "error": f"导入dirscan模块失败: {str(e)}",
            "metadata": {"tool": "dirscan", "target": target}
        }
    except Exception as e:
        return {
            "success": False,
            "data": None,
            "error": f"执行dirscan工具异常: {str(e)}",
            "metadata": {"tool": "dirscan", "target": target}
        }


if __name__ == "__main__":
    test_result = dirscan("http://testphp.vulnweb.com")
    print(test_result)
