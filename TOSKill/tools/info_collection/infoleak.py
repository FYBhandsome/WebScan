# -*- coding:utf-8 -*-
"""
信息泄露扫描工具
使用@tool装饰器封装backend.plugins.infoleak模块
"""

from langchain.tools import tool
from typing import Dict, Any


@tool
def infoleak_scan(target: str) -> Dict[str, Any]:
    """信息泄露扫描工具，扫描目标URL的敏感文件和目录
    
    扫描目标URL的敏感文件和目录：
    - 检测潜在的信息泄露风险(如备份文件、配置文件等)
    - 支持多线程并发扫描，提升效率
    - 基于风险路径字典进行检测
    - 支持多种HTTP状态码判断(200、206、401、305、407)
    
    Args:
        target: 目标URL
        
    Returns:
        包含扫描结果的字典，包括：
        - success: 执行状态(True/False)
        - data: 发现的风险链接列表
        - error: 错误信息(成功时为None)
        - metadata: 元数据(工具名称、目标、风险链接数量等)
    """
    try:
        from backend.plugins.infoleak.infoleak import get_infoleak
        
        risk_links = get_infoleak(target)
        
        grouped_results = {}
        for key, url in risk_links:
            if key not in grouped_results:
                grouped_results[key] = []
            grouped_results[key].append(url)
        
        return {
            "success": True,
            "data": {
                "risk_links": [{"type": k, "url": v} for k, v in risk_links],
                "grouped_results": grouped_results,
                "total_count": len(risk_links)
            },
            "error": None,
            "metadata": {
                "tool": "infoleak_scan",
                "target": target,
                "risk_count": len(risk_links),
                "risk_types": list(grouped_results.keys())
            }
        }
    except ImportError as e:
        return {
            "success": False,
            "data": None,
            "error": f"导入infoleak模块失败: {str(e)}",
            "metadata": {"tool": "infoleak_scan", "target": target}
        }
    except Exception as e:
        return {
            "success": False,
            "data": None,
            "error": f"执行infoleak_scan工具异常: {str(e)}",
            "metadata": {"tool": "infoleak_scan", "target": target}
        }


if __name__ == "__main__":
    test_result = infoleak_scan.invoke("https://example.com")
    print(test_result)
