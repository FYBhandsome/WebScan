# -*- coding:utf-8 -*-
"""
旁站查询工具
使用@tool装饰器封装backend.plugins.webside模块
"""

from langchain.tools import tool
from typing import Dict, Any


@tool
def webside_query(ip: str) -> Dict[str, Any]:
    """旁站查询工具，查询指定IP地址的旁站信息
    
    查询指定IP地址的旁站信息(同IP下的其他域名)：
    - 使用webscan.cc免费API进行查询
    - 支持IPv4地址格式校验
    - 自动处理BOM字符，避免JSON解析错误
    - 标准化返回结果
    
    Args:
        ip: IPv4地址
        
    Returns:
        包含旁站信息的字典，包括：
        - success: 执行状态(True/False)
        - data: 旁站数据列表
        - error: 错误信息(成功时为None)
        - metadata: 元数据(工具名称、IP地址、旁站数量等)
    """
    try:
        from backend.plugins.webside.webside import get_side_info
        
        result = get_side_info(ip)
        
        return {
            "success": result.get("success", False),
            "data": {
                "has_data": result.get("has_data", False),
                "side_sites": result.get("data", []),
                "total_count": len(result.get("data", []))
            },
            "error": None if result.get("success") else (
                f"旁站查询外部服务不可用: {result.get('message') or '未知错误'}"
            ),
            "metadata": {
                "tool": "webside_query",
                "ip": ip,
                "has_data": result.get("has_data", False),
                "sites_count": len(result.get("data", [])),
                "provider": "api.webscan.cc",
            }
        }
    except ImportError as e:
        return {
            "success": False,
            "data": None,
            "error": f"导入webside模块失败: {str(e)}",
            "metadata": {"tool": "webside_query", "ip": ip}
        }
    except Exception as e:
        return {
            "success": False,
            "data": None,
            "error": f"执行webside_query工具异常: {str(e)}",
            "metadata": {"tool": "webside_query", "ip": ip}
        }


if __name__ == "__main__":
    test_result = webside_query("8.8.8.8")
    print(test_result)
