# -*- coding:utf-8 -*-
"""
IP定位工具
封装backend.plugins.iplocating模块
"""

from typing import Dict, Any


def ip_locate(ip: str) -> Dict[str, Any]:
    """IP定位工具，查询IP地址的地理位置信息
    
    查询IP地址的地理位置信息：
    - 使用ip-api.com免费API进行查询
    - 支持IPv4地址格式校验
    - 返回国家、省份、城市信息
    - 自动处理编码，避免中文乱码
    
    Args:
        ip: IPv4地址
        
    Returns:
        包含IP地理位置的字典，包括：
        - success: 执行状态(True/False)
        - data: 地理位置信息
        - error: 错误信息(成功时为None)
        - metadata: 元数据(工具名称、IP地址等)
    """
    try:
        from backend.plugins.iplocating.iplocating import get_locating
        
        result = get_locating(ip)
        
        is_success = "国家" in result and "省份" in result
        
        return {
            "success": is_success,
            "data": {
                "location": result,
                "ip": ip
            },
            "error": "" if is_success else str(result or ""),
            "metadata": {
                "tool": "ip_locate",
                "ip": ip,
                "location": result if is_success else None
            }
        }
    except ImportError as e:
        return {
            "success": False,
            "data": {},
            "error": f"导入iplocating模块失败: {str(e)}",
            "metadata": {"tool": "ip_locate", "ip": ip}
        }
    except Exception as e:
        return {
            "success": False,
            "data": {},
            "error": f"执行ip_locate工具异常: {str(e)}",
            "metadata": {"tool": "ip_locate", "ip": ip}
        }


if __name__ == "__main__":
    test_result = ip_locate("8.8.8.8")
    print(test_result)
