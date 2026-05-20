# -*- coding:utf-8 -*-
"""
随机请求头生成工具
封装backend.plugins.randheader模块
"""

from typing import Dict, Any, Optional


def random_headers(conn_type: Optional[str] = "keep-alive") -> Dict[str, Any]:
    """随机请求头生成工具，生成伪造的HTTP请求头
    
    生成伪造的HTTP请求头：
    - 生成随机的User-Agent请求头
    - 伪造随机的公网IP地址(X-Forwarded-For和X-Real-IP)
    - 支持自定义Connection头类型
    - 自动排除内网IP段，生成更真实的公网IP
    
    Args:
        conn_type: Connection头值(keep-alive/close)，默认keep-alive
        
    Returns:
        包含请求头的字典，包括：
        - success: 执行状态(True/False)
        - data: 生成的请求头字典
        - error: 错误信息(成功时为None)
        - metadata: 元数据(工具名称、连接类型等)
    """
    try:
        from backend.plugins.randheader.randheader import get_random_headers
        
        headers = get_random_headers(conn_type)
        
        return {
            "success": True,
            "data": {
                "headers": headers,
                "user_agent": headers.get("User-Agent", ""),
                "fake_ip": headers.get("X-Forwarded-For", ""),
                "connection": headers.get("Connection", "")
            },
            "error": "",
            "metadata": {
                "tool": "random_headers",
                "conn_type": conn_type
            }
        }
    except ImportError as e:
        return {
            "success": False,
            "data": {},
            "error": f"导入randheader模块失败: {str(e)}",
            "metadata": {"tool": "random_headers", "conn_type": conn_type}
        }
    except Exception as e:
        return {
            "success": False,
            "data": {},
            "error": f"执行random_headers工具异常: {str(e)}",
            "metadata": {"tool": "random_headers", "conn_type": conn_type}
        }


if __name__ == "__main__":
    test_result = random_headers("keep-alive")
    print(test_result)
