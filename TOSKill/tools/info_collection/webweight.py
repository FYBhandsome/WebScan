# -*- coding:utf-8 -*-
"""
网站权重查询工具
封装backend.plugins.webweight模块
"""

from typing import Dict, Any


def web_weight(domain: str) -> Dict[str, Any]:
    """网站权重查询工具，查询域名的百度权重
    
    查询域名的百度权重(PC端和移动端)：
    - 使用爱站网API进行查询
    - 支持域名格式校验和提取
    - 返回PC权重、移动权重、预计来路
    - 自动处理编码，避免中文乱码
    
    Args:
        domain: 域名或URL(如https://example.com)
        
    Returns:
        包含权重信息的字典，包括：
        - success: 执行状态(True/False)
        - data: 权重数据
        - error: 错误信息(成功时为None)
        - metadata: 元数据(工具名称、域名、权重等)
    """
    try:
        from backend.plugins.webweight.webweight import get_web_weight
        
        result = get_web_weight(domain)
        
        return {
            "success": result.get("success", False),
            "data": {
                "result": result.get("result", ""),
                "raw_data": result.get("raw_data", {})
            },
            "error": "" if result.get("success") else str(result.get("message") or ""),
            "metadata": {
                "tool": "web_weight",
                "domain": domain,
                "result": result.get("result", "")
            }
        }
    except ImportError as e:
        return {
            "success": False,
            "data": {},
            "error": f"导入webweight模块失败: {str(e)}",
            "metadata": {"tool": "web_weight", "domain": domain}
        }
    except Exception as e:
        return {
            "success": False,
            "data": {},
            "error": f"执行web_weight工具异常: {str(e)}",
            "metadata": {"tool": "web_weight", "domain": domain}
        }


if __name__ == "__main__":
    test_result = web_weight("https://www.baidu.com")
    print(test_result)
