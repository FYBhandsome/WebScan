# -*- coding:utf-8 -*-
"""
CDN检测工具
封装backend.plugins.cdnexist模块
"""

from typing import Dict, Any


def cdn_detect(target: str) -> Dict[str, Any]:
    """CDN检测工具，检测目标主机是否使用CDN
    
    检测目标主机是否使用CDN：
    - 通过IP段匹配和ASN匹配进行检测
    - 支持URL、域名、IP地址作为输入
    - 使用GeoIP2数据库进行ASN查询
    - 预编译CDN网段，提升检测性能
    
    Args:
        target: 目标URL、域名或IP地址
        
    Returns:
        包含CDN检测结果的字典，包括：
        - success: 执行状态(True/False)
        - data: CDN检测结果
        - error: 错误信息(成功时为None)
        - metadata: 元数据(工具名称、目标、是否使用CDN等)
    """
    try:
        from backend.plugins.cdnexist.cdnexist import is_cdn
        
        result = is_cdn(target)
        
        if isinstance(result, str):
            return {
                "success": False,
                "data": {},
                "error": result,
                "metadata": {"tool": "cdn_detect", "target": target}
            }
        
        return {
            "success": True,
            "data": {
                "has_cdn": result,
                "message": "目标使用CDN" if result else "目标未使用CDN"
            },
            "error": "",
            "metadata": {
                "tool": "cdn_detect",
                "target": target,
                "has_cdn": result
            }
        }
    except ImportError as e:
        return {
            "success": False,
            "data": {},
            "error": f"导入cdnexist模块失败: {str(e)}",
            "metadata": {"tool": "cdn_detect", "target": target}
        }
    except Exception as e:
        return {
            "success": False,
            "data": {},
            "error": f"执行cdn_detect工具异常: {str(e)}",
            "metadata": {"tool": "cdn_detect", "target": target}
        }


if __name__ == "__main__":
    test_result = cdn_detect.invoke("https://www.baidu.com")
    print(test_result)
