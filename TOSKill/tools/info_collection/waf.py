# -*- coding:utf-8 -*-
"""
WAF检测工具
封装backend.plugins.waf模块
"""

from typing import Dict, Any


def waf_detect(target: str) -> Dict[str, Any]:
    """WAF(Web应用防火墙)检测工具，检测目标网站是否部署WAF
    
    检测目标网站是否部署WAF：
    - 支持多种WAF类型识别(360、CloudFlare、F5、Baidu等)
    - 通过HTTP响应头和内容特征进行识别
    - 支持URL/域名/IP作为输入
    - 内置多种WAF识别规则
    
    Args:
        target: 目标URL
        
    Returns:
        包含WAF检测结果的字典，包括：
        - success: 执行状态(True/False)
        - data: WAF检测结果
        - error: 错误信息(成功时为None)
        - metadata: 元数据(工具名称、目标、WAF名称等)
    """
    try:
        from backend.plugins.waf.waf import get_waf
        
        result = get_waf(target)
        
        return {
            "success": result.get("status") == "success",
            "data": {
                "has_waf": result.get("has_waf"),
                "waf_name": result.get("waf_name"),
                "message": result.get("message")
            },
            "error": None if result.get("status") == "success" else result.get("message"),
            "metadata": {
                "tool": "waf_detect",
                "target": target,
                "has_waf": result.get("has_waf"),
                "waf_name": result.get("waf_name")
            }
        }
    except ImportError as e:
        return {
            "success": False,
            "data": None,
            "error": f"导入waf模块失败: {str(e)}",
            "metadata": {"tool": "waf_detect", "target": target}
        }
    except Exception as e:
        return {
            "success": False,
            "data": None,
            "error": f"执行waf_detect工具异常: {str(e)}",
            "metadata": {"tool": "waf_detect", "target": target}
        }


if __name__ == "__main__":
    test_result = waf_detect("https://www.baidu.com")
    print(test_result)
