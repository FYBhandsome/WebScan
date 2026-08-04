# -*- coding:utf-8 -*-
"""
CMS识别工具
封装backend.plugins.whatcms模块
"""

from typing import Dict, Any


def cms_detect(target: str) -> Dict[str, Any]:
    """CMS(内容管理系统)识别工具，识别目标网站使用的CMS类型和版本
    
    识别目标网站使用的CMS类型和版本：
    - 基于Wappalyzer规则库进行检测
    - 支持多种检测方式(URL、HTML、Script、Header等)
    - 支持自定义规则和扩展
    - 返回详细的CMS信息和相关技术栈
    
    Args:
        target: 目标URL
        
    Returns:
        包含CMS识别结果的字典，包括：
        - success: 执行状态(True/False)
        - data: CMS识别结果数据
        - error: 错误信息(成功时为None)
        - metadata: 元数据(工具名称、目标、识别到的应用等)
    """
    try:
        from backend.plugins.whatcms.whatcms import getwhatcms
        
        result = getwhatcms(target)
        
        return {
            "success": result.get("success", False),
            "data": {
                "apps": result.get("data", {}).get("apps", []),
                "title": result.get("data", {}).get("title", ""),
                "server": result.get("data", {}).get("server", ""),
                "security": result.get("data", {}).get("security", []),
                "url": result.get("data", {}).get("url", target)
            },
            "error": None if result.get("success") else result.get("message"),
            "metadata": {
                "tool": "cms_detect",
                "target": target,
                "apps_count": len(result.get("data", {}).get("apps", [])),
                "server": result.get("data", {}).get("server", "")
            }
        }
    except ImportError as e:
        return {
            "success": False,
            "data": None,
            "error": f"导入whatcms模块失败: {str(e)}",
            "metadata": {"tool": "cms_detect", "target": target}
        }
    except Exception as e:
        return {
            "success": False,
            "data": None,
            "error": f"执行cms_detect工具异常: {str(e)}",
            "metadata": {"tool": "cms_detect", "target": target}
        }


if __name__ == "__main__":
    test_result = cms_detect("https://www.baidu.com")
    print(test_result)
