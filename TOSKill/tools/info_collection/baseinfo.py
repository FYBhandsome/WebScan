# -*- coding:utf-8 -*-
"""
基础信息收集工具
封装backend.plugins.baseinfo模块
"""

from typing import Dict, Any


def baseinfo(target: str) -> Dict[str, Any]:
    """基础信息收集工具，收集目标域名/IP的基本信息
    
    收集目标URL的基础信息，包括：
    - 域名信息
    - IP地址列表及物理地址
    - 服务器类型
    - 编程语言
    - 操作系统推断
    - WHOIS注册信息链接
    
    Args:
        target: 目标URL、域名或IP地址
        
    Returns:
        包含基础信息的字典，包括：
        - success: 执行状态(True/False)
        - data: 执行结果数据
        - error: 错误信息(成功时为None)
        - metadata: 元数据(工具名称、目标等)
    """
    try:
        from backend.plugins.baseinfo.baseinfo import getbaseinfo
        
        result = getbaseinfo(target)
        
        return {
            "success": result.get("code") == 200,
            "data": result,
            "error": "" if result.get("code") == 200 else str(result.get("msg") or ""),
            "metadata": {
                "tool": "baseinfo",
                "target": target,
                "domain": result.get("domain"),
                "server": result.get("server"),
                "os": result.get("os")
            }
        }
    except ImportError as e:
        return {
            "success": False,
            "data": {},
            "error": f"导入baseinfo模块失败: {str(e)}",
            "metadata": {"tool": "baseinfo", "target": target}
        }
    except Exception as e:
        return {
            "success": False,
            "data": {},
            "error": f"执行baseinfo工具异常: {str(e)}",
            "metadata": {"tool": "baseinfo", "target": target}
        }


if __name__ == "__main__":
    test_result = baseinfo("https://www.baidu.com")
    print(test_result)
