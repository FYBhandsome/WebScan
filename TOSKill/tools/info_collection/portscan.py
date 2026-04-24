# -*- coding:utf-8 -*-
"""
端口扫描工具
使用@tool装饰器封装backend.plugins.portscan模块
"""

from langchain.tools import tool
from typing import Dict, Any, List


@tool
def portscan(target: str) -> Dict[str, Any]:
    """TCP全连接端口扫描工具，识别目标开放端口及对应服务
    
    对目标进行TCP全连接端口扫描，识别：
    - 开放的端口号
    - 端口对应的服务类型
    - 服务Banner信息
    - 支持常见端口扫描(21,22,23,25,53,80,443等)
    
    Args:
        target: 目标IP、域名或URL
        
    Returns:
        包含扫描结果的字典，包括：
        - success: 执行状态(True/False)
        - data: 开放端口和服务列表
        - error: 错误信息(成功时为None)
        - metadata: 元数据(工具名称、目标、开放端口数等)
    """
    try:
        from backend.plugins.portscan.portscan import ScanPort
        
        scanner = ScanPort(target)
        
        if not scanner.run_scan():
            return {
                "success": False,
                "data": None,
                "error": "端口扫描执行失败，可能是目标不可达",
                "metadata": {"tool": "portscan", "target": target}
            }
        
        results = scanner.get_results()
        
        return {
            "success": True,
            "data": {
                "open_ports": results,
                "total_count": len(results),
                "portspoof_detected": "Portspoof:0" in results
            },
            "error": None,
            "metadata": {
                "tool": "portscan",
                "target": target,
                "ip": scanner.ipaddr,
                "open_ports_count": len(results)
            }
        }
    except ImportError as e:
        return {
            "success": False,
            "data": None,
            "error": f"导入portscan模块失败: {str(e)}",
            "metadata": {"tool": "portscan", "target": target}
        }
    except Exception as e:
        return {
            "success": False,
            "data": None,
            "error": f"执行portscan工具异常: {str(e)}",
            "metadata": {"tool": "portscan", "target": target}
        }


if __name__ == "__main__":
    test_result = portscan.invoke("127.0.0.1")
    print(test_result)
