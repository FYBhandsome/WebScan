# -*- coding:utf-8 -*-
"""
WebLogic漏洞POC验证工具
使用@tool装饰器封装backend.poc.weblogic模块
"""

from langchain.tools import tool
from typing import Dict, Any
import socket
import time
import re


@tool
def weblogic_cve_2020_2551(target: str, timeout: int = 10) -> Dict[str, Any]:
    """WebLogic CVE-2020-2551 T3/IIOP协议反序列化漏洞检测工具
    
    检测目标是否存在WebLogic Server T3/IIOP协议反序列化漏洞。
    攻击者可以通过发送恶意的T3/IIOP请求来执行任意代码。
    
    影响版本:
    - Oracle WebLogic Server 10.3.6.0.0
    - Oracle WebLogic Server 12.1.3.0.0
    - Oracle WebLogic Server 12.2.1.3.0
    - Oracle WebLogic Server 12.2.1.4.0
    - Oracle WebLogic Server 14.1.1.0.0
    
    检测原理:
    通过发送特定的GIOP请求包，如果服务器返回包含'GIOP'的响应，
    则说明目标可能存在该漏洞。
    
    Args:
        target: 目标URL，如 http://127.0.0.1:7001
        timeout: 请求超时时间(秒)，默认10秒
        
    Returns:
        包含检测结果的字典，包括：
        - success: 执行状态(True/False)
        - data: 执行结果数据
        - error: 错误信息(成功时为None)
        - metadata: 元数据(工具名称、目标、漏洞信息等)
    """
    try:
        from urllib.parse import urlparse
        
        def doSendOne(ip, port, data):
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(7)
                server_addr = (ip, int(port))
                sock.connect(server_addr)
                sock.send(data)
                res = sock.recv(20)
                if b'GIOP' in res:
                    return True
            except Exception:
                pass
            finally:
                if sock is not None:
                    sock.close()
            return False
        
        if not target.startswith('http'):
            target = 'http://' + target
        oH = urlparse(target)
        a = oH.netloc.split(':')
        port = 7001
        if len(a) == 2:
            port = a[1]
        elif 'https' in oH.scheme:
            port = 443
        
        if doSendOne(a[0], port, bytes.fromhex('47494f50010200030000001700000002000000000000000b4e616d6553657276696365')):
            return {
                "success": True,
                "data": {
                    "vulnerable": True,
                    "cve_id": "CVE-2020-2551",
                    "vulnerability": "WebLogic T3/IIOP Protocol Deserialization RCE",
                    "target": target
                },
                "error": None,
                "metadata": {
                    "tool": "weblogic_cve_2020_2551",
                    "target": target,
                    "cve_id": "CVE-2020-2551",
                    "severity": "critical"
                }
            }
        else:
            return {
                "success": True,
                "data": {
                    "vulnerable": False,
                    "cve_id": "CVE-2020-2551",
                    "target": target
                },
                "error": None,
                "metadata": {
                    "tool": "weblogic_cve_2020_2551",
                    "target": target,
                    "cve_id": "CVE-2020-2551"
                }
            }
    except Exception as e:
        return {
            "success": False,
            "data": None,
            "error": f"执行weblogic_cve_2020_2551工具异常: {str(e)}",
            "metadata": {"tool": "weblogic_cve_2020_2551", "target": target}
        }


if __name__ == "__main__":
    test_result = weblogic_cve_2020_2551.invoke("http://127.0.0.1:7001")
    print(test_result)
