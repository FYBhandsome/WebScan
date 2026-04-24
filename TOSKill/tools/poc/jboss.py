# -*- coding:utf-8 -*-
"""
JBoss漏洞POC验证工具
使用@tool装饰器封装backend.poc.jboss模块
"""

from langchain.tools import tool
from typing import Dict, Any


@tool
def jboss_cve_2017_12149(target: str, timeout: int = 10) -> Dict[str, Any]:
    """JBoss CVE-2017-12149 反序列化漏洞检测工具
    
    检测目标是否存在JBoss Application Server JMXInvokerServlet反序列化漏洞。
    攻击者可以通过发送恶意的序列化对象来执行任意代码。
    
    影响版本:
    - JBoss AS 5.x
    - JBoss AS 6.x
    - WildFly 10.x
    
    检测原理:
    通过向/invoker/readonly端点发送POST请求。
    如果服务器返回500状态码，则说明可能存在漏洞。
    
    Args:
        target: 目标URL，如 http://127.0.0.1:8080/
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
        vulurl = target_url + "/invoker/readonly"
        
        headers = {
            'User-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:63.0) Gecko/20100101 Firefox/63.0",
            'Accept': "*/*",
            'Content-Type': "application/json",
            'X-Requested-With': "XMLHttpRequest",
            'Connection': "close",
            'Cache-Control': "no-cache"
        }
        
        r = requests.post(vulurl, headers=headers, verify=False, timeout=timeout)
        status_code = r.status_code
        
        if status_code == 500:
            return {
                "success": True,
                "data": {
                    "vulnerable": True,
                    "cve_id": "CVE-2017-12149",
                    "vulnerability": "JBoss JMXInvokerServlet Deserialization RCE",
                    "target": target_url,
                    "status_code": status_code
                },
                "error": None,
                "metadata": {
                    "tool": "jboss_cve_2017_12149",
                    "target": target,
                    "cve_id": "CVE-2017-12149",
                    "severity": "critical"
                }
            }
        else:
            return {
                "success": True,
                "data": {
                    "vulnerable": False,
                    "cve_id": "CVE-2017-12149",
                    "target": target_url,
                    "status_code": status_code
                },
                "error": None,
                "metadata": {
                    "tool": "jboss_cve_2017_12149",
                    "target": target,
                    "cve_id": "CVE-2017-12149"
                }
            }
    except ImportError as e:
        return {
            "success": False,
            "data": None,
            "error": f"导入requests模块失败: {str(e)}",
            "metadata": {"tool": "jboss_cve_2017_12149", "target": target}
        }
    except Exception as e:
        return {
            "success": False,
            "data": None,
            "error": f"执行jboss_cve_2017_12149工具异常: {str(e)}",
            "metadata": {"tool": "jboss_cve_2017_12149", "target": target}
        }


if __name__ == "__main__":
    test_result = jboss_cve_2017_12149.invoke("http://127.0.0.1:8080/")
    print(test_result)
