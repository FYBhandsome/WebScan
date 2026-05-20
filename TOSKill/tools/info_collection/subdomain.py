# -*- coding:utf-8 -*-
"""
子域名枚举工具
封装backend.plugins.subdomain模块
"""

from typing import Dict, Any


def subdomain(domain: str) -> Dict[str, Any]:
    """子域名枚举工具，获取域名的子域名列表
    
    使用ip138.com免费API查询域名的子域名：
    - 支持域名格式校验
    - 自动去重处理
    - 返回唯一子域名列表
    
    Args:
        domain: 主域名(如baidu.com)
        
    Returns:
        包含子域名列表的字典，包括：
        - success: 执行状态(True/False)
        - data: 子域名列表
        - error: 错误信息(成功时为None)
        - metadata: 元数据(工具名称、域名、子域名数量等)
    """
    try:
        from backend.plugins.subdomain.subdomain import get_subdomain
        
        subdomains = get_subdomain(domain)
        
        return {
            "success": len(subdomains) > 0,
            "data": {
                "subdomains": subdomains,
                "total_count": len(subdomains)
            },
            "error": "" if subdomains else f"未找到 {domain} 的子域名",
            "metadata": {
                "tool": "subdomain",
                "domain": domain,
                "subdomain_count": len(subdomains)
            }
        }
    except ImportError as e:
        return {
            "success": False,
            "data": {},
            "error": f"导入subdomain模块失败: {str(e)}",
            "metadata": {"tool": "subdomain", "domain": domain}
        }
    except Exception as e:
        return {
            "success": False,
            "data": {},
            "error": f"执行subdomain工具异常: {str(e)}",
            "metadata": {"tool": "subdomain", "domain": domain}
        }


if __name__ == "__main__":
    test_result = subdomain("baidu.com")
    print(test_result)
