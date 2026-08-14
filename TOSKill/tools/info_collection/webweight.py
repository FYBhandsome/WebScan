# -*- coding:utf-8 -*-
"""
网站权重查询工具
封装backend.plugins.webweight模块
"""

import ipaddress
from urllib.parse import urlparse
from typing import Dict, Any


def _registrable_domain(target: str) -> str:
    """Return a queryable host, collapsing ordinary multi-level subdomains."""
    value = str(target or "").strip()
    parsed = urlparse(value if "://" in value else f"//{value}")
    host = (parsed.hostname or "").strip(".").lower()
    if not host:
        raise ValueError("网站权重查询缺少有效域名")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if len(labels) < 2 or any(not label for label in labels):
            raise ValueError(f"网站权重查询域名格式无效: {host}")
        # The provider accepts root domains. This covers common public suffixes
        # without introducing another network-backed dependency.
        second_level_suffixes = {"com.cn", "net.cn", "org.cn", "gov.cn", "co.uk", "org.uk", "com.au"}
        suffix = ".".join(labels[-2:])
        return ".".join(labels[-3:]) if suffix in second_level_suffixes and len(labels) >= 3 else suffix
    raise ValueError("网站权重查询仅支持域名，不支持 IP 地址")


def web_weight(domain: str) -> Dict[str, Any]:
    """网站权重查询工具，查询域名的百度权重
    
    查询域名的百度权重(PC端和移动端)：
    - 使用爱站网API进行查询
    - 支持域名格式校验和提取
    - 返回PC权重、移动权重、预计来路
    - 自动处理编码，避免中文乱码
    
    Args:
        domain: 域名或URL(如https://example.com)
        
    Returns:
        包含权重信息的字典，包括：
        - success: 执行状态(True/False)
        - data: 权重数据
        - error: 错误信息(成功时为None)
        - metadata: 元数据(工具名称、域名、权重等)
    """
    try:
        from backend.plugins.webweight.webweight import get_web_weight
        
        lookup_domain = _registrable_domain(domain)
        result = get_web_weight(lookup_domain)
        
        return {
            "success": result.get("success", False),
            "data": {
                "result": result.get("result", ""),
                "raw_data": result.get("raw_data", {}),
                "lookup_domain": lookup_domain,
            },
            "error": None if result.get("success") else result.get("message"),
            "metadata": {
                "tool": "web_weight",
                "domain": domain,
                "lookup_domain": lookup_domain,
                "result": result.get("result", "")
            }
        }
    except ImportError as e:
        return {
            "success": False,
            "data": None,
            "error": f"导入webweight模块失败: {str(e)}",
            "metadata": {"tool": "web_weight", "domain": domain}
        }
    except Exception as e:
        return {
            "success": False,
            "data": None,
            "error": f"执行web_weight工具异常: {str(e)}",
            "metadata": {"tool": "web_weight", "domain": domain}
        }


if __name__ == "__main__":
    test_result = web_weight("https://www.baidu.com")
    print(test_result)
