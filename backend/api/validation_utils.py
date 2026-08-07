"""
验证工具模块

提供URL、IP等输入验证的公共工具函数
"""
import re
from typing import Optional
from urllib.parse import urlparse

# IP地址正则表达式
IP_PATTERN = re.compile(
    r'^((25[0-5]|2[0-4]\d|[01]?\d?\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d?\d?)$'
)

# URL正则表达式（简化版）
URL_PATTERN = re.compile(
    r'^https?://[^\s/$.?#].[^\s]*$'
)

def validate_ip(ip: str) -> bool:
    """
    验证IP地址格式
    
    Args:
        ip: IP地址字符串
        
    Returns:
        bool: 是否为有效的IP地址
    """
    if not ip:
        return False
    
    return bool(IP_PATTERN.match(ip))

def validate_url(url: str) -> Optional[str]:
    """
    验证URL格式
    
    Args:
        url: URL字符串
        
    Returns:
        Optional[str]: 验证通过返回URL，否则返回None
    """
    if not url:
        return None
    
    # 检查是否以http://或https://开头
    if not url.startswith(('http://', 'https://')):
        return None
    
    return url


def normalize_target_url(value: str, default_scheme: str = "https") -> Optional[str]:
    """Normalize a bare domain/IP or URL to a usable HTTP URL."""
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    parsed = urlparse(raw if "://" in raw else f"{default_scheme}://{raw}")
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    if "://" in raw:
        return raw.rstrip("/")
    return f"{default_scheme}://{parsed.netloc}{parsed.path}".rstrip("/")


def normalize_target_domain(value: str) -> Optional[str]:
    """Normalize a URL or bare host to its hostname."""
    normalized = normalize_target_url(value)
    return urlparse(normalized).hostname if normalized else None

def validate_domain(domain: str) -> bool:
    """
    验证域名格式
    
    Args:
        domain: 域名字符串
        
    Returns:
        bool: 是否为有效的域名
    """
    if not domain:
        return False
    
    # 简单的域名验证
    domain_pattern = re.compile(
        r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?$'
    )
    return bool(domain_pattern.match(domain))

def validate_port_range(port_range: str) -> bool:
    """
    验证端口范围格式
    
    Args:
        port_range: 端口范围字符串，如"1-1000"
        
    Returns:
        bool: 是否为有效的端口范围
    """
    if not port_range:
        return True
    
    try:
        if '-' in port_range:
            start, end = port_range.split('-')
            start_port = int(start)
            end_port = int(end)
            return 0 < start_port <= 65535 and 0 < end_port <= 65535
        else:
            port = int(port_range)
            return 0 < port <= 65535
    except ValueError:
        return False
