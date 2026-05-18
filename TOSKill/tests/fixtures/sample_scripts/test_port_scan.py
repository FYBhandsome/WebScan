"""
示例上传脚本 - 端口扫描
用于测试脚本上传和注册流程
"""
import socket
from typing import Dict, List

def run(target: str) -> Dict[str, any]:
    """扫描目标常用端口开放情况"""
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1723, 3306, 3389, 5900, 8080]
    open_ports: List[Dict] = []
    
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except Exception:
                service = "unknown"
            open_ports.append({"port": port, "service": service})
        sock.close()
    
    return {
        "success": True,
        "data": {"target": target, "open_ports": open_ports, "total_scanned": len(common_ports)},
        "timestamp": "2024-01-01T00:00:00"
    }