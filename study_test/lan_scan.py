# lan_scan.py 局域网扫描工具（独立运行 + 供外部调用）
# 无任何循环导入，无报错
from scapy.all import ARP, Ether, srp
import socket

def get_local_subnet():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        return None

    prefix = ".".join(local_ip.split(".")[:3])
    return f"{prefix}.0/24"

def scan_online_devices(subnet):
    print("\n[扫描] 正在扫描局域网在线设备...")
    arp = ARP(pdst=subnet)
    eth = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = eth / arp
    result = srp(packet, timeout=3, verbose=0)[0]

    online_ips = []
    for sent, received in result:
        online_ips.append(received.psrc)
        print(f"[在线设备] {received.psrc}")
    return online_ips

# ===================== 提供给外部调用的函数 =====================
def select_single_target():
    subnet = get_local_subnet()
    if not subnet:
        return None
    ips = scan_online_devices(subnet)

    if not ips:
        return None

    print("\n======= 选择攻击目标 =======")
    for i, ip in enumerate(ips):
        print(f"[{i}] {ip}")

    while True:
        try:
            idx = int(input("请输入序号："))
            return ips[idx]
        except:
            print("输入错误，请重试")

def select_all_targets():
    subnet = get_local_subnet()
    if not subnet:
        return []
    return scan_online_devices(subnet)

# 独立运行
if __name__ == "__main__":
    print("======= 局域网扫描工具 独立运行 =======")
    select_all_targets()
    input("\n按回车退出")