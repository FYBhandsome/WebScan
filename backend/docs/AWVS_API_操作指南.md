# AWVS API 操作指南

本文档将详细介绍如何通过 API Key 调用 AWVS（Acunetix Web Vulnerability Scanner）的 REST API，实现**自动化执行扫描任务**、**获取扫描漏洞结果**、**生成并下载扫描报告**的完整流程，适配 AWVS 11/12/13/14 等主流版本。

## 一、前提准备

### 1. 获取 API Key

在 AWVS 后台中生成 API 认证密钥：

1. 使用管理员账户登录 AWVS 后台
2. 点击右上角头像 → `Profile`
3. 找到 `API Key` 选项，点击 `Generate New Api Key`
4. 保存生成的 API Key（后续所有接口都需要用它做认证）

### 2. 基础配置

- **AWVS 服务地址**：本地部署默认地址，旧版本（11/12）为 `https://127.0.0.1:3443`，新版本（13/14/15）为 `https://127.0.0.1:13443`，请根据你的实际部署修改
- **请求头**：所有 API 请求都需要携带以下认证头：
  - ```http
    X-Auth: 你的API Key
    Content-Type: application/json; charset=utf8
    ```

## 二、完整操作流程与示例代码

以下是完整的 Python 自动化脚本，你只需要修改开头的配置参数，即可一键完成从创建目标、启动扫描、等待完成、获取结果到下载报告的全流程。

```python
import requests
import json
import time
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# ===================== 请修改以下配置 =====================
API_KEY = "你的API Key"  # 替换为你自己的API Key
AWVS_URL = "https://127.0.0.1:13443"  # 替换为你的AWVS服务地址
TARGET_URL = "http://testphp.vulnweb.com/"  # 你要扫描的目标网站
SCAN_PROFILE_ID = "11111111-1111-1111-1111-111111111111"  # 扫描类型，默认是完全扫描
REPORT_TEMPLATE_ID = "11111111-1111-1111-1111-111111111111"  # 报告模板，默认是Developer报告
# =========================================================

# 关闭SSL警告（因为AWVS默认是自签名证书）
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# 基础请求头
headers = {
    "X-Auth": API_KEY,
    "Content-Type": "application/json; charset=utf8"
}

def add_target(target_url):
    """1. 创建扫描目标，返回target_id"""
    url = f"{AWVS_URL}/api/v1/targets"
    data = {
        "address": target_url,
        "description": f"API自动添加的目标: {target_url}",
        "criticality": 10  # 目标重要程度，10为最高
    }
    resp = requests.post(url, headers=headers, json=data, verify=False)
    result = resp.json()
    target_id = result["target_id"]
    print(f"✅ 创建目标成功，目标ID: {target_id}")
    return target_id

def start_scan(target_id, profile_id):
    """2. 启动扫描任务，返回scan_id"""
    url = f"{AWVS_URL}/api/v1/scans"
    data = {
        "target_id": target_id,
        "profile_id": profile_id,
        "schedule": {
            "disable": False,  # 立即启动扫描
            "start_date": None,
            "time_sensitive": False
        }
    }
    resp = requests.post(url, headers=headers, json=data, verify=False)
    # 从响应头的Location中获取scan_id
    scan_id = resp.headers["Location"].split("/")[-1]
    print(f"✅ 启动扫描成功，扫描任务ID: {scan_id}")
    return scan_id

def wait_scan_complete(scan_id):
    """3. 轮询扫描状态，直到扫描完成，返回scan_session_id"""
    while True:
        url = f"{AWVS_URL}/api/v1/scans/{scan_id}"
        resp = requests.get(url, headers=headers, verify=False)
        result = resp.json()
        status = result["current_session"]["status"]
        progress = result["current_session"]["progress"]
        print(f"⏳ 扫描进度: {progress}%，当前状态: {status}")
        
        if status == "completed":
            scan_session_id = result["current_session"]["scan_session_id"]
            print(f"✅ 扫描完成！扫描会话ID: {scan_session_id}")
            return scan_session_id
        elif status == "aborted":
            raise Exception("扫描任务被中止！")
        
        time.sleep(30)  # 每30秒检查一次状态

def get_scan_vulnerabilities(scan_id, scan_session_id):
    """4. 获取扫描结果（漏洞列表）"""
    url = f"{AWVS_URL}/api/v1/scans/{scan_id}/results/{scan_session_id}/vulnerabilities"
    resp = requests.get(url, headers=headers, verify=False)
    result = resp.json()
    vulnerabilities = result.get("vulnerabilities", [])
    print(f"\n📋 扫描结果：共发现 {len(vulnerabilities)} 个漏洞")
    # 打印漏洞摘要
    for vuln in vulnerabilities:
        severity = vuln["severity"]
        name = vuln["vt_name"]
        url = vuln["affects_url"]
        print(f"  [{severity}] {name} -> {url}")
    return vulnerabilities

def generate_and_download_report(scan_id, template_id):
    """5. 生成并下载扫描报告"""
    # 生成报告
    url = f"{AWVS_URL}/api/v1/reports"
    data = {
        "template_id": template_id,
        "source": {
            "list_type": "scans",
            "id_list": [scan_id]
        }
    }
    resp = requests.post(url, headers=headers, json=data, verify=False)
    report_id = resp.headers["Location"].split("/")[-1]
    print(f"\n📄 开始生成报告，报告ID: {report_id}")
    
    # 等待报告生成完成
    time.sleep(10)  # 简单等待，也可以轮询报告状态
    
    # 下载HTML报告
    download_url = f"{AWVS_URL}/reports/download/{report_id}.html"
    resp = requests.get(download_url, headers=headers, verify=False)
    with open("awvs_scan_report.html", "wb") as f:
        f.write(resp.content)
    print(f"✅ 报告下载完成，已保存为: awvs_scan_report.html")

if __name__ == "__main__":
    try:
        # 1. 创建目标
        target_id = add_target(TARGET_URL)
        # 2. 启动扫描
        scan_id = start_scan(target_id, SCAN_PROFILE_ID)
        # 3. 等待扫描完成
        scan_session_id = wait_scan_complete(scan_id)
        # 4. 获取漏洞结果
        get_scan_vulnerabilities(scan_id, scan_session_id)
        # 5. 生成并下载报告
        generate_and_download_report(scan_id, REPORT_TEMPLATE_ID)
        print("\n🎉 所有操作执行完成！")
    except Exception as e:
        print(f"\n❌ 执行出错: {str(e)}")
```

## 三、扫描类型与报告模板对照表

AWVS 内置了多种扫描配置和报告模板，你可以根据需求替换脚本中的 `SCAN_PROFILE_ID` 和 `REPORT_TEMPLATE_ID`。

### 1. 扫描类型（profile_id）对照表

| 扫描类型                                         | profile_id                             | 说明                         |
| ------------------------------------------------ | -------------------------------------- | ---------------------------- |
| Full Scan（完全扫描）                            | `11111111-1111-1111-1111-111111111111` | 完整的全量漏洞扫描，默认选项 |
| High Risk Vulnerabilities（高风险漏洞扫描）      | `11111111-1111-1111-1111-111111111112` | 仅扫描高危漏洞，速度更快     |
| SQL Injection Vulnerabilities（SQL 注入扫描）    | `11111111-1111-1111-1111-111111111113` | 仅扫描 SQL 注入漏洞          |
| Weak Passwords（弱口令检测）                     | `11111111-1111-1111-1111-111111111115` | 仅检测弱口令                 |
| Cross-site Scripting Vulnerabilities（XSS 扫描） | `11111111-1111-1111-1111-111111111116` | 仅扫描 XSS 漏洞              |
| Crawl Only（仅爬虫）                             | `11111111-1111-1111-1111-111111111117` | 仅爬取网站链接，不做漏洞检测 |
| Malware Scan（恶意软件扫描）                     | `11111111-1111-1111-1111-111111111120` | 仅扫描网站恶意软件           |

### 2. 报告模板（template_id）对照表

| 报告类型                            | template_id                            | 说明                                             |
| ----------------------------------- | -------------------------------------- | ------------------------------------------------ |
| Developer（开发人员报告）           | `11111111-1111-1111-1111-111111111111` | 详细的技术报告，包含漏洞复现和修复建议，默认选项 |
| Quick（快速报告）                   | `11111111-1111-1111-1111-111111111112` | 精简的快速报告                                   |
| Executive Summary（管理层摘要报告） | `11111111-1111-1111-1111-111111111113` | 面向管理层的执行摘要，无技术细节                 |
| HIPAA 合规报告                      | `11111111-1111-1111-1111-111111111114` | HIPAA 合规性审计报告                             |
| Affected Items（受影响项报告）      | `11111111-1111-1111-1111-111111111115` | 仅列出受漏洞影响的资产                           |
| CWE 2011 报告                       | `11111111-1111-1111-1111-111111111116` | CWE 分类报告                                     |
| ISO 27001 合规报告                  | `11111111-1111-1111-1111-111111111117` | ISO 27001 合规报告                               |
| NIST SP800 53 合规报告              | `11111111-1111-1111-1111-111111111118` | NIST 合规报告                                    |
| OWASP Top 10 2013                   | `11111111-1111-1111-1111-111111111119` | OWASP Top10 2013 报告                            |
| PCI DSS 3.2 合规报告                | `11111111-1111-1111-1111-111111111120` | PCI DSS 支付行业合规报告                         |
| OWASP Top 10 2017                   | `11111111-1111-1111-1111-111111111125` | OWASP Top10 2017 报告                            |

## 四、常见问题

### 1. 认证失败？

- 检查 API Key 是否正确，有没有复制多余的空格
- 检查 AWVS 地址和端口是否正确，新版本默认是 13443，旧版本是 3443
- 如果你使用的是 AWVS v21+ 云版本，认证方式可能变为 `Authorization: Bearer <Token>`，请参考官方文档调整请求头

### 2. SSL 证书错误？

AWVS 默认使用自签名 SSL 证书，所以请求时需要关闭 SSL 验证（也就是脚本中的 `verify=False`），这是正常的。

### 3. 扫描一直卡在某个进度？

可以检查目标网站是否能正常访问，或者调整扫描速度，也可以手动在 AWVS 后台查看扫描状态。

### 4. 报告生成失败？

如果报告生成失败，可以尝试延长等待时间，或者检查 scan_id 是否正确。