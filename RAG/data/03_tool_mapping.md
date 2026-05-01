# 工具-漏洞-参数映射表（Tool Mapping）

## 核心映射关系
此表定义了 TOSKill 扫描工具与漏洞类型的精确映射关系，是 ReAct Agent 智能决策的核心依据。

## 漏洞扫描工具映射

| 工具ID | 导入模块 | 函数名 | 漏洞类型 | CWE | OWASP2021 | 严重等级 | 所属模式 |
|--------|----------|--------|----------|-----|-----------|----------|----------|
| xss | TOSKill.tools.vuln_scan.xss | xss_scan | XSS跨站脚本 | CWE-79 | A03:Injection | high/medium | fast/deep/full |
| sqli | TOSKill.tools.vuln_scan.sqli | sqli_scan | SQL注入 | CWE-89 | A03:Injection | critical/high | fast/deep/full |
| cmdi | TOSKill.tools.vuln_scan.cmdi | cmdi_scan | 命令执行/RCE | CWE-77/78 | A03:Injection | critical | deep/full |
| fileupload | TOSKill.tools.vuln_scan.fileupload | fileupload_scan | 文件上传 | CWE-434 | A04:Insecure Design | critical/high | deep/full |
| weakpass | TOSKill.tools.vuln_scan.weakpass | weakpass_scan | 弱口令 | CWE-521 | A07:Auth Failures | high/medium | deep/full |
| ssrf | TOSKill.tools.vuln_scan.ssrf | ssrf_scan | SSRF | CWE-918 | A10:SSRF | high/medium | deep/full |
| csrf | TOSKill.tools.vuln_scan.csrf | csrf_scan | CSRF | CWE-352 | A01:Access Control | medium | deep/full |
| lfi | TOSKill.tools.vuln_scan.lfi | lfi_scan | 文件包含/目录遍历 | CWE-22 | A01:Access Control | high/medium | deep/full |

## 信息收集工具映射

| 工具ID | 导入模块 | 函数名 | 收集信息 | 用途 | 所属模式 |
|--------|----------|--------|----------|------|----------|
| portscan | TOSKill.tools.info_collection.portscan | portscan | 开放端口 | 攻击面识别 | full |
| dirscan | TOSKill.tools.info_collection.dirscan | dirscan | 敏感目录 | 信息泄露检测 | full |
| subdomain | TOSKill.tools.info_collection.subdomain | subdomain | 子域名 | 扩大攻击面 | full |
| waf | TOSKill.tools.info_collection.waf | waf_detect | WAF类型 | 判断防护策略 | full |
| baseinfo | TOSKill.tools.info_collection.baseinfo | baseinfo | HTTP头/SSL | 基础信息收集 | full |
| cdnexist | TOSKill.tools.info_collection.cdnexist | cdn_detect | CDN使用 | 真实IP识别 | full |
| whatcms | TOSKill.tools.info_collection.whatcms | cms_detect | CMS/框架 | 漏洞匹配 | full |
| infoleak | TOSKill.tools.info_collection.infoleak | infoleak_scan | 敏感文件 | 信息泄露检测 | full |

## 扫描模式 → 工具选择规则

| 模式 | 选择的工具 | 适用场景 |
|------|-----------|----------|
| fast | xss, sqli | 快速评估、应急响应 |
| deep | xss, sqli, cmdi, fileupload, weakpass, ssrf, csrf, lfi | 全面渗透测试 |
| full | 全部16个工具（漏洞+信息收集） | 完整安全评估、红蓝对抗 |

## Agent 决策规则
1. 当用户说"快速扫描"、"简单检测" → 使用 mode=fast
2. 当用户说"深度扫描"、"全面检测" → 使用 mode=deep
3. 当用户说"完整扫描"、"全部检测"、"渗透测试" → 先 info_collection(mode=full)，再 web_vuln_scan(mode=deep)
4. 当用户指定具体漏洞类型（如"只扫XSS"） → 单独调用对应工具
5. 当用户说"先收集信息" → 使用 info_collection

## 严禁的映射
- 禁止对无授权目标使用任何扫描工具
- 禁止扫描内网地址: 192.168.x.x, 10.x.x.x, 172.16-31.x.x, 127.x.x.x
- 禁止对 .gov.cn .mil.cn 域名进行未授权扫描
