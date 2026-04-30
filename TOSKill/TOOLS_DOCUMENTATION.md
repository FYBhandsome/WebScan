# TOSKill 内置工具详细文档

> 版本: v2.3.0  
> 更新日期: 2026-04-26  
> 工具总数: 22个

---

## 目录

1. [信息收集工具](#一信息收集工具)
2. [漏洞扫描工具](#二漏洞扫描工具)
3. [POC验证工具](#三poc验证工具)
4. [工具返回格式标准](#四工具返回格式标准)
5. [认证参数说明](#五认证参数说明)
6. [工具使用最佳实践](#六工具使用最佳实践)

---

## 一、信息收集工具

### 1.1 baseinfo_scan - 基础信息收集

**功能描述**: 获取目标网站的基本信息，包括网站标题、服务器类型、技术栈、HTTP响应头等。

**使用场景**:
- 初步侦察阶段，了解目标基本情况
- 识别目标技术栈，为后续渗透测试做准备
- 发现潜在的信息泄露

**输入参数**:
| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| target | string | 是 | 目标域名或IP地址 |

**返回格式** (ToolResult):
```json
{
    "success": true,
    "data": {
        "title": "网站标题",
        "server": "nginx/1.18.0",
        "tech_stack": ["PHP", "MySQL", "jQuery"],
        "headers": {
            "X-Frame-Options": "SAMEORIGIN",
            "Content-Security-Policy": "..."
        },
        "status_code": 200
    },
    "error": null,
    "auth_info": null,
    "timestamp": "2026-04-26T12:00:00.000Z"
}
```

**使用示例**:
```bash
curl -X POST "http://localhost:8081/api/toskill/tools/execute" \
  -H "Content-Type: application/json" \
  -d '{"tool_name": "baseinfo_scan", "target": "example.com"}'
```

---

### 1.2 port_scan - 端口扫描

**功能描述**: 扫描目标主机开放的TCP端口，识别运行的服务。

**使用场景**:
- 网络资产发现
- 识别潜在攻击面
- 服务指纹识别

**输入参数**:
| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| target | string | 是 | 目标域名或IP地址 |

**返回格式** (ToolResult):
```json
{
    "success": true,
    "data": {
        "ports": [22, 80, 443, 3306, 8080],
        "services": {
            "22": "ssh",
            "80": "http",
            "443": "https",
            "3306": "mysql"
        },
        "scan_time": 2.5
    },
    "error": null,
    "auth_info": null,
    "timestamp": "2026-04-26T12:00:00.000Z"
}
```

**使用示例**:
```bash
curl -X POST "http://localhost:8081/api/toskill/tools/execute" \
  -H "Content-Type: application/json" \
  -d '{"tool_name": "port_scan", "target": "192.168.1.1"}'
```

---

### 1.3 subdomain_scan - 子域名扫描

**功能描述**: 发现目标域名的子域名，扩大攻击面。

**使用场景**:
- 资产收集阶段
- 发现隐藏的测试/开发环境
- 扩大渗透测试范围

**输入参数**:
| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| target | string | 是 | 目标域名 |

**返回格式** (ToolResult):
```json
{
    "success": true,
    "data": {
        "subdomains": [
            "www.example.com",
            "api.example.com",
            "dev.example.com",
            "mail.example.com"
        ],
        "count": 4
    },
    "error": null,
    "auth_info": null,
    "timestamp": "2026-04-26T12:00:00.000Z"
}
```

---

### 1.4 dir_brute - 目录扫描

**功能描述**: 暴力破解目标网站的目录结构，发现隐藏路径和敏感文件。

**使用场景**:
- 敏感目录发现
- 后台路径探测
- 备份文件发现

**输入参数**:
| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| target | string | 是 | 目标URL |

**返回格式** (ToolResult):
```json
{
    "success": true,
    "data": {
        "directories": ["/admin", "/backup", "/config", "/uploads"],
        "files": ["/robots.txt", "/sitemap.xml", "/.git/config"],
        "count": 6
    },
    "error": null,
    "auth_info": null,
    "timestamp": "2026-04-26T12:00:00.000Z"
}
```

---

### 1.5 waf_detect_scan - WAF检测

**功能描述**: 检测目标网站是否部署Web应用防火墙(WAF)。

**使用场景**:
- 渗透测试前置侦察
- 确定绕过策略
- 安全配置评估

**输入参数**:
| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| target | string | 是 | 目标URL |

**返回格式** (ToolResult):
```json
{
    "success": true,
    "data": {
        "waf_detected": true,
        "waf_name": "Cloudflare",
        "waf_vendor": "Cloudflare Inc.",
        "bypass_suggestions": ["使用编码绕过", "分块传输"]
    },
    "error": null,
    "auth_info": null,
    "timestamp": "2026-04-26T12:00:00.000Z"
}
```

---

### 1.6 cdn_detect_scan - CDN检测

**功能描述**: 检测目标网站是否使用CDN服务，帮助发现真实IP地址。

**使用场景**:
- 真实IP发现
- 绕过CDN保护
- 资产定位

**输入参数**:
| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| target | string | 是 | 目标域名 |

**返回格式** (ToolResult):
```json
{
    "success": true,
    "data": {
        "cdn_detected": true,
        "cdn_provider": "Akamai",
        "cdn_ips": ["23.45.67.89", "23.45.67.90"],
        "real_ip_hint": "可能存在真实IP泄露"
    },
    "error": null,
    "auth_info": null,
    "timestamp": "2026-04-26T12:00:00.000Z"
}
```

---

### 1.7 cms_detect_scan - CMS识别

**功能描述**: 识别目标网站使用的内容管理系统(CMS)。

**使用场景**:
- 漏洞利用准备
- 已知漏洞匹配
- 技术栈分析

**输入参数**:
| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| target | string | 是 | 目标URL |

**返回格式** (ToolResult):
```json
{
    "success": true,
    "data": {
        "cms": "WordPress",
        "version": "6.0.2",
        "plugins": ["woocommerce", "yoast-seo"],
        "theme": "twentytwentytwo"
    },
    "error": null,
    "auth_info": null,
    "timestamp": "2026-04-26T12:00:00.000Z"
}
```

---

### 1.8 infoleak_scan - 信息泄露扫描

**功能描述**: 检测目标网站是否存在敏感信息泄露。

**使用场景**:
- 敏感数据发现
- 配置文件泄露检测
- 源码泄露检测

**输入参数**:
| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| target | string | 是 | 目标URL |

**返回格式** (ToolResult):
```json
{
    "success": true,
    "data": {
        "leaks": [
            {"type": "git_exposure", "url": "/.git/config", "severity": "high"},
            {"type": "backup_file", "url": "/backup.zip", "severity": "medium"}
        ]
    },
    "error": null,
    "auth_info": null,
    "timestamp": "2026-04-26T12:00:00.000Z"
}
```

---

### 1.9 ip_locate_scan - IP定位

**功能描述**: 查询IP地址的地理位置信息。

**使用场景**:
- 资产定位
- 地理位置分析
- 合规性检查

**输入参数**:
| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| target | string | 是 | IP地址 |

**返回格式** (ToolResult):
```json
{
    "success": true,
    "data": {
        "ip": "8.8.8.8",
        "location": {
            "country": "United States",
            "region": "California",
            "city": "Mountain View"
        },
        "isp": "Google LLC",
        "asn": "AS15169"
    },
    "error": null,
    "auth_info": null,
    "timestamp": "2026-04-26T12:00:00.000Z"
}
```

---

### 1.10 webside_query_scan - 备案查询

**功能描述**: 查询网站的ICP备案信息。

**使用场景**:
- 合规性检查
- 网站归属确认
- 资产调查

**输入参数**:
| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| target | string | 是 | 目标域名 |

**返回格式** (ToolResult):
```json
{
    "success": true,
    "data": {
        "icp": "京ICP备12345678号",
        "owner": "某某科技有限公司",
        "register_date": "2020-01-01",
        "expire_date": "2025-01-01"
    },
    "error": null,
    "auth_info": null,
    "timestamp": "2026-04-26T12:00:00.000Z"
}
```

---

### 1.11 web_weight_scan - 权重查询

**功能描述**: 查询网站的搜索引擎权重和流量估算。

**使用场景**:
- 资产价值评估
- 目标优先级排序
- 流量分析

**输入参数**:
| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| target | string | 是 | 目标域名 |

**返回格式** (ToolResult):
```json
{
    "success": true,
    "data": {
        "baidu_weight": 5,
        "google_pr": 0,
        "alexa_rank": 12345,
        "estimated_traffic": "10K-50K"
    },
    "error": null,
    "auth_info": null,
    "timestamp": "2026-04-26T12:00:00.000Z"
}
```

---

## 二、漏洞扫描工具

> **注意**: 所有漏洞扫描工具支持认证参数，可在已认证状态下进行深度扫描。

### 2.1 sqli_scan - SQL注入扫描

**功能描述**: 检测目标网站是否存在SQL注入漏洞。

**使用场景**:
- 数据库安全测试
- OWASP Top 10漏洞检测
- 渗透测试

**输入参数**:
| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| target | string | 是 | 目标URL（需包含参数） |
| cookies | dict | 否 | Cookie认证信息，格式：`{"name": "value"}` |
| headers | dict | 否 | 自定义HTTP头，格式：`{"Header-Name": "value"}` |
| auth_token | string | 否 | Token认证字符串 |

**返回格式** (ToolResult):
```json
{
    "success": true,
    "data": {
        "vulnerable": true,
        "injection_type": "Boolean-based",
        "injection_point": "id parameter",
        "db_type": "MySQL",
        "payload": "1' AND 1=1--"
    },
    "error": null,
    "auth_info": null,
    "timestamp": "2026-04-26T12:00:00.000Z"
}
```

**风险等级**: 高危

**使用示例（带认证）**:
```bash
curl -X POST "http://localhost:8081/api/toskill/tools/execute" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "sqli_scan",
    "target": "http://example.com/page?id=1",
    "cookies": {"session": "abc123"}
  }'
```

---

### 2.2 xss_scan - XSS扫描

**功能描述**: 检测目标网站是否存在跨站脚本(XSS)漏洞。

**使用场景**:
- 前端安全测试
- 用户输入验证测试
- OWASP Top 10漏洞检测

**输入参数**:
| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| target | string | 是 | 目标URL |
| cookies | dict | 否 | Cookie认证信息 |
| headers | dict | 否 | 自定义HTTP头 |
| auth_token | string | 否 | Token认证字符串 |

**返回格式** (ToolResult):
```json
{
    "success": true,
    "data": {
        "vulnerable": true,
        "xss_type": "Reflected",
        "injection_point": "search parameter",
        "payload": "<script>alert('XSS')</script>",
        "severity": "medium"
    },
    "error": null,
    "auth_info": null,
    "timestamp": "2026-04-26T12:00:00.000Z"
}
```

**风险等级**: 中危

---

### 2.3 csrf_scan - CSRF扫描

**功能描述**: 检测目标网站是否存在跨站请求伪造(CSRF)漏洞。

**使用场景**:
- 认证安全测试
- 表单安全验证
- OWASP Top 10漏洞检测

**输入参数**:
| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| target | string | 是 | 目标URL |
| cookies | dict | 否 | Cookie认证信息 |
| headers | dict | 否 | 自定义HTTP头 |
| auth_token | string | 否 | Token认证字符串 |

**返回格式** (ToolResult):
```json
{
    "success": true,
    "data": {
        "vulnerable": true,
        "form_action": "/api/user/update",
        "missing_token": true,
        "severity": "medium"
    },
    "error": null,
    "auth_info": null,
    "timestamp": "2026-04-26T12:00:00.000Z"
}
```

**风险等级**: 中危

---

### 2.4 fileupload_scan - 文件上传扫描

**功能描述**: 检测目标网站的文件上传功能是否存在安全漏洞。

**使用场景**:
- 上传功能安全测试
- Webshell上传测试
- 服务器安全评估

**输入参数**:
| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| target | string | 是 | 目标URL |
| cookies | dict | 否 | Cookie认证信息 |
| headers | dict | 否 | 自定义HTTP头 |
| auth_token | string | 否 | Token认证字符串 |

**返回格式** (ToolResult):
```json
{
    "success": true,
    "data": {
        "vulnerable": true,
        "upload_endpoint": "/api/upload",
        "bypass_method": "Extension bypass",
        "uploaded_path": "/uploads/shell.php",
        "severity": "critical"
    },
    "error": null,
    "auth_info": null,
    "timestamp": "2026-04-26T12:00:00.000Z"
}
```

**风险等级**: 严重

---

### 2.5 cmdi_scan - 命令注入扫描

**功能描述**: 检测目标网站是否存在操作系统命令注入漏洞。

**使用场景**:
- 系统安全测试
- 服务器命令执行测试
- OWASP Top 10漏洞检测

**输入参数**:
| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| target | string | 是 | 目标URL |
| cookies | dict | 否 | Cookie认证信息 |
| headers | dict | 否 | 自定义HTTP头 |
| auth_token | string | 否 | Token认证字符串 |

**返回格式** (ToolResult):
```json
{
    "success": true,
    "data": {
        "vulnerable": true,
        "injection_param": "ping_host",
        "payload": "; id",
        "output": "uid=33(www-data) gid=33(www-data)",
        "severity": "critical"
    },
    "error": null,
    "auth_info": null,
    "timestamp": "2026-04-26T12:00:00.000Z"
}
```

**风险等级**: 严重

---

### 2.6 ssrf_scan - SSRF扫描

**功能描述**: 检测目标网站是否存在服务端请求伪造(SSRF)漏洞。

**使用场景**:
- 内网探测测试
- 云元数据泄露检测
- OWASP Top 10漏洞检测

**输入参数**:
| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| target | string | 是 | 目标URL |
| cookies | dict | 否 | Cookie认证信息 |
| headers | dict | 否 | 自定义HTTP头 |
| auth_token | string | 否 | Token认证字符串 |

**返回格式** (ToolResult):
```json
{
    "success": true,
    "data": {
        "vulnerable": true,
        "injection_param": "url",
        "reachable_internal": true,
        "internal_services": ["169.254.169.254:80"],
        "severity": "high"
    },
    "error": null,
    "auth_info": null,
    "timestamp": "2026-04-26T12:00:00.000Z"
}
```

**风险等级**: 高危

---

### 2.7 lfi_scan - LFI扫描

**功能描述**: 检测目标网站是否存在本地文件包含(LFI)漏洞。

**使用场景**:
- 文件读取测试
- 敏感文件泄露检测
- 服务器安全评估

**输入参数**:
| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| target | string | 是 | 目标URL |
| cookies | dict | 否 | Cookie认证信息 |
| headers | dict | 否 | 自定义HTTP头 |
| auth_token | string | 否 | Token认证字符串 |

**返回格式** (ToolResult):
```json
{
    "success": true,
    "data": {
        "vulnerable": true,
        "injection_param": "file",
        "readable_files": ["/etc/passwd", "/etc/hosts"],
        "severity": "high"
    },
    "error": null,
    "auth_info": null,
    "timestamp": "2026-04-26T12:00:00.000Z"
}
```

**风险等级**: 高危

---

### 2.8 weakpass_scan - 弱口令扫描

**功能描述**: 检测目标系统的登录功能是否存在弱口令问题。成功破解后会自动获取认证信息。

**使用场景**:
- 认证安全测试
- 密码策略评估
- 账户安全检查

**输入参数**:
| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| target | string | 是 | 目标登录页面URL |

**返回格式** (ToolResult):
```json
{
    "success": true,
    "data": {
        "weak_accounts": [
            {"username": "admin", "password": "admin123", "role": "administrator"}
        ],
        "severity": "high"
    },
    "error": null,
    "auth_info": {
        "cookies": {"session": "abc123", "token": "xyz789"},
        "type": "cookie",
        "source": "weakpass_scan"
    },
    "timestamp": "2026-04-26T12:00:00.000Z"
}
```

**风险等级**: 高危

**特殊说明**: 此工具成功后会返回 `auth_info` 字段，包含获取的认证信息，后续工具可自动使用。

---

## 三、POC验证工具

### 3.1 thinkphp_rce_scan - ThinkPHP RCE检测

**功能描述**: 检测目标是否存在ThinkPHP远程代码执行漏洞。

**使用场景**:
- ThinkPHP框架漏洞验证
- 已知CVE漏洞检测
- 应急响应

**输入参数**:
| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| target | string | 是 | 目标URL |

**返回格式** (ToolResult):
```json
{
    "success": true,
    "data": {
        "vulnerable": true,
        "version": "5.0.23",
        "cve": "CVE-2019-9082",
        "exploit_url": "/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo",
        "severity": "critical"
    },
    "error": null,
    "auth_info": null,
    "timestamp": "2026-04-26T12:00:00.000Z"
}
```

**风险等级**: 严重

---

### 3.2 struts2_scan - Struts2漏洞检测

**功能描述**: 检测目标是否存在Apache Struts2系列漏洞。

**使用场景**:
- Struts2框架漏洞验证
- 已知CVE漏洞批量检测
- 应急响应

**输入参数**:
| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| target | string | 是 | 目标URL |

**返回格式** (ToolResult):
```json
{
    "success": true,
    "data": {
        "vulnerable": true,
        "cve_list": ["CVE-2017-5638", "CVE-2018-11776"],
        "version": "2.3.34",
        "severity": "critical"
    },
    "error": null,
    "auth_info": null,
    "timestamp": "2026-04-26T12:00:00.000Z"
}
```

**风险等级**: 严重

---

### 3.3 weblogic_scan - WebLogic漏洞检测

**功能描述**: 检测目标是否存在Oracle WebLogic系列漏洞。

**使用场景**:
- WebLogic中间件漏洞验证
- 已知CVE漏洞批量检测
- 企业内网安全评估

**输入参数**:
| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| target | string | 是 | 目标URL或IP:端口 |

**返回格式** (ToolResult):
```json
{
    "success": true,
    "data": {
        "vulnerable": true,
        "cve_list": ["CVE-2020-2551", "CVE-2023-21839"],
        "version": "14.1.1.0.0",
        "severity": "critical"
    },
    "error": null,
    "auth_info": null,
    "timestamp": "2026-04-26T12:00:00.000Z"
}
```

**风险等级**: 严重

---

## 四、工具返回格式标准

### 4.1 ToolResult 标准格式

所有工具返回统一的标准格式：

```python
class ToolResult(TypedDict, total=False):
    success: bool           # 执行是否成功（必需）
    data: Dict[str, Any]    # 返回数据（必需）
    error: Optional[str]    # 错误信息（可选）
    auth_info: Optional[Dict[str, Any]]  # 认证信息（可选）
    timestamp: str          # 时间戳，ISO格式（必需）
```

### 4.2 字段说明

| 字段 | 类型 | 必需 | 说明 |
|------|------|------|------|
| success | boolean | 是 | 执行是否成功 |
| data | object | 是 | 返回数据，包含工具执行结果 |
| error | string\|null | 否 | 错误信息，成功时为null |
| auth_info | object\|null | 否 | 认证信息，仅部分工具返回 |
| timestamp | string | 是 | 时间戳，ISO 8601格式 |

### 4.3 成功响应示例

```json
{
    "success": true,
    "data": {
        "vulnerable": false,
        "scan_time": 2.5
    },
    "error": null,
    "auth_info": null,
    "timestamp": "2026-04-26T12:00:00.000Z"
}
```

### 4.4 失败响应示例

```json
{
    "success": false,
    "data": {},
    "error": "连接超时：目标服务器无响应",
    "auth_info": null,
    "timestamp": "2026-04-26T12:00:00.000Z"
}
```

### 4.5 包含认证信息的响应

```json
{
    "success": true,
    "data": {
        "weak_accounts": [{"username": "admin", "password": "admin123"}]
    },
    "error": null,
    "auth_info": {
        "cookies": {"session": "abc123"},
        "headers": {"Authorization": "Bearer xxx"},
        "token": "eyJhbGciOiJIUzI1NiIs...",
        "type": "cookie",
        "source": "weakpass_scan"
    },
    "timestamp": "2026-04-26T12:00:00.000Z"
}
```

---

## 五、认证参数说明

### 5.1 支持认证的工具

以下漏洞扫描工具支持认证参数：

| 工具名称 | 支持认证 | 说明 |
|---------|---------|------|
| sqli_scan | ✅ | SQL注入扫描 |
| xss_scan | ✅ | XSS扫描 |
| csrf_scan | ✅ | CSRF扫描 |
| fileupload_scan | ✅ | 文件上传扫描 |
| cmdi_scan | ✅ | 命令注入扫描 |
| ssrf_scan | ✅ | SSRF扫描 |
| lfi_scan | ✅ | LFI扫描 |
| weakpass_scan | ✅ | 弱口令扫描（可返回认证信息） |

### 5.2 认证参数格式

| 参数名 | 类型 | 格式 | 示例 |
|--------|------|------|------|
| cookies | dict | `{"name": "value"}` | `{"session": "abc123", "token": "xyz"}` |
| headers | dict | `{"Header-Name": "value"}` | `{"Authorization": "Bearer xxx"}` |
| auth_token | string | Token字符串 | `"eyJhbGciOiJIUzI1NiIs..."` |

### 5.3 认证信息自动传递

当 `weakpass_scan` 成功获取认证信息后，系统会自动将其传递给后续工具：

1. 弱口令扫描成功 → 返回 `auth_info`
2. 系统存储到会话状态 → `state.auth_info`
3. 后续工具自动使用 → 无需手动传递

### 5.4 认证过期处理

- **默认过期时间**: 30分钟
- **过期检测**: 自动检测 `auth_expires_at` 或基于时间戳计算
- **过期通知**: WebSocket 推送 `auth_expired` 消息

---

## 六、工具使用最佳实践

### 6.1 扫描顺序建议

**信息收集阶段**:
```
baseinfo_scan → port_scan → subdomain_scan → dir_brute
waf_detect_scan → cdn_detect_scan → cms_detect_scan
```

**漏洞扫描阶段**:
```
weakpass_scan → sqli_scan → xss_scan → fileupload_scan
cmdi_scan → ssrf_scan → lfi_scan
```

**POC验证阶段**:
```
根据CMS识别结果选择对应的POC工具
```

### 6.2 认证扫描流程

```
1. 运行 weakpass_scan 获取认证信息
2. 系统自动存储 auth_info
3. 运行漏洞扫描工具（自动使用认证）
4. 发现更多安全漏洞
```

### 6.3 安全注意事项

1. **授权要求**: 确保已获得目标系统所有者的明确授权
2. **测试环境**: 建议先在测试环境中验证工具行为
3. **数据保护**: 扫描过程中获取的敏感数据应妥善保管
4. **法律合规**: 遵守当地法律法规，不得用于非法目的

### 6.4 性能优化建议

1. **并发控制**: 避免同时运行过多扫描任务
2. **超时设置**: 根据目标响应速度调整超时参数
3. **资源监控**: 关注系统资源使用情况
4. **批量执行**: 使用批量执行接口提高效率

---

*文档版本: 2.3.0 | 最后更新: 2026-04-26*
