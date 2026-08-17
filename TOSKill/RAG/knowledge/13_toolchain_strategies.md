# 工具链组合策略库

本文档定义了工具之间的协同工作策略，帮助AI选择最优的工具组合。

---

## 一、信息收集工具链

### 标准信息收集链

```
baseinfo_scan → port_scan → subdomain_scan → dir_brute → waf_detect_scan
```

**执行顺序原因**:
1. baseinfo_scan: 获取基础信息，确定技术栈
2. port_scan: 发现开放端口，确定攻击面
3. subdomain_scan: 扩大攻击范围
4. dir_brute: 发现公开文件和目录线索
5. waf_detect_scan: 检测防护设备，调整扫描强度

### 快速信息收集链

```
baseinfo_scan → port_scan → waf_detect_scan
```

**适用场景**: 用户要求快速扫描，时间有限

### 深度信息收集链

```
baseinfo_scan → port_scan → subdomain_scan → dir_brute → waf_detect_scan → cdn_detect_scan → cms_detect_scan
```

**适用场景**: 渗透测试，需要全面信息

---

## 二、漏洞检测工具链

### Web应用漏洞链

```
xss_scan → sqli_scan → fileupload_scan → ssrf_scan → csrf_scan
```

**执行策略**:
- 优先检测高危漏洞（SQL注入）
- 其次检测中危漏洞（XSS、文件上传）
- 最后检测低危漏洞（CSRF）

### 服务漏洞链

```
weakpass_scan → lfi_scan → cmdi_scan
```

**触发条件**: 发现非Web服务端口开放

### 完整漏洞链

```
xss_scan → sqli_scan → cmdi_scan → fileupload_scan → ssrf_scan → weakpass_scan → csrf_scan → lfi_scan
```

---

## 三、条件触发工具链

### 端口触发

| 发现端口 | 触发工具链 |
|---------|-----------|
| 3306 | weakpass_scan → sqli_scan |
| 6379 | weakpass_scan |
| 27017 | weakpass_scan |
| 21 | weakpass_scan |
| 22 | weakpass_scan |
| 3389 | weakpass_scan |
| 80/443/8080 | xss_scan → sqli_scan → dir_brute |

### 技术栈触发

| 发现技术栈 | 触发工具链 |
|-----------|-----------|
| PHP | sqli_scan → fileupload_scan → lfi_scan |
| Java | sqli_scan → ssrf_scan → fileupload_scan |
| .NET | sqli_scan → fileupload_scan |
| Node.js | xss_scan → ssrf_scan → cmdi_scan |
| Python | sqli_scan → ssrf_scan → cmdi_scan |

### 功能触发

| 发现功能 | 触发工具链 |
|---------|-----------|
| 登录表单 | sqli_scan → weakpass_scan → csrf_scan |
| 搜索功能 | sqli_scan → xss_scan |
| 文件上传 | fileupload_scan |
| URL跳转 | ssrf_scan |
| 用户输入 | xss_scan → sqli_scan |

---

## 四、绕过策略工具链

### WAF绕过链

```
waf_detect_scan → [识别拦截特征] → [降低请求频率] → [保留未完成项]
```

**具体策略**:
1. 检测WAF类型
2. 选择对应绕过技术
3. 组合多种绕过方法
4. 降低扫描频率

### 认证绕过链

```
weakpass_scan → [默认凭证] → [会话固定] → [权限提升]
```

---

## 五、漏洞利用链

### SQL注入利用链

```
sqli_scan(发现) → [数据库识别] → [数据提取] → [权限提升] → [系统命令]
```

**利用步骤**:
1. 确认注入类型
2. 识别数据库类型
3. 提取敏感数据
4. 尝试写入WebShell
5. 尝试执行系统命令

### XSS利用链

```
xss_scan(发现) → [窃取Cookie] → [会话劫持] → [账户接管]
```

**利用步骤**:
1. 确认XSS类型
2. 构造窃取Cookie的Payload
3. 等待受害者触发
4. 使用窃取的Cookie登录

### SSRF利用链

```
ssrf_scan(发现) → [内网探测] → [云元数据] → [敏感服务访问]
```

**利用步骤**:
1. 确认SSRF存在
2. 探测内网服务
3. 尝试读取云元数据
4. 访问内网敏感服务

---

## 六、工具依赖关系

### 依赖图

```
baseinfo_scan ──┬── port_scan ────┬── weakpass_scan
                │                 ├── sqli_scan
                │                 └── dir_brute
                ├── waf_detect_scan ──┴── [调整扫描强度]
                └── subdomain_scan

xss_scan ──────────┬── csrf_scan
sqli_scan ─────────┼── lfi_scan
fileupload_scan ───┴── cmdi_scan
```

### 前置条件

| 工具 | 建议前置 | 原因 |
|-----|---------|------|
| sqli_scan | baseinfo_scan | 了解技术栈选择Payload |
| xss_scan | waf_detect_scan | 根据WAF结果控制频率并解释拦截 |
| weakpass_scan | port_scan | 确认服务端口开放 |
| fileupload_scan | baseinfo_scan | 了解服务器类型 |

---

## 七、工具失败回退

### 回退策略

```
工具A失败 → 尝试替代工具B → 尝试替代工具C → 跳过并记录
```

### 回退映射表

| 失败工具 | 回退工具1 | 回退工具2 | 最终回退 |
|---------|----------|----------|---------|
| sqli_scan | xss_scan | cmdi_scan | 跳过 |
| xss_scan | csrf_scan | - | 跳过 |
| fileupload_scan | dir_brute | - | 跳过 |
| weakpass_scan | baseinfo_scan | - | 跳过 |
| ssrf_scan | csrf_scan | - | 跳过 |

---

## 八、并行执行策略

### 可并行工具组

**组1: 信息收集**
```
[baseinfo_scan, port_scan, subdomain_scan] - 可并行
```

**组2: 漏洞检测**
```
[xss_scan, sqli_scan, ssrf_scan] - 可并行（无WAF时）
```

### 串行执行场景

**必须串行**:
- waf_detect_scan 应在需要解释拦截结果时优先执行
- port_scan 结果影响 weakpass_scan 选择
- baseinfo_scan 结果影响后续工具选择

---

## 九、执行效率优化

### 时间优化策略

1. **并行化**: 无依赖的工具并行执行
2. **优先级**: 高价值目标优先检测
3. **剪枝**: 无意义检测跳过
4. **缓存**: 重复请求使用缓存

### 资源优化策略

1. **限流**: 控制请求频率
2. **超时**: 设置合理超时时间
3. **重试**: 失败请求有限重试
4. **断路**: 连续失败停止检测
