# 漏洞严重等级分类体系（Severity Classification）

## CVSS 3.1 评分体系

### 评分维度
| 维度 | 指标 | 说明 |
|------|------|------|
| AV (攻击向量) | N/A/L/P | Network/Adjacent/Local/Physical |
| AC (攻击复杂度) | L/H | Low/High |
| PR (权限要求) | N/L/H | None/Low/High |
| UI (用户交互) | N/R | None/Required |
| S (作用域) | U/C | Unchanged/Changed |
| C (机密性) | N/L/H | None/Low/High |
| I (完整性) | N/L/H | None/Low/High |
| A (可用性) | N/L/H | None/Low/High |

### 等级划分
| 等级 | CVSS分数 | 标签 | 响应时间 |
|------|----------|------|----------|
| critical | 9.0-10.0 | CRITICAL | 24小时内修复 |
| high | 7.0-8.9 | HIGH | 72小时内修复 |
| medium | 4.0-6.9 | MEDIUM | 下一版本修复 |
| low | 0.1-3.9 | LOW | 排期修复 |
| info | 0/N/A | INFO | 加固建议 |

---

## TOSKill 漏洞等级判定规则

### critical（严重）
满足以下任一条件：
- SQL注入可获取数据库完全控制权
- 命令执行/RCE获取系统Shell
- 文件上传可直接执行WebShell
- 任意文件读取泄漏数据库凭据
- 未授权访问可读写关键配置

### high（高危）
满足以下任一条件：
- 存储型XSS影响所有用户
- SQL注入时间盲注可逐字节脱库
- SSRF可直接访问内网核心服务
- 弱口令获取管理员权限
- LFI可达成RCE链

### medium（中危）
满足以下任一条件：
- 反射型XSS（需用户点击）
- CSRF可修改用户配置
- SSRF仅可探测内网端口
- 目录遍历但权限受限
- 敏感信息泄露（版本号、路径）

### low（低危）
满足以下任一条件：
- 不安全的HTTP方法（PUT/DELETE）
- 缺少安全响应头
- 错误页面泄露框架版本
- 目录列表功能开启
- HTTP明文传输（无HSTS）

### info（信息）
- 最佳实践建议
- 加固指南
- 配置优化建议

---

## 漏洞对应等级速查表

| 漏洞类型 | 默认等级 | 最高可达 | 降级条件 |
|----------|----------|----------|----------|
| SQL注入(回显) | critical | critical | - |
| SQL注入(盲注) | high | critical | 命中核心库 |
| RCE命令执行 | critical | critical | - |
| 存储型XSS | high | critical | 管理员触发 |
| 反射型XSS | medium | high | 无CSRF保护 |
| DOM型XSS | medium | high | 敏感数据操作 |
| 文件上传(WebShell) | critical | critical | - |
| 文件上传(任意类型) | high | critical | 可执行 |
| SSRF(内网可达) | high | critical | Redis/DB |
| SSRF(仅出网) | medium | high | 云元数据 |
| CSRF(修改密码) | medium | high | 无二次验证 |
| 弱口令(管理员) | high | critical | SSH/RDP |
| 弱口令(普通用户) | medium | high | 可提权 |
| LFI(到RCE) | high | critical | - |
| LFI(仅读取) | medium | high | 敏感文件 |
| 目录遍历 | medium | high | 覆盖配置文件 |
