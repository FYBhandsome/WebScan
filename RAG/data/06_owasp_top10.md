# OWASP Top 10 映射（2021版）

## OWASP Top 10 2021 → TOSKill 工具覆盖

| OWASP排名 | 风险类别 | 对应漏洞 | TOSKill覆盖 | 对应工具 |
|-----------|----------|----------|-------------|----------|
| A01 | Broken Access Control（访问控制失效） | CSRF、目录遍历、权限绕过 | ✓ 部分覆盖 | csrf, lfi |
| A02 | Cryptographic Failures（加密失效） | 明文传输、弱加密 | ✗ 未覆盖 | - |
| A03 | Injection（注入） | SQL注入、XSS、命令注入 | ✓ 完整覆盖 | sqli, xss, cmdi |
| A04 | Insecure Design（不安全设计） | 文件上传、缺少速率限制 | ✓ 部分覆盖 | fileupload, weakpass |
| A05 | Security Misconfiguration（安全配置错误） | 默认口令、错误页泄露 | ✓ 部分覆盖 | weakpass, baseinfo |
| A06 | Vulnerable Components（漏洞组件） | 框架/CMS已知漏洞 | ✗ 未覆盖 | (依赖CMS识别+手动验证) |
| A07 | Auth Failures（认证失效） | 弱口令、会话固定 | ✓ 部分覆盖 | weakpass |
| A08 | Software & Data Integrity（软件数据完整性） | 不安全的反序列化 | ✗ 未覆盖 | - |
| A09 | Logging & Monitoring（日志监控失效） | 日志注入、审计缺失 | ✗ 未覆盖 | - |
| A10 | SSRF（服务端请求伪造） | SSRF | ✓ 完整覆盖 | ssrf |

## OWASP Top 10 2017 对照

| 2017排名 | 风险类别 | 对应工具 |
|----------|----------|----------|
| A1 | Injection | sqli, xss, cmdi |
| A2 | Broken Authentication | weakpass |
| A3 | Sensitive Data Exposure | infoleak |
| A4 | XML External Entities (XXE) | ✗ |
| A5 | Broken Access Control | csrf, lfi |
| A6 | Security Misconfiguration | baseinfo, waf |
| A7 | Cross-Site Scripting (XSS) | xss |
| A8 | Insecure Deserialization | ✗ |
| A9 | Using Known Vulnerable Components | whatcms (+手动) |
| A10 | Insufficient Logging & Monitoring | ✗ |

## 覆盖度统计

| 指标 | 数值 |
|------|------|
| OWASP 2021 覆盖面 | 6/10 (60%) |
| OWASP 2017 覆盖面 | 8/10 (80%) |
| 漏洞扫描工具数 | 8个 |
| 信息收集工具数 | 8个 |
| 工具总数 | 16个 |

## Agent 报告中应包含的OWASP标注
当发现漏洞时，Agent应在报告中标注对应的OWASP分类，如：
```
发现SQL注入漏洞 [OWASP A03:2021-Injection] [CWE-89]
```
