# OWASP Top 10 2021 能力映射

> 参考框架：OWASP Top 10 2021
> 适用范围：TOSKill 26个信息收集与漏洞扫描工具
> 最后复核：2026-08-14

本映射描述自动化扫描能够提供的技术证据，不代表对某个OWASP风险类别的完整审计或合规认证。

## 能力矩阵

| 类别 | TOSKill可提供的证据 | 主要工具 | 覆盖边界 |
|---|---|---|---|
| A01 Broken Access Control | CSRF、路径遍历、部分CORS访问控制缺陷 | `csrf_scan`、`lfi_scan`、`cors_misconfiguration_scan` | 部分检测；不能覆盖全部业务越权和对象级授权 |
| A02 Cryptographic Failures | TLS协议与证书、Cookie传输属性、HSTS配置 | `tls_certificate_scan`、`cookie_security_scan`、`http_security_headers_scan` | 配置层证据；不能证明数据全生命周期加密 |
| A03 Injection | SQL注入、XSS、OS命令注入 | `sqli_scan`、`xss_scan`、`cmdi_scan` | 核心Web入口检测；仍受爬取范围、认证和输入点覆盖影响 |
| A04 Insecure Design | 文件上传、CSRF等设计缺陷线索 | `fileupload_scan`、`csrf_scan` | 只能提供局部技术线索，无法代替威胁建模和设计评审 |
| A05 Security Misconfiguration | 安全响应头、Cookie、CORS、HTTP方法、公开元数据、默认口令 | `http_security_headers_scan`、`cookie_security_scan`、`cors_misconfiguration_scan`、`http_methods_scan`、`public_metadata_scan`、`weakpass_scan` | 较强配置检测，但不覆盖全部平台、中间件和云配置 |
| A06 Vulnerable and Outdated Components | CMS/框架指纹和公开版本线索 | `cms_detect_scan`、`baseinfo_scan` | 仅识别线索；需要资产清单、版本确认和漏洞情报进行二次验证 |
| A07 Identification and Authentication Failures | 弱口令、会话Cookie属性 | `weakpass_scan`、`cookie_security_scan` | 部分检测；不能覆盖完整身份生命周期和多因素认证流程 |
| A08 Software and Data Integrity Failures | 公开元数据和部分安全头线索 | `public_metadata_scan`、`http_security_headers_scan` | 低覆盖；无法验证供应链、签名、CI/CD和反序列化安全 |
| A09 Security Logging and Monitoring Failures | 几乎无直接证据 | 无专用工具 | 需要日志配置、告警流程和留存策略的人工审计 |
| A10 Server-Side Request Forgery | SSRF检测 | `ssrf_scan` | 仅覆盖可达输入点；禁止越权访问内网和云凭据端点 |

## 报告标注规则

漏洞条目可以标注对应的OWASP类别和CWE，例如：

```text
SQL注入 [OWASP A03:2021 Injection] [CWE-89]
```

同时必须标注覆盖状态：

- `direct_evidence`：工具直接得到可复核证据。
- `supporting_signal`：只有配置或指纹线索。
- `not_assessed`：本次扫描无法判断。

禁止用“执行过一个相关工具”推导“完整覆盖某个OWASP类别”，也不再输出缺乏评测依据的总体覆盖率百分比。
