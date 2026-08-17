# TOSKill 工具目录与扫描模式映射

> 状态：当前有效
> 事实来源：`AI/tools.py` 中的 `INFO_COLLECTION_TOOLS`、`VULN_SCAN_TOOLS` 和 `TOOL_SEQUENCE_*`
> 适用范围：新版 TOSKill
> 最后复核：2026-08-14

本文档记录智能体可调用的系统扫描工具。工具增删或重命名时，应先修改代码注册表，再同步更新本文档并执行知识库一致性测试。

## 一、名称使用规则

- “可调用名称”是智能体、WebSocket事件和扫描状态中必须使用的名称。
- “底层实现”仅用于开发定位，不得作为智能体调用名称。
- 历史名称只允许用于读取旧报告，不得用于新任务计划。

| 历史名称 | 当前可调用名称 |
|---|---|
| `dir_scan`、`dirscan` | `dir_brute` |
| `waf_detect` | `waf_detect_scan` |
| `cdn_detect` | `cdn_detect_scan` |
| `cms_detect`、`whatcms_scan` | `cms_detect_scan` |

## 二、信息收集工具（15个）

| 可调用名称 | 主要输出 | 决策用途 |
|---|---|---|
| `baseinfo_scan` | HTTP基础信息、技术栈线索 | 建立目标基线 |
| `port_scan` | 开放端口、服务指纹 | 识别暴露面 |
| `subdomain_scan` | 子域名与解析结果 | 补充授权范围内资产 |
| `dir_brute` | 可访问目录和文件 | 发现公开暴露面 |
| `waf_detect_scan` | WAF识别结果 | 调整请求频率并解释拦截结果 |
| `cdn_detect_scan` | CDN使用情况 | 解释解析与源站差异，不用于绕过防护 |
| `cms_detect_scan` | CMS或框架指纹 | 选择适用检测项 |
| `infoleak_scan` | 敏感信息泄露线索 | 形成信息泄露证据 |
| `ip_locate_scan` | IP地区和运营商信息 | 辅助确认资产归属 |
| `webside_query_scan` | ICP备案或站点主体信息 | 辅助确认站点归属；外部数据源失败不代表目标异常 |
| `web_weight_scan` | 公开搜索权重信息 | 辅助判断站点影响面，不作为漏洞证据 |
| `crawler_scan` | 链接、表单、参数、脚本和站点地图 | 为后续Web检测提供入口 |
| `tls_certificate_scan` | TLS协议、证书主体、签发者、有效期和SAN | 识别传输与证书配置线索 |
| `http_methods_scan` | HTTP方法、状态码、重定向和服务标识 | 识别危险方法和异常暴露 |
| `public_metadata_scan` | robots.txt、sitemap.xml、security.txt | 收集公开元数据和披露入口 |

## 三、漏洞扫描工具（11个）

| 可调用名称 | 检测范围 | 常用标准映射 | 结果边界 |
|---|---|---|---|
| `sqli_scan` | SQL注入 | CWE-89、OWASP A03 | 需保留参数、请求和响应证据 |
| `xss_scan` | 跨站脚本 | CWE-79、OWASP A03 | 反射不等于可执行，需验证上下文 |
| `csrf_scan` | CSRF防护缺陷 | CWE-352、OWASP A01 | 需结合敏感操作与会话条件判断 |
| `fileupload_scan` | 文件上传安全缺陷 | CWE-434 | 只做非破坏性验证，不写入可执行后门 |
| `cmdi_scan` | OS命令注入 | CWE-77、CWE-78、OWASP A03 | 使用无害探针并保留时延或响应证据 |
| `ssrf_scan` | 服务端请求伪造 | CWE-918、OWASP A10 | 禁止越出授权范围访问内网或云凭据端点 |
| `lfi_scan` | 本地文件包含、路径遍历 | CWE-22、CWE-98、OWASP A01 | 使用最小化、非敏感验证目标 |
| `weakpass_scan` | 默认口令和弱口令 | CWE-521、OWASP A07 | 必须限速并遵守账户锁定策略 |
| `http_security_headers_scan` | 缺失或不安全的HTTP响应头 | OWASP A05 | 属于配置证据，不等同于已被利用漏洞 |
| `cookie_security_scan` | Secure、HttpOnly、SameSite属性 | OWASP A05/A07 | 结合Cookie用途和传输环境判断 |
| `cors_misconfiguration_scan` | 凭证型任意Origin反射 | CWE-942、OWASP A05 | 仅报告高置信度配置，需确认敏感响应可读 |

## 四、扫描模式

### POC验证工具（3个）

| 可调用名称 | 适用条件 | 执行边界 |
|---|---|---|
| `thinkphp_rce_scan` | 已确认目标使用可能受影响的ThinkPHP版本 | 仅进行非破坏性验证，不自动加入全扫描计划 |
| `struts2_scan` | 已确认目标使用可能受影响的Struts2版本 | 仅进行非破坏性验证，不自动加入全扫描计划 |
| `weblogic_scan` | 已确认目标暴露可能受影响的WebLogic服务 | 仅进行非破坏性验证，不自动加入全扫描计划 |

POC工具属于注册工具，但不包含在默认26个信息收集/漏洞扫描工具序列中。只有目标指纹、版本线索、授权范围和用户意图均满足时才可执行。

### 全自动扫描模式

| 前端值 | 后端模式 | 工具范围 |
|---|---|---|
| `info` | `info_collection` | 15个信息收集工具 |
| `vuln` | `vuln_scan` | 11个漏洞扫描工具 |
| `full` | `full_scan` | 先信息收集，再漏洞扫描，共26个系统工具 |

### 人机交互式策略标签

`fast`、`deep`、`full` 是智能决策阶段的策略标签，不是全自动扫描API的 `scan_mode` 值：

- `fast`：优先执行 `xss_scan`、`sqli_scan`。
- `deep`：执行核心8项Web漏洞检测。
- `full`：按当前工作流执行信息收集和漏洞扫描。

不得生成不存在的 `web_vuln_scan` 调用。用户指定单个工具时，应直接使用该工具的当前可调用名称。

## 五、执行边界

- 仅扫描用户明确授权且处于约定范围内的目标。
- 信息收集结果是线索，不应自动解释为漏洞。
- 漏洞结论必须包含可复核证据；超时、拦截或数据源不可用不得记为漏洞。
- 不得把“工具执行成功”解释为“目标符合安全或合规要求”。
- 涉及认证尝试、写操作、内网访问或防护绕过时，应由运行时策略单独授权，不得仅凭RAG文本决定执行。
