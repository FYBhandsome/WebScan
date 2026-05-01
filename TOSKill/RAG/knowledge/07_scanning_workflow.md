# Web安全扫描工作流（Scanning Workflow）

## 标准扫描流程

### Phase 1: 信息收集（Recon）
**目的**: 了解目标攻击面，指导后续漏洞扫描策略

1. 基础信息收集（baseinfo）: HTTP头、服务器类型、SSL证书
2. CMS/框架识别（whatcms）: 确定技术栈
3. CDN检测（cdnexist）: 判断是否有CDN，决定是否需要绕过
4. WAF检测（waf）: 了解防护策略，调整Payload策略
5. 子域名扫描（subdomain）: 扩大攻击面
6. 端口扫描（portscan）: 发现非Web服务
7. 目录扫描（dirscan）: 发现隐藏路径、备份文件
8. 信息泄露（infoleak）: 敏感文件泄露检测

### Phase 2: 漏洞扫描（Vulnerability Assessment）
**目的**: 发现Web应用层漏洞

1. **快速扫描(fast)**: XSS + SQL注入（应急/初筛）
2. **深度扫描(deep)**: 全部8项漏洞检测
3. **完整扫描(full)**: Phase1全部 + Phase2深度

### Phase 3: 结果分析（Analysis）
1. 聚类去重: 同类型漏洞合并
2. 严重等级排序: 按CVSS/Critical排序
3. 关联分析: 端口暴露 + 弱口令 = 高危
4. 攻击链: 信息泄露 → SQL注入 → 数据脱库

### Phase 4: 报告生成（Reporting）
1. 摘要: 发现漏洞总数、等级分布
2. 详情: 每个漏洞的技术细节、证据
3. 修复建议: 针对性的修复方案
4. OWASP/CWE映射: 对接国际标准

---

## Agent 决策流程图

```
用户输入
    │
    ├── "快速" / "简单" → [web_vuln_scan mode=fast]
    │
    ├── "深度" / "全面" → [web_vuln_scan mode=deep]
    │
    ├── "完整" / "全" / "渗透测试" → 
    │        [info_collection tools=all]
    │        → [web_vuln_scan mode=deep]
    │
    ├── "先收集信息" / "信息收集" →
    │        [info_collection]
    │        → 询问是否继续漏洞扫描
    │
    ├── "只扫XSS" / "SQL注入" →
    │        单独调用指定工具
    │
    └── 非法目标（内网/无http）→ 
            拒绝执行 + 给出原因
```

---

## 并发与限速策略

### 线程建议
| 目标类型 | 建议线程 | 延迟(ms) |
|----------|----------|----------|
| 高性能服务器 | 8-10 | 100 |
| 普通Web站点 | 5 | 200 |
| 老旧/低配 | 2-3 | 500 |
| 有WAF防护 | 1-2 | 1000 |
| CDN站点 | 1 | 1500 |

### 注意事项
1. 高并发可能触发WAF封禁IP
2. 时间盲注需要单线程稳定测试
3. 文件上传爆破使用低频、长间隔
4. 短时间内大量404请求会被标记为恶意

---

## 扫描安全规则（Guardrails）

### 禁止扫描目标
1. 非 http/https 的URL
2. 内网地址: 192.168.x.x, 10.x.x.x, 172.16-31.x.x, 127.x.x.x
3. 政府网站: .gov.cn, .mil.cn（未授权）
4. 金融核心系统: 需书面授权
5. 关键基础设施: 电力、水利、交通

### 必须检查
1. URL格式合法性（urlparse解析）
2. 目标可达性（DNS解析+HTTP可达）
3. 扫描授权确认

### 运行时保护
1. 单次扫描超时保护（默认5分钟）
2. 请求速率限制（避免DDoS效果）
3. 异常恢复（单工具失败不影响整体）
4. 日志完整记录（审计追溯）

---

## 输出格式规范

### JSON输出结构
```json
{
  "success": true/false,
  "target": "目标URL",
  "mode": "扫描模式",
  "scan_start": "ISO时间戳",
  "total_vulnerabilities": 0,
  "tool_results": {
    "工具名": {工具返回的完整结果}
  },
  "summary": {
    "vulnerabilities_found": 0,
    "severity_breakdown": {"critical":0, "high":0, "medium":0, "low":0},
    "tools_executed": 0,
    "tools_succeeded": 0,
    "all_vulnerabilities": [...]
  }
}
```

### 漏洞条目规范
```json
{
  "vuln_type": "漏洞类型",
  "url": "漏洞URL",
  "severity": "严重等级",
  "title": "漏洞标题",
  "description": "详细描述",
  "parameter": "漏洞参数",
  "method": "HTTP方法",
  "payload": "攻击Payload",
  "evidence": "漏洞证据",
  "confidence": "置信度",
  "cwe_id": "CWE编号",
  "cvss_score": 0.0,
  "solution": "修复建议"
}
```
