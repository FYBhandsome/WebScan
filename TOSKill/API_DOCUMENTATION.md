# TOSKill API 接口文档

> 版本: v2.0.0  
> 基础地址: `http://localhost:8081`  
> 更新日期: 2026-04-26

---

## 目录

1. [概述](#1-概述)
2. [通用说明](#2-通用说明)
3. [扫描接口](#3-扫描接口)
4. [工具执行接口](#4-工具执行接口)
5. [会话管理接口](#5-会话管理接口)
6. [WebSocket API 接口](#6-websocket-api-接口)
7. [报告管理接口](#7-报告管理接口)
8. [错误码说明](#8-错误码说明)
9. [工具列表](#9-工具列表)

---

## 1. 概述

TOSKill 是一个 Web 安全扫描服务，直接调用工具集执行扫描任务，支持：

- **信息收集**: 端口扫描、子域名发现、目录扫描等
- **漏洞扫描**: SQL注入、XSS、CSRF 等常见漏洞检测
- **POC验证**: ThinkPHP RCE、Struts2、WebLogic 等漏洞验证
- **工具执行**: 支持单个或批量执行指定工具

### 服务信息

| 项目 | 值 |
|------|-----|
| 服务名称 | TOSKill Security Scanner |
| 默认端口 | 8081 |
| 协议支持 | HTTP/1.1, WebSocket |
| 数据格式 | JSON |
| 工具数量 | 22 |

---

## 2. 通用说明

### 2.1 请求头

所有 REST API 请求应包含以下请求头：

```
Content-Type: application/json
Accept: application/json
```

### 2.2 统一响应格式

所有 REST API 响应采用统一的 JSON 格式：

```json
{
    "code": 200,
    "message": "success",
    "data": { ... }
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| code | integer | 状态码，200 表示成功 |
| message | string | 响应消息 |
| data | object | 响应数据，可能为 null |

### 2.3 错误响应格式

当请求失败时，返回格式如下：

```json
{
    "detail": "错误描述信息"
}
```

---

## 3. 扫描接口

### 3.1 通用扫描

执行扫描任务，可指定工具列表或使用全部工具。

**请求信息**

| 项目 | 值 |
|------|-----|
| 方法 | `POST` |
| 路径 | `/api/toskill/scan` |
| Content-Type | `application/json` |

**请求体**

```json
{
    "target": "string",           // 必填，扫描目标
    "tools": ["string"]           // 可选，指定工具列表，为空则使用全部工具
}
```

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| target | string | 是 | 扫描目标域名或IP |
| tools | array | 否 | 指定工具名称列表，为空则执行所有工具 |

**响应体**

```json
{
    "code": 200,
    "message": "扫描完成: 20/22 工具执行成功",
    "data": {
        "target": "example.com",
        "total_tools": 22,
        "success_count": 20,
        "error_count": 2,
        "results": [
            {
                "tool": "port_scan",
                "success": true,
                "result": { ... },
                "timestamp": "2026-04-26T12:00:00"
            }
        ],
        "timestamp": "2026-04-26T12:05:00"
    }
}
```

**请求示例**

```bash
curl -X POST "http://localhost:8081/api/toskill/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "tools": ["port_scan", "subdomain_scan", "sqli_scan"]
  }'
```

---

### 3.2 信息收集扫描

执行信息收集工具集。

**请求信息**

| 项目 | 值 |
|------|-----|
| 方法 | `POST` |
| 路径 | `/api/toskill/scan/info` |
| Content-Type | `application/json` |

**请求体**

```json
{
    "target": "string",           // 必填，扫描目标
    "tools": ["string"]           // 可选，指定工具列表
}
```

**响应体**

```json
{
    "code": 200,
    "message": "信息收集完成: 11/11",
    "data": {
        "target": "example.com",
        "scan_type": "info_collection",
        "tools_used": ["baseinfo_scan", "port_scan", ...],
        "results": [ ... ],
        "timestamp": "2026-04-26T12:00:00"
    }
}
```

**请求示例**

```bash
curl -X POST "http://localhost:8081/api/toskill/scan/info" \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'
```

---

### 3.3 漏洞扫描

执行漏洞扫描工具集。

**请求信息**

| 项目 | 值 |
|------|-----|
| 方法 | `POST` |
| 路径 | `/api/toskill/scan/vuln` |
| Content-Type | `application/json` |

**请求体**

```json
{
    "target": "string",           // 必填，扫描目标
    "tools": ["string"]           // 可选，指定工具列表
}
```

**响应体**

```json
{
    "code": 200,
    "message": "漏洞扫描完成: 8/8, 发现漏洞: 2",
    "data": {
        "target": "example.com",
        "scan_type": "vuln_scan",
        "tools_used": ["sqli_scan", "xss_scan", ...],
        "vulnerabilities_found": 2,
        "results": [ ... ],
        "timestamp": "2026-04-26T12:00:00"
    }
}
```

**请求示例**

```bash
curl -X POST "http://localhost:8081/api/toskill/scan/vuln" \
  -H "Content-Type: application/json" \
  -d '{"target": "http://example.com"}'
```

---

### 3.4 完整扫描

执行所有工具（信息收集 + 漏洞扫描）。

**请求信息**

| 项目 | 值 |
|------|-----|
| 方法 | `POST` |
| 路径 | `/api/toskill/scan/full` |
| Content-Type | `application/json` |

**请求体**

```json
{
    "target": "string",           // 必填，扫描目标
    "tools": ["string"]           // 可选，指定工具列表
}
```

**响应体**

```json
{
    "code": 200,
    "message": "完整扫描完成: 19/19, 发现漏洞: 3",
    "data": {
        "target": "example.com",
        "scan_type": "full_scan",
        "info_collection": {
            "tools_count": 11,
            "results": [ ... ]
        },
        "vuln_scan": {
            "tools_count": 8,
            "vulnerabilities_found": 3,
            "results": [ ... ]
        },
        "timestamp": "2026-04-26T12:00:00"
    }
}
```

**请求示例**

```bash
curl -X POST "http://localhost:8081/api/toskill/scan/full" \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'
```

---

## 4. 工具执行接口

### 4.1 获取工具列表

获取所有可用工具列表。

**请求信息**

| 项目 | 值 |
|------|-----|
| 方法 | `GET` |
| 路径 | `/api/toskill/tools` |

**响应体**

```json
{
    "code": 200,
    "message": "success",
    "data": {
        "tools": [
            {
                "name": "port_scan",
                "description": "端口扫描 - 扫描目标开放端口",
                "category": "info_collection"
            },
            {
                "name": "sqli_scan",
                "description": "SQL注入扫描 - 检测SQL注入漏洞",
                "category": "vuln_scan"
            }
        ],
        "count": 22
    }
}
```

**请求示例**

```bash
curl -X GET "http://localhost:8081/api/toskill/tools"
```

---

### 4.2 获取工具分类

获取按类别分组的工具列表。

**请求信息**

| 项目 | 值 |
|------|-----|
| 方法 | `GET` |
| 路径 | `/api/toskill/tools/categories` |

**响应体**

```json
{
    "code": 200,
    "message": "success",
    "data": {
        "info_collection": ["baseinfo_scan", "port_scan", ...],
        "vuln_scan": ["sqli_scan", "xss_scan", ...],
        "poc": ["thinkphp_rce_scan", "struts2_scan", ...],
        "all": ["baseinfo_scan", "port_scan", ...]
    }
}
```

**请求示例**

```bash
curl -X GET "http://localhost:8081/api/toskill/tools/categories"
```

---

### 4.3 获取工具详情

获取单个工具的详细信息。

**请求信息**

| 项目 | 值 |
|------|-----|
| 方法 | `GET` |
| 路径 | `/api/toskill/tools/{tool_name}` |

**路径参数**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| tool_name | string | 是 | 工具名称 |

**响应体**

```json
{
    "code": 200,
    "message": "success",
    "data": {
        "name": "port_scan",
        "description": "端口扫描 - 扫描目标开放端口",
        "category": "info_collection"
    }
}
```

**请求示例**

```bash
curl -X GET "http://localhost:8081/api/toskill/tools/port_scan"
```

---

### 4.4 执行单个工具

执行指定的安全工具。

**请求信息**

| 项目 | 值 |
|------|-----|
| 方法 | `POST` |
| 路径 | `/api/toskill/tools/execute` |
| Content-Type | `application/json` |

**请求体**

```json
{
    "tool_name": "string",        // 必填，工具名称
    "target": "string",           // 必填，扫描目标
    "params": {}                  // 可选，工具参数
}
```

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| tool_name | string | 是 | 工具名称，如 `port_scan` |
| target | string | 是 | 扫描目标 |
| params | object | 否 | 工具额外参数 |

**响应体**

```json
{
    "code": 200,
    "message": "工具执行完成",
    "data": {
        "tool": "port_scan",
        "success": true,
        "result": {
            "open_ports": [22, 80, 443],
            "scan_time": 2.5
        },
        "timestamp": "2026-04-26T12:00:00"
    }
}
```

**请求示例**

```bash
curl -X POST "http://localhost:8081/api/toskill/tools/execute" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "port_scan",
    "target": "example.com"
  }'
```

---

### 4.5 批量执行工具

批量执行多个工具，支持并行或顺序执行。

**请求信息**

| 项目 | 值 |
|------|-----|
| 方法 | `POST` |
| 路径 | `/api/toskill/tools/execute/batch` |
| Content-Type | `application/json` |

**请求体**

```json
{
    "tool_names": ["string"],     // 必填，工具名称列表
    "target": "string",           // 必填，扫描目标
    "parallel": true              // 可选，是否并行执行，默认 true
}
```

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| tool_names | array | 是 | - | 工具名称数组 |
| target | string | 是 | - | 扫描目标 |
| parallel | boolean | 否 | true | 是否并行执行 |

**响应体**

```json
{
    "code": 200,
    "message": "批量执行完成: 3/3",
    "data": {
        "target": "example.com",
        "tools": ["port_scan", "subdomain_scan", "dir_brute"],
        "total": 3,
        "success_count": 3,
        "results": [ ... ]
    }
}
```

**请求示例**

```bash
curl -X POST "http://localhost:8081/api/toskill/tools/execute/batch" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_names": ["port_scan", "subdomain_scan", "dir_brute"],
    "target": "example.com",
    "parallel": true
  }'
```

---

## 5. 会话管理接口

### 5.1 创建会话

创建一个新的扫描会话。

**请求信息**

| 项目 | 值 |
|------|-----|
| 方法 | `POST` |
| 路径 | `/api/toskill/sessions` |
| Content-Type | `application/json` |

**请求体**

```json
{
    "target": "string",           // 可选，扫描目标
    "tools": ["string"]           // 可选，工具列表
}
```

**响应体**

```json
{
    "code": 200,
    "message": "会话创建成功",
    "data": {
        "session_id": "a1b2c3d4"
    }
}
```

**请求示例**

```bash
curl -X POST "http://localhost:8081/api/toskill/sessions" \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'
```

---

### 5.2 获取会话状态

获取指定会话的当前状态。

**请求信息**

| 项目 | 值 |
|------|-----|
| 方法 | `GET` |
| 路径 | `/api/toskill/sessions/{session_id}` |

**响应体**

```json
{
    "code": 200,
    "message": "success",
    "data": {
        "target": "example.com",
        "tools": ["port_scan", "sqli_scan", ...],
        "status": "created",
        "created_at": "2026-04-26T12:00:00"
    }
}
```

**请求示例**

```bash
curl -X GET "http://localhost:8081/api/toskill/sessions/a1b2c3d4"
```

---

### 5.3 删除会话

删除指定的会话。

**请求信息**

| 项目 | 值 |
|------|-----|
| 方法 | `DELETE` |
| 路径 | `/api/toskill/sessions/{session_id}` |

**响应体**

```json
{
    "code": 200,
    "message": "会话删除成功",
    "data": null
}
```

**请求示例**

```bash
curl -X DELETE "http://localhost:8081/api/toskill/sessions/a1b2c3d4"
```

---

### 5.4 健康检查

检查 API 服务是否正常运行。

**请求信息**

| 项目 | 值 |
|------|-----|
| 方法 | `GET` |
| 路径 | `/api/toskill/health` |

**响应体**

```json
{
    "code": 200,
    "message": "TOSKill API 服务正常",
    "data": {
        "status": "healthy",
        "timestamp": "2026-04-26T12:00:00",
        "tools_count": 22,
        "available_tools": ["baseinfo_scan", "port_scan", ...]
    }
}
```

**请求示例**

```bash
curl -X GET "http://localhost:8081/api/toskill/health"
```

---

## 6. WebSocket API 接口

### 6.1 连接信息

| 项目 | 值 |
|------|-----|
| 端点 | `ws://localhost:8081/api/ai-chat/ws` |
| 协议 | WebSocket |
| 数据格式 | JSON |

### 6.2 消息格式

所有消息采用统一的 JSON 格式：

```json
{
    "type": "message_type",
    "payload": { ... }
}
```

### 6.3 客户端消息类型

| 类型 | 说明 | payload |
|------|------|---------|
| `start_scan` | 开始扫描 | `{target, scan_mode}` |
| `stop_scan` | 停止扫描 | `{}` |
| `user_choice` | 用户选择 | `{choice}` |
| `chat` | AI对话 | `{content}` |
| `execute_tool` | 执行工具 | `{tool_name, target}` |
| `get_status` | 获取状态 | `{}` |
| `get_history` | 获取历史 | `{}` |

### 6.4 服务端消息类型

| 类型 | 说明 |
|------|------|
| `connected` | 连接成功 |
| `interaction_required` | 需要用户交互 |
| `workflow_resumed` | 工作流已恢复 |
| `scan_started` | 扫描已开始 |
| `scan_completed` | 扫描已完成 |
| `scan_cancelled` | 扫描已取消 |
| `tool_execution_started` | 工具开始执行 |
| `tool_execution_completed` | 工具执行完成 |
| `ai_message` | AI回复消息 |
| `error` | 错误消息 |

### 6.5 连接示例

```javascript
const ws = new WebSocket('ws://localhost:8081/api/ai-chat/ws');

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    
    if (data.type === 'interaction_required') {
        // 显示交互选项按钮
        showInteractionButtons(data.payload);
    }
};

// 发送扫描请求
ws.send(JSON.stringify({
    type: 'start_scan',
    payload: { target: 'example.com', scan_mode: 'full' }
}));

// 发送用户选择
ws.send(JSON.stringify({
    type: 'user_choice',
    payload: { choice: '1' }
}));
```

---

## 7. 报告管理接口

### 7.1 获取报告列表

**请求信息**

| 项目 | 值 |
|------|-----|
| 方法 | `GET` |
| 路径 | `/api/reports/list` |

**响应体**

```json
{
    "success": true,
    "reports": [
        {
            "id": "scan_report_20260426",
            "name": "scan_report_20260426.md",
            "size": 12345,
            "created_at": "2026-04-26T12:00:00",
            "download_url": "/api/reports/download/scan_report_20260426.md"
        }
    ],
    "total": 1
}
```

**请求示例**

```bash
curl -X GET "http://localhost:8081/api/reports/list"
```

---

### 7.2 下载报告

**请求信息**

| 项目 | 值 |
|------|-----|
| 方法 | `GET` |
| 路径 | `/api/reports/download/{filename}` |

**请求示例**

```bash
curl -X GET "http://localhost:8081/api/reports/download/scan_report_20260426.md" -o report.md
```

---

### 7.3 获取报告内容

**请求信息**

| 项目 | 值 |
|------|-----|
| 方法 | `GET` |
| 路径 | `/api/reports/{filename}/content` |

**响应体**

```json
{
    "success": true,
    "filename": "scan_report_20260426.md",
    "content": "# 安全扫描报告\n\n..."
}
```

**请求示例**

```bash
curl -X GET "http://localhost:8081/api/reports/scan_report_20260426.md/content"
```

---

### 7.4 删除报告

**请求信息**

| 项目 | 值 |
|------|-----|
| 方法 | `DELETE` |
| 路径 | `/api/reports/{filename}` |

**请求示例**

```bash
curl -X DELETE "http://localhost:8081/api/reports/scan_report_20260426.md"
```

---

## 8. 错误码说明

### 8.1 HTTP 状态码

| 状态码 | 说明 |
|--------|------|
| 200 | 请求成功 |
| 400 | 请求参数错误 |
| 404 | 资源不存在（工具、会话、报告等） |
| 500 | 服务器内部错误 |

### 8.2 错误响应示例

**参数错误**

```json
{
    "detail": "扫描目标不能为空"
}
```

**工具不存在**

```json
{
    "detail": "工具 invalid_tool 不存在"
}
```

---

## 9. 工具列表

### 9.1 信息收集工具 (11个)

| 工具名称 | 说明 |
|----------|------|
| `baseinfo_scan` | 基础信息收集 |
| `port_scan` | 端口扫描 |
| `subdomain_scan` | 子域名扫描 |
| `dir_brute` | 目录扫描 |
| `waf_detect_scan` | WAF检测 |
| `cdn_detect_scan` | CDN检测 |
| `cms_detect_scan` | CMS识别 |
| `infoleak_scan` | 信息泄露扫描 |
| `ip_locate_scan` | IP定位 |
| `webside_query_scan` | 备案查询 |
| `web_weight_scan` | 权重查询 |

### 9.2 漏洞扫描工具 (8个)

| 工具名称 | 说明 |
|----------|------|
| `sqli_scan` | SQL注入扫描 |
| `xss_scan` | XSS扫描 |
| `csrf_scan` | CSRF扫描 |
| `fileupload_scan` | 文件上传扫描 |
| `cmdi_scan` | 命令注入扫描 |
| `ssrf_scan` | SSRF扫描 |
| `lfi_scan` | LFI扫描 |
| `weakpass_scan` | 弱口令扫描 |

### 9.3 POC工具 (3个)

| 工具名称 | 说明 |
|----------|------|
| `thinkphp_rce_scan` | ThinkPHP RCE检测 |
| `struts2_scan` | Struts2漏洞检测 |
| `weblogic_scan` | WebLogic漏洞检测 |

---

## 附录

### A. 扫描模式说明

| 模式 | 端点 | 工具数量 |
|------|------|---------|
| 信息收集 | `/scan/info` | 11 |
| 漏洞扫描 | `/scan/vuln` | 8 |
| 完整扫描 | `/scan/full` | 19 |
| 自定义 | `/scan` | 指定工具 |

### B. 执行模式说明

| 模式 | 说明 |
|------|------|
| 并行执行 | 多个工具同时执行，速度快 |
| 顺序执行 | 工具按顺序执行，便于调试 |

### C. 最佳实践

1. **工具选择**: 根据目标类型选择合适的工具集
2. **并行执行**: 大多数场景使用并行执行提高效率
3. **错误处理**: 检查响应中的 `success` 字段判断执行结果
4. **超时设置**: 扫描接口可能需要较长时间，建议设置 300 秒超时

---

*文档版本: 2.0.0 | 最后更新: 2026-04-26*
