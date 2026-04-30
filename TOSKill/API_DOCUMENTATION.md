# TOSKill API 接口文档

> 版本: v2.3.0  
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
8. [脚本管理接口](#8-脚本管理接口)
9. [错误码说明](#9-错误码说明)
10. [工具列表](#10-工具列表)
11. [认证机制](#11-认证机制)
12. [WebSocket数据传输完整性](#12-websocket数据传输完整性)
13. [记忆化机制](#13-记忆化机制)
14. [工具返回格式标准](#14-工具返回格式标准)

---

## 1. 概述

TOSKill 是一个 Web 安全扫描服务，直接调用工具集执行扫描任务，支持：

- **信息收集**: 端口扫描、子域名发现、目录扫描等
- **漏洞扫描**: SQL注入、XSS、CSRF 等常见漏洞检测
- **POC验证**: ThinkPHP RCE、Struts2、WebLogic 等漏洞验证
- **工具执行**: 支持单个或批量执行指定工具
- **动态工具**: 支持上传自定义脚本、AI生成脚本，自动注册为工具
- **意图识别**: AI智能识别用户意图，支持扫描/工具直调/聊天/脚本管理
- **实时反馈**: WebSocket实时推送工作流进度和状态
- **数据审核**: AI智能审核用户输入，自动提取关键参数
- **错误处理**: 完善的错误捕获和恢复机制

### 服务信息

| 项目 | 值 |
|------|-----|
| 服务名称 | TOSKill Security Scanner |
| 默认端口 | 8081 |
| 协议支持 | HTTP/1.1, WebSocket |
| 数据格式 | JSON |
| 内置工具数量 | 22 |
| 动态工具 | 支持无限扩展 |

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
    "tools": ["string"],          // 可选，指定工具列表，为空则使用全部工具
    "generate_report": true       // 可选，是否生成报告，默认 true
}
```

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| target | string | 是 | - | 扫描目标域名或IP |
| tools | array | 否 | 全部工具 | 指定工具名称列表 |
| generate_report | boolean | 否 | true | 是否生成扫描报告 |

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
    "tools": ["string"],          // 可选，指定工具列表
    "generate_report": true       // 可选，是否生成报告，默认 true
}
```

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| target | string | 是 | - | 扫描目标域名或IP |
| tools | array | 否 | 信息收集工具集 | 指定工具名称列表 |
| generate_report | boolean | 否 | true | 是否生成扫描报告 |

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
    "tools": ["string"],          // 可选，指定工具列表
    "generate_report": true       // 可选，是否生成报告，默认 true
}
```

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| target | string | 是 | - | 扫描目标域名或IP |
| tools | array | 否 | 漏洞扫描工具集 | 指定工具名称列表 |
| generate_report | boolean | 否 | true | 是否生成扫描报告 |

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
    "tools": ["string"],          // 可选，指定工具列表
    "generate_report": true       // 可选，是否生成报告，默认 true
}
```

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| target | string | 是 | - | 扫描目标域名或IP |
| tools | array | 否 | 全部工具 | 指定工具名称列表 |
| generate_report | boolean | 否 | true | 是否生成扫描报告 |

**响应体**

```json
{
    "code": 200,
    "message": "完整扫描完成: 19/19, 发现漏洞: 3",
    "data": {
        "session_id": "a1b2c3d4",
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
        "report_url": "/api/reports/download/scan_report_a1b2c3d4.md",
        "report_id": "scan_report_a1b2c3d4",
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
| `user_message` | 用户消息（触发意图识别） | `{content}` |
| `chat` | AI对话 | `{content}` |
| `execute_tool` | 执行工具 | `{tool_name, target}` |
| `direct_tool` | 工具直调 | `{tool_name, target}` |
| `script_content` | 脚本内容提交 | `{script_content, script_name}` |
| `script_description` | 脚本描述提交 | `{description}` |
| `upload_script` | 上传脚本请求 | `{}` |
| `generate_script` | 生成脚本请求 | `{}` |
| `input_response` | 数据输入响应 | `{field, value}` |
| `get_status` | 获取状态 | `{}` |
| `get_history` | 获取历史 | `{}` |

### 6.4 服务端消息类型

| 类型 | 说明 |
|------|------|
| `connected` | 连接成功 |
| `interaction_required` | 需要用户交互（5个选项） |
| `workflow_resumed` | 工作流已恢复 |
| `intent_recognized` | 意图识别结果 |
| `intent_validation_error` | 意图校验错误 |
| `tool_not_found` | 工具不存在 |
| `scan_started` | 扫描已开始 |
| `scan_completed` | 扫描已完成 |
| `scan_cancelled` | 扫描已取消 |
| `scan_flow_started` | 扫描流程启动 |
| `direct_tool_started` | 工具直调开始 |
| `direct_tool_completed` | 工具直调完成 |
| `direct_tool_error` | 工具直调错误 |
| `tool_execution_started` | 工具开始执行 |
| `tool_execution_completed` | 工具执行完成 |
| `script_upload_request` | 请求上传脚本 |
| `script_generate_request` | 请求生成脚本描述 |
| `script_analyzing` | AI分析脚本中 |
| `script_generating` | AI生成脚本中 |
| `script_registered` | 脚本注册成功 |
| `script_generated` | 脚本生成成功 |
| `script_error` | 脚本处理错误 |
| `ai_decision` | AI决策信息 |
| `ai_decision_complete` | AI决策完成 |
| `task_started` | 任务开始 |
| `task_completed` | 任务完成 |
| `task_error` | 任务错误 |
| `ai_chat` | AI聊天回复 |
| `report_generation_started` | 报告生成开始 |
| `report_generated` | 报告生成完成 |
| `report_error` | 报告生成错误 |
| `input_request` | 请求数据输入 |
| `input_validated` | 输入验证通过 |
| `input_validation_error` | 输入验证失败 |
| `workflow_progress` | 工作流进度更新 |
| `workflow_error` | 工作流错误 |
| `validation_started` | 数据审核开始 |
| `validation_completed` | 数据审核完成 |
| `error` | 错误消息 |

### 6.5 数据输入请求

当工作流需要用户提供关键数据时，服务端会发送 `input_request` 消息：

```json
{
    "type": "input_request",
    "payload": {
        "field": "target",
        "label": "目标网址",
        "description": "请输入要扫描的目标网址",
        "placeholder": "https://example.com",
        "required": true,
        "validation": "url_or_ip"
    }
}
```

客户端响应示例：

```json
{
    "type": "input_response",
    "payload": {
        "field": "target",
        "value": "https://example.com"
    }
}
```

### 6.6 工作流进度反馈

服务端会实时推送工作流进度：

```json
{
    "type": "workflow_progress",
    "payload": {
        "stage": "info_collection",
        "status": "running",
        "completed": 3,
        "total": 11,
        "progress_percent": 27.3,
        "current_task": "port_scan"
    }
}
```

**状态说明**:
- `pending`: 等待中
- `running`: 进行中
- `completed`: 已完成
- `error`: 出错

### 6.7 工作流错误处理

当工作流出现错误时，服务端会发送详细错误信息：

```json
{
    "type": "workflow_error",
    "payload": {
        "node": "execute_task",
        "error_type": "ConnectionError",
        "message": "无法连接到目标服务器",
        "level": "error",
        "timestamp": "2026-04-26T12:00:00",
        "suggestion": "请检查目标地址是否可达",
        "action": "retry"
    }
}
```

**错误级别**:
- `warning`: 警告，可继续执行
- `error`: 错误，需要处理
- `critical`: 严重错误，终止执行

**恢复动作**:
- `retry`: 重试
- `skip`: 跳过
- `terminate`: 终止
- `ask_user`: 询问用户

### 6.8 意图识别说明

系统支持5种意图类型：

| 意图类型 | 说明 | 触发关键词 |
|----------|------|-----------|
| `scan` | 完整扫描流程 | 扫描、漏洞、渗透、检测 |
| `tool` | 工具直调 | 调用、执行、使用工具 |
| `chat` | 纯聊天 | 咨询、问答、闲聊 |
| `upload_script` | 上传脚本 | 上传脚本、自定义脚本 |
| `generate_script` | AI生成脚本 | 生成脚本、AI写脚本 |

### 6.9 交互选项说明

扫描过程中，用户可选择5个选项：

| 选项 | 说明 |
|------|------|
| 1 | 执行当前任务 |
| 2 | 停止扫描并生成报告 |
| 3 | 与AI助手聊天 |
| 4 | 上传自定义脚本 |
| 5 | AI生成扫描脚本 |

### 6.10 连接示例

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

**响应体**

```json
{
    "success": true,
    "message": "报告已删除"
}
```

**请求示例**

```bash
curl -X DELETE "http://localhost:8081/api/reports/scan_report_20260426.md"
```

---

### 7.5 根据会话ID获取报告

**请求信息**

| 项目 | 值 |
|------|-----|
| 方法 | `GET` |
| 路径 | `/api/reports/session/{session_id}` |

**响应体**

```json
{
    "success": true,
    "report": {
        "id": "scan_report_a1b2c3d4",
        "name": "scan_report_a1b2c3d4.md",
        "size": 12345,
        "created_at": "2026-04-26T12:00:00",
        "download_url": "/api/reports/download/scan_report_a1b2c3d4.md"
    }
}
```

**请求示例**

```bash
curl -X GET "http://localhost:8081/api/reports/session/a1b2c3d4"
```

---

### 7.6 根据会话ID删除报告

**请求信息**

| 项目 | 值 |
|------|-----|
| 方法 | `DELETE` |
| 路径 | `/api/reports/session/{session_id}` |

**响应体**

```json
{
    "success": true,
    "message": "报告已删除"
}
```

**请求示例**

```bash
curl -X DELETE "http://localhost:8081/api/reports/session/a1b2c3d4"
```

---

## 8. 脚本管理接口

### 8.1 脚本上传

通过WebSocket上传自定义脚本。

**WebSocket消息**

```json
{
    "type": "upload_script",
    "payload": {}
}
```

**服务端响应**

```json
{
    "type": "script_upload_request",
    "payload": {
        "message": "请上传您的脚本文件或粘贴脚本内容"
    }
}
```

**客户端提交脚本**

```json
{
    "type": "script_content",
    "payload": {
        "script_content": "def run(target):\n    return {'success': True}",
        "script_name": "custom_scan"
    }
}
```

**脚本要求**
- 必须包含 `run(target: str)` 函数
- 返回 `Dict` 类型结果
- 建议包含错误处理

---

### 8.2 AI生成脚本

通过WebSocket让AI生成脚本。

**WebSocket消息**

```json
{
    "type": "generate_script",
    "payload": {}
}
```

**服务端响应**

```json
{
    "type": "script_generate_request",
    "payload": {
        "message": "请描述您需要的扫描脚本功能"
    }
}
```

**客户端提交描述**

```json
{
    "type": "script_description",
    "payload": {
        "description": "检测目标网站是否存在敏感文件泄露"
    }
}
```

**生成成功响应**

```json
{
    "type": "script_generated",
    "payload": {
        "tool_name": "ai_gen_20260426",
        "script_code": "def run(target):\n    ...",
        "description": "敏感文件泄露检测",
        "message": "AI脚本已生成并注册: ai_gen_20260426"
    }
}
```

---

### 8.3 动态工具列表

上传或生成的脚本会自动注册为工具，可通过工具列表API查询。

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
                "name": "custom_port_check",
                "description": "自定义端口检测",
                "category": "custom",
                "is_custom": true
            },
            {
                "name": "ai_gen_20260426",
                "description": "敏感文件泄露检测",
                "category": "custom",
                "is_custom": true
            }
        ],
        "count": 24
    }
}
```

---

### 8.4 工具存在性校验

当用户调用不存在的工具时，系统会自动进行AI模糊匹配，并返回可用选项。

**服务端消息**

```json
{
    "type": "tool_not_found",
    "payload": {
        "tool_name": "invalid_tool",
        "available_tools": ["port_scan", "sqli_scan", ...],
        "message": "工具 'invalid_tool' 不存在。您可以选择上传自定义脚本或让AI生成脚本。",
        "options": [
            {"key": "upload", "label": "上传脚本"},
            {"key": "generate", "label": "AI生成脚本"},
            {"key": "other", "label": "使用其他工具"}
        ]
    }
}
```

---

## 9. 错误码说明

### 9.1 HTTP 状态码

| 状态码 | 说明 |
|--------|------|
| 200 | 请求成功 |
| 400 | 请求参数错误 |
| 404 | 资源不存在（工具、会话、报告等） |
| 500 | 服务器内部错误 |

### 9.2 错误响应示例

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

## 10. 工具列表

### 10.1 信息收集工具 (11个)

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

### 10.2 漏洞扫描工具 (8个)

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

### 10.3 POC工具 (3个)

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
5. **实时反馈**: 通过WebSocket接收工作流进度和状态更新
6. **数据审核**: 系统会自动审核用户输入，缺失数据时会请求补充

---

## 11. 认证机制

### 11.1 概述

TOSKill 支持在工作流节点间共享认证信息，实现深度扫描。当某个工具（如弱口令扫描）成功获取认证信息后，系统会自动将其传递给后续工具使用。

### 11.2 认证信息存储结构

认证信息统一存储在会话状态的 `auth_info` 字段中：

```json
{
    "auth_info": {
        "cookies": {"session": "abc123", "token": "xyz789"},
        "headers": {"Authorization": "Bearer xxx"},
        "token": "eyJhbGciOiJIUzI1NiIs...",
        "type": "cookie",
        "source": "weakpass_scan"
    },
    "auth_timestamp": "2026-04-26T12:00:00",
    "auth_expires_at": "2026-04-26T12:30:00"
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| cookies | dict | Cookie认证信息 |
| headers | dict | HTTP头认证信息 |
| token | string | Token认证字符串 |
| type | string | 认证类型：cookie/header/token |
| source | string | 认证信息来源工具 |
| auth_timestamp | string | 认证信息获取时间 |
| auth_expires_at | string | 认证过期时间 |

### 11.3 认证参数传递

所有支持认证的漏洞扫描工具接受以下参数：

```json
{
    "target": "http://example.com",
    "cookies": {"session": "abc123"},
    "headers": {"Authorization": "Bearer xxx"},
    "auth_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

| 参数 | 类型 | 说明 |
|------|------|------|
| cookies | dict | Cookie认证，格式：`{"name": "value"}` |
| headers | dict | HTTP头认证，格式：`{"Header-Name": "value"}` |
| auth_token | string | Token认证字符串 |

### 11.4 认证过期检测

系统自动检测认证信息是否过期：

- **显式过期**：检查 `auth_expires_at` 字段
- **隐式过期**：基于 `auth_timestamp` + 默认过期时间（30分钟）

### 11.5 认证失败自动重试

当使用认证信息调用工具失败（返回401/403）时，系统会：

1. 检测认证失败响应
2. 触发重新认证流程
3. 最多重试3次
4. WebSocket 通知用户重新登录

### 11.6 多步骤认证支持

系统支持复杂的多步骤认证场景：

| 认证类型 | 说明 |
|---------|------|
| CSRF Token | 自动获取表单中的隐藏字段 |
| 登录表单 | 支持自定义字段名和额外数据 |
| 验证码 | 预留接口，支持注册处理器 |

### 11.7 认证状态 WebSocket 通知

| 消息类型 | 说明 |
|---------|------|
| `auth_info_obtained` | 认证信息获取成功 |
| `auth_expired` | 认证已过期 |
| `auth_refresh_required` | 需要刷新认证 |
| `auth_refresh_success` | 认证刷新成功 |
| `auth_expiring_soon` | 认证即将过期（<5分钟） |
| `auth_retry_exhausted` | 重试次数耗尽 |

---

## 12. WebSocket数据传输完整性

### 12.1 标准消息格式

所有 WebSocket 消息采用统一格式：

```json
{
    "message_id": "550e8400-e29b-41d4-a716-446655440000",
    "timestamp": "2026-04-26T12:00:00.000Z",
    "message_type": "task_completed",
    "message_hash": "a1b2c3d4e5f6g7h8",
    "payload": { ... }
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| message_id | string | 消息唯一标识（UUID格式） |
| timestamp | string | 消息时间戳（ISO格式） |
| message_type | string | 消息类型 |
| message_hash | string | 消息哈希值（SHA256前16位） |
| payload | object | 消息内容 |

### 12.2 消息确认机制

客户端收到消息后应发送确认：

```json
{
    "type": "message_ack",
    "payload": {
        "message_id": "550e8400-e29b-41d4-a716-446655440000"
    }
}
```

### 12.3 消息重传功能

客户端可请求重传消息：

```json
{
    "type": "message_retransmit",
    "payload": {
        "message_id": "550e8400-e29b-41d4-a716-446655440000"
    }
}
```

或批量重传最近N条消息：

```json
{
    "type": "message_retransmit",
    "payload": {
        "count": 10
    }
}
```

### 12.4 数据完整性校验

客户端可验证消息完整性：

```json
{
    "type": "verify_message",
    "payload": {
        "message_id": "550e8400-e29b-41d4-a716-446655440000",
        "message_hash": "a1b2c3d4e5f6g7h8"
    }
}
```

服务端响应：

```json
{
    "type": "message_verification_result",
    "payload": {
        "message_id": "550e8400-e29b-41d4-a716-446655440000",
        "valid": true
    }
}
```

### 12.5 task_completed 消息结构

工具执行完成消息包含分离的原始数据和AI分析：

```json
{
    "type": "task_completed",
    "payload": {
        "tool": "sqli_scan",
        "target": "http://example.com",
        "raw_result": {
            "vulnerable": true,
            "injection_type": "Boolean-based",
            "injection_point": "id parameter",
            "db_type": "MySQL"
        },
        "analysis": "检测到SQL注入漏洞，类型为布尔盲注，位于id参数",
        "vulnerable": true,
        "auth_obtained": false,
        "timestamp": "2026-04-26T12:00:00"
    }
}
```

---

## 13. 记忆化机制

### 13.1 会话存储

系统使用 `MemoryStore` 管理会话状态：

| 存储内容 | 说明 |
|---------|------|
| 会话状态 | ScanState 完整状态 |
| 聊天历史 | 每个会话的聊天记录 |
| 待处理交互 | 等待用户响应的交互请求 |
| WebSocket回调 | 实时推送函数 |

### 13.2 TTL过期清理

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| 会话TTL | 3600秒 (1小时) | 会话过期时间 |
| 清理间隔 | 600秒 (10分钟) | 定时清理检查间隔 |

过期会话自动清理，包括：
- 会话状态
- 聊天历史
- WebSocket回调
- 待处理交互

### 13.3 数据冗余合并

当同一会话存在重复数据时，系统自动合并去重：
- 按时间戳去重
- 保留最新数据
- 合并后按时间戳排序

### 13.4 聊天历史自动清理

每个会话最多保留100条聊天记录，超出时自动删除最早的记录。

### 13.5 存储状态监控接口

可通过 WebSocket 获取存储统计：

```json
{
    "type": "get_storage_stats",
    "payload": {}
}
```

响应：

```json
{
    "type": "storage_stats",
    "payload": {
        "sessions": {
            "total": 5,
            "active_websocket": 3,
            "pending_interactions": 1
        },
        "chat_history": {
            "total_messages": 150,
            "avg_per_session": 30
        },
        "memory": {
            "estimated_bytes": 1048576,
            "estimated_mb": 1.0
        }
    }
}
```

---

## 14. 工具返回格式标准

### 14.1 ToolResult 标准格式

所有工具返回统一格式：

```json
{
    "success": true,
    "data": {
        "vulnerable": false,
        "results": [...]
    },
    "error": null,
    "auth_info": null,
    "timestamp": "2026-04-26T12:00:00.000Z"
}
```

| 字段 | 类型 | 必需 | 说明 |
|------|------|------|------|
| success | boolean | 是 | 执行是否成功 |
| data | object | 是 | 返回数据 |
| error | string\|null | 否 | 错误信息 |
| auth_info | object\|null | 否 | 认证信息 |
| timestamp | string | 是 | 时间戳（ISO格式） |

### 14.2 成功响应示例

```json
{
    "success": true,
    "data": {
        "open_ports": [22, 80, 443],
        "scan_time": 2.5
    },
    "error": null,
    "auth_info": null,
    "timestamp": "2026-04-26T12:00:00.000Z"
}
```

### 14.3 失败响应示例

```json
{
    "success": false,
    "data": {},
    "error": "连接超时：目标服务器无响应",
    "auth_info": null,
    "timestamp": "2026-04-26T12:00:00.000Z"
}
```

### 14.4 包含认证信息的响应

```json
{
    "success": true,
    "data": {
        "weak_accounts": [{"username": "admin", "password": "admin123"}]
    },
    "error": null,
    "auth_info": {
        "cookies": {"session": "abc123"},
        "type": "cookie",
        "source": "weakpass_scan"
    },
    "timestamp": "2026-04-26T12:00:00.000Z"
}
```

### 14.5 格式验证

系统提供 `validate_tool_result()` 函数验证返回格式：

```python
from TOSKill.AI.tools import validate_tool_result

result = {"success": True, "data": {}, "timestamp": "..."}
is_valid = validate_tool_result(result)  # True/False
```

---

*文档版本: 2.3.0 | 最后更新: 2026-04-26*
