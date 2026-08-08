# TOSKill API 接口文档

> 版本: v1.0.0\
> 基础地址: `http://localhost:8081`\
> 更新日期: 2026-05-01

***

## 目录

1. [概述](#1-概述)
2. [通用说明](#2-通用说明)
3. [扫描接口](#3-扫描接口)
4. [工具执行接口](#4-工具执行接口)
5. [会话管理接口](#5-会话管理接口)
6. [WebSocket API 接口](#6-websocket-api-接口)
7. [报告管理接口](#7-报告管理接口)
8. [脚本管理接口](#8-脚本管理接口)
9. [聊天兼容接口](#9-聊天兼容接口)
10. [错误码说明](#10-错误码说明)
11. [工具列表](#11-工具列表)
12. [认证机制](#12-认证机制)
13. [RAG知识库](#13-rag知识库)
14. [用户交互机制](#14-用户交互机制)
15. [记忆化机制](#15-记忆化机制)
16. [工具返回格式标准](#16-工具返回格式标准)
17. [意图识别机制](#17-意图识别机制)

***

## 1. 概述

TOSKill 是重构版的AI驱动Web安全扫描后端服务，基于LangGraph工作流引擎构建，支持：

- **信息收集**: 端口扫描、子域名发现、目录扫描等
- **漏洞扫描**: SQL注入、XSS、CSRF等常见漏洞检测
- **POC验证**: ThinkPHP RCE、Struts2、WebLogic等漏洞验证
- **工具执行**: 支持单个或批量执行指定工具
- **动态工具**: 支持上传自定义脚本、AI生成脚本，自动注册为工具
- **RAG知识库**: LlamaIndex驱动的专业知识检索增强
- **用户交互中断**: 工作流支持interrupt暂停等待用户确认
- **意图识别**: 基于LLM Function Calling的结构化意图识别
- **实时反馈**: WebSocket实时推送工作流进度和状态
- **认证共享**: 工具间自动传递认证信息，支持深度扫描

### 服务信息

| 项目     | 值                            |
| ------ | ---------------------------- |
| 服务名称   | TOSKill Security Scanner     |
| 默认端口   | 8081                         |
| 协议支持   | HTTP/1.1, WebSocket          |
| 数据格式   | JSON                         |
| 内置工具数量 | 22                           |
| 动态工具   | 支持无限扩展                       |
| 框架版本   | LangGraph + Function Calling |

### 架构特性

- **LangGraph工作流**: 基于StateGraph的智能体编排
- **ReACT推理循环**: `ai_decision → user_interact → router → execute_task → vulnerability_check → ai_decision`
- **interrupt机制**: 工作流暂停等待用户交互
- **Command恢复**: 使用`Command(resume=...)`恢复中断的工作流
- **RAG增强**: LlamaIndex知识库检索增强AI决策

***

## 2. 通用说明

### 2.1 请求头

所有REST API请求应包含以下请求头：

```
Content-Type: application/json
Accept: application/json
```

### 2.2 统一响应格式

所有REST API响应采用统一的JSON格式：

```json
{
    "code": 200,
    "message": "success",
    "data": { ... }
}
```

| 字段      | 类型      | 说明           |
| ------- | ------- | ------------ |
| code    | integer | 状态码，200表示成功  |
| message | string  | 响应消息         |
| data    | object  | 响应数据，可能为null |

### 2.3 错误响应格式

当请求失败时，返回格式如下：

```json
{
    "detail": "错误描述信息"
}
```

***

## 3. 扫描接口

### 3.1 通用扫描

执行扫描任务，可指定工具列表或使用全部工具。

**请求信息**

| 项目           | 值                  |
| ------------ | ------------------ |
| 方法           | `POST`             |
| 路径           | `/api/scan`        |
| Content-Type | `application/json` |

**请求体**

```json
{
    "target": "string",
    "tools": ["string"],
    "generate_report": true
}
```

| 参数               | 类型      | 必填 | 默认值  | 说明        |
| ---------------- | ------- | -- | ---- | --------- |
| target           | string  | 是  | -    | 扫描目标域名或IP |
| tools            | array   | 否  | 全部工具 | 指定工具名称列表  |
| generate\_report | boolean | 否  | true | 是否生成扫描报告  |

**响应体**

```json
{
    "session_id": "a1b2c3d4",
    "target": "example.com",
    "completed_tasks": ["portscan", "subdomain", ...],
    "tool_results": { ... },
    "errors": [],
    "report": "# 安全扫描报告\n...",
    "report_url": "/api/reports/download/scan_report_a1b2c3d4.md"
}
```

***

### 3.2 信息收集扫描

执行信息收集工具集。

**请求信息**

| 项目           | 值                  |
| ------------ | ------------------ |
| 方法           | `POST`             |
| 路径           | `/api/scan/info`   |
| Content-Type | `application/json` |

**请求体**

```json
{
    "target": "string"
}
```

***

### 3.3 漏洞扫描

执行漏洞扫描工具集。

**请求信息**

| 项目           | 值                  |
| ------------ | ------------------ |
| 方法           | `POST`             |
| 路径           | `/api/scan/vuln`   |
| Content-Type | `application/json` |

**请求体**

```json
{
    "target": "string"
}
```

***

### 3.4 完整扫描

执行所有工具（信息收集 + 漏洞扫描）。

**请求信息**

| 项目           | 值                  |
| ------------ | ------------------ |
| 方法           | `POST`             |
| 路径           | `/api/scan/full`   |
| Content-Type | `application/json` |

**请求体**

```json
{
    "target": "string"
}
```

**响应体**

```json
{
    "session_id": "a1b2c3d4",
    "target": "example.com",
    "completed_tasks": [...],
    "tool_results": { ... },
    "vulnerabilities": [...],
    "report": "# 安全扫描报告\n...",
    "report_url": "/api/reports/download/scan_report_a1b2c3d4.md",
    "scan_summary": {
        "timestamp": "2026-05-01T12:00:00",
        "tool_count": 19,
        "vulnerability_count": 3
    }
}
```

***

## 4. 工具执行接口

### 4.1 获取工具列表

获取所有可用工具列表。

**请求信息**

| 项目 | 值            |
| -- | ------------ |
| 方法 | `GET`        |
| 路径 | `/api/tools` |

**响应体**

```json
[
    {"name": "portscan", "description": "端口扫描 - 扫描目标开放端口"},
    {"name": "sqli", "description": "SQL注入扫描 - 检测SQL注入漏洞"}
]
```

***

### 4.2 获取工具分类

获取按类别分组的工具列表。

**请求信息**

| 项目 | 值                       |
| -- | ----------------------- |
| 方法 | `GET`                   |
| 路径 | `/api/tools/categories` |

**响应体**

```json
{
    "info_collection": ["baseinfo", "portscan", ...],
    "vuln_scan": ["sqli", "xss", ...],
    "all": ["baseinfo", "portscan", ...]
}
```

***

### 4.3 执行单个工具

执行指定的安全工具。

**请求信息**

| 项目           | 值                    |
| ------------ | -------------------- |
| 方法           | `POST`               |
| 路径           | `/api/tools/execute` |
| Content-Type | `application/json`   |

**请求体**

```json
{
    "tool_name": "string",
    "target": "string"
}
```

| 参数         | 类型     | 必填 | 说明               |
| ---------- | ------ | -- | ---------------- |
| tool\_name | string | 是  | 工具名称，如`portscan` |
| target     | string | 是  | 扫描目标             |

**响应体**

```json
{
    "tool_name": "portscan",
    "target": "example.com",
    "result": {
        "open_ports": [22, 80, 443]
    },
    "timestamp": "2026-05-01T12:00:00"
}
```

***

### 4.4 批量执行工具

批量执行多个工具。

**请求信息**

| 项目           | 值                          |
| ------------ | -------------------------- |
| 方法           | `POST`                     |
| 路径           | `/api/tools/execute/batch` |
| Content-Type | `application/json`         |

**请求体**

```json
{
    "tool_names": ["portscan", "subdomain"],
    "target": "string"
}
```

***

## 5. 会话管理接口

### 5.1 创建会话

创建一个新的扫描会话。

**请求信息**

| 项目           | 值                  |
| ------------ | ------------------ |
| 方法           | `POST`             |
| 路径           | `/api/sessions`    |
| Content-Type | `application/json` |

**请求体**

```json
{
    "target": "string",
    "mode": "full_scan"
}
```

**响应体**

```json
{
    "session_id": "a1b2c3d4"
}
```

***

### 5.2 获取会话状态

获取指定会话的当前状态。

**请求信息**

| 项目 | 值                            |
| -- | ---------------------------- |
| 方法 | `GET`                        |
| 路径 | `/api/sessions/{session_id}` |

**响应体**

```json
{
    "task_id": "a1b2c3d4",
    "target": "example.com",
    "mode": "full_scan",
    "completed_tasks": ["portscan", "subdomain"],
    "is_complete": false
}
```

***

### 5.3 删除会话

删除指定的会话。

**请求信息**

| 项目 | 值                            |
| -- | ---------------------------- |
| 方法 | `DELETE`                     |
| 路径 | `/api/sessions/{session_id}` |

***

### 5.4 健康检查

检查API服务是否正常运行。

**请求信息**

| 项目 | 值         |
| -- | --------- |
| 方法 | `GET`     |
| 路径 | `/health` |

**响应体**

```json
{
    "status": "healthy"
}
```

***

## 6. WebSocket API 接口

### 6.1 连接信息

| 项目   | 值                                    |
| ---- | ------------------------------------ |
| 端点   | `ws://localhost:8081/api/ai-chat/ws` |
| 协议   | WebSocket                            |
| 数据格式 | JSON                                 |

### 6.2 消息格式

所有消息采用统一的JSON格式：

```json
{
    "type": "message_type",
    "payload": { ... }
}
```

### 6.3 客户端消息类型

| 类型                   | 说明       | payload                          |
| -------------------- | -------- | -------------------------------- |
| `start_scan`         | 开始扫描     | `{target, scan_mode}`            |
| `stop_scan`          | 停止扫描     | `{}`                             |
| `user_confirm`       | 用户确认选择   | `{choice}`                       |
| `user_choice`        | 用户选择（别名） | `{choice}`                       |
| `user_input`         | 用户输入内容   | `{content}`                      |
| `chat`               | AI对话     | `{content}`                      |
| `execute_tool`       | 执行工具     | `{tool_name, target}`            |
| `script_content`     | 上传自定义脚本  | `{script_content, script_name?}` |
| `script_description` | AI生成脚本描述 | `{description}`                  |
| `input_response`     | 输入字段响应   | `{field, value}`                 |
| `subscribe`          | 订阅已有会话   | `{session_id}`                   |
| `get_history`        | 获取聊天历史   | `{}`                             |
| `get_status`         | 获取会话状态   | `{}`                             |
| `high_risk_confirm`  | 高危漏洞确认   | `{choice}`                       |

### 6.4 服务端消息类型

| 类型                                 | 说明                 |
| ---------------------------------- | ------------------ |
| `connected`                        | 连接成功，返回session\_id |
| `interaction_required`             | 需要用户交互（5个选项）       |
| `workflow_resumed`                 | 工作流已恢复             |
| `high_risk_vulnerability_detected` | 高危漏洞检测             |
| `high_risk_confirmed`              | 高危漏洞已确认            |
| `intent_recognized`                | 意图识别结果             |
| `intent_validation_error`          | 意图校验错误             |
| `tool_not_found`                   | 工具不存在              |
| `scan_started`                     | 扫描已开始              |
| `scan_completed`                   | 扫描已完成              |
| `scan_cancelled`                   | 扫描已取消              |
| `scan_flow_started`                | 扫描流程启动             |
| `direct_tool_started`              | 工具直调开始             |
| `direct_tool_completed`            | 工具直调完成             |
| `direct_tool_error`                | 工具直调错误             |
| `task_started`                     | 任务开始               |
| `task_completed`                   | 任务完成               |
| `task_skipped`                     | 任务跳过               |
| `task_error`                       | 任务错误               |
| `ai_decision`                      | AI决策信息             |
| `ai_decision_complete`             | AI决策完成             |
| `ai_message`                       | AI聊天回复             |
| `ai_chat`                          | AI聊天回复（别名）         |
| `workflow_progress`                | 工作流进度更新            |
| `report_generation_started`        | 报告生成开始             |
| `report_generated`                 | 报告生成完成             |
| `report_error`                     | 报告生成错误             |
| `auth_info_obtained`               | 认证信息获取成功           |
| `auth_refresh_required`            | 需要刷新认证             |
| `auth_refresh_success`             | 认证刷新成功             |
| `auth_unavailable`                 | 认证不可用              |
| `auth_retry_exhausted`             | 重试次数耗尽             |
| `script_upload_request`            | 请求上传脚本             |
| `script_generate_request`          | 请求生成脚本描述           |
| `script_analyzing`                 | AI分析脚本中            |
| `script_generating`                | AI生成脚本中            |
| `script_registered`                | 脚本注册成功             |
| `script_generated`                 | 脚本生成成功             |
| `script_error`                     | 脚本处理错误             |
| `history`                          | 聊天历史               |
| `status`                           | 会话状态               |
| `subscribed`                       | 订阅成功               |
| `error`                            | 错误消息               |

### 6.5 用户交互说明

#### 交互选项

扫描过程中，用户可选择5个选项：

| 选项 | 说明        |
| -- | --------- |
| 1  | 执行当前任务    |
| 2  | 停止扫描并生成报告 |
| 3  | 与AI助手聊天   |
| 4  | 上传自定义脚本   |
| 5  | AI生成扫描脚本  |

#### 交互消息示例

服务端发送：

```json
{
    "type": "interaction_required",
    "session_id": "abc12345",
    "next_task": "sqli",
    "target": "example.com",
    "mode": "full_scan",
    "options": [
        {"key": "1", "label": "执行", "description": "执行任务: sqli"},
        {"key": "2", "label": "停止", "description": "停止扫描并生成报告"},
        {"key": "3", "label": "聊天", "description": "与AI助手对话"},
        {"key": "4", "label": "上传脚本", "description": "上传自定义扫描脚本"},
        {"key": "5", "label": "生成脚本", "description": "AI生成专属扫描脚本"}
    ]
}
```

客户端响应：

```json
{
    "type": "user_confirm",
    "payload": {"choice": "1"}
}
```

### 6.6 高危漏洞确认

检测到高危漏洞时，服务端发送：

```json
{
    "type": "high_risk_vulnerability_detected",
    "highest_risk_level": "critical",
    "risk_summary": {"critical": 1, "high": 2, "medium": 3, "low": 5},
    "vulnerabilities": [...],
    "options": [
        {"key": "continue", "label": "继续扫描"},
        {"key": "stop", "label": "停止并报告"},
        {"key": "poc_verify", "label": "POC验证"}
    ]
}
```

### 6.7 工作流进度

服务端实时推送工作流进度：

```json
{
    "type": "workflow_progress",
    "payload": {
        "stage": "info_collection",
        "status": "running",
        "completed": 3,
        "total": 11,
        "progress_percent": 27.3,
        "rag_enabled": true,
        "rag_strategy": "..."
    }
}
```

### 6.8 连接示例

```javascript
const ws = new WebSocket('ws://localhost:8081/api/ai-chat/ws');

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    
    switch(data.type) {
        case 'connected':
            console.log('Session ID:', data.payload.session_id);
            break;
        case 'interaction_required':
            showInteractionButtons(data.options);
            break;
        case 'task_completed':
            updateTaskResult(data.payload);
            break;
        case 'scan_completed':
            showFinalReport(data.payload);
            break;
    }
};

// 发送扫描请求
ws.send(JSON.stringify({
    type: 'start_scan',
    payload: { target: 'example.com', scan_mode: 'full' }
}));

// 发送用户选择
ws.send(JSON.stringify({
    type: 'user_confirm',
    payload: { choice: '1' }
}));
```

***

## 7. 报告管理接口

### 7.1 获取报告列表

**请求信息**

| 项目 | 值                   |
| -- | ------------------- |
| 方法 | `GET`               |
| 路径 | `/api/reports/list` |

**响应体**

```json
{
    "reports": [
        {
            "id": "scan_report_abc123_20260501_173000",
            "name": "scan_report_abc123_20260501_173000.md",
            "size": 1024,
            "created_at": "2026-05-01T17:30:00",
            "download_url": "/api/reports/download/scan_report_abc123_20260501_173000.md"
        }
    ],
    "total": 1
}
```

***

### 7.2 下载报告

**请求信息**

| 项目 | 值                                  |
| -- | ---------------------------------- |
| 方法 | `GET`                              |
| 路径 | `/api/reports/download/{filename}` |

***

### 7.3 获取报告内容

**请求信息**

| 项目 | 值                                 |
| -- | --------------------------------- |
| 方法 | `GET`                             |
| 路径 | `/api/reports/{filename}/content` |

**响应体**

```json
{
    "success": true,
    "filename": "scan_report_20260501.md",
    "content": "# 安全扫描报告\n\n..."
}
```

***

### 7.4 删除报告

**请求信息**

| 项目 | 值                         |
| -- | ------------------------- |
| 方法 | `DELETE`                  |
| 路径 | `/api/reports/{filename}` |

***

## 8. 脚本管理接口

### 8.1 脚本上传（WebSocket）

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

- 必须包含`run(target: str)`函数
- 返回`Dict`类型结果
- 建议包含错误处理
- 自动进行安全审查

***

### 8.2 AI生成脚本（WebSocket）

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
        "tool_name": "ai_gen_20260501",
        "script_code": "def run(target):\n    ...",
        "description": "敏感文件泄露检测"
    }
}
```

***

## 9. 聊天兼容接口

### 9.1 发送聊天消息

```http
POST /api/chat/send
```

**请求体**:

```json
{
    "session_id": "abc12345",
    "message": "你好，帮我扫描这个网站"
}
```

### 9.2 获取聊天历史

```http
GET /api/chat/history/{session_id}?limit=20
```

**响应体**:

```json
{
    "history": [
        {"role": "user", "content": "你好", "timestamp": "2026-05-01T17:30:00"},
        {"role": "assistant", "content": "您好！", "timestamp": "2026-05-01T17:30:02"}
    ]
}
```

***

## 10. 错误码说明

### 10.1 HTTP状态码

| 状态码 | 说明      |
| --- | ------- |
| 200 | 请求成功    |
| 400 | 请求参数错误  |
| 404 | 资源不存在   |
| 500 | 服务器内部错误 |

### 10.2 错误响应示例

```json
{
    "detail": "扫描目标不能为空"
}
```

***

## 11. 工具列表

### 11.1 信息收集工具 (11个)

| 工具名称         | 说明     |
| ------------ | ------ |
| `baseinfo`   | 基础信息收集 |
| `portscan`   | 端口扫描   |
| `subdomain`  | 子域名扫描  |
| `dirscan`    | 目录扫描   |
| `waf`        | WAF检测  |
| `cdnexist`   | CDN检测  |
| `whatcms`    | CMS识别  |
| `infoleak`   | 信息泄露扫描 |
| `iplocating` | IP定位   |
| `webside`    | 备案查询   |
| `webweight`  | 权重查询   |

### 11.2 漏洞扫描工具 (8个)

| 工具名称         | 说明      | 风险等级 |
| ------------ | ------- | ---- |
| `sqli`       | SQL注入扫描 | 高危   |
| `xss`        | XSS扫描   | 中危   |
| `csrf`       | CSRF扫描  | 中危   |
| `fileupload` | 文件上传扫描  | 严重   |
| `cmdi`       | 命令注入扫描  | 严重   |
| `ssrf`       | SSRF扫描  | 高危   |
| `lfi`        | LFI扫描   | 高危   |
| `weakpass`   | 弱口令扫描   | 高危   |

### 11.3 POC工具 (3个)

| 工具名称       | 说明             |
| ---------- | -------------- |
| `thinkphp` | ThinkPHP RCE检测 |
| `struts2`  | Struts2漏洞检测    |
| `weblogic` | WebLogic漏洞检测   |

***

## 12. 认证机制

### 12.1 认证信息共享

TOSKill支持在工作流节点间共享认证信息：

```
1. weakpass扫描成功登录 → 获取Cookie/Token
2. 系统加密存储到auth_info → 自动传递给后续工具
3. 后续工具自动使用认证信息 → 实现深度扫描
```

### 12.2 认证信息存储

```json
{
    "auth_info": {
        "cookies": {"session": "abc123"},
        "headers": {"Authorization": "Bearer xxx"},
        "token": "eyJhbGciOiJIUzI1NiIs...",
        "type": "cookie"
    },
    "auth_timestamp": "2026-05-01T12:00:00",
    "auth_expires_at": "2026-05-01T12:30:00"
}
```

### 12.3 认证重试机制

- 最大重试次数：3次
- 检测401/403响应自动触发重试
- 重试失败后通知用户手动认证

***

## 13. RAG知识库

### 13.1 知识文档

TOSKill内置7个专业知识文档：

| 文档                              | 内容           |
| ------------------------------- | ------------ |
| `01_vulnerability_types.md`     | 漏洞类型分类       |
| `02_attack_vectors.md`          | 攻击向量说明       |
| `03_tool_mapping.md`            | 工具映射关系       |
| `04_remediation_guide.md`       | 修复建议指南       |
| `05_severity_classification.md` | 严重程度分类       |
| `06_owasp_top10.md`             | OWASP Top 10 |
| `07_scanning_workflow.md`       | 扫描工作流程       |

### 13.2 RAG检索增强

AI决策节点使用RAG检索专业知识：

```python
rag_strategy = get_scan_strategy(
    target=target,
    current_task="",
    completed_tasks=done,
    last_result=last_result
)
```

### 13.3 添加自定义知识

将Markdown文档放入`TOSKill/RAG/knowledge/`目录，系统会自动索引。

***

## 14. 用户交互机制

### 14.1 工作流中断

使用LangGraph的`interrupt()`机制实现用户交互：

```python
user_choice = interrupt({
    "type": "interaction_required",
    "options": [...]
})
```

### 14.2 工作流恢复

使用`Command(resume=...)`恢复中断的工作流：

```python
result = await orchestrator.resume_workflow(
    session_id, 
    user_choice
)
```

### 14.3 高危漏洞确认

检测到高危漏洞时自动中断：

```python
user_decision = interrupt({
    "type": "high_risk_vulnerability_detected",
    "options": [
        {"key": "continue", "label": "继续扫描"},
        {"key": "stop", "label": "停止并报告"},
        {"key": "poc_verify", "label": "POC验证"}
    ]
})
```

***

## 15. 记忆化机制

### 15.1 会话存储

系统使用`MemoryStore`管理会话状态：

| 存储内容        | 说明            |
| ----------- | ------------- |
| 会话状态        | ScanState完整状态 |
| 聊天历史        | 每个会话的聊天记录     |
| 待处理交互       | 等待用户响应的交互请求   |
| WebSocket回调 | 实时推送函数        |

### 15.2 TTL过期清理

| 配置项    | 默认值   | 说明         |
| ------ | ----- | ---------- |
| 会话TTL  | 3600秒 | 会话过期时间     |
| 清理间隔   | 600秒  | 定时清理检查间隔   |
| 最大聊天记录 | 100条  | 每会话最大聊天记录数 |

***

## 16. 工具返回格式标准

### 16.1 标准格式

```json
{
    "success": true,
    "data": {
        "vulnerable": false,
        "results": [...]
    },
    "error": null,
    "auth_info": null,
    "timestamp": "2026-05-01T12:00:00"
}
```

| 字段         | 类型           | 必需 | 说明     |
| ---------- | ------------ | -- | ------ |
| success    | boolean      | 是  | 执行是否成功 |
| data       | object       | 是  | 返回数据   |
| error      | string\|null | 否  | 错误信息   |
| auth\_info | object\|null | 否  | 认证信息   |
| timestamp  | string       | 是  | 时间戳    |

***

## 17. 意图识别机制

### 17.1 意图类型

系统支持5种意图类型：

| 意图类型              | 说明     | 触发关键词       |
| ----------------- | ------ | ----------- |
| `scan`            | 完整扫描流程 | 扫描、漏洞、渗透、检测 |
| `tool`            | 工具直调   | 调用、执行、使用工具  |
| `chat`            | 纯聊天    | 咨询、问答、闲聊    |
| `upload_script`   | 上传脚本   | 上传脚本、自定义脚本  |
| `generate_script` | AI生成脚本 | 生成脚本、AI写脚本  |

### 17.2 Function Calling流程

```
用户输入 → LLM.bind_tools(INTENT_TOOLS) → AIMessage.tool_calls → 提取意图
```

### 17.3 ReACT推理循环

工作流保持ReACT循环结构：

```
ai_decision → user_interact → router → execute_task → vulnerability_check → ai_decision
```

- `ai_decision`: RAG增强的AI决策
- `user_interact`: interrupt等待用户交互
- `router`: 用户选择路由
- `execute_task`: 执行工具
- `vulnerability_check`: 高危漏洞检测

***

*文档版本: 1.0.0 | 最后更新: 2026-05-01*
## pause_for_chat / resume_scan WebSocket 协议

协议版本：`1.0`。

客户端请求格式：

```json
{
  "type": "pause_for_chat",
  "payload": {
    "protocol_version": "1.0",
    "request_id": "req-001",
    "interaction_id": "session:interaction:baseinfo_scan:0"
  }
}
```

```json
{
  "type": "resume_scan",
  "payload": {
    "protocol_version": "1.0",
    "request_id": "req-002",
    "pause_id": "session:pause:abcdef123456"
  }
}
```

`interaction_id` 和 `pause_id` 在兼容旧客户端时可以省略，服务端会从当前会话状态补齐；新客户端应始终传递它们。

暂停成功后服务端发送 `scan_paused_for_chat`，恢复过程依次发送 `scan_resume_requested`、`decision_replanned` 和 `workflow_resumed`。上述消息均包含：

```json
{
  "protocol_version": "1.0",
  "request_id": "req-002",
  "session_id": "session-id"
}
```

协议错误统一返回 `type=error`，并在 `payload.details` 中包含 `request_id`、`protocol_version` 和字段校验信息。
