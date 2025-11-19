# WebScan AI - API接口文档

本文档描述了WebScan AI系统的后端API接口规范。前端代码中所有标记为`TODO`的地方都需要调用这些API接口。

## 基础信息

- **Base URL**: `http://localhost:8080/api`
- **认证方式**: Bearer Token (JWT)
- **数据格式**: JSON
- **字符编码**: UTF-8

## 通用响应格式

### 成功响应
```json
{
  "success": true,
  "data": {}, // 具体数据
  "message": "操作成功"
}
```

### 错误响应
```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "错误描述",
    "details": {} // 详细错误信息（可选）
  }
}
```

## 认证接口

### 用户登录
```http
POST /auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "password"
}
```

**响应**:
```json
{
  "success": true,
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
      "id": 1,
      "username": "admin",
      "email": "admin@webscan.ai",
      "role": "administrator"
    }
  }
}
```

## 仪表盘接口

### 获取仪表盘统计数据
```http
GET /dashboard/stats
Authorization: Bearer {token}
```

**响应**:
```json
{
  "success": true,
  "data": {
    "todayScans": 12,
    "highRiskVulns": 5,
    "weeklyTrend": -15,
    "completedScans": 89,
    "totalTasks": 156,
    "activeScans": 3
  }
}
```

### 获取漏洞趋势数据
```http
GET /dashboard/trends?period=7
Authorization: Bearer {token}
```

**参数**:
- `period`: 时间周期（7, 30, 90天）

**响应**:
```json
{
  "success": true,
  "data": [
    {
      "date": "11-11",
      "high": 3,
      "medium": 5,
      "low": 8
    }
  ]
}
```

### 获取最新扫描结果
```http
GET /scans/recent?limit=4
Authorization: Bearer {token}
```

**参数**:
- `limit`: 返回数量限制

## 扫描任务接口

### 获取扫描任务列表
```http
GET /scan-tasks?page=1&size=20&status=&priority=
Authorization: Bearer {token}
```

**参数**:
- `page`: 页码（从1开始）
- `size`: 每页数量
- `status`: 状态筛选（waiting, running, completed, failed）
- `priority`: 优先级筛选（low, medium, high, critical）

**响应**:
```json
{
  "success": true,
  "data": {
    "items": [
      {
        "id": 1,
        "name": "电商网站安全扫描",
        "targetUrl": "https://shop.example.com",
        "status": "completed",
        "priority": "high",
        "scanType": "深度扫描",
        "startTime": "2024-11-17 14:30",
        "endTime": "2024-11-17 16:45",
        "progress": 100,
        "vulnerabilityCount": {
          "high": 3,
          "medium": 8,
          "low": 12,
          "total": 23
        }
      }
    ],
    "total": 156,
    "page": 1,
    "size": 20
  }
}
```

### 创建扫描任务
```http
POST /scan-tasks
Authorization: Bearer {token}
Content-Type: application/json

{
  "name": "新扫描任务",
  "targetUrls": ["https://example.com", "https://api.example.com"],
  "scanType": "deep",
  "priority": "high",
  "scheduleType": "immediate",
  "scheduledTime": null,
  "config": {
    "depth": 2,
    "concurrency": 5,
    "enableAuth": false,
    "requestTimeout": 30
  }
}
```

**响应**:
```json
{
  "success": true,
  "data": {
    "id": 157,
    "name": "新扫描任务",
    "status": "waiting",
    "createdAt": "2024-11-17 20:30"
  }
}
```

### 获取扫描任务详情
```http
GET /scan-tasks/{taskId}
Authorization: Bearer {token}
```

### 停止扫描任务
```http
POST /scan-tasks/{taskId}/stop
Authorization: Bearer {token}
```

### 重新启动扫描任务
```http
POST /scan-tasks/{taskId}/restart
Authorization: Bearer {token}
```

### 删除扫描任务
```http
DELETE /scan-tasks/{taskId}
Authorization: Bearer {token}
```

## 漏洞管理接口

### 获取任务漏洞统计
```http
GET /scan-tasks/{taskId}/vulnerability-stats
Authorization: Bearer {token}
```

**响应**:
```json
{
  "success": true,
  "data": {
    "high": 3,
    "medium": 8,
    "low": 12,
    "total": 23
  }
}
```

### 获取任务漏洞列表
```http
GET /scan-tasks/{taskId}/vulnerabilities?priority=&type=&status=&search=
Authorization: Bearer {token}
```

**参数**:
- `priority`: 优先级筛选（high, medium, low）
- `type`: 漏洞类型筛选
- `status`: 状态筛选（unfixed, fixed, false-positive）
- `search`: 搜索关键词

**响应**:
```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "taskId": 1,
      "title": "SQL注入漏洞 - 用户登录接口",
      "type": "sql-injection",
      "priority": "high",
      "severity": "critical",
      "description": "漏洞描述",
      "location": "/api/login",
      "method": "POST",
      "parameter": "username",
      "cvssScore": 9.1,
      "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "impact": "数据泄露、身份验证绕过",
      "discoveredAt": "2024-11-17 15:23",
      "status": "unfixed"
    }
  ]
}
```

### 获取漏洞详情
```http
GET /vulnerabilities/{id}
Authorization: Bearer {token}
```

**响应**:
```json
{
  "success": true,
  "data": {
    "id": 1,
    "title": "SQL注入漏洞 - 用户登录接口",
    "type": "sql-injection",
    "priority": "high",
    "description": "详细描述",
    "technicalDetails": "技术细节",
    "location": "/api/login",
    "cvssScore": 9.1,
    "payload": "恶意载荷",
    "response": "响应示例",
    "references": ["https://owasp.org/..."]
  }
}
```

### 获取漏洞AI分析
```http
GET /vulnerabilities/{id}/ai-analysis
Authorization: Bearer {token}
```

**响应**:
```json
{
  "success": true,
  "data": {
    "priorityReason": "优先级理由",
    "riskCorrelation": "风险关联分析",
    "falsePositive": false,
    "fpReason": "误报判断理由"
  }
}
```

### 获取漏洞修复步骤
```http
GET /vulnerabilities/{id}/fix-steps
Authorization: Bearer {token}
```

**响应**:
```json
{
  "success": true,
  "data": [
    {
      "title": "使用参数化查询",
      "description": "修复描述",
      "code": "示例代码"
    }
  ]
}
```

### 标记漏洞状态
```http
PATCH /vulnerabilities/{id}/status
Authorization: Bearer {token}
Content-Type: application/json

{
  "status": "fixed", // fixed, false-positive
  "comment": "修复说明"
}
```

## 报告管理接口

### 获取报告列表
```http
GET /reports?format=&taskId=
Authorization: Bearer {token}
```

**参数**:
- `format`: 报告格式筛选（html, pdf, json）
- `taskId`: 任务ID筛选

**响应**:
```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "name": "电商网站安全扫描报告",
      "taskName": "电商网站安全扫描",
      "taskId": 1,
      "format": "pdf",
      "size": "2.3 MB",
      "createdAt": "2024-11-17 16:45",
      "downloadUrl": "/api/reports/1/download"
    }
  ]
}
```

### 生成报告
```http
POST /reports
Authorization: Bearer {token}
Content-Type: application/json

{
  "taskId": 1,
  "format": "pdf",
  "content": ["summary", "vulnerabilities", "recommendations"],
  "name": "自定义报告名称"
}
```

**响应**:
```json
{
  "success": true,
  "data": {
    "id": 2,
    "status": "generating",
    "estimatedTime": "2分钟"
  }
}
```

### 下载报告
```http
GET /reports/{id}/download
Authorization: Bearer {token}
```

**响应**: 文件流

### 删除报告
```http
DELETE /reports/{id}
Authorization: Bearer {token}
```

## 系统设置接口

### 获取系统设置
```http
GET /settings
Authorization: Bearer {token}
```

**响应**:
```json
{
  "success": true,
  "data": {
    "general": {
      "systemName": "WebScan AI",
      "language": "zh-CN",
      "timezone": "Asia/Shanghai",
      "autoUpdate": true
    },
    "scan": {
      "defaultDepth": "2",
      "defaultConcurrency": 5,
      "requestTimeout": 30
    },
    "notification": {
      "emailEnabled": false,
      "smtpServer": "",
      "events": ["high-vulnerability"]
    },
    "security": {
      "sessionTimeout": 120,
      "requireHttps": true
    }
  }
}
```

### 更新系统设置
```http
PUT /settings
Authorization: Bearer {token}
Content-Type: application/json

{
  "general": {
    "systemName": "WebScan AI",
    "language": "zh-CN"
  }
}
```

### 获取扫描规则
```http
GET /scan-rules
Authorization: Bearer {token}
```

**响应**:
```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "name": "SQL注入检测",
      "description": "检测SQL注入漏洞",
      "enabled": true,
      "category": "injection"
    }
  ]
}
```

### 更新扫描规则
```http
PATCH /scan-rules/{id}
Authorization: Bearer {token}
Content-Type: application/json

{
  "enabled": true
}
```

## API密钥管理接口

### 获取API密钥列表
```http
GET /api-keys
Authorization: Bearer {token}
```

**响应**:
```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "name": "默认API密钥",
      "masked": "wsa_****************************abc123",
      "createdAt": "2024-11-15 10:30",
      "lastUsed": "2024-11-17 20:15",
      "permissions": ["read", "write"]
    }
  ]
}
```

### 创建API密钥
```http
POST /api-keys
Authorization: Bearer {token}
Content-Type: application/json

{
  "name": "新API密钥",
  "permissions": ["read", "write"]
}
```

**响应**:
```json
{
  "success": true,
  "data": {
    "id": 2,
    "name": "新API密钥",
    "key": "wsa_1234567890abcdef1234567890abcdef",
    "createdAt": "2024-11-17 20:30"
  }
}
```

### 重新生成API密钥
```http
POST /api-keys/{id}/regenerate
Authorization: Bearer {token}
```

### 删除API密钥
```http
DELETE /api-keys/{id}
Authorization: Bearer {token}
```

## 通知接口

### 获取通知列表
```http
GET /notifications?read=&type=
Authorization: Bearer {token}
```

**参数**:
- `read`: 是否已读筛选（true, false）
- `type`: 通知类型筛选

**响应**:
```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "title": "高危漏洞发现",
      "message": "在 shop.example.com 发现 SQL 注入漏洞",
      "type": "high-vulnerability",
      "time": "5分钟前",
      "read": false
    }
  ]
}
```

### 标记通知为已读
```http
PATCH /notifications/{id}/read
Authorization: Bearer {token}
```

### 标记所有通知为已读
```http
POST /notifications/mark-all-read
Authorization: Bearer {token}
```

## 用户管理接口

### 获取用户信息
```http
GET /user/profile
Authorization: Bearer {token}
```

**响应**:
```json
{
  "success": true,
  "data": {
    "id": 1,
    "username": "admin",
    "email": "admin@webscan.ai",
    "role": "administrator",
    "lastLogin": "2024-11-17 20:00",
    "permissions": ["scan:create", "scan:read"]
  }
}
```

### 更新用户信息
```http
PUT /user/profile
Authorization: Bearer {token}
Content-Type: application/json

{
  "email": "new-email@webscan.ai"
}
```

### 修改密码
```http
POST /user/change-password
Authorization: Bearer {token}
Content-Type: application/json

{
  "currentPassword": "old-password",
  "newPassword": "new-password"
}
```

## WebSocket接口

### 实时扫描进度
```javascript
// 连接WebSocket
const ws = new WebSocket('ws://localhost:8080/ws/scan-progress');

// 订阅扫描任务进度
ws.send(JSON.stringify({
  type: 'subscribe',
  taskId: 1
}));

// 接收进度更新
ws.onmessage = function(event) {
  const data = JSON.parse(event.data);
  // data.progress: 0-100
  // data.status: 'running', 'completed', 'failed'
  // data.currentUrl: 当前扫描的URL
};
```

## 错误代码

| 错误代码 | HTTP状态码 | 描述 |
|---------|-----------|------|
| `UNAUTHORIZED` | 401 | 未授权访问 |
| `FORBIDDEN` | 403 | 权限不足 |
| `NOT_FOUND` | 404 | 资源不存在 |
| `VALIDATION_ERROR` | 400 | 请求参数验证失败 |
| `TASK_NOT_FOUND` | 404 | 扫描任务不存在 |
| `TASK_ALREADY_RUNNING` | 409 | 任务已在运行中 |
| `VULNERABILITY_NOT_FOUND` | 404 | 漏洞不存在 |
| `REPORT_GENERATION_FAILED` | 500 | 报告生成失败 |
| `SETTINGS_UPDATE_FAILED` | 500 | 设置更新失败 |

## 限流规则

- **API调用频率**: 每分钟最多100次请求
- **扫描任务创建**: 每小时最多10个任务
- **报告生成**: 每小时最多5个报告

## 数据模型

### 扫描任务状态流转
```
waiting → running → completed
                 → failed
```

### 漏洞优先级映射
- **critical**: CVSS 9.0-10.0
- **high**: CVSS 7.0-8.9
- **medium**: CVSS 4.0-6.9
- **low**: CVSS 0.1-3.9

### 权限系统
- **administrator**: 所有权限
- **scanner**: 扫描相关权限
- **viewer**: 只读权限

## 开发注意事项

1. **认证**: 所有API请求都需要在Header中包含有效的JWT Token
2. **分页**: 列表接口支持分页，默认每页20条记录
3. **缓存**: 统计数据接口有5分钟缓存
4. **异步处理**: 扫描任务和报告生成为异步操作
5. **文件上传**: 支持multipart/form-data格式
6. **日志记录**: 所有API调用都会记录操作日志

## 测试环境

- **测试服务器**: `http://test.webscan.ai:8080`
- **测试账号**: `test@webscan.ai` / `test123`
- **API文档**: `http://test.webscan.ai:8080/swagger-ui`
