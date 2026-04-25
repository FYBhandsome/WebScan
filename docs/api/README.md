# API文档总览

## 简介

本文档描述了AI WebSecurity系统的所有API接口，包括HTTP REST API和WebSocket实时通信接口。

## 基础信息

- **基础URL**: `http://127.0.0.1:8888/api`
- **认证方式**: Bearer Token (JWT)
- **数据格式**: JSON
- **字符编码**: UTF-8

## 通用响应格式

所有HTTP接口返回统一的JSON格式：

```json
{
  "code": 200,
  "message": "操作成功",
  "data": { ... }
}
```

### 状态码说明

| 状态码 | 说明 |
|--------|------|
| 200 | 成功 |
| 400 | 请求参数错误 |
| 401 | 未授权 |
| 403 | 禁止访问 |
| 404 | 资源不存在 |
| 500 | 服务器内部错误 |

## API模块列表

### HTTP API

1. [知识库API](./http/kb_api.md) - `/api/kb`
2. [Seebug API](./http/seebug_api.md) - `/api/seebug`
3. [设置API](./http/settings_api.md) - `/api/settings`
4. [任务API](./http/tasks_api.md) - `/api/tasks`
5. [报告API](./http/reports_api.md) - `/api/reports`
6. [AI对话API](./http/ai_api.md) - `/api/ai`
7. [扫描API](./http/scan_api.md) - `/api/scan`
8. [AWVS API](./http/awvs_api.md) - `/api/awvs`
9. [POC API](./http/poc_api.md) - `/api/poc`
10. [用户API](./http/user_api.md) - `/api/user`
11. [通知API](./http/notifications_api.md) - `/api/notifications`

### WebSocket API

1. [连接文档](./websocket/connection.md) - WebSocket连接和心跳
2. [聊天消息](./websocket/chat.md) - AI对话消息
3. [扫描进度](./websocket/scan.md) - 任务扫描进度
4. [通知推送](./websocket/notification.md) - 实时通知推送

## 快速开始

### 1. 获取认证Token

```bash
curl -X POST http://127.0.0.1:8888/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

### 2. 使用Token访问API

```bash
curl -X GET http://127.0.0.1:8888/api/kb/vulnerabilities \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 3. 建立WebSocket连接

```javascript
const ws = new WebSocket('ws://127.0.0.1:8888/ws')
ws.onmessage = (event) => {
  const data = JSON.parse(event.data)
  console.log('Received:', data)
}
```

## 错误处理

所有API错误都会返回统一的错误格式：

```json
{
  "code": 400,
  "message": "请求参数错误",
  "data": null
}
```

## 分页

列表接口支持分页，使用以下参数：

- `page`: 页码（从1开始）
- `page_size`: 每页数量（默认20）

## 版本控制

API版本通过URL路径控制，当前版本为v1（默认不显示版本号）。

## 变更日志

查看 [变更日志](./changelog.md) 了解API的更新历史。
