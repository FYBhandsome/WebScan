# WebSocket连接文档

## 连接地址

```
ws://127.0.0.1:8888/ws
```

## 连接流程

### 1. 建立连接

```javascript
const ws = new WebSocket('ws://127.0.0.1:8888/ws')

ws.onopen = () => {
  console.log('WebSocket已连接')
}
```

### 2. 心跳检测

客户端发送：`ping`

服务端响应：`pong`

建议心跳间隔：30秒

```javascript
setInterval(() => {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send('ping')
  }
}, 30000)
```

### 3. 消息格式

所有消息使用JSON格式：

```json
{
  "type": "消息类型",
  "payload": {
    // 消息内容
  }
}
```

### 4. 断线重连

```javascript
ws.onclose = (event) => {
  console.log('连接关闭:', event.code, event.reason)
  // 实现重连逻辑
  setTimeout(() => {
    // 重新建立连接
  }, 3000)
}
```

## 消息类型

### 客户端发送消息

| 类型 | 说明 | payload |
|------|------|---------|
| chat_message | 发送聊天消息 | `{ message: string }` |
| ai_user_input | AI用户输入 | `{ input: string }` |
| ai_user_confirm | AI用户确认 | `{ decision_id: string, choice: string }` |
| ai_start_scan | 启动AI扫描 | `{ target: string, options: object }` |

### 服务端推送消息

| 类型 | 说明 | payload |
|------|------|---------|
| task_update | 任务状态更新 | `{ task_id, status, progress, message }` |
| task_progress | 任务进度更新 | `{ task_id, current_step, total_steps, step_name }` |
| task_completed | 任务完成 | `{ task_id, status, result }` |
| task_failed | 任务失败 | `{ task_id, error }` |
| vulnerability_found | 发现漏洞 | `{ task_id, vulnerability }` |
| scan_started | 扫描开始 | `{ task_id, target, scan_type }` |
| scan_stopped | 扫描停止 | `{ task_id, reason }` |
| new_notification | 新通知 | `{ id, title, message, type }` |
| ai_message | AI消息 | `{ conversation_id, message, type }` |
| ai_progress | AI进度 | `{ stage, progress, details }` |
| ai_decision | AI决策请求 | `{ decision_id, question, options }` |
| ai_error | AI错误 | `{ error_code, error_message }` |

## 连接状态

| 状态 | 说明 |
|------|------|
| CONNECTING (0) | 正在连接 |
| OPEN (1) | 已连接 |
| CLOSING (2) | 正在关闭 |
| CLOSED (3) | 已关闭 |

## 错误处理

```javascript
ws.onerror = (error) => {
  console.error('WebSocket错误:', error)
  // 处理错误
}
```

## 完整示例

```javascript
class WebSocketClient {
  constructor(url) {
    this.url = url
    this.ws = null
    this.reconnectAttempts = 0
    this.maxReconnectAttempts = 5
  }
  
  connect() {
    this.ws = new WebSocket(this.url)
    
    this.ws.onopen = () => {
      console.log('已连接')
      this.reconnectAttempts = 0
      this.startHeartbeat()
    }
    
    this.ws.onmessage = (event) => {
      if (event.data === 'pong') return
      const data = JSON.parse(event.data)
      this.handleMessage(data)
    }
    
    this.ws.onerror = (error) => {
      console.error('错误:', error)
    }
    
    this.ws.onclose = () => {
      console.log('连接关闭')
      this.stopHeartbeat()
      this.reconnect()
    }
  }
  
  startHeartbeat() {
    this.heartbeatTimer = setInterval(() => {
      if (this.ws.readyState === WebSocket.OPEN) {
        this.ws.send('ping')
      }
    }, 30000)
  }
  
  stopHeartbeat() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer)
    }
  }
  
  reconnect() {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++
      setTimeout(() => this.connect(), 3000)
    }
  }
  
  handleMessage(data) {
    console.log('收到消息:', data)
  }
  
  send(type, payload) {
    if (this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ type, payload }))
    }
  }
}

// 使用示例
const client = new WebSocketClient('ws://127.0.0.1:8888/ws')
client.connect()
```

## 安全说明

1. 建议使用WSS（WebSocket Secure）加密连接
2. 连接时需要携带认证Token
3. 消息内容需要进行验证和过滤
