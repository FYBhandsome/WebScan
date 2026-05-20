import { ref, onMounted, onBeforeUnmount } from 'vue'

const MAX_LOG_ENTRIES = 500

const LOG_WS_PATH = '/api/logs/ws'

class LogWebSocketManager {
  constructor() {
    this.ws = null
    this.connected = false
    this.reconnectAttempts = 0
    this.maxReconnectAttempts = 10
    this.reconnectDelay = 1000
    this.reconnectTimer = null
    this.messageHandlers = new Map()
    this.logs = ref([])
    this.clientId = null
  }

  connect() {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      return Promise.resolve(this.clientId)
    }

    return new Promise((resolve, reject) => {
      try {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
        const host = window.location.host
        const url = `${protocol}//${host}${LOG_WS_PATH}`

        this.ws = new WebSocket(url)

        this.ws.onopen = () => {
          console.log('[LogWS] 连接成功')
          this.connected = true
          this.reconnectAttempts = 0
        }

        this.ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data)
            this.handleMessage(data)

            if (data.type === 'connected' && data.payload?.client_id) {
              this.clientId = data.payload.client_id
              resolve(this.clientId)
            }
          } catch (error) {
            console.error('[LogWS] 解析消息失败:', error)
          }
        }

        this.ws.onclose = (event) => {
          console.log('[LogWS] 连接关闭:', event.code)
          this.connected = false
          this.scheduleReconnect()
        }

        this.ws.onerror = (error) => {
          console.error('[LogWS] 连接错误:', error)
          reject(error)
        }
      } catch (error) {
        reject(error)
      }
    })
  }

  scheduleReconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.log('[LogWS] 达到最大重连次数')
      return
    }

    this.reconnectAttempts++
    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1)

    console.log(`[LogWS] ${delay}ms 后重连 (${this.reconnectAttempts}/${this.maxReconnectAttempts})`)

    this.reconnectTimer = setTimeout(() => {
      this.connect()
    }, delay)
  }

  disconnect() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
    if (this.ws) {
      this.ws.close()
      this.ws = null
      this.connected = false
    }
  }

  send(type, payload = {}) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      return false
    }
    this.ws.send(JSON.stringify({ type, payload }))
    return true
  }

  handleMessage(data) {
    const handlers = this.messageHandlers.get(data.type) || []
    handlers.forEach(handler => handler(data.payload, data))

    if (data.type === 'logs:single') {
      this.addLog(data.payload)
    } else if (data.type === 'logs:batch') {
      const logs = data.payload?.logs || []
      logs.forEach(log => this.addLog(log))
    }
  }

  addLog(logEntry) {
    const id = logEntry.id || `log_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    const level = (logEntry.level || 'info').toUpperCase()
    const timestamp = logEntry.timestamp || new Date().toLocaleTimeString('en-US', { hour12: false })

    this.logs.value.push({
      id,
      timestamp,
      level,
      message: logEntry.message || '',
      category: logEntry.category || 'system',
      node: logEntry.node || '-',
      details: logEntry.details || {},
      color: logEntry.color || this.getLevelColor(level)
    })

    while (this.logs.value.length > MAX_LOG_ENTRIES) {
      this.logs.value.shift()
    }
  }

  getLevelColor(level) {
    const colors = {
      DEBUG: '#888888',
      INFO: '#2196F3',
      WARNING: '#FF9800',
      ERROR: '#F44336',
      SUCCESS: '#4CAF50'
    }
    return colors[level] || '#2196F3'
  }

  on(messageType, callback) {
    if (!this.messageHandlers.has(messageType)) {
      this.messageHandlers.set(messageType, [])
    }
    this.messageHandlers.get(messageType).push(callback)
  }

  off(messageType, callback) {
    if (!this.messageHandlers.has(messageType)) return
    const handlers = this.messageHandlers.get(messageType)
    const index = handlers.indexOf(callback)
    if (index !== -1) {
      handlers.splice(index, 1)
    }
  }

  clearLogs() {
    this.logs.value = []
    this.send('clear_logs')
  }

  getHistory(count = 200) {
    this.send('get_history', { count })
  }

  subscribe(sessionId) {
    this.send('subscribe', { session_id: sessionId })
  }

  unsubscribe(sessionId) {
    this.send('unsubscribe', { session_id: sessionId })
  }

  isConnected() {
    return this.connected && this.ws && this.ws.readyState === WebSocket.OPEN
  }
}

export const logWsManager = new LogWebSocketManager()

export function useLogWebSocket() {
  const connect = () => logWsManager.connect()
  const disconnect = () => logWsManager.disconnect()
  const clearLogs = () => logWsManager.clearLogs()
  const getHistory = (count) => logWsManager.getHistory(count)
  const subscribe = (sessionId) => logWsManager.subscribe(sessionId)
  const unsubscribe = (sessionId) => logWsManager.unsubscribe(sessionId)

  onMounted(() => {
    if (!logWsManager.isConnected()) {
      logWsManager.connect()
    }
  })

  onBeforeUnmount(() => {
    // 不在这里断开，保持全局连接
  })

  return {
    logs: logWsManager.logs,
    connect,
    disconnect,
    clearLogs,
    getHistory,
    subscribe,
    unsubscribe,
    isConnected: () => logWsManager.isConnected()
  }
}
