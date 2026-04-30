import { ref, onMounted, onUnmounted } from 'vue'

class WebSocketManager {
  constructor(url, options = {}) {
    this.url = url
    this.options = {
      reconnect: true,
      reconnectInterval: 1000,
      maxReconnectAttempts: 5,
      heartbeatInterval: 30000,
      enableExponentialBackoff: true,
      maxReconnectDelay: 30000,
      enableMessageAck: true,
      enableIntegrityCheck: true,
      ...options
    }
    
    this.ws = null
    this.reconnectAttempts = 0
    this.heartbeatTimer = null
    this.reconnectTimer = null
    this.messageQueue = []
    this.eventHandlers = new Map()
    this.isConnected = ref(false)
    this.isConnecting = ref(false)
    this.isReconnecting = ref(false)
    this.reconnectStatus = ref('')
    this.connectionStatus = ref('disconnected')
    this.pendingMessages = new Map()
    this.messageHistory = []
    this.maxHistorySize = 100
  }

  connect() {
    if (this.isConnecting.value || this.isConnected.value) {
      return
    }

    this.isConnecting.value = true
    this.connectionStatus.value = 'connecting'

    try {
      this.ws = new WebSocket(this.url)
      this.setupEventListeners()
    } catch (error) {
      console.error('WebSocket连接失败:', error)
      this.handleConnectionError(error)
    }
  }

  setupEventListeners() {
    this.ws.onopen = () => {
      console.log('WebSocket连接成功')
      this.isConnected.value = true
      this.isConnecting.value = false
      this.isReconnecting.value = false
      this.reconnectAttempts = 0
      this.connectionStatus.value = 'connected'
      this.reconnectStatus.value = ''
      
      this.startHeartbeat()
      this.flushMessageQueue()
      
      this.emit('connected')
      this.emit('statusChange', this.getStatus())
    }

    this.ws.onmessage = (event) => {
      if (event.data === 'pong') {
        return
      }
      
      try {
        const data = JSON.parse(event.data)
        this.handleMessage(data)
      } catch (error) {
        console.error('WebSocket消息解析失败:', error)
      }
    }

    this.ws.onerror = (error) => {
      console.error('WebSocket错误:', error)
      this.connectionStatus.value = 'error'
      this.emit('error', error)
      this.emit('statusChange', this.getStatus())
    }

    this.ws.onclose = (event) => {
      console.log('WebSocket连接关闭:', event.code, event.reason)
      this.isConnected.value = false
      this.isConnecting.value = false
      this.connectionStatus.value = 'disconnected'
      
      this.stopHeartbeat()
      this.emit('disconnected', event)
      this.emit('statusChange', this.getStatus())
      
      if (this.options.reconnect && !event.wasClean) {
        this.scheduleReconnect()
      }
    }
  }

  handleMessage(data) {
    const { message_id, timestamp, message_type, message_hash, payload } = data
    const type = message_type || data.type
    
    if (this.options.enableIntegrityCheck && message_hash) {
      const isValid = this.verifyMessageHash(data)
      if (!isValid) {
        console.warn('消息完整性校验失败:', message_id)
        this.emit('integrity_error', { message_id, message_type })
        return
      }
    }
    
    if (this.options.enableMessageAck && message_id) {
      this.sendAck(message_id)
      this.addToHistory(data)
    }
    
    switch (type) {
      case 'task_update':
        this.emit('task:update', payload)
        break
      case 'task_progress':
        this.emit('task:progress', payload)
        break
      case 'task_completed':
        this.emit('task:completed', { ...payload, message_id, timestamp })
        break
      case 'stage_update':
        this.emit('stage:update', payload)
        break
      case 'task_failed':
        this.emit('task:failed', payload)
        break
      case 'vulnerability_found':
        this.emit('vulnerability:found', payload)
        break
      case 'scan_started':
        this.emit('scan:started', payload)
        break
      case 'scan_stopped':
        this.emit('scan:stopped', payload)
        break
      case 'notification':
        this.emit('notification', payload)
        break
      case 'subgraph_progress':
        this.emit('subgraph:progress', payload)
        break
      case 'tool_execution':
        this.emit('tool:execution', payload)
        break
      case 'new_notification':
        this.emit('new_notification', payload)
        break
      case 'heartbeat':
        this.handleHeartbeat()
        break
      case 'connected':
        this.emit('ai:connected', payload)
        break
      case 'ai_message':
        this.emit('ai:message', payload)
        break
      case 'decision':
        this.emit('ai:decision', payload)
        break
      case 'progress':
        this.emit('ai:progress', payload)
        break
      case 'confirmation_required':
        this.emit('ai:confirmation', payload)
        break
      case 'report_ready':
        this.emit('ai:report', payload)
        break
      case 'scan_cancelled':
        this.emit('ai:cancelled', payload)
        break
      case 'error':
        this.emit('ai:error', payload)
        break
      case 'history':
        this.emit('ai:history', payload)
        break
      case 'status':
        this.emit('ai:status', payload)
        break
      case 'user_message_received':
        this.emit('ai:user_received', payload)
        break
      case 'message_verification_result':
        this.emit('message:verification', payload)
        break
      case 'retransmit_batch':
        this.emit('message:retransmit_batch', payload)
        break
      case 'retransmit_failed':
        this.emit('message:retransmit_failed', payload)
        break
      default:
        this.emit('message', data)
    }
  }

  verifyMessageHash(message) {
    const { message_id, timestamp, message_type, message_hash, payload } = message
    if (!message_hash) return true
    
    const hashData = `${message_id}|${timestamp}|${message_type}|${JSON.stringify(payload, Object.keys(payload).sort())}`
    
    return true
  }

  sendAck(messageId) {
    this.send('message_ack', { message_id: messageId })
  }

  requestRetransmit(messageId) {
    this.send('message_retransmit', { message_id: messageId })
  }

  requestRecentMessages(count = 10) {
    this.send('message_retransmit', { count })
  }

  verifyMessage(message) {
    this.send('verify_message', { message })
  }

  addToHistory(message) {
    this.messageHistory.push({
      message_id: message.message_id,
      message_type: message.message_type,
      timestamp: message.timestamp,
      payload: message.payload
    })
    
    if (this.messageHistory.length > this.maxHistorySize) {
      this.messageHistory.shift()
    }
  }

  on(event, handler) {
    if (!this.eventHandlers.has(event)) {
      this.eventHandlers.set(event, [])
    }
    this.eventHandlers.get(event).push(handler)
  }

  off(event, handler) {
    if (!this.eventHandlers.has(event)) return
    
    const handlers = this.eventHandlers.get(event)
    const index = handlers.indexOf(handler)
    if (index > -1) {
      handlers.splice(index, 1)
    }
  }

  emit(event, data) {
    const handlers = this.eventHandlers.get(event)
    if (handlers) {
      handlers.forEach(handler => handler(data))
    }
  }

  send(type, payload = {}) {
    const message = JSON.stringify({ type, payload })
    
    if (this.isConnected.value) {
      this.ws.send(message)
    } else {
      this.messageQueue.push(message)
    }
  }

  flushMessageQueue() {
    while (this.messageQueue.length > 0 && this.isConnected.value) {
      const message = this.messageQueue.shift()
      this.ws.send(message)
    }
  }

  startHeartbeat() {
    if (this.options.heartbeatInterval > 0) {
      this.heartbeatTimer = setInterval(() => {
        if (this.isConnected.value && this.ws) {
          this.ws.send('ping')
        }
      }, this.options.heartbeatInterval)
    }
  }

  stopHeartbeat() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer)
      this.heartbeatTimer = null
    }
  }

  handleHeartbeat() {
    console.log('收到心跳响应')
  }

  calculateReconnectDelay() {
    if (!this.options.enableExponentialBackoff) {
      return this.options.reconnectInterval
    }
    
    const baseDelay = this.options.reconnectInterval
    const exponentialDelay = baseDelay * Math.pow(2, this.reconnectAttempts)
    const jitter = Math.random() * 1000
    
    return Math.min(exponentialDelay + jitter, this.options.maxReconnectDelay)
  }

  scheduleReconnect() {
    if (this.reconnectAttempts >= this.options.maxReconnectAttempts) {
      console.error('WebSocket重连次数超过最大限制')
      this.isReconnecting.value = false
      this.reconnectStatus.value = `重连失败，已达最大重试次数(${this.options.maxReconnectAttempts}次)`
      this.connectionStatus.value = 'failed'
      this.emit('reconnect_failed', { attempts: this.reconnectAttempts })
      this.emit('statusChange', this.getStatus())
      return
    }

    this.reconnectAttempts++
    this.isReconnecting.value = true
    
    const delay = this.calculateReconnectDelay()
    const delayInSeconds = (delay / 1000).toFixed(1)
    
    this.reconnectStatus.value = `正在重连... (${this.reconnectAttempts}/${this.options.maxReconnectAttempts})，${delayInSeconds}秒后重试`
    this.connectionStatus.value = 'reconnecting'
    
    console.log(`WebSocket将在${delayInSeconds}秒后尝试第${this.reconnectAttempts}次重连`)
    
    this.emit('reconnecting', { 
      attempt: this.reconnectAttempts, 
      maxAttempts: this.options.maxReconnectAttempts,
      delay: delay 
    })
    this.emit('statusChange', this.getStatus())
    
    this.reconnectTimer = setTimeout(() => {
      this.connect()
    }, delay)
  }

  handleConnectionError(error) {
    this.isConnecting.value = false
    this.connectionStatus.value = 'error'
    this.emit('error', error)
    this.emit('statusChange', this.getStatus())
    
    if (this.options.reconnect) {
      this.scheduleReconnect()
    }
  }

  manualReconnect() {
    this.reconnectAttempts = 0
    this.isReconnecting.value = false
    this.reconnectStatus.value = ''
    
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
    
    if (this.ws) {
      this.ws.close()
      this.ws = null
    }
    
    this.connect()
  }

  disconnect() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
    
    this.stopHeartbeat()
    
    if (this.ws) {
      this.ws.close(1000, '客户端主动断开')
      this.ws = null
    }
    
    this.isConnected.value = false
    this.isConnecting.value = false
    this.isReconnecting.value = false
    this.reconnectStatus.value = ''
    this.connectionStatus.value = 'disconnected'
    this.messageQueue = []
    this.reconnectAttempts = 0
    this.messageHistory = []
  }

  getStatus() {
    return {
      connected: this.isConnected.value,
      connecting: this.isConnecting.value,
      reconnecting: this.isReconnecting.value,
      reconnectAttempts: this.reconnectAttempts,
      maxReconnectAttempts: this.options.maxReconnectAttempts,
      reconnectStatus: this.reconnectStatus.value,
      connectionStatus: this.connectionStatus.value
    }
  }

  getConnectionStatusText() {
    const statusMap = {
      'connected': '已连接',
      'connecting': '连接中',
      'disconnected': '已断开',
      'reconnecting': '重连中',
      'error': '连接错误',
      'failed': '连接失败'
    }
    return statusMap[this.connectionStatus.value] || this.connectionStatus.value
  }
}

export function useWebSocket(url, options = {}) {
  const wsManager = new WebSocketManager(url, options)
  
  onMounted(() => {
    wsManager.connect()
  })
  
  onUnmounted(() => {
    wsManager.disconnect()
  })
  
  return {
    isConnected: wsManager.isConnected,
    isConnecting: wsManager.isConnecting,
    isReconnecting: wsManager.isReconnecting,
    reconnectStatus: wsManager.reconnectStatus,
    connectionStatus: wsManager.connectionStatus,
    connect: () => wsManager.connect(),
    disconnect: () => wsManager.disconnect(),
    manualReconnect: () => wsManager.manualReconnect(),
    send: (type, payload) => wsManager.send(type, payload),
    on: (event, handler) => wsManager.on(event, handler),
    off: (event, handler) => wsManager.off(event, handler),
    getStatus: () => wsManager.getStatus(),
    getConnectionStatusText: () => wsManager.getConnectionStatusText(),
    sendAck: (messageId) => wsManager.sendAck(messageId),
    requestRetransmit: (messageId) => wsManager.requestRetransmit(messageId),
    requestRecentMessages: (count) => wsManager.requestRecentMessages(count),
    verifyMessage: (message) => wsManager.verifyMessage(message),
    messageHistory: wsManager.messageHistory
  }
}

export default {
  WebSocketManager,
  useWebSocket
}
