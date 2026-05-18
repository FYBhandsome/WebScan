import { ref, reactive, computed, onMounted, onUnmounted, watch } from 'vue'

const LOG_STORAGE_KEY = 'server-log-cache'
const MAX_LOGS = 2000
const RECONNECT_DELAY = 2000
const MAX_RECONNECT_ATTEMPTS = 10

export function useLogWebSocket(options = {}) {
  const {
    sessionId = null,
    autoConnect = true,
    onLogReceived = null,
    onStatusChange = null,
    onError = null
  } = options

  const logs = ref([])
  const isConnected = ref(false)
  const isConnecting = ref(false)
  const connectionStatus = ref('disconnected')
  const reconnectAttempts = ref(0)
  const error = ref(null)

  let ws = null
  let reconnectTimer = null
  let heartbeatTimer = null
  let clientId = null

  const wsUrl = computed(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = window.location.host
    let url = `${protocol}//${host}/api/logs/ws`
    if (sessionId) {
      url += `?session_id=${sessionId}`
    }
    return url
  })

  const stats = computed(() => {
    const result = { total: logs.value.length }
    const levels = ['debug', 'info', 'warning', 'error', 'success']
    levels.forEach(level => {
      result[level] = logs.value.filter(log => log.level === level).length
    })
    return result
  })

  function loadCache() {
    try {
      const cache = localStorage.getItem(LOG_STORAGE_KEY)
      if (cache) {
        const parsed = JSON.parse(cache)
        if (Array.isArray(parsed)) {
          logs.value = parsed.slice(-MAX_LOGS)
        }
      }
    } catch (e) {
      console.warn('加载日志缓存失败:', e)
    }
  }

  function saveCache() {
    try {
      const toSave = logs.value.slice(-MAX_LOGS)
      localStorage.setItem(LOG_STORAGE_KEY, JSON.stringify(toSave))
    } catch (e) {
      console.warn('保存日志缓存失败:', e)
    }
  }

  function connect() {
    if (ws && (isConnected.value || isConnecting.value)) {
      return
    }

    isConnecting.value = true
    connectionStatus.value = 'connecting'
    error.value = null

    try {
      ws = new WebSocket(wsUrl.value)

      ws.onopen = () => {
        console.log('日志WebSocket连接成功')
        isConnected.value = true
        isConnecting.value = false
        connectionStatus.value = 'connected'
        reconnectAttempts.value = 0
        
        startHeartbeat()
        requestHistory()
        
        if (onStatusChange) {
          onStatusChange({ connected: true, status: 'connected' })
        }
      }

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          handleMessage(data)
        } catch (e) {
          console.error('解析日志消息失败:', e)
        }
      }

      ws.onerror = (err) => {
        console.error('日志WebSocket错误:', err)
        error.value = err
        connectionStatus.value = 'error'
        if (onError) {
          onError(err)
        }
      }

      ws.onclose = (event) => {
        console.log('日志WebSocket关闭:', event.code, event.reason)
        isConnected.value = false
        isConnecting.value = false
        connectionStatus.value = 'disconnected'
        
        stopHeartbeat()
        
        if (onStatusChange) {
          onStatusChange({ connected: false, status: 'disconnected', event })
        }

        if (event.code !== 1000 && reconnectAttempts.value < MAX_RECONNECT_ATTEMPTS) {
          scheduleReconnect()
        }
      }
    } catch (e) {
      console.error('创建WebSocket失败:', e)
      error.value = e
      connectionStatus.value = 'error'
      isConnecting.value = false
    }
  }

  function disconnect() {
    if (reconnectTimer) {
      clearTimeout(reconnectTimer)
      reconnectTimer = null
    }
    stopHeartbeat()
    
    if (ws) {
      ws.close(1000, '客户端主动断开')
      ws = null
    }
    
    isConnected.value = false
    isConnecting.value = false
    connectionStatus.value = 'disconnected'
  }

  function scheduleReconnect() {
    if (reconnectTimer) {
      clearTimeout(reconnectTimer)
    }
    
    reconnectAttempts.value++
    const delay = RECONNECT_DELAY * Math.pow(1.5, reconnectAttempts.value - 1)
    
    console.log(`日志WebSocket将在${delay}ms后尝试第${reconnectAttempts.value}次重连`)
    connectionStatus.value = 'reconnecting'
    
    if (onStatusChange) {
      onStatusChange({ 
        connected: false, 
        status: 'reconnecting', 
        attempt: reconnectAttempts.value 
      })
    }
    
    reconnectTimer = setTimeout(() => {
      connect()
    }, delay)
  }

  function startHeartbeat() {
    stopHeartbeat()
    heartbeatTimer = setInterval(() => {
      if (ws && isConnected.value) {
        send('ping')
      }
    }, 30000)
  }

  function stopHeartbeat() {
    if (heartbeatTimer) {
      clearInterval(heartbeatTimer)
      heartbeatTimer = null
    }
  }

  function handleMessage(data) {
    const { type, payload } = data

    switch (type) {
      case 'connected':
        clientId = payload?.client_id
        console.log('日志服务已连接, client_id:', clientId)
        break
      
      case 'logs:single':
        addLog(payload)
        break
      
      case 'logs:batch':
        if (payload?.logs) {
          payload.logs.forEach(log => addLog(log))
        }
        break
      
      case 'subscribed':
        console.log('已订阅会话:', payload?.session_id)
        break
      
      case 'unsubscribed':
        console.log('已取消订阅:', payload?.session_id)
        break
      
      case 'logs:heartbeat':
      case 'pong':
        break
      
      default:
        if (payload) {
          addLog(payload)
        }
    }
  }

  function addLog(logEntry) {
    if (!logEntry || !logEntry.id) {
      return
    }

    const exists = logs.value.some(log => log.id === logEntry.id)
    if (exists) {
      return
    }

    logs.value.unshift(logEntry)
    
    if (logs.value.length > MAX_LOGS) {
      logs.value = logs.value.slice(0, MAX_LOGS)
    }
    
    saveCache()
    
    if (onLogReceived) {
      onLogReceived(logEntry)
    }
  }

  function send(type, payload = {}) {
    if (ws && isConnected.value) {
      ws.send(JSON.stringify({ type, ...payload }))
    }
  }

  function subscribe(sessionIdToSubscribe) {
    send('subscribe', { session_id: sessionIdToSubscribe })
  }

  function unsubscribe(sessionIdToUnsubscribe) {
    send('unsubscribe', { session_id: sessionIdToUnsubscribe })
  }

  function requestHistory(sessionIdToGet = null) {
    send('get_history', { session_id: sessionIdToGet || sessionId })
  }

  function clearLogs() {
    logs.value = []
    localStorage.removeItem(LOG_STORAGE_KEY)
  }

  function getFilteredLogs(levelFilter = 'all', searchText = '') {
    return logs.value.filter(log => {
      const matchLevel = levelFilter === 'all' || log.level === levelFilter
      const matchSearch = !searchText || 
        log.message?.toLowerCase().includes(searchText.toLowerCase()) ||
        log.node?.toLowerCase().includes(searchText.toLowerCase())
      return matchLevel && matchSearch
    })
  }

  function copyLogs(format = 'text') {
    const text = logs.value
      .map(log => `[${log.timestamp}] [${log.level?.toUpperCase()}] [${log.node}] ${log.message}`)
      .join('\n')
    
    return navigator.clipboard.writeText(text)
  }

  onMounted(() => {
    loadCache()
    if (autoConnect) {
      connect()
    }
  })

  onUnmounted(() => {
    saveCache()
    disconnect()
  })

  watch(() => sessionId, (newId, oldId) => {
    if (newId && newId !== oldId && isConnected.value) {
      if (oldId) {
        unsubscribe(oldId)
      }
      subscribe(newId)
    }
  })

  return {
    logs,
    isConnected,
    isConnecting,
    connectionStatus,
    reconnectAttempts,
    error,
    stats,
    connect,
    disconnect,
    subscribe,
    unsubscribe,
    requestHistory,
    clearLogs,
    getFilteredLogs,
    copyLogs,
    send
  }
}

export default {
  useLogWebSocket
}
