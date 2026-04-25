import { ref, reactive, computed, onMounted, onUnmounted, watch } from 'vue'
import { useWebSocket } from './websocket'
import { WorkflowDataProcessor } from './workflowData'

export function useWorkflowRealtime(options = {}) {
  const {
    taskId = null,
    autoConnect = true,
    onDataUpdate = null,
    onStatusChange = null,
    onError = null,
    onComplete = null
  } = options

  const workflowData = ref(null)
  const isConnected = ref(false)
  const isConnecting = ref(false)
  const connectionStatus = ref('disconnected')
  const lastUpdateTime = ref(null)
  const error = ref(null)

  const statusHistory = reactive([])
  const maxHistoryLength = 100

  const wsUrl = computed(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = window.location.host
    const baseWsUrl = `${protocol}//${host}/api/workflow/ws`
    return taskId ? `${baseWsUrl}?task_id=${taskId}` : baseWsUrl
  })

  let wsManager = null
  let eventHandlers = []

  const connect = () => {
    if (wsManager) {
      wsManager.disconnect()
    }

    wsManager = useWebSocket(wsUrl.value, {
      reconnect: true,
      reconnectInterval: 2000,
      maxReconnectAttempts: 10,
      heartbeatInterval: 30000,
      enableExponentialBackoff: true,
      maxReconnectDelay: 30000
    })

    setupEventHandlers()
    wsManager.connect()
  }

  const setupEventHandlers = () => {
    const handleConnected = () => {
      isConnected.value = true
      isConnecting.value = false
      connectionStatus.value = 'connected'
      error.value = null
      if (onStatusChange) {
        onStatusChange({ connected: true, status: 'connected' })
      }
    }

    const handleDisconnected = (event) => {
      isConnected.value = false
      connectionStatus.value = 'disconnected'
      if (onStatusChange) {
        onStatusChange({ connected: false, status: 'disconnected', event })
      }
    }

    const handleError = (err) => {
      error.value = err
      connectionStatus.value = 'error'
      if (onError) {
        onError(err)
      }
    }

    const handleTaskUpdate = (payload) => {
      updateWorkflowData(payload)
    }

    const handleTaskProgress = (payload) => {
      updateWorkflowData(payload)
    }

    const handleTaskCompleted = (payload) => {
      updateWorkflowData(payload)
      if (onComplete) {
        onComplete(payload)
      }
    }

    const handleTaskFailed = (payload) => {
      updateWorkflowData(payload)
      error.value = payload.error || '任务执行失败'
      if (onError) {
        onError(payload)
      }
    }

    const handleStageUpdate = (payload) => {
      updateWorkflowData(payload)
    }

    const handleSubgraphProgress = (payload) => {
      updateWorkflowData(payload)
    }

    const handleToolExecution = (payload) => {
      addToHistory({
        type: 'tool_execution',
        timestamp: Date.now(),
        data: payload
      })
    }

    const handlers = [
      { event: 'connected', handler: handleConnected },
      { event: 'disconnected', handler: handleDisconnected },
      { event: 'error', handler: handleError },
      { event: 'task:update', handler: handleTaskUpdate },
      { event: 'task:progress', handler: handleTaskProgress },
      { event: 'task:completed', handler: handleTaskCompleted },
      { event: 'task:failed', handler: handleTaskFailed },
      { event: 'stage:update', handler: handleStageUpdate },
      { event: 'subgraph:progress', handler: handleSubgraphProgress },
      { event: 'tool:execution', handler: handleToolExecution }
    ]

    handlers.forEach(({ event, handler }) => {
      wsManager.on(event, handler)
      eventHandlers.push({ event, handler })
    })

    if (wsManager.isConnected) {
      isConnected.value = wsManager.isConnected.value
      isConnecting.value = wsManager.isConnecting.value
      connectionStatus.value = wsManager.connectionStatus.value
    }
  }

  const updateWorkflowData = (payload) => {
    const processed = WorkflowDataProcessor.processWorkflowData(payload)
    workflowData.value = processed
    lastUpdateTime.value = Date.now()

    addToHistory({
      type: 'data_update',
      timestamp: lastUpdateTime.value,
      status: processed.status,
      progress: processed.progress
    })

    if (onDataUpdate) {
      onDataUpdate(processed)
    }
  }

  const addToHistory = (entry) => {
    statusHistory.push(entry)
    if (statusHistory.length > maxHistoryLength) {
      statusHistory.shift()
    }
  }

  const disconnect = () => {
    if (wsManager) {
      eventHandlers.forEach(({ event, handler }) => {
        wsManager.off(event, handler)
      })
      eventHandlers = []
      wsManager.disconnect()
      wsManager = null
    }
    isConnected.value = false
    connectionStatus.value = 'disconnected'
  }

  const reconnect = () => {
    disconnect()
    connect()
  }

  const sendData = (type, payload = {}) => {
    if (wsManager && isConnected.value) {
      wsManager.send(type, payload)
      return true
    }
    return false
  }

  const subscribeToTask = (newTaskId) => {
    if (newTaskId) {
      sendData('subscribe', { task_id: newTaskId })
    }
  }

  const unsubscribeFromTask = (taskIdToUnsubscribe) => {
    sendData('unsubscribe', { task_id: taskIdToUnsubscribe })
  }

  const clearData = () => {
    workflowData.value = null
    statusHistory.length = 0
    lastUpdateTime.value = null
    error.value = null
  }

  const getConnectionStatusText = () => {
    const statusMap = {
      'connected': '已连接',
      'connecting': '连接中',
      'disconnected': '已断开',
      'reconnecting': '重连中',
      'error': '连接错误',
      'failed': '连接失败'
    }
    return statusMap[connectionStatus.value] || connectionStatus.value
  }

  watch(() => taskId, (newTaskId, oldTaskId) => {
    if (newTaskId && newTaskId !== oldTaskId && isConnected.value) {
      if (oldTaskId) {
        unsubscribeFromTask(oldTaskId)
      }
      subscribeToTask(newTaskId)
    }
  })

  onMounted(() => {
    if (autoConnect) {
      connect()
    }
  })

  onUnmounted(() => {
    disconnect()
  })

  return {
    workflowData,
    isConnected,
    isConnecting,
    connectionStatus,
    lastUpdateTime,
    error,
    statusHistory,
    connect,
    disconnect,
    reconnect,
    sendData,
    subscribeToTask,
    unsubscribeFromTask,
    clearData,
    getConnectionStatusText
  }
}

export function useWorkflowVisualization(options = {}) {
  const {
    taskId = null,
    autoUpdate = true,
    updateInterval = 1000
  } = options

  const realtime = useWorkflowRealtime({
    taskId,
    autoConnect: autoUpdate,
    ...options
  })

  const visualizationData = computed(() => {
    if (!realtime.workflowData.value) return null
    return {
      timeline: WorkflowDataProcessor.getTimelineData(realtime.workflowData.value),
      graph: WorkflowDataProcessor.getGraphVisualizationData(realtime.workflowData.value),
      summary: WorkflowDataProcessor.getExecutionSummary(realtime.workflowData.value)
    }
  })

  const progress = computed(() => {
    return realtime.workflowData.value?.progress || 0
  })

  const status = computed(() => {
    return realtime.workflowData.value?.status || 'pending'
  })

  const isRunning = computed(() => {
    return status.value === 'running'
  })

  const isCompleted = computed(() => {
    return ['completed', 'success'].includes(status.value)
  })

  const isFailed = computed(() => {
    return ['failed', 'error'].includes(status.value)
  })

  return {
    ...realtime,
    visualizationData,
    progress,
    status,
    isRunning,
    isCompleted,
    isFailed
  }
}

export default {
  useWorkflowRealtime,
  useWorkflowVisualization
}
