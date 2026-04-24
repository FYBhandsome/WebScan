import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { ElMessage } from 'element-plus'

export const useAIChatStore = defineStore('aiChat', () => {
  const messages = ref([])
  const isConnected = ref(false)
  const sessionId = ref(null)
  const ws = ref(null)
  const isWaitingConfirm = ref(false)
  const confirmationPrompt = ref('')
  const isScanning = ref(false)
  const currentTaskId = ref(null)
  
  const reconnectAttempts = ref(0)
  const maxReconnectAttempts = 5
  const reconnectDelay = 3000
  
  const wsUrl = computed(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = window.location.host
    return `${protocol}//${host}/api/ai-chat/ws`
  })
  
  const connect = () => {
    if (ws.value && ws.value.readyState === WebSocket.OPEN) {
      return
    }
    
    try {
      ws.value = new WebSocket(wsUrl.value)
      
      ws.value.onopen = () => {
        console.log('AI Chat WebSocket 连接成功')
        isConnected.value = true
        reconnectAttempts.value = 0
        ElMessage.success('AI助手已连接')
      }
      
      ws.value.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          handleMessage(data)
        } catch (e) {
          console.error('解析消息失败:', e)
        }
      }
      
      ws.value.onclose = (event) => {
        console.log('AI Chat WebSocket 连接关闭', event)
        isConnected.value = false
        isWaitingConfirm.value = false
        
        if (reconnectAttempts.value < maxReconnectAttempts) {
          reconnectAttempts.value++
          console.log(`尝试重连 (${reconnectAttempts.value}/${maxReconnectAttempts})...`)
          setTimeout(connect, reconnectDelay)
        }
      }
      
      ws.value.onerror = (error) => {
        console.error('AI Chat WebSocket 错误:', error)
        ElMessage.error('AI助手连接失败')
      }
      
    } catch (error) {
      console.error('创建WebSocket连接失败:', error)
      ElMessage.error('无法连接AI助手')
    }
  }
  
  const disconnect = () => {
    if (ws.value) {
      ws.value.close()
      ws.value = null
    }
    isConnected.value = false
    sessionId.value = null
  }
  
  const handleMessage = (data) => {
    const { type, payload } = data
    
    switch (type) {
      case 'connected':
        sessionId.value = payload.session_id
        addSystemMessage(`会话已建立: ${payload.session_id.slice(0, 8)}...`)
        break
        
      case 'ai_message':
        addMessage('assistant', payload.content, { type: 'text' })
        break
        
      case 'decision':
        addMessage('assistant', payload.decision?.reason || 'AI决策中...', {
          type: 'decision',
          decision: payload.decision
        })
        break
        
      case 'progress':
        addMessage('assistant', payload.message, {
          type: 'progress',
          progress: payload
        })
        break
        
      case 'confirmation_required':
        isWaitingConfirm.value = true
        confirmationPrompt.value = payload.prompt
        addMessage('assistant', payload.prompt, { type: 'confirmation' })
        break
        
      case 'tool_execution':
        handleToolExecution(payload)
        break
        
      case 'report_ready':
        addMessage('assistant', '报告已生成完成！', {
          type: 'report_ready',
          report: payload.report
        })
        isScanning.value = false
        break
        
      case 'scan_started':
        currentTaskId.value = payload.task_id
        isScanning.value = true
        addSystemMessage(`开始扫描: ${payload.target}`)
        break
        
      case 'scan_cancelled':
        isScanning.value = false
        isWaitingConfirm.value = false
        addSystemMessage('扫描已取消')
        break
        
      case 'error':
        ElMessage.error(payload.error)
        addMessage('system', `错误: ${payload.error}`, { type: 'error' })
        isScanning.value = false
        break
        
      case 'history':
        if (payload.history && payload.history.length > 0) {
          messages.value = payload.history.map(msg => ({
            role: msg.role,
            content: msg.content,
            timestamp: msg.timestamp,
            type: 'text'
          }))
        }
        break
        
      case 'status':
        if (payload.state) {
          isScanning.value = payload.state.workflow_status === 'running'
        }
        break
        
      default:
        console.log('未处理的消息类型:', type, payload)
    }
  }
  
  const handleToolExecution = (payload) => {
    const { tool_name, status, description, result, error } = payload
    
    if (status === 'started') {
      addMessage('assistant', `正在执行工具: ${tool_name}`, { type: 'tool' })
    } else if (status === 'completed') {
      addMessage('assistant', `工具 ${tool_name} 执行完成`, { type: 'tool', result })
    } else if (status === 'failed') {
      addMessage('assistant', `工具 ${tool_name} 执行失败: ${error}`, { type: 'error' })
    }
  }
  
  const addMessage = (role, content, extra = {}) => {
    messages.value.push({
      role,
      content,
      timestamp: new Date().toISOString(),
      ...extra
    })
  }
  
  const addSystemMessage = (content) => {
    addMessage('system', content, { type: 'system' })
  }
  
  const sendMessage = (type, payload) => {
    if (!ws.value || ws.value.readyState !== WebSocket.OPEN) {
      ElMessage.warning('WebSocket未连接')
      return false
    }
    
    try {
      ws.value.send(JSON.stringify({ type, payload }))
      return true
    } catch (error) {
      console.error('发送消息失败:', error)
      return false
    }
  }
  
  const sendUserInput = (content) => {
    if (sendMessage('user_input', { content })) {
      addMessage('user', content)
    }
  }
  
  const sendUserConfirm = (choice) => {
    if (sendMessage('user_confirm', { choice })) {
      isWaitingConfirm.value = false
      addMessage('user', `用户选择: ${choice}`)
    }
  }
  
  const startScan = (target, scanMode = 'full') => {
    if (sendMessage('start_scan', { target, scan_mode: scanMode })) {
      addMessage('user', `开始扫描目标: ${target}`)
    }
  }
  
  const getHistory = () => {
    sendMessage('get_history', {})
  }
  
  const getStatus = () => {
    sendMessage('get_status', {})
  }
  
  const cancelScan = () => {
    sendMessage('user_cancel', {})
    isScanning.value = false
  }
  
  const clearMessages = () => {
    messages.value = []
  }
  
  return {
    messages,
    isConnected,
    sessionId,
    isWaitingConfirm,
    confirmationPrompt,
    isScanning,
    currentTaskId,
    connect,
    disconnect,
    sendUserInput,
    sendUserConfirm,
    startScan,
    getHistory,
    getStatus,
    cancelScan,
    clearMessages
  }
})
