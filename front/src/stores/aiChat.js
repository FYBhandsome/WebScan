import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { ElMessage } from 'element-plus'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8888'

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
  
  const lastErrorMessage = ref('')
  const lastErrorTime = ref(0)
  
  const showUniqueMessage = (msg) => {
    const now = Date.now()
    const timeDiff = now - lastErrorTime.value
    if (msg === lastErrorMessage.value && timeDiff < 5000) {
      return 
    }
    lastErrorMessage.value = msg
    lastErrorTime.value = now
    ElMessage.error(msg)
  }
  
  const wsUrl = computed(() => {
    let baseUrl = API_BASE_URL.replace(/^http/, 'ws')
    baseUrl = baseUrl.replace(/\/api$/, '')
    return `${baseUrl}/api/ai-chat/ws`
  })
  
  const connect = (reconnectSessionId = null) => {
    if (ws.value && ws.value.readyState === WebSocket.OPEN) {
      return
    }
    
    try {
      let url = wsUrl.value
      if (reconnectSessionId || sessionId.value) {
        const sid = reconnectSessionId || sessionId.value
        url = `${url}?session_id=${sid}`
      }
      ws.value = new WebSocket(url)
      
      ws.value.onopen = () => {
        console.log('AI Chat WebSocket 杩炴帴鎴愬姛')
        isConnected.value = true
        reconnectAttempts.value = 0
        ElMessage.success('AI鍔╂墜宸茶繛鎺?)
      }
      
      ws.value.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          handleMessage(data)
        } catch (e) {
          console.error('瑙ｆ瀽娑堟伅澶辫触:', e)
        }
      }
      
      ws.value.onclose = (event) => {
        console.log('AI Chat WebSocket 杩炴帴鍏抽棴', event)
        isConnected.value = false
        isWaitingConfirm.value = false
        
        if (reconnectAttempts.value < maxReconnectAttempts) {
          reconnectAttempts.value++
          console.log(`灏濊瘯閲嶈繛 (${reconnectAttempts.value}/${maxReconnectAttempts})...`)
          setTimeout(() => connect(sessionId.value), reconnectDelay)
        }
      }
      
      ws.value.onerror = (error) => {
      console.error('AI Chat WebSocket 閿欒:', error)
      showUniqueMessage('AI鍔╂墜杩炴帴澶辫触')
    }
    
  } catch (error) {
    console.error('鍒涘缓WebSocket杩炴帴澶辫触:', error)
    showUniqueMessage('鏃犳硶杩炴帴AI鍔╂墜')
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
        if (payload.reconnected) {
          addSystemMessage(`浼氳瘽宸叉仮澶? ${payload.session_id.slice(0, 8)}...`)
          if (payload.state) {
            isScanning.value = !payload.state.is_complete && payload.state.completed_tasks?.length > 0
          }
          if (payload.pending_interaction) {
            isWaitingConfirm.value = true
            confirmationPrompt.value = payload.pending_interaction.payload?.description || '鏈夊緟澶勭悊鐨勪氦浜掕姹?
            addMessage('assistant', confirmationPrompt.value, { type: 'confirmation', pending: payload.pending_interaction })
          }
        } else {
          addSystemMessage(`浼氳瘽宸插缓绔? ${payload.session_id.slice(0, 8)}...`)
        }
        break
        
      case 'ai_message':
        addMessage('assistant', payload.content, { type: 'text' })
        break
        
      case 'decision':
        addMessage('assistant', payload.decision?.reason || 'AI鍐崇瓥涓?..', {
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
        
      case 'task_executing':
        addMessage('assistant', `姝ｅ湪鎵ц宸ュ叿: ${payload.tool_name} -> ${payload.target}`, { type: 'tool' })
        break
        
      case 'interaction_required':
        isWaitingConfirm.value = true
        confirmationPrompt.value = payload.options?.map(o => `[${o.key}] ${o.label}: ${o.description}`).join('\n') || '璇烽€夋嫨鎿嶄綔'
        addMessage('assistant', `馃搵 涓嬩竴姝? ${payload.next_task}\n馃幆 鐩爣: ${payload.target}\n${payload.tool_params_info ? '鍙傛暟: ' + JSON.stringify(payload.tool_params_info) : ''}`, { 
          type: 'confirmation',
          tool_params_info: payload.tool_params_info,
          auth_status: payload.auth_status,
          options: payload.options
        })
        break
        
      case 'report_ready':
        addMessage('assistant', '鎶ュ憡宸茬敓鎴愬畬鎴愶紒', {
          type: 'report_ready',
          report: payload.report
        })
        isScanning.value = false
        break

      case 'scan_completed':
        isScanning.value = false
        currentTaskId.value = payload.task_id || currentTaskId.value
        addMessage('assistant', '扫描已完成: ' + (payload.target || '未知目标'), {
          type: 'scan_completed',
          scan: payload
        })
        if (typeof window !== 'undefined') {
          window.dispatchEvent(new CustomEvent('ai-chat:scan-completed', {
            detail: payload
          }))
        }
        break

      case 'scan_started':
        currentTaskId.value = payload.task_id
        isScanning.value = true
        addSystemMessage(`寮€濮嬫壂鎻? ${payload.target}`)
        break
        
      case 'scan_cancelled':
        isScanning.value = false
        isWaitingConfirm.value = false
        addSystemMessage('鎵弿宸插彇娑?)
        break
        
      case 'error':
        showUniqueMessage(payload.error)
        addMessage('system', `閿欒: ${payload.error}`, { type: 'error' })
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
        console.log('鏈鐞嗙殑娑堟伅绫诲瀷:', type, payload)
    }
  }
  
  const handleToolExecution = (payload) => {
    const { tool_name, status, description, result, error } = payload
    
    if (status === 'started') {
      addMessage('assistant', `姝ｅ湪鎵ц宸ュ叿: ${tool_name}`, { type: 'tool' })
    } else if (status === 'completed') {
      addMessage('assistant', `宸ュ叿 ${tool_name} 鎵ц瀹屾垚`, { type: 'tool', result })
    } else if (status === 'failed') {
      addMessage('assistant', `宸ュ叿 ${tool_name} 鎵ц澶辫触: ${error}`, { type: 'error' })
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
      ElMessage.warning('WebSocket鏈繛鎺?)
      return false
    }
    
    try {
      ws.value.send(JSON.stringify({ type, payload }))
      return true
    } catch (error) {
      console.error('鍙戦€佹秷鎭け璐?', error)
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
      addMessage('user', `鐢ㄦ埛閫夋嫨: ${choice}`)
    }
  }
  
  const startScan = (target, scanMode = 'full') => {
    if (sendMessage('start_scan', { target, scan_mode: scanMode })) {
      addMessage('user', `寮€濮嬫壂鎻忕洰鏍? ${target}`)
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
