<template>
  <div class="ai-chat-floater" :style="floaterStyle">
    <div
      ref="floaterButton"
      class="floater-button"
      :class="{ 'expanded': isExpanded, 'dragging': isDragging }"
      @mousedown="startDrag"
      @touchstart="startDrag"
      @click="handleButtonClick"
    >
      <div class="button-ripple"></div>
      <el-icon v-if="!isExpanded" :size="28" color="#fff">
        <ChatDotRound />
      </el-icon>
      <el-icon v-else :size="28" color="#fff">
        <Close />
      </el-icon>
      <div v-if="hasUnreadMessages && !isExpanded" class="unread-badge">
        {{ unreadCount > 9 ? '9+' : unreadCount }}
      </div>
    </div>

    <transition name="chat-panel">
      <div v-if="isExpanded" ref="chatPanel" class="chat-panel" :style="panelStyle" @mousedown="startPanelDrag">
        <div class="panel-drag-handle">
          <div class="drag-indicator"></div>
        </div>
        <div class="panel-header">
          <div class="header-title">
            <div class="title-icon">
              <el-icon :size="20" color="#fff">
                <ChatDotRound />
              </el-icon>
            </div>
            <div class="title-text">
              <span class="title-main">AI 对话助手</span>
              <span class="title-sub">
                <span 
                  class="connection-status" 
                  :class="{
                    'connected': aiConnectionStatus?.connection_test === 'success',
                    'disconnected': aiConnectionStatus?.connection_test === 'failed',
                    'checking': !aiConnectionStatus || aiConnectionStatus?.connection_test === 'not_tested'
                  }"
                >
                  <span class="status-dot"></span>
                  {{ getConnectionStatusText() }}
                </span>
              </span>
            </div>
          </div>
          <div class="header-actions">
            <el-tooltip content="测试AI连接" placement="bottom">
              <button
                class="action-btn"
                @click="testAIConnection"
                :disabled="isTestingConnection"
              >
                <el-icon :class="{ 'is-loading': isTestingConnection }"><Connection /></el-icon>
              </button>
            </el-tooltip>
            <el-tooltip content="清空对话" placement="bottom">
              <button
                v-if="messages.length > 0"
                class="action-btn"
                @click="clearHistory"
              >
                <el-icon><Delete /></el-icon>
              </button>
            </el-tooltip>
            <el-tooltip content="最小化" placement="bottom">
              <button class="action-btn" @click="toggleChat">
                <el-icon><Minus /></el-icon>
              </button>
            </el-tooltip>
          </div>
        </div>

        <div class="panel-body">
          <div v-if="isLoading" class="loading-state">
            <div class="loading-spinner">
              <div class="spinner-ring"></div>
              <div class="spinner-ring"></div>
              <div class="spinner-ring"></div>
            </div>
            <p>连接中...</p>
          </div>

          <div v-else-if="messages.length === 0" class="empty-state">
            <div class="empty-icon">
              <el-icon :size="56" color="#C0C4CC">
                <ChatDotRound />
              </el-icon>
            </div>
            <p class="empty-title">开始与AI助手对话</p>
            <p class="empty-hint">您可以询问漏洞分析、POC生成等问题</p>
            <div class="quick-actions">
              <button 
              v-for="action in quickActions" 
              :key="action.text"
              class="quick-action-btn"
              @click="sendQuickAction(action.text)"
            >
              <component :is="action.icon" :size="14" />
              {{ action.text }}
            </button>
            </div>
          </div>

          <div v-else ref="messagesContainer" class="messages-container">
            <div
              v-for="(message, index) in messages"
              :key="message.id || index"
              :class="['message-item', message.role]"
            >
              <div class="message-avatar" :class="message.role">
                <el-avatar v-if="message.role === 'user'" :size="36" color="#409EFF">
                  <el-icon :size="18"><User /></el-icon>
                </el-avatar>
                <el-avatar v-else :size="36" color="#67C23A">
                  <el-icon :size="18"><ChatDotRound /></el-icon>
                </el-avatar>
              </div>
              <div class="message-content">
                <div class="message-info">
                  <span class="message-role">{{ message.role === 'user' ? '我' : 'AI助手' }}</span>
                  <span class="message-time">{{ formatTime(message.timestamp) }}</span>
                </div>
                <div class="message-bubble">
                  <div class="message-text" v-html="formatMessage(message.content)"></div>
                  <div v-if="message.role === 'assistant'" class="message-actions">
                    <button class="msg-action-btn" @click="copyMessage(message.content)" title="复制">
                      <el-icon :size="14"><DocumentCopy /></el-icon>
                    </button>
                  </div>
                </div>
              </div>
            </div>
            <div v-if="isTyping" class="message-item assistant typing">
              <div class="message-avatar assistant">
                <el-avatar :size="36" color="#67C23A">
                  <el-icon :size="18"><ChatDotRound /></el-icon>
                </el-avatar>
              </div>
              <div class="message-content">
                <div class="message-bubble">
                  <div class="typing-indicator">
                    <span></span>
                    <span></span>
                    <span></span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div class="panel-footer">
          <div 
            class="input-resize-handle"
            @mousedown="startInputResize"
            v-if="isExpanded"
          >
            <div class="resize-line"></div>
          </div>
          <div 
            class="input-wrapper" 
            :class="{ 'focused': isInputFocused }"
            :style="{ height: inputHeight + 'px' }"
          >
            <el-input
              ref="inputRef"
              v-model="inputMessage"
              type="textarea"
              :rows="2"
              :autosize="false"
              :style="{ height: '100%' }"
              placeholder="输入您的问题... (Enter发送, Shift+Enter换行)"
              :disabled="isSending"
              @focus="isInputFocused = true"
              @blur="isInputFocused = false"
              @keydown.enter.exact.prevent="sendMessage"
              @keydown.enter.shift.exact="inputMessage += '\n'"
            />
          </div>
          <div class="footer-actions">
            <div class="footer-hint">
              <span v-if="isSending" class="sending-hint">
                <el-icon :size="14" class="is-loading">
                  <Loading />
                </el-icon>
                AI正在思考...
              </span>
              <span v-else class="char-count">
                {{ inputMessage.length }} / 500
              </span>
            </div>
            <el-button
              type="primary"
              class="send-btn"
              :disabled="!inputMessage.trim() || isSending || inputMessage.length > 500"
              @click="sendMessage"
            >
              <el-icon class="send-icon" :class="{ 'sending': isSending }"><Promotion /></el-icon>
              发送
            </el-button>
          </div>
        </div>
      </div>
    </transition>
  </div>
</template>

<script setup>
import { ref, computed, watch, nextTick, onMounted, onUnmounted } from 'vue'
import { ElMessage } from 'element-plus'
import {
  ChatDotRound,
  Close,
  Loading,
  User,
  Promotion,
  Delete,
  Minus,
  DocumentCopy,
  Warning,
  Search,
  Document,
  Connection
} from '@element-plus/icons-vue'

const isExpanded = ref(false)
const messages = ref([])
const inputMessage = ref('')
const messagesContainer = ref(null)
const inputRef = ref(null)
const isLoading = ref(false)
const isSending = ref(false)
const isTyping = ref(false)
const isInputFocused = ref(false)
const ws = ref(null)
const hasUnreadMessages = ref(false)
const unreadCount = ref(0)
const aiConnectionStatus = ref(null)
const chatInstanceId = ref(null)
const isTestingConnection = ref(false)

const isDragging = ref(false)
const dragStartPos = ref({ x: 0, y: 0 })
const floaterPos = ref({ x: 24, y: 24 })
const inputHeight = ref(80)
const isResizingInput = ref(false)
const resizeStartY = ref(0)
const resizeStartHeight = ref(0)
const API_BASE_ORIGIN = (() => {
  const url = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8888'
  try {
    const u = new URL(url)
    return u.origin
  } catch {
    return url.replace(/\/api\/?$/, '').replace(/\/+$/, '')
  }
})()
const STORAGE_KEY = 'ai_chat_history'
const POSITION_KEY = 'ai_chat_floater_position'
const PANEL_POSITION_KEY = 'ai_chat_panel_position'

const isPanelDragging = ref(false)
const panelDragStart = ref({ x: 0, y: 0 })
const panelPos = ref({ x: 0, y: 0 })
const chatPanel = ref(null)

const quickActions = [
  { text: '漏洞分析', icon: Warning },
  { text: 'POC生成', icon: Document },
  { text: '安全建议', icon: Search }
]

const floaterStyle = computed(() => ({
  right: `${floaterPos.value.x}px`,
  bottom: `${floaterPos.value.y}px`
}))

const panelStyle = computed(() => {
  const isNearRight = floaterPos.value.x < 450
  const isNearBottom = floaterPos.value.y < 450
  return {
    right: isNearRight ? 'auto' : '0',
    left: isNearRight ? '0' : 'auto',
    bottom: isNearBottom ? 'auto' : '72px',
    top: isNearBottom ? '-420px' : 'auto',
    transform: `translate(${panelPos.value.x}px, ${panelPos.value.y}px)`,
    transition: isPanelDragging.value ? 'none' : 'transform 0.2s ease'
  }
})

const loadPosition = () => {
  try {
    const saved = localStorage.getItem(POSITION_KEY)
    if (saved) {
      const pos = JSON.parse(saved)
      floaterPos.value = {
        x: Math.max(24, Math.min(window.innerWidth - 80, pos.x)),
        y: Math.max(24, Math.min(window.innerHeight - 80, pos.y))
      }
    }
  } catch (error) {
    console.error('加载位置失败:', error)
  }
}

const savePosition = () => {
  try {
    localStorage.setItem(POSITION_KEY, JSON.stringify(floaterPos.value))
  } catch (error) {
    console.error('保存位置失败:', error)
  }
}

const startDrag = (e) => {
  if (isExpanded.value) return
  
  e.preventDefault()
  isDragging.value = true
  
  const clientX = e.type === 'touchstart' ? e.touches[0].clientX : e.clientX
  const clientY = e.type === 'touchstart' ? e.touches[0].clientY : e.clientY
  
  dragStartPos.value = {
    x: clientX + floaterPos.value.x,
    y: clientY + floaterPos.value.y
  }
  
  document.addEventListener('mousemove', onDrag)
  document.addEventListener('mouseup', endDrag)
  document.addEventListener('touchmove', onDrag)
  document.addEventListener('touchend', endDrag)
}

const onDrag = (e) => {
  if (!isDragging.value) return
  
  const clientX = e.type === 'touchmove' ? e.touches[0].clientX : e.clientX
  const clientY = e.type === 'touchmove' ? e.touches[0].clientY : e.clientY
  
  const newX = dragStartPos.value.x - clientX
  const newY = dragStartPos.value.y - clientY
  
  floaterPos.value = {
    x: Math.max(24, Math.min(window.innerWidth - 80, newX)),
    y: Math.max(24, Math.min(window.innerHeight - 80, newY))
  }
}

const endDrag = () => {
  isDragging.value = false
  savePosition()
  
  document.removeEventListener('mousemove', onDrag)
  document.removeEventListener('mouseup', endDrag)
  document.removeEventListener('touchmove', onDrag)
  document.removeEventListener('touchend', endDrag)
}

const loadPanelPosition = () => {
  try {
    const saved = localStorage.getItem(PANEL_POSITION_KEY)
    if (saved) {
      panelPos.value = JSON.parse(saved)
    }
  } catch (error) {
    console.error('加载面板位置失败:', error)
  }
}

const savePanelPosition = () => {
  try {
    localStorage.setItem(PANEL_POSITION_KEY, JSON.stringify(panelPos.value))
  } catch (error) {
    console.error('保存面板位置失败:', error)
  }
}

const startPanelDrag = (e) => {
  if (!e.target.closest('.panel-drag-handle')) return
  
  e.preventDefault()
  isPanelDragging.value = true
  
  const clientX = e.type === 'touchstart' ? e.touches[0].clientX : e.clientX
  const clientY = e.type === 'touchstart' ? e.touches[0].clientY : e.clientY
  
  panelDragStart.value = {
    x: clientX - panelPos.value.x,
    y: clientY - panelPos.value.y
  }
  
  document.addEventListener('mousemove', onPanelDrag)
  document.addEventListener('mouseup', endPanelDrag)
  document.addEventListener('touchmove', onPanelDrag)
  document.addEventListener('touchend', endPanelDrag)
}

const onPanelDrag = (e) => {
  if (!isPanelDragging.value) return
  
  const clientX = e.type === 'touchmove' ? e.touches[0].clientX : e.clientX
  const clientY = e.type === 'touchmove' ? e.touches[0].clientY : e.clientY
  
  panelPos.value = {
    x: clientX - panelDragStart.value.x,
    y: clientY - panelDragStart.value.y
  }
}

const endPanelDrag = () => {
  isPanelDragging.value = false
  savePanelPosition()
  
  document.removeEventListener('mousemove', onPanelDrag)
  document.removeEventListener('mouseup', endPanelDrag)
}

const startInputResize = (e) => {
  e.preventDefault()
  isResizingInput.value = true
  resizeStartY.value = e.clientY
  resizeStartHeight.value = inputHeight.value
  
  document.addEventListener('mousemove', onInputResize)
  document.addEventListener('mouseup', endInputResize)
}

const onInputResize = (e) => {
  if (!isResizingInput.value) return
  
  const deltaY = resizeStartY.value - e.clientY
  const newHeight = Math.min(Math.max(resizeStartHeight.value + deltaY, 60), 200)
  inputHeight.value = newHeight
}

const endInputResize = () => {
  isResizingInput.value = false
  
  document.removeEventListener('mousemove', onInputResize)
  document.removeEventListener('mouseup', endInputResize)
  
  localStorage.setItem('ai_chat_input_height', inputHeight.value.toString())
}

const handleButtonClick = (e) => {
  if (isDragging.value) return
  toggleChat()
}

const toggleChat = () => {
  isExpanded.value = !isExpanded.value
  if (isExpanded.value) {
    hasUnreadMessages.value = false
    unreadCount.value = 0
    fetchAIConnectionStatus()
    connectWebSocket()
    nextTick(() => {
      if (inputRef.value && typeof inputRef.value.focus === 'function') {
        inputRef.value.focus()
      }
    })
  } else {
    disconnectWebSocket()
  }
}

const fetchAIConnectionStatus = async () => {
  try {
    const token = localStorage.getItem('token')
    const response = await fetch(`${API_BASE_ORIGIN}/api/ai/connection-status`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    })
    const data = await response.json()
    if (data.code === 200 && data.data) {
      aiConnectionStatus.value = data.data
      console.log('AI连接状态:', data.data)
    }
  } catch (error) {
    console.error('获取AI连接状态失败:', error)
    aiConnectionStatus.value = {
      configured: false,
      connection_test: 'failed',
      error_message: '无法获取连接状态'
    }
  }
}

const getConnectionStatusText = () => {
  if (!aiConnectionStatus.value) return '检测中...'
  if (aiConnectionStatus.value.connection_test === 'success') return '已连接'
  if (aiConnectionStatus.value.connection_test === 'failed') return '连接失败'
  if (!aiConnectionStatus.value.configured) return '未配置'
  return '检测中...'
}

const testAIConnection = async () => {
  isTestingConnection.value = true
  try {
    const token = localStorage.getItem('token')
    const response = await fetch(`${API_BASE_ORIGIN}/api/ai/test-analysis`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    })
    const data = await response.json()
    if (data.code === 200 && data.data?.test_passed) {
      ElMessage.success('AI连接测试成功')
      aiConnectionStatus.value = {
        ...aiConnectionStatus.value,
        connection_test: 'success'
      }
    } else {
      ElMessage.error('AI连接测试失败: ' + (data.message || '未知错误'))
      aiConnectionStatus.value = {
        ...aiConnectionStatus.value,
        connection_test: 'failed'
      }
    }
  } catch (error) {
    console.error('测试AI连接失败:', error)
    ElMessage.error('AI连接测试失败')
  } finally {
    isTestingConnection.value = false
  }
}

const loadHistory = () => {
  try {
    const history = localStorage.getItem(STORAGE_KEY)
    if (history) {
      messages.value = JSON.parse(history)
    }
  } catch (error) {
    console.error('加载聊天历史失败:', error)
  }
}

const saveHistory = () => {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(messages.value))
  } catch (error) {
    console.error('保存聊天历史失败:', error)
  }
}

const clearHistory = () => {
  messages.value = []
  localStorage.removeItem(STORAGE_KEY)
  ElMessage.success('聊天历史已清空')
}

const connectWebSocket = () => {
  if (ws.value && ws.value.readyState === WebSocket.OPEN) {
    return
  }

  isLoading.value = true

  const token = localStorage.getItem('token')
  const wsUrl = `${API_BASE_ORIGIN.replace(/^http/, 'ws')}/api/ws?token=${token}`

  try {
    ws.value = new WebSocket(wsUrl)

    ws.value.onopen = () => {
      console.log('AI聊天WebSocket连接成功')
      isLoading.value = false
    }

    ws.value.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data)
            
            if (data.type === 'chat_response' || data.type === 'ai_response') {
              isTyping.value = false
              messages.value.push({
                id: Date.now(),
                role: 'assistant',
                content: data.content || data.message,
                timestamp: data.created_at ? new Date(data.created_at) : new Date()
              })
              
              saveHistory()
              scrollToBottom()
              
              if (!isExpanded.value) {
                hasUnreadMessages.value = true
                unreadCount.value++
              }
            } else if (data.type === 'chat_instance_created') {
              chatInstanceId.value = data.instance_id
            } else if (data.type === 'typing') {
              isTyping.value = true
              scrollToBottom()
            } else if (data.type === 'error') {
              isTyping.value = false
              ElMessage.error(data.message || '发生错误')
              isSending.value = false
            }
          } catch (error) {
            console.error('处理WebSocket消息失败:', error)
            isSending.value = false
            isTyping.value = false
          }
        }

    ws.value.onerror = (error) => {
      console.error('WebSocket错误:', error)
      isLoading.value = false
      isSending.value = false
      isTyping.value = false
      ElMessage.error('连接失败，请检查网络')
    }

    ws.value.onclose = () => {
      console.log('WebSocket连接关闭')
      isLoading.value = false
      isSending.value = false
      isTyping.value = false
    }
  } catch (error) {
    console.error('创建WebSocket连接失败:', error)
    isLoading.value = false
    ElMessage.error('无法建立连接')
  }
}

const disconnectWebSocket = () => {
  if (ws.value) {
    ws.value.close()
    ws.value = null
  }
}

const sendMessage = async () => {
  const message = inputMessage.value.trim()
  if (!message || isSending.value || message.length > 500) {
    return
  }

  isSending.value = true
  isTyping.value = true

  const userMessage = {
    id: Date.now(),
    role: 'user',
    content: message,
    timestamp: new Date()
  }

  messages.value.push(userMessage)
  saveHistory()
  scrollToBottom()

  inputMessage.value = ''

  try {
    const token = localStorage.getItem('token')
    
    if (ws.value && ws.value.readyState === WebSocket.OPEN) {
      ws.value.send(JSON.stringify({
        type: 'chat_message',
        message: message,
        token: token
      }))
    } else {
      await sendViaAPI(message, token)
    }
  } catch (error) {
    console.error('发送消息失败:', error)
    isSending.value = false
    isTyping.value = false
    ElMessage.error('发送失败，请重试')
  }
}

const sendQuickAction = (text) => {
  inputMessage.value = text
  sendMessage()
}

const sendViaAPI = async (message, token) => {
  try {
    const response = await fetch(`${API_BASE_ORIGIN}/api/ai/chat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({ message })
    })

    const data = await response.json()
    
    isTyping.value = false
    
    if (data.code === 200 && data.data) {
      messages.value.push({
        id: Date.now(),
        role: 'assistant',
        content: data.data.response || data.data.message || '处理完成',
        timestamp: new Date()
      })
      saveHistory()
      scrollToBottom()
    } else {
      throw new Error(data.message || '请求失败')
    }
  } catch (error) {
    console.error('API请求失败:', error)
    ElMessage.error('发送失败，请重试')
  } finally {
    isSending.value = false
  }
}

const scrollToBottom = () => {
  nextTick(() => {
    if (messagesContainer.value) {
      messagesContainer.value.scrollTo({
        top: messagesContainer.value.scrollHeight,
        behavior: 'smooth'
      })
    }
  })
}

const formatTime = (date) => {
  if (!date) return '--:--'
  try {
    const d = date instanceof Date ? date : new Date(date)
    if (isNaN(d.getTime())) return '--:--'
    const hours = d.getHours().toString().padStart(2, '0')
    const minutes = d.getMinutes().toString().padStart(2, '0')
    return `${hours}:${minutes}`
  } catch {
    return '--:--'
  }
}

const formatMessage = (content) => {
  if (!content) return ''
  return content
    .replace(/```(\w*)\n?([\s\S]*?)```/g, '<pre class="code-block"><code>$2</code></pre>')
    .replace(/`([^`]+)`/g, '<code class="inline-code">$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\n/g, '<br>')
}

const copyMessage = async (content) => {
  try {
    await navigator.clipboard.writeText(content)
    ElMessage.success('已复制到剪贴板')
  } catch (error) {
    ElMessage.error('复制失败')
  }
}

watch(isExpanded, (newVal) => {
  if (newVal) {
    loadHistory()
    nextTick(() => {
      scrollToBottom()
    })
  }
})

onMounted(() => {
  loadPosition()
  loadPanelPosition()
  loadHistory()
})

onUnmounted(() => {
  disconnectWebSocket()
  document.removeEventListener('mousemove', onDrag)
  document.removeEventListener('mouseup', endDrag)
  document.removeEventListener('touchmove', onDrag)
  document.removeEventListener('touchend', endDrag)
})
</script>

<style scoped>
.ai-chat-floater {
  position: fixed;
  z-index: 9999;
}

.floater-button {
  width: 60px;
  height: 60px;
  border-radius: 50%;
  background: linear-gradient(135deg, #409EFF 0%, #66B1FF 50%, #409EFF 100%);
  background-size: 200% 200%;
  box-shadow: 0 4px 20px rgba(64, 158, 255, 0.4), 0 0 0 0 rgba(64, 158, 255, 0.4);
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  position: relative;
  overflow: hidden;
  animation: gradientShift 3s ease infinite;
}

@keyframes gradientShift {
  0%, 100% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
}

.floater-button:hover:not(.dragging) {
  transform: scale(1.1);
  box-shadow: 0 6px 24px rgba(64, 158, 255, 0.5), 0 0 0 8px rgba(64, 158, 255, 0.1);
}

.floater-button:active:not(.dragging) {
  transform: scale(0.95);
}

.floater-button.expanded {
  background: linear-gradient(135deg, #F56C6C 0%, #F78989 100%);
  box-shadow: 0 4px 20px rgba(245, 108, 108, 0.4);
  animation: none;
}

.floater-button.dragging {
  cursor: grabbing;
  transform: scale(1.15);
  box-shadow: 0 8px 32px rgba(64, 158, 255, 0.6);
}

.button-ripple {
  position: absolute;
  top: 50%;
  left: 50%;
  width: 0;
  height: 0;
  background: rgba(255, 255, 255, 0.3);
  border-radius: 50%;
  transform: translate(-50%, -50%);
  transition: width 0.6s, height 0.6s;
}

.floater-button:active .button-ripple {
  width: 120px;
  height: 120px;
}

.unread-badge {
  position: absolute;
  top: -4px;
  right: -4px;
  min-width: 20px;
  height: 20px;
  background: #F56C6C;
  color: #fff;
  font-size: 12px;
  font-weight: 600;
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 0 6px;
  animation: badgePulse 2s ease infinite;
}

@keyframes badgePulse {
  0%, 100% { transform: scale(1); }
  50% { transform: scale(1.1); }
}

.chat-panel {
  position: absolute;
  width: 420px;
  height: 520px;
  background: #ffffff;
  border-radius: 16px;
  box-shadow: 0 12px 48px rgba(0, 0, 0, 0.12), 0 0 0 1px rgba(0, 0, 0, 0.05);
  display: flex;
  flex-direction: column;
  overflow: hidden;
  cursor: default;
}

.panel-drag-handle {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 12px;
  background: transparent;
  cursor: move;
  z-index: 10;
  display: flex;
  align-items: center;
  justify-content: center;
  padding-top: 4px;
}

.drag-indicator {
  width: 40px;
  height: 4px;
  background: rgba(0, 0, 0, 0.15);
  border-radius: 2px;
}

.panel-drag-handle:hover .drag-indicator {
  background: rgba(0, 0, 0, 0.25);
}

.panel-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px 20px;
  background: linear-gradient(135deg, #409EFF 0%, #66B1FF 100%);
  color: #ffffff;
  flex-shrink: 0;
}

.header-title {
  display: flex;
  align-items: center;
  gap: 12px;
}

.title-icon {
  width: 40px;
  height: 40px;
  background: rgba(255, 255, 255, 0.2);
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.title-text {
  display: flex;
  flex-direction: column;
}

.title-main {
  font-size: 16px;
  font-weight: 600;
  letter-spacing: 0.5px;
}

.title-sub {
  font-size: 12px;
  opacity: 0.8;
  margin-top: 2px;
}

.connection-status {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 11px;
  font-weight: 500;
}

.connection-status .status-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  animation: pulse 2s ease-in-out infinite;
}

.connection-status.connected {
  background: rgba(103, 194, 58, 0.2);
  color: #67C23A;
}

.connection-status.connected .status-dot {
  background: #67C23A;
}

.connection-status.disconnected {
  background: rgba(245, 108, 108, 0.2);
  color: #F56C6C;
}

.connection-status.disconnected .status-dot {
  background: #F56C6C;
  animation: none;
}

.connection-status.checking {
  background: rgba(230, 162, 60, 0.2);
  color: #E6A23C;
}

.connection-status.checking .status-dot {
  background: #E6A23C;
}

@keyframes pulse {
  0%, 100% { opacity: 1; transform: scale(1); }
  50% { opacity: 0.6; transform: scale(0.9); }
}

.header-actions {
  display: flex;
  gap: 8px;
}

.action-btn {
  width: 32px;
  height: 32px;
  background: rgba(255, 255, 255, 0.2);
  border: none;
  border-radius: 8px;
  color: #fff;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.2s;
}

.action-btn:hover {
  background: rgba(255, 255, 255, 0.3);
  transform: scale(1.05);
}

.panel-body {
  flex: 1;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  background: #F8FAFC;
}

.loading-state,
.empty-state {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 40px 20px;
}

.loading-spinner {
  width: 48px;
  height: 48px;
  position: relative;
}

.spinner-ring {
  position: absolute;
  width: 100%;
  height: 100%;
  border: 3px solid transparent;
  border-top-color: #409EFF;
  border-radius: 50%;
  animation: spin 1s linear infinite;
}

.spinner-ring:nth-child(2) {
  width: 80%;
  height: 80%;
  top: 10%;
  left: 10%;
  border-top-color: #67C23A;
  animation-delay: 0.2s;
}

.spinner-ring:nth-child(3) {
  width: 60%;
  height: 60%;
  top: 20%;
  left: 20%;
  border-top-color: #E6A23C;
  animation-delay: 0.4s;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.loading-state p {
  margin-top: 20px;
  font-size: 14px;
  color: #909399;
}

.empty-icon {
  width: 80px;
  height: 80px;
  background: linear-gradient(135deg, #EBF5FF 0%, #E1F0FF 100%);
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 16px;
}

.empty-title {
  font-size: 16px;
  font-weight: 500;
  color: #303133;
  margin-bottom: 8px;
}

.empty-hint {
  font-size: 13px;
  color: #909399;
  margin-bottom: 24px;
}

.quick-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  justify-content: center;
}

.quick-action-btn {
  padding: 8px 16px;
  background: #fff;
  border: 1px solid #E4E7ED;
  border-radius: 20px;
  font-size: 13px;
  color: #606266;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 6px;
  transition: all 0.2s;
}

.quick-action-btn:hover {
  background: #409EFF;
  border-color: #409EFF;
  color: #fff;
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(64, 158, 255, 0.3);
}

.messages-container {
  flex: 1;
  overflow-y: auto;
  padding: 16px;
  scroll-behavior: smooth;
}

.messages-container::-webkit-scrollbar {
  width: 6px;
}

.messages-container::-webkit-scrollbar-track {
  background: transparent;
}

.messages-container::-webkit-scrollbar-thumb {
  background: #DCDFE6;
  border-radius: 3px;
}

.messages-container::-webkit-scrollbar-thumb:hover {
  background: #C0C4CC;
}

.message-item {
  display: flex;
  gap: 12px;
  margin-bottom: 20px;
  animation: messageSlideIn 0.3s ease-out;
}

.message-item.user {
  flex-direction: row-reverse;
}

.message-item.assistant {
  flex-direction: row;
}

@keyframes messageSlideIn {
  from {
    opacity: 0;
    transform: translateY(16px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

.message-avatar {
  flex-shrink: 0;
}

.message-avatar.user :deep(.el-avatar) {
  background: linear-gradient(135deg, #409EFF 0%, #66B1FF 100%);
}

.message-avatar.assistant :deep(.el-avatar) {
  background: linear-gradient(135deg, #67C23A 0%, #85CE61 100%);
}

.message-content {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
}

.message-item.user .message-content {
  align-items: flex-end;
}

.message-item.assistant .message-content {
  align-items: flex-start;
}

.message-info {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 6px;
}

.message-item.user .message-info {
  flex-direction: row-reverse;
}

.message-role {
  font-size: 13px;
  font-weight: 600;
  color: #606266;
}

.message-item.user .message-role {
  color: #409EFF;
}

.message-item.assistant .message-role {
  color: #67C23A;
}

.message-time {
  font-size: 11px;
  color: #C0C4CC;
}

.message-bubble {
  position: relative;
  max-width: 85%;
}

.message-text {
  padding: 12px 16px;
  border-radius: 12px;
  line-height: 1.7;
  word-wrap: break-word;
  font-size: 14px;
  text-align: left;
  display: inline-block;
  width: fit-content;
  max-width: 100%;
}

.message-item.user .message-text {
  background: linear-gradient(135deg, #409EFF 0%, #66B1FF 100%);
  color: #ffffff;
  border-bottom-right-radius: 4px;
  border-bottom-left-radius: 12px;
}

.message-item.assistant .message-text {
  background: #ffffff;
  color: #303133;
  border: 1px solid #EBEEF5;
  border-bottom-left-radius: 4px;
}

.message-text :deep(.code-block) {
  background: #1E1E1E;
  color: #D4D4D4;
  padding: 12px;
  border-radius: 8px;
  margin: 8px 0;
  overflow-x: auto;
  font-family: 'Fira Code', 'Consolas', monospace;
  font-size: 13px;
}

.message-text :deep(.inline-code) {
  background: rgba(64, 158, 255, 0.1);
  color: #409EFF;
  padding: 2px 6px;
  border-radius: 4px;
  font-family: 'Fira Code', 'Consolas', monospace;
  font-size: 13px;
}

.message-actions {
  display: flex;
  gap: 8px;
  margin-top: 8px;
  opacity: 0;
  transition: opacity 0.2s;
}

.message-item:hover .message-actions {
  opacity: 1;
}

.msg-action-btn {
  padding: 4px 8px;
  background: #F5F7FA;
  border: 1px solid #EBEEF5;
  border-radius: 6px;
  color: #909399;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 12px;
  transition: all 0.2s;
}

.msg-action-btn:hover {
  background: #409EFF;
  border-color: #409EFF;
  color: #fff;
}

.typing-indicator {
  display: flex;
  gap: 4px;
  padding: 12px 16px;
  background: #ffffff;
  border: 1px solid #EBEEF5;
  border-radius: 12px;
  border-bottom-left-radius: 4px;
}

.typing-indicator span {
  width: 8px;
  height: 8px;
  background: #67C23A;
  border-radius: 50%;
  animation: typingBounce 1.4s ease-in-out infinite;
}

.typing-indicator span:nth-child(2) {
  animation-delay: 0.2s;
}

.typing-indicator span:nth-child(3) {
  animation-delay: 0.4s;
}

@keyframes typingBounce {
  0%, 60%, 100% { transform: translateY(0); }
  30% { transform: translateY(-8px); }
}

.panel-footer {
  padding: 16px;
  background: #ffffff;
  border-top: 1px solid #EBEEF5;
  flex-shrink: 0;
}

.input-wrapper {
  border: 2px solid #E4E7ED;
  border-radius: 12px;
  transition: all 0.2s;
  overflow: hidden;
  min-height: 60px;
  max-height: 200px;
}

.input-resize-handle {
  height: 8px;
  cursor: ns-resize;
  display: flex;
  align-items: center;
  justify-content: center;
  background: transparent;
  transition: background 0.2s;
}

.input-resize-handle:hover {
  background: rgba(64, 158, 255, 0.1);
}

.input-resize-handle .resize-line {
  width: 40px;
  height: 3px;
  background: #DCDFE6;
  border-radius: 2px;
  transition: background 0.2s;
}

.input-resize-handle:hover .resize-line {
  background: #409EFF;
}

.input-wrapper.focused {
  border-color: #409EFF;
  box-shadow: 0 0 0 3px rgba(64, 158, 255, 0.1);
}

.input-wrapper :deep(.el-textarea__inner) {
  border: none;
  padding: 12px;
  font-size: 14px;
  line-height: 1.6;
  resize: none;
  background: transparent;
}

.input-wrapper :deep(.el-textarea__inner:focus) {
  box-shadow: none;
}

.footer-actions {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-top: 12px;
}

.footer-hint {
  font-size: 12px;
  color: #909399;
}

.sending-hint {
  display: flex;
  align-items: center;
  gap: 6px;
  color: #409EFF;
}

.char-count {
  color: #C0C4CC;
}

.send-btn {
  padding: 10px 24px;
  border-radius: 10px;
  font-weight: 500;
  display: flex;
  align-items: center;
  gap: 6px;
  transition: all 0.2s;
}

.send-btn:hover:not(:disabled) {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(64, 158, 255, 0.3);
}

.send-icon {
  transition: transform 0.3s;
}

.send-icon.sending {
  animation: sendPulse 0.6s ease infinite;
}

@keyframes sendPulse {
  0%, 100% { transform: translateX(0); }
  50% { transform: translateX(4px); }
}

.chat-panel-enter-active,
.chat-panel-leave-active {
  transition: all 0.35s cubic-bezier(0.4, 0, 0.2, 1);
}

.chat-panel-enter-from {
  opacity: 0;
  transform: scale(0.9) translateY(20px);
}

.chat-panel-leave-to {
  opacity: 0;
  transform: scale(0.9) translateY(20px);
}

@media (max-width: 768px) {
  .ai-chat-floater {
    right: 16px !important;
    bottom: 16px !important;
  }

  .floater-button {
    width: 52px;
    height: 52px;
  }

  .chat-panel {
    width: calc(100vw - 32px);
    max-width: 380px;
    height: 480px;
    right: 0 !important;
    bottom: 68px !important;
    left: auto !important;
    top: auto !important;
  }

  .panel-body {
    max-height: 320px;
  }
}

@media (max-width: 480px) {
  .chat-panel {
    width: calc(100vw - 16px);
    height: calc(100vh - 100px);
    max-height: 500px;
    border-radius: 12px;
  }

  .panel-header {
    padding: 12px 16px;
  }

  .title-icon {
    width: 36px;
    height: 36px;
  }

  .title-main {
    font-size: 15px;
  }

  .messages-container {
    padding: 12px;
  }

  .message-text {
    font-size: 13px;
    padding: 10px 12px;
  }

  .panel-footer {
    padding: 12px;
  }
}
</style>
