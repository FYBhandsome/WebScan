<template>
  <div class="ai-chat-sidebar" :class="{ 'expanded': isExpanded, 'collapsed': !isExpanded }">
    <div class="chat-toggle" @click="toggleChat">
      <div class="toggle-content">
        <el-icon :size="18" color="#409EFF">
          <ChatDotRound />
        </el-icon>
        <span v-if="!isExpanded" class="toggle-text">AI助手</span>
      </div>
      <el-icon :size="16" class="toggle-arrow" :class="{ 'rotated': isExpanded }">
        <ArrowUp />
      </el-icon>
      <div v-if="hasUnreadMessages && !isExpanded" class="unread-dot"></div>
    </div>

    <transition name="chat-expand">
      <div v-if="isExpanded" class="chat-container">
        <div class="chat-header">
          <div class="header-info">
            <el-icon :size="16" color="#409EFF"><ChatDotRound /></el-icon>
            <span class="header-title">AI 对话助手</span>
          </div>
          <div class="header-status">
            <span 
              class="status-indicator" 
              :class="{
                'connected': aiConnectionStatus?.connection_test === 'success',
                'disconnected': aiConnectionStatus?.connection_test === 'failed',
                'checking': !aiConnectionStatus || aiConnectionStatus?.connection_test === 'not_tested'
              }"
            >
              <span class="status-dot"></span>
              {{ getConnectionStatusText() }}
            </span>
          </div>
        </div>

        <div class="chat-body">
          <div v-if="isLoading" class="loading-state">
            <el-icon class="is-loading" :size="24" color="#409EFF">
              <Loading />
            </el-icon>
            <span>连接中...</span>
          </div>

          <div v-else-if="messages.length === 0" class="empty-state">
            <div class="empty-icon">
              <el-icon :size="32" color="#C0C4CC">
                <ChatDotRound />
              </el-icon>
            </div>
            <p class="empty-text">开始与AI助手对话</p>
            <div class="quick-actions">
              <button 
                v-for="action in quickActions" 
                :key="action.text"
                class="quick-btn"
                @click="sendQuickAction(action.text)"
              >
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
              <div class="message-bubble">
                <div class="message-text" v-html="formatMessage(message.content)"></div>
                <div class="message-time">{{ formatTime(message.timestamp) }}</div>
              </div>
            </div>
            <div v-if="isTyping" class="message-item assistant">
              <div class="message-bubble typing">
                <div class="typing-indicator">
                  <span></span>
                  <span></span>
                  <span></span>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div class="chat-footer">
          <div class="input-area">
            <el-input
              v-model="inputMessage"
              type="textarea"
              :rows="2"
              :autosize="{ minRows: 2, maxRows: 4 }"
              placeholder="输入问题..."
              :disabled="isSending"
              @keydown.enter.exact.prevent="sendMessage"
            />
          </div>
          <div class="footer-actions">
            <el-button
              v-if="messages.length > 0"
              text
              size="small"
              @click="clearHistory"
            >
              <el-icon><Delete /></el-icon>
              清空
            </el-button>
            <el-button
              type="primary"
              size="small"
              :disabled="!inputMessage.trim() || isSending"
              @click="sendMessage"
              :loading="isSending"
            >
              发送
            </el-button>
          </div>
        </div>
      </div>
    </transition>
  </div>
</template>

<script setup>
import { ref, watch, nextTick, onMounted, onUnmounted } from 'vue'
import { ElMessage } from 'element-plus'
import {
  ChatDotRound,
  ArrowUp,
  Loading,
  Delete
} from '@element-plus/icons-vue'

const isExpanded = ref(false)
const messages = ref([])
const inputMessage = ref('')
const messagesContainer = ref(null)
const isLoading = ref(false)
const isSending = ref(false)
const isTyping = ref(false)
const ws = ref(null)
const hasUnreadMessages = ref(false)
const aiConnectionStatus = ref(null)
const chatInstanceId = ref(null)

const STORAGE_KEY = 'ai_chat_history'

const quickActions = [
  { text: '漏洞分析' },
  { text: 'POC生成' },
  { text: '安全建议' }
]

const toggleChat = () => {
  isExpanded.value = !isExpanded.value
  if (isExpanded.value) {
    hasUnreadMessages.value = false
    fetchAIConnectionStatus()
    connectWebSocket()
  } else {
    disconnectWebSocket()
  }
}

const fetchAIConnectionStatus = async () => {
  try {
    const token = localStorage.getItem('token')
    const response = await fetch('http://127.0.0.1:8888/api/ai/connection-status', {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    })
    const data = await response.json()
    if (data.code === 200 && data.data) {
      aiConnectionStatus.value = data.data
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
  if (!aiConnectionStatus.value) return '检测中'
  if (aiConnectionStatus.value.connection_test === 'success') return '已连接'
  if (aiConnectionStatus.value.connection_test === 'failed') return '未连接'
  if (!aiConnectionStatus.value.configured) return '未配置'
  return '检测中'
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
  const wsUrl = `ws://localhost:8888/api/ws?token=${token}`

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
      ElMessage.error('连接失败')
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
  if (!message || isSending.value) {
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
    ElMessage.error('发送失败')
  }
}

const sendQuickAction = (text) => {
  inputMessage.value = text
  sendMessage()
}

const sendViaAPI = async (message, token) => {
  try {
    const response = await fetch('http://127.0.0.1:8888/api/ai/chat', {
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
    ElMessage.error('发送失败')
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
  if (!date) return ''
  try {
    const d = date instanceof Date ? date : new Date(date)
    if (isNaN(d.getTime())) return ''
    const hours = d.getHours().toString().padStart(2, '0')
    const minutes = d.getMinutes().toString().padStart(2, '0')
    return `${hours}:${minutes}`
  } catch {
    return ''
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

watch(isExpanded, (newVal) => {
  if (newVal) {
    loadHistory()
    nextTick(() => {
      scrollToBottom()
    })
  }
})

onMounted(() => {
  loadHistory()
})

onUnmounted(() => {
  disconnectWebSocket()
})
</script>

<style scoped>
.ai-chat-sidebar {
  position: absolute;
  bottom: 0;
  left: 0;
  right: 0;
  background: var(--el-fill-color-blank);
  border-top: 1px solid var(--el-border-color-light);
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  z-index: 10;
  box-shadow: 0 -2px 8px rgba(0, 0, 0, 0.05);
}

.ai-chat-sidebar.collapsed {
  height: 48px;
}

.ai-chat-sidebar.expanded {
  height: 450px;
}

.chat-toggle {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  cursor: pointer;
  background: linear-gradient(135deg, var(--el-color-primary-light-9) 0%, var(--el-fill-color-light) 100%);
  transition: all 0.2s;
  position: relative;
  user-select: none;
}

.chat-toggle:hover {
  background: linear-gradient(135deg, var(--el-color-primary-light-8) 0%, var(--el-fill-color) 100%);
}

.chat-toggle:active {
  transform: scale(0.98);
}

.toggle-content {
  display: flex;
  align-items: center;
  gap: 8px;
}

.toggle-text {
  font-size: 14px;
  font-weight: 500;
  color: var(--el-text-color-primary);
}

.toggle-arrow {
  transition: transform 0.3s;
  color: var(--el-text-color-secondary);
}

.toggle-arrow.rotated {
  transform: rotate(180deg);
}

.unread-dot {
  position: absolute;
  top: 8px;
  right: 16px;
  width: 8px;
  height: 8px;
  background: #F56C6C;
  border-radius: 50%;
  animation: pulse 2s ease infinite;
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}

.chat-container {
  display: flex;
  flex-direction: column;
  height: calc(100% - 48px);
  background: var(--el-fill-color-blank);
}

.chat-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 16px;
  border-bottom: 1px solid var(--el-border-color-lighter);
  background: var(--el-fill-color-light);
}

.header-info {
  display: flex;
  align-items: center;
  gap: 8px;
}

.header-title {
  font-size: 14px;
  font-weight: 600;
  color: var(--el-text-color-primary);
}

.header-status {
  display: flex;
  align-items: center;
}

.status-indicator {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 12px;
  padding: 2px 8px;
  border-radius: 10px;
}

.status-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
}

.status-indicator.connected {
  background: rgba(103, 194, 58, 0.1);
  color: #67C23A;
}

.status-indicator.connected .status-dot {
  background: #67C23A;
  animation: pulse 2s ease infinite;
}

.status-indicator.disconnected {
  background: rgba(245, 108, 108, 0.1);
  color: #F56C6C;
}

.status-indicator.disconnected .status-dot {
  background: #F56C6C;
}

.status-indicator.checking {
  background: rgba(230, 162, 60, 0.1);
  color: #E6A23C;
}

.status-indicator.checking .status-dot {
  background: #E6A23C;
}

.chat-body {
  flex: 1;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.loading-state,
.empty-state {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 12px;
  padding: 20px;
}

.loading-state span,
.empty-text {
  font-size: 13px;
  color: var(--el-text-color-secondary);
}

.empty-icon {
  width: 56px;
  height: 56px;
  background: var(--el-fill-color-light);
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
}

.quick-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  justify-content: center;
  margin-top: 8px;
}

.quick-btn {
  padding: 6px 12px;
  background: var(--el-fill-color-blank);
  border: 1px solid var(--el-border-color);
  border-radius: 14px;
  font-size: 12px;
  color: var(--el-text-color-regular);
  cursor: pointer;
  transition: all 0.2s;
}

.quick-btn:hover {
  background: var(--el-color-primary);
  border-color: var(--el-color-primary);
  color: #fff;
}

.messages-container {
  flex: 1;
  overflow-y: auto;
  padding: 12px;
}

.messages-container::-webkit-scrollbar {
  width: 4px;
}

.messages-container::-webkit-scrollbar-thumb {
  background: var(--el-border-color);
  border-radius: 2px;
}

.message-item {
  margin-bottom: 12px;
  animation: fadeIn 0.3s ease;
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(8px); }
  to { opacity: 1; transform: translateY(0); }
}

.message-item.user {
  display: flex;
  justify-content: flex-end;
}

.message-item.assistant {
  display: flex;
  justify-content: flex-start;
}

.message-bubble {
  max-width: 85%;
  padding: 10px 14px;
  border-radius: 14px;
  position: relative;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
}

.message-item.user .message-bubble {
  background: linear-gradient(135deg, var(--el-color-primary) 0%, var(--el-color-primary-light-3) 100%);
  color: #fff;
  border-bottom-right-radius: 4px;
}

.message-item.assistant .message-bubble {
  background: var(--el-fill-color-light);
  color: var(--el-text-color-primary);
  border-bottom-left-radius: 4px;
  border: 1px solid var(--el-border-color-lighter);
}

.message-bubble.typing {
  padding: 12px 16px;
}

.message-text {
  font-size: 13px;
  line-height: 1.5;
  word-wrap: break-word;
}

.message-text :deep(.code-block) {
  background: #1E1E1E;
  color: #D4D4D4;
  padding: 8px;
  border-radius: 4px;
  margin: 4px 0;
  overflow-x: auto;
  font-size: 11px;
}

.message-text :deep(.inline-code) {
  background: rgba(0, 0, 0, 0.1);
  padding: 1px 4px;
  border-radius: 3px;
  font-size: 12px;
}

.message-item.user .message-text :deep(.inline-code) {
  background: rgba(255, 255, 255, 0.2);
}

.message-time {
  font-size: 10px;
  opacity: 0.7;
  margin-top: 4px;
  text-align: right;
}

.typing-indicator {
  display: flex;
  gap: 4px;
}

.typing-indicator span {
  width: 6px;
  height: 6px;
  background: var(--el-color-primary);
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
  30% { transform: translateY(-6px); }
}

.chat-footer {
  padding: 12px;
  border-top: 1px solid var(--el-border-color-lighter);
  background: var(--el-fill-color-blank);
}

.input-area {
  margin-bottom: 10px;
}

.input-area :deep(.el-textarea__inner) {
  font-size: 13px;
  padding: 10px 12px;
  border-radius: 10px;
  border: 1px solid var(--el-border-color);
  transition: all 0.2s;
}

.input-area :deep(.el-textarea__inner:focus) {
  border-color: var(--el-color-primary);
  box-shadow: 0 0 0 2px var(--el-color-primary-light-9);
}

.footer-actions {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.chat-expand-enter-active,
.chat-expand-leave-active {
  transition: all 0.3s ease;
}

.chat-expand-enter-from,
.chat-expand-leave-to {
  opacity: 0;
  transform: translateY(-10px);
}

@media (max-width: 768px) {
  .ai-chat-sidebar.expanded {
    height: 350px;
  }
  
  .chat-toggle {
    padding: 10px 12px;
  }
  
  .toggle-text {
    font-size: 13px;
  }
  
  .message-bubble {
    max-width: 90%;
  }
}
</style>
