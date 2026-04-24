<template>
  <div class="ai-chat-sidebar" :class="{ 'collapsed': isCollapsed }">
    <div class="sidebar-header">
      <div class="header-left">
        <div class="ai-icon">
          <el-icon :size="24"><ChatDotRound /></el-icon>
        </div>
        <div v-if="!isCollapsed" class="header-info">
          <h3 class="header-title">AI 对话助手</h3>
          <div class="connection-status" :class="connectionStatusClass">
            <span class="status-dot"></span>
            {{ connectionStatusText }}
          </div>
        </div>
      </div>
      <div class="header-actions">
        <el-tooltip :content="isCollapsed ? '展开' : '收起'" placement="bottom">
          <button class="action-btn" @click="toggleCollapse">
            <el-icon :size="18">
              <ArrowLeft v-if="!isCollapsed" />
              <ArrowRight v-else />
            </el-icon>
          </button>
        </el-tooltip>
      </div>
    </div>

    <template v-if="!isCollapsed">
      <div class="sidebar-toolbar">
        <el-tooltip content="新建对话" placement="bottom">
          <button class="toolbar-btn" @click="createNewConversation">
            <el-icon><Plus /></el-icon>
          </button>
        </el-tooltip>
        <el-tooltip content="清空对话" placement="bottom">
          <button class="toolbar-btn" @click="clearCurrentChat" :disabled="messages.length === 0">
            <el-icon><Delete /></el-icon>
          </button>
        </el-tooltip>
        <el-tooltip content="导出对话" placement="bottom">
          <button class="toolbar-btn" @click="exportChat" :disabled="messages.length === 0">
            <el-icon><Download /></el-icon>
          </button>
        </el-tooltip>
        <el-tooltip content="测试连接" placement="bottom">
          <button class="toolbar-btn" @click="testConnection" :disabled="isTestingConnection">
            <el-icon :class="{ 'is-loading': isTestingConnection }"><Connection /></el-icon>
          </button>
        </el-tooltip>
      </div>

      <div class="conversations-list" v-if="showConversationsList && conversations.length > 0">
        <div class="conversations-header">
          <span>历史对话</span>
          <button class="toggle-list-btn" @click="showConversationsList = false">
            <el-icon><ArrowUp /></el-icon>
          </button>
        </div>
        <div class="conversations-items">
          <div
            v-for="conv in conversations"
            :key="conv.id"
            class="conversation-item"
            :class="{ 'active': currentConversationId === conv.id }"
            @click="loadConversation(conv.id)"
          >
            <el-icon class="conv-icon"><ChatLineRound /></el-icon>
            <div class="conv-info">
              <span class="conv-title">{{ conv.title || '新对话' }}</span>
              <span class="conv-time">{{ formatConvTime(conv.updatedAt) }}</span>
            </div>
            <button class="conv-delete" @click.stop="deleteConversation(conv.id)">
              <el-icon><Close /></el-icon>
            </button>
          </div>
        </div>
      </div>

      <div class="messages-area" ref="messagesContainer">
        <div v-if="isLoading" class="loading-state">
          <div class="loading-spinner">
            <div class="spinner-ring"></div>
            <div class="spinner-ring"></div>
            <div class="spinner-ring"></div>
          </div>
          <p>正在连接AI服务...</p>
        </div>

        <div v-else-if="messages.length === 0" class="empty-state">
          <div class="empty-icon">
            <el-icon :size="48" color="#C0C4CC"><ChatDotRound /></el-icon>
          </div>
          <p class="empty-title">开始新的对话</p>
          <p class="empty-hint">输入问题，AI助手将为您提供帮助</p>
          <div class="quick-commands">
            <button
              v-for="cmd in quickCommands"
              :key="cmd.text"
              class="quick-cmd-btn"
              @click="sendQuickCommand(cmd.text)"
            >
              <el-icon :size="16"><component :is="cmd.icon" /></el-icon>
              <span>{{ cmd.text }}</span>
            </button>
          </div>
        </div>

        <div v-else class="messages-list">
          <div
            v-for="(message, index) in messages"
            :key="message.id || index"
            class="message-item"
            :class="message.role"
          >
            <div class="message-avatar" :class="message.role">
              <el-avatar v-if="message.role === 'user'" :size="32" color="#409EFF">
                <el-icon :size="16"><User /></el-icon>
              </el-avatar>
              <el-avatar v-else :size="32" color="#67C23A">
                <el-icon :size="16"><ChatDotRound /></el-icon>
              </el-avatar>
            </div>
            <div class="message-body">
              <div class="message-header">
                <span class="message-role-text">
                  {{ message.role === 'user' ? '我' : 'AI助手' }}
                </span>
                <span class="message-time">{{ formatTime(message.timestamp) }}</span>
              </div>
              <div class="message-content" :class="{ 'has-code': hasCodeBlock(message.content) }">
                <div class="message-text" v-html="renderMarkdown(message.content)"></div>
              </div>
              <div v-if="message.role === 'assistant'" class="message-actions">
                <button class="msg-action-btn" @click="copyMessage(message.content)" title="复制内容">
                  <el-icon :size="14"><DocumentCopy /></el-icon>
                </button>
                <button v-if="hasCodeBlock(message.content)" class="msg-action-btn" @click="copyCodeBlocks(message.content)" title="复制代码">
                  <el-icon :size="14"><CopyDocument /></el-icon>
                </button>
                <button class="msg-action-btn" @click="regenerateResponse(index)" title="重新生成">
                  <el-icon :size="14"><Refresh /></el-icon>
                </button>
              </div>
            </div>
          </div>
          <div v-if="isTyping" class="message-item assistant typing">
            <div class="message-avatar assistant">
              <el-avatar :size="32" color="#67C23A">
                <el-icon :size="16"><ChatDotRound /></el-icon>
              </el-avatar>
            </div>
            <div class="message-body">
              <div class="typing-indicator">
                <span></span>
                <span></span>
                <span></span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="input-area">
        <div class="input-container" :class="{ 'focused': isInputFocused }">
          <el-input
            ref="inputRef"
            v-model="inputMessage"
            type="textarea"
            :rows="2"
            :autosize="{ minRows: 2, maxRows: 6 }"
            placeholder="输入问题... (Enter发送, Shift+Enter换行)"
            :disabled="isSending"
            @focus="isInputFocused = true"
            @blur="isInputFocused = false"
            @keydown.enter.exact.prevent="handleSend"
            @keydown.enter.shift.exact="inputMessage += '\n'"
          />
        </div>
        <div class="input-footer">
          <div class="input-hints">
            <span v-if="isSending" class="sending-hint">
              <el-icon :size="14" class="is-loading"><Loading /></el-icon>
              AI正在思考...
            </span>
            <span v-else class="char-count">{{ inputMessage.length }} / 2000</span>
          </div>
          <div class="input-actions">
            <el-button
              type="primary"
              :disabled="!canSend"
              :loading="isSending"
              @click="handleSend"
              class="send-btn"
            >
              <template #icon>
                <el-icon><Promotion /></el-icon>
              </template>
              发送
            </el-button>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, watch, nextTick, onMounted, onUnmounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  ChatDotRound,
  ArrowLeft,
  ArrowRight,
  Plus,
  Delete,
  Download,
  Connection,
  ChatLineRound,
  Close,
  User,
  DocumentCopy,
  CopyDocument,
  Refresh,
  Loading,
  Promotion,
  Warning,
  Search,
  Document,
  Aim
} from '@element-plus/icons-vue'

const props = defineProps({
  collapsed: {
    type: Boolean,
    default: false
  }
})

const emit = defineEmits(['update:collapsed', 'command-executed'])

const isCollapsed = ref(props.collapsed)
const messages = ref([])
const inputMessage = ref('')
const messagesContainer = ref(null)
const inputRef = ref(null)
const isLoading = ref(false)
const isSending = ref(false)
const isTyping = ref(false)
const isInputFocused = ref(false)
const isTestingConnection = ref(false)
const ws = ref(null)
const connectionStatus = ref('disconnected')
const currentConversationId = ref(null)
const conversations = ref([])
const showConversationsList = ref(false)

const STORAGE_KEY = 'ai_chat_sidebar_history'
const CONVERSATIONS_KEY = 'ai_chat_sidebar_conversations'

const quickCommands = [
  { text: '漏洞分析', icon: Warning },
  { text: 'POC生成', icon: Aim },
  { text: '安全建议', icon: Search },
  { text: '代码审计', icon: Document }
]

const connectionStatusClass = computed(() => {
  const statusMap = {
    'connected': 'connected',
    'connecting': 'connecting',
    'disconnected': 'disconnected',
    'error': 'error'
  }
  return statusMap[connectionStatus.value] || 'disconnected'
})

const connectionStatusText = computed(() => {
  const textMap = {
    'connected': '已连接',
    'connecting': '连接中',
    'disconnected': '未连接',
    'error': '连接错误'
  }
  return textMap[connectionStatus.value] || '未连接'
})

const canSend = computed(() => {
  return inputMessage.value.trim() && !isSending.value && inputMessage.value.length <= 2000
})

const toggleCollapse = () => {
  isCollapsed.value = !isCollapsed.value
  emit('update:collapsed', isCollapsed.value)
}

const connectWebSocket = () => {
  if (ws.value && ws.value.readyState === WebSocket.OPEN) {
    return
  }

  connectionStatus.value = 'connecting'
  const token = localStorage.getItem('token')
  const wsUrl = `ws://localhost:8888/api/ws?token=${token}`

  try {
    ws.value = new WebSocket(wsUrl)

    ws.value.onopen = () => {
      connectionStatus.value = 'connected'
      console.log('AI Chat Sidebar WebSocket连接成功')
    }

    ws.value.onmessage = (event) => {
      handleWebSocketMessage(event)
    }

    ws.value.onerror = (error) => {
      console.error('WebSocket错误:', error)
      connectionStatus.value = 'error'
    }

    ws.value.onclose = () => {
      connectionStatus.value = 'disconnected'
      console.log('WebSocket连接关闭')
    }
  } catch (error) {
    console.error('创建WebSocket连接失败:', error)
    connectionStatus.value = 'error'
  }
}

const handleWebSocketMessage = (event) => {
  try {
    const data = JSON.parse(event.data)
    
    if (data.type === 'chat_response' || data.type === 'ai_response') {
      isTyping.value = false
      messages.value.push({
        id: Date.now(),
        role: 'assistant',
        content: data.content || data.message,
        timestamp: new Date()
      })
      saveHistory()
      scrollToBottom()
    } else if (data.type === 'typing') {
      isTyping.value = true
      scrollToBottom()
    } else if (data.type === 'error') {
      isTyping.value = false
      isSending.value = false
      ElMessage.error(data.message || '发生错误')
    } else if (data.type === 'command_result') {
      isTyping.value = false
      isSending.value = false
      emit('command-executed', data)
    }
  } catch (error) {
    console.error('处理WebSocket消息失败:', error)
  }
}

const disconnectWebSocket = () => {
  if (ws.value) {
    ws.value.close()
    ws.value = null
  }
}

const testConnection = async () => {
  isTestingConnection.value = true
  try {
    const token = localStorage.getItem('token')
    const response = await fetch('http://127.0.0.1:8888/api/ai/test-analysis', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    })
    const data = await response.json()
    if (data.code === 200 && data.data?.test_passed) {
      ElMessage.success('AI连接测试成功')
      connectionStatus.value = 'connected'
    } else {
      ElMessage.error('AI连接测试失败: ' + (data.message || '未知错误'))
      connectionStatus.value = 'error'
    }
  } catch (error) {
    console.error('测试AI连接失败:', error)
    ElMessage.error('AI连接测试失败')
    connectionStatus.value = 'error'
  } finally {
    isTestingConnection.value = false
  }
}

const handleSend = async () => {
  const message = inputMessage.value.trim()
  if (!message || isSending.value || message.length > 2000) {
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
    ElMessage.error('发送失败，请重试')
  } finally {
    isSending.value = false
  }
}

const sendQuickCommand = (text) => {
  inputMessage.value = text
  handleSend()
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

const formatConvTime = (date) => {
  if (!date) return ''
  try {
    const d = date instanceof Date ? date : new Date(date)
    if (isNaN(d.getTime())) return ''
    const now = new Date()
    const diff = now - d
    const days = Math.floor(diff / (1000 * 60 * 60 * 24))
    if (days === 0) return formatTime(d)
    if (days === 1) return '昨天'
    if (days < 7) return `${days}天前`
    return d.toLocaleDateString()
  } catch {
    return ''
  }
}

const renderMarkdown = (content) => {
  if (!content) return ''
  
  let html = content
  
  html = html.replace(/```(\w*)\n?([\s\S]*?)```/g, (match, lang, code) => {
    const langLabel = lang ? `<span class="code-lang">${lang}</span>` : ''
    return `<pre class="code-block">${langLabel}<code>${escapeHtml(code.trim())}</code></pre>`
  })
  
  html = html.replace(/`([^`]+)`/g, '<code class="inline-code">$1</code>')
  
  html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
  html = html.replace(/\*([^*]+)\*/g, '<em>$1</em>')
  
  html = html.replace(/^### (.+)$/gm, '<h4>$1</h4>')
  html = html.replace(/^## (.+)$/gm, '<h3>$1</h3>')
  html = html.replace(/^# (.+)$/gm, '<h2>$1</h2>')
  
  html = html.replace(/^- (.+)$/gm, '<li>$1</li>')
  html = html.replace(/(<li>.*<\/li>\n?)+/g, '<ul>$&</ul>')
  
  html = html.replace(/^\d+\. (.+)$/gm, '<li>$1</li>')
  
  html = html.replace(/\n/g, '<br>')
  
  return html
}

const escapeHtml = (text) => {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  }
  return text.replace(/[&<>"']/g, m => map[m])
}

const hasCodeBlock = (content) => {
  return content && content.includes('```')
}

const copyMessage = async (content) => {
  try {
    await navigator.clipboard.writeText(content)
    ElMessage.success('已复制到剪贴板')
  } catch {
    ElMessage.error('复制失败')
  }
}

const copyCodeBlocks = (content) => {
  const codeBlockRegex = /```[\w]*\n?([\s\S]*?)```/g
  const matches = []
  let match
  while ((match = codeBlockRegex.exec(content)) !== null) {
    matches.push(match[1].trim())
  }
  if (matches.length > 0) {
    copyMessage(matches.join('\n\n---\n\n'))
  }
}

const regenerateResponse = async (messageIndex) => {
  if (messageIndex < 1) return
  
  const userMessage = messages.value[messageIndex - 1]
  if (userMessage.role !== 'user') return
  
  messages.value = messages.value.slice(0, messageIndex)
  inputMessage.value = userMessage.content
  await handleSend()
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

const loadConversations = () => {
  try {
    const saved = localStorage.getItem(CONVERSATIONS_KEY)
    if (saved) {
      conversations.value = JSON.parse(saved)
    }
  } catch (error) {
    console.error('加载对话列表失败:', error)
  }
}

const saveConversations = () => {
  try {
    localStorage.setItem(CONVERSATIONS_KEY, JSON.stringify(conversations.value))
  } catch (error) {
    console.error('保存对话列表失败:', error)
  }
}

const createNewConversation = () => {
  if (messages.value.length > 0) {
    const title = messages.value[0].content.slice(0, 30) + (messages.value[0].content.length > 30 ? '...' : '')
    const conv = {
      id: Date.now(),
      title: title,
      messages: [...messages.value],
      createdAt: new Date(),
      updatedAt: new Date()
    }
    conversations.value.unshift(conv)
    saveConversations()
  }
  
  messages.value = []
  currentConversationId.value = null
  localStorage.removeItem(STORAGE_KEY)
  ElMessage.success('已创建新对话')
}

const loadConversation = (convId) => {
  const conv = conversations.value.find(c => c.id === convId)
  if (conv) {
    messages.value = conv.messages
    currentConversationId.value = convId
    showConversationsList.value = false
    scrollToBottom()
  }
}

const deleteConversation = async (convId) => {
  try {
    await ElMessageBox.confirm('确定要删除此对话吗？', '提示', {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'warning'
    })
    conversations.value = conversations.value.filter(c => c.id !== convId)
    saveConversations()
    if (currentConversationId.value === convId) {
      currentConversationId.value = null
    }
    ElMessage.success('对话已删除')
  } catch {
    // 用户取消
  }
}

const clearCurrentChat = async () => {
  try {
    await ElMessageBox.confirm('确定要清空当前对话吗？', '提示', {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'warning'
    })
    messages.value = []
    localStorage.removeItem(STORAGE_KEY)
    ElMessage.success('对话已清空')
  } catch {
    // 用户取消
  }
}

const exportChat = () => {
  if (messages.value.length === 0) return
  
  let content = '# AI对话记录\n\n'
  content += `导出时间: ${new Date().toLocaleString()}\n\n---\n\n`
  
  messages.value.forEach(msg => {
    const role = msg.role === 'user' ? '**我**' : '**AI助手**'
    const time = formatTime(msg.timestamp)
    content += `${role} (${time})\n\n${msg.content}\n\n---\n\n`
  })
  
  const blob = new Blob([content], { type: 'text/markdown' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `ai-chat-${new Date().toISOString().slice(0, 10)}.md`
  a.click()
  URL.revokeObjectURL(url)
  ElMessage.success('对话已导出')
}

watch(isCollapsed, (newVal) => {
  if (!newVal) {
    connectWebSocket()
    nextTick(() => {
      scrollToBottom()
    })
  }
})

watch(() => props.collapsed, (newVal) => {
  isCollapsed.value = newVal
})

onMounted(() => {
  loadHistory()
  loadConversations()
  if (!isCollapsed.value) {
    connectWebSocket()
  }
})

onUnmounted(() => {
  disconnectWebSocket()
})
</script>

<style scoped>
.ai-chat-sidebar {
  width: 380px;
  height: 100%;
  background: #ffffff;
  border-left: 1px solid #EBEEF5;
  display: flex;
  flex-direction: column;
  transition: width 0.3s ease;
  box-shadow: -2px 0 8px rgba(0, 0, 0, 0.05);
}

.ai-chat-sidebar.collapsed {
  width: 60px;
}

.sidebar-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px;
  background: linear-gradient(135deg, #409EFF 0%, #66B1FF 100%);
  color: #ffffff;
  flex-shrink: 0;
}

.header-left {
  display: flex;
  align-items: center;
  gap: 12px;
}

.ai-icon {
  width: 40px;
  height: 40px;
  background: rgba(255, 255, 255, 0.2);
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.header-info {
  display: flex;
  flex-direction: column;
}

.header-title {
  margin: 0;
  font-size: 16px;
  font-weight: 600;
}

.connection-status {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  margin-top: 4px;
  padding: 2px 8px;
  border-radius: 10px;
  background: rgba(255, 255, 255, 0.2);
}

.status-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: currentColor;
}

.connection-status.connected {
  color: #67C23A;
}

.connection-status.connecting {
  color: #E6A23C;
}

.connection-status.disconnected,
.connection-status.error {
  color: #F56C6C;
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
}

.sidebar-toolbar {
  display: flex;
  gap: 8px;
  padding: 12px 16px;
  border-bottom: 1px solid #EBEEF5;
  background: #F8FAFC;
}

.toolbar-btn {
  width: 36px;
  height: 36px;
  background: #ffffff;
  border: 1px solid #DCDFE6;
  border-radius: 8px;
  color: #606266;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.2s;
}

.toolbar-btn:hover:not(:disabled) {
  border-color: #409EFF;
  color: #409EFF;
  background: #ECF5FF;
}

.toolbar-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.conversations-list {
  border-bottom: 1px solid #EBEEF5;
  max-height: 200px;
  overflow-y: auto;
}

.conversations-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 10px 16px;
  background: #F5F7FA;
  font-size: 13px;
  color: #909399;
}

.toggle-list-btn {
  background: none;
  border: none;
  color: #909399;
  cursor: pointer;
  padding: 4px;
}

.conversations-items {
  padding: 8px;
}

.conversation-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 12px;
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s;
}

.conversation-item:hover {
  background: #F5F7FA;
}

.conversation-item.active {
  background: #ECF5FF;
}

.conv-icon {
  color: #909399;
}

.conv-info {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
}

.conv-title {
  font-size: 13px;
  color: #303133;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.conv-time {
  font-size: 11px;
  color: #C0C4CC;
  margin-top: 2px;
}

.conv-delete {
  width: 24px;
  height: 24px;
  background: none;
  border: none;
  color: #C0C4CC;
  cursor: pointer;
  border-radius: 4px;
  display: flex;
  align-items: center;
  justify-content: center;
  opacity: 0;
  transition: all 0.2s;
}

.conversation-item:hover .conv-delete {
  opacity: 1;
}

.conv-delete:hover {
  background: #F56C6C;
  color: #fff;
}

.messages-area {
  flex: 1;
  overflow-y: auto;
  padding: 16px;
  background: #F8FAFC;
}

.messages-area::-webkit-scrollbar {
  width: 6px;
}

.messages-area::-webkit-scrollbar-track {
  background: transparent;
}

.messages-area::-webkit-scrollbar-thumb {
  background: #DCDFE6;
  border-radius: 3px;
}

.loading-state,
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100%;
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

.quick-commands {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  justify-content: center;
}

.quick-cmd-btn {
  padding: 8px 16px;
  background: #ffffff;
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

.quick-cmd-btn:hover {
  background: #409EFF;
  border-color: #409EFF;
  color: #fff;
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(64, 158, 255, 0.3);
}

.messages-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.message-item {
  display: flex;
  gap: 12px;
  animation: messageSlideIn 0.3s ease-out;
}

.message-item.user {
  flex-direction: row-reverse;
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

.message-body {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
}

.message-item.user .message-body {
  align-items: flex-end;
}

.message-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 6px;
}

.message-role-text {
  font-size: 12px;
  font-weight: 600;
  color: #606266;
}

.message-item.user .message-role-text {
  color: #409EFF;
}

.message-item.assistant .message-role-text {
  color: #67C23A;
}

.message-time {
  font-size: 11px;
  color: #C0C4CC;
}

.message-content {
  max-width: 90%;
}

.message-text {
  padding: 12px 16px;
  border-radius: 12px;
  line-height: 1.7;
  word-wrap: break-word;
  font-size: 14px;
  text-align: left;
}

.message-item.user .message-text {
  background: linear-gradient(135deg, #409EFF 0%, #66B1FF 100%);
  color: #ffffff;
  border-bottom-right-radius: 4px;
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
  position: relative;
}

.message-text :deep(.code-lang) {
  position: absolute;
  top: 8px;
  right: 8px;
  font-size: 11px;
  color: #909399;
  background: rgba(255, 255, 255, 0.1);
  padding: 2px 8px;
  border-radius: 4px;
}

.message-text :deep(.inline-code) {
  background: rgba(64, 158, 255, 0.1);
  color: #409EFF;
  padding: 2px 6px;
  border-radius: 4px;
  font-family: 'Fira Code', 'Consolas', monospace;
  font-size: 13px;
}

.message-text :deep(h2),
.message-text :deep(h3),
.message-text :deep(h4) {
  margin: 12px 0 8px 0;
  font-weight: 600;
}

.message-text :deep(ul) {
  margin: 8px 0;
  padding-left: 20px;
}

.message-text :deep(li) {
  margin: 4px 0;
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

.input-area {
  padding: 16px;
  background: #ffffff;
  border-top: 1px solid #EBEEF5;
  flex-shrink: 0;
}

.input-container {
  border: 2px solid #E4E7ED;
  border-radius: 12px;
  transition: all 0.2s;
  overflow: hidden;
}

.input-container.focused {
  border-color: #409EFF;
  box-shadow: 0 0 0 3px rgba(64, 158, 255, 0.1);
}

.input-container :deep(.el-textarea__inner) {
  border: none;
  padding: 12px;
  font-size: 14px;
  line-height: 1.6;
  resize: none;
  background: transparent;
}

.input-container :deep(.el-textarea__inner:focus) {
  box-shadow: none;
}

.input-footer {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-top: 12px;
}

.input-hints {
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
  border-radius: 8px;
  font-weight: 500;
}

@media (max-width: 768px) {
  .ai-chat-sidebar {
    width: 100%;
    position: fixed;
    top: 0;
    right: 0;
    bottom: 0;
    z-index: 1000;
  }

  .ai-chat-sidebar.collapsed {
    width: 0;
    border: none;
  }
}
</style>
