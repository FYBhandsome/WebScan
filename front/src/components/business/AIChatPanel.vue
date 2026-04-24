<template>
  <div class="ai-chat-panel">
    <div class="chat-header">
      <h3>AI 安全助手</h3>
      <div class="header-actions">
        <el-button size="small" @click="clearChat" :icon="Delete">清空对话</el-button>
        <el-button size="small" @click="toggleExpand" :icon="isExpanded ? Minus : Plus">
          {{ isExpanded ? '收起' : '展开' }}
        </el-button>
      </div>
    </div>
    
    <div class="chat-messages" ref="messagesContainer" v-show="isExpanded">
      <div 
        v-for="(message, index) in messages" 
        :key="index"
        :class="['message', message.role]"
      >
        <div class="message-avatar">
          <el-avatar v-if="message.role === 'user'" :icon="User" />
          <el-avatar v-else :icon="Monitor" />
        </div>
        <div class="message-content">
          <div class="message-header">
            <span class="role-name">{{ message.role === 'user' ? '用户' : 'AI助手' }}</span>
            <span class="timestamp">{{ formatTime(message.timestamp) }}</span>
          </div>
          <div class="message-text" v-html="formatMessage(message.content)"></div>
          
          <div v-if="message.type === 'decision'" class="decision-info">
            <el-tag type="info">{{ message.decision?.action }}</el-tag>
            <span class="decision-reason">{{ message.decision?.reason }}</span>
          </div>
          
          <div v-if="message.type === 'progress'" class="progress-info">
            <el-progress :percentage="message.progress?.percent || 0" :stroke-width="6" />
            <span class="progress-message">{{ message.progress?.message }}</span>
          </div>
          
          <div v-if="message.type === 'report_ready'" class="report-info">
            <el-button type="primary" size="small" @click="downloadReport(message.report)">
              <el-icon><Download /></el-icon> 下载报告
            </el-button>
          </div>
        </div>
      </div>
      
      <div v-if="isWaitingConfirm" class="confirmation-panel">
        <div class="confirmation-prompt">{{ confirmationPrompt }}</div>
        <div class="confirmation-buttons">
          <el-button type="primary" @click="handleConfirm('confirm')">确认执行</el-button>
          <el-button type="warning" @click="handleConfirm('skip')">跳过</el-button>
          <el-button type="danger" @click="handleConfirm('cancel')">取消</el-button>
        </div>
      </div>
      
      <div v-if="isLoading" class="loading-indicator">
        <el-icon class="is-loading"><Loading /></el-icon>
        <span>AI正在思考...</span>
      </div>
    </div>
    
    <div class="chat-input" v-show="isExpanded">
      <el-input
        v-model="inputMessage"
        type="textarea"
        :rows="2"
        placeholder="输入消息或扫描目标..."
        @keydown.enter.ctrl="sendMessage"
        :disabled="!isConnected"
      />
      <div class="input-actions">
        <el-button 
          type="primary" 
          @click="sendMessage" 
          :disabled="!inputMessage.trim() || !isConnected"
        >
          发送
        </el-button>
        <el-button 
          type="success" 
          @click="startScan" 
          :disabled="!inputMessage.trim() || !isConnected || isScanning"
        >
          开始扫描
        </el-button>
      </div>
    </div>
    
    <div class="connection-status" :class="{ connected: isConnected }">
      <el-icon><Connection /></el-icon>
      <span>{{ isConnected ? '已连接' : '未连接' }}</span>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, nextTick, computed } from 'vue'
import { 
  Delete, Plus, Minus, User, Monitor, Download, Loading, Connection 
} from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import { useAIChatStore } from '@/stores/aiChat'
import { storeToRefs } from 'pinia'

const props = defineProps({
  target: {
    type: String,
    default: ''
  }
})

const emit = defineEmits(['scan-started', 'scan-completed', 'report-ready'])

const aiChatStore = useAIChatStore()
const { 
  messages, 
  isConnected, 
  sessionId, 
  isWaitingConfirm,
  confirmationPrompt,
  isScanning
} = storeToRefs(aiChatStore)

const inputMessage = ref('')
const isExpanded = ref(true)
const messagesContainer = ref(null)

const isLoading = computed(() => isScanning.value)

const toggleExpand = () => {
  isExpanded.value = !isExpanded.value
}

const clearChat = () => {
  aiChatStore.clearMessages()
}

const sendMessage = () => {
  if (!inputMessage.value.trim() || !isConnected.value) return
  
  aiChatStore.sendUserInput(inputMessage.value)
  inputMessage.value = ''
}

const startScan = () => {
  if (!inputMessage.value.trim() || !isConnected.value) return
  
  const target = inputMessage.value.trim()
  aiChatStore.startScan(target, 'full')
  inputMessage.value = ''
  
  emit('scan-started', { target })
}

const handleConfirm = (choice) => {
  aiChatStore.sendUserConfirm(choice)
}

const downloadReport = (report) => {
  if (report?.download_url) {
    window.open(report.download_url, '_blank')
    emit('report-ready', report)
  }
}

const formatTime = (timestamp) => {
  if (!timestamp) return ''
  const date = new Date(timestamp)
  return date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' })
}

const formatMessage = (content) => {
  if (!content) return ''
  return content.replace(/\n/g, '<br>').replace(/`([^`]+)`/g, '<code>$1</code>')
}

const scrollToBottom = () => {
  nextTick(() => {
    if (messagesContainer.value) {
      messagesContainer.value.scrollTop = messagesContainer.value.scrollHeight
    }
  })
}

onMounted(() => {
  aiChatStore.connect()
  if (props.target) {
    inputMessage.value = props.target
  }
})

onUnmounted(() => {
  aiChatStore.disconnect()
})
</script>

<style scoped>
.ai-chat-panel {
  display: flex;
  flex-direction: column;
  height: 100%;
  background: #fff;
  border-radius: 8px;
  box-shadow: 0 2px 12px rgba(0, 0, 0, 0.1);
}

.chat-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 16px;
  border-bottom: 1px solid #ebeef5;
}

.chat-header h3 {
  margin: 0;
  font-size: 16px;
  color: #303133;
}

.header-actions {
  display: flex;
  gap: 8px;
}

.chat-messages {
  flex: 1;
  overflow-y: auto;
  padding: 16px;
  min-height: 300px;
  max-height: 500px;
}

.message {
  display: flex;
  gap: 12px;
  margin-bottom: 16px;
}

.message.user {
  flex-direction: row-reverse;
}

.message-avatar {
  flex-shrink: 0;
}

.message-content {
  flex: 1;
  max-width: 80%;
}

.message.user .message-content {
  text-align: right;
}

.message-header {
  margin-bottom: 4px;
}

.role-name {
  font-weight: 500;
  color: #606266;
  margin-right: 8px;
}

.timestamp {
  font-size: 12px;
  color: #909399;
}

.message-text {
  padding: 10px 14px;
  border-radius: 8px;
  background: #f4f4f5;
  color: #303133;
  line-height: 1.5;
  word-break: break-word;
}

.message.user .message-text {
  background: #409eff;
  color: #fff;
}

.message-text code {
  background: rgba(0, 0, 0, 0.1);
  padding: 2px 6px;
  border-radius: 4px;
  font-family: monospace;
}

.decision-info,
.progress-info,
.report-info {
  margin-top: 8px;
  padding: 8px;
  background: #f0f9ff;
  border-radius: 4px;
}

.decision-reason {
  margin-left: 8px;
  color: #606266;
}

.progress-message {
  display: block;
  margin-top: 4px;
  font-size: 12px;
  color: #909399;
}

.confirmation-panel {
  padding: 16px;
  background: #fdf6ec;
  border-radius: 8px;
  margin-bottom: 16px;
}

.confirmation-prompt {
  margin-bottom: 12px;
  color: #e6a23c;
  font-weight: 500;
}

.confirmation-buttons {
  display: flex;
  gap: 8px;
}

.loading-indicator {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px;
  color: #909399;
}

.chat-input {
  padding: 12px 16px;
  border-top: 1px solid #ebeef5;
}

.input-actions {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  margin-top: 8px;
}

.connection-status {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 8px;
  font-size: 12px;
  color: #f56c6c;
  border-top: 1px solid #ebeef5;
}

.connection-status.connected {
  color: #67c23a;
}
</style>
