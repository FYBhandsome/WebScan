<template>
  <div class="server-log-box">
    <div class="log-toolbar">
      <div class="toolbar-left">
        <button class="btn btn-clear" @click="handleClear" title="清空日志">
          <span class="icon">🗑️</span> 清空
        </button>
        <button class="btn btn-copy" @click="handleCopy" title="复制全部日志">
          <span class="icon">📋</span> 复制
        </button>
        <select v-model="fontSize" class="font-select" title="字体大小">
          <option value="12px">小字体</option>
          <option value="14px">中字体</option>
          <option value="16px">大字体</option>
        </select>
      </div>
      <div class="toolbar-right">
        <select v-model="levelFilter" class="level-select" title="日志级别筛选">
          <option value="all">全部级别</option>
          <option value="debug">DEBUG</option>
          <option value="info">INFO</option>
          <option value="warning">WARN</option>
          <option value="error">ERROR</option>
          <option value="success">SUCCESS</option>
        </select>
        <input
          v-model="searchText"
          type="text"
          placeholder="搜索日志..."
          class="search-input"
          title="搜索日志内容"
        />
        <button 
          class="btn btn-toggle" 
          :class="{ active: autoScroll }" 
          @click="autoScroll = !autoScroll"
          title="自动滚动"
        >
          {{ autoScroll ? '🔽 自动' : '⏸️ 暂停' }}
        </button>
      </div>
    </div>

    <div 
      ref="logContent" 
      class="log-content" 
      :style="{ fontSize: fontSize }"
      @scroll="handleScroll"
    >
      <div v-if="filteredLogs.length === 0" class="log-empty">
        <span class="empty-icon">📭</span>
        <span class="empty-text">暂无日志</span>
      </div>
      <div
        v-for="log in filteredLogs"
        :key="log.id"
        :class="['log-item', `log-${log.level}`]"
        @click="handleLogClick(log)"
      >
        <span class="log-time">{{ formatTime(log.timestamp) }}</span>
        <span :class="['log-level', log.level]">{{ log.level?.toUpperCase() }}</span>
        <span v-if="log.node && log.node !== '-'" class="log-node">[{{ log.node }}]</span>
        <span class="log-message">{{ log.message }}</span>
      </div>
    </div>

    <div class="log-status">
      <div class="status-left">
        <span :class="['connection-dot', connectionStatus]"></span>
        <span class="status-text">{{ statusText }}</span>
      </div>
      <div class="status-center">
        <span class="log-count">日志: {{ filteredLogs.length }}/{{ logs.length }}</span>
        <span v-if="levelFilter !== 'all'" class="filter-tag">
          {{ levelFilter.toUpperCase() }}: {{ stats[levelFilter] || 0 }}
        </span>
      </div>
      <div class="status-right">
        <span class="cache-status">💾 已缓存</span>
      </div>
    </div>

    <div v-if="selectedLog" class="log-detail-modal" @click.self="selectedLog = null">
      <div class="log-detail-content">
        <div class="detail-header">
          <span>日志详情</span>
          <button class="btn-close" @click="selectedLog = null">✕</button>
        </div>
        <div class="detail-body">
          <div class="detail-row">
            <span class="detail-label">时间:</span>
            <span class="detail-value">{{ selectedLog.timestamp }}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">级别:</span>
            <span :class="['detail-value', `log-${selectedLog.level}`]">
              {{ selectedLog.level?.toUpperCase() }}
            </span>
          </div>
          <div class="detail-row">
            <span class="detail-label">分类:</span>
            <span class="detail-value">{{ selectedLog.category }}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">节点:</span>
            <span class="detail-value">{{ selectedLog.node }}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">消息:</span>
            <span class="detail-value">{{ selectedLog.message }}</span>
          </div>
          <div v-if="selectedLog.details && Object.keys(selectedLog.details).length" class="detail-row">
            <span class="detail-label">详情:</span>
            <pre class="detail-json">{{ JSON.stringify(selectedLog.details, null, 2) }}</pre>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch, nextTick, onMounted } from 'vue'
import { useLogWebSocket } from '@/utils/useLogWebSocket'

const props = defineProps({
  sessionId: {
    type: String,
    default: null
  },
  height: {
    type: String,
    default: '500px'
  },
  autoConnect: {
    type: Boolean,
    default: true
  }
})

const emit = defineEmits(['log-click', 'status-change'])

const logContent = ref(null)
const fontSize = ref('14px')
const levelFilter = ref('all')
const searchText = ref('')
const autoScroll = ref(true)
const selectedLog = ref(null)

const {
  logs,
  isConnected,
  connectionStatus,
  stats,
  clearLogs,
  getFilteredLogs,
  copyLogs
} = useLogWebSocket({
  sessionId: props.sessionId,
  autoConnect: props.autoConnect,
  onStatusChange: (status) => {
    emit('status-change', status)
  },
  onLogReceived: (log) => {
    if (autoScroll.value) {
      scrollToTop()
    }
  }
})

const filteredLogs = computed(() => {
  return getFilteredLogs(levelFilter.value, searchText.value)
})

const statusText = computed(() => {
  const statusMap = {
    'connected': '已连接',
    'connecting': '连接中...',
    'disconnected': '已断开',
    'reconnecting': '重连中...',
    'error': '连接错误'
  }
  return statusMap[connectionStatus.value] || connectionStatus.value
})

function formatTime(timestamp) {
  if (!timestamp) return ''
  if (timestamp.includes('T')) {
    return timestamp.replace('T', ' ').substring(0, 19)
  }
  return timestamp.substring(0, 19)
}

function scrollToTop() {
  nextTick(() => {
    if (logContent.value) {
      logContent.value.scrollTop = 0
    }
  })
}

function handleScroll() {
  if (logContent.value) {
    const { scrollTop, scrollHeight, clientHeight } = logContent.value
    if (scrollTop > 50) {
      autoScroll.value = false
    }
  }
}

function handleClear() {
  if (confirm('确定要清空所有日志吗？')) {
    clearLogs()
  }
}

async function handleCopy() {
  try {
    await copyLogs()
    alert('日志已复制到剪贴板')
  } catch (e) {
    console.error('复制失败:', e)
  }
}

function handleLogClick(log) {
  selectedLog.value = log
  emit('log-click', log)
}

watch([levelFilter, searchText], () => {
  if (autoScroll.value) {
    scrollToTop()
  }
})

onMounted(() => {
  scrollToTop()
})
</script>

<style scoped>
.server-log-box {
  display: flex;
  flex-direction: column;
  background: #1a1a2e;
  border-radius: 8px;
  overflow: hidden;
  font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
  height: v-bind(height);
  min-height: 300px;
}

.log-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 10px 12px;
  background: #16213e;
  border-bottom: 1px solid #0f3460;
  flex-wrap: wrap;
  gap: 8px;
}

.toolbar-left,
.toolbar-right {
  display: flex;
  align-items: center;
  gap: 8px;
}

.btn {
  padding: 6px 12px;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 12px;
  transition: all 0.2s;
  background: #0f3460;
  color: #e0e0e0;
}

.btn:hover {
  background: #1a4a7a;
}

.btn-toggle.active {
  background: #00a8cc;
  color: #fff;
}

.font-select,
.level-select {
  padding: 6px 10px;
  border: 1px solid #0f3460;
  border-radius: 4px;
  background: #1a1a2e;
  color: #e0e0e0;
  font-size: 12px;
  cursor: pointer;
}

.search-input {
  padding: 6px 12px;
  border: 1px solid #0f3460;
  border-radius: 4px;
  background: #1a1a2e;
  color: #e0e0e0;
  font-size: 12px;
  width: 150px;
  transition: width 0.3s;
}

.search-input:focus {
  outline: none;
  border-color: #00a8cc;
  width: 200px;
}

.log-content {
  flex: 1;
  overflow-y: auto;
  padding: 12px;
  background: #0d0d1a;
  scroll-behavior: smooth;
}

.log-content::-webkit-scrollbar {
  width: 8px;
}

.log-content::-webkit-scrollbar-track {
  background: #1a1a2e;
}

.log-content::-webkit-scrollbar-thumb {
  background: #0f3460;
  border-radius: 4px;
}

.log-content::-webkit-scrollbar-thumb:hover {
  background: #1a4a7a;
}

.log-empty {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100%;
  color: #666;
}

.empty-icon {
  font-size: 48px;
  margin-bottom: 12px;
}

.empty-text {
  font-size: 14px;
}

.log-item {
  display: flex;
  align-items: flex-start;
  padding: 6px 8px;
  margin-bottom: 2px;
  border-radius: 4px;
  cursor: pointer;
  transition: background 0.2s;
  line-height: 1.5;
  word-break: break-all;
}

.log-item:hover {
  background: rgba(255, 255, 255, 0.05);
}

.log-time {
  color: #666;
  margin-right: 8px;
  flex-shrink: 0;
}

.log-level {
  padding: 1px 6px;
  border-radius: 3px;
  font-size: 10px;
  font-weight: bold;
  margin-right: 8px;
  flex-shrink: 0;
}

.log-level.debug { background: #444; color: #888; }
.log-level.info { background: #1a4a7a; color: #ccc; }
.log-level.warning { background: #856404; color: #ffcc00; }
.log-level.error { background: #7a1a1a; color: #ff4444; }
.log-level.success { background: #1a7a4a; color: #00ff66; }

.log-node {
  color: #00a8cc;
  margin-right: 8px;
  flex-shrink: 0;
}

.log-message {
  color: #e0e0e0;
  flex: 1;
}

.log-debug .log-message { color: #888; }
.log-info .log-message { color: #ccc; }
.log-warning .log-message { color: #ffcc00; }
.log-error .log-message { color: #ff4444; }
.log-success .log-message { color: #00ff66; }

.log-status {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 12px;
  background: #16213e;
  border-top: 1px solid #0f3460;
  font-size: 12px;
  color: #888;
}

.status-left {
  display: flex;
  align-items: center;
  gap: 6px;
}

.connection-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  animation: pulse 2s infinite;
}

.connection-dot.connected { background: #00ff66; }
.connection-dot.connecting { background: #ffcc00; }
.connection-dot.disconnected { background: #666; }
.connection-dot.reconnecting { background: #ffcc00; }
.connection-dot.error { background: #ff4444; }

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}

.status-center {
  display: flex;
  align-items: center;
  gap: 12px;
}

.filter-tag {
  padding: 2px 6px;
  background: #0f3460;
  border-radius: 3px;
  color: #00a8cc;
}

.log-detail-modal {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.7);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.log-detail-content {
  background: #1a1a2e;
  border-radius: 8px;
  max-width: 600px;
  width: 90%;
  max-height: 80vh;
  overflow: auto;
}

.detail-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 16px;
  background: #16213e;
  border-bottom: 1px solid #0f3460;
  color: #e0e0e0;
  font-weight: bold;
}

.btn-close {
  background: none;
  border: none;
  color: #888;
  font-size: 18px;
  cursor: pointer;
}

.btn-close:hover {
  color: #e0e0e0;
}

.detail-body {
  padding: 16px;
}

.detail-row {
  margin-bottom: 12px;
}

.detail-label {
  color: #888;
  margin-right: 8px;
}

.detail-value {
  color: #e0e0e0;
}

.detail-json {
  background: #0d0d1a;
  padding: 12px;
  border-radius: 4px;
  overflow: auto;
  color: #00a8cc;
  font-size: 12px;
  margin-top: 8px;
}

@media (max-width: 768px) {
  .log-toolbar {
    flex-direction: column;
    align-items: stretch;
  }
  
  .toolbar-left,
  .toolbar-right {
    justify-content: center;
  }
  
  .search-input {
    width: 100%;
  }
  
  .search-input:focus {
    width: 100%;
  }
}
</style>
