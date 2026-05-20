<template>
  <teleport to="body">
    <div
      v-if="isCollapsed"
      class="log-toggle-btn"
      @click="togglePanel"
      title="展开日志面板"
    >
      <svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
        <polyline points="14 2 14 8 20 8"></polyline>
        <line x1="16" y1="13" x2="8" y2="13"></line>
        <line x1="16" y1="17" x2="8" y2="17"></line>
        <polyline points="10 9 9 9 8 9"></polyline>
      </svg>
      <span v-if="logs.length" class="log-badge">{{ logs.length > 99 ? '99+' : logs.length }}</span>
      <span v-if="!isConnected" class="log-status-indicator disconnected"></span>
    </div>

    <div
      v-else
      ref="panelRef"
      class="log-panel"
      :style="panelStyle"
    >
      <div
        class="log-panel-header"
        @mousedown="onDragStart"
      >
        <span class="log-panel-title">
          实时日志
          <span class="log-connection-status" :class="{ connected: isConnected }">
            {{ isConnected ? '已连接' : '未连接' }}
          </span>
        </span>
        <div class="log-panel-actions">
          <button class="log-action-btn" @click="loadHistory" title="加载历史">
            <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="1 4 1 10 7 10"></polyline>
              <path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"></path>
            </svg>
          </button>
          <button class="log-action-btn" @click="handleClearLogs" title="清空日志">
            <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="3 6 5 6 21 6"></polyline>
              <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
            </svg>
          </button>
          <button class="log-action-btn" @click="togglePanel" title="折叠面板">
            <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round">
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
          </button>
        </div>
      </div>

      <div class="log-filter-bar">
        <button 
          v-for="filter in filters" 
          :key="filter.value"
          class="filter-btn"
          :class="{ active: activeFilter === filter.value }"
          @click="activeFilter = filter.value"
        >
          {{ filter.label }}
        </button>
      </div>

      <div ref="logListRef" class="log-panel-body">
        <div
          v-for="log in filteredLogs"
          :key="log.id"
          class="log-entry"
          :class="`log-level-${log.level.toLowerCase()}`"
          :style="{ borderLeftColor: log.color }"
        >
          <span class="log-time">{{ formatTime(log.timestamp) }}</span>
          <span
            class="log-level-tag"
            :style="{ backgroundColor: log.color }"
          >{{ log.level }}</span>
          <span class="log-node" v-if="log.node && log.node !== '-'">[{{ log.node }}]</span>
          <span class="log-msg">{{ log.message }}</span>
        </div>
        <div v-if="filteredLogs.length === 0" class="log-empty">
          {{ isConnected ? '暂无日志' : '正在连接...' }}
        </div>
      </div>

      <div class="log-panel-footer">
        <span class="log-count">共 {{ filteredLogs.length }} 条日志</span>
      </div>
    </div>
  </teleport>
</template>

<script setup>
import { ref, reactive, computed, watch, nextTick, onMounted, onBeforeUnmount } from 'vue'
import { useLogWebSocket } from '../services/logWebSocket.js'

const {
  logs,
  connect,
  clearLogs,
  getHistory,
  isConnected
} = useLogWebSocket()

const panelRef = ref(null)
const logListRef = ref(null)
const isCollapsed = ref(true)

const position = reactive({ x: null, y: null })
const panelStyle = ref({})

const isDragging = ref(false)
const dragOffset = reactive({ x: 0, y: 0 })

const activeFilter = ref('all')
const filters = [
  { label: '全部', value: 'all' },
  { label: 'INFO', value: 'INFO' },
  { label: 'WARN', value: 'WARNING' },
  { label: 'ERROR', value: 'ERROR' },
  { label: 'SUCCESS', value: 'SUCCESS' }
]

const filteredLogs = computed(() => {
  if (activeFilter.value === 'all') {
    return logs.value
  }
  return logs.value.filter(log => log.level === activeFilter.value)
})

function togglePanel() {
  isCollapsed.value = !isCollapsed.value
}

function handleClearLogs() {
  clearLogs()
}

function loadHistory() {
  getHistory(100)
}

function formatTime(timestamp) {
  if (!timestamp) return ''
  try {
    const d = new Date(timestamp)
    return d.toLocaleTimeString('zh-CN', { hour12: false })
  } catch {
    return timestamp
  }
}

function onDragStart(e) {
  if (e.target.closest('.log-action-btn')) return
  isDragging.value = true
  const rect = panelRef.value.getBoundingClientRect()
  dragOffset.x = e.clientX - rect.left
  dragOffset.y = e.clientY - rect.top
  document.addEventListener('mousemove', onDragMove)
  document.addEventListener('mouseup', onDragEnd)
}

function onDragMove(e) {
  if (!isDragging.value) return
  position.x = window.innerWidth - (e.clientX - dragOffset.x) - panelRef.value.offsetWidth
  position.y = window.innerHeight - (e.clientY - dragOffset.y) - panelRef.value.offsetHeight
  if (position.x < 0) position.x = 0
  if (position.y < 0) position.y = 0
  if (position.x + panelRef.value.offsetWidth > window.innerWidth) {
    position.x = window.innerWidth - panelRef.value.offsetWidth
  }
  if (position.y + panelRef.value.offsetHeight > window.innerHeight) {
    position.y = window.innerHeight - panelRef.value.offsetHeight
  }
  panelStyle.value = {
    right: position.x + 'px',
    bottom: position.y + 'px'
  }
}

function onDragEnd() {
  isDragging.value = false
  document.removeEventListener('mousemove', onDragMove)
  document.removeEventListener('mouseup', onDragEnd)
}

watch(() => logs.value.length, () => {
  nextTick(() => {
    if (logListRef.value) {
      logListRef.value.scrollTop = logListRef.value.scrollHeight
    }
  })
})

onMounted(() => {
  connect()
})

onBeforeUnmount(() => {
  document.removeEventListener('mousemove', onDragMove)
  document.removeEventListener('mouseup', onDragEnd)
})
</script>

<style scoped>
.log-toggle-btn {
  position: fixed;
  bottom: 24px;
  right: 24px;
  width: 44px;
  height: 44px;
  border-radius: 50%;
  background: #ffffff;
  border: 1px solid #E4E4E7;
  color: #52525B;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.08), 0 1px 4px rgba(0, 0, 0, 0.04);
  z-index: 9999;
  transition: all 0.2s ease;
  position: relative;
}

.log-toggle-btn:hover {
  background: #F4F4F5;
  border-color: #10B981;
  color: #10B981;
  box-shadow: 0 6px 20px rgba(16, 185, 129, 0.15);
}

.log-badge {
  position: absolute;
  top: -4px;
  right: -4px;
  min-width: 18px;
  height: 18px;
  border-radius: 9px;
  background: #F44336;
  color: #fff;
  font-size: 10px;
  font-weight: 700;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 0 5px;
  line-height: 1;
}

.log-status-indicator {
  position: absolute;
  bottom: -2px;
  left: 50%;
  transform: translateX(-50%);
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #F44336;
  border: 2px solid #fff;
}

.log-status-indicator.connected {
  background: #10B981;
}

.log-panel {
  position: fixed;
  bottom: 24px;
  right: 24px;
  width: 480px;
  max-height: 420px;
  background: #ffffff;
  border: 1px solid #E4E4E7;
  border-radius: 12px;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.12), 0 2px 8px rgba(0, 0, 0, 0.06);
  z-index: 9999;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  animation: panel-appear 0.2s ease;
}

@keyframes panel-appear {
  from {
    opacity: 0;
    transform: translateY(12px) scale(0.96);
  }
  to {
    opacity: 1;
    transform: translateY(0) scale(1);
  }
}

.log-panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 16px;
  border-bottom: 1px solid #F4F4F5;
  cursor: grab;
  user-select: none;
  background: #FAFAFA;
  flex-shrink: 0;
}

.log-panel-header:active {
  cursor: grabbing;
}

.log-panel-title {
  font-size: 13px;
  font-weight: 600;
  color: #18181B;
  display: flex;
  align-items: center;
  gap: 8px;
}

.log-connection-status {
  font-size: 11px;
  font-weight: 500;
  color: #A1A1AA;
  padding: 2px 6px;
  border-radius: 4px;
  background: #F4F4F5;
}

.log-connection-status.connected {
  color: #10B981;
  background: #ECFDF5;
}

.log-panel-actions {
  display: flex;
  gap: 4px;
}

.log-action-btn {
  width: 28px;
  height: 28px;
  border-radius: 6px;
  border: none;
  background: transparent;
  color: #A1A1AA;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.15s ease;
}

.log-action-btn:hover {
  background: #F4F4F5;
  color: #52525B;
}

.log-filter-bar {
  display: flex;
  gap: 4px;
  padding: 8px 12px;
  border-bottom: 1px solid #F4F4F5;
  flex-shrink: 0;
}

.filter-btn {
  padding: 4px 10px;
  border-radius: 4px;
  border: 1px solid #E4E4E7;
  background: #fff;
  color: #71717A;
  font-size: 11px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.15s ease;
}

.filter-btn:hover {
  border-color: #D4D4D8;
  color: #52525B;
}

.filter-btn.active {
  background: #18181B;
  border-color: #18181B;
  color: #fff;
}

.log-panel-body {
  flex: 1;
  overflow-y: auto;
  padding: 8px 12px;
  display: flex;
  flex-direction: column;
  gap: 4px;
  min-height: 200px;
  max-height: 280px;
}

.log-panel-body::-webkit-scrollbar {
  width: 4px;
}

.log-panel-body::-webkit-scrollbar-track {
  background: transparent;
}

.log-panel-body::-webkit-scrollbar-thumb {
  background: #E4E4E7;
  border-radius: 2px;
}

.log-entry {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 6px 10px;
  border-radius: 6px;
  background: #FAFAFA;
  border-left: 3px solid #2196F3;
  font-size: 12px;
  line-height: 1.5;
  animation: log-slide 0.15s ease;
}

@keyframes log-slide {
  from {
    opacity: 0;
    transform: translateX(-8px);
  }
  to {
    opacity: 1;
    transform: translateX(0);
  }
}

.log-level-error {
  background: #FEF2F2;
}

.log-level-warning {
  background: #FFFBEB;
}

.log-level-success {
  background: #ECFDF5;
}

.log-time {
  color: #A1A1AA;
  white-space: nowrap;
  font-family: 'SF Mono', 'Cascadia Code', 'Consolas', monospace;
  font-size: 11px;
  flex-shrink: 0;
  min-width: 68px;
}

.log-level-tag {
  padding: 1px 6px;
  border-radius: 3px;
  color: #fff;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.5px;
  flex-shrink: 0;
  min-width: 52px;
  text-align: center;
}

.log-node {
  color: #71717A;
  font-size: 11px;
  flex-shrink: 0;
}

.log-msg {
  color: #3F3F46;
  word-break: break-all;
  flex: 1;
  min-width: 0;
}

.log-empty {
  text-align: center;
  color: #A1A1AA;
  font-size: 12px;
  padding: 24px 0;
}

.log-panel-footer {
  padding: 8px 12px;
  border-top: 1px solid #F4F4F5;
  background: #FAFAFA;
  flex-shrink: 0;
}

.log-count {
  font-size: 11px;
  color: #A1A1AA;
}

@media (max-width: 768px) {
  .log-panel {
    width: calc(100vw - 32px);
    right: 16px !important;
    bottom: 16px !important;
  }
}
</style>
