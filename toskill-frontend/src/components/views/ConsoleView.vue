<template>
  <div class="page active" @click="onPageClick">
    <div class="agent-workspace-layout">
      
      <div class="main-console">
        <ChatArea 
          :blocks="workspaceBlocks" 
          :is-typing="isTyping"
          :scan-progress="scanProgress"
          @action="handleBlockAction"
          @submit-input="handleInputResponse"
          @select-mode="handleModeSelect"
          @scan-confirm="handleScanConfirm"
          @scan-cancel="handleScanCancel"
        />
        <CommandInput 
          v-show="!inputCollapsed"
          v-model="inputText"
          :disabled="isTyping || waitingForChoice"
          :is-active="scanActive"
          @send="sendMessage"
          @stop="handleStop"
          @quick-action="handleQuickAction"
        />
      </div>

      <HistoryRail 
        class="floating-rail"
        :style="{ bottom: inputCollapsed ? '60px' : '90px' }"
        :blocks="workspaceBlocks" 
        @navigate="handleBlockAction" 
      />
      
    </div>

    <div
      v-if="logPanelVisible"
      class="log-panel-wrapper"
      :style="{ height: logPanelHeight + 'px' }"
    >
      <div
        class="log-resize-handle"
        @mousedown.prevent="startResize"
      ></div>

      <div class="log-panel">
        <div class="log-panel-header">
          <div class="log-panel-title">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="4 17 10 11 4 5"></polyline>
              <line x1="12" y1="19" x2="20" y2="19"></line>
            </svg>
            <span>终端日志</span>
            <span v-if="logEntries.length > 0" class="log-count">{{ logEntries.length }}</span>
          </div>
          <div class="log-panel-actions">
            <button class="log-action-btn" @click="toggleAutoScroll" :title="autoScroll ? '暂停自动滚动' : '开启自动滚动'">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path v-if="autoScroll" d="M13 17l5-5-5-5M6 17l5-5-5-5"></path>
                <path v-else d="M11 17l-5-5 5-5M18 17l-5-5 5-5"></path>
              </svg>
            </button>
            <button class="log-action-btn" @click="clearLogs" title="清空日志">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <polyline points="3 6 5 6 21 6"></polyline>
                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
              </svg>
            </button>
            <button class="log-action-btn" @click="logPanelVisible = false" title="关闭日志面板">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <line x1="18" y1="6" x2="6" y2="18"></line>
                <line x1="6" y1="6" x2="18" y2="18"></line>
              </svg>
            </button>
          </div>
        </div>

        <div class="log-panel-body" ref="logBodyRef">
          <div v-if="logEntries.length === 0" class="log-empty">暂无日志输出</div>
          <div
            v-for="(entry, idx) in logEntries"
            :key="idx"
            class="log-entry"
            :class="'log-level-' + entry.level"
          >
            <span class="log-timestamp">{{ entry.timestamp }}</span>
            <span class="log-level" :class="'level-' + entry.level">{{ entry.level.toUpperCase() }}</span>
            <span class="log-source" v-if="entry.source">{{ entry.source }}</span>
            <span class="log-message">{{ entry.message }}</span>
          </div>
        </div>
      </div>
    </div>

    <div class="bottom-bar">
      <button
        v-if="inputCollapsed"
        class="expand-fixed-btn"
        @click.stop="onExpandInput"
        title="展开输入框"
      >
        <svg viewBox="0 0 24 24" width="22" height="22" stroke="currentColor" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round">
          <line x1="12" y1="19" x2="12" y2="5"></line>
          <polyline points="5 12 12 5 19 12"></polyline>
        </svg>
      </button>

      <button
        class="log-toggle-btn"
        :class="{ active: logPanelVisible }"
        @click.stop="logPanelVisible = !logPanelVisible"
        title="终端日志"
      >
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="4 17 10 11 4 5"></polyline>
          <line x1="12" y1="19" x2="20" y2="19"></line>
        </svg>
        <span v-if="logEntries.length > 0" class="log-badge">{{ logEntries.length }}</span>
      </button>
    </div>
  </div>
</template>

<script setup>
import { ref, watch, nextTick, onMounted, onUnmounted } from 'vue'
import { useAgentChat } from '../../composables/useAgentChat.js'
import ChatArea from '../../components/AgentWorkspace/ChatArea.vue'
import CommandInput from '../../components/AgentWorkspace/CommandInput.vue'
import HistoryRail from '../../components/AgentWorkspace/HistoryRail.vue'
import { ws } from '../../services/websocket.js'

const inputCollapsed = ref(false)
const logPanelVisible = ref(false)
const logPanelHeight = ref(220)
const autoScroll = ref(true)
const logEntries = ref([])
const logBodyRef = ref(null)

const MIN_PANEL_HEIGHT = 100
const MAX_PANEL_HEIGHT = 600

const onPageClick = () => {
  if (!inputCollapsed.value) {
    inputCollapsed.value = true
  }
}

const onExpandInput = () => {
  inputCollapsed.value = false
}

const toggleAutoScroll = () => {
  autoScroll.value = !autoScroll.value
}

const clearLogs = () => {
  logEntries.value = []
}

const formatTime = () => {
  const now = new Date()
  return now.toLocaleTimeString('en-US', { hour12: false }) + '.' + String(now.getMilliseconds()).padStart(3, '0')
}

const addLog = (level, message, source = '') => {
  logEntries.value.push({
    timestamp: formatTime(),
    level,
    message,
    source
  })
  if (logEntries.value.length > 2000) {
    logEntries.value = logEntries.value.slice(-1500)
  }
  if (autoScroll.value) {
    nextTick(() => {
      if (logBodyRef.value) {
        logBodyRef.value.scrollTop = logBodyRef.value.scrollHeight
      }
    })
  }
}

const wsLogHandler = (data) => {
  if (data.type === 'connected') {
    addLog('info', `WebSocket 已连接 | Session: ${data.payload?.session_id || '-'}`, 'ws')
  } else if (data.type === 'error') {
    addLog('error', data.payload?.error || '未知错误', 'ws')
  } else if (data.type === 'scan_started') {
    addLog('info', `扫描启动 | 目标: ${data.payload?.target || '-'}`, 'scan')
  } else if (data.type === 'scan_completed') {
    addLog('info', `扫描完成 | 目标: ${data.payload?.target || '-'} | 漏洞: ${data.payload?.vulnerabilities_count ?? 0}`, 'scan')
  } else if (data.type === 'scan_cancelled') {
    addLog('warn', '扫描已取消', 'scan')
  } else if (data.type === 'task_started') {
    addLog('info', `执行工具: ${data.payload?.tool || '-'} → ${data.payload?.target || '-'}`, 'tool')
  } else if (data.type === 'task_completed') {
    addLog('info', `工具完成: ${data.payload?.tool || '-'}`, 'tool')
  } else if (data.type === 'task_error') {
    addLog('error', `工具错误 | ${data.payload?.tool || '-'}: ${data.payload?.error || '-'}`, 'tool')
  } else if (data.type === 'tool_execution_started') {
    addLog('info', `工具执行开始: ${data.payload?.tool_name || '-'}`, 'tool')
  } else if (data.type === 'tool_execution_completed') {
    addLog('info', `工具执行完成: ${data.payload?.tool_name || '-'}`, 'tool')
  } else if (data.type === 'script_registered') {
    addLog('info', `脚本注册成功: ${data.payload?.tool_name || '-'}`, 'script')
  } else if (data.type === 'script_generated') {
    addLog('info', `脚本生成完成: ${data.payload?.tool_name || '-'}`, 'script')
  } else if (data.type === 'script_generating') {
    addLog('info', `AI 生成脚本中...`, 'script')
  } else if (data.type === 'ai_message') {
    addLog('info', `AI 响应: ${(data.payload?.content || '').slice(0, 120)}`, 'ai')
  } else if (data.type === 'workflow_resumed') {
    addLog('info', `工作流已恢复`, 'workflow')
  } else if (data.type === 'workflow_progress') {
    addLog('info', `进度: ${data.payload?.stage || '...'} (${data.payload?.completed || 0}/${data.payload?.total || 0})`, 'workflow')
  } else if (data.type === 'ai_decision') {
    addLog('info', `AI 决策: ${data.payload?.next_task || '-'}`, 'ai')
  } else if (data.type === 'high_risk_vulnerability_detected') {
    addLog('error', `高危漏洞! ${data.payload?.message || ''}`, 'scan')
  } else if (data.type === 'report_generated') {
    addLog('info', `报告已生成: ${data.payload?.report_id || '-'}`, 'report')
  }
}

onMounted(() => {
  ws.on('*', wsLogHandler)
  addLog('info', '日志面板已初始化', 'system')
})

onUnmounted(() => {
  ws.off('*', wsLogHandler)
})

let resizing = false
let startY = 0
let startHeight = 0

const startResize = (e) => {
  resizing = true
  startY = e.clientY
  startHeight = logPanelHeight.value

  const onMouseMove = (e) => {
    if (!resizing) return
    const delta = startY - e.clientY
    const newHeight = Math.min(MAX_PANEL_HEIGHT, Math.max(MIN_PANEL_HEIGHT, startHeight + delta))
    logPanelHeight.value = newHeight
  }

  const onMouseUp = () => {
    resizing = false
    document.removeEventListener('mousemove', onMouseMove)
    document.removeEventListener('mouseup', onMouseUp)
    document.body.style.cursor = ''
    document.body.style.userSelect = ''
  }

  document.body.style.cursor = 'ns-resize'
  document.body.style.userSelect = 'none'
  document.addEventListener('mousemove', onMouseMove)
  document.addEventListener('mouseup', onMouseUp)
}

const {
  inputText,
  workspaceBlocks,
  isTyping,
  waitingForChoice,
  sendMessage,
  handleQuickAction,
  handleBlockAction,
  scanProgress,
  handleInputResponse,
  scanActive,
  handleStop,
  handleModeSelect,
  handleScanConfirm,
  handleScanCancel
} = useAgentChat()
</script>

<style scoped>
.page {
  height: 100vh;
  display: flex;
  flex-direction: column;
  background-color: #ffffff;
}

.agent-workspace-layout {
  position: relative;
  display: flex;
  flex-direction: row;
  flex: 1;
  overflow: hidden;
  max-width: 1200px; 
  margin: 0 auto;
  width: 100%;
  min-height: 0;
}

.main-console {
  flex: 1;
  display: flex;
  flex-direction: column;
  position: relative;
  width: 100%;
  min-width: 0; 
  min-height: 0;
  overflow: hidden;
}

.floating-rail {
  position: absolute;
  right: 10px;
  top: 0;
  bottom: 90px;
  z-index: 50;
}

.bottom-bar {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 12px;
  padding: 8px 24px;
  background: #ffffff;
  border-top: 1px solid #E4E4E7;
  flex-shrink: 0;
}

.expand-fixed-btn {
  width: 44px;
  height: 44px;
  border-radius: 50%;
  background: #ffffff;
  border: 1px solid #E4E4E7;
  color: #18181B;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.08), 0 1px 4px rgba(0, 0, 0, 0.04);
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}

.expand-fixed-btn:hover {
  background: #F4F4F5;
  border-color: #10B981;
  color: #10B981;
  box-shadow: 0 6px 24px rgba(16, 185, 129, 0.2);
  transform: translateY(-2px);
}

.log-toggle-btn {
  position: relative;
  width: 44px;
  height: 44px;
  border-radius: 50%;
  background: #ffffff;
  border: 1px solid #E4E4E7;
  color: #71717A;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}

.log-toggle-btn:hover {
  border-color: #10B981;
  color: #10B981;
}

.log-toggle-btn.active {
  background: #18181B;
  border-color: #18181B;
  color: #ffffff;
}

.log-badge {
  position: absolute;
  top: -4px;
  right: -4px;
  min-width: 18px;
  height: 18px;
  border-radius: 9px;
  background: #10B981;
  color: #ffffff;
  font-size: 10px;
  font-weight: 700;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 0 4px;
}

/* ===== Log Panel ===== */
.log-panel-wrapper {
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  border-top: 1px solid #E4E4E7;
  background: #FAFAFA;
  position: relative;
  min-height: 100px;
  max-height: 600px;
}

.log-resize-handle {
  height: 6px;
  cursor: ns-resize;
  background: transparent;
  position: relative;
  flex-shrink: 0;
  z-index: 10;
}

.log-resize-handle::after {
  content: '';
  position: absolute;
  left: 50%;
  top: 50%;
  transform: translate(-50%, -50%);
  width: 32px;
  height: 3px;
  border-radius: 2px;
  background: #D4D4D8;
  transition: background 0.2s;
}

.log-resize-handle:hover::after {
  background: #10B981;
}

.log-panel {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  min-height: 0;
}

.log-panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 6px 16px;
  background: #F4F4F5;
  border-bottom: 1px solid #E4E4E7;
  flex-shrink: 0;
}

.log-panel-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  font-weight: 600;
  color: #52525B;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.log-count {
  font-size: 10px;
  padding: 1px 6px;
  border-radius: 8px;
  background: #D4D4D8;
  color: #3F3F46;
  font-weight: 700;
}

.log-panel-actions {
  display: flex;
  gap: 4px;
}

.log-action-btn {
  width: 26px;
  height: 26px;
  border: none;
  background: transparent;
  border-radius: 4px;
  color: #71717A;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.15s;
}

.log-action-btn:hover {
  background: #E4E4E7;
  color: #18181B;
}

.log-panel-body {
  flex: 1;
  overflow-y: auto;
  overflow-x: hidden;
  padding: 8px 0;
  font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
  font-size: 12px;
  line-height: 1.7;
  min-height: 0;
}

.log-panel-body::-webkit-scrollbar {
  width: 6px;
}

.log-panel-body::-webkit-scrollbar-track {
  background: transparent;
}

.log-panel-body::-webkit-scrollbar-thumb {
  background-color: rgba(156, 163, 175, 0.2);
  border-radius: 3px;
}

.log-panel-body:hover::-webkit-scrollbar-thumb {
  background-color: rgba(156, 163, 175, 0.4);
}

.log-empty {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
  color: #A1A1AA;
  font-size: 13px;
  font-family: inherit;
}

.log-entry {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 2px 16px;
  transition: background 0.1s;
  word-break: break-all;
}

.log-entry:hover {
  background: rgba(0, 0, 0, 0.02);
}

.log-timestamp {
  color: #A1A1AA;
  flex-shrink: 0;
  font-size: 11px;
  min-width: 90px;
}

.log-level {
  flex-shrink: 0;
  font-size: 10px;
  font-weight: 700;
  padding: 1px 5px;
  border-radius: 3px;
  min-width: 40px;
  text-align: center;
}

.log-level.level-info {
  background: #EFF6FF;
  color: #2563EB;
}

.log-level.level-warn {
  background: #FFFBEB;
  color: #D97706;
}

.log-level.level-error {
  background: #FEF2F2;
  color: #DC2626;
}

.log-level.level-debug {
  background: #F4F4F5;
  color: #71717A;
}

.log-source {
  flex-shrink: 0;
  color: #71717A;
  font-size: 11px;
  min-width: 50px;
  max-width: 80px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.log-message {
  color: #3F3F46;
  flex: 1;
  min-width: 0;
}

.log-entry.log-level-error .log-message {
  color: #991B1B;
}

.log-entry.log-level-warn .log-message {
  color: #92400E;
}

@keyframes btn-rise {
  from {
    opacity: 0;
    transform: translateY(12px) scale(0.8);
  }
  to {
    opacity: 1;
    transform: translateY(0) scale(1);
  }
}

@media (max-width: 768px) {
  .log-panel-wrapper {
    max-height: 50vh;
  }

  .log-entry {
    padding: 2px 10px;
  }

  .log-source {
    display: none;
  }

  .log-timestamp {
    min-width: 70px;
    font-size: 10px;
  }
}
</style>
