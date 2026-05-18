<template>
  <teleport to="body">
    <div
      v-if="logState.collapsed"
      class="log-toggle-btn"
      @click="logState.collapsed = false"
      title="展开日志面板"
    >
      <svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
        <polyline points="14 2 14 8 20 8"></polyline>
        <line x1="16" y1="13" x2="8" y2="13"></line>
        <line x1="16" y1="17" x2="8" y2="17"></line>
        <polyline points="10 9 9 9 8 9"></polyline>
      </svg>
      <span v-if="logState.logs.length" class="log-badge">{{ logState.logs.length }}</span>
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
        <span class="log-panel-title">实时日志</span>
        <div class="log-panel-actions">
          <button class="log-action-btn" @click="clearLogs" title="清空日志">
            <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="3 6 5 6 21 6"></polyline>
              <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
            </svg>
          </button>
          <button class="log-action-btn" @click="logState.collapsed = true" title="折叠面板">
            <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round">
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
          </button>
        </div>
      </div>

      <div ref="logListRef" class="log-panel-body">
        <div
          v-for="log in logState.logs"
          :key="log.id"
          class="log-entry"
          :style="{ borderLeftColor: levelColor(log.level) }"
        >
          <span class="log-time">{{ log.timestamp }}</span>
          <span
            class="log-level-tag"
            :style="{ backgroundColor: levelColor(log.level) }"
          >{{ log.level }}</span>
          <span class="log-msg">{{ log.message }}</span>
        </div>
        <div v-if="logState.logs.length === 0" class="log-empty">暂无日志</div>
      </div>
    </div>
  </teleport>
</template>

<script setup>
import { ref, reactive, watch, nextTick, onBeforeUnmount } from 'vue'
import { logState, clearLogs } from '../composables/useLogBus.js'

const panelRef = ref(null)
const logListRef = ref(null)

const position = reactive({ x: null, y: null })

const panelStyle = ref({})

const isDragging = ref(false)
const dragOffset = reactive({ x: 0, y: 0 })

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

function levelColor(level) {
  const colors = {
    INFO: '#2196F3',
    WARNING: '#FF9800',
    ERROR: '#F44336'
  }
  return colors[level] || '#2196F3'
}

watch(() => logState.logs.length, () => {
  nextTick(() => {
    if (logListRef.value) {
      logListRef.value.scrollTop = logListRef.value.scrollHeight
    }
  })
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

.log-panel {
  position: fixed;
  bottom: 24px;
  right: 24px;
  width: 420px;
  max-height: 360px;
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

.log-panel-body {
  flex: 1;
  overflow-y: auto;
  padding: 8px 12px;
  display: flex;
  flex-direction: column;
  gap: 4px;
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
</style>