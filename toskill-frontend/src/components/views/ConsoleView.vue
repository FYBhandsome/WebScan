<template>
  <div class="page active" @click="onPageClick">
    <div class="agent-workspace-layout">
      <!-- 对话列 -->
      <ConversationSidebar
        v-show="convSidebarVisible"
        :conversations="conversationState.conversations"
        :current-id="conversationState.currentId"
        :scan-active="scanActive"
        @new-conversation="handleNewConversation"
        @switch-conversation="handleSwitchConversation"
        @delete-conversation="handleDeleteConversation"
        @rename-conversation="handleRenameConversation"
        @collapse="convSidebarVisible = false"
      />

      <!-- 收起时的展开按钮 -->
      <button
        v-if="!convSidebarVisible"
        class="conv-expand-btn"
        @click.stop="convSidebarVisible = true"
        title="打开对话列表"
      >
        <svg viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="9 18 15 12 9 6"></polyline>
        </svg>
      </button>

      <div class="main-console">
        <div
          v-if="canResumeScan || scanPause.status === 'resuming'"
          class="scan-pause-toolbar"
          @click.stop
        >
          <span class="scan-pause-status">
            {{ scanPause.status === 'resuming' ? '正在根据聊天内容重新规划...' : '扫描已暂停，可继续聊天' }}
          </span>
          <button
            type="button"
            class="resume-scan-btn"
            :disabled="scanPause.status === 'resuming'"
            @click.stop="resumeScan"
          >
            {{ scanPause.status === 'resuming' ? '正在恢复...' : '继续扫描' }}
          </button>
        </div>
        <ChatArea
          :blocks="workspaceBlocks"
          :is-typing="isTyping"
          :current-thinking="currentThinking"
          :is-thinking="isThinking"
          @action="handleBlockAction"
          @submit-input="handleInputResponse"
        />
        <CommandInput
          v-show="!inputCollapsed || isScanPausedForChat"
          v-model="inputText"
          :disabled="isTyping && !waitingForChoice"
          :is-active="scanActive"
          :chat-mode="isScanPausedForChat"
          :placeholder="chatInputPlaceholder"
          @send="sendMessage"
          @stop="handleStop"
          @quick-action="handleQuickAction"
        />
      </div>

      <HistoryRail
        class="floating-rail"
        :style="{ bottom: inputCollapsed && !isScanPausedForChat ? '60px' : '90px' }"
        :blocks="workspaceBlocks"
        @navigate="handleHistoryNavigate"
      />

    </div>

    <button
      v-if="inputCollapsed && !isScanPausedForChat"
      class="expand-fixed-btn"
      @click.stop="onExpandInput"
      title="展开输入框"
    >
      <svg viewBox="0 0 24 24" width="22" height="22" stroke="currentColor" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round">
        <line x1="12" y1="19" x2="12" y2="5"></line>
        <polyline points="5 12 12 5 19 12"></polyline>
      </svg>
    </button>
  </div>
</template>

<script setup>
import { ref, watch } from 'vue'
import { useAgentChat } from '../../composables/useAgentChat.js'
import { conversationState } from '../../store.js'
import ChatArea from '../../components/AgentWorkspace/ChatArea.vue'
import CommandInput from '../../components/AgentWorkspace/CommandInput.vue'
import HistoryRail from '../../components/AgentWorkspace/HistoryRail.vue'
import ConversationSidebar from '../../components/AgentWorkspace/ConversationSidebar.vue'

// UI 偏好：从 localStorage 恢复
const UI_PREFS_KEY = 'toskill_ui_prefs'
const loadUiPrefs = () => {
  try {
    const raw = localStorage.getItem(UI_PREFS_KEY)
    if (raw) return JSON.parse(raw)
  } catch (e) { /* ignore */ }
  return {}
}
const _initialPrefs = loadUiPrefs()

const inputCollapsed = ref(_initialPrefs.inputCollapsed === true)
const convSidebarVisible = ref(_initialPrefs.convSidebarVisible !== false)

// UI 偏好变化时持久化
let _uiPrefsTimer = null
watch([convSidebarVisible, inputCollapsed], () => {
  if (_uiPrefsTimer) clearTimeout(_uiPrefsTimer)
  _uiPrefsTimer = setTimeout(() => {
    try {
      localStorage.setItem(UI_PREFS_KEY, JSON.stringify({
        convSidebarVisible: convSidebarVisible.value,
        inputCollapsed: inputCollapsed.value,
        savedAt: new Date().toISOString()
      }))
    } catch (e) { /* ignore */ }
  }, 300)
})

const onPageClick = () => {
  if (!inputCollapsed.value && scanPause.status !== 'pausing' && !isScanPausedForChat.value) {
    inputCollapsed.value = true
  }
}

const onExpandInput = () => {
  inputCollapsed.value = false
}

const handleHistoryNavigate = (id) => {
  const blockElement = document.querySelector(`[data-block-id="${id}"]`)
  blockElement?.scrollIntoView({ behavior: 'smooth', block: 'center' })
}

const {
  inputText,
  workspaceBlocks,
  isTyping,
  currentThinking,
  isThinking,
  waitingForChoice,
  sendMessage,
  handleQuickAction,
  handleBlockAction,
  handleInputResponse,
  scanActive,
  scanPause,
  isScanPausedForChat,
  canResumeScan,
  chatInputPlaceholder,
  resumeScan,
  handleStop,
  handleNewConversation,
  handleSwitchConversation,
  handleDeleteConversation,
  handleRenameConversation,
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
  width: 100%;
}

.main-console {
  flex: 1;
  display: flex;
  flex-direction: column;
  position: relative;
  width: 100%;
  min-width: 0; 
}

.scan-pause-toolbar {
  position: absolute;
  top: 12px;
  right: 28px;
  z-index: 60;
  display: flex;
  align-items: center;
  gap: 10px;
  max-width: calc(100% - 56px);
  padding: 6px 8px 6px 12px;
  border: 1px solid #bbf7d0;
  border-radius: 9px;
  background: rgba(240, 253, 244, .96);
  box-shadow: 0 4px 14px rgba(16, 185, 129, .12);
}

.scan-pause-status {
  overflow: hidden;
  color: #047857;
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.resume-scan-btn {
  flex: 0 0 auto;
  padding: 7px 13px;
  border: 1px solid #10b981;
  border-radius: 6px;
  background: #10b981;
  color: #fff;
  font: 13px var(--font-family);
  cursor: pointer;
}

.resume-scan-btn:hover:not(:disabled) { background: #059669; border-color: #059669; }
.resume-scan-btn:disabled { opacity: .65; cursor: wait; }

.floating-rail {
  position: absolute;
  right: 10px;
  top: 0;
  bottom: 90px;
  z-index: 50;
}

.conv-expand-btn {
  position: absolute;
  left: 0;
  top: 12px;
  width: 32px;
  height: 32px;
  border: 1px solid #E4E4E7;
  border-radius: 6px;
  background: #FFFFFF;
  color: #52525B;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 30;
  box-shadow: 0 2px 8px rgba(0,0,0,0.06);
}
.conv-expand-btn:hover { border-color: #10B981; color: #10B981; }

.expand-fixed-btn {
  position: fixed;
  bottom: 24px;
  left: 50%;
  transform: translateX(-50%);
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
  z-index: 100;
  animation: btn-rise 0.35s cubic-bezier(0.34, 1.56, 0.64, 1);
}

.expand-fixed-btn:hover {
  background: #F4F4F5;
  border-color: #10B981;
  color: #10B981;
  box-shadow: 0 6px 24px rgba(16, 185, 129, 0.2);
  transform: translateX(-50%) translateY(-2px);
}

@keyframes btn-rise {
  from {
    opacity: 0;
    transform: translateX(-50%) translateY(12px) scale(0.8);
  }
  to {
    opacity: 1;
    transform: translateX(-50%) translateY(0) scale(1);
  }
}
</style>
