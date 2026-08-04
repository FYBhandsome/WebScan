<template>
  <div class="page active" @click="onPageClick">
    <div class="agent-workspace-layout">
      
      <div class="main-console">
        <ChatArea 
          :blocks="workspaceBlocks" 
          :is-typing="isTyping"
          :current-thinking="currentThinking"
          :is-thinking="isThinking"
          @action="handleBlockAction"
          @submit-input="handleInputResponse"
        />
        <CommandInput 
          v-show="!inputCollapsed"
          v-model="inputText"
          :disabled="isTyping && !waitingForChoice"
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
        @navigate="handleHistoryNavigate"
      />
      
    </div>

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
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useAgentChat } from '../../composables/useAgentChat.js'
import ChatArea from '../../components/AgentWorkspace/ChatArea.vue'
import CommandInput from '../../components/AgentWorkspace/CommandInput.vue'
import HistoryRail from '../../components/AgentWorkspace/HistoryRail.vue'

const inputCollapsed = ref(false)

const onPageClick = () => {
  if (!inputCollapsed.value) {
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
  handleStop,
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
}

.main-console {
  flex: 1;
  display: flex;
  flex-direction: column;
  position: relative;
  width: 100%;
  min-width: 0; 
}

.floating-rail {
  position: absolute;
  right: 10px;
  top: 0;
  bottom: 90px;
  z-index: 50;
}

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
