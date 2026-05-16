<template>
  <div class="chat-area" ref="scrollContainer">
    <div v-if="blocks.length === 0" class="welcome-section">
      <h2 class="welcome-brand">TOSK<span class="accent-dot">i</span>ll</h2>
      <p class="welcome-desc">System Online. 请输入目标 URL 或指令以初始化扫描进程。</p>
    </div>

    <div v-for="block in blocks" :key="block.id" class="message-wrapper" :class="block.type === 'user_command' ? 'is-user' : 'is-ai'">
      <div v-if="block.type !== 'user_command'" class="ai-avatar">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M4 10V4H10" stroke="#18181B" stroke-width="2.5" stroke-linecap="square"/>
          <path d="M20 14V20H14" stroke="#18181B" stroke-width="2.5" stroke-linecap="square"/>
          <circle cx="12" cy="12" r="3" fill="#10B981" />
        </svg>
      </div>
      <div class="bubble-content" :class="block.type === 'user_command' ? 'user-bubble' : 'ai-bubble'">
        
        <template v-if="block.type === 'user_command'">
          <div class="text-content">{{ block.content }}</div>
        </template>

        <template v-else-if="block.type === 'agent_text'">
          <details v-if="block.thought" class="cot-details">
            <summary>Agent 思考过程 (Chain of Thought)</summary>
            <div class="cot-content">{{ block.thought }}</div>
          </details>
          <div class="text-content pre-wrap">{{ block.content }}</div>
        </template>

        <template v-else-if="block.type === 'agent_action_request'">
          <div :class="['proposal-card', { resolved: block.resolved }]">
            <div class="card-header">
              <span class="tag warning">ACTION REQUIRED</span>
              <h4>{{ block.title }}</h4>
            </div>
            <div class="card-body">
              <p class="desc">{{ block.description }}</p>
              <div class="code-params" v-if="block.params && Object.keys(block.params).length">
                <div v-for="(val, key) in block.params" :key="key">
                  <span class="var-name">{{ key }}</span>: <span class="var-value">{{ val }}</span>
                </div>
              </div>
            </div>
            <div class="card-actions">
              <button 
                v-for="opt in block.options" :key="opt.key"
                :class="['btn', opt.style === 'btn-primary' ? 'btn-emerald' : 'btn-ghost']"
                :disabled="block.resolved"
                @click="$emit('action', block, opt.key, opt.label)"
              >
                {{ opt.label }}
              </button>
            </div>
          </div>
        </template>
      </div>
    </div>

    <div v-if="isTyping" class="message-wrapper is-ai">
      <div class="ai-avatar thinking">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path class="corner-tl" d="M4 10V4H10" stroke="#18181B" stroke-width="2.5" stroke-linecap="square"/>
          <path class="corner-br" d="M20 14V20H14" stroke="#18181B" stroke-width="2.5" stroke-linecap="square"/>
          <circle cx="12" cy="12" r="3" fill="#10B981" />
        </svg>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, watch, nextTick } from 'vue'

const props = defineProps({
  blocks: Array,
  isTyping: Boolean
})

defineEmits(['action', 'submit-input'])

const scrollContainer = ref(null)

watch(() => [props.blocks.length, props.isTyping], async () => {
  await nextTick()
  if (scrollContainer.value) {
    scrollContainer.value.scrollTop = scrollContainer.value.scrollHeight
  }
}, { deep: true })
</script>

<style scoped>
/* 欢迎区保留 */
.welcome-section { margin: auto; text-align: center; }
.welcome-brand { font-size: 50px; font-weight: 900; margin-bottom: 8px; }
.accent-dot { color: #10B981; }
.welcome-desc { color: #666; font-family: monospace; font-size: 13px; }

/* === 气泡基础布局 === */
.message-wrapper {
  display: flex;
  align-items: flex-start;
  max-width: 85%;
  gap: 12px;
}

.is-user { align-self: flex-end; flex-direction: row-reverse; }
.is-ai { align-self: flex-start; }

/* === 气泡视觉规范 === */
.bubble-content {
  padding: 14px 18px;
  font-size: 14px;
  line-height: 1.6;
}

/* 用户气泡：靠右，无头像，极浅灰，右下直角 */
.user-bubble {
  background: #F4F4F5;
  color: #111;
  border-radius: 12px 12px 0 12px; /* 重点：右下直角 */
  font-weight: 500;
}

/* AI 气泡：靠左，纯白带微阴影，左上直角 */
.ai-bubble {
  background: #FFFFFF;
  color: #111;
  border-radius: 0 12px 12px 12px; /* 重点：左上直角 */
  box-shadow: 0 2px 12px rgba(0, 0, 0, 0.04), 0 1px 2px rgba(0,0,0,0.02);
  border: 1px solid rgba(0,0,0,0.03);
}

.pre-wrap { white-space: pre-wrap; word-wrap: break-word; }

/* === 思考链 (Chain of Thought) === */
.cot-details {
  margin-bottom: 12px;
  padding: 8px 12px;
  background: #FAFAFA;
  border-radius: 6px;
  border-left: 2px solid #10B981;
}
.cot-details summary {
  font-size: 12px;
  font-family: monospace;
  color: #666;
  cursor: pointer;
  user-select: none;
}
.cot-content {
  margin-top: 8px;
  font-size: 12px;
  color: #888;
  font-family: monospace;
  white-space: pre-wrap;
}

/* === Proposal Card (深色终端风格) === */
.proposal-card {
  background: #181825; /* 深色极客风 */
  border-radius: 8px;
  border: 1px solid #313244;
  overflow: hidden;
  width: 400px;
  max-width: 100%;
  color: #CDD6F4;
  margin-top: 8px;
}
.proposal-card.resolved { opacity: 0.6; pointer-events: none; filter: grayscale(100%); }

.card-header {
  padding: 10px 14px;
  border-bottom: 1px solid #313244;
  display: flex;
  align-items: center;
  gap: 10px;
  background: #11111B;
}
.card-header h4 { margin: 0; font-size: 13px; color: #fff; font-family: monospace; }
.tag.warning { background: rgba(243, 139, 168, 0.15); color: #F38BA8; padding: 2px 6px; font-size: 10px; border-radius: 4px; border: 1px solid rgba(243, 139, 168, 0.3); }

.card-body { padding: 14px; }
.desc { font-size: 13px; margin-bottom: 12px; color: #BAC2DE; }
.code-params {
  background: #11111B;
  padding: 10px;
  border-radius: 6px;
  font-family: monospace;
  font-size: 12px;
}
.var-name { color: #89B4FA; }
.var-value { color: #A6E3A1; }

.card-actions {
  padding: 12px 14px;
  background: #11111B;
  border-top: 1px solid #313244;
  display: flex;
  gap: 8px;
}
.btn { padding: 6px 12px; border-radius: 4px; font-size: 12px; font-weight: 600; cursor: pointer; transition: all 0.2s; border: 1px solid transparent; }
.btn-emerald { background: #10B981; color: #111; }
.btn-emerald:hover { background: #0EA5E9; filter: brightness(1.1); }
.btn-ghost { background: transparent; color: #BAC2DE; border-color: #45475A; }
.btn-ghost:hover { background: #313244; color: #fff; }

/* === AI 头像 (项目Logo) === */
.ai-avatar {
  width: 28px;
  height: 28px;
  flex-shrink: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 8px;
  background: #F4F4F5;
  padding: 4px;
}

.ai-avatar svg {
  width: 100%;
  height: 100%;
}

.ai-avatar.thinking {
  background: transparent;
  padding: 0;
}

.ai-avatar.thinking svg .corner-tl {
  animation: scan-tl 1.5s ease-in-out infinite;
  transform-origin: 4px 4px;
}

.ai-avatar.thinking svg .corner-br {
  animation: scan-br 1.5s ease-in-out infinite;
  transform-origin: 20px 20px;
}

@keyframes scan-tl {
  0%, 100% { transform: translate(0, 0) scale(1); }
  50%      { transform: translate(2.5px, 2.5px) scale(0.65); }
}

@keyframes scan-br {
  0%, 100% { transform: translate(0, 0) scale(1); }
  50%      { transform: translate(-2.5px, -2.5px) scale(0.65); }
}
.chat-area {
  position: relative;
  flex: 1;
  overflow-y: auto;
  padding: 40px 20px 20px;
  display: flex;
  flex-direction: column;
  gap: 24px;
  
  padding-right: 60px; 
}

/* 极简超低透明度滑动条 */
.chat-area::-webkit-scrollbar {
  width: 5px; /* 极细的滚动条 */
}
.chat-area::-webkit-scrollbar-track {
  background: transparent; /* 轨道完全透明 */
}
.chat-area::-webkit-scrollbar-thumb {
  background-color: rgba(156, 163, 175, 0.15); /* 极低透明度的浅灰色，平时几乎隐形 */
  border-radius: 4px;
}
.chat-area:hover::-webkit-scrollbar-thumb {
  background-color: rgba(156, 163, 175, 0.4);
}

</style>