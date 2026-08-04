<template>
  <div ref="scrollContainer" class="chat-area" @scroll.passive="handleScroll">
    <div v-if="blocks.length === 0" class="welcome-section">
      <h2 class="welcome-brand">TOSK<span class="accent-dot">i</span>ll</h2>
      <p class="welcome-desc">System Online. 请输入目标 URL 或指令以初始化扫描进程。</p>
    </div>

    <section
      v-for="block in blocks"
      :key="block.id"
      :data-block-id="block.id"
      class="content-block"
      :class="`type-${block.type}`"
    >
      <div v-if="block.type === 'user_command'" class="user-message">
        {{ block.content }}
      </div>

      <AgentRunTimeline
        v-else-if="block.type === 'agent_run'"
        :run="block"
        @action="(...args) => $emit('action', ...args)"
        @submit-input="(...args) => $emit('submit-input', ...args)"
      />

      <div
        v-else
        class="assistant-message markdown-body"
        :class="{ 'is-error': block.tone === 'error' || block.type === 'agent_error' }"
        v-html="renderMarkdown(block.content || block.description || '')"
      ></div>
    </section>

    <div v-if="isThinking || currentThinking" class="live-thinking">
      <span class="thinking-dot"></span>
      <div>
        <strong>{{ isThinking ? '正在思考' : '正在执行' }}</strong>
        <div class="thinking-text">{{ currentThinking || '智能体正在处理当前任务，请稍候…' }}</div>
      </div>
    </div>

    <button v-if="showNewActivity" class="new-activity" type="button" @click="scrollToLatest(true)">
      有新动态，回到最新位置
    </button>
  </div>
</template>

<script setup>
import { nextTick, onMounted, ref, watch } from 'vue'
import { marked } from 'marked'
import AgentRunTimeline from './AgentRunTimeline.vue'

marked.setOptions({ breaks: true, gfm: true })

const props = defineProps({
  blocks: { type: Array, default: () => [] },
  isTyping: Boolean,
  currentThinking: String,
  isThinking: Boolean
})

defineEmits(['action', 'submit-input'])

const scrollContainer = ref(null)
const isNearBottom = ref(true)
const showNewActivity = ref(false)
const FOLLOW_THRESHOLD = 110

const renderMarkdown = (text) => marked.parse(text || '')

const updateFollowState = () => {
  const container = scrollContainer.value
  if (!container) return
  const distance = container.scrollHeight - container.scrollTop - container.clientHeight
  isNearBottom.value = distance <= FOLLOW_THRESHOLD
  if (isNearBottom.value) showNewActivity.value = false
}

const handleScroll = () => updateFollowState()

const scrollToLatest = async (force = false) => {
  if (!force && !isNearBottom.value) {
    showNewActivity.value = true
    return
  }
  await nextTick()
  const container = scrollContainer.value
  if (!container) return
  container.scrollTo({ top: container.scrollHeight, behavior: force ? 'smooth' : 'auto' })
  isNearBottom.value = true
  showNewActivity.value = false
}

watch(
  () => props.blocks.length,
  (length, previousLength) => {
    const newest = props.blocks[length - 1]
    const userAddedContent = length > previousLength && newest?.type === 'user_command'
    scrollToLatest(userAddedContent)
  }
)

watch(
  () => [props.blocks, props.isTyping, props.currentThinking],
  () => scrollToLatest(false),
  { deep: true }
)

onMounted(() => scrollToLatest(true))
</script>

<style scoped>
.chat-area {
  position: relative;
  flex: 1;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 22px;
  padding: 36px 64px 28px 28px;
  font-family: var(--font-family);
  font-size: 15px;
  line-height: 1.65;
  text-align: left;
  scroll-behavior: smooth;
}

.chat-area::-webkit-scrollbar { width: 5px; }
.chat-area::-webkit-scrollbar-track { background: transparent; }
.chat-area::-webkit-scrollbar-thumb { background: rgba(156, 163, 175, .2); border-radius: 4px; }
.chat-area:hover::-webkit-scrollbar-thumb { background: rgba(156, 163, 175, .45); }

.welcome-section { margin: auto; text-align: center; }
.welcome-brand { margin-bottom: 8px; font-size: 50px; font-weight: 900; }
.accent-dot { color: #10b981; }
.welcome-desc { color: #71717a; font-size: 14px; }

.content-block { width: min(820px, 100%); align-self: flex-start; text-align: left; }
.content-block.type-user_command { width: auto; max-width: min(720px, 85%); align-self: flex-end; }

.user-message {
  padding: 8px 12px;
  border-radius: 10px 10px 2px 10px;
  background: #f4f4f5;
  color: #18181b;
  white-space: pre-wrap;
  word-break: break-word;
}

.assistant-message {
  width: 100%;
  padding: 0;
  color: #27272a;
  font: inherit;
  text-align: left;
  word-break: break-word;
}
.assistant-message.is-error { color: #b91c1c; border-left: 2px solid #ef4444; padding-left: 10px; }

.live-thinking {
  width: min(820px, 100%);
  display: flex;
  align-items: flex-start;
  gap: 10px;
  color: #52525b;
  text-align: left;
}
.thinking-dot {
  width: 8px;
  height: 8px;
  margin-top: 8px;
  flex: 0 0 auto;
  border-radius: 50%;
  background: #10b981;
  box-shadow: 0 0 0 0 rgba(16, 185, 129, .35);
  animation: thinking-pulse 1.4s infinite;
}
.thinking-text { margin-top: 2px; color: #71717a; white-space: pre-wrap; }

.new-activity {
  position: fixed;
  left: 50%;
  bottom: 92px;
  transform: translateX(-50%);
  z-index: 5;
  padding: 7px 13px;
  border: 1px solid #d4d4d8;
  border-radius: 18px;
  background: rgba(255, 255, 255, .96);
  color: #3f3f46;
  font: 13px var(--font-family);
  box-shadow: 0 4px 14px rgba(0, 0, 0, .08);
  cursor: pointer;
}
.new-activity:hover { color: #047857; border-color: #6ee7b7; }

.markdown-body :deep(p) { margin: 0 0 10px; text-align: left; }
.markdown-body :deep(p:last-child) { margin-bottom: 0; }
.markdown-body :deep(h1),
.markdown-body :deep(h2),
.markdown-body :deep(h3),
.markdown-body :deep(h4) { margin: 14px 0 7px; text-align: left; line-height: 1.35; }
.markdown-body :deep(ul),
.markdown-body :deep(ol) { margin: 8px 0; padding-left: 24px; text-align: left; }
.markdown-body :deep(code) { font-family: Consolas, Monaco, monospace; }
.markdown-body :deep(pre) {
  overflow-x: auto;
  margin: 10px 0;
  padding: 12px 14px;
  border-radius: 7px;
  background: #18181b;
  color: #e4e4e7;
  font: 13px/1.55 Consolas, Monaco, monospace;
  text-align: left;
}

@keyframes thinking-pulse {
  70% { box-shadow: 0 0 0 7px rgba(16, 185, 129, 0); }
}

@media (max-width: 768px) {
  .chat-area { padding: 24px 20px; }
}
</style>
