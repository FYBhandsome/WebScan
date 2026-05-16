<template>
  <div class="chat-area" ref="scrollContainer">
    <div v-if="scanProgress && scanProgress.total > 0" class="scan-progress-bar">
      <div class="progress-header">
        <span class="progress-label">扫描进度</span>
        <span class="progress-count">{{ scanProgress.current }} / {{ scanProgress.total }}</span>
      </div>
      <div class="progress-track">
        <div class="progress-fill" :style="{ width: progressPercent + '%' }"></div>
      </div>
      <div v-if="scanProgress.activeTool" class="progress-tool">
        正在执行: {{ scanProgress.activeTool }}
      </div>
    </div>
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
          <div class="text-content markdown-body" v-html="renderMarkdown(block.content)"></div>
        </template>

        <template v-else-if="block.type === 'agent_info'">
          <div class="info-message">
            <span>{{ block.content }}</span>
          </div>
        </template>

        <template v-else-if="block.type === 'agent_error'">
          <div class="error-message">
            <span>{{ block.content }}</span>
          </div>
        </template>

        <template v-else-if="block.type === 'agent_mode_select'">
          <div :class="['proposal-card', { resolved: block.resolved }]">
            <div class="card-header">
              <span class="tag warning">MODE SELECT</span>
              <h4>{{ block.target || '目标扫描' }}</h4>
            </div>
            <div class="card-body">
              <p class="desc">{{ block.description }}</p>
              <div class="mode-grid">
                <div
                  v-for="mode in block.modes" :key="mode.key"
                  class="mode-option"
                  @click="$emit('select-mode', block, mode.key)"
                >
                  <strong>{{ mode.label }}</strong>
                  <p>{{ mode.desc }}</p>
                  <span class="mode-badge">{{ mode.badge }}</span>
                </div>
              </div>
            </div>
          </div>
        </template>

        <template v-else-if="block.type === 'agent_script_result'">
          <div class="script-result-card">
            <div class="result-header">
              <span class="script-tag" :class="block.vulnerable ? 'vuln' : 'safe'">
                {{ block.vulnerable ? 'VULNERABLE' : 'SAFE' }}
              </span>
              <strong>{{ block.tool_name }}</strong>
            </div>
            <div class="result-summary">
              <div class="summary-item">
                <span>{{ block.vulnerable ? '已发现' : '无' }}漏洞</span>
              </div>
              <div class="summary-item" v-if="block.auth_obtained">
                <span>🔑 已获取认证</span>
              </div>
            </div>
            <div class="result-body" v-if="block.analysis">
              <pre class="analysis-code">{{ block.analysis }}</pre>
            </div>
            <div class="result-raw" v-if="block.raw_result && Object.keys(block.raw_result).length">
              <details>
                <summary>原始数据</summary>
                <pre class="analysis-code">{{ JSON.stringify(block.raw_result, null, 2) }}</pre>
              </details>
            </div>
            <div class="result-footer">
              <span class="timestamp">{{ block.timestamp || '' }}</span>
            </div>
          </div>
        </template>

        <template v-else-if="block.type === 'agent_input_request'">
          <div :class="['proposal-card', { resolved: block.resolved }]">
            <div class="card-header">
              <span class="tag warning">INPUT REQUIRED</span>
              <h4>{{ block.title || '参数输入' }}</h4>
            </div>
            <div class="card-body">
              <p class="desc">{{ block.description }}</p>
              <div class="input-group" v-for="field in block.fields" :key="field.field">
                <label>{{ field.label }} <span v-if="field.required" class="required-mark">*</span></label>
                <select v-if="field.options?.length" v-model="field.value" class="form-select">
                  <option value="" disabled>请选择...</option>
                  <option v-for="opt in field.options" :key="opt" :value="opt">{{ opt }}</option>
                </select>
                <input v-else v-model="field.value" :placeholder="field.placeholder" class="form-input" />
                <span v-if="field.description" class="field-hint">{{ field.description }}</span>
              </div>
            </div>
            <div class="card-actions">
              <button class="btn btn-emerald" :disabled="block.resolved" @click="$emit('submit-input', block, block.fields)">
                确认提交
              </button>
            </div>
          </div>
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
                :class="['btn', 
                  opt.style === 'btn-primary' ? 'btn-emerald' : 
                  opt.style === 'btn-danger' ? 'btn-danger' : 
                  opt.style === 'btn-outline' ? 'btn-outline' : 
                  'btn-ghost']"
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
import { ref, computed, watch, nextTick } from 'vue'
import { marked } from 'marked'

marked.setOptions({
  breaks: true,
  gfm: true
})

const renderMarkdown = (text) => {
  if (!text) return ''
  return marked.parse(text)
}

const props = defineProps({
  blocks: Array,
  isTyping: Boolean,
  scanProgress: Object
})

defineEmits(['action', 'submit-input', 'select-mode'])

const progressPercent = computed(() => {
  if (!props.scanProgress || props.scanProgress.total === 0) return 0
  const pct = Math.round((props.scanProgress.current / props.scanProgress.total) * 100)
  return Math.min(pct, 100)
})

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
  background: #FFFFFF;
  border-radius: 8px;
  border: 1px solid #E4E4E7;
  overflow: hidden;
  width: 400px;
  max-width: 100%;
  color: #3F3F46;
  margin-top: 8px;
}
.proposal-card.resolved { opacity: 0.6; pointer-events: none; filter: grayscale(100%); }

.card-header {
  padding: 10px 14px;
  border-bottom: 1px solid #E4E4E7;
  display: flex;
  align-items: center;
  gap: 10px;
  background: #F0F0F0;
}
.card-header h4 { margin: 0; font-size: 13px; color: #18181B; font-family: monospace; }
.tag.warning { background: #F0F0F0; color: #71717A; padding: 2px 6px; font-size: 10px; border-radius: 4px; border: 1px solid #E4E4E7; }

.card-body { padding: 14px; }
.desc { font-size: 13px; margin-bottom: 12px; color: #52525B; }
.code-params {
  background: #F0F0F0;
  padding: 10px;
  border-radius: 6px;
  font-family: monospace;
  font-size: 12px;
}
.var-name { color: #3B82F6; }
.var-value { color: #16A34A; }

.card-actions {
  padding: 12px 14px;
  background: #F0F0F0;
  border-top: 1px solid #E4E4E7;
  display: flex;
  gap: 8px;
}
.btn { padding: 6px 12px; border-radius: 4px; font-size: 12px; font-weight: 600; cursor: pointer; transition: all 0.2s; border: 1px solid #E4E4E7; background: #F0F0F0; color: #3F3F46; }
.btn:hover { background: #E5E5E5; }
.btn:disabled { opacity: 0.4; cursor: default; }
.btn-emerald { background: #F0F0F0; color: #18181B; border-color: #E4E4E7; }
.btn-emerald:hover { background: #E5E5E5; }
.btn-ghost { background: #FFFFFF; color: #52525B; border-color: #E4E4E7; }
.btn-ghost:hover { background: #F0F0F0; }

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

/* === Markdown 渲染内容样式 === */
.markdown-body {
  text-align: left;
  word-break: break-word;
}

.markdown-body :deep(h1),
.markdown-body :deep(h2),
.markdown-body :deep(h3),
.markdown-body :deep(h4),
.markdown-body :deep(h5),
.markdown-body :deep(h6) {
  text-align: left;
  margin: 16px 0 8px 0;
  font-weight: 700;
  line-height: 1.3;
  color: #18181B;
}

.markdown-body :deep(h1) { font-size: 1.5em; }
.markdown-body :deep(h2) { font-size: 1.3em; border-bottom: 1px solid #E4E4E7; padding-bottom: 6px; }
.markdown-body :deep(h3) { font-size: 1.15em; }
.markdown-body :deep(h4) { font-size: 1.05em; }

.markdown-body :deep(p) {
  text-align: left;
  margin: 0 0 10px 0;
  line-height: 1.7;
}

.markdown-body :deep(ul),
.markdown-body :deep(ol) {
  text-align: left;
  padding-left: 24px;
  margin: 8px 0;
}

.markdown-body :deep(li) {
  margin-bottom: 4px;
  line-height: 1.6;
}

.markdown-body :deep(code) {
  background: #F4F4F5;
  padding: 2px 6px;
  border-radius: 4px;
  font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
  font-size: 0.9em;
  color: #D946EF;
}

.markdown-body :deep(pre) {
  text-align: left;
  background: #18181B;
  color: #E4E4E7;
  padding: 14px 18px;
  border-radius: 8px;
  overflow-x: auto;
  margin: 12px 0;
  font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
  font-size: 0.85em;
  line-height: 1.5;
}

.markdown-body :deep(pre code) {
  background: transparent;
  padding: 0;
  color: inherit;
  font-size: inherit;
}

.markdown-body :deep(a) {
  color: #2563EB;
  text-decoration: underline;
  text-underline-offset: 2px;
}

.markdown-body :deep(a:hover) {
  color: #1D4ED8;
}

.markdown-body :deep(strong) {
  font-weight: 700;
  color: #18181B;
}

.markdown-body :deep(em) {
  font-style: italic;
}

.markdown-body :deep(blockquote) {
  text-align: left;
  border-left: 3px solid #10B981;
  padding: 6px 14px;
  margin: 12px 0;
  color: #52525B;
  background: #FAFAFA;
  border-radius: 0 6px 6px 0;
}

.markdown-body :deep(table) {
  text-align: left;
  border-collapse: collapse;
  margin: 12px 0;
  width: 100%;
}

.markdown-body :deep(th),
.markdown-body :deep(td) {
  border: 1px solid #E4E4E7;
  padding: 8px 12px;
  text-align: left;
}

.markdown-body :deep(th) {
  background: #F4F4F5;
  font-weight: 600;
}

.markdown-body :deep(hr) {
  border: none;
  border-top: 1px solid #E4E4E7;
  margin: 16px 0;
}

.markdown-body :deep(img) {
  max-width: 100%;
  border-radius: 8px;
}

.script-result-card {
  background: #FFFFFF;
  border: 1px solid #E4E4E7;
  border-radius: 10px;
  padding: 16px;
  margin-top: 8px;
  width: 400px;
  max-width: 100%;
}

.result-header {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 10px;
}

.script-tag {
  font-size: 11px;
  padding: 2px 8px;
  border-radius: 10px;
  font-weight: 500;
}

.script-tag.vuln {
  background: #FEF2F2;
  color: #DC2626;
  border: 1px solid #FECACA;
}

.script-tag.safe {
  background: #F0FDF4;
  color: #16A34A;
  border: 1px solid #BBF7D0;
}

.result-header strong {
  font-size: 14px;
  color: #18181B;
}

.result-summary {
  display: flex;
  gap: 12px;
  margin-bottom: 10px;
}

.summary-item {
  font-size: 12px;
  color: #64748B;
  background: #F8FAFC;
  padding: 4px 10px;
  border-radius: 6px;
}

.analysis-code {
  background: #F8FAFC;
  border: 1px solid #E2E8F0;
  border-radius: 6px;
  padding: 10px;
  font-size: 11px;
  font-family: monospace;
  color: #334155;
  white-space: pre-wrap;
  max-height: 200px;
  overflow-y: auto;
  line-height: 1.5;
}

.result-footer {
  margin-top: 8px;
}

.timestamp {
  font-size: 11px;
  color: #94A3B8;
  font-family: monospace;
}

.mode-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 10px;
}

.mode-option {
  border: 1px solid #E4E4E7;
  border-radius: 8px;
  padding: 14px 10px;
  cursor: pointer;
  text-align: center;
  transition: border-color 0.2s, transform 0.2s;
}

.mode-option:hover {
  border-color: #89B4FA;
  transform: translateY(-2px);
}

.mode-option .mode-icon {
  color: #6B7280;
  margin-bottom: 8px;
}

.mode-option strong {
  display: block;
  font-size: 13px;
  color: #18181B;
  margin-bottom: 6px;
}

.mode-option p {
  font-size: 11px;
  color: #6B7280;
  line-height: 1.4;
  margin-bottom: 8px;
}

.mode-badge {
  font-size: 10px;
  padding: 2px 7px;
  border: 1px solid #E4E4E7;
  border-radius: 8px;
  color: #71717A;
}

.btn-outline {
  background: #FFFFFF;
  color: #16A34A;
  border: 1px solid #16A34A;
}

.btn-outline:hover {
  background: #F0F0F0;
  color: #16A34A;
}

.btn-danger {
  background: #FFFFFF;
  color: #EF4444;
  border: 1px solid #EF4444;
}

.btn-danger:hover {
  background: #FEF2F2;
  color: #EF4444;
}

.info-message {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 10px 14px;
  background: #FFFFFF;
  border-left: 3px solid #D1D5DB;
  border-radius: 6px;
  font-size: 13px;
  color: #3F3F46;
}

.error-message {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 10px 14px;
  background: #FFFFFF;
  border-left: 3px solid #D1D5DB;
  border-radius: 6px;
  font-size: 13px;
  color: #3F3F46;
}

.input-group {
  margin-bottom: 12px;
}

.input-group label {
  display: block;
  font-size: 12px;
  color: #52525B;
  margin-bottom: 4px;
}

.required-mark {
  color: #EF4444;
}

.form-input,
.form-select {
  width: 100%;
  padding: 8px 12px;
  background: #F0F0F0;
  border: 1px solid #E4E4E7;
  border-radius: 6px;
  color: #3F3F46;
  font-size: 13px;
  font-family: monospace;
}

.form-input:focus,
.form-select:focus {
  border-color: #89B4FA;
  outline: none;
}

.field-hint {
  display: block;
  font-size: 11px;
  color: #94A3B8;
  margin-top: 4px;
}

.scan-progress-bar {
  padding: 12px 18px;
  margin: 0 0 8px 0;
  background: #FFFFFF;
  border: 1px solid #E2E8F0;
  border-radius: 8px;
  position: sticky;
  top: 0;
  z-index: 10;
}

.progress-header {
  display: flex;
  justify-content: space-between;
  margin-bottom: 6px;
}

.progress-label {
  font-size: 12px;
  font-weight: 600;
  color: #334155;
}

.progress-count {
  font-size: 12px;
  color: #64748B;
  font-family: monospace;
}

.progress-track {
  height: 6px;
  background: #E2E8F0;
  border-radius: 3px;
  overflow: hidden;
}

.progress-fill {
  height: 100%;
  background: linear-gradient(90deg, #10B981, #0EA5E9);
  border-radius: 3px;
  transition: width 0.5s cubic-bezier(0.4, 0, 0.2, 1);
}

.progress-tool {
  font-size: 12px;
  color: #64748B;
  margin-top: 6px;
  font-family: monospace;
}
</style>