<template>
  <div class="script-viewer">
    <div class="viewer-header">
      <div class="script-info">
        <span class="script-name">{{ scriptName }}</span>
        <span class="script-meta" v-if="script">
          <span class="source-badge" :class="script.source">{{ script.source === 'generate' ? 'AI生成' : '上传' }}</span>
          <span class="timestamp">{{ formatTime(script.created_at) }}</span>
        </span>
      </div>
      <div class="actions">
        <button class="btn-copy" @click="copyCode" title="复制代码">
          <span v-if="!copied">📋 复制</span>
          <span v-else class="copied">✓ 已复制</span>
        </button>
        <button class="btn-download" @click="downloadCode" title="下载脚本">
          ⬇️ 下载
        </button>
        <button class="btn-delete" @click="confirmDelete" v-if="showDelete" title="删除脚本">
          🗑️ 删除
        </button>
      </div>
    </div>
    <div class="description" v-if="script?.description">
      {{ script.description }}
    </div>
    <div class="code-container">
      <pre><code class="language-python" v-html="highlightedCode"></code></pre>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'

const props = defineProps({
  script: {
    type: Object,
    default: null
  },
  showDelete: {
    type: Boolean,
    default: true
  }
})

const emit = defineEmits(['delete', 'copy', 'download'])

const copied = ref(false)

const scriptName = computed(() => props.script?.tool_name || '未命名脚本')

const scriptContent = computed(() => props.script?.script_content || '')

const highlightedCode = computed(() => {
  if (!scriptContent.value) return ''
  return escapeHtml(scriptContent.value)
})

function escapeHtml(text) {
  const div = document.createElement('div')
  div.textContent = text
  return div.innerHTML
}

function formatTime(timestamp) {
  if (!timestamp) return ''
  const date = new Date(timestamp)
  return date.toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit'
  })
}

async function copyCode() {
  try {
    await navigator.clipboard.writeText(scriptContent.value)
    copied.value = true
    setTimeout(() => {
      copied.value = false
    }, 2000)
    emit('copy', scriptContent.value)
  } catch (err) {
    console.error('复制失败:', err)
  }
}

function downloadCode() {
  const blob = new Blob([scriptContent.value], { type: 'text/plain' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `${scriptName.value}.py`
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
  emit('download', scriptName.value)
}

function confirmDelete() {
  if (confirm(`确定要删除脚本 "${scriptName.value}" 吗？`)) {
    emit('delete', scriptName.value)
  }
}
</script>

<style scoped>
.script-viewer {
  background: #1a1a2e;
  border-radius: 8px;
  overflow: hidden;
  border: 1px solid #2d2d44;
}

.viewer-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 16px;
  background: #16162a;
  border-bottom: 1px solid #2d2d44;
}

.script-info {
  display: flex;
  align-items: center;
  gap: 12px;
}

.script-name {
  font-weight: 600;
  color: #e0e0e0;
  font-size: 14px;
}

.script-meta {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
}

.source-badge {
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
}

.source-badge.upload {
  background: #2d5a27;
  color: #7fff7f;
}

.source-badge.generate {
  background: #5a4a27;
  color: #ffd700;
}

.timestamp {
  color: #888;
}

.actions {
  display: flex;
  gap: 8px;
}

.actions button {
  padding: 6px 12px;
  border-radius: 4px;
  border: none;
  cursor: pointer;
  font-size: 12px;
  transition: all 0.2s;
}

.btn-copy {
  background: #2d2d44;
  color: #e0e0e0;
}

.btn-copy:hover {
  background: #3d3d54;
}

.btn-copy .copied {
  color: #7fff7f;
}

.btn-download {
  background: #2d4a5a;
  color: #7fd4ff;
}

.btn-download:hover {
  background: #3d5a6a;
}

.btn-delete {
  background: #5a2d2d;
  color: #ff7f7f;
}

.btn-delete:hover {
  background: #6a3d3d;
}

.description {
  padding: 12px 16px;
  color: #aaa;
  font-size: 13px;
  background: #1e1e32;
  border-bottom: 1px solid #2d2d44;
}

.code-container {
  padding: 16px;
  overflow-x: auto;
  max-height: 500px;
  overflow-y: auto;
}

.code-container pre {
  margin: 0;
  font-family: 'Fira Code', 'Consolas', monospace;
  font-size: 13px;
  line-height: 1.5;
}

.code-container code {
  color: #e0e0e0;
  white-space: pre;
}
</style>
