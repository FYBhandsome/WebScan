<template>
  <section class="generated-script-editor" :aria-busy="interaction.isRegistering">
    <header class="editor-header">
      <div class="editor-identity">
        <span class="python-mark" aria-hidden="true">&lt;/&gt;</span>
        <div>
          <p class="eyebrow">本地生成 · 待确认</p>
          <h4>脚本工作台</h4>
        </div>
      </div>
      <span class="safety-badge">等待安全审查</span>
    </header>

    <p class="editor-description">{{ interaction.description }}</p>
    <p class="editor-hint">可先编辑代码、名称与分类。加入扫描队列或保存前，系统会进行后端安全审查。</p>

    <div class="editor-meta">
      <label>
        <span>脚本名称</span>
        <input v-model="interaction.scriptName" :disabled="interaction.isRegistering" maxlength="64" autocomplete="off">
      </label>
      <label>
        <span>工具分类</span>
        <select v-model="interaction.scriptCategory" :disabled="interaction.isRegistering">
          <option value="info_collection">信息收集</option>
          <option value="vuln_scan">漏洞扫描</option>
        </select>
      </label>
    </div>

    <div class="code-panel">
      <div class="code-toolbar">
        <span>Python · 可编辑</span>
        <button type="button" class="copy-button" :disabled="interaction.isRegistering" @click="copyScript">
          {{ copied ? '已复制' : '复制代码' }}
        </button>
      </div>
      <div class="code-editor-shell">
        <pre class="line-numbers" aria-hidden="true" :style="{ transform: `translateY(-${scrollOffset}px)` }">{{ lineNumbers }}</pre>
        <textarea
          ref="codeEditor"
          v-model="interaction.scriptCode"
          class="code-editor"
          aria-label="生成的 Python 脚本"
          spellcheck="false"
          wrap="off"
          :disabled="interaction.isRegistering"
          @scroll="syncCodeScroll"
        ></textarea>
      </div>
    </div>

    <p v-if="interaction.error" class="editor-error" role="alert">{{ interaction.error }}</p>

    <footer class="editor-actions">
      <button
        type="button"
        class="editor-button primary"
        :disabled="interaction.isRegistering"
        @click="emitAction('queue', '加入本次扫描队列')"
      >
        {{ interaction.isRegistering ? '正在审查并注册…' : '加入本次扫描队列' }}
      </button>
      <button type="button" class="editor-button secondary" :disabled="interaction.isRegistering" @click="emitAction('save', '保存到工具库')">
        保存到工具库
      </button>
      <button type="button" class="editor-button ghost" :disabled="interaction.isRegistering" @click="emitAction('regenerate', '重新填写需求')">
        重新生成
      </button>
      <button type="button" class="editor-button discard" :disabled="interaction.isRegistering" @click="emitAction('discard', '放弃并继续扫描')">
        放弃并继续扫描
      </button>
    </footer>
  </section>
</template>

<script setup>
import { computed, nextTick, onMounted, ref } from 'vue'

const props = defineProps({
  interaction: { type: Object, required: true }
})

const emit = defineEmits(['action'])
const copied = ref(false)
const codeEditor = ref(null)
const scrollOffset = ref(0)
const lineNumbers = computed(() => {
  const total = Math.max(1, String(props.interaction.scriptCode || '').split('\n').length)
  return Array.from({ length: total }, (_, index) => index + 1).join('\n')
})

const emitAction = (key, label) => emit('action', key, label)

const copyScript = async () => {
  try {
    await navigator.clipboard?.writeText(props.interaction.scriptCode || '')
    copied.value = true
    setTimeout(() => { copied.value = false }, 1800)
  } catch {
    copied.value = false
  }
}

const syncCodeScroll = () => {
  scrollOffset.value = codeEditor.value?.scrollTop || 0
}

onMounted(() => {
  nextTick(() => {
    if (!codeEditor.value) return
    codeEditor.value.scrollTop = 0
    scrollOffset.value = 0
  })
})
</script>

<style scoped>
.generated-script-editor {
  margin-top: 12px;
  overflow: hidden;
  border: 1px solid #a7f3d0;
  border-radius: 12px;
  background: #fff;
  box-shadow: 0 6px 18px rgba(15, 23, 42, .05);
}
.editor-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  padding: 15px 17px;
  border-bottom: 1px solid #d1fae5;
  background: #fff;
}
.editor-identity { display: flex; align-items: center; gap: 10px; }
.python-mark {
  display: grid;
  width: 32px;
  height: 32px;
  place-items: center;
  border: 1px solid #6ee7b7;
  border-radius: 8px;
  color: #10b981;
  background: #ecfdf5;
  font: 700 12px/1 Consolas, Monaco, monospace;
}
.eyebrow { margin: 0 0 2px; color: #10b981; font-size: 11px; font-weight: 700; letter-spacing: .04em; }
.editor-identity h4 { margin: 0; color: #0f172a; font-size: 16px; }
.safety-badge { padding: 4px 8px; border: 1px solid #e2e8f0; border-radius: 999px; color: #64748b; background: #f8fafc; font-size: 12px; white-space: nowrap; }
.editor-description { margin: 16px 17px 4px; color: #1f2937; font-weight: 600; }
.editor-hint { margin: 0 17px 14px; color: #64748b; font-size: 12px; line-height: 1.55; }
.editor-meta { display: grid; grid-template-columns: minmax(0, 1.4fr) minmax(130px, .6fr); gap: 10px; padding: 0 17px 14px; }
.editor-meta label { display: grid; gap: 5px; color: #475569; font-size: 12px; font-weight: 600; }
.editor-meta input, .editor-meta select {
  min-width: 0;
  padding: 8px 9px;
  border: 1px solid #bbf7d0;
  border-radius: 7px;
  outline: none;
  color: #1f2937;
  background: #fff;
  font: 13px var(--font-family);
}
.editor-meta input:focus, .editor-meta select:focus, .code-editor:focus { border-color: #10b981; box-shadow: 0 0 0 3px rgba(16, 185, 129, .16); }
.code-panel { margin: 0 17px; overflow: hidden; border: 1px solid #e2e8f0; border-radius: 8px; background: #f8fafc; }
.code-toolbar { display: flex; align-items: center; justify-content: space-between; padding: 8px 10px; border-bottom: 1px solid #e2e8f0; color: #475569; background: #f1f5f9; font: 700 12px/1.4 Consolas, Monaco, monospace; }
.copy-button { border: 1px solid #cbd5e1; border-radius: 5px; padding: 4px 7px; color: #10b981; background: #fff; font: 12px var(--font-family); cursor: pointer; }
.copy-button:hover:not(:disabled) { border-color: #10b981; background: #ecfdf5; }
.code-editor-shell { position: relative; display: grid; grid-template-columns: 44px minmax(0, 1fr); height: clamp(300px, 42vh, 460px); overflow: hidden; background: #f8fafc; }
.line-numbers { z-index: 1; margin: 0; padding: 13px 8px 13px 0; overflow: hidden; color: #94a3b8; border-right: 1px solid #e2e8f0; background: #f1f5f9; font: 13px/1.65 Consolas, Monaco, monospace; text-align: right; user-select: none; white-space: pre; will-change: transform; }
.code-editor { display: block; box-sizing: border-box; width: 100%; height: 100%; resize: none; padding: 13px 15px; border: 0; outline: none; color: #1f2937; background: #f8fafc; font: 13px/1.65 Consolas, Monaco, monospace; tab-size: 4; }
.editor-error { margin: 12px 17px 0; padding: 9px 10px; border: 1px solid #fecaca; border-radius: 7px; color: #b91c1c; background: #fef2f2; font-size: 13px; }
.editor-actions { display: flex; flex-wrap: wrap; gap: 8px; padding: 15px 17px 17px; }
.editor-button { min-height: 34px; padding: 7px 11px; border: 1px solid transparent; border-radius: 7px; font: 600 13px var(--font-family); cursor: pointer; }
.editor-button:disabled, .copy-button:disabled { cursor: wait; opacity: .66; }
.primary { color: #fff; border-color: #10b981; background: #10b981; }
.primary:hover:not(:disabled) { background: #059669; }
.secondary { color: #10b981; border-color: #6ee7b7; background: #fff; }
.secondary:hover:not(:disabled) { border-color: #10b981; background: #d1fae5; }
.ghost { color: #475569; border-color: #d1d5db; background: #fff; }
.ghost:hover:not(:disabled) { border-color: #94a3b8; color: #1f2937; }
.discard { color: #64748b; border-color: transparent; background: transparent; }
.discard:hover:not(:disabled) { color: #334155; background: #f8fafc; }
@media (max-width: 620px) {
  .editor-header { align-items: flex-start; }
  .safety-badge { font-size: 11px; }
  .editor-meta { grid-template-columns: 1fr; }
  .editor-actions { display: grid; grid-template-columns: 1fr 1fr; }
  .primary { grid-column: 1 / -1; }
  .code-editor { min-height: 270px; }
}
</style>
