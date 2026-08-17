<template>
  <section class="agent-run" :class="`status-${run.status || 'running'}`">
    <header class="run-header">
      <div>
        <div class="run-title">{{ run.title || '智能体扫描' }}</div>
        <div v-if="run.target" class="run-target">{{ run.target }}</div>
      </div>
      <span class="run-status">{{ statusLabel(run.status) }}</span>
    </header>

    <div class="run-steps">
      <article
        v-for="step in run.steps"
        :key="step.stepId"
        :data-step-id="step.stepId"
        class="run-step"
      >
        <div class="step-rail">
          <span class="step-dot" :class="`status-${step.status || 'pending'}`">
            <svg
              v-if="step.status === 'completed'"
              class="step-check-icon"
              viewBox="0 0 16 16"
              aria-label="已完成"
            >
              <path d="M3.5 8.2 6.6 11l5.9-6.2" />
            </svg>
            <span v-else aria-hidden="true">{{ statusIcon(step.status) }}</span>
          </span>
          <span class="step-line"></span>
        </div>

        <div class="step-content">
          <div class="step-heading">
            <strong>{{ step.title || step.stepId }}</strong>
            <span class="step-status">{{ statusLabel(step.status) }}</span>
          </div>
          <div v-if="step.message" class="step-message">{{ step.message }}</div>
          <a
            v-for="reportLink in step.reportLinks || (step.reportLink ? [step.reportLink] : [])"
            :key="reportLink.filename"
            href="#"
            class="report-link"
            @click.prevent="$emit('open-report', reportLink.filename || '')"
          >
            {{ reportLink.label || '查看扫描报告' }}
          </a>
          <div v-if="step.analysis && step.analysis !== step.message" class="step-analysis">{{ step.analysis }}</div>

          <div v-if="step.interaction" class="step-interaction">
            <div v-if="!step.interaction.resolved" class="interaction-active">
              <div v-if="step.interaction.title" class="interaction-title">{{ step.interaction.title }}</div>
              <div v-if="step.interaction.description && step.interaction.description !== step.message" class="interaction-description">
                {{ step.interaction.description }}
              </div>
              <dl v-if="step.interaction.params && Object.keys(step.interaction.params).length" class="interaction-params">
                <template v-for="(value, key) in step.interaction.params" :key="key">
                  <dt>{{ key }}</dt>
                  <dd>{{ value }}</dd>
                </template>
              </dl>

              <div v-if="step.interaction.type === 'input'" class="interaction-fields">
                <label v-for="field in step.interaction.fields" :key="field.field" class="interaction-field">
                  <span>{{ field.label }}<em v-if="field.required"> *</em></span>
                  <select v-if="field.options?.length" v-model="field.value">
                    <option value="" disabled>请选择...</option>
                    <option
                      v-for="option in field.options"
                      :key="typeof option === 'object' ? option.value : option"
                      :value="typeof option === 'object' ? option.value : option"
                    >{{ typeof option === 'object' ? option.label : option }}</option>
                  </select>
                  <textarea
                    v-else-if="field.validation === 'python_code'"
                    v-model="field.value"
                    :placeholder="field.placeholder"
                    rows="8"
                  ></textarea>
                  <input v-else v-model="field.value" :placeholder="field.placeholder" />
                  <small v-if="field.description">{{ field.description }}</small>
                </label>
                <button
                  class="interaction-button is-primary"
                  type="button"
                  @click="$emit('submit-input', step.interaction, step.interaction.fields)"
                >
                  确认提交
                </button>
              </div>

              <div v-else class="interaction-actions">
                <button
                  v-for="option in step.interaction.options || []"
                  :key="option.key"
                  type="button"
                  class="interaction-button"
                  :class="{ 'is-primary': option.primary || option.style === 'btn-primary', 'is-danger': option.danger || option.style === 'btn-danger' }"
                  @click="$emit('action', step.interaction, option.key, option.label)"
                >
                  {{ option.label }}
                </button>
              </div>
            </div>
            <div v-else class="interaction-resolved">
              <template v-if="step.interaction.resolutionMessage">{{ step.interaction.resolutionMessage }}</template>
              <template v-else>用户选择：{{ step.interaction.selectedChoice || '已处理' }}</template>
            </div>
          </div>

          <details v-if="step.logs?.length" class="step-details" :open="step.status === 'running'">
            <summary>执行记录（{{ step.logs.length }}）</summary>
            <div class="step-logs">
              <div
                v-for="entry in step.logs"
                :key="entry.id || `${entry.timestamp}:${entry.message}`"
                class="step-log"
                :class="`level-${entry.level || 'info'}`"
              >
                <time>{{ formatTime(entry.timestamp) }}</time>
                <span>{{ entry.message }}</span>
              </div>
            </div>
          </details>

          <details v-if="step.rawResult && Object.keys(step.rawResult).length" class="step-details">
            <summary>原始扫描结果</summary>
            <pre>{{ JSON.stringify(step.rawResult, null, 2) }}</pre>
          </details>
        </div>
      </article>
    </div>

    <footer
      v-if="run.summary"
      class="run-summary markdown-body"
      v-html="renderMarkdown(run.summary)"
    ></footer>
  </section>
</template>

<script setup>
import { marked } from 'marked'

defineProps({ run: { type: Object, required: true } })
defineEmits(['action', 'submit-input', 'open-report'])

const statusLabel = (status) => ({
  pending: '等待', running: '运行中', completed: '已完成', failed: '失败',
  skipped: '已跳过', waiting: '等待确认', cancelled: '已取消'
}[status] || '运行中')

const statusIcon = (status) => ({
  failed: '×', skipped: '−', waiting: '?', cancelled: '−', running: '•'
}[status] || '○')

const formatTime = (timestamp) => {
  if (!timestamp) return ''
  const date = new Date(timestamp)
  return Number.isNaN(date.getTime()) ? timestamp : date.toLocaleTimeString('zh-CN', { hour12: false })
}

const renderMarkdown = (text) => marked.parse(text || '', { breaks: true, gfm: true })
</script>

<style scoped>
.agent-run {
  width: min(820px, 100%);
  color: #27272a;
  font: 15px/1.65 var(--font-family);
  text-align: left;
}
.run-header { display: flex; justify-content: space-between; align-items: flex-start; gap: 20px; margin-bottom: 16px; }
.run-title { font-size: 16px; font-weight: 700; }
.run-target { margin-top: 2px; color: #71717a; font-size: 13px; word-break: break-all; }
.run-status, .step-status { color: #71717a; font-size: 12px; white-space: nowrap; }
.status-running > .run-status, .status-running .step-status { color: #059669; }
.status-failed > .run-status { color: #dc2626; }

.run-step { display: grid; grid-template-columns: 22px minmax(0, 1fr); min-height: 48px; }
.step-rail { position: relative; display: flex; justify-content: center; }
.step-dot {
  position: relative;
  z-index: 1;
  width: 17px;
  height: 17px;
  display: grid;
  place-items: center;
  border: 1px solid #d4d4d8;
  border-radius: 50%;
  background: white;
  color: #a1a1aa;
  font: 11px monospace;
}
.step-dot.status-running { color: #059669; border-color: #34d399; animation: pulse 1.4s infinite; }
.step-dot.status-completed { color: white; border-color: #10b981; background: #10b981; }
.step-check-icon {
  width: 12px;
  height: 12px;
  fill: none;
  stroke: currentColor;
  stroke-width: 2;
  stroke-linecap: round;
  stroke-linejoin: round;
}
.step-dot.status-failed { color: white; border-color: #ef4444; background: #ef4444; }
.step-dot.status-skipped, .step-dot.status-cancelled { background: #f4f4f5; }
.step-line { position: absolute; top: 17px; bottom: 0; width: 1px; background: #e4e4e7; }
.run-step:last-child .step-line { display: none; }
.step-content { min-width: 0; padding: 0 0 18px 10px; text-align: left; }
.step-heading { display: flex; justify-content: space-between; gap: 12px; line-height: 18px; }
.step-heading strong { font: 600 14px/1.4 var(--font-family); }
.step-message, .step-analysis { margin-top: 4px; color: #52525b; white-space: pre-wrap; word-break: break-word; }
.step-analysis { padding-left: 10px; border-left: 2px solid #d1fae5; }
.report-link {
  display: flex;
  width: fit-content;
  margin-top: 7px;
  padding: 0;
  border: 0;
  background: transparent;
  color: #047857;
  font: 600 14px/1.5 var(--font-family);
  text-decoration: underline;
  text-underline-offset: 3px;
  cursor: pointer;
}
.report-link:hover { color: #059669; }

.step-interaction { margin-top: 11px; }
.interaction-active { padding-left: 12px; border-left: 2px solid #10b981; }
.interaction-title { font-weight: 600; color: #27272a; }
.interaction-description { margin-top: 3px; color: #71717a; }
.interaction-params { display: grid; grid-template-columns: max-content 1fr; gap: 3px 12px; margin: 8px 0 0; font-size: 13px; }
.interaction-params dt { color: #71717a; }
.interaction-params dd { margin: 0; color: #3f3f46; word-break: break-all; }
.interaction-actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
.interaction-button {
  padding: 7px 13px;
  border: 1px solid #d4d4d8;
  border-radius: 6px;
  background: #fff;
  color: #3f3f46;
  font: 13px var(--font-family);
  cursor: pointer;
}
.interaction-button:hover { border-color: #6ee7b7; color: #047857; }
.interaction-button.is-primary { border-color: #10b981; background: #10b981; color: #fff; }
.interaction-button.is-danger { border-color: #fecaca; color: #dc2626; }
.interaction-resolved { color: #71717a; font-size: 13px; }

.interaction-fields { display: grid; gap: 11px; margin-top: 10px; }
.interaction-field { display: grid; gap: 5px; color: #3f3f46; font-size: 13px; }
.interaction-field em { color: #dc2626; font-style: normal; }
.interaction-field input,
.interaction-field select,
.interaction-field textarea {
  width: 100%;
  padding: 8px 10px;
  border: 1px solid #d4d4d8;
  border-radius: 6px;
  outline: none;
  color: #18181b;
  background: #fff;
  font: 14px/1.55 var(--font-family);
  text-align: left;
}
.interaction-field textarea { resize: vertical; font-family: Consolas, Monaco, monospace; }
.interaction-field input:focus,
.interaction-field select:focus,
.interaction-field textarea:focus { border-color: #10b981; }
.interaction-field small { color: #71717a; }

.step-details { margin-top: 8px; color: #71717a; }
.step-details summary { cursor: pointer; user-select: none; font-size: 12px; }
.step-logs { max-height: 210px; overflow: auto; margin-top: 6px; font: 12px/1.55 Consolas, Monaco, monospace; }
.step-log { display: grid; grid-template-columns: 72px 1fr; gap: 8px; padding: 2px 0; color: #52525b; }
.step-log time { color: #a1a1aa; }
.step-log.level-error { color: #dc2626; }
.step-log.level-warning { color: #b45309; }
.step-details pre { max-height: 240px; overflow: auto; padding: 10px; border-radius: 6px; background: #f4f4f5; color: #3f3f46; font: 12px/1.5 Consolas, Monaco, monospace; white-space: pre-wrap; }
.run-summary { margin-top: 4px; padding-left: 12px; border-left: 2px solid #10b981; color: #3f3f46; word-break: break-word; }
.run-summary :deep(p) { margin: 0 0 10px; }
.run-summary :deep(p:last-child) { margin-bottom: 0; }
.run-summary :deep(h1),
.run-summary :deep(h2),
.run-summary :deep(h3),
.run-summary :deep(h4) { margin: 16px 0 8px; color: #27272a; line-height: 1.4; }
.run-summary :deep(h1) { font-size: 20px; }
.run-summary :deep(h2) { font-size: 18px; }
.run-summary :deep(h3) { font-size: 16px; }
.run-summary :deep(ul),
.run-summary :deep(ol) { margin: 0 0 10px; padding-left: 24px; }
.run-summary :deep(li) { margin-bottom: 4px; }
.run-summary :deep(hr) { margin: 18px 0; border: 0; border-top: 1px solid #d4d4d8; }
.run-summary :deep(pre) { overflow: auto; padding: 10px; border-radius: 6px; background: #f4f4f5; }
.run-summary :deep(code) { font-family: Consolas, Monaco, monospace; }

@keyframes pulse { 50% { box-shadow: 0 0 0 4px rgba(16, 185, 129, .12); } }
</style>
