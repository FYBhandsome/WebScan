<template>
  <div id="page-scan" class="page active">
    <div class="page-header">
      <h2>扫描任务</h2>
    </div>
    <div class="scan-layout">
      <div class="scan-sidebar">
        <div class="scan-form">
          <div class="form-group">
            <label>扫描目标</label>
            <input
              type="text"
              id="scanTarget"
              v-model="form.target"
              placeholder="例如: https://example.com"
              @keydown.enter="startScan"
            >
          </div>
          <div class="form-group">
            <label>扫描模式</label>
            <select id="scanMode" v-model="form.mode">
              <option value="info_collection">信息收集</option>
              <option value="vuln_scan">漏洞扫描</option>
              <option value="full_scan">完整扫描</option>
            </select>
          </div>
          <div class="form-group">
            <label>任务参数（JSON，可选）</label>
            <textarea v-model="form.paramsText" rows="4" placeholder='例如：{"timeout": 30, "next_task": "baseinfo_scan"}' @keydown.ctrl.enter="startScan"></textarea>
            <p v-if="paramsError" class="field-error">{{ paramsError }}</p>
          </div>
          <button
            id="startScanBtn"
            class="primary-btn"
            @click="startScan"
            :disabled="isScanning"
          >
            {{ isScanning ? '扫描中...' : '开始扫描' }}
          </button>
        </div>

        <div class="quick-targets" v-if="scanHistory.length > 0">
          <span class="quick-label">最近目标</span>
          <div class="quick-chips">
            <span
              class="quick-chip"
              v-for="(item, i) in scanHistory"
              :key="i"
              @click="form.target = item"
              :title="item"
            >{{ item }}</span>
          </div>
        </div>

        <a class="cancel-scan-link" v-if="isScanning" @click="cancelScan">取消扫描</a>
      </div>

      <div class="scan-main">
        <div class="empty-state" v-if="!isScanning && !showResults">
          <div class="empty-icon">
            <svg width="80" height="80" viewBox="0 0 80 80" fill="none">
              <circle cx="40" cy="40" r="36" stroke="var(--border-light)" stroke-width="2" />
              <circle cx="40" cy="40" r="24" stroke="var(--border-light)" stroke-width="1.5" stroke-dasharray="4 4" />
              <circle cx="40" cy="40" r="12" stroke="var(--border-light)" stroke-width="1.5" />
              <circle cx="40" cy="40" r="3" fill="var(--text-primary)" />
              <line x1="40" y1="0" x2="40" y2="4" stroke="var(--text-secondary)" stroke-width="1.5" />
              <line x1="64" y1="16" x2="61" y2="19" stroke="var(--text-secondary)" stroke-width="1.5" />
            </svg>
          </div>
          <h3>准备开始扫描</h3>
          <p class="empty-desc">输入目标地址并选择扫描模式，即可开始安全扫描分析</p>
          <div class="mode-cards">
            <div
              class="mode-card"
              v-for="mode in scanModes"
              :key="mode.value"
              :class="{ selected: form.mode === mode.value }"
              @click="form.mode = mode.value"
            >
              <svg class="mode-icon" v-if="mode.value === 'info'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="12" cy="12" r="10"></circle>
              <circle cx="12" cy="12" r="6"></circle>
              <circle cx="12" cy="12" r="2"></circle>
              <line x1="12" y1="2" x2="12" y2="6"></line>
            </svg>
            <svg class="mode-icon" v-else-if="mode.value === 'vuln'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 2L3 7v5c0 5.2 3.8 9 9 10 5.2-1 9-4.8 9-10V7l-9-5z"></path>
              <line x1="9" y1="12" x2="11" y2="14"></line>
              <line x1="11" y1="14" x2="15" y2="10"></line>
            </svg>
            <svg class="mode-icon" v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <rect x="6" y="6" width="12" height="12" rx="2"></rect>
              <rect x="9" y="9" width="6" height="6" rx="1"></rect>
              <line x1="12" y1="3" x2="12" y2="6"></line>
            </svg>
              <strong>{{ mode.name }}</strong>
              <p>{{ mode.desc }}</p>
              <span class="mode-badge">{{ mode.badge }}</span>
            </div>
          </div>
        </div>

        <div class="scan-progress" id="scanProgress" v-show="isScanning || progress > 0">
          <div class="progress-overview">
            <div class="stage-indicators">
              <div class="stage-item" :class="{ active: progress >= 0, done: progress >= 30 }">
                <span class="stage-dot"></span>
                <span class="stage-label">初始化</span>
              </div>
              <div class="stage-connector" :class="{ done: progress >= 70 }"></div>
              <div class="stage-item" :class="{ active: progress >= 30, done: progress >= 70 }">
                <span class="stage-dot"></span>
                <span class="stage-label">工具执行</span>
              </div>
              <div class="stage-connector" :class="{ done: progress >= 100 }"></div>
              <div class="stage-item" :class="{ active: progress >= 70, done: progress >= 100 }">
                <span class="stage-dot"></span>
                <span class="stage-label">报告生成</span>
              </div>
            </div>
          </div>
       
          <div class="task-list" id="taskList">
            <div class="task-item" v-for="(task, index) in tasks" :key="index" @click="toggleTaskDetails(index)">
              <div class="task-main">
                <span class="task-dot" :class="task.status"></span>
                <span class="task-name">{{ task.name }}</span>
                <span class="task-elapsed">{{ task.elapsed || 'N/A' }}</span>
                <span class="task-badge" :class="task.status">{{ badgeText(task.status) }}</span>
                <span class="task-expand-icon" v-if="task.inputParams && Object.keys(task.inputParams).length > 0">
                  {{ task.showDetails ? '▼' : '▶' }}
                </span>
              </div>
              <div class="task-details" v-if="task.showDetails && task.inputParams">
                <div class="detail-row" v-for="(value, key) in task.inputParams" :key="key">
                  <span class="detail-key">{{ key }}:</span>
                  <span class="detail-value">{{ value }}</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- 轮询兜底提示：WS 断开但轮询仍在工作 -->
        <div class="poll-banner" v-if="isPolling && wsOffline">
          <span class="poll-banner-dot"></span>
          <span>WebSocket 已断开，正在通过轮询获取任务状态...</span>
        </div>

        <!-- 中断点：等待用户补充参数（waiting_user_input） -->
        <div class="interactive-panel" v-if="interactionRequest">
          <div class="panel-header">
            <h4>{{ interactionRequest.title || '需要进一步操作' }}</h4>
            <p class="panel-desc">{{ interactionRequest.description || '请选择下一步操作以继续扫描' }}</p>
          </div>
          <div class="panel-footer interaction-options">
            <button v-for="option in interactionRequest.options" :key="option.key" class="primary-btn" :class="option.style || 'btn-secondary'" @click="submitInteraction(option.key)">{{ option.label }}</button>
          </div>
        </div>

        <div class="interactive-panel" v-if="waitingInput">
          <div class="panel-header">
            <h4>需要补充参数</h4>
            <p class="panel-desc">扫描任务已暂停，请填写以下参数后继续</p>
          </div>
          <div class="panel-body">
            <div class="form-group" v-for="field in waitingInput.fields" :key="field.name">
              <label>
                {{ field.name }}
                <span class="required-mark" v-if="field.required">*</span>
              </label>
              <p class="field-desc" v-if="field.description">{{ field.description }}</p>
              <input
                v-if="field.type === 'boolean'"
                type="checkbox"
                v-model="inputFormValues[field.name]"
              >
              <input
                v-else-if="field.type === 'number'"
                type="number"
                v-model="inputFormValues[field.name]"
                :placeholder="field.default || ''"
              >
              <input
                v-else-if="field.type === 'password'"
                type="password"
                v-model="inputFormValues[field.name]"
                :placeholder="field.default || ''"
              >
              <input
                v-else
                type="text"
                v-model="inputFormValues[field.name]"
                :placeholder="field.default || ''"
              >
            </div>
          </div>
          <div class="panel-footer">
            <button class="primary-btn" @click="submitInputForm" :disabled="submittingInput">
              {{ submittingInput ? '提交中...' : '提交参数' }}
            </button>
          </div>
        </div>

        <!-- 中断点：等待用户上传脚本（waiting_script_upload） -->
        <div class="interactive-panel" v-if="waitingScript">
          <div class="panel-header">
            <h4>需要上传脚本</h4>
            <p class="panel-desc">所需能力: <code>{{ waitingScript.capability }}</code></p>
          </div>
          <div class="panel-body" v-if="waitingScript.params && waitingScript.params.length">
            <p class="params-title">入参规范：</p>
            <ul class="params-list">
              <li v-for="p in waitingScript.params" :key="p.name">
                <code>{{ p.name }}</code>
                <span class="param-type">({{ p.type }})</span>
                <span class="param-desc" v-if="p.description"> — {{ p.description }}</span>
              </li>
            </ul>
          </div>
          <div class="panel-body">
            <div class="form-group">
              <label>脚本名称</label>
              <input type="text" v-model="scriptForm.script_name" placeholder="例如: custom_scanner">
            </div>
            <div class="form-group">
              <label>脚本内容</label>
              <textarea v-model="scriptForm.script_content" rows="8" placeholder="粘贴脚本内容..."></textarea>
            </div>
            <div class="form-group">
              <label>或从文件导入</label>
              <input type="file" @change="onScriptFileChange" accept=".py,.js">
            </div>
            <p v-if="scriptProgress.message" class="upload-status" :class="scriptProgress.stage">{{ scriptProgress.message }}</p>
          </div>
          <div class="panel-footer">
            <button class="primary-btn" @click="submitScriptUpload" :disabled="submittingScript || readingScript">
              {{ readingScript ? '读取中...' : (submittingScript ? '上传中...' : '上传脚本') }}
            </button>
          </div>
        </div>

        <div class="scan-results" id="scanResults" v-show="showResults">
          <h3>扫描结果</h3>

          <div class="results-summary">
            <div class="summary-stat">
              <span class="stat-number">{{ resultsData.completed_tasks?.length || 0 }}</span>
              <span class="stat-label">完成任务</span>
            </div>
            <div class="summary-stat" :class="{ warning: (resultsData.vulnerabilities?.length || 0) > 0 }">
              <span class="stat-number">{{ resultsData.vulnerabilities?.length || 0 }}</span>
              <span class="stat-label">发现漏洞</span>
            </div>
            <div class="summary-stat">
              <span class="stat-number">{{ resultsData.errors?.length || 0 }}</span>
              <span class="stat-label">错误</span>
            </div>
            <div class="summary-stat">
              <span class="stat-number">{{ resultsData.tool_results ? Object.keys(resultsData.tool_results).length : 0 }}</span>
              <span class="stat-label">工具执行</span>
            </div>
          </div>

          <div class="results-content" id="resultsContent">
            <div class="result-section" v-if="resultsData.completed_tasks?.length > 0">
              <h4>完成的任务</h4>
              <button
                class="task-result-btn"
                v-for="(t, i) in resultsData.completed_tasks"
                :key="i"
                @click="openTaskResultModal(t)"
              >{{ t }}</button>
            </div>

            <div class="result-section" v-if="resultsData.vulnerabilities?.length > 0">
              <h4>发现的漏洞 ({{ resultsData.vulnerabilities.length }})</h4>
              <div
                v-for="(vuln, i) in resultsData.vulnerabilities"
                :key="i"
                class="vulnerability-card"
                :class="vuln.severity || 'medium'"
              >
                <div class="vuln-header">
                  <span class="severity-badge" :class="vuln.severity || 'medium'">{{ severityLabel(vuln.severity || 'medium') }}</span>
                  <strong>{{ vuln.name || vuln.type || '未知漏洞' }}</strong>
                </div>
                <p class="vuln-desc">{{ vuln.description || vuln.details || '' }}</p>
                <div class="vuln-meta" v-if="vuln.cve || vuln.cvss">
                  <span v-if="vuln.cve" class="vuln-cve">{{ vuln.cve }}</span>
                  <span v-if="vuln.cvss" class="vuln-cvss">CVSS {{ vuln.cvss }}</span>
                </div>
              </div>
            </div>

            <div class="result-section" v-if="resultsData.report">
              <h4>扫描报告</h4>
              <div class="report-toolbar">
                <a v-if="resultsData.html_report_url" class="primary-btn report-link" :href="resultsData.html_report_url" target="_blank" rel="noopener">打开 HTML 报告</a>
                <a v-if="resultsData.report_url" class="secondary-btn report-link" :href="resultsData.report_url" target="_blank" rel="noopener">下载 Markdown</a>
              </div>
              <iframe v-if="resultsData.html_report_url" class="report-preview" :src="resultsData.html_report_url" sandbox="allow-same-origin" title="AI 扫描报告预览"></iframe>
              <iframe v-else class="report-preview" :srcdoc="renderMarkdownDocument(resultsData.report)" sandbox title="AI 扫描报告预览"></iframe>
            </div>

            <div class="result-section report-analysis" v-if="resultsData.report_analysis && Object.keys(resultsData.report_analysis).length">
              <h4>AI 风险分析</h4>
              <div class="analysis-grid">
                <div v-for="(value, key) in resultsData.report_analysis" :key="key" class="analysis-item">
                  <strong>{{ key }}</strong><span>{{ typeof value === 'object' ? JSON.stringify(value) : value }}</span>
                </div>
              </div>
            </div>

            <div class="result-section" v-if="resultsData.errors?.length > 0">
              <h4>错误信息</h4>
              <div class="result-item" v-for="(err, i) in resultsData.errors" :key="i" style="color: var(--error-color);">
                {{ err }}
              </div>
            </div>

            <div class="result-section" v-if="isResultEmpty()">
              <p>扫描完成，未发现异常</p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <Transition name="modal-fade">
      <div v-if="taskModal.show" class="task-modal-overlay" @click.self="closeTaskResultModal"></div>
    </Transition>

    <Transition name="modal-slide">
      <div v-if="taskModal.show" class="task-modal-panel">
        <div class="task-modal-header">
          <h3>任务结果: {{ formatTaskName(taskModal.taskName) }}</h3>
          <button class="task-modal-close" @click="closeTaskResultModal">&times;</button>
        </div>
        <div class="task-modal-content">
          <div class="task-modal-report markdown-body" v-html="renderedTaskResult"></div>
        </div>
      </div>
    </Transition>
  </div>
</template>

<script setup>
import { reactive, ref, computed, onMounted, onUnmounted, watch } from 'vue'
import { API } from '../../services/api.js'
import { ws } from '../../services/websocket.js'
import { showToast, globalState, addScanHistory, getScanHistory } from '../../store.js'
import { marked } from 'marked'
import { TaskPoller } from '../../services/taskPoller.js'

marked.setOptions({ breaks: true, gfm: true })

const scanModes = [
  { value: 'info_collection', name: '信息收集', desc: 'WHOIS、DNS、子域名、端口扫描等基础信息', badge: '轻量·快速' },
  { value: 'vuln_scan', name: '漏洞扫描', desc: 'XSS、SQL注入、CSRF等常见Web漏洞检测', badge: '中等·约3-5分钟' },
  { value: 'full_scan', name: '完整扫描', desc: '信息收集+漏洞扫描+AI决策链条', badge: '深度·约5-10分钟' },
]

const form = reactive({ target: '', mode: 'info_collection', paramsText: '' })
const paramsError = ref('')
const requestedNextTask = ref('')
const isScanning = ref(false)
const progress = ref(0)
const statusText = ref('准备中...')
const showResults = ref(false)
const tasks = ref([])
const completedTasksCount = ref(0)
const totalTasksCount = ref(0)
const resultsData = ref({})
const scanHistory = ref([])
const isGeneratingReport = ref(false)

// === 任务轮询（TaskPoller，作为 WS 的补充/兜底通道） ===
const taskPoller = new TaskPoller()
/** 当前跟踪的任务 ID（停止轮询后仍保留，供提交参数后重启轮询使用） */
const currentTaskId = ref(null)
const isPolling = ref(false)
/** WS 连接是否已断开（在每次轮询回调中刷新，不注册 onDisconnect 以免覆盖其他组件回调） */
const wsOffline = ref(false)
/** waiting_user_input 时填充：{ fields: [{name,type,description,required,default}] } */
const waitingInput = ref(null)
/** waiting_script_upload 时填充：{ capability, params: [{name,type,description}] } */
const waitingScript = ref(null)
const interactionRequest = ref(null)
/** 动态输入表单的值（按 field.name 为 key） */
const inputFormValues = reactive({})
const submittingInput = ref(false)
/** 脚本上传表单 */
const scriptForm = reactive({ script_name: '', script_content: '', filename: '' })
const submittingScript = ref(false)
const readingScript = ref(false)
const scriptProgress = reactive({ stage: '', progress: 0, message: '' })
const SCAN_STATE_STORAGE_KEY = 'toskill_scan_view_state_v2'

const persistScanState = () => {
  try {
    sessionStorage.setItem(SCAN_STATE_STORAGE_KEY, JSON.stringify({
      form: { ...form },
      isScanning: isScanning.value,
      progress: progress.value,
      statusText: statusText.value,
      showResults: showResults.value,
      tasks: tasks.value,
      completedTasksCount: completedTasksCount.value,
      totalTasksCount: totalTasksCount.value,
      resultsData: resultsData.value,
      currentTaskId: currentTaskId.value,
      isPolling: isPolling.value,
      wsOffline: wsOffline.value,
      waitingInput: waitingInput.value,
      waitingScript: waitingScript.value,
      interactionRequest: interactionRequest.value,
      inputFormValues: { ...inputFormValues },
      scriptForm: { ...scriptForm },
      savedAt: new Date().toISOString()
    }))
  } catch (error) {
    if (import.meta.env.DEV) console.warn('Failed to persist scan state:', error)
  }
}

const restoreScanState = () => {
  try {
    const saved = sessionStorage.getItem(SCAN_STATE_STORAGE_KEY)
    if (!saved) return
    const state = JSON.parse(saved)
    if (state.form) {
      Object.assign(form, state.form)
      const modeAliases = { info: 'info_collection', vuln: 'vuln_scan', full: 'full_scan' }
      if (modeAliases[form.mode]) form.mode = modeAliases[form.mode]
      if (typeof form.paramsText !== 'string') form.paramsText = ''
    }
    if (typeof state.isScanning === 'boolean') isScanning.value = state.isScanning
    if (typeof state.progress === 'number') progress.value = state.progress
    if (typeof state.statusText === 'string') statusText.value = state.statusText
    if (typeof state.showResults === 'boolean') showResults.value = state.showResults
    if (Array.isArray(state.tasks)) tasks.value = state.tasks
    if (typeof state.completedTasksCount === 'number') completedTasksCount.value = state.completedTasksCount
    if (typeof state.totalTasksCount === 'number') totalTasksCount.value = state.totalTasksCount
    if (state.resultsData && typeof state.resultsData === 'object') resultsData.value = state.resultsData
    if (state.currentTaskId) currentTaskId.value = state.currentTaskId
    if (typeof state.isPolling === 'boolean') isPolling.value = state.isPolling
    if (typeof state.wsOffline === 'boolean') wsOffline.value = state.wsOffline
    if (state.waitingInput) waitingInput.value = state.waitingInput
    if (state.waitingScript) waitingScript.value = state.waitingScript
    if (state.interactionRequest) interactionRequest.value = state.interactionRequest
    if (state.inputFormValues && typeof state.inputFormValues === 'object') {
      Object.assign(inputFormValues, state.inputFormValues)
    }
    if (state.scriptForm && typeof state.scriptForm === 'object') {
      Object.assign(scriptForm, state.scriptForm)
    }
  } catch (error) {
    if (import.meta.env.DEV) console.warn('Failed to restore scan state:', error)
  }
}

watch(
  [
    form,
    isScanning,
    progress,
    statusText,
    showResults,
    tasks,
    completedTasksCount,
    totalTasksCount,
    resultsData,
    currentTaskId,
    isPolling,
    wsOffline,
    waitingInput,
    waitingScript,
    interactionRequest,
    inputFormValues,
    scriptForm
  ],
  persistScanState,
  { deep: true }
)

const taskModal = reactive({
  show: false,
  taskName: '',
  result: ''
})

const circumference = 2 * Math.PI * 34
const ringOffset = computed(() => circumference * (1 - progress.value / 100))

const badgeText = (status) => {
  switch (status) {
    case 'pending': return '等待中'
    case 'running': return '执行中'
    case 'completed': return '已完成'
    case 'error': return '失败'
    default: return status
  }
}

const toggleTaskDetails = (index) => {
  if (tasks.value[index]) {
    tasks.value[index].showDetails = !tasks.value[index].showDetails
  }
}

const severityLabel = (severity) => {
  switch (severity) {
    case 'high': return '高危'
    case 'medium': return '中危'
    case 'low': return '低危'
    default: return severity
  }
}

const formatResult = (result) => {
  if (typeof result === 'string') {
    try {
      result = JSON.parse(result)
    } catch (e) {
      return result
    }
  }
  if (typeof result === 'object') {
    return JSON.stringify(result, null, 2)
  }
  return String(result)
}

const isResultEmpty = () => {
  const d = resultsData.value
  return !(d.completed_tasks?.length || d.vulnerabilities?.length || d.report || d.errors?.length)
}

const openTaskResultModal = (taskName) => {
  taskModal.taskName = taskName
  const res = resultsData.value.tool_results?.[taskName]
  if (res !== undefined && res !== null) {
    if (typeof res === 'string') {
      taskModal.result = res
    } else {
      taskModal.result = JSON.stringify(res, null, 2)
    }
  } else {
    taskModal.result = '*该任务无可用结果数据*'
  }
  taskModal.show = true
}

const closeTaskResultModal = () => {
  taskModal.show = false
  taskModal.taskName = ''
  taskModal.result = ''
}

const formatTaskName = (name) => {
  if (!name) return ''
  return name.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

const renderedTaskResult = computed(() => {
  if (!taskModal.result) return ''
  return marked.parse(taskModal.result)
})

const renderMarkdownDocument = (content) => {
  const body = content ? marked.parse(String(content)) : ''
  return `<!doctype html><html><head><meta charset="utf-8"><style>body{font:14px/1.7 system-ui,sans-serif;color:#1f2937;padding:24px;max-width:1100px;margin:auto}h1,h2,h3{color:#111827;border-bottom:1px solid #e5e7eb;padding-bottom:.35em}table{border-collapse:collapse;width:100%}th,td{border:1px solid #d1d5db;padding:8px;text-align:left}pre,code{background:#f3f4f6;border-radius:5px}pre{padding:14px;overflow:auto}blockquote{border-left:4px solid #60a5fa;margin-left:0;padding-left:14px;color:#4b5563}</style></head><body>${body}</body></html>`
}

const formatElapsed = (ms) => {
  if (ms < 1000) return Math.round(ms) + 'ms'
  return (ms / 1000).toFixed(1) + 's'
}

const initProgress = () => {
  isScanning.value = true
  showResults.value = false
  progress.value = 0
  statusText.value = '正在初始化扫描...'
  tasks.value = []
  completedTasksCount.value = 0
  totalTasksCount.value = 0
  resultsData.value = {}
}

const addTask = (taskName, status = 'pending') => {
  if (!tasks.value.find(t => t.name === taskName)) {
    tasks.value.push({ name: taskName, status, startTime: Date.now(), elapsed: null })
    totalTasksCount.value++
  }
}

const updateTaskStatus = (taskName, status) => {
  if (!taskName) return
  if (!tasks.value.find(t => t.name === taskName)) addTask(taskName, status)
  const task = tasks.value.find(t => t.name === taskName)
  if (task && task.status !== status) {
    task.status = status
    if (status === 'completed' || status === 'error') {
      task.elapsed = task.startTime ? formatElapsed(Date.now() - task.startTime) : 'N/A'
    }
    completedTasksCount.value = tasks.value.filter(item => ['completed', 'error'].includes(item.status)).length
    totalTasksCount.value = Math.max(totalTasksCount.value, tasks.value.length)
    const pct = Math.round((completedTasksCount.value / (totalTasksCount.value || 1)) * 100)
    progress.value = pct
    statusText.value = `已完成 ${completedTasksCount.value}/${totalTasksCount.value} 任务`
  }
}

const startScan = async () => {
  const target = form.target.trim()
  if (!target) {
    showToast('请输入扫描目标', 'warning')
    return
  }

  let params = {}
  try {
    if (form.paramsText.trim()) {
      params = JSON.parse(form.paramsText)
      if (!params || Array.isArray(params) || typeof params !== 'object') throw new Error('任务参数必须是 JSON 对象')
    }
    requestedNextTask.value = String(params.next_task || params.user_directed_next_task || '').trim()
    paramsError.value = ''
  } catch (error) {
    paramsError.value = error.message
    showToast(error.message, 'warning')
    return
  }

  initProgress()

  try {
    if (ws.isConnected()) {
      if (!ws.startScan(target, form.mode, params)) throw new Error('WebSocket 发送失败')
      globalState.currentTarget = target
      statusText.value = '扫描请求已发送，等待 AI 规划...'
      addScanHistory(target)
      scanHistory.value = getScanHistory()
      return
    }

    let result
    switch (form.mode) {
      case 'info_collection': result = await API.startInfoScan(target, params); break
      case 'vuln_scan': result = await API.startVulnScan(target, params); break
      case 'full_scan': result = await API.startFullScan(target, params); break
    }

    if (!result || !result.data) {
      showToast('扫描返回数据异常', 'error')
      isScanning.value = false
      return
    }

    const hasCompletedTasks = result.data.completed_tasks && result.data.completed_tasks.length > 0
    const hasVulnerabilities = result.data.vulnerabilities && result.data.vulnerabilities.length > 0
    const hasResults = result.data.results && result.data.results.length > 0
    const hasSuccesses = result.data.results && result.data.results.some(r => r.success)

    if (hasCompletedTasks || hasVulnerabilities || (hasResults && hasSuccesses)) {
      if (!result.data.tool_results && result.data.results) {
        result.data.tool_results = {}
        result.data.results.forEach(r => {
          if (r.success) {
            result.data.tool_results[r.tool] = r.result
          }
        })
      }
      handleScanResult(result.data)
      showToast('扫描完成', 'success')
      globalState.currentTarget = target
    } else if (hasResults && !hasSuccesses) {
      handleScanResult(result.data)
      isScanning.value = false
      showToast('扫描失败，所有工具执行异常', 'error')
      globalState.currentTarget = target
    } else {
      statusText.value = '指令已发送，等待执行...'
      globalState.currentTarget = target
      // 异步扫描：若有 task_id 则启动轮询兜底（WS 仍为主通道）
      const tid = result.task_id || result.data?.task_id
      if (tid) startTaskPolling(tid)
    }
  } catch (error) {
    showToast('扫描启动失败: ' + error.message, 'error')
    isScanning.value = false
  }
}

const ensureReportGenerated = async (scanData) => {
  const sessionId = scanData?.session_id || scanData?.task_id
  if (!sessionId || isGeneratingReport.value) return

  // Completed polling status may contain the persisted report URL but omit
  // the full Markdown body. Load it directly instead of generating a duplicate.
  if (!scanData?.report && scanData?.report_url) {
    try {
      const filename = decodeURIComponent(String(scanData.report_url).split('/').pop())
      const response = await API.getReportContent(filename)
      const content = response?.data?.content || ''
      if (content) {
        resultsData.value = {
          ...resultsData.value,
          ...scanData,
          report: content,
          report_status: 'completed'
        }
        return
      }
    } catch (error) {
      console.warn('已保存报告读取失败，将尝试重新生成:', error)
    }
  }

  if (scanData?.report) return

  isGeneratingReport.value = true
  resultsData.value = {
    ...resultsData.value,
    report_status: 'generating',
    report: 'AI report generation in progress...'
  }
  try {
    const response = await API.generateScanReport(sessionId)
    const generated = response?.data || response || {}
    resultsData.value = {
      ...resultsData.value,
      ...generated,
      report: generated.report || generated.report_preview || resultsData.value.report || '',
      report_status: 'completed'
    }
  } catch (error) {
    resultsData.value = {
      ...resultsData.value,
      report_status: 'error',
      report_error: error.message
    }
    showToast('AI report generation failed: ' + error.message, 'error')
  } finally {
    isGeneratingReport.value = false
  }
}

const handleScanResult = (data) => {
  isScanning.value = false
  progress.value = 100
  statusText.value = '扫描完成'
  resultsData.value = data?.payload || data?.data || data || {}
  const resultTasks = resultsData.value.completed_tasks || []
  if (Array.isArray(resultTasks)) {
    resultTasks.forEach(name => updateTaskStatus(name, 'completed'))
    completedTasksCount.value = resultTasks.length
    totalTasksCount.value = Math.max(totalTasksCount.value, resultTasks.length)
  }
  if (resultsData.value.next_task) {
    statusText.value = `扫描完成，下一任务：${resultsData.value.next_task}`
  }
  showResults.value = true
  if (form.target.trim()) {
    addScanHistory(form.target.trim())
    scanHistory.value = getScanHistory()
  }
  void ensureReportGenerated(resultsData.value)
}

const cancelScan = () => {
  ws.sendStopScan()
  isScanning.value = false
  progress.value = 0
  statusText.value = '已取消'
  stopTaskPolling()
  showToast('扫描已取消', 'warning')
}

// === 任务轮询：启动 / 停止 / 状态回调 ===

/**
 * 启动任务轮询。若已有轮询在跑则先停止。
 * 轮询是 WS 的补充：WS 仍是主通道，这里仅作状态兜底与中断点驱动。
 * @param {string} taskId 任务 ID
 */
const startTaskPolling = (taskId) => {
  if (!taskId) return
  currentTaskId.value = taskId
  taskPoller.stop()
  taskPoller.start(taskId, onTaskStatus, {
    interval: 2000,
    onError: (error) => {
      wsOffline.value = !ws.isConnected()
      if (error.message.includes('超过上限')) {
        showToast('任务轮询已达到后端执行上限，请检查后端日志或重新发起扫描', 'warning')
      }
    }
  })
  isPolling.value = taskPoller.isPolling
}

const stopTaskPolling = () => {
  taskPoller.stop()
  isPolling.value = false
}

const normalizeTaskStatus = (status) => {
  const root = status?.data?.status ? status.data : (status?.data || status || {})
  const result = root.result?.data || root.result || {}
  const completed = root.completed_tasks || result.completed_tasks || []
  const total = root.total_tasks || result.total_tasks || root.total || totalTasksCount.value || completed.length
  const progressValue = root.progress_percent ?? root.progress ?? (total ? (completed.length / total) * 100 : 0)
  completed.forEach(name => {
    addTask(name, 'completed')
    const task = tasks.value.find(item => item.name === name)
    if (task && !task.elapsed && task.startTime) task.elapsed = formatElapsed(Date.now() - task.startTime)
  })
  completedTasksCount.value = completed.length
  totalTasksCount.value = Math.max(totalTasksCount.value, Number(total) || 0)
  progress.value = Math.max(progress.value, Math.min(100, Number(progressValue) || 0))
  if (root.next_task) statusText.value = `${root.stage || '工作流'}，下一任务：${root.next_task}`
  return { ...root, progress: Number(progressValue) || 0, result }
}

const submitInteraction = (choice) => {
  if (!choice) return
  if (!ws.isConnected()) {
    showToast('WebSocket 已断开，请重新连接后重试', 'error')
    return
  }
  if (String(choice) === '3') {
    waitingInput.value = {
      context: 'interaction_chat',
      fields: [{ name: 'chat_message', type: 'text', description: '请输入要向智能体询问或补充的内容', required: true }]
    }
    interactionRequest.value = null
    return
  }
  if (String(choice) === '2') {
    ws.sendStopScan()
    interactionRequest.value = null
    waitingInput.value = null
    waitingScript.value = null
    isScanning.value = false
    stopTaskPolling()
    showToast('扫描已停止', 'warning')
    return
  }
  ws.sendConfirm(choice)
  interactionRequest.value = null
  if (String(choice) === '4') {
    waitingScript.value = { capability: '自定义扫描脚本', params: [] }
  } else if (String(choice) === '5') {
    waitingInput.value = {
      context: 'script_generate',
      fields: [{ name: 'script_description', type: 'text', description: '请描述希望 AI 生成的扫描脚本功能', required: true }]
    }
  }
  const tid = currentTaskId.value
  if (tid) setTimeout(() => startTaskPolling(tid), 500)
}

/**
 * 轮询状态回调。按 status 更新 UI。
 * 兼容后端可能的 {data:{...}} 包装。
 */
const onTaskStatus = (status) => {
  // 兼容后端返回 {data:{...}} 或裸对象
  const st = normalizeTaskStatus(status)
  if (!st.status) return

  // 每次轮询刷新 WS 连接状态（不注册 onDisconnect 以免覆盖其他组件回调）
  wsOffline.value = !ws.isConnected()
  isPolling.value = taskPoller.isPolling

  switch (st.status) {
    case 'queued':
    case 'planning':
    case 'running':
      // 更新进度展示（仅在轮询进度更高时覆盖，避免回退 WS 已有进度）
      if (typeof st.progress === 'number') {
        progress.value = Math.max(progress.value, st.progress)
      }
      if (st.stage) statusText.value = st.stage
      // 任务已恢复运行，清除中断面板
      waitingInput.value = null
      waitingScript.value = null
      break

    case 'waiting_user_input':
      waitingInput.value = st.waiting_input || st.data?.waiting_input || null
      // 用 default 初始化表单值（仅初始化未出现过的字段）
      if (waitingInput.value && Array.isArray(waitingInput.value.fields)) {
        waitingInput.value.fields.forEach(f => {
          if (inputFormValues[f.name] === undefined) {
            inputFormValues[f.name] = (f.default !== undefined && f.default !== '')
              ? f.default
              : (f.type === 'boolean' ? false : '')
          }
        })
      }
      // 任务已暂停等待输入，停止轮询避免空转；提交后重启
      taskPoller.stop()
      isPolling.value = false
      break

    case 'waiting_script_upload':
      waitingScript.value = st.waiting_script || st.data?.waiting_script || null
      // 同样停止轮询，等待用户上传后重启
      taskPoller.stop()
      isPolling.value = false
      break

    case 'completed':
      waitingInput.value = null
      waitingScript.value = null
      handleScanResult({ ...(st.result || {}), ...st })
      stopTaskPolling()
      break

    case 'exception':
      waitingInput.value = null
      waitingScript.value = null
      showToast('扫描异常: ' + (st.error || '未知错误'), 'error')
      stopTaskPolling()
      break
  }
}

// === 中断点：提交用户输入参数 ===

const submitInputForm = () => {
  if (!waitingInput.value) return
  const fields = waitingInput.value.fields || []
  // 必填校验
  for (const f of fields) {
    const val = inputFormValues[f.name]
    if (f.required && (val === '' || val === undefined || val === null)) {
      showToast(`字段 [${f.name}] 为必填项`, 'warning')
      return
    }
  }
  // 组装多字段 payload：{ fields: [{field, value}] }
  const context = waitingInput.value.context
  const firstValue = fields.length ? inputFormValues[fields[0].name] : ''
  if (context === 'interaction_chat') {
    const sent = ws.send('interaction_chat', { content: firstValue })
    if (sent) {
      waitingInput.value = null
      delete inputFormValues.chat_message
      showToast('消息已发送，智能体正在处理', 'success')
    } else showToast('发送失败：WebSocket 未连接', 'error')
    return
  }
  if (context === 'script_generate') {
    const sent = ws.send('script_description', { description: firstValue })
    if (sent) {
      waitingInput.value = null
      delete inputFormValues.script_description
      showToast('已提交脚本需求，AI 正在生成', 'success')
    } else showToast('发送失败：WebSocket 未连接', 'error')
    return
  }

  const payloadFields = fields.map(f => ({
    field: f.name,
    value: inputFormValues[f.name]
  }))
  submittingInput.value = true
  const sent = ws.send('input_response', { fields: payloadFields })
  submittingInput.value = false
  if (sent) {
    showToast('参数已提交', 'success')
    waitingInput.value = null
    // 提交后重启轮询以追踪恢复后的进度（给后端 resume 处理时间）
    const tid = currentTaskId.value
    if (tid) {
      setTimeout(() => {
        if (!taskPoller.isPolling) startTaskPolling(tid)
      }, 1500)
    }
  } else {
    showToast('提交失败，WebSocket 未连接', 'error')
  }
}

// === 中断点：提交脚本上传 ===

const submitScriptUpload = () => {
  if (!waitingScript.value) return
  if (!scriptForm.script_content.trim()) {
    showToast('脚本内容不能为空', 'warning')
    return
  }
  const name = scriptForm.script_name.trim() || `custom_${Date.now().toString(36)}`
  const language = scriptForm.filename.toLowerCase().endsWith('.js') ? 'js' : 'py'
  scriptProgress.stage = 'uploading'
  scriptProgress.progress = 0
  scriptProgress.message = `正在发送脚本(${language})...`
  submittingScript.value = true
  const sent = ws.send('script_content', {
    script_content: scriptForm.script_content,
    script_name: name,
    filename: scriptForm.filename || name,
    language
  })
  submittingScript.value = false
  if (sent) {
    showToast('脚本已上传，正在注册...', 'success')
    waitingScript.value = null
    scriptForm.script_name = ''
    scriptForm.script_content = ''
    scriptForm.filename = ''
    scriptProgress.stage = 'sent'
    scriptProgress.progress = 10
    scriptProgress.message = '脚本已发送，等待后端校验...'
    // 重启轮询追踪恢复进度
    const tid = currentTaskId.value
    if (tid) {
      setTimeout(() => {
        if (!taskPoller.isPolling) startTaskPolling(tid)
      }, 1500)
    }
  } else {
    showToast('上传失败，WebSocket 未连接', 'error')
  }
}

/** 从文件读取脚本内容填入表单 */
const onScriptFileChange = (event) => {
  const file = event.target.files && event.target.files[0]
  if (!file) return
  const extension = file.name.slice(file.name.lastIndexOf('.')).toLowerCase()
  if (!['.py', '.js'].includes(extension)) {
    showToast('仅支持 .py 或 .js 脚本文件', 'warning')
    event.target.value = ''
    return
  }
  if (file.size > 1024 * 1024) {
    showToast('脚本文件不能超过 1MB', 'warning')
    event.target.value = ''
    return
  }
  readingScript.value = true
  const reader = new FileReader()
  reader.onload = (e) => {
    scriptForm.script_content = String(e.target.result || '')
    if (!scriptForm.script_name.trim()) {
      scriptForm.script_name = file.name.replace(/\.[^.]+$/, '')
    }
    scriptForm.filename = file.name
    scriptProgress.stage = 'ready'
    scriptProgress.progress = 0
    scriptProgress.message = `已载入 ${file.name}`
    readingScript.value = false
  }
  reader.onerror = () => {
    readingScript.value = false
    showToast('文件读取失败', 'error')
  }
  reader.readAsText(file)
}

const handleWSMessage = (data) => {
  switch (data.type) {
    case 'interaction_required': {
      const payload = data.payload || {}
      const rawOptions = Array.isArray(payload.options) && payload.options.length
        ? payload.options
        : [{ key: '1', label: '执行' }, { key: '2', label: '停止' }, { key: '3', label: '聊天' }, { key: '4', label: '上传脚本' }, { key: '5', label: '生成脚本' }]
      interactionRequest.value = {
        title: payload.message || '需要进一步操作',
        description: `目标: ${payload.target || form.target || '-'} | 下一任务: ${payload.next_task || requestedNextTask.value || '-'}`,
        options: rawOptions.map(option => {
          const item = typeof option === 'string' ? { key: option, label: option } : (option || {})
          return { key: item.key ?? item.value ?? '', label: item.label ?? item.name ?? item.key ?? '', style: item.style || 'btn-secondary' }
        }).filter(option => option.key && option.label)
      }
      waitingInput.value = null
      waitingScript.value = null
      stopTaskPolling()
      isScanning.value = true
      break
    }

    case 'waiting_for_user_input': {
      const payload = data.payload || data
      const fields = Array.isArray(payload.fields) ? payload.fields : (payload.waiting_input?.fields || [])
      if (!fields.length) {
        waitingInput.value = null
        statusText.value = payload.message || '工作流等待后端提供参数定义'
        showToast('后端未返回可填写的参数字段', 'warning')
        break
      }
      waitingInput.value = {
        fields
      }
      interactionRequest.value = null
      waitingScript.value = null
      isScanning.value = true
      stopTaskPolling()
      break
    }

    case 'script_generate_request':
      waitingInput.value = {
        context: 'script_generate',
        fields: [{ name: 'script_description', type: 'text', description: data.payload?.message || '请描述希望 AI 生成的扫描脚本功能', required: true }]
      }
      interactionRequest.value = null
      waitingScript.value = null
      stopTaskPolling()
      break

    case 'script_upload_request':
      waitingScript.value = { capability: data.payload?.message || '自定义扫描脚本', params: [] }
      interactionRequest.value = null
      waitingInput.value = null
      stopTaskPolling()
      break

    case 'script_registered':
    case 'script_generated':
      waitingInput.value = null
      waitingScript.value = null
      scriptProgress.stage = 'completed'
      scriptProgress.progress = 100
      scriptProgress.message = data.payload?.message || '脚本处理完成'
      showToast(data.payload?.message || '脚本已注册', 'success')
      break

    case 'script_upload_progress':
    case 'script_generation_progress':
      scriptProgress.stage = data.payload?.stage || 'processing'
      scriptProgress.progress = Number(data.payload?.progress || 0)
      scriptProgress.message = data.payload?.message || '脚本处理中...'
      break

    case 'script_error':
      scriptProgress.stage = 'failed'
      scriptProgress.progress = 100
      scriptProgress.message = data.payload?.error || '脚本处理失败'
      showToast('脚本处理失败: ' + (data.payload?.error || '未知错误'), 'error')
      break

    case 'input_received':
      waitingInput.value = null
      showToast('参数已接收，工作流继续执行', 'success')
      break

    case 'workflow_resumed':
      if (data.payload?.resumed) {
        const tid = currentTaskId.value
        if (tid && !taskPoller.isPolling) startTaskPolling(tid)
      }
      break

    case 'scan_started':
      addTask(data.payload.task_id || '初始化任务', 'running')
      progress.value = 10
      statusText.value = '扫描已启动'
      // WS 推送的 task_id 同步启动轮询兜底
      if (data.payload.task_id) startTaskPolling(data.payload.task_id)
      break

    case 'tool_execution_started':
      addTask(data.payload.tool_name || data.payload.tool, 'running')
      break

    case 'tool_execution_update':
      const toolName = data.payload.tool_name
      const toolStatus = data.payload.status
      const inputParams = data.payload.input_params || {}
      
      if (toolStatus === 'started') {
        addTask(toolName, 'running')
        const existingTask = tasks.value.find(t => t.name === toolName)
        if (existingTask) {
          existingTask.inputParams = inputParams
        }
      } else if (toolStatus === 'completed') {
        updateTaskStatus(toolName, 'completed')
      } else if (toolStatus === 'failed') {
        updateTaskStatus(toolName, 'error')
      }
      break

    case 'tool_execution_completed':
      updateTaskStatus(data.payload.tool_name || data.payload.tool, 'completed')
      break

    case 'scan_completed':
      interactionRequest.value = null
      handleScanResult(data)
      stopTaskPolling()
      showToast('扫描完成', 'success')
      break

    case 'scan_cancelled':
      if (data.payload?.report_status === 'completed' || data.payload?.report_id || data.payload?.report_url) {
        resultsData.value = {
          ...resultsData.value,
          ...data.payload,
          report: data.payload.report || resultsData.value.report || data.payload.report_preview || '',
        }
        progress.value = 100
        statusText.value = '扫描已停止，报告已生成'
        showResults.value = true
        isScanning.value = false
        stopTaskPolling()
        if (typeof window !== 'undefined') {
          window.dispatchEvent(new CustomEvent('ai-websocket:report-ready', { detail: data.payload }))
        }
        showToast('扫描已停止，报告已生成', 'success')
        break
      }
      progress.value = 0
      statusText.value = '扫描已取消'
      isScanning.value = false
      stopTaskPolling()
      showToast('扫描已取消', 'warning')
      break

    case 'error':
      showToast('扫描错误: ' + (data.payload.error || data.payload.message), 'error')
      break

    case 'task_skipped':
      updateTaskStatus(data.payload.tool, 'error')
      showToast('任务跳过: ' + data.payload.reason, 'warning')
      break

    case 'task_error':
      updateTaskStatus(data.payload.tool, 'error')
      showToast('任务失败: ' + data.payload.error, 'error')
      break

    case 'workflow_progress':
      const pData = data.payload
      if (pData.progress_percent !== undefined) {
        progress.value = pData.progress_percent
        statusText.value = `${pData.stage || '扫描中'} - ${pData.completed}/${pData.total}`
      }
      break

    case 'report_generation_started':
      statusText.value = '正在生成 AI 报告...'
      break

    case 'report_generated':
      resultsData.value = {
        ...resultsData.value,
        ...data.payload,
        report_status: 'completed',
        report: data.payload?.report || resultsData.value.report || data.payload?.report_preview || ''
      }
      showResults.value = true
      isScanning.value = false
      stopTaskPolling()
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent('ai-websocket:report-ready', { detail: data.payload }))
      }
      break

    case 'ai_decision':
      const dData = data.payload
      progress.value = Math.round(((dData.completed_tasks?.length || 0) / (dData.total_tasks || 1)) * 100)
      statusText.value = `AI决策: 下一步 ${dData.next_task}`
      break
  }
}

onMounted(() => {
  restoreScanState()
  scanHistory.value = getScanHistory()
  ws.on('*', handleWSMessage)
  if (isScanning.value && currentTaskId.value && !waitingInput.value && !waitingScript.value) {
    startTaskPolling(currentTaskId.value)
  }
})

onUnmounted(() => {
  ws.off('*', handleWSMessage)
  stopTaskPolling()
})
</script>

<style scoped>
.scan-layout {
  display: flex;
  gap: 20px;
  align-items: stretch;
}

.scan-sidebar {
  width: 320px;
  flex-shrink: 0;
  background: #FAFAFA;
  border: 1px solid #EAEAEA;
  border-radius: 0px;
  padding: 24px;
  display: flex;
  flex-direction: column;
}

.scan-main {
  flex: 1;
  min-width: 0;
  background: #FAFAFA;
  border: 1px solid #EAEAEA;
  border-radius: 0px;
  padding: 24px;
}

.page-header {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  margin-bottom: 24px;
  width: 100%;
}

.form-group label {
  font-weight: 600;
}

.scan-count {
  font-size: 13px;
  color: var(--text-secondary);
}

.quick-targets {
  margin-top: 20px;
}

.quick-label {
  font-size: 16px;
  color: var(--text-secondary);
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  display: block;
  margin-bottom: 8px;
}

.quick-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  justify-content: center;
}

.quick-chip {
  font-size: 12px;
  padding: 4px 10px;
  border: 1px solid var(--border-light);
  border-radius: 14px;
  cursor: pointer;
  transition: border-color 0.25s cubic-bezier(0.25, 0.1, 0.25, 1), color 0.25s cubic-bezier(0.25, 0.1, 0.25, 1);
  max-width:400px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--text-secondary);
  flex-shrink: 0;     /* 禁止自动缩小 */
  width: fit-content; /* 宽度自适应内容 */
}

.quick-chip:hover {
  border-color: var(--text-primary);
  color: var(--text-primary);
}

.cancel-scan-link {
  display: inline-block;
  margin-top: 16px;
  font-size: 13px;
  color: var(--error-color, #ff3b30);
  cursor: pointer;
  text-decoration: none;
  transition: opacity 0.25s cubic-bezier(0.25, 0.1, 0.25, 1);
}

.cancel-scan-link:hover {
  opacity: 0.7;
}

.primary-btn {
  position: relative;
  transition: padding-right 0.25s cubic-bezier(0.25, 0.1, 0.25, 1);
}

.primary-btn::after {
  content: '\2192';
  position: absolute;
  right: 16px;
  opacity: 0;
  transform: translateX(-4px);
  transition: opacity 0.25s cubic-bezier(0.25, 0.1, 0.25, 1), transform 0.25s cubic-bezier(0.25, 0.1, 0.25, 1);
}

.primary-btn:not(:disabled):hover::after {
  opacity: 1;
  transform: translateX(0);
}

.primary-btn:not(:disabled):hover {
  padding-right: 36px;
}

input:focus,
select:focus {
  box-shadow: inset 2px 0 0 var(--text-primary);
}

.empty-state {
  text-align: center;
  padding: 36px 16px;
}

.empty-icon {
  margin-bottom: 20px;
  opacity: 0.6;
}

.empty-state h3 {
  font-size: 20px;
  font-weight: 600;
  color: var(--text-primary);
  margin-bottom: 8px;
}

.empty-desc {
  font-size: 14px;
  color: var(--text-secondary);
  margin-bottom: 32px;
}

.mode-cards {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 12px;
  max-width: 720px;
  margin: 0 auto;
}

.mode-card {
  border: 1px solid var(--border-light);
  border-radius: 5px;
  padding: 20px 14px;
  cursor: pointer;
  transition: border-color 0.25s cubic-bezier(0.25, 0.1, 0.25, 1), transform 0.2s cubic-bezier(0.25, 0.1, 0.25, 1);
  text-align: center;
}

.mode-card:hover {
  border-color: var(--text-primary);
  transform: translateY(-2px);
}

.mode-card.selected {
  border-color: var(--text-primary);
}

.mode-card .mode-icon {
  width: 32px;
  height: 32px;
  color: var(--text-secondary);
  display: block;
  margin: 0 auto 8px;
  transition: color 0.25s cubic-bezier(0.25, 0.1, 0.25, 1);
}

.mode-card:hover .mode-icon,
.mode-card.selected .mode-icon {
  color: var(--text-primary);
}

.mode-card strong {
  display: block;
  font-size: 14px;
  color: var(--text-primary);
  margin-bottom: 6px;
}

.mode-card p {
  font-size: 12px;
  color: var(--text-secondary);
  margin-bottom: 10px;
  line-height: 1.5;
}

.mode-badge {
  font-size: 11px;
  padding: 2px 8px;
  border: 1px solid var(--border-light);
  border-radius: 10px;
  color: var(--text-secondary);
}

.scan-progress {
  padding: 0;
}

.progress-overview {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 16px;
  margin-bottom: 16px;
  min-height: 80px;
}

.progress-ring {
  flex-shrink: 0;
}

.ring-bg {
  opacity: 0.3;
}

.ring-fill {
  transition: stroke-dashoffset 0.5s cubic-bezier(0.25, 0.1, 0.25, 1);
}

.ring-percent {
  font-size: 14px;
  font-weight: 600;
  font-variant-numeric: tabular-nums;
  color: var(--text-primary);
}

.stage-indicators {
  display: flex;
  align-items: center;
  gap: 0;
  flex: 1;
  min-width: 0;
  justify-content: center;
}

.stage-item {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 4px;
  opacity: 0.35;
  transition: opacity 0.3s cubic-bezier(0.25, 0.1, 0.25, 1);
}

.stage-item.active {
  opacity: 0.8;
}

.stage-item.done {
  opacity: 1;
}

.stage-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--border-light);
  transition: background 0.3s cubic-bezier(0.25, 0.1, 0.25, 1);
}

.stage-item.active .stage-dot {
  background: var(--text-primary);
}

.stage-item.done .stage-dot {
  background: var(--success-color);
}

.stage-label {
  font-size: 13px;
  font-weight: 500; 
  color: var(--text-secondary);
  white-space: nowrap;
}

.stage-connector {
  width: 300px;
  flex-shrink: 0;
  height: 1.5px;
  background: var(--border-light);
  margin: 0 4px;
  align-self: center;
  transition: background 0.3s cubic-bezier(0.25, 0.1, 0.25, 1);
}

.stage-connector.done {
  background: var(--text-primary);
}

.progress-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.progress-title {
  font-size: 14px;
  font-weight: 500;
  color: var(--text-primary);
}

.progress-status {
  font-size: 13px;
  color: var(--text-secondary);
}

.progress-bar {
  height: 4px;
  background: var(--border-light);
  border-radius: 2px;
  overflow: hidden;
  margin-bottom: 16px;
}

.progress-fill {
  height: 100%;
  background: var(--text-primary);
  border-radius: 2px;
  transition: width 0.35s cubic-bezier(0.25, 0.1, 0.25, 1);
}

.task-list {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.task-item {
  display: flex;
  flex-direction: column;
  gap: 0;
  padding: 8px 10px;
  border-radius: 0px;
  transition: background 0.2s cubic-bezier(0.25, 0.1, 0.25, 1);
  cursor: pointer;
}

.task-item:hover {
  background: var(--bg-secondary);
}

.task-main {
  display: flex;
  align-items: center;
  gap: 10px;
}

.task-expand-icon {
  margin-left: auto;
  font-size: 10px;
  color: var(--text-secondary);
}

.task-details {
  margin-top: 8px;
  margin-left: 18px;
  padding: 8px 12px;
  background: var(--bg-secondary);
  border-radius: 6px;
  font-size: 12px;
  animation: slideDown 0.2s ease;
}

@keyframes slideDown {
  from {
    opacity: 0;
    transform: translateY(-5px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

.detail-row {
  display: flex;
  gap: 8px;
  padding: 4px 0;
}

.detail-key {
  color: var(--text-secondary);
  min-width: 80px;
}

.detail-value {
  color: var(--text-primary);
  word-break: break-all;
}

.task-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
  background: var(--border-light);
}

.task-dot.pending {
  background: var(--border-light);
}

.task-dot.running {
  background: var(--text-primary);
  animation: pulse-dot 1.2s cubic-bezier(0.25, 0.1, 0.25, 1) infinite;
}

.task-dot.completed {
  background: var(--success-color);
}

.task-dot.error {
  background: var(--error-color);
}

@keyframes pulse-dot {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.35; }
}

.task-name {
  flex: 1;
  font-size: 13px;
  color: var(--text-primary);
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.task-elapsed {
  font-size: 11px;
  color: var(--text-secondary);
  font-variant-numeric: tabular-nums;
  flex-shrink: 0;
}

.task-badge {
  font-size: 11px;
  padding: 1px 8px;
  border-radius: 0px;
  flex-shrink: 0;
}

.task-badge.pending {
  color: var(--text-secondary);
  border: 1px solid var(--border-light);
}

.task-badge.running {
  color: var(--text-primary);
  border: 1px solid var(--text-primary);
}

.task-badge.completed {
  color: var(--success-color);
  border: 1px solid var(--success-color);
}

.task-badge.error {
  color: var(--error-color);
  border: 1px solid var(--error-color);
}

.scan-results {
  animation: fadeInUp 0.45s cubic-bezier(0.25, 0.1, 0.25, 1);
}

@keyframes fadeInUp {
  from {
    opacity: 0;
    transform: translateY(12px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

.results-summary {
  display: flex;
  gap: 16px;
  margin-bottom: 24px;
}

.summary-stat {
  flex: 1;
  border: 1px solid var(--border-light);
  border-radius: 0px;
  padding: 16px;
  text-align: center;
}

.summary-stat.warning {
  border-color: rgba(255, 149, 0, 0.35);
}

.summary-stat.warning .stat-number {
  color: var(--warning-color);
}

.stat-number {
  display: block;
  font-size: 28px;
  font-weight: 600;
  color: var(--text-primary);
  font-variant-numeric: tabular-nums;
}

.stat-label {
  display: block;
  font-size: 12px;
  color: var(--text-secondary);
  margin-top: 4px;
}

.result-section {
  animation: fadeInUp 0.35s cubic-bezier(0.25, 0.1, 0.25, 1);
}

.result-section:nth-child(1) { animation-delay: 0s; }
.result-section:nth-child(2) { animation-delay: 0.05s; }
.result-section:nth-child(3) { animation-delay: 0.1s; }
.result-section:nth-child(4) { animation-delay: 0.15s; }
.result-section:nth-child(5) { animation-delay: 0.2s; }
.result-section:nth-child(6) { animation-delay: 0.25s; }

.vulnerability-card {
  border: 1px solid rgba(255, 149, 0, 0.2);
  border-radius: 0px;
  padding: 16px;
  margin-bottom: 10px;
  background: #fffdf8;
  transition: border-color 0.25s cubic-bezier(0.25, 0.1, 0.25, 1), background 0.25s cubic-bezier(0.25, 0.1, 0.25, 1);
}

.vulnerability-card.high {
  border-color: rgba(255, 59, 48, 0.35);
  background: #fffaf9;
}

.vulnerability-card.medium {
  border-color: rgba(255, 149, 0, 0.2);
  background: #fffdf8;
}

.vulnerability-card.low {
  border-color: rgba(52, 199, 89, 0.2);
  background: #f8fdf9;
}

.vuln-header {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 8px;
}

.severity-badge {
  font-size: 11px;
  font-weight: 500;
  padding: 2px 8px;
  border-radius: 0px;
  color: #fff;
  flex-shrink: 0;
}

.severity-badge.high {
  background: var(--error-color);
}

.severity-badge.medium {
  background: var(--warning-color);
}

.severity-badge.low {
  background: var(--success-color);
}

.vuln-desc {
  font-size: 13px;
  color: var(--text-secondary);
  line-height: 1.5;
  margin-bottom: 6px;
}

.vuln-meta {
  display: flex;
  gap: 8px;
}

.vuln-cve,
.vuln-cvss {
  font-size: 11px;
  padding: 2px 8px;
  border: 1px solid var(--border-light);
  border-radius: 0px;
  color: var(--text-secondary);
  font-family: 'SF Mono', 'Consolas', monospace;
}

.task-result-btn {
  display: block;
  width: 100%;
  text-align: left;
  padding: 10px 12px;
  border: 1px solid var(--border-light);
  border-radius: 4px;
  background: transparent;
  cursor: pointer;
  font-size: 13px;
  color: var(--text-primary);
  margin-bottom: 4px;
  transition: all 0.2s ease;
  font-family: inherit;
}

.task-result-btn:hover {
  border-color: var(--text-primary);
  background: var(--bg-secondary, #f5f5f5);
}

.task-result-btn:active {
  transform: scale(0.98);
}

.task-modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.45);
  z-index: 999;
}

.task-modal-panel {
  position: fixed;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  background: var(--card-bg, #ffffff);
  border-radius: 12px;
  box-shadow: var(--shadow-lg, 0 8px 32px rgba(0,0,0,0.15));
  width: 650px;
  max-width: 92vw;
  max-height: 85vh;
  z-index: 1000;
  display: flex;
  flex-direction: column;
}

.task-modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 20px 28px;
  border-bottom: 1px solid var(--border-color, #e5e7eb);
  flex-shrink: 0;
}

.task-modal-header h3 {
  font-size: 16px;
  font-weight: 600;
  color: var(--text-primary);
  margin: 0;
}

.task-modal-close {
  width: 32px;
  height: 32px;
  border: none;
  background: var(--bg-color, #f5f5f5);
  border-radius: 50%;
  font-size: 20px;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--text-secondary);
  transition: background 0.2s ease, color 0.2s ease;
  line-height: 1;
  flex-shrink: 0;
}

.task-modal-close:hover {
  background: var(--text-primary);
  color: #fff;
}

.task-modal-content {
  overflow-y: auto;
  flex: 1;
  padding: 24px 28px;
}

.task-modal-report {
  background: var(--card-bg, #ffffff);
  border: 1px solid var(--border-color, #e5e7eb);
  border-radius: 8px;
  padding: 24px 28px;
}

.modal-fade-enter-active,
.modal-fade-leave-active {
  transition: opacity 0.3s ease;
}

.modal-fade-enter-from,
.modal-fade-leave-to {
  opacity: 0;
}

.modal-slide-enter-active {
  transition: opacity 0.35s cubic-bezier(0.4, 0, 0.2, 1), transform 0.35s cubic-bezier(0.4, 0, 0.2, 1);
}

.modal-slide-leave-active {
  transition: opacity 0.25s cubic-bezier(0.4, 0, 0.2, 1), transform 0.25s cubic-bezier(0.4, 0, 0.2, 1);
}

.modal-slide-enter-from {
  opacity: 0;
  transform: translate(-50%, calc(-50% - 30px));
}

.modal-slide-leave-to {
  opacity: 0;
  transform: translate(-50%, calc(-50% + 20px));
}

.markdown-body {
  font-size: 14px;
  line-height: 1.8;
  color: var(--text-primary);
  text-align: left;
}

.markdown-body :deep(h1),
.markdown-body :deep(h2),
.markdown-body :deep(h3),
.markdown-body :deep(h4) {
  color: var(--text-primary);
  margin: 16px 0 8px;
  font-weight: 600;
}

.markdown-body :deep(h1) { font-size: 20px; }
.markdown-body :deep(h2) { font-size: 18px; }
.markdown-body :deep(h3) { font-size: 16px; }

.markdown-body :deep(p) {
  margin: 8px 0;
  text-align: left;
}

.markdown-body :deep(strong) {
  font-weight: 600;
  color: var(--text-primary);
}

.markdown-body :deep(code) {
  background: #f5f5f5;
  padding: 2px 6px;
  border-radius: 4px;
  font-family: 'Consolas', 'Monaco', monospace;
  font-size: 13px;
}

.markdown-body :deep(pre) {
  background: #1e293b;
  color: #e2e8f0;
  padding: 16px;
  border-radius: 8px;
  overflow-x: auto;
  font-size: 13px;
  line-height: 1.6;
  margin: 12px 0;
}

.markdown-body :deep(pre code) {
  background: none;
  padding: 0;
  color: inherit;
}

.markdown-body :deep(blockquote) {
  border-left: 4px solid var(--primary-color, #1677ff);
  padding: 8px 16px;
  margin: 12px 0;
  background: #f8fafc;
  color: var(--text-secondary);
}

.markdown-body :deep(ul),
.markdown-body :deep(ol) {
  padding-left: 24px;
  margin: 8px 0;
}

.markdown-body :deep(li) {
  margin: 4px 0;
  text-align: left;
}

.markdown-body :deep(table) {
  width: 100%;
  border-collapse: collapse;
  margin: 12px 0;
}

.markdown-body :deep(th),
.markdown-body :deep(td) {
  border: 1px solid var(--border-color);
  padding: 8px 12px;
  text-align: left;
}

.markdown-body :deep(th) {
  background: #f5f7fa;
  font-weight: 600;
}

@media (max-width: 768px) {
  .scan-layout {
    flex-direction: column;
  }

  .scan-sidebar {
    width: 100%;
    padding: 20px;
  }

  .scan-main {
    padding: 20px;
  }

  .mode-cards {
    grid-template-columns: 1fr;
  }

  .progress-overview {
    flex-direction: column;
    align-items: flex-start;
  }

  .results-summary {
    flex-wrap: wrap;
  }

  .summary-stat {
    flex: 1 1 calc(50% - 8px);
  }

  .task-modal-panel {
    width: 95vw;
  }

  .task-modal-header {
    padding: 16px 20px;
  }

  .task-modal-content {
    padding: 16px 20px;
  }

  .task-modal-report {
    padding: 16px;
  }
}

/* === 任务轮询：中断点交互面板 === */

.poll-banner {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  margin-bottom: 12px;
  border: 1px solid var(--warning-color, #ff9500);
  background: #fffdf8;
  border-radius: 4px;
  font-size: 13px;
  color: var(--text-primary);
}

.poll-banner-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--warning-color, #ff9500);
  flex-shrink: 0;
  animation: pulse-dot 1.2s cubic-bezier(0.25, 0.1, 0.25, 1) infinite;
}

.interactive-panel {
  border: 1px solid var(--primary-color, #1677ff);
  border-radius: 6px;
  background: #f8fbff;
  padding: 20px;
  margin-bottom: 16px;
  animation: fadeInUp 0.35s cubic-bezier(0.25, 0.1, 0.25, 1);
}

.panel-header {
  margin-bottom: 16px;
}

.panel-header h4 {
  font-size: 15px;
  font-weight: 600;
  color: var(--text-primary);
  margin: 0 0 4px;
}

.panel-desc {
  font-size: 13px;
  color: var(--text-secondary);
  margin: 0;
}

.panel-desc code {
  background: #eef4ff;
  padding: 1px 6px;
  border-radius: 3px;
  font-family: 'SF Mono', 'Consolas', monospace;
  font-size: 12px;
  color: var(--primary-color, #1677ff);
}

.panel-body {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.panel-body .form-group {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.panel-body .form-group label {
  font-size: 13px;
  font-weight: 600;
  color: var(--text-primary);
}

.required-mark {
  color: var(--error-color, #ff3b30);
  margin-left: 2px;
}

.field-desc {
  font-size: 12px;
  color: var(--text-secondary);
  margin: 0 0 4px;
  line-height: 1.4;
}

.panel-body input[type="text"],
.panel-body input[type="number"],
.panel-body input[type="password"],
.panel-body textarea {
  width: 100%;
  padding: 8px 10px;
  border: 1px solid var(--border-light, #e5e7eb);
  border-radius: 4px;
  font-size: 13px;
  font-family: inherit;
  color: var(--text-primary);
  background: #fff;
  box-sizing: border-box;
  transition: border-color 0.2s ease;
}

.panel-body input:focus,
.panel-body textarea:focus {
  outline: none;
  border-color: var(--primary-color, #1677ff);
}

.panel-body textarea {
  resize: vertical;
  font-family: 'SF Mono', 'Consolas', monospace;
  line-height: 1.5;
}

.panel-body input[type="file"] {
  font-size: 12px;
}

.field-error,
.upload-status {
  margin: 4px 0 0;
  font-size: 12px;
  line-height: 1.4;
}

.field-error,
.upload-status.failed {
  color: var(--error-color, #ff3b30);
}

.upload-status {
  color: var(--text-secondary);
}

.upload-status.completed {
  color: var(--success-color, #34c759);
}

.params-title {
  font-size: 12px;
  font-weight: 600;
  color: var(--text-secondary);
  margin: 0 0 6px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.params-list {
  list-style: none;
  padding: 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.params-list li {
  font-size: 12px;
  color: var(--text-secondary);
  line-height: 1.6;
}

.params-list code {
  background: #eef4ff;
  padding: 1px 6px;
  border-radius: 3px;
  font-family: 'SF Mono', 'Consolas', monospace;
  color: var(--primary-color, #1677ff);
}

.param-type {
  color: var(--text-secondary);
  font-size: 11px;
  margin-left: 4px;
}

.param-desc {
  color: var(--text-secondary);
}

.panel-footer {
  margin-top: 16px;
  display: flex;
  justify-content: flex-end;
}

.panel-footer .primary-btn {
  padding-right: 24px;
}

.panel-footer .primary-btn::after {
  display: none;
}

.interaction-options { justify-content: flex-start; flex-wrap: wrap; gap: 10px; }
.report-toolbar { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 12px; }
.report-link { display: inline-flex; align-items: center; text-decoration: none; }
.report-preview { width: 100%; min-height: 680px; border: 1px solid var(--border-light); border-radius: 8px; background: #fff; }
.report-markdown { padding: 18px; border: 1px solid var(--border-light); border-radius: 8px; background: var(--surface-card, #fff); }
.analysis-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }
.analysis-item { display: flex; flex-direction: column; gap: 5px; padding: 12px; border-radius: 8px; background: var(--surface-muted, #f5f7fa); }
.analysis-item strong { color: var(--text-secondary); font-size: 12px; }
.analysis-item span { white-space: pre-wrap; word-break: break-word; }
</style>
