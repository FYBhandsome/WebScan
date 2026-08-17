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
              placeholder="例如: example.com、192.168.1.10 或 https://example.com"
              @keydown.enter="startScan"
            >
          </div>
          <div class="form-group">
            <label>扫描模式</label>
            <select id="scanMode" v-model="form.mode">
              <option value="info">信息收集</option>
              <option value="vuln">漏洞扫描</option>
              <option value="full">完整扫描</option>
            </select>
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
          <div class="progress-header">
            <span class="progress-title">{{ statusText }}</span>
            <span class="progress-status">{{ Math.round(progress) }}%</span>
          </div>
          <div class="progress-bar">
            <div class="progress-fill" :style="{ width: `${progress}%` }"></div>
          </div>
          <div class="current-tool-progress" v-if="currentTool || currentToolProgress">
            <strong>{{ currentTool || '工具' }}</strong>
            <span>{{ currentToolProgress || '执行中...' }}</span>
          </div>
          <div class="task-list" id="taskList">
            <button
              type="button"
              class="task-item"
              v-for="task in tasks"
              :key="task.name"
              :class="{ clickable: canOpenTaskResult(task) }"
              :disabled="!canOpenTaskResult(task)"
              :title="canOpenTaskResult(task) ? '查看扫描结果' : ''"
              @click="openTaskResultModal(task.name)"
            >
              <span class="task-dot" :class="task.status"></span>
              <span class="task-name">{{ task.name }}</span>
              <span class="task-badge" :class="task.status">{{ badgeText(task.status) }}</span>
              <span v-if="canOpenTaskResult(task)" class="task-result-action">查看结果</span>
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
            <div class="summary-stat info" v-if="informationResults.length > 0">
              <span class="stat-number">{{ informationResults.length }}</span>
              <span class="stat-label">已收集信息</span>
            </div>
            <div class="summary-stat" v-if="showVulnerabilityResults" :class="{ warning: logicalVulnerabilityCount > 0 }">
              <span class="stat-number">{{ rawVulnerabilityCount }}</span>
              <span class="stat-label">原始扫描命中</span>
            </div>
            <div class="summary-stat" v-if="showVulnerabilityResults" :class="{ warning: logicalVulnerabilityCount > 0 }">
              <span class="stat-number">{{ logicalVulnerabilityCount }}</span>
              <span class="stat-label">归并后安全问题</span>
            </div>
            <div class="summary-stat" v-if="showVulnerabilityResults" :class="{ warning: verifiedVulnerabilityCount > 0 }">
              <span class="stat-number">{{ verifiedVulnerabilityCount }}</span>
              <span class="stat-label">已验证问题</span>
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

            <div class="result-section" v-if="resultsData.errors?.length > 0">
              <h4>错误信息</h4>
              <div class="result-item" v-for="(err, i) in resultsData.errors" :key="i" style="color: var(--error-color);">
                {{ err }}
              </div>
            </div>

            <section v-if="hasReportLinks" class="report-entry-section" aria-label="扫描报告">
              <div>
                <h4>扫描报告已生成</h4>
                <p>完整报告已保存至报告页面，可按格式查看或下载。</p>
              </div>
              <div class="report-entry-actions">
                <button
                  v-if="htmlReportFilename"
                  type="button"
                  class="report-entry-btn primary"
                  @click="openReport(resultsData.html_report_url)"
                >查看 HTML 报告</button>
                <button
                  v-if="markdownReportFilename"
                  type="button"
                  class="report-entry-btn secondary"
                  @click="openReport(resultsData.report_url)"
                >查看 Markdown 报告</button>
              </div>
            </section>

            <div class="result-section" v-if="isResultEmpty()">
              <p>{{ emptyResultMessage }}</p>
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
          <h3>执行总结: {{ taskModal.title }}</h3>
          <button class="task-modal-close" @click="closeTaskResultModal">&times;</button>
        </div>
        <div class="task-modal-content">
          <dl class="task-summary-list">
            <div v-for="field in taskModal.items" :key="field.label">
              <dt>{{ field.label }}</dt>
              <dd>{{ field.value }}</dd>
            </div>
          </dl>
        </div>
      </div>
    </Transition>
  </div>
</template>

<script setup>
import { reactive, ref, computed, watch, onMounted, onUnmounted } from 'vue'
import { ws } from '../../services/websocket.js'
import { storageService } from '../../services/storageService.js'
import { showToast, globalState, addScanHistory, getScanHistory } from '../../store.js'

const scanModes = [
  { value: 'info', name: '信息收集', desc: 'WHOIS、DNS、子域名、端口扫描等基础信息', badge: '轻量·快速' },
  { value: 'vuln', name: '漏洞扫描', desc: 'XSS、SQL注入、CSRF等常见Web漏洞检测', badge: '中等·约3-5分钟' },
  { value: 'full', name: '完整扫描', desc: '信息收集+漏洞扫描+AI决策链条', badge: '深度·约5-10分钟' },
]

const form = reactive({ target: '', mode: 'info' })
const isScanning = ref(false)
const progress = ref(0)
const statusText = ref('准备中...')
const showResults = ref(false)
const tasks = ref([])
const completedTasksCount = ref(0)
const totalTasksCount = ref(0)
const resultsData = ref({})
const scanHistory = ref([])
const currentTool = ref('')
const currentToolProgress = ref('')
const activeRunId = ref('')
const cancelRequested = ref(false)
let persistTimer = null
const emit = defineEmits(['open-report'])

const selectedReportType = computed(() => {
  if (resultsData.value.report_type) return resultsData.value.report_type
  return { info: 'info_collection', vuln: 'vuln_scan', full: 'full_scan' }[form.mode] || 'info_collection'
})

const informationResults = computed(() => Array.isArray(resultsData.value.information_results)
  ? resultsData.value.information_results
  : [])

const htmlReportFilename = computed(() => extractReportFilename(resultsData.value.html_report_url))
const markdownReportFilename = computed(() => extractReportFilename(resultsData.value.report_url))
const hasReportLinks = computed(() => Boolean(htmlReportFilename.value || markdownReportFilename.value))

const showVulnerabilityResults = computed(() => selectedReportType.value !== 'info_collection')

const logicalVulnerabilityCount = computed(() => Number(
  resultsData.value.vulnerabilities_count ?? resultsData.value.vulnerabilities?.length ?? 0
))

const rawVulnerabilityCount = computed(() => Number(
  resultsData.value.raw_vulnerabilities_count ?? logicalVulnerabilityCount.value
))

const verifiedVulnerabilityCount = computed(() => Number(
  resultsData.value.verified_vulnerabilities_count ?? 0
))

const emptyResultMessage = computed(() => selectedReportType.value === 'info_collection'
  ? '信息收集已完成，工具未返回可展示的信息。'
  : '扫描完成，未产生需要复核的安全告警。')

const taskModal = reactive({
  show: false,
  taskName: '',
  title: '',
  items: []
})

const restoreScanState = () => {
  const saved = storageService.getScanState()
  if (!saved) return

  // TTL 校验：超过 24 小时的数据视为过期
  const SCAN_TTL = 24 * 60 * 60 * 1000
  const savedAt = saved.savedAt ? new Date(saved.savedAt).getTime() : 0
  if (savedAt && Date.now() - savedAt > SCAN_TTL) {
    storageService.remove('scan_workspace')
    return
  }

  form.target = saved.form?.target || ''
  form.mode = saved.form?.mode || 'info'
  // isScanning 不再持久化恢复，始终初始化为 false，依赖后端 get_status 同步
  isScanning.value = false
  progress.value = Number(saved.progress) || 0
  statusText.value = saved.statusText || '准备中...'
  showResults.value = Boolean(saved.showResults)
  tasks.value = Array.isArray(saved.tasks) ? saved.tasks : []
  completedTasksCount.value = Number(saved.completedTasksCount) || 0
  totalTasksCount.value = Number(saved.totalTasksCount) || 0
  resultsData.value = saved.resultsData || {}
  if (form.target) globalState.currentTarget = form.target
}

const persistScanState = () => {
  storageService.saveScanState({
    sessionId: ws.getSessionId() || storageService.getActiveSessionId(),
    form: { ...form },
    // isScanning 不再持久化，避免刷新后误显示"扫描中"
    progress: progress.value,
    statusText: statusText.value,
    showResults: showResults.value,
    tasks: tasks.value,
    completedTasksCount: completedTasksCount.value,
    totalTasksCount: totalTasksCount.value,
    resultsData: resultsData.value
  })
}

const scheduleScanPersist = () => {
  if (persistTimer) clearTimeout(persistTimer)
  persistTimer = setTimeout(persistScanState, 200)
}

restoreScanState()

const circumference = 2 * Math.PI * 34
const ringOffset = computed(() => circumference * (1 - progress.value / 100))

const badgeText = (status) => {
  switch (status) {
    case 'pending': return '等待中'
    case 'running': return '执行中'
    case 'completed': return '已完成'
    case 'not_applicable': return '不适用'
    case 'skipped': return '已跳过'
    case 'error': return '失败'
    default: return status
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
  return !(Object.keys(d.tool_results || {}).length || d.information_results?.length || d.vulnerabilities?.length || d.report || d.html_report_url || d.errors?.length)
}

const upsertInformationResult = (tool, items = []) => {
  if (!tool || !Array.isArray(items) || items.length === 0) return
  const current = Array.isArray(resultsData.value.information_results)
    ? [...resultsData.value.information_results]
    : []
  const next = {
    tool,
    title: formatTaskName(tool),
    items
  }
  const index = current.findIndex(item => item.tool === tool)
  if (index >= 0) current.splice(index, 1, next)
  else current.push(next)
  resultsData.value.information_results = current
}

const openTaskResultModal = (taskName) => {
  const summary = informationResults.value.find(item => item.tool === taskName)
  if (!summary) return
  taskModal.taskName = taskName
  taskModal.title = summary.title || formatTaskName(taskName)
  taskModal.items = Array.isArray(summary.items) ? summary.items : []
  taskModal.show = true
}

const canOpenTaskResult = (task) => {
  if (!showResults.value || !['completed', 'not_applicable'].includes(task?.status) || !task?.name) return false
  return informationResults.value.some(item => item.tool === task.name && item.items?.length)
}

const closeTaskResultModal = () => {
  taskModal.show = false
  taskModal.taskName = ''
  taskModal.title = ''
  taskModal.items = []
}

const formatTaskName = (name) => {
  if (!name) return ''
  return name.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

const formatElapsed = (ms) => {
  // Date.now() has millisecond resolution, so very fast tools can otherwise
  // be rounded down to the misleading value "0ms".  A completed tool always
  // took at least one measurable millisecond from the UI's perspective.
  const elapsed = Math.max(1, Math.round(Number(ms) || 0))
  if (elapsed < 1000) return elapsed + 'ms'
  return (elapsed / 1000).toFixed(1) + 's'
}

const initProgress = () => {
  isScanning.value = true
  cancelRequested.value = false
  showResults.value = false
  progress.value = 0
  statusText.value = '正在初始化扫描...'
  tasks.value = []
  completedTasksCount.value = 0
  totalTasksCount.value = 0
  resultsData.value = {}
  currentTool.value = ''
  currentToolProgress.value = ''
  activeRunId.value = ''
}

const addTask = (taskName, status = 'pending') => {
  if (!taskName) return null
  const existing = tasks.value.find(t => t.name === taskName)
  if (existing) {
    if (status && status !== 'pending' && (existing.status === 'pending' || existing.status === 'error')) {
      existing.status = status
      if (status === 'running') existing.startTime = Date.now()
    }
    return existing
  }
  const task = { name: taskName, status, startTime: Date.now(), elapsed: null, message: '', counted: false }
  tasks.value.push(task)
  totalTasksCount.value++
  return task
}

const updateTaskStatus = (taskName, status, durationMs = null) => {
  const task = tasks.value.find(t => t.name === taskName) || addTask(taskName, status)
  if (task && task.status !== status) {
    task.status = status
    if (['completed', 'not_applicable', 'skipped', 'error'].includes(status)) {
      const measuredDuration = Number(durationMs)
      task.elapsed = formatElapsed(
        Number.isFinite(measuredDuration) && measuredDuration >= 0
          ? measuredDuration
          : Date.now() - task.startTime
      )
      if (!task.counted) {
        task.counted = true
        completedTasksCount.value++
      }
    }
    const pct = Math.round((completedTasksCount.value / (totalTasksCount.value || 1)) * 80)
    progress.value = Math.max(progress.value, pct)
    statusText.value = `已完成 ${completedTasksCount.value}/${totalTasksCount.value} 任务`
  }
}

const payloadDurationMs = (payload) => {
  if (!payload || typeof payload !== 'object') return null
  if (payload.duration_ms !== undefined) return Number(payload.duration_ms)
  if (payload.execution_time !== undefined) return Number(payload.execution_time) * 1000
  // Task executor completion events expose `duration` in seconds.
  if (payload.duration !== undefined) return Number(payload.duration) * 1000
  // Some tool events put the measured execution time inside the raw result.
  const result = payload.raw_result || payload.result
  if (result && typeof result === 'object' && result.execution_time !== undefined) {
    return Number(result.execution_time) * 1000
  }
  return null
}

const taskDurationMs = (state, taskName) => {
  return Number(state?.task_metadata?.[taskName]?.duration_ms)
}

const payloadOf = (data) => data?.payload || {}

const isAutomaticEvent = (data) => {
  const payload = payloadOf(data)
  const runType = payload.run_type || payload.state?.run_type || payload.details?.run_type
  if (runType) return runType === 'automatic'
  return Boolean(activeRunId.value && payload.run_id === activeRunId.value)
}

const extractReportFilename = (reportUrl) => {
  if (!reportUrl) return ''
  try {
    const pathname = new URL(reportUrl, window.location.origin).pathname
    return decodeURIComponent(pathname.split('/').filter(Boolean).pop() || '')
  } catch (error) {
    return decodeURIComponent(String(reportUrl).split('/').pop() || '')
  }
}

const mergeResultPayload = (data) => {
  const payload = data?.payload || data?.data || data || {}
  resultsData.value = { ...resultsData.value, ...payload }
  return payload
}

const openReport = (reportUrl) => {
  const filename = extractReportFilename(reportUrl)
  if (filename) emit('open-report', filename)
}

const handleScanResult = (data) => {
  const payload = mergeResultPayload(data)
  ;(payload.completed_tasks || []).forEach(task => {
    const status = payload.task_metadata?.[task]?.status === 'not_applicable' ? 'not_applicable' : 'completed'
    updateTaskStatus(task, status, taskDurationMs(payload, task))
  })
  isScanning.value = false
  cancelRequested.value = false
  progress.value = 100
  statusText.value = '扫描完成'
  showResults.value = true
  const historyTarget = payload.target || form.target.trim()
  if (historyTarget) {
    form.target = historyTarget
    globalState.currentTarget = historyTarget
    addScanHistory(historyTarget)
    scanHistory.value = getScanHistory()
  }
}

const handleScanCancelled = (data) => {
  const payload = mergeResultPayload(data)
  isScanning.value = false
  cancelRequested.value = false
  progress.value = Number(payload.progress ?? progress.value) || 0
  statusText.value = '扫描已取消'
  showResults.value = Boolean(
    payload.completed_tasks?.length ||
    Object.keys(payload.tool_results || {}).length ||
    payload.vulnerabilities?.length ||
    payload.errors?.length
  )
  showToast('扫描已取消', 'warning')
}

const applyRunState = (state) => {
  if (!state || state.run_type !== 'automatic') return
  if (state.run_id) activeRunId.value = state.run_id
  if (state.target) {
    form.target = state.target
    globalState.currentTarget = state.target
  }
  const modeMap = { info_collection: 'info', vuln_scan: 'vuln', full_scan: 'full' }
  if (state.mode && modeMap[state.mode]) form.mode = modeMap[state.mode]

  tasks.value = []
  ;(state.planned_tasks || []).forEach(task => addTask(task, 'pending'))
  ;(state.completed_tasks || []).forEach(task => {
    const status = state.task_metadata?.[task]?.status === 'not_applicable' ? 'not_applicable' : 'completed'
    updateTaskStatus(task, status, taskDurationMs(state, task))
  })
  ;(state.failed_tasks || []).forEach(task => {
    updateTaskStatus(task, 'error', taskDurationMs(state, task))
  })
  currentTool.value = state.current_tool || state.current_task || ''
  progress.value = Number(state.progress) || progress.value
  resultsData.value = {
    ...resultsData.value,
    target: state.target || resultsData.value.target,
    completed_tasks: state.completed_tasks || [],
    failed_tasks: state.failed_tasks || [],
    tool_results: state.tool_results || {},
    information_results: state.information_results || resultsData.value.information_results || [],
    vulnerabilities: state.vulnerabilities || [],
    vulnerabilities_count: state.vulnerabilities_count ?? resultsData.value.vulnerabilities_count,
    raw_vulnerabilities_count: state.raw_vulnerabilities_count ?? resultsData.value.raw_vulnerabilities_count,
    verified_vulnerabilities_count: state.verified_vulnerabilities_count ?? resultsData.value.verified_vulnerabilities_count,
    report_type: state.report_type || resultsData.value.report_type || '',
    errors: state.errors || [],
    report: state.report || resultsData.value.report || '',
    report_url: state.report_url || resultsData.value.report_url || '',
    report_id: state.report_id || resultsData.value.report_id || '',
    html_report_url: state.html_report_url || resultsData.value.html_report_url || ''
  }
  if (state.cancelled || state.scan_status === 'cancelled') {
    handleScanCancelled({ payload: resultsData.value })
  } else if (state.is_complete) {
    handleScanResult({ payload: resultsData.value })
  } else if (state.target) {
    isScanning.value = true
    statusText.value = `正在扫描 ${currentTool.value || '准备执行工具'}...`
  }
}

const startScan = async () => {
  const target = form.target.trim()
  if (!target) {
    showToast('请输入扫描目标', 'warning')
    return
  }

  initProgress()
  globalState.currentTarget = target

  try {
    if (!ws.isConnected()) await ws.connect()
    if (!ws.startAutoScan(target, form.mode)) {
      throw new Error('WebSocket 未连接')
    }
    statusText.value = '扫描请求已发送，等待工具启动...'
  } catch (error) {
    showToast('扫描启动失败: ' + error.message, 'error')
    isScanning.value = false
  }
}

const cancelScan = () => {
  if (!isScanning.value || cancelRequested.value) return
  if (!ws.sendStopScan()) {
    showToast('取消请求发送失败，请检查 WebSocket 连接', 'error')
    return
  }
  cancelRequested.value = true
  statusText.value = '正在取消扫描...'
}

const handleWSMessage = (data) => {
  if (!data || !isAutomaticEvent(data)) return
  const payload = payloadOf(data)

  switch (data.type) {
    case 'scan_started':
      if (payload.run_id) activeRunId.value = payload.run_id
      progress.value = Math.max(progress.value, 2)
      statusText.value = '扫描已启动'
      break

    case 'scan_flow_started':
      if (payload.run_id) activeRunId.value = payload.run_id
      tasks.value = []
      ;(payload.planned_tasks || []).forEach(task => addTask(task, 'pending'))
      progress.value = Math.max(progress.value, 5)
      statusText.value = `已准备 ${payload.total_tasks || tasks.value.length} 个工具`
      break

    case 'task_started': {
      const tool = payload.tool || payload.tool_name
      currentTool.value = tool || ''
      currentToolProgress.value = ''
      addTask(tool, 'running')
      statusText.value = `正在执行: ${tool}`
      break
    }

    case 'tool_execution_started':
      addTask(payload.tool_name || payload.tool, 'running')
      break

    case 'tool_progress': {
      const tool = payload.tool || payload.tool_name
      const task = addTask(tool, 'running')
      if (task) task.message = payload.message || ''
      currentTool.value = tool || currentTool.value
      currentToolProgress.value = payload.message || ''
      statusText.value = tool ? `${tool}: ${payload.message || '执行中'}` : (payload.message || '工具执行中')
      break
    }

    case 'task_completed':
    case 'tool_execution_completed':
      {
        const toolName = payload.tool_name || payload.tool
        const toolResult = payload.raw_result ?? payload.result
        const completedStatus = payload.result_status === 'not_applicable' ? 'not_applicable' : 'completed'
        updateTaskStatus(toolName, completedStatus, payloadDurationMs(payload))
        if (toolName && toolResult !== undefined) {
          resultsData.value.tool_results = { ...(resultsData.value.tool_results || {}), [toolName]: toolResult }
        }
        if (payload.tool_category === 'info_collection') {
          upsertInformationResult(toolName, payload.information_summary)
        }
      }
      break

    case 'task_skipped':
      updateTaskStatus(payload.tool, 'skipped')
      showToast('任务跳过: ' + (payload.reason || ''), 'warning')
      break

    case 'task_error':
      updateTaskStatus(payload.tool, 'error')
      resultsData.value.errors = [...(resultsData.value.errors || []), payload.error || '工具执行失败']
      showToast('任务失败: ' + (payload.error || ''), 'error')
      break

    case 'workflow_progress':
      if (payload.progress_percent !== undefined) {
        progress.value = Math.max(progress.value, Number(payload.progress_percent) || 0)
        statusText.value = `${payload.stage || '扫描中'} - ${payload.completed || 0}/${payload.total || 0}`
      }
      break

    case 'report_generation_started':
      progress.value = Math.max(progress.value, 85)
      statusText.value = '正在生成扫描报告...'
      break

    case 'report_generated':
      mergeResultPayload(data)
      progress.value = Math.max(progress.value, 95)
      statusText.value = '扫描报告已生成'
      break

    case 'report_error': {
      const reportError = payload.error || '扫描报告生成失败'
      statusText.value = '报告生成失败'
      showToast(reportError, 'error')
      break
    }

    case 'scan_completed':
      handleScanResult(data)
      showToast('扫描完成', 'success')
      break

    case 'scan_cancelled':
      handleScanCancelled(data)
      break

    case 'run_snapshot':
      applyRunState(payload)
      break

    case 'status':
      applyRunState(payload.state)
      break

    case 'error': {
      const message = payload.message || payload.error || '未知错误'
      isScanning.value = false
      cancelRequested.value = false
      statusText.value = '扫描失败'
      showToast('扫描错误: ' + message, 'error')
      break
    }
  }
}

watch(
  [form, isScanning, progress, statusText, showResults, tasks, resultsData],
  scheduleScanPersist,
  { deep: true }
)

onMounted(() => {
  scanHistory.value = getScanHistory()
  ws.on('*', handleWSMessage)
  const ready = ws.isConnected() ? Promise.resolve() : ws.connect()
  ready
    .then(() => ws.sendGetStatus())
    .catch(() => {})
})

onUnmounted(() => {
  ws.off('*', handleWSMessage)
  if (persistTimer) clearTimeout(persistTimer)
  persistScanState()
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

.progress-header {
  width: 60%;
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin: 0 auto 8px;
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
  width: 60%;
  height: 4px;
  background: var(--border-light);
  border-radius: 2px;
  overflow: hidden;
  margin: 0 auto 16px;
}

.progress-fill {
  height: 100%;
  background: var(--text-primary);
  border-radius: 2px;
  transition: width 0.35s cubic-bezier(0.25, 0.1, 0.25, 1);
}

.current-tool-progress {
  display: flex;
  align-items: baseline;
  gap: 8px;
  min-height: 22px;
  margin: -4px 0 12px;
  padding: 8px 10px;
  background: var(--bg-secondary, #f5f5f5);
  color: var(--text-secondary);
  font-size: 12px;
  overflow: hidden;
}

.current-tool-progress strong {
  color: var(--text-primary);
  flex-shrink: 0;
}

.current-tool-progress span {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.task-list {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.task-item {
  width: 100%;
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 10px;
  border: 0;
  border-radius: 0px;
  background: transparent;
  color: inherit;
  font: inherit;
  text-align: left;
  transition: background 0.2s cubic-bezier(0.25, 0.1, 0.25, 1);
}

.task-item.clickable {
  cursor: pointer;
}

.task-item.clickable:hover,
.task-item.clickable:focus-visible {
  background: var(--bg-secondary);
}

.task-item.clickable:focus-visible {
  outline: 1px solid var(--text-primary);
  outline-offset: -1px;
}

.task-item:disabled {
  cursor: default;
  opacity: 1;
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

.task-dot.not_applicable,
.task-dot.skipped {
  background: var(--text-secondary);
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

.task-badge.not_applicable,
.task-badge.skipped {
  color: var(--text-secondary);
  border: 1px solid var(--border-light);
}

.task-badge.error {
  color: var(--error-color);
  border: 1px solid var(--error-color);
}

.task-result-action {
  color: var(--primary-color, #047857);
  font-size: 12px;
  flex-shrink: 0;
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

.summary-stat.info {
  border-color: rgba(4, 120, 87, 0.35);
}

.summary-stat.info .stat-number {
  color: var(--primary-color, #047857);
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

.report-entry-section {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 20px;
  margin-top: 20px;
  padding: 20px;
  border: 1px solid color-mix(in srgb, var(--primary-color, #047857) 28%, transparent);
  background: color-mix(in srgb, var(--primary-color, #047857) 5%, #fff);
}

.report-entry-section h4 {
  margin: 0 0 6px;
  color: var(--text-primary);
  font-size: 15px;
}

.report-entry-section p {
  margin: 0;
  color: var(--text-secondary);
  font-size: 13px;
}

.report-entry-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  flex-shrink: 0;
}

.report-entry-btn {
  min-height: 36px;
  padding: 0 14px;
  border: 1px solid var(--primary-color, #047857);
  border-radius: 0;
  cursor: pointer;
  font-size: 13px;
  font-weight: 600;
  transition: background 0.2s ease, color 0.2s ease, border-color 0.2s ease;
}

.report-entry-btn.primary {
  background: var(--primary-color, #047857);
  color: #fff;
}

.report-entry-btn.primary:hover {
  background: color-mix(in srgb, var(--primary-color, #047857) 86%, #000);
}

.report-entry-btn.secondary {
  background: transparent;
  color: var(--primary-color, #047857);
}

.report-entry-btn.secondary:hover {
  background: color-mix(in srgb, var(--primary-color, #047857) 10%, transparent);
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

.task-summary-list {
  background: var(--card-bg, #ffffff);
  border: 1px solid var(--border-color, #e5e7eb);
  border-radius: 8px;
  margin: 0;
  padding: 12px 20px;
}

.task-summary-list > div {
  display: grid;
  grid-template-columns: minmax(100px, 0.32fr) minmax(0, 1fr);
  gap: 16px;
  padding: 13px 0;
  border-top: 1px dashed var(--border-light);
}

.task-summary-list > div:first-child {
  border-top: 0;
}

.task-summary-list dt {
  color: var(--text-secondary);
  font-size: 13px;
}

.task-summary-list dd {
  margin: 0;
  color: var(--text-primary);
  font-size: 14px;
  line-height: 1.6;
  overflow-wrap: anywhere;
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
  border-left: 4px solid var(--primary-color, #047857);
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

  .progress-header {
    width: 100%;
  }

  .progress-bar {
    width: 100%;
  }

  .results-summary {
    flex-wrap: wrap;
  }

  .summary-stat {
    flex: 1 1 calc(50% - 8px);
  }

  .report-entry-section {
    align-items: flex-start;
    flex-direction: column;
  }

  .report-entry-actions {
    width: 100%;
  }

  .report-entry-btn {
    flex: 1 1 180px;
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

  .task-summary-list {
    padding: 10px 16px;
  }

  .task-summary-list > div {
    grid-template-columns: 1fr;
    gap: 4px;
    padding: 11px 0;
  }
}

</style>
