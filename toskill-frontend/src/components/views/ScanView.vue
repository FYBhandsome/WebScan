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
            <div class="task-item" v-for="(task, index) in tasks" :key="index">
              <span class="task-dot" :class="task.status"></span>
              <span class="task-name">{{ task.name }}</span>
              <span class="task-elapsed">{{ task.elapsed || 'N/A' }}</span>
              <span class="task-badge" :class="task.status">{{ badgeText(task.status) }}</span>
            </div>
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
              <div class="code-block">{{ resultsData.report }}</div>
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
import { reactive, ref, computed, onMounted, onUnmounted } from 'vue'
import { API } from '../../services/api.js'
import { ws } from '../../services/websocket.js'
import { showToast, globalState, addScanHistory, getScanHistory } from '../../store.js'
import { marked } from 'marked'

marked.setOptions({ breaks: true, gfm: true })

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
  const task = tasks.value.find(t => t.name === taskName)
  if (task && task.status !== status) {
    task.status = status
    if (status === 'completed' || status === 'error') {
      task.elapsed = formatElapsed(Date.now() - task.startTime)
      completedTasksCount.value++
    }
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

  initProgress()

  try {
    let result
    switch (form.mode) {
      case 'info': result = await API.startInfoScan(target); break
      case 'vuln': result = await API.startVulnScan(target); break
      case 'full': result = await API.startFullScan(target); break
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
    }
  } catch (error) {
    showToast('扫描启动失败: ' + error.message, 'error')
    isScanning.value = false
  }
}

const handleScanResult = (data) => {
  isScanning.value = false
  progress.value = 100
  statusText.value = '扫描完成'
  resultsData.value = data.payload || data.data || data
  showResults.value = true
  if (form.target.trim()) {
    addScanHistory(form.target.trim())
    scanHistory.value = getScanHistory()
  }
}

const cancelScan = () => {
  ws.send('cancel_scan', {})
  isScanning.value = false
  progress.value = 0
  statusText.value = '已取消'
  showToast('扫描已取消', 'warning')
}

const handleWSMessage = (data) => {
  switch (data.type) {
    case 'scan_started':
      addTask(data.payload.task_id || '初始化任务', 'running')
      progress.value = 10
      statusText.value = '扫描已启动'
      break

    case 'tool_execution_started':
      addTask(data.payload.tool_name || data.payload.tool, 'running')
      break

    case 'tool_execution_completed':
      updateTaskStatus(data.payload.tool_name || data.payload.tool, 'completed')
      break

    case 'scan_completed':
      handleScanResult(data)
      showToast('扫描完成', 'success')
      break

    case 'scan_cancelled':
      progress.value = 0
      statusText.value = '扫描已取消'
      isScanning.value = false
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

    case 'ai_decision':
      const dData = data.payload
      progress.value = Math.round(((dData.completed_tasks?.length || 0) / (dData.total_tasks || 1)) * 100)
      statusText.value = `AI决策: 下一步 ${dData.next_task}`
      break
  }
}

onMounted(() => {
  scanHistory.value = getScanHistory()
  ws.on('*', handleWSMessage)
})

onUnmounted(() => {
  ws.off('*', handleWSMessage)
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
  align-items: center;
  gap: 10px;
  padding: 8px 10px;
  border-radius: 0px;
  transition: background 0.2s cubic-bezier(0.25, 0.1, 0.25, 1);
}

.task-item:hover {
  background: var(--bg-secondary);
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
</style>