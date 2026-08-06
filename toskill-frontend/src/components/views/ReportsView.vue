<template>
  <div id="page-reports" class="page active">
    <div class="page-header">
      <h2>扫描报告</h2>
      <button class="secondary-btn" @click="fetchReports" :disabled="isLoading">
        {{ isLoading ? '刷新中...' : '刷新' }}
      </button>
    </div>

    <div class="reports-list" id="reportsList">
      <div v-if="isLoading" class="loading">加载报告列表...</div>
      <div v-else-if="errorMsg" class="error" style="color: var(--error-color); padding: 20px; text-align: center;">
        {{ errorMsg }}
      </div>
      <div v-else-if="reports.length === 0" class="loading">暂无报告</div>

      <div
        v-else
        v-for="report in reports"
        :key="report.name"
        class="report-card"
      >
        <div class="report-info">
          <h4>{{ report.name }}</h4>
          <p>大小: {{ formatSize(report.size) }} | 修改时间: {{ formatDate(report.modified_at) }}</p>
        </div>
        <div v-if="confidenceTotal(report) !== null" class="report-confidence" title="报告置信度">
          <svg viewBox="0 0 42 42" class="confidence-ring">
            <circle cx="21" cy="21" r="17" class="confidence-ring-track" />
            <circle cx="21" cy="21" r="17" class="confidence-ring-value" :style="confidenceRingStyle(report)" />
          </svg>
          <span>{{ confidenceTotal(report) }}%</span>
        </div>
        <div class="report-actions">
          <button class="action-btn" @click="openViewer(report.name)">查看</button>
          <button class="action-btn" @click="download(report.name)">下载</button>
          <button class="action-btn" style="color: var(--error-color);" @click="deleteReport(report.name)">删除</button>
        </div>
      </div>
    </div>

    <div class="report-viewer" v-show="viewer.show">
      <div class="viewer-header">
        <h3 id="reportTitle">{{ viewer.filename }}</h3>
        <div class="viewer-actions">
          <button class="viewer-icon-btn" @click="download(viewer.filename)" :disabled="viewer.isLoading" title="下载">
            <Download :size="18" />
          </button>
          <button class="viewer-icon-btn" @click="closeViewer" title="关闭">
            <X :size="18" />
          </button>
        </div>
      </div>
      <div class="viewer-content">
        <div v-if="viewer.isLoading" class="loading">加载中...</div>
        <div v-else-if="viewer.error" class="error" style="color: var(--error-color);">{{ viewer.error }}</div>
        <iframe 
          v-else-if="isHtmlReport" 
          :srcdoc="viewer.content" 
          class="html-report-frame"
          sandbox="allow-same-origin allow-scripts"
        ></iframe>
        <div v-else class="markdown-body" v-html="renderedContent"></div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { marked } from 'marked'
import { Download, X } from 'lucide-vue-next'
import { API } from '../../services/api.js'
import { showToast } from '../../store.js'

const reports = ref([])
const isLoading = ref(false)
const errorMsg = ref('')

const viewer = reactive({
  show: false,
  filename: '',
  content: '',
  isLoading: false,
  error: ''
})

const renderedContent = computed(() => {
  if (!viewer.content) return ''
  if (viewer.filename && viewer.filename.endsWith('.html')) {
    return viewer.content
  }
  return marked(viewer.content) || ''
})

const isHtmlReport = computed(() => {
  return viewer.filename && viewer.filename.endsWith('.html') && viewer.content
})

const fetchReports = async () => {
  isLoading.value = true
  errorMsg.value = ''
  try {
    const result = await API.getReports()
    reports.value = result.data?.reports || []
  } catch (error) {
    errorMsg.value = `加载失败: ${error.message}`
  } finally {
    isLoading.value = false
  }
}

onMounted(() => {
  fetchReports()
})

const openViewer = async (filename) => {
  viewer.show = true
  viewer.filename = filename
  viewer.content = ''
  viewer.error = ''
  viewer.isLoading = true

  try {
    const result = await API.getReportContent(filename)
    viewer.content = result.data?.content || result.data || ''
  } catch (error) {
    viewer.error = `加载失败: ${error.message}`
  } finally {
    viewer.isLoading = false
  }
}

const closeViewer = () => {
  viewer.show = false
  viewer.filename = ''
  viewer.content = ''
}

const download = (filename) => {
  const url = API.getReportDownloadUrl(filename)

  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.style.display = 'none'

  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)

  showToast('开始下载: ' + filename, 'success')
}

const deleteReport = async (filename) => {
  if (!window.confirm(`确定要删除报告 "${filename}" 吗？`)) {
    return
  }

  try {
    await API.deleteReport(filename)
    showToast('报告已成功删除', 'success')
    fetchReports()

    if (viewer.show && viewer.filename === filename) {
      closeViewer()
    }
  } catch (error) {
    showToast('删除失败: ' + error.message, 'error')
  }
}

const confidenceTotal = (report) => {
  const confidence = report?.confidence
  const value = confidence && typeof confidence === 'object'
    ? confidence.total
    : typeof report?.confidence_score === 'number' ? report.confidence_score : null
  if (typeof value !== 'number' || !Number.isFinite(value)) return null
  return Math.max(0, Math.min(100, Math.round(value)))
}

const confidenceRingStyle = (report) => ({
  strokeDasharray: `${confidenceTotal(report) * 1.068} 106.8`
})

const formatSize = (bytes) => {
  if (bytes == null) return '--'
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB'
  return (bytes / (1024 * 1024)).toFixed(2) + ' MB'
}

const formatDate = (dateStr) => {
  if (!dateStr) return '--'
  const date = new Date(dateStr)
  return date.toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit'
  })
}
</script>

<style scoped>
.report-viewer {
  border-radius: 8px !important;
  border: 1px solid rgba(0, 0, 0, 0.08);
  box-shadow:
    0 8px 32px rgba(0, 0, 0, 0.12),
    0 2px 8px rgba(0, 0, 0, 0.06) !important;
  background: #fafaf9;
}

.viewer-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 14px 24px;
  border-bottom: 1px solid rgba(0, 0, 0, 0.06);
}

.viewer-header h3 {
  font-size: 15px;
  font-weight: 600;
  color: var(--text-primary);
  flex: 1;
}

.viewer-actions {
  display: flex;
  align-items: center;
  gap: 4px;
  flex-shrink: 0;
}

.viewer-icon-btn {
  width: 32px;
  height: 32px;
  border: none;
  background: transparent;
  border-radius: 50%;
  color: var(--text-secondary);
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: background 0.15s, color 0.15s;
}

.viewer-icon-btn:hover {
  background: rgba(0, 0, 0, 0.06);
  color: var(--text-primary);
}

.viewer-icon-btn:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}

.viewer-icon-btn:disabled:hover {
  background: transparent;
}

.viewer-content {
  padding: 20px 28px;
  scrollbar-width: thin;
  scrollbar-color: transparent transparent;
}

.viewer-content:hover {
  scrollbar-color: rgba(0, 0, 0, 0.15) transparent;
}

.viewer-content::-webkit-scrollbar {
  width: 5px;
}

.viewer-content::-webkit-scrollbar-track {
  background: transparent;
}

.viewer-content::-webkit-scrollbar-thumb {
  background: rgba(0, 0, 0, 0.12);
  border-radius: 3px;
}

.viewer-content::-webkit-scrollbar-thumb:hover {
  background: rgba(0, 0, 0, 0.28);
}

.markdown-body {
  font-size: 14px;
  line-height: 1.85;
  color: var(--text-primary);
  word-break: break-word;
  text-align: left;
}

.markdown-body :deep(h1) {
  font-size: 1.6em;
  font-weight: 700;
  margin: 24px 0 14px;
  padding-bottom: 8px;
  border-bottom: 1px solid rgba(0, 0, 0, 0.08);
  color: var(--text-primary);
}

.markdown-body :deep(h2) {
  font-size: 1.35em;
  font-weight: 700;
  margin: 22px 0 12px;
  padding-bottom: 6px;
  border-bottom: 1px solid rgba(0, 0, 0, 0.06);
  color: var(--text-primary);
}

.markdown-body :deep(h3) {
  font-size: 1.18em;
  font-weight: 600;
  margin: 18px 0 10px;
  color: var(--text-primary);
}

.markdown-body :deep(h4) {
  font-size: 1.05em;
  font-weight: 600;
  margin: 14px 0 8px;
  color: var(--text-primary);
}

.markdown-body :deep(h5),
.markdown-body :deep(h6) {
  font-size: 0.95em;
  font-weight: 600;
  margin: 12px 0 6px;
  color: var(--text-secondary);
}

.markdown-body :deep(p) {
  margin: 0 0 12px;
}

.markdown-body :deep(ul),
.markdown-body :deep(ol) {
  margin: 0 0 14px;
  padding-left: 24px;
}

.markdown-body :deep(li) {
  margin-bottom: 4px;
}

.markdown-body :deep(li > ul),
.markdown-body :deep(li > ol) {
  margin-top: 4px;
  margin-bottom: 4px;
}

.markdown-body :deep(blockquote) {
  margin: 0 0 14px;
  padding: 10px 18px;
  border-left: 4px solid var(--accent-color);
  background: rgba(0, 122, 255, 0.04);
  color: var(--text-secondary);
  border-radius: 0 6px 6px 0;
}

.markdown-body :deep(code) {
  padding: 2px 6px;
  font-size: 0.88em;
  font-family: 'SF Mono', 'Fira Code', 'Consolas', 'Monaco', monospace;
  background: rgba(0, 0, 0, 0.06);
  border-radius: 4px;
  color: #d63384;
}

.markdown-body :deep(pre) {
  margin: 0 0 16px;
  padding: 16px 20px;
  background: #1e1e2e;
  border-radius: 8px;
  overflow-x: auto;
}

.markdown-body :deep(pre code) {
  padding: 0;
  font-size: 0.85em;
  line-height: 1.7;
  background: transparent;
  color: #cdd6f4;
  border-radius: 0;
}

.markdown-body :deep(table) {
  width: 100%;
  margin: 0 0 16px;
  border-collapse: collapse;
  border-spacing: 0;
}

.markdown-body :deep(th),
.markdown-body :deep(td) {
  padding: 10px 14px;
  border: 1px solid rgba(0, 0, 0, 0.08);
  text-align: left;
}

.markdown-body :deep(th) {
  background: rgba(0, 0, 0, 0.03);
  font-weight: 600;
  font-size: 0.92em;
}

.markdown-body :deep(tr:nth-child(even)) {
  background: rgba(0, 0, 0, 0.015);
}

.markdown-body :deep(a) {
  color: var(--accent-color);
  text-decoration: none;
}

.markdown-body :deep(a:hover) {
  text-decoration: underline;
}

.markdown-body :deep(hr) {
  margin: 24px 0;
  border: none;
  border-top: 1px solid rgba(0, 0, 0, 0.08);
}

.markdown-body :deep(img) {
  max-width: 100%;
  border-radius: 6px;
}

.markdown-body :deep(strong) {
  font-weight: 700;
  color: var(--text-primary);
}

.markdown-body :deep(em) {
  font-style: italic;
}

.markdown-body :deep(del) {
  color: var(--text-secondary);
  text-decoration: line-through;
}

.markdown-body :deep(input[type="checkbox"]) {
  margin-right: 6px;
  accent-color: var(--accent-color);
}

.report-card {
  background: #FAFAFA !important;
  border: 1px solid #EDEDED;
}

.report-confidence {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-left: auto;
  color: var(--text-secondary);
  font-size: 13px;
  font-weight: 600;
}

.confidence-ring {
  width: 34px;
  height: 34px;
  transform: rotate(-90deg);
}

.confidence-ring-track,
.confidence-ring-value {
  fill: none;
  stroke-width: 4;
}

.confidence-ring-track {
  stroke: rgba(22, 160, 133, 0.16);
}

.confidence-ring-value {
  stroke: #16a085;
  stroke-linecap: round;
}

.html-report-frame {
  width: 100%;
  height: 80vh;
  border: none;
  border-radius: 8px;
  background: white;
}
</style>