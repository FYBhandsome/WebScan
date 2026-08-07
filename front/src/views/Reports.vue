<template>
  <div class="reports">
    <div class="page-header">
      <h1>报告生成</h1>
      <p class="page-subtitle">生成和管理安全扫描报告</p>
    </div>

    <div class="report-generator">
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">生成新报告</h3>
        </div>
        <div class="generator-content">
          <div class="form-section">
            <div class="form-group">
              <label class="form-label">选择扫描任务</label>
              <select v-model="selectedTask" class="form-select" :disabled="loadingTasks">
                <option value="">请选择扫描任务</option>
                <option v-for="task in scanTasks" :key="task.id" :value="task.id">
                  {{ task.task_name }} - {{ task.target }}
                </option>
              </select>
              <span v-if="loadingTasks" class="form-hint">加载中...</span>
            </div>
            
            <div class="form-group">
              <label class="form-label">报告格式</label>
              <div class="format-tabs">
                <button 
                  v-for="format in reportFormats" 
                  :key="format.value"
                  @click="selectedFormat = format.value"
                  :class="['format-tab', { 'active': selectedFormat === format.value }]"
                >
                  <span class="format-icon">{{ format.icon }}</span>
                  <span class="format-name">{{ format.name }}</span>
                </button>
              </div>
            </div>
            
            <div class="form-group">
              <label class="form-label">报告内容</label>
              <div class="content-options">
                <label v-for="option in contentOptions" :key="option.value" class="checkbox-label">
                  <input 
                    v-model="selectedContent" 
                    type="checkbox" 
                    :value="option.value"
                    class="checkbox-input"
                  >
                  <span class="checkbox-custom"></span>
                  <span>{{ option.label }}</span>
                </label>
              </div>
            </div>
          </div>
          
          <div class="generator-actions">
            <button @click="generateReport" class="btn btn-success" :disabled="!canGenerate || generating">
              <span v-if="generating">⏳ 生成中...</span>
              <span v-else>📄 生成报告</span>
            </button>
          </div>
        </div>
      </div>
    </div>

    <div class="report-history">
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">历史报告</h3>
          <div class="history-filters">
            <select v-model="historyFilter" class="form-select">
              <option value="">全部报告</option>
              <option value="html">HTML报告</option>
              <option value="pdf">PDF报告</option>
              <option value="json">JSON报告</option>
            </select>
          </div>
        </div>
        
        <div v-if="loadingReports" class="loading-state">
          <div class="loading-spinner"></div>
          <div class="loading-text">加载报告列表...</div>
        </div>
        
        <div v-else class="history-list">
          <div 
            v-for="report in filteredReports" 
            :key="report.id"
            class="report-item"
          >
            <div class="report-info">
              <div class="report-name">{{ report.report_name }}</div>
              <div class="report-meta">
                <span class="report-task">{{ report.task_name }}</span>
                <span class="report-date">{{ formatDate(report.created_at) }}</span>
              </div>
            </div>
            
            <div class="report-format">
              <span :class="['format-badge', `format-${report.report_type}`]">
                {{ (report.report_type || '').toUpperCase() }}
              </span>
            </div>
            
            <div class="report-size">
              {{ formatFileSize(report.size) }}
            </div>
            
            <div class="report-actions">
              <button @click="downloadReport(report)" class="btn-icon" title="下载" :disabled="downloading === report.id">
                <span v-if="downloading === report.id">⏳</span>
                <span v-else>📥</span>
              </button>
              <button @click="viewReport(report)" class="btn-icon" title="预览">
                👁️
              </button>
              <button @click="deleteReport(report.id)" class="btn-icon btn-danger" title="删除" :disabled="deleting === report.id">
                <span v-if="deleting === report.id">⏳</span>
                <span v-else>🗑️</span>
              </button>
            </div>
          </div>
        </div>
        
        <div v-if="!filteredReports || filteredReports.length === 0" class="empty-state">
          <div class="empty-icon">📋</div>
          <div class="empty-title">暂无报告</div>
          <div class="empty-description">生成第一个安全扫描报告</div>
        </div>
      </div>
    </div>

    <Alert
      v-if="errorMessage"
      type="error"
      :message="errorMessage"
      @close="errorMessage = ''"
    />

    <Alert
      v-if="successMessage"
      type="success"
      :message="successMessage"
      @close="successMessage = ''"
    />
  </div>
</template>

<script>
import { ref, onMounted, onUnmounted, computed } from 'vue'
import { useRouter } from 'vue-router'
import { reportsApi, tasksApi } from '@/utils/api'
import Alert from '@/components/common/Alert.vue'
import { formatDate } from '@/utils/date'

export default {
  name: 'ReportsPage',
  components: {
    Alert
  },
  setup() {
    const router = useRouter()
    const errorMessage = ref('')
    const successMessage = ref('')
    const scanTasks = ref([])
    const reports = ref([])
    const selectedTask = ref('')
    const selectedFormat = ref('html')
    const selectedContent = ref(['summary', 'vulnerabilities'])
    const historyFilter = ref('')
    const loadingTasks = ref(false)
    const loadingReports = ref(false)
    const generating = ref(false)
    const downloading = ref(null)
    const deleting = ref(null)
    const scanReportListener = ref(null)

    const reportFormats = [
      { value: 'html', name: 'HTML', icon: '🌐' },
      { value: 'pdf', name: 'PDF', icon: '📄' },
      { value: 'json', name: 'JSON', icon: '📊' }
    ]

    const contentOptions = [
      { value: 'summary', label: '扫描摘要' },
      { value: 'vulnerabilities', label: '漏洞详情' },
      { value: 'recommendations', label: '修复建议' },
      { value: 'charts', label: '统计图表' },
      { value: 'appendix', label: '技术附录' }
    ]

    const canGenerate = computed(() => {
      return selectedTask.value && selectedFormat.value && selectedContent.value && selectedContent.value.length > 0
    })

    const filteredReports = computed(() => {
      if (!historyFilter.value) return reports.value || []
      return (reports.value || []).filter(report => report.report_type === historyFilter.value)
    })

    const fetchTasks = async () => {
      loadingTasks.value = true
      try {
        const response = await tasksApi.getTasks()
        if (response.code === 200 && response.data && response.data.tasks) {
          scanTasks.value = response.data.tasks
        } else if (Array.isArray(response.data)) {
          scanTasks.value = response.data
        } else {
          scanTasks.value = []
        }
      } catch (error) {
        console.error('获取任务列表失败:', error)
        scanTasks.value = []
      } finally {
        loadingTasks.value = false
      }
    }

    const fetchReports = async () => {
      loadingReports.value = true
      try {
        const response = await reportsApi.getReports()
        if (response.code === 200 && response.data && response.data.reports) {
          reports.value = response.data.reports
        } else {
          reports.value = response.data || []
        }
      } catch (error) {
        console.error('获取报告列表失败:', error)
        reports.value = []
      } finally {
        loadingReports.value = false
      }
    }

    const bindReportRefresh = () => {
      if (typeof window === 'undefined') return
      scanReportListener.value = () => {
        fetchReports()
      }
      window.addEventListener('ai-websocket:scan-completed', scanReportListener.value)
      window.addEventListener('ai-websocket:report-ready', scanReportListener.value)
    }

    const unbindReportRefresh = () => {
      if (typeof window === 'undefined' || !scanReportListener.value) return
      window.removeEventListener('ai-websocket:scan-completed', scanReportListener.value)
      window.removeEventListener('ai-websocket:report-ready', scanReportListener.value)
      scanReportListener.value = null
    }

    const generateReport = async () => {
      if (!canGenerate.value) return
      
      const task = scanTasks.value.find(t => t.id == selectedTask.value)
      if (!task) return
      
      generating.value = true
      try {
        const reportData = {
          task_id: task.id,
          format: selectedFormat.value,
          name: `${task.task_name}报告`,
          include_summary: selectedContent.value.includes('summary'),
          include_vulnerabilities: selectedContent.value.includes('vulnerabilities'),
          include_recommendations: selectedContent.value.includes('recommendations'),
          include_charts: selectedContent.value.includes('charts'),
          include_appendix: selectedContent.value.includes('appendix')
        }
        
        const response = await reportsApi.createReport(reportData)
        if (response.code === 200) {
          successMessage.value = '报告生成成功！'
          await fetchReports()
        } else {
          errorMessage.value = '生成报告失败: ' + (response.message || '未知错误')
        }
      } catch (error) {
        console.error('生成报告失败:', error)
        errorMessage.value = '生成报告失败: ' + error.message
      } finally {
        generating.value = false
      }
    }

    const downloadReport = async (report) => {
      if (!report) return
      
      downloading.value = report.id
      try {
        const baseUrl = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8888/api'
        const url = `${baseUrl}/reports/${report.id}/export?format=${report.report_type}`
        const token = localStorage.getItem('token')
        
        const response = await fetch(url, {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        })
        
        if (!response.ok) {
          throw new Error('下载失败')
        }
        
        const blob = await response.blob()
        const downloadUrl = URL.createObjectURL(blob)
        
        const link = document.createElement('a')
        link.href = downloadUrl
        link.download = `${report.report_name || 'report'}.${report.report_type}`
        document.body.appendChild(link)
        link.click()
        document.body.removeChild(link)
        URL.revokeObjectURL(downloadUrl)
        
        successMessage.value = '报告下载成功'
      } catch (error) {
        console.error('下载报告失败:', error)
        errorMessage.value = '下载报告失败: ' + error.message
      } finally {
        downloading.value = null
      }
    }

    const previewReport = async (report) => {
      if (!report) return
      
      try {
        const baseUrl = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8888/api'
        const token = localStorage.getItem('token')
        
        if (report.report_type === 'pdf') {
          const url = `${baseUrl}/reports/${report.id}/export?format=pdf`
          const response = await fetch(url, {
            headers: {
              'Authorization': `Bearer ${token}`
            }
          })
          
          if (!response.ok) {
            throw new Error('预览失败')
          }
          
          const blob = await response.blob()
          const previewUrl = URL.createObjectURL(blob)
          window.open(previewUrl, '_blank')
        } else if (report.report_type === 'html') {
          const url = `${baseUrl}/reports/${report.id}/export?format=html`
          const response = await fetch(url, {
            headers: {
              'Authorization': `Bearer ${token}`
            }
          })
          
          if (!response.ok) {
            throw new Error('预览失败')
          }
          
          const htmlContent = await response.text()
          const previewWindow = window.open('', '_blank')
          previewWindow.document.write(htmlContent)
          previewWindow.document.close()
        } else {
          router.push(`/report-detail?report=${report.id}`)
        }
      } catch (error) {
        console.error('预览报告失败:', error)
        errorMessage.value = '预览报告失败: ' + error.message
      }
    }

    const viewReport = async (report) => {
      router.push(`/report-detail?report=${report.id}`)
    }

    const deleteReport = async (reportId) => {
      if (confirm('确定要删除这个报告吗？')) {
        deleting.value = reportId
        try {
          const response = await reportsApi.deleteReport(reportId)
          if (response.code === 200) {
            reports.value = (reports.value || []).filter(r => r.id !== reportId)
            successMessage.value = '删除成功'
          } else {
            errorMessage.value = '删除失败: ' + (response.message || '未知错误')
          }
        } catch (error) {
          console.error('删除报告失败:', error)
          errorMessage.value = '删除报告失败'
        } finally {
          deleting.value = null
        }
      }
    }

    const formatFileSize = (bytes) => {
      if (!bytes) return '0 B'
      const k = 1024
      const sizes = ['B', 'KB', 'MB', 'GB']
      const i = Math.floor(Math.log(bytes) / Math.log(k))
      return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i]
    }

    onMounted(() => {
      fetchTasks()
      fetchReports()
      bindReportRefresh()
    })

    onUnmounted(() => {
      unbindReportRefresh()
    })

    return {
      errorMessage,
      successMessage,
      scanTasks,
      reports,
      selectedTask,
      selectedFormat,
      selectedContent,
      historyFilter,
      loadingTasks,
      loadingReports,
      generating,
      downloading,
      deleting,
      reportFormats,
      contentOptions,
      canGenerate,
      filteredReports,
      generateReport,
      downloadReport,
      previewReport,
      viewReport,
      deleteReport,
      formatFileSize,
      formatDate
    }
  }
}
</script>

<style scoped>
.reports {
  max-width: 1200px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: var(--spacing-xl);
}

.page-header h1 {
  margin: 0 0 var(--spacing-sm) 0;
  font-size: 2rem;
  color: var(--text-primary);
}

.page-subtitle {
  margin: 0;
  color: var(--text-secondary);
  font-size: 1rem;
}

.report-generator {
  margin-bottom: var(--spacing-xl);
}

.generator-content {
  display: block;
}

.form-section {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
  max-width: 800px;
  margin: 0 auto;
}

.form-hint {
  display: block;
  font-size: 12px;
  color: var(--text-secondary);
  margin-top: var(--spacing-xs);
}

.format-tabs {
  display: flex;
  gap: var(--spacing-sm);
}

.format-tab {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: var(--spacing-md);
  border: 2px solid var(--border-color);
  border-radius: var(--border-radius);
  background: none;
  cursor: pointer;
  transition: all 0.2s ease;
  flex: 1;
}

.format-tab:hover {
  border-color: var(--secondary-color);
}

.format-tab.active {
  border-color: var(--secondary-color);
  background-color: rgba(74, 144, 226, 0.1);
}

.format-icon {
  font-size: 24px;
  margin-bottom: var(--spacing-xs);
}

.format-name {
  font-size: 12px;
  font-weight: bold;
}

.content-options {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.checkbox-label {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  cursor: pointer;
  padding: var(--spacing-sm);
  border-radius: var(--border-radius);
  transition: background-color 0.2s ease;
}

.checkbox-label:hover {
  background-color: var(--background-color);
}

.checkbox-input {
  display: none;
}

.checkbox-custom {
  width: 16px;
  height: 16px;
  border: 2px solid var(--border-color);
  border-radius: 3px;
  position: relative;
  transition: all 0.2s ease;
}

.checkbox-input:checked + .checkbox-custom {
  background-color: var(--secondary-color);
  border-color: var(--secondary-color);
}

.checkbox-input:checked + .checkbox-custom::after {
  content: '';
  position: absolute;
  left: 5px;
  top: 1px;
  width: 4px;
  height: 9px;
  border: solid white;
  border-width: 0 2px 2px 0;
  transform: rotate(45deg);
}

.generator-actions {
  display: flex;
  justify-content: flex-end;
  padding-top: var(--spacing-lg);
  border-top: 1px solid var(--border-color);
}

.history-filters {
  display: flex;
  gap: var(--spacing-md);
}

.loading-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--spacing-md);
  padding: var(--spacing-xl);
}

.loading-spinner {
  width: 40px;
  height: 40px;
  border: 4px solid var(--border-color);
  border-top-color: var(--secondary-color);
  border-radius: 50%;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}

.loading-text {
  color: var(--text-secondary);
  font-size: 14px;
}

.history-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
  margin-top: var(--spacing-md);
}

.report-item {
  display: flex;
  align-items: center;
  padding: var(--spacing-md);
  border: 1px solid var(--border-color);
  border-radius: var(--border-radius);
  transition: all 0.2s ease;
}

.report-item:hover {
  background-color: var(--background-color);
  border-color: var(--secondary-color);
}

.report-info {
  flex: 1;
}

.report-name {
  font-weight: bold;
  color: var(--text-primary);
  margin-bottom: var(--spacing-xs);
}

.report-meta {
  display: flex;
  gap: var(--spacing-md);
  font-size: 12px;
  color: var(--text-secondary);
}

.report-task {
  flex: 1;
}

.report-date {
  white-space: nowrap;
}

.report-format {
  margin: 0 var(--spacing-md);
}

.format-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-sm);
  font-size: 10px;
  font-weight: bold;
}

.format-badge.format-html {
  background-color: rgba(74, 144, 226, 0.1);
  color: var(--secondary-color);
}

.format-badge.format-pdf {
  background-color: rgba(231, 76, 60, 0.1);
  color: var(--danger-color);
}

.format-badge.format-json {
  background-color: rgba(46, 204, 113, 0.1);
  color: var(--success-color);
}

.report-size {
  margin: 0 var(--spacing-md);
  color: var(--text-secondary);
  font-size: 12px;
}

.report-actions {
  display: flex;
  gap: var(--spacing-xs);
}

.btn-icon {
  background: none;
  border: none;
  cursor: pointer;
  padding: var(--spacing-xs);
  border-radius: var(--border-radius);
  font-size: 14px;
  transition: background-color 0.2s ease;
}

.btn-icon:hover:not(:disabled) {
  background-color: var(--background-color);
}

.btn-icon:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn-icon.btn-danger:hover:not(:disabled) {
  background-color: rgba(231, 76, 60, 0.1);
}

.empty-state {
  text-align: center;
  padding: var(--spacing-xl);
  color: var(--text-secondary);
}

.empty-icon {
  font-size: 48px;
  margin-bottom: var(--spacing-md);
}

.empty-title {
  font-size: 18px;
  font-weight: bold;
  margin-bottom: var(--spacing-sm);
  color: var(--text-primary);
}

.empty-description {
  font-size: 14px;
}

@media (max-width: 768px) {
  .report-item {
    flex-direction: column;
    align-items: flex-start;
    gap: var(--spacing-sm);
  }
  
  .report-meta {
    flex-direction: column;
    gap: var(--spacing-xs);
  }
  
  .report-actions {
    width: 100%;
    justify-content: flex-start;
  }
}
</style>
