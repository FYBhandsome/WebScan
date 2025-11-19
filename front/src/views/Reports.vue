<template>
  <div class="reports">
    <div class="page-header">
      <h1>报告生成</h1>
      <p class="page-subtitle">生成和管理安全扫描报告</p>
    </div>

    <!-- 报告生成表单 -->
    <div class="report-generator">
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">生成新报告</h3>
        </div>
        <div class="generator-content">
          <div class="form-section">
            <div class="form-group">
              <label class="form-label">选择扫描任务</label>
              <select v-model="selectedTask" class="form-select">
                <option value="">请选择扫描任务</option>
                <option v-for="task in scanTasks" :key="task.id" :value="task.id">
                  {{ task.name }} - {{ task.targetUrl }}
                </option>
              </select>
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
          
          <!-- 报告预览 -->
          <div class="preview-section">
            <h4>报告预览</h4>
            <div class="report-preview">
              <div class="preview-header">
                <h3>{{ getPreviewTitle() }}</h3>
                <div class="preview-meta">
                  <span>生成时间: {{ new Date().toLocaleString('zh-CN') }}</span>
                </div>
              </div>
              
              <div class="preview-content">
                <div v-if="selectedContent.includes('summary')" class="preview-section-item">
                  <h4>扫描摘要</h4>
                  <div class="summary-stats">
                    <span class="stat-item high">高危: 3</span>
                    <span class="stat-item medium">中危: 8</span>
                    <span class="stat-item low">低危: 12</span>
                  </div>
                </div>
                
                <div v-if="selectedContent.includes('vulnerabilities')" class="preview-section-item">
                  <h4>漏洞列表</h4>
                  <div class="vuln-preview">
                    <div class="vuln-item-preview">
                      <span class="vuln-priority high">高危</span>
                      <span class="vuln-title">SQL注入漏洞 - 用户登录接口</span>
                    </div>
                    <div class="vuln-item-preview">
                      <span class="vuln-priority medium">中危</span>
                      <span class="vuln-title">跨站脚本攻击 - 评论功能</span>
                    </div>
                  </div>
                </div>
                
                <div v-if="selectedContent.includes('recommendations')" class="preview-section-item">
                  <h4>修复建议</h4>
                  <p class="recommendation-text">
                    建议立即修复所有高危漏洞，加强输入验证和输出编码...
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
        
        <div class="generator-actions">
          <button @click="generateReport" class="btn btn-success" :disabled="!canGenerate">
            📄 生成报告
          </button>
        </div>
      </div>
    </div>

    <!-- 历史报告 -->
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
        
        <div class="history-list">
          <div 
            v-for="report in filteredReports" 
            :key="report.id"
            class="report-item"
          >
            <div class="report-info">
              <div class="report-name">{{ report.name }}</div>
              <div class="report-meta">
                <span class="report-task">{{ report.taskName }}</span>
                <span class="report-date">{{ report.createdAt }}</span>
              </div>
            </div>
            
            <div class="report-format">
              <span :class="['format-badge', `format-${report.format}`]">
                {{ report.format.toUpperCase() }}
              </span>
            </div>
            
            <div class="report-size">
              {{ report.size }}
            </div>
            
            <div class="report-actions">
              <button @click="downloadReport(report)" class="btn-icon" title="下载">
                📥
              </button>
              <button @click="viewReport(report)" class="btn-icon" title="预览">
                👁️
              </button>
              <button @click="deleteReport(report.id)" class="btn-icon btn-danger" title="删除">
                🗑️
              </button>
            </div>
          </div>
        </div>
        
        <div v-if="filteredReports.length === 0" class="empty-state">
          <div class="empty-icon">📋</div>
          <div class="empty-title">暂无报告</div>
          <div class="empty-description">生成第一个安全扫描报告</div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
// TODO: 替换为真实的API调用
import { mockScanTasks, mockReports } from '../data/mockData.js'

export default {
  name: 'Reports',
  data() {
    return {
      selectedTask: '',
      selectedFormat: 'html',
      selectedContent: ['summary', 'vulnerabilities', 'recommendations'],
      historyFilter: '',
      reportFormats: [
        { value: 'html', name: 'HTML', icon: '🌐' },
        { value: 'pdf', name: 'PDF', icon: '📄' },
        { value: 'json', name: 'JSON', icon: '📊' }
      ],
      contentOptions: [
        { value: 'summary', label: '扫描摘要' },
        { value: 'vulnerabilities', label: '漏洞详情' },
        { value: 'recommendations', label: '修复建议' },
        { value: 'charts', label: '统计图表' },
        { value: 'appendix', label: '技术附录' }
      ],
      // TODO: 从API获取扫描任务列表 - GET /api/scan-tasks
      scanTasks: mockScanTasks,
      
      // TODO: 从API获取报告历史 - GET /api/reports
      reports: mockReports
    }
  },
  computed: {
    canGenerate() {
      return this.selectedTask && this.selectedFormat && this.selectedContent.length > 0
    },
    filteredReports() {
      if (!this.historyFilter) return this.reports
      return this.reports.filter(report => report.format === this.historyFilter)
    }
  },
  methods: {
    getPreviewTitle() {
      const task = this.scanTasks.find(t => t.id == this.selectedTask)
      return task ? `${task.name} - 安全扫描报告` : '安全扫描报告'
    },
    generateReport() {
      if (!this.canGenerate) return
      
      // 模拟报告生成
      const task = this.scanTasks.find(t => t.id == this.selectedTask)
      const newReport = {
        id: Date.now(),
        name: `${task.name}报告`,
        taskName: task.name,
        format: this.selectedFormat,
        size: this.getRandomSize(),
        createdAt: new Date().toLocaleString('zh-CN')
      }
      
      this.reports.unshift(newReport)
      alert('报告生成成功！')
    },
    getRandomSize() {
      const sizes = ['1.2 MB', '2.5 MB', '3.1 MB', '856 KB', '1.8 MB']
      return sizes[Math.floor(Math.random() * sizes.length)]
    },
    downloadReport(report) {
      // 实现下载功能
      console.log('下载报告:', report.name)
      alert(`开始下载: ${report.name}`)
    },
    viewReport(report) {
      // 实现预览功能
      console.log('预览报告:', report.name)
    },
    deleteReport(reportId) {
      if (confirm('确定要删除这个报告吗？')) {
        this.reports = this.reports.filter(r => r.id !== reportId)
      }
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

.page-subtitle {
  color: var(--text-secondary);
  margin-top: var(--spacing-xs);
}

/* 报告生成器 */
.report-generator {
  margin-bottom: var(--spacing-xl);
}

.generator-content {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: var(--spacing-xl);
}

.form-section {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

/* 格式选择标签 */
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

/* 内容选项 */
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
  content: '✓';
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  color: white;
  font-size: 10px;
  font-weight: bold;
}

/* 报告预览 */
.preview-section h4 {
  color: var(--primary-color);
  margin-bottom: var(--spacing-md);
}

.report-preview {
  border: 1px solid var(--border-color);
  border-radius: var(--border-radius);
  padding: var(--spacing-lg);
  background-color: white;
  min-height: 300px;
}

.preview-header {
  border-bottom: 1px solid var(--border-color);
  padding-bottom: var(--spacing-md);
  margin-bottom: var(--spacing-lg);
}

.preview-header h3 {
  color: var(--primary-color);
  margin-bottom: var(--spacing-xs);
}

.preview-meta {
  color: var(--text-secondary);
  font-size: 12px;
}

.preview-section-item {
  margin-bottom: var(--spacing-lg);
}

.preview-section-item h4 {
  color: var(--text-primary);
  font-size: 14px;
  margin-bottom: var(--spacing-sm);
}

.summary-stats {
  display: flex;
  gap: var(--spacing-md);
}

.stat-item {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius);
  font-size: 12px;
  font-weight: bold;
}

.stat-item.high {
  background-color: rgba(231, 76, 60, 0.1);
  color: var(--high-risk);
}

.stat-item.medium {
  background-color: rgba(245, 166, 35, 0.1);
  color: var(--medium-risk);
}

.stat-item.low {
  background-color: rgba(241, 196, 15, 0.1);
  color: var(--low-risk);
}

.vuln-preview {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
}

.vuln-item-preview {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-xs);
  font-size: 12px;
}

.vuln-priority {
  padding: 2px var(--spacing-xs);
  border-radius: 10px;
  font-size: 10px;
  font-weight: bold;
}

.vuln-priority.high {
  background-color: var(--high-risk);
  color: white;
}

.vuln-priority.medium {
  background-color: var(--medium-risk);
  color: white;
}

.vuln-title {
  color: var(--text-primary);
}

.recommendation-text {
  color: var(--text-secondary);
  font-size: 12px;
  line-height: 1.4;
}

.generator-actions {
  display: flex;
  justify-content: flex-end;
  padding-top: var(--spacing-lg);
  border-top: 1px solid var(--border-color);
}

/* 历史报告 */
.history-filters {
  display: flex;
  gap: var(--spacing-md);
}

.history-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
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

.report-format {
  margin: 0 var(--spacing-md);
}

.format-badge {
  padding: 2px var(--spacing-xs);
  border-radius: 3px;
  font-size: 10px;
  font-weight: bold;
}

.format-badge.format-html {
  background-color: rgba(74, 144, 226, 0.1);
  color: var(--secondary-color);
}

.format-badge.format-pdf {
  background-color: rgba(231, 76, 60, 0.1);
  color: var(--high-risk);
}

.format-badge.format-json {
  background-color: rgba(46, 204, 113, 0.1);
  color: var(--success-color);
}

.report-size {
  color: var(--text-secondary);
  font-size: 12px;
  margin-right: var(--spacing-md);
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

.btn-icon:hover {
  background-color: var(--background-color);
}

.btn-icon.btn-danger:hover {
  background-color: rgba(231, 76, 60, 0.1);
}

/* 空状态 */
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
}

.empty-description {
  font-size: 14px;
}

/* 响应式设计 */
@media (max-width: 768px) {
  .generator-content {
    grid-template-columns: 1fr;
  }
  
  .format-tabs {
    flex-direction: column;
  }
  
  .report-item {
    flex-direction: column;
    align-items: flex-start;
    gap: var(--spacing-sm);
  }
  
  .report-meta {
    flex-direction: column;
    gap: var(--spacing-xs);
  }
}
</style>
