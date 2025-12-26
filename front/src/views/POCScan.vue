<template>
  <div class="poc-scan">
    <div class="page-header">
      <div class="header-content">
        <h1>POC 漏洞扫描</h1>
        <button @click="showCreateModal = true" class="btn btn-success">
          <span>➕</span>
          创建扫描任务
        </button>
      </div>
      
      <!-- 搜索和筛选 -->
      <div class="filters">
        <div class="search-box">
          <input 
            v-model="searchQuery" 
            type="text" 
            placeholder="搜索目标或POC类型..." 
            class="form-input"
          >
        </div>
        <select v-model="pocTypeFilter" class="form-select">
          <option value="">全部POC类型</option>
          <option v-for="pocType in availablePOCTypes" :key="pocType" :value="pocType">
            {{ getPOCTypeName(pocType) }}
          </option>
        </select>
        <select v-model="vulnerabilityFilter" class="form-select">
          <option value="">全部结果</option>
          <option value="vulnerable">存在漏洞</option>
          <option value="safe">安全</option>
        </select>
      </div>
    </div>

    <!-- 统计卡片 -->
    <div class="stats-container">
      <div class="stat-card">
        <div class="stat-icon">📊</div>
        <div class="stat-content">
          <div class="stat-value">{{ totalScanned }}</div>
          <div class="stat-label">总扫描数</div>
        </div>
      </div>
      <div class="stat-card stat-danger">
        <div class="stat-icon">⚠️</div>
        <div class="stat-content">
          <div class="stat-value">{{ vulnerableCount }}</div>
          <div class="stat-label">存在漏洞</div>
        </div>
      </div>
      <div class="stat-card stat-success">
        <div class="stat-icon">✅</div>
        <div class="stat-content">
          <div class="stat-value">{{ safeCount }}</div>
          <div class="stat-label">安全</div>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-icon">🎯</div>
        <div class="stat-content">
          <div class="stat-value">{{ availablePOCTypes.length }}</div>
          <div class="stat-label">POC类型</div>
        </div>
      </div>
    </div>

    <!-- 扫描结果列表 -->
    <div class="results-container">
      <div class="card">
        <div class="results-table">
          <div class="table-header">
            <div class="th poc-type">POC类型</div>
            <div class="th target">目标</div>
            <div class="th status">状态</div>
            <div class="th severity">严重程度</div>
            <div class="th cve">CVE编号</div>
            <div class="th message">消息</div>
            <div class="th time">扫描时间</div>
          </div>
          
          <div class="table-body">
            <div 
              v-for="result in filteredResults" 
              :key="result.id" 
              class="table-row"
            >
              <div class="td poc-type">
                <div class="poc-type-badge">
                  {{ getPOCTypeName(result.poc_type) }}
                </div>
              </div>
              
              <div class="td target">
                <div class="url-display" :title="result.target">
                  {{ result.target }}
                </div>
              </div>
              
              <div class="td status">
                <span :class="['status', result.vulnerable ? 'status-vulnerable' : 'status-safe']">
                  <span class="status-dot"></span>
                  {{ result.vulnerable ? '存在漏洞' : '安全' }}
                </span>
              </div>
              
              <div class="td severity">
                <span :class="['severity', `severity-${result.severity || 'unknown'}`]">
                  {{ getSeverityText(result.severity) }}
                </span>
              </div>
              
              <div class="td cve">
                <span class="cve-badge">{{ result.cve_id || '-' }}</span>
              </div>
              
              <div class="td message">
                <div class="message-display" :title="result.message">
                  {{ truncateMessage(result.message) }}
                </div>
              </div>
              
              <div class="td time">
                {{ formatTime(result.timestamp) }}
              </div>
            </div>
            
            <div v-if="filteredResults.length === 0" class="empty-state">
              <div class="empty-icon">📭</div>
              <div class="empty-text">暂无扫描结果</div>
              <div class="empty-hint">点击"创建扫描任务"开始扫描</div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 创建扫描任务模态框 -->
    <div v-if="showCreateModal" class="modal-overlay" @click="closeModal">
      <div class="modal" @click.stop>
        <div class="modal-header">
          <h2>创建POC扫描任务</h2>
          <button @click="closeModal" class="close-btn">×</button>
        </div>
        
        <div class="modal-body">
          <form @submit.prevent="createScan">
            <div class="form-group">
              <label class="form-label">目标URL</label>
              <input 
                v-model="newScan.target" 
                type="text" 
                class="form-input" 
                placeholder="输入目标URL，例如：http://example.com"
                required
              >
            </div>
            
            <div class="form-group">
              <label class="form-label">POC类型</label>
              <div class="poc-types-grid">
                <label v-for="pocType in availablePOCTypes" :key="pocType" class="checkbox-label">
                  <input 
                    v-model="newScan.pocTypes" 
                    type="checkbox" 
                    :value="pocType"
                    class="checkbox-input"
                  >
                  <span class="checkbox-custom"></span>
                  <span class="poc-type-label">{{ getPOCTypeName(pocType) }}</span>
                </label>
              </div>
              <div class="form-help">不选择则扫描所有POC类型</div>
            </div>
            
            <div class="form-group">
              <label class="form-label">超时时间（秒）</label>
              <input 
                v-model="newScan.timeout" 
                type="number" 
                min="1" 
                max="60"
                class="form-input"
                placeholder="默认10秒"
              >
            </div>
          </form>
        </div>
        
        <div class="modal-footer">
          <button @click="closeModal" class="btn btn-outline" :disabled="isScanning">
            取消
          </button>
          <button @click="createScan" class="btn btn-success" :disabled="isScanning">
            {{ isScanning ? '扫描中...' : '开始扫描' }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { pocApi } from '../utils/api.js'

export default {
  name: 'POCScan',
  data() {
    return {
      searchQuery: '',
      pocTypeFilter: '',
      vulnerabilityFilter: '',
      showCreateModal: false,
      isScanning: false,
      
      // 扫描结果
      results: [],
      availablePOCTypes: [],
      
      // 新扫描配置
      newScan: {
        target: '',
        pocTypes: [],
        timeout: 10
      }
    }
  },
  computed: {
    filteredResults() {
      return this.results.filter(result => {
        const matchesSearch = !this.searchQuery || 
          result.target.toLowerCase().includes(this.searchQuery.toLowerCase()) ||
          result.poc_type.toLowerCase().includes(this.searchQuery.toLowerCase())
        
        const matchesPOCType = !this.pocTypeFilter || result.poc_type === this.pocTypeFilter
        const matchesVulnerability = !this.vulnerabilityFilter || 
          (this.vulnerabilityFilter === 'vulnerable' && result.vulnerable) ||
          (this.vulnerabilityFilter === 'safe' && !result.vulnerable)
        
        return matchesSearch && matchesPOCType && matchesVulnerability
      })
    },
    totalScanned() {
      return this.results.length
    },
    vulnerableCount() {
      return this.results.filter(r => r.vulnerable).length
    },
    safeCount() {
      return this.results.filter(r => !r.vulnerable).length
    }
  },
  async mounted() {
    await this.loadAvailablePOCTypes()
  },
  methods: {
    async loadAvailablePOCTypes() {
      try {
        const response = await pocApi.getTypes()
        this.availablePOCTypes = response.data || response
      } catch (error) {
        console.error('加载POC类型失败:', error)
        this.availablePOCTypes = [
          'weblogic_cve_2020_2551',
          'weblogic_cve_2018_2628',
          'weblogic_cve_2018_2894',
          'struts2_009',
          'struts2_032',
          'tomcat_cve_2017_12615',
          'jboss_cve_2017_12149',
          'nexus_cve_2020_10199',
          'drupal_cve_2018_7600'
        ]
      }
    },
    async createScan() {
      if (!this.newScan.target) {
        alert('请输入目标URL')
        return
      }
      
      this.isScanning = true
      
      try {
        const payload = {
          target: this.newScan.target,
          poc_types: this.newScan.pocTypes.length > 0 ? this.newScan.pocTypes : undefined,
          timeout: this.newScan.timeout
        }
        
        const response = await pocApi.scan(payload)
        
        if (response.success) {
          // 将新结果添加到结果列表
          this.results = [...response.results, ...this.results]
          
          alert(`扫描完成！共扫描 ${response.total_scanned} 个POC，发现 ${response.vulnerable_count} 个漏洞`)
        } else {
          alert('扫描失败')
        }
      } catch (error) {
        console.error('扫描失败:', error)
        alert('扫描失败：' + (error.message || '未知错误'))
      } finally {
        this.isScanning = false
        this.closeModal()
      }
    },
    closeModal() {
      if (!this.isScanning) {
        this.showCreateModal = false
        this.resetForm()
      }
    },
    resetForm() {
      this.newScan = {
        target: '',
        pocTypes: [],
        timeout: 10
      }
    },
    getPOCTypeName(pocType) {
      const nameMap = {
        'weblogic_cve_2020_2551': 'WebLogic CVE-2020-2551',
        'weblogic_cve_2018_2628': 'WebLogic CVE-2018-2628',
        'weblogic_cve_2018_2894': 'WebLogic CVE-2018-2894',
        'struts2_009': 'Struts2 S2-009',
        'struts2_032': 'Struts2 S2-032',
        'tomcat_cve_2017_12615': 'Tomcat CVE-2017-12615',
        'jboss_cve_2017_12149': 'JBoss CVE-2017-12149',
        'nexus_cve_2020_10199': 'Nexus CVE-2020-10199',
        'drupal_cve_2018_7600': 'Drupal CVE-2018-7600'
      }
      return nameMap[pocType] || pocType
    },
    getSeverityText(severity) {
      const severityMap = {
        'high': '高危',
        'medium': '中危',
        'low': '低危'
      }
      return severityMap[severity] || '未知'
    },
    truncateMessage(message) {
      if (!message) return '-'
      return message.length > 50 ? message.substring(0, 50) + '...' : message
    },
    formatTime(timestamp) {
      if (!timestamp) return '-'
      const date = new Date(timestamp)
      return date.toLocaleString('zh-CN', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit'
      })
    }
  }
}
</script>

<style scoped>
.poc-scan {
  max-width: 1400px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: var(--spacing-xl);
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-lg);
}

.filters {
  display: flex;
  gap: var(--spacing-md);
  align-items: center;
}

.search-box {
  flex: 1;
  max-width: 300px;
}

/* 统计卡片 */
.stats-container {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: var(--spacing-lg);
  margin-bottom: var(--spacing-xl);
}

.stat-card {
  background-color: var(--card-background);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-lg);
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
  box-shadow: var(--shadow-sm);
  transition: transform 0.2s ease, box-shadow 0.2s ease;
}

.stat-card:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-md);
}

.stat-card.stat-danger {
  border-left: 4px solid #e74c3c;
}

.stat-card.stat-success {
  border-left: 4px solid #27ae60;
}

.stat-icon {
  font-size: 32px;
  opacity: 0.8;
}

.stat-content {
  flex: 1;
}

.stat-value {
  font-size: 28px;
  font-weight: bold;
  color: var(--text-primary);
  line-height: 1;
}

.stat-label {
  font-size: 13px;
  color: var(--text-secondary);
  margin-top: var(--spacing-xs);
}

/* 结果表格 */
.results-table {
  display: table;
  width: 100%;
  border-collapse: collapse;
}

.table-header {
  display: table-row;
  background-color: var(--background-color);
  font-weight: bold;
}

.table-body {
  display: table-row-group;
}

.table-row {
  display: table-row;
  transition: background-color 0.2s ease;
}

.table-row:hover {
  background-color: var(--background-color);
}

.th, .td {
  display: table-cell;
  padding: var(--spacing-md);
  border-bottom: 1px solid var(--border-color);
  vertical-align: middle;
}

.th {
  color: var(--text-primary);
  font-weight: bold;
  font-size: 13px;
}

.poc-type {
  width: 18%;
}

.target {
  width: 20%;
}

.status {
  width: 10%;
}

.severity {
  width: 10%;
}

.cve {
  width: 12%;
}

.message {
  width: 20%;
}

.time {
  width: 10%;
}

.poc-type-badge {
  background-color: var(--background-color);
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius);
  font-size: 12px;
  font-weight: 500;
}

.url-display {
  color: var(--secondary-color);
  font-family: monospace;
  font-size: 12px;
  word-break: break-all;
}

.status {
  display: inline-flex;
  align-items: center;
  gap: var(--spacing-xs);
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius);
  font-size: 12px;
  font-weight: 500;
}

.status-vulnerable {
  background-color: rgba(231, 76, 60, 0.1);
  color: #e74c3c;
}

.status-safe {
  background-color: rgba(39, 174, 96, 0.1);
  color: #27ae60;
}

.status-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background-color: currentColor;
}

.severity {
  display: inline-block;
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius);
  font-size: 12px;
  font-weight: 500;
}

.severity-high {
  background-color: rgba(231, 76, 60, 0.1);
  color: #e74c3c;
}

.severity-medium {
  background-color: rgba(243, 156, 18, 0.1);
  color: #f39c12;
}

.severity-low {
  background-color: rgba(52, 152, 219, 0.1);
  color: #3498db;
}

.severity-unknown {
  background-color: var(--background-color);
  color: var(--text-secondary);
}

.cve-badge {
  font-family: monospace;
  font-size: 12px;
  color: var(--secondary-color);
}

.message-display {
  font-size: 12px;
  color: var(--text-secondary);
}

.time {
  font-size: 12px;
  color: var(--text-secondary);
}

/* 空状态 */
.empty-state {
  text-align: center;
  padding: var(--spacing-xxl);
  color: var(--text-secondary);
}

.empty-icon {
  font-size: 48px;
  margin-bottom: var(--spacing-md);
  opacity: 0.5;
}

.empty-text {
  font-size: 16px;
  font-weight: 500;
  margin-bottom: var(--spacing-xs);
}

.empty-hint {
  font-size: 13px;
  opacity: 0.8;
}

/* 模态框 */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal {
  background-color: var(--card-background);
  border-radius: var(--border-radius-lg);
  box-shadow: var(--shadow-lg);
  width: 90%;
  max-width: 700px;
  max-height: 90vh;
  overflow-y: auto;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-lg);
  border-bottom: 1px solid var(--border-color);
}

.modal-header h2 {
  margin: 0;
  color: var(--text-primary);
}

.close-btn {
  background: none;
  border: none;
  font-size: 24px;
  cursor: pointer;
  color: var(--text-secondary);
  padding: 0;
  width: 30px;
  height: 30px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-body {
  padding: var(--spacing-lg);
}

.modal-footer {
  display: flex;
  justify-content: flex-end;
  gap: var(--spacing-md);
  padding: var(--spacing-lg);
  border-top: 1px solid var(--border-color);
}

.form-help {
  font-size: 12px;
  color: var(--text-secondary);
  margin-top: var(--spacing-xs);
}

.poc-types-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-md);
}

.checkbox-label {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
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
  font-size: 12px;
  font-weight: bold;
}

.poc-type-label {
  font-size: 13px;
  color: var(--text-primary);
}

.btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

/* 响应式设计 - 平板设备 */
@media (max-width: 1024px) {
  .stats-container {
    grid-template-columns: repeat(3, 1fr);
  }
  
  .search-box {
    max-width: 250px;
  }
  
  .modal {
    max-width: 600px;
  }
}

/* 响应式设计 - 手机设备 */
@media (max-width: 768px) {
  .poc-scan {
    padding: 0;
  }
  
  .page-header {
    margin-bottom: var(--spacing-lg);
  }
  
  .header-content {
    flex-direction: column;
    align-items: flex-start;
    gap: var(--spacing-md);
  }
  
  .filters {
    flex-direction: column;
    align-items: stretch;
    width: 100%;
  }
  
  .search-box {
    max-width: 100%;
  }
  
  .stats-container {
    grid-template-columns: 1fr;
    gap: var(--spacing-md);
  }
  
  .stat-card {
    padding: var(--spacing-md);
  }
  
  .stat-value {
    font-size: 28px;
  }
  
  .results-table {
    overflow-x: auto;
  }
  
  .table-header,
  .table-row {
    min-width: 800px;
  }
  
  .modal {
    width: 95%;
    max-height: 85vh;
  }
  
  .modal-header,
  .modal-body,
  .modal-footer {
    padding: var(--spacing-md);
  }
  
  .poc-types-grid {
    grid-template-columns: 1fr;
  }
  
  .checkbox-label {
    padding: var(--spacing-sm);
  }
}

/* 响应式设计 - 小屏手机 */
@media (max-width: 480px) {
  .page-header h1 {
    font-size: 20px;
  }
  
  .stat-card {
    padding: var(--spacing-sm);
  }
  
  .stat-value {
    font-size: 24px;
  }
  
  .stat-label {
    font-size: 13px;
  }
  
  .modal {
    width: 100%;
    max-height: 100vh;
    border-radius: 0;
  }
  
  .modal-header h2 {
    font-size: 18px;
  }
  
  .form-label {
    font-size: 13px;
  }
  
  .form-input {
    font-size: 13px;
  }
  
  .poc-type-label {
    font-size: 12px;
  }
  
  .btn {
    padding: var(--spacing-xs) var(--spacing-sm);
    font-size: 12px;
  }
}

/* 响应式设计 - 超小屏设备 */
@media (max-width: 360px) {
  .stat-value {
    font-size: 20px;
  }
  
  .stat-label {
    font-size: 12px;
  }
  
  .poc-type-badge,
  .cve-badge {
    font-size: 11px;
  }
  
  .status,
  .severity {
    font-size: 11px;
    padding: 2px 6px;
  }
}
</style>