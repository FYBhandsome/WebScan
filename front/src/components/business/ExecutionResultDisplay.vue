<template>
  <div class="execution-result-display">
    <el-card v-if="loading" class="loading-card">
      <div class="loading-content">
        <el-icon class="is-loading" :size="32"><Loading /></el-icon>
        <span>加载执行结果...</span>
      </div>
    </el-card>

    <template v-else-if="resultData">
      <el-card class="result-card">
        <template #header>
          <div class="card-header" @click="toggleSection('main')">
            <span class="title">
              <el-icon><CircleCheck /></el-icon>
              执行结果数据
            </span>
            <div class="header-right">
              <el-tag :type="getResultType(resultData.status)">
                {{ getResultLabel(resultData.status) }}
              </el-tag>
              <el-icon class="collapse-icon" :class="{ 'is-expanded': expandedSections.main }">
                <ArrowDown />
              </el-icon>
            </div>
          </div>
        </template>

        <el-collapse-transition>
          <div v-show="expandedSections.main">
            <el-descriptions :column="2" border class="result-info">
              <el-descriptions-item label="任务ID">
                {{ resultData.task_id || '无' }}
              </el-descriptions-item>
              <el-descriptions-item label="执行状态">
                <el-tag :type="getResultType(resultData.status)" size="small">
                  {{ getResultLabel(resultData.status) }}
                </el-tag>
              </el-descriptions-item>
              <el-descriptions-item label="目标">
                {{ resultData.target || '无' }}
              </el-descriptions-item>
              <el-descriptions-item label="执行时间">
                {{ formatTimestamp(resultData.executed_at || resultData.end_time) || '无' }}
              </el-descriptions-item>
              <el-descriptions-item label="总耗时">
                {{ formatDuration(resultData.duration) || '无' }}
              </el-descriptions-item>
              <el-descriptions-item label="执行者">
                {{ resultData.executor || resultData.executed_by || '无' }}
              </el-descriptions-item>
            </el-descriptions>

            <div v-if="resultData.summary" class="summary-section">
              <div class="section-header" @click="toggleSection('summary')">
                <span class="section-title">
                  <el-icon><DataAnalysis /></el-icon>
                  执行摘要
                </span>
                <el-icon class="collapse-icon" :class="{ 'is-expanded': expandedSections.summary }">
                  <ArrowDown />
                </el-icon>
              </div>
              <el-collapse-transition>
                <div v-show="expandedSections.summary" class="summary-content">
                  <el-row :gutter="16">
                    <el-col :span="6">
                      <div class="summary-stat">
                        <span class="stat-value success">{{ resultData.summary.success_count || 0 }}</span>
                        <span class="stat-label">成功</span>
                      </div>
                    </el-col>
                    <el-col :span="6">
                      <div class="summary-stat">
                        <span class="stat-value danger">{{ resultData.summary.failed_count || 0 }}</span>
                        <span class="stat-label">失败</span>
                      </div>
                    </el-col>
                    <el-col :span="6">
                      <div class="summary-stat">
                        <span class="stat-value warning">{{ resultData.summary.warning_count || 0 }}</span>
                        <span class="stat-label">警告</span>
                      </div>
                    </el-col>
                    <el-col :span="6">
                      <div class="summary-stat">
                        <span class="stat-value info">{{ resultData.summary.skipped_count || 0 }}</span>
                        <span class="stat-label">跳过</span>
                      </div>
                    </el-col>
                  </el-row>
                  <div v-if="resultData.summary.description" class="summary-description">
                    {{ resultData.summary.description }}
                  </div>
                </div>
              </el-collapse-transition>
            </div>

            <div v-if="resultData.vulnerabilities?.length" class="vulnerabilities-section">
              <div class="section-header" @click="toggleSection('vulnerabilities')">
                <span class="section-title">
                  <el-icon><Warning /></el-icon>
                  发现漏洞 ({{ resultData.vulnerabilities.length }})
                </span>
                <el-icon class="collapse-icon" :class="{ 'is-expanded': expandedSections.vulnerabilities }">
                  <ArrowDown />
                </el-icon>
              </div>
              <el-collapse-transition>
                <div v-show="expandedSections.vulnerabilities" class="vulnerabilities-list">
                  <div 
                    v-for="(vuln, index) in resultData.vulnerabilities" 
                    :key="index"
                    class="vuln-item"
                  >
                    <div class="vuln-header" @click="toggleVulnItem(index)">
                      <div class="vuln-left">
                        <el-tag :type="getSeverityType(vuln.severity)" size="small">
                          {{ vuln.severity || 'Unknown' }}
                        </el-tag>
                        <span class="vuln-title">{{ vuln.title || vuln.type || vuln.name || '未知漏洞' }}</span>
                      </div>
                      <el-icon class="collapse-icon" :class="{ 'is-expanded': expandedVulnItems[index] }">
                        <ArrowDown />
                      </el-icon>
                    </div>
                    <el-collapse-transition>
                      <div v-show="expandedVulnItems[index]" class="vuln-detail">
                        <div v-if="vuln.url" class="detail-row">
                          <span class="detail-label">URL:</span>
                          <span class="detail-value url-value">{{ vuln.url }}</span>
                        </div>
                        <div v-if="vuln.description" class="detail-row">
                          <span class="detail-label">描述:</span>
                          <span class="detail-value">{{ vuln.description }}</span>
                        </div>
                        <div v-if="vuln.solution" class="detail-row">
                          <span class="detail-label">修复建议:</span>
                          <span class="detail-value">{{ vuln.solution }}</span>
                        </div>
                        <div v-if="vuln.references?.length" class="detail-row">
                          <span class="detail-label">参考链接:</span>
                          <div class="reference-links">
                            <a 
                              v-for="(ref, i) in vuln.references" 
                              :key="i" 
                              :href="ref" 
                              target="_blank"
                              class="reference-link"
                            >
                              {{ ref }}
                            </a>
                          </div>
                        </div>
                        <div v-if="vuln.evidence" class="detail-block">
                          <span class="detail-label">证据:</span>
                          <pre class="detail-content">{{ typeof vuln.evidence === 'string' ? vuln.evidence : JSON.stringify(vuln.evidence, null, 2) }}</pre>
                        </div>
                        <div v-if="vuln.request" class="detail-block">
                          <span class="detail-label">请求:</span>
                          <pre class="detail-content">{{ vuln.request }}</pre>
                        </div>
                        <div v-if="vuln.response" class="detail-block">
                          <span class="detail-label">响应:</span>
                          <pre class="detail-content">{{ vuln.response }}</pre>
                        </div>
                        <div v-if="!vuln.url && !vuln.description && !vuln.solution && !vuln.evidence && !vuln.request && !vuln.response" class="detail-empty">
                          无详细数据
                        </div>
                      </div>
                    </el-collapse-transition>
                  </div>
                </div>
              </el-collapse-transition>
            </div>

            <div v-if="resultData.findings?.length" class="findings-section">
              <div class="section-header" @click="toggleSection('findings')">
                <span class="section-title">
                  <el-icon><Search /></el-icon>
                  发现结果 ({{ resultData.findings.length }})
                </span>
                <el-icon class="collapse-icon" :class="{ 'is-expanded': expandedSections.findings }">
                  <ArrowDown />
                </el-icon>
              </div>
              <el-collapse-transition>
                <div v-show="expandedSections.findings" class="findings-list">
                  <div 
                    v-for="(finding, index) in resultData.findings" 
                    :key="index"
                    class="finding-item"
                  >
                    <div class="finding-header" @click="toggleFindingItem(index)">
                      <div class="finding-left">
                        <el-tag :type="getFindingType(finding.type)" size="small">
                          {{ finding.type || '未知类型' }}
                        </el-tag>
                        <span class="finding-title">{{ finding.title || finding.name || `发现 ${index + 1}` }}</span>
                      </div>
                      <el-icon class="collapse-icon" :class="{ 'is-expanded': expandedFindingItems[index] }">
                        <ArrowDown />
                      </el-icon>
                    </div>
                    <el-collapse-transition>
                      <div v-show="expandedFindingItems[index]" class="finding-detail">
                        <div v-if="finding.description" class="detail-row">
                          <span class="detail-label">描述:</span>
                          <span class="detail-value">{{ finding.description }}</span>
                        </div>
                        <div v-if="finding.value" class="detail-row">
                          <span class="detail-label">值:</span>
                          <span class="detail-value">{{ finding.value }}</span>
                        </div>
                        <div v-if="finding.location" class="detail-row">
                          <span class="detail-label">位置:</span>
                          <span class="detail-value">{{ finding.location }}</span>
                        </div>
                        <div v-if="finding.data && Object.keys(finding.data).length > 0" class="detail-block">
                          <span class="detail-label">详细数据:</span>
                          <pre class="detail-content">{{ JSON.stringify(finding.data, null, 2) }}</pre>
                        </div>
                        <div v-if="!finding.description && !finding.value && !finding.location && !finding.data" class="detail-empty">
                          无详细数据
                        </div>
                      </div>
                    </el-collapse-transition>
                  </div>
                </div>
              </el-collapse-transition>
            </div>

            <div v-if="resultData.output" class="output-section">
              <div class="section-header" @click="toggleSection('output')">
                <span class="section-title">
                  <el-icon><Document /></el-icon>
                  输出日志
                </span>
                <el-icon class="collapse-icon" :class="{ 'is-expanded': expandedSections.output }">
                  <ArrowDown />
                </el-icon>
              </div>
              <el-collapse-transition>
                <div v-show="expandedSections.output" class="output-content">
                  <pre>{{ resultData.output }}</pre>
                </div>
              </el-collapse-transition>
            </div>

            <div v-if="resultData.errors?.length" class="errors-section">
              <div class="section-header" @click="toggleSection('errors')">
                <span class="section-title">
                  <el-icon><CircleClose /></el-icon>
                  错误信息 ({{ resultData.errors.length }})
                </span>
                <el-icon class="collapse-icon" :class="{ 'is-expanded': expandedSections.errors }">
                  <ArrowDown />
                </el-icon>
              </div>
              <el-collapse-transition>
                <div v-show="expandedSections.errors" class="errors-list">
                  <div 
                    v-for="(error, index) in resultData.errors" 
                    :key="index"
                    class="error-item"
                  >
                    <el-icon color="#F56C6C"><CircleCloseFilled /></el-icon>
                    <span>{{ typeof error === 'string' ? error : error.message || JSON.stringify(error) }}</span>
                  </div>
                </div>
              </el-collapse-transition>
            </div>

            <div v-if="resultData.metadata && Object.keys(resultData.metadata).length > 0" class="metadata-section">
              <div class="section-header" @click="toggleSection('metadata')">
                <span class="section-title">
                  <el-icon><Setting /></el-icon>
                  元数据
                </span>
                <el-icon class="collapse-icon" :class="{ 'is-expanded': expandedSections.metadata }">
                  <ArrowDown />
                </el-icon>
              </div>
              <el-collapse-transition>
                <div v-show="expandedSections.metadata" class="metadata-content">
                  <pre>{{ JSON.stringify(resultData.metadata, null, 2) }}</pre>
                </div>
              </el-collapse-transition>
            </div>
          </div>
        </el-collapse-transition>
      </el-card>
    </template>

    <el-empty v-else description="暂无执行结果" />
  </div>
</template>

<script setup>
import { reactive, watch } from 'vue'
import { 
  Loading, 
  CircleCheck, 
  DataAnalysis, 
  Warning, 
  Search, 
  Document, 
  CircleClose,
  CircleCloseFilled,
  Setting,
  ArrowDown
} from '@element-plus/icons-vue'
import { formatDuration, formatTimestamp } from '@/utils/workflowData'

const props = defineProps({
  resultData: {
    type: Object,
    default: null
  },
  loading: {
    type: Boolean,
    default: false
  }
})

const expandedSections = reactive({
  main: true,
  summary: true,
  vulnerabilities: true,
  findings: false,
  output: false,
  errors: false,
  metadata: false
})

const expandedVulnItems = reactive({})
const expandedFindingItems = reactive({})

const toggleSection = (section) => {
  expandedSections[section] = !expandedSections[section]
}

const toggleVulnItem = (index) => {
  expandedVulnItems[index] = !expandedVulnItems[index]
}

const toggleFindingItem = (index) => {
  expandedFindingItems[index] = !expandedFindingItems[index]
}

const getResultType = (status) => {
  const typeMap = {
    'success': 'success',
    'completed': 'success',
    'failed': 'danger',
    'error': 'danger',
    'partial': 'warning',
    'cancelled': 'info'
  }
  return typeMap[status?.toLowerCase()] || 'info'
}

const getResultLabel = (status) => {
  const labelMap = {
    'success': '成功',
    'completed': '已完成',
    'failed': '失败',
    'error': '错误',
    'partial': '部分成功',
    'cancelled': '已取消'
  }
  return labelMap[status?.toLowerCase()] || status || '未知'
}

const getSeverityType = (severity) => {
  const typeMap = {
    'critical': 'danger',
    'high': 'danger',
    'medium': 'warning',
    'low': 'info',
    'info': 'info'
  }
  return typeMap[severity?.toLowerCase()] || 'info'
}

const getFindingType = (type) => {
  const typeMap = {
    'info': 'info',
    'warning': 'warning',
    'error': 'danger',
    'success': 'success'
  }
  return typeMap[type?.toLowerCase()] || 'info'
}

watch(() => props.resultData, (newData) => {
  if (newData?.vulnerabilities) {
    newData.vulnerabilities.forEach((_, index) => {
      if (expandedVulnItems[index] === undefined) {
        expandedVulnItems[index] = false
      }
    })
  }
  if (newData?.findings) {
    newData.findings.forEach((_, index) => {
      if (expandedFindingItems[index] === undefined) {
        expandedFindingItems[index] = false
      }
    })
  }
}, { immediate: true })
</script>

<style scoped>
.execution-result-display {
  width: 100%;
}

.loading-card {
  min-height: 200px;
}

.loading-content {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 150px;
  gap: 16px;
}

.result-card {
  margin-bottom: 16px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  cursor: pointer;
  user-select: none;
}

.card-header .title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-weight: 600;
}

.header-right {
  display: flex;
  align-items: center;
  gap: 12px;
}

.collapse-icon {
  transition: transform 0.3s ease;
  color: #909399;
}

.collapse-icon.is-expanded {
  transform: rotate(180deg);
}

.result-info {
  margin-bottom: 16px;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 16px;
  background: #f5f7fa;
  border-radius: 4px;
  cursor: pointer;
  user-select: none;
  margin-bottom: 12px;
}

.section-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-weight: 500;
  color: #303133;
}

.summary-section,
.vulnerabilities-section,
.findings-section,
.output-section,
.errors-section,
.metadata-section {
  margin-top: 16px;
}

.summary-content {
  padding: 16px;
  background: #f5f7fa;
  border-radius: 4px;
}

.summary-stat {
  text-align: center;
  padding: 12px;
}

.stat-value {
  display: block;
  font-size: 28px;
  font-weight: 600;
}

.stat-value.success {
  color: #67C23A;
}

.stat-value.danger {
  color: #F56C6C;
}

.stat-value.warning {
  color: #E6A23C;
}

.stat-value.info {
  color: #909399;
}

.stat-label {
  display: block;
  font-size: 13px;
  color: #909399;
  margin-top: 4px;
}

.summary-description {
  margin-top: 16px;
  padding-top: 16px;
  border-top: 1px solid #e4e7ed;
  color: #606266;
  line-height: 1.6;
}

.vulnerabilities-list,
.findings-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.vuln-item,
.finding-item {
  border: 1px solid #e4e7ed;
  border-radius: 4px;
  overflow: hidden;
}

.vuln-header,
.finding-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px;
  background: #fafafa;
  cursor: pointer;
}

.vuln-left,
.finding-left {
  display: flex;
  align-items: center;
  gap: 8px;
}

.vuln-title,
.finding-title {
  font-weight: 500;
  color: #303133;
}

.vuln-detail,
.finding-detail {
  padding: 12px;
  background: #fff;
  border-top: 1px solid #e4e7ed;
}

.detail-row {
  display: flex;
  margin-bottom: 8px;
}

.detail-row:last-child {
  margin-bottom: 0;
}

.detail-row .detail-label {
  min-width: 80px;
  color: #909399;
  font-size: 13px;
  flex-shrink: 0;
}

.detail-row .detail-value {
  color: #303133;
  font-size: 13px;
  word-break: break-all;
}

.url-value {
  color: #409EFF;
}

.reference-links {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.reference-link {
  color: #409EFF;
  text-decoration: none;
  font-size: 13px;
}

.reference-link:hover {
  text-decoration: underline;
}

.detail-block {
  margin-bottom: 12px;
}

.detail-block:last-child {
  margin-bottom: 0;
}

.detail-block .detail-label {
  display: block;
  font-size: 12px;
  color: #909399;
  margin-bottom: 4px;
}

.detail-content {
  margin: 0;
  padding: 8px;
  background: #f5f7fa;
  border-radius: 4px;
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 200px;
  overflow: auto;
}

.detail-empty {
  text-align: center;
  color: #909399;
  font-size: 13px;
  padding: 8px;
}

.output-content pre {
  margin: 0;
  padding: 12px;
  background: #1e1e1e;
  color: #d4d4d4;
  border-radius: 4px;
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 400px;
  overflow: auto;
}

.errors-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.error-item {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 12px;
  background: #fef0f0;
  border-radius: 4px;
  border-left: 3px solid #F56C6C;
  color: #F56C6C;
  font-size: 13px;
}

.metadata-content pre {
  margin: 0;
  padding: 12px;
  background: #f5f7fa;
  border-radius: 4px;
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 300px;
  overflow: auto;
}
</style>
