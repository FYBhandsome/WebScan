<template>
  <div class="workflow-execution-display">
    <el-card v-if="loading" class="loading-card">
      <div class="loading-content">
        <el-icon class="is-loading" :size="32"><Loading /></el-icon>
        <span>加载执行数据...</span>
      </div>
    </el-card>

    <template v-else-if="executionData">
      <el-card class="execution-card">
        <template #header>
          <div class="card-header" @click="toggleSection('main')">
            <span class="title">
              <el-icon><Operation /></el-icon>
              任务执行数据
            </span>
            <div class="header-right">
              <el-tag :type="getStatusType(executionData.status)">
                {{ getStatusLabel(executionData.status) }}
              </el-tag>
              <el-icon class="collapse-icon" :class="{ 'is-expanded': expandedSections.main }">
                <ArrowDown />
              </el-icon>
            </div>
          </div>
        </template>

        <el-collapse-transition>
          <div v-show="expandedSections.main">
            <el-descriptions :column="2" border class="execution-info">
              <el-descriptions-item label="任务ID">
                {{ executionData.task_id || '无' }}
              </el-descriptions-item>
              <el-descriptions-item label="执行状态">
                <el-tag :type="getStatusType(executionData.status)" size="small">
                  {{ getStatusLabel(executionData.status) }}
                </el-tag>
              </el-descriptions-item>
              <el-descriptions-item label="目标">
                {{ executionData.target || '无' }}
              </el-descriptions-item>
              <el-descriptions-item label="进度">
                <el-progress 
                  :percentage="executionData.progress || 0" 
                  :stroke-width="8"
                  :status="getProgressStatus(executionData.status)"
                />
              </el-descriptions-item>
              <el-descriptions-item label="开始时间">
                {{ formatTimestamp(executionData.start_time) || '无' }}
              </el-descriptions-item>
              <el-descriptions-item label="结束时间">
                {{ formatTimestamp(executionData.end_time) || '无' }}
              </el-descriptions-item>
              <el-descriptions-item label="总耗时">
                {{ formatDuration(executionData.duration) || '无' }}
              </el-descriptions-item>
              <el-descriptions-item label="当前步骤">
                {{ executionData.current_step ? `${executionData.current_step}/${executionData.total_steps || 0}` : '无' }}
              </el-descriptions-item>
            </el-descriptions>

            <div v-if="executionData.execution_history?.length" class="history-section">
              <div class="section-header" @click="toggleSection('history')">
                <span class="section-title">
                  <el-icon><Clock /></el-icon>
                  执行历史 ({{ executionData.execution_history.length }})
                </span>
                <el-icon class="collapse-icon" :class="{ 'is-expanded': expandedSections.history }">
                  <ArrowDown />
                </el-icon>
              </div>
              <el-collapse-transition>
                <div v-show="expandedSections.history" class="history-list">
                  <div 
                    v-for="(step, index) in executionData.execution_history" 
                    :key="index"
                    class="history-item"
                  >
                    <div class="history-header" @click="toggleHistoryItem(index)">
                      <div class="history-left">
                        <el-tag :type="getStatusType(step.status)" size="small">
                          {{ getStatusLabel(step.status) }}
                        </el-tag>
                        <span class="step-name">{{ step.task || step.node_name || step.tool_name || '未知任务' }}</span>
                      </div>
                      <div class="history-right">
                        <span v-if="step.execution_time" class="step-time">
                          {{ step.execution_time.toFixed(2) }}s
                        </span>
                        <el-icon class="collapse-icon" :class="{ 'is-expanded': expandedHistoryItems[index] }">
                          <ArrowDown />
                        </el-icon>
                      </div>
                    </div>
                    <el-collapse-transition>
                      <div v-show="expandedHistoryItems[index]" class="history-detail">
                        <div v-if="step.input_params && Object.keys(step.input_params).length > 0" class="detail-block">
                          <span class="detail-label">输入参数:</span>
                          <pre class="detail-content">{{ JSON.stringify(step.input_params, null, 2) }}</pre>
                        </div>
                        <div v-if="step.output_data && Object.keys(step.output_data).length > 0" class="detail-block">
                          <span class="detail-label">输出数据:</span>
                          <pre class="detail-content">{{ JSON.stringify(step.output_data, null, 2) }}</pre>
                        </div>
                        <div v-if="step.error || step.error_message" class="detail-block error-block">
                          <span class="detail-label">错误信息:</span>
                          <span class="error-text">{{ step.error || step.error_message }}</span>
                        </div>
                        <div v-if="!step.input_params && !step.output_data && !step.error && !step.error_message" class="detail-empty">
                          无详细数据
                        </div>
                      </div>
                    </el-collapse-transition>
                  </div>
                </div>
              </el-collapse-transition>
            </div>

            <div v-if="executionData.graph_flow" class="graph-section">
              <div class="section-header" @click="toggleSection('graph')">
                <span class="section-title">
                  <el-icon><Share /></el-icon>
                  图流程结构
                </span>
                <el-icon class="collapse-icon" :class="{ 'is-expanded': expandedSections.graph }">
                  <ArrowDown />
                </el-icon>
              </div>
              <el-collapse-transition>
                <div v-show="expandedSections.graph" class="graph-content">
                  <div 
                    v-for="(subgraph, index) in executionData.graph_flow?.subgraphs" 
                    :key="index"
                    class="subgraph-item"
                  >
                    <div class="subgraph-header">
                      <el-icon><FolderOpened /></el-icon>
                      <span>{{ subgraph.subgraph_name || `子图 ${subgraph.subgraph_id || index + 1}` }}</span>
                      <el-tag :type="getStatusType(subgraph.status)" size="small">
                        {{ getStatusLabel(subgraph.status) }}
                      </el-tag>
                    </div>
                    <div class="nodes-list">
                      <div 
                        v-for="node in subgraph.nodes" 
                        :key="node.node_id"
                        class="node-item"
                      >
                        <el-tag :type="getStatusType(node.status)" size="small">
                          {{ getStatusLabel(node.status) }}
                        </el-tag>
                        <span class="node-name">{{ node.node_name || node.node_id || '未知节点' }}</span>
                        <span v-if="node.execution_time" class="node-time">{{ node.execution_time.toFixed(2) }}s</span>
                      </div>
                      <div v-if="!subgraph.nodes?.length" class="empty-nodes">无节点数据</div>
                    </div>
                  </div>
                  <div v-if="!executionData.graph_flow?.subgraphs?.length" class="empty-graph">无图流程数据</div>
                </div>
              </el-collapse-transition>
            </div>

            <div v-if="executionData.metadata && Object.keys(executionData.metadata).length > 0" class="metadata-section">
              <div class="section-header" @click="toggleSection('metadata')">
                <span class="section-title">
                  <el-icon><Document /></el-icon>
                  元数据
                </span>
                <el-icon class="collapse-icon" :class="{ 'is-expanded': expandedSections.metadata }">
                  <ArrowDown />
                </el-icon>
              </div>
              <el-collapse-transition>
                <div v-show="expandedSections.metadata" class="metadata-content">
                  <pre>{{ JSON.stringify(executionData.metadata, null, 2) }}</pre>
                </div>
              </el-collapse-transition>
            </div>
          </div>
        </el-collapse-transition>
      </el-card>
    </template>

    <el-empty v-else description="暂无执行数据" />
  </div>
</template>

<script setup>
import { ref, reactive, watch } from 'vue'
import { 
  Loading, 
  Operation, 
  Clock, 
  Share, 
  FolderOpened, 
  Document,
  ArrowDown 
} from '@element-plus/icons-vue'
import { 
  WorkflowStatus, 
  WorkflowDataProcessor,
  formatDuration,
  formatTimestamp
} from '@/utils/workflowData'

const props = defineProps({
  executionData: {
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
  history: true,
  graph: false,
  metadata: false
})

const expandedHistoryItems = reactive({})

const toggleSection = (section) => {
  expandedSections[section] = !expandedSections[section]
}

const toggleHistoryItem = (index) => {
  expandedHistoryItems[index] = !expandedHistoryItems[index]
}

const getStatusType = (status) => {
  return WorkflowStatus.getType(status)
}

const getStatusLabel = (status) => {
  return WorkflowStatus.getLabel(status)
}

const getProgressStatus = (status) => {
  if (status === 'completed' || status === 'success') return 'success'
  if (status === 'failed' || status === 'error') return 'exception'
  return null
}

watch(() => props.executionData, (newData) => {
  if (newData?.execution_history) {
    newData.execution_history.forEach((_, index) => {
      if (expandedHistoryItems[index] === undefined) {
        expandedHistoryItems[index] = false
      }
    })
  }
}, { immediate: true })
</script>

<style scoped>
.workflow-execution-display {
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

.execution-card {
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

.execution-info {
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

.history-section,
.graph-section,
.metadata-section {
  margin-top: 16px;
}

.history-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.history-item {
  border: 1px solid #e4e7ed;
  border-radius: 4px;
  overflow: hidden;
}

.history-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px;
  background: #fafafa;
  cursor: pointer;
}

.history-left {
  display: flex;
  align-items: center;
  gap: 8px;
}

.history-right {
  display: flex;
  align-items: center;
  gap: 8px;
}

.step-name {
  font-weight: 500;
  color: #303133;
}

.step-time {
  font-size: 12px;
  color: #909399;
}

.history-detail {
  padding: 12px;
  background: #fff;
  border-top: 1px solid #e4e7ed;
}

.detail-block {
  margin-bottom: 12px;
}

.detail-block:last-child {
  margin-bottom: 0;
}

.detail-label {
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

.error-block {
  padding: 8px;
  background: #fef0f0;
  border-radius: 4px;
}

.error-text {
  color: #F56C6C;
  font-size: 13px;
}

.detail-empty {
  text-align: center;
  color: #909399;
  font-size: 13px;
  padding: 8px;
}

.graph-content {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.subgraph-item {
  border: 1px solid #e4e7ed;
  border-radius: 4px;
  padding: 12px;
}

.subgraph-header {
  display: flex;
  align-items: center;
  gap: 8px;
  font-weight: 600;
  margin-bottom: 12px;
  padding-bottom: 8px;
  border-bottom: 1px solid #e4e7ed;
}

.nodes-list {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.node-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 12px;
  background: #f5f7fa;
  border-radius: 4px;
}

.node-name {
  font-size: 13px;
}

.node-time {
  font-size: 12px;
  color: #909399;
}

.empty-nodes,
.empty-graph {
  text-align: center;
  color: #909399;
  font-size: 13px;
  padding: 12px;
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
