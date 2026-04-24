<template>
  <div class="workflow-timeline">
    <div v-if="loading" class="loading-container">
      <el-icon class="is-loading" :size="32"><Loading /></el-icon>
      <span>加载时间线数据...</span>
    </div>

    <template v-else-if="timelineData.length > 0">
      <div class="timeline-header">
        <div class="header-left">
          <el-icon><Clock /></el-icon>
          <span class="title">执行时间线</span>
          <el-tag size="small" type="info">{{ timelineData.length }} 步骤</el-tag>
        </div>
        <div class="header-right">
          <el-switch
            v-model="showDetails"
            active-text="显示详情"
            inactive-text="简洁模式"
          />
          <el-button-group size="small">
            <el-button 
              :type="viewMode === 'timeline' ? 'primary' : 'default'"
              @click="viewMode = 'timeline'"
            >
              <el-icon><Clock /></el-icon>
              时间线
            </el-button>
            <el-button 
              :type="viewMode === 'list' ? 'primary' : 'default'"
              @click="viewMode = 'list'"
            >
              <el-icon><List /></el-icon>
              列表
            </el-button>
          </el-button-group>
        </div>
      </div>

      <div class="timeline-stats">
        <div class="stat-item">
          <span class="stat-value success">{{ completedCount }}</span>
          <span class="stat-label">已完成</span>
        </div>
        <div class="stat-item">
          <span class="stat-value primary">{{ runningCount }}</span>
          <span class="stat-label">运行中</span>
        </div>
        <div class="stat-item">
          <span class="stat-value danger">{{ failedCount }}</span>
          <span class="stat-label">失败</span>
        </div>
        <div class="stat-item">
          <span class="stat-value info">{{ pendingCount }}</span>
          <span class="stat-label">等待中</span>
        </div>
        <div class="stat-item">
          <span class="stat-value">{{ totalDuration }}</span>
          <span class="stat-label">总耗时</span>
        </div>
      </div>

      <el-timeline v-if="viewMode === 'timeline'" class="timeline-content">
        <el-timeline-item
          v-for="(step, index) in timelineData"
          :key="step.id || index"
          :type="getStepType(step.status)"
          :timestamp="formatTimestamp(step.timestamp)"
          :hollow="step.status === 'pending'"
          placement="top"
          :class="['timeline-step', `status-${step.status}`]"
        >
          <div class="step-card" @click="toggleStepDetail(index)">
            <div class="step-header">
              <div class="step-left">
                <el-tag :type="getStatusType(step.status)" size="small" effect="dark">
                  <el-icon v-if="step.status === 'running'" class="is-loading"><Loading /></el-icon>
                  <el-icon v-else-if="step.status === 'completed'"><CircleCheckFilled /></el-icon>
                  <el-icon v-else-if="step.status === 'failed'"><CircleCloseFilled /></el-icon>
                  <el-icon v-else><Clock /></el-icon>
                </el-tag>
                <span class="step-number">步骤 {{ step.stepNumber || index + 1 }}</span>
                <span class="step-title">{{ step.title }}</span>
              </div>
              <div class="step-right">
                <span v-if="step.duration" class="step-duration">
                  <el-icon><Timer /></el-icon>
                  {{ formatDuration(step.duration) }}
                </span>
                <el-icon 
                  v-if="showDetails && (step.content?.input_params || step.content?.output_data || step.content?.error)"
                  class="expand-icon"
                  :class="{ 'is-expanded': expandedSteps[index] }"
                >
                  <ArrowDown />
                </el-icon>
              </div>
            </div>

            <el-collapse-transition>
              <div v-show="showDetails && expandedSteps[index]" class="step-details">
                <div v-if="step.content?.input_params && Object.keys(step.content.input_params).length > 0" class="detail-block">
                  <div class="detail-label">
                    <el-icon><Document /></el-icon>
                    输入参数
                  </div>
                  <pre class="detail-content">{{ JSON.stringify(step.content.input_params, null, 2) }}</pre>
                </div>
                <div v-if="step.content?.output_data && Object.keys(step.content.output_data).length > 0" class="detail-block">
                  <div class="detail-label">
                    <el-icon><Document /></el-icon>
                    输出数据
                  </div>
                  <pre class="detail-content">{{ JSON.stringify(step.content.output_data, null, 2) }}</pre>
                </div>
                <div v-if="step.content?.error" class="detail-block error-block">
                  <div class="detail-label">
                    <el-icon><WarningFilled /></el-icon>
                    错误信息
                  </div>
                  <div class="error-content">{{ step.content.error }}</div>
                </div>
              </div>
            </el-collapse-transition>
          </div>
        </el-timeline-item>
      </el-timeline>

      <div v-else class="list-content">
        <el-table :data="timelineData" stripe style="width: 100%">
          <el-table-column type="index" label="#" width="50" />
          <el-table-column label="步骤名称" min-width="200">
            <template #default="{ row }">
              <div class="list-step-name">
                <el-tag :type="getStatusType(row.status)" size="small">
                  {{ getStatusLabel(row.status) }}
                </el-tag>
                <span>{{ row.title }}</span>
              </div>
            </template>
          </el-table-column>
          <el-table-column label="状态" width="100" align="center">
            <template #default="{ row }">
              <el-tag :type="getStatusType(row.status)" size="small">
                {{ getStatusLabel(row.status) }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="耗时" width="100" align="center">
            <template #default="{ row }">
              <span v-if="row.duration">{{ formatDuration(row.duration) }}</span>
              <span v-else>-</span>
            </template>
          </el-table-column>
          <el-table-column label="时间" width="180">
            <template #default="{ row }">
              <span class="timestamp">{{ formatTimestamp(row.timestamp) }}</span>
            </template>
          </el-table-column>
          <el-table-column v-if="showDetails" label="操作" width="80" align="center">
            <template #default="{ row, $index }">
              <el-button 
                v-if="row.content?.input_params || row.content?.output_data || row.content?.error"
                type="primary" 
                link 
                size="small"
                @click="showStepDialog(row)"
              >
                详情
              </el-button>
            </template>
          </el-table-column>
        </el-table>
      </div>
    </template>

    <el-empty v-else description="暂无执行记录" />

    <el-dialog
      v-model="dialogVisible"
      :title="`步骤详情 - ${currentStep?.title || ''}`"
      width="600px"
      destroy-on-close
    >
      <div v-if="currentStep" class="step-dialog-content">
        <div v-if="currentStep.content?.input_params && Object.keys(currentStep.content.input_params).length > 0" class="dialog-block">
          <div class="dialog-label">输入参数</div>
          <pre class="dialog-content">{{ JSON.stringify(currentStep.content.input_params, null, 2) }}</pre>
        </div>
        <div v-if="currentStep.content?.output_data && Object.keys(currentStep.content.output_data).length > 0" class="dialog-block">
          <div class="dialog-label">输出数据</div>
          <pre class="dialog-content">{{ JSON.stringify(currentStep.content.output_data, null, 2) }}</pre>
        </div>
        <div v-if="currentStep.content?.error" class="dialog-block error">
          <div class="dialog-label">错误信息</div>
          <div class="dialog-error">{{ currentStep.content.error }}</div>
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, watch, reactive } from 'vue'
import { 
  Loading, 
  Clock, 
  List, 
  CircleCheckFilled, 
  CircleCloseFilled, 
  Timer,
  ArrowDown,
  Document,
  WarningFilled
} from '@element-plus/icons-vue'
import { 
  WorkflowStatus, 
  WorkflowDataProcessor,
  formatDuration as formatDurationUtil,
  formatTimestamp as formatTimestampUtil
} from '@/utils/workflowData'

const props = defineProps({
  executionData: {
    type: Object,
    default: null
  },
  loading: {
    type: Boolean,
    default: false
  },
  autoExpand: {
    type: Boolean,
    default: false
  }
})

const viewMode = ref('timeline')
const showDetails = ref(true)
const expandedSteps = reactive({})
const dialogVisible = ref(false)
const currentStep = ref(null)

const timelineData = computed(() => {
  if (!props.executionData) return []
  return WorkflowDataProcessor.getTimelineData(
    WorkflowDataProcessor.processWorkflowData(props.executionData)
  )
})

const completedCount = computed(() => 
  timelineData.value.filter(s => s.status === 'completed').length
)

const runningCount = computed(() => 
  timelineData.value.filter(s => s.status === 'running').length
)

const failedCount = computed(() => 
  timelineData.value.filter(s => s.status === 'failed').length
)

const pendingCount = computed(() => 
  timelineData.value.filter(s => s.status === 'pending').length
)

const totalDuration = computed(() => {
  const total = timelineData.value.reduce((sum, s) => sum + (s.duration || 0), 0)
  return formatDurationUtil(total)
})

const toggleStepDetail = (index) => {
  expandedSteps[index] = !expandedSteps[index]
}

const showStepDialog = (step) => {
  currentStep.value = step
  dialogVisible.value = true
}

const getStatusType = (status) => WorkflowStatus.getType(status)
const getStatusLabel = (status) => WorkflowStatus.getLabel(status)
const getStepType = (status) => WorkflowStatus.getType(status)
const formatTimestamp = (timestamp) => formatTimestampUtil(timestamp)
const formatDuration = (seconds) => formatDurationUtil(seconds)

watch(() => props.executionData, (newData) => {
  if (newData && props.autoExpand) {
    timelineData.value.forEach((_, index) => {
      expandedSteps[index] = false
    })
  }
}, { immediate: true })
</script>

<style scoped>
.workflow-timeline {
  width: 100%;
  background: #fff;
  border-radius: 8px;
  padding: 16px;
}

.loading-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 200px;
  gap: 16px;
  color: #909399;
}

.timeline-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
  padding-bottom: 12px;
  border-bottom: 1px solid #e4e7ed;
}

.header-left {
  display: flex;
  align-items: center;
  gap: 8px;
}

.header-left .title {
  font-size: 16px;
  font-weight: 600;
  color: #303133;
}

.header-right {
  display: flex;
  align-items: center;
  gap: 12px;
}

.timeline-stats {
  display: flex;
  gap: 24px;
  margin-bottom: 20px;
  padding: 12px 16px;
  background: #f5f7fa;
  border-radius: 6px;
}

.stat-item {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 4px;
}

.stat-value {
  font-size: 20px;
  font-weight: 600;
  color: #303133;
}

.stat-value.success { color: #67C23A; }
.stat-value.primary { color: #409EFF; }
.stat-value.danger { color: #F56C6C; }
.stat-value.info { color: #909399; }

.stat-label {
  font-size: 12px;
  color: #909399;
}

.timeline-content {
  padding: 8px 0;
}

.timeline-step {
  transition: all 0.3s ease;
}

.step-card {
  background: #fafafa;
  border-radius: 6px;
  padding: 12px 16px;
  cursor: pointer;
  transition: all 0.2s ease;
  border: 1px solid transparent;
}

.step-card:hover {
  background: #f0f2f5;
  border-color: #dcdfe6;
}

.step-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.step-left {
  display: flex;
  align-items: center;
  gap: 8px;
}

.step-number {
  font-size: 12px;
  color: #909399;
  font-weight: 500;
}

.step-title {
  font-weight: 500;
  color: #303133;
}

.step-right {
  display: flex;
  align-items: center;
  gap: 12px;
}

.step-duration {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 12px;
  color: #909399;
}

.expand-icon {
  transition: transform 0.3s ease;
  color: #909399;
}

.expand-icon.is-expanded {
  transform: rotate(180deg);
}

.step-details {
  margin-top: 12px;
  padding-top: 12px;
  border-top: 1px dashed #dcdfe6;
}

.detail-block {
  margin-bottom: 12px;
}

.detail-block:last-child {
  margin-bottom: 0;
}

.detail-label {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: #606266;
  margin-bottom: 6px;
  font-weight: 500;
}

.detail-content {
  margin: 0;
  padding: 8px 12px;
  background: #fff;
  border-radius: 4px;
  font-size: 12px;
  font-family: 'Consolas', 'Monaco', monospace;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 200px;
  overflow: auto;
  border: 1px solid #e4e7ed;
}

.error-block .detail-label {
  color: #F56C6C;
}

.error-content {
  padding: 8px 12px;
  background: #fef0f0;
  border-radius: 4px;
  color: #F56C6C;
  font-size: 13px;
  border: 1px solid #fbc4c4;
}

.list-content {
  margin-top: 8px;
}

.list-step-name {
  display: flex;
  align-items: center;
  gap: 8px;
}

.timestamp {
  font-size: 12px;
  color: #909399;
}

.step-dialog-content {
  max-height: 60vh;
  overflow-y: auto;
}

.dialog-block {
  margin-bottom: 16px;
}

.dialog-block:last-child {
  margin-bottom: 0;
}

.dialog-label {
  font-size: 13px;
  font-weight: 500;
  color: #606266;
  margin-bottom: 8px;
}

.dialog-content {
  margin: 0;
  padding: 12px;
  background: #f5f7fa;
  border-radius: 4px;
  font-size: 12px;
  font-family: 'Consolas', 'Monaco', monospace;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 300px;
  overflow: auto;
}

.dialog-block.error .dialog-label {
  color: #F56C6C;
}

.dialog-error {
  padding: 12px;
  background: #fef0f0;
  border-radius: 4px;
  color: #F56C6C;
  font-size: 13px;
  border: 1px solid #fbc4c4;
}

.status-running .step-card {
  border-left: 3px solid #409EFF;
}

.status-completed .step-card {
  border-left: 3px solid #67C23A;
}

.status-failed .step-card {
  border-left: 3px solid #F56C6C;
}

.status-pending .step-card {
  border-left: 3px solid #909399;
}
</style>
