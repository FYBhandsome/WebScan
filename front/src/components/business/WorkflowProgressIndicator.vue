<template>
  <div class="workflow-progress-indicator">
    <div v-if="loading" class="loading-container">
      <el-icon class="is-loading" :size="32"><Loading /></el-icon>
      <span>加载进度数据...</span>
    </div>

    <template v-else-if="progressData">
      <div class="progress-header">
        <div class="header-left">
          <el-icon><TrendCharts /></el-icon>
          <span class="title">工作流进度</span>
        </div>
        <div class="header-right">
          <el-tag :type="getStatusType(progressData.status)" effect="dark">
            <el-icon v-if="progressData.status === 'running'" class="is-loading"><Loading /></el-icon>
            {{ getStatusLabel(progressData.status) }}
          </el-tag>
        </div>
      </div>

      <div class="main-progress">
        <div class="progress-info">
          <span class="progress-label">总体进度</span>
          <span class="progress-value">{{ progressData.progress }}%</span>
        </div>
        <el-progress
          :percentage="progressData.progress"
          :status="getProgressStatus(progressData.status)"
          :stroke-width="progressStrokeWidth"
          :text-inside="true"
          :class="['main-progress-bar', `status-${progressData.status}`]"
        />
        <div class="progress-meta">
          <span v-if="progressData.currentStep && progressData.totalSteps">
            步骤: {{ progressData.currentStep }} / {{ progressData.totalSteps }}
          </span>
          <span v-if="progressData.duration">
            耗时: {{ formatDuration(progressData.duration) }}
          </span>
          <span v-if="estimatedTimeRemaining">
            预计剩余: {{ estimatedTimeRemaining }}
          </span>
        </div>
      </div>

      <div class="progress-stats">
        <div class="stat-card completed">
          <div class="stat-icon">
            <el-icon><CircleCheckFilled /></el-icon>
          </div>
          <div class="stat-content">
            <div class="stat-value">{{ stepStats.completed }}</div>
            <div class="stat-label">已完成</div>
          </div>
        </div>
        <div class="stat-card running">
          <div class="stat-icon">
            <el-icon class="is-loading"><Loading /></el-icon>
          </div>
          <div class="stat-content">
            <div class="stat-value">{{ stepStats.running }}</div>
            <div class="stat-label">运行中</div>
          </div>
        </div>
        <div class="stat-card failed">
          <div class="stat-icon">
            <el-icon><CircleCloseFilled /></el-icon>
          </div>
          <div class="stat-content">
            <div class="stat-value">{{ stepStats.failed }}</div>
            <div class="stat-label">失败</div>
          </div>
        </div>
        <div class="stat-card pending">
          <div class="stat-icon">
            <el-icon><Clock /></el-icon>
          </div>
          <div class="stat-content">
            <div class="stat-value">{{ stepStats.pending }}</div>
            <div class="stat-label">等待中</div>
          </div>
        </div>
      </div>

      <div v-if="showStepProgress && stepProgress.length > 0" class="step-progress">
        <div class="section-header">
          <span class="section-title">步骤进度</span>
          <el-switch v-model="showAllSteps" active-text="全部" inactive-text="当前" />
        </div>
        <div class="steps-container">
          <div
            v-for="(step, index) in displayedSteps"
            :key="step.id || index"
            :class="['step-item', `status-${step.status}`]"
          >
            <div class="step-indicator">
              <div :class="['step-dot', step.status]">
                <el-icon v-if="step.status === 'running'" class="is-loading"><Loading /></el-icon>
                <el-icon v-else-if="step.status === 'completed'"><Check /></el-icon>
                <el-icon v-else-if="step.status === 'failed'"><Close /></el-icon>
                <span v-else>{{ index + 1 }}</span>
              </div>
              <div v-if="index < displayedSteps.length - 1" class="step-line"></div>
            </div>
            <div class="step-content">
              <div class="step-name">{{ step.name }}</div>
              <div class="step-info">
                <el-tag :type="getStatusType(step.status)" size="small">
                  {{ getStatusLabel(step.status) }}
                </el-tag>
                <span v-if="step.duration" class="step-duration">{{ formatDuration(step.duration) }}</span>
              </div>
              <el-progress
                v-if="step.status === 'running' && step.progress !== undefined"
                :percentage="step.progress"
                :stroke-width="4"
                :show-text="false"
                class="step-progress-bar"
              />
            </div>
          </div>
        </div>
      </div>

      <div v-if="progressData.target" class="target-info">
        <el-icon><Aim /></el-icon>
        <span>目标: {{ progressData.target }}</span>
      </div>

      <div v-if="progressData.startTime" class="time-info">
        <div class="time-item">
          <el-icon><Clock /></el-icon>
          <span>开始时间: {{ formatTimestamp(progressData.startTime) }}</span>
        </div>
        <div v-if="progressData.endTime" class="time-item">
          <el-icon><Finished /></el-icon>
          <span>结束时间: {{ formatTimestamp(progressData.endTime) }}</span>
        </div>
      </div>
    </template>

    <el-empty v-else description="暂无进度数据" />
  </div>
</template>

<script setup>
import { ref, computed, watch, onMounted, onUnmounted } from 'vue'
import { 
  Loading, 
  TrendCharts,
  CircleCheckFilled, 
  CircleCloseFilled, 
  Clock,
  Check,
  Close,
  Aim,
  Finished
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
  showStepProgress: {
    type: Boolean,
    default: true
  },
  progressStrokeWidth: {
    type: Number,
    default: 20
  },
  autoUpdate: {
    type: Boolean,
    default: false
  },
  updateInterval: {
    type: Number,
    default: 1000
  }
})

const emit = defineEmits(['progress-update', 'complete', 'error'])

const showAllSteps = ref(false)
const internalProgress = ref(null)
let updateTimer = null

const progressData = computed(() => {
  if (internalProgress.value) return internalProgress.value
  if (!props.executionData) return null
  return WorkflowDataProcessor.processWorkflowData(props.executionData)
})

const stepStats = computed(() => {
  if (!progressData.value?.execution_history) {
    return { completed: 0, running: 0, failed: 0, pending: 0 }
  }
  
  const history = progressData.value.execution_history
  return {
    completed: history.filter(h => ['completed', 'success'].includes(h.status)).length,
    running: history.filter(h => h.status === 'running').length,
    failed: history.filter(h => ['failed', 'error'].includes(h.status)).length,
    pending: history.filter(h => h.status === 'pending').length
  }
})

const stepProgress = computed(() => {
  if (!progressData.value?.execution_history) return []
  
  return progressData.value.execution_history.map((step, index) => ({
    id: step.node_id || `step-${index}`,
    name: step.node_name || step.task || `步骤 ${index + 1}`,
    status: step.status,
    progress: step.progress,
    duration: step.execution_time
  }))
})

const displayedSteps = computed(() => {
  if (showAllSteps.value) return stepProgress.value
  
  const currentIndex = stepProgress.value.findIndex(s => s.status === 'running')
  if (currentIndex === -1) {
    const lastCompleted = stepProgress.value.map((s, i) => ({ ...s, index: i }))
      .filter(s => s.status === 'completed' || s.status === 'failed')
      .pop()
    if (lastCompleted) {
      return stepProgress.value.slice(Math.max(0, lastCompleted.index - 2), lastCompleted.index + 3)
    }
    return stepProgress.value.slice(0, 5)
  }
  
  const start = Math.max(0, currentIndex - 2)
  const end = Math.min(stepProgress.value.length, currentIndex + 3)
  return stepProgress.value.slice(start, end)
})

const estimatedTimeRemaining = computed(() => {
  if (!progressData.value || progressData.value.status !== 'running') return null
  if (progressData.value.progress <= 0 || progressData.value.progress >= 100) return null
  
  const elapsed = progressData.value.duration || 0
  const remaining = (elapsed / progressData.value.progress) * (100 - progressData.value.progress)
  
  return formatDurationUtil(remaining)
})

const getStatusType = (status) => WorkflowStatus.getType(status)
const getStatusLabel = (status) => WorkflowStatus.getLabel(status)
const formatDuration = (seconds) => formatDurationUtil(seconds)
const formatTimestamp = (timestamp) => formatTimestampUtil(timestamp)

const getProgressStatus = (status) => {
  if (status === 'completed' || status === 'success') return 'success'
  if (status === 'failed' || status === 'error') return 'exception'
  return null
}

const updateProgress = () => {
  if (!props.autoUpdate || !progressData.value) return
  
  if (progressData.value.status === 'running') {
    emit('progress-update', progressData.value)
  } else if (WorkflowStatus.isFinished(progressData.value.status)) {
    if (progressData.value.status === 'completed' || progressData.value.status === 'success') {
      emit('complete', progressData.value)
    } else if (progressData.value.status === 'failed' || progressData.value.status === 'error') {
      emit('error', progressData.value)
    }
    stopAutoUpdate()
  }
}

const startAutoUpdate = () => {
  if (updateTimer) return
  updateTimer = setInterval(updateProgress, props.updateInterval)
}

const stopAutoUpdate = () => {
  if (updateTimer) {
    clearInterval(updateTimer)
    updateTimer = null
  }
}

const setProgress = (data) => {
  internalProgress.value = data
}

watch(() => props.autoUpdate, (enabled) => {
  if (enabled) {
    startAutoUpdate()
  } else {
    stopAutoUpdate()
  }
}, { immediate: true })

onMounted(() => {
  if (props.autoUpdate) {
    startAutoUpdate()
  }
})

onUnmounted(() => {
  stopAutoUpdate()
})

defineExpose({
  setProgress,
  startAutoUpdate,
  stopAutoUpdate
})
</script>

<style scoped>
.workflow-progress-indicator {
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

.progress-header {
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

.main-progress {
  margin-bottom: 20px;
}

.progress-info {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.progress-label {
  font-size: 14px;
  color: #606266;
}

.progress-value {
  font-size: 20px;
  font-weight: 600;
  color: #303133;
}

.main-progress-bar {
  margin-bottom: 8px;
}

.main-progress-bar.status-running :deep(.el-progress-bar__inner) {
  background: linear-gradient(90deg, #409EFF, #79bbff);
  animation: progress-stripes 1s linear infinite;
}

.main-progress-bar.status-completed :deep(.el-progress-bar__inner) {
  background: linear-gradient(90deg, #67C23A, #95d475);
}

.main-progress-bar.status-failed :deep(.el-progress-bar__inner) {
  background: linear-gradient(90deg, #F56C6C, #fab6b6);
}

@keyframes progress-stripes {
  from {
    background-position: 40px 0;
  }
  to {
    background-position: 0 0;
  }
}

.progress-meta {
  display: flex;
  gap: 16px;
  font-size: 12px;
  color: #909399;
}

.progress-stats {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
  margin-bottom: 20px;
}

.stat-card {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 16px;
  background: #f5f7fa;
  border-radius: 8px;
  border-left: 3px solid #909399;
}

.stat-card.completed { border-left-color: #67C23A; }
.stat-card.running { border-left-color: #409EFF; }
.stat-card.failed { border-left-color: #F56C6C; }
.stat-card.pending { border-left-color: #E6A23C; }

.stat-icon {
  width: 36px;
  height: 36px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 18px;
  background: #fff;
}

.stat-card.completed .stat-icon { color: #67C23A; }
.stat-card.running .stat-icon { color: #409EFF; }
.stat-card.failed .stat-icon { color: #F56C6C; }
.stat-card.pending .stat-icon { color: #E6A23C; }

.stat-content {
  flex: 1;
}

.stat-value {
  font-size: 20px;
  font-weight: 600;
  color: #303133;
}

.stat-label {
  font-size: 12px;
  color: #909399;
}

.step-progress {
  margin-bottom: 20px;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}

.section-title {
  font-size: 14px;
  font-weight: 500;
  color: #303133;
}

.steps-container {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.step-item {
  display: flex;
  gap: 12px;
  padding: 12px;
  background: #fafafa;
  border-radius: 6px;
  transition: all 0.2s ease;
}

.step-item:hover {
  background: #f0f2f5;
}

.step-item.status-running {
  background: #ecf5ff;
  border: 1px solid #b3d8ff;
}

.step-item.status-completed {
  background: #f0f9eb;
}

.step-item.status-failed {
  background: #fef0f0;
}

.step-indicator {
  display: flex;
  flex-direction: column;
  align-items: center;
}

.step-dot {
  width: 28px;
  height: 28px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 12px;
  font-weight: 600;
  background: #e4e7ed;
  color: #909399;
}

.step-dot.completed {
  background: #67C23A;
  color: #fff;
}

.step-dot.running {
  background: #409EFF;
  color: #fff;
}

.step-dot.failed {
  background: #F56C6C;
  color: #fff;
}

.step-dot.pending {
  background: #E6A23C;
  color: #fff;
}

.step-line {
  width: 2px;
  flex: 1;
  min-height: 20px;
  background: #e4e7ed;
  margin-top: 4px;
}

.step-content {
  flex: 1;
}

.step-name {
  font-weight: 500;
  color: #303133;
  margin-bottom: 6px;
}

.step-info {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 6px;
}

.step-duration {
  font-size: 12px;
  color: #909399;
}

.step-progress-bar {
  margin-top: 6px;
}

.target-info {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px;
  background: #f5f7fa;
  border-radius: 6px;
  margin-bottom: 12px;
  font-size: 13px;
  color: #606266;
}

.target-info .el-icon {
  color: #409EFF;
}

.time-info {
  display: flex;
  gap: 16px;
  padding: 12px;
  background: #f5f7fa;
  border-radius: 6px;
}

.time-item {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: #909399;
}

.time-item .el-icon {
  color: #409EFF;
}
</style>
