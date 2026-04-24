<template>
  <div class="task-planning-display">
    <el-card v-if="loading" class="loading-card">
      <div class="loading-content">
        <el-icon class="is-loading" :size="32"><Loading /></el-icon>
        <span>加载规划数据...</span>
      </div>
    </el-card>

    <template v-else-if="planningData">
      <el-card class="planning-card">
        <template #header>
          <div class="card-header" @click="toggleSection('main')">
            <span class="title">
              <el-icon><List /></el-icon>
              任务规划数据
            </span>
            <div class="header-right">
              <el-tag :type="getPlanStatusType(planningData.status)">
                {{ getPlanStatusLabel(planningData.status) }}
              </el-tag>
              <el-icon class="collapse-icon" :class="{ 'is-expanded': expandedSections.main }">
                <ArrowDown />
              </el-icon>
            </div>
          </div>
        </template>

        <el-collapse-transition>
          <div v-show="expandedSections.main">
            <el-descriptions :column="2" border class="planning-info">
              <el-descriptions-item label="规划ID">
                {{ planningData.plan_id || '无' }}
              </el-descriptions-item>
              <el-descriptions-item label="规划状态">
                <el-tag :type="getPlanStatusType(planningData.status)" size="small">
                  {{ getPlanStatusLabel(planningData.status) }}
                </el-tag>
              </el-descriptions-item>
              <el-descriptions-item label="目标">
                {{ planningData.target || '无' }}
              </el-descriptions-item>
              <el-descriptions-item label="任务类型">
                {{ planningData.task_type || '无' }}
              </el-descriptions-item>
              <el-descriptions-item label="创建时间">
                {{ formatTimestamp(planningData.created_at) || '无' }}
              </el-descriptions-item>
              <el-descriptions-item label="预估时间">
                {{ planningData.estimated_duration ? `${planningData.estimated_duration}分钟` : '无' }}
              </el-descriptions-item>
            </el-descriptions>

            <div v-if="planningData.description" class="description-section">
              <div class="section-header" @click="toggleSection('description')">
                <span class="section-title">
                  <el-icon><Document /></el-icon>
                  任务描述
                </span>
                <el-icon class="collapse-icon" :class="{ 'is-expanded': expandedSections.description }">
                  <ArrowDown />
                </el-icon>
              </div>
              <el-collapse-transition>
                <div v-show="expandedSections.description" class="description-content">
                  {{ planningData.description || '无描述' }}
                </div>
              </el-collapse-transition>
            </div>

            <div v-if="planningData.steps?.length" class="steps-section">
              <div class="section-header" @click="toggleSection('steps')">
                <span class="section-title">
                  <el-icon><Finished /></el-icon>
                  执行步骤 ({{ planningData.steps.length }})
                </span>
                <el-icon class="collapse-icon" :class="{ 'is-expanded': expandedSections.steps }">
                  <ArrowDown />
                </el-icon>
              </div>
              <el-collapse-transition>
                <div v-show="expandedSections.steps" class="steps-list">
                  <div 
                    v-for="(step, index) in planningData.steps" 
                    :key="index"
                    class="step-item"
                  >
                    <div class="step-header" @click="toggleStepItem(index)">
                      <div class="step-left">
                        <span class="step-number">{{ index + 1 }}</span>
                        <span class="step-name">{{ step.name || step.task || `步骤 ${index + 1}` }}</span>
                        <el-tag v-if="step.priority" :type="getPriorityType(step.priority)" size="small">
                          P{{ step.priority }}
                        </el-tag>
                      </div>
                      <div class="step-right">
                        <el-tag v-if="step.status" :type="getStatusType(step.status)" size="small">
                          {{ getStatusLabel(step.status) }}
                        </el-tag>
                        <el-icon class="collapse-icon" :class="{ 'is-expanded': expandedStepItems[index] }">
                          <ArrowDown />
                        </el-icon>
                      </div>
                    </div>
                    <el-collapse-transition>
                      <div v-show="expandedStepItems[index]" class="step-detail">
                        <div v-if="step.description" class="detail-row">
                          <span class="detail-label">描述:</span>
                          <span class="detail-value">{{ step.description }}</span>
                        </div>
                        <div v-if="step.tool" class="detail-row">
                          <span class="detail-label">工具:</span>
                          <span class="detail-value">{{ step.tool }}</span>
                        </div>
                        <div v-if="step.target" class="detail-row">
                          <span class="detail-label">目标:</span>
                          <span class="detail-value">{{ step.target }}</span>
                        </div>
                        <div v-if="step.estimated_time" class="detail-row">
                          <span class="detail-label">预估时间:</span>
                          <span class="detail-value">{{ step.estimated_time }}秒</span>
                        </div>
                        <div v-if="step.dependencies?.length" class="detail-row">
                          <span class="detail-label">依赖步骤:</span>
                          <span class="detail-value">{{ step.dependencies.join(', ') }}</span>
                        </div>
                        <div v-if="step.parameters && Object.keys(step.parameters).length > 0" class="detail-block">
                          <span class="detail-label">参数配置:</span>
                          <pre class="detail-content">{{ JSON.stringify(step.parameters, null, 2) }}</pre>
                        </div>
                        <div v-if="step.conditions && Object.keys(step.conditions).length > 0" class="detail-block">
                          <span class="detail-label">执行条件:</span>
                          <pre class="detail-content">{{ JSON.stringify(step.conditions, null, 2) }}</pre>
                        </div>
                        <div v-if="!step.description && !step.tool && !step.target && !step.parameters && !step.conditions" class="detail-empty">
                          无详细数据
                        </div>
                      </div>
                    </el-collapse-transition>
                  </div>
                </div>
              </el-collapse-transition>
            </div>

            <div v-if="planningData.dependencies?.length" class="dependencies-section">
              <div class="section-header" @click="toggleSection('dependencies')">
                <span class="section-title">
                  <el-icon><Connection /></el-icon>
                  步骤依赖关系
                </span>
                <el-icon class="collapse-icon" :class="{ 'is-expanded': expandedSections.dependencies }">
                  <ArrowDown />
                </el-icon>
              </div>
              <el-collapse-transition>
                <div v-show="expandedSections.dependencies" class="dependencies-content">
                  <div 
                    v-for="(dep, index) in planningData.dependencies" 
                    :key="index"
                    class="dependency-item"
                  >
                    <span class="dep-from">{{ dep.from || dep.source }}</span>
                    <el-icon class="dep-arrow"><Right /></el-icon>
                    <span class="dep-to">{{ dep.to || dep.target }}</span>
                    <span v-if="dep.condition" class="dep-condition">({{ dep.condition }})</span>
                  </div>
                </div>
              </el-collapse-transition>
            </div>

            <div v-if="planningData.resources" class="resources-section">
              <div class="section-header" @click="toggleSection('resources')">
                <span class="section-title">
                  <el-icon><Coin /></el-icon>
                  资源需求
                </span>
                <el-icon class="collapse-icon" :class="{ 'is-expanded': expandedSections.resources }">
                  <ArrowDown />
                </el-icon>
              </div>
              <el-collapse-transition>
                <div v-show="expandedSections.resources" class="resources-content">
                  <el-descriptions :column="2" border>
                    <el-descriptions-item label="CPU">
                      {{ planningData.resources.cpu || '无' }}
                    </el-descriptions-item>
                    <el-descriptions-item label="内存">
                      {{ planningData.resources.memory || '无' }}
                    </el-descriptions-item>
                    <el-descriptions-item label="存储">
                      {{ planningData.resources.storage || '无' }}
                    </el-descriptions-item>
                    <el-descriptions-item label="网络">
                      {{ planningData.resources.network || '无' }}
                    </el-descriptions-item>
                  </el-descriptions>
                </div>
              </el-collapse-transition>
            </div>

            <div v-if="planningData.metadata && Object.keys(planningData.metadata).length > 0" class="metadata-section">
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
                  <pre>{{ JSON.stringify(planningData.metadata, null, 2) }}</pre>
                </div>
              </el-collapse-transition>
            </div>
          </div>
        </el-collapse-transition>
      </el-card>
    </template>

    <el-empty v-else description="暂无规划数据" />
  </div>
</template>

<script setup>
import { reactive, watch } from 'vue'
import { 
  Loading, 
  List, 
  Document, 
  Finished, 
  Connection, 
  Coin,
  Setting,
  ArrowDown,
  Right
} from '@element-plus/icons-vue'
import { WorkflowStatus, formatTimestamp } from '@/utils/workflowData'

const props = defineProps({
  planningData: {
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
  description: true,
  steps: true,
  dependencies: false,
  resources: false,
  metadata: false
})

const expandedStepItems = reactive({})

const toggleSection = (section) => {
  expandedSections[section] = !expandedSections[section]
}

const toggleStepItem = (index) => {
  expandedStepItems[index] = !expandedStepItems[index]
}

const getStatusType = (status) => {
  return WorkflowStatus.getType(status)
}

const getStatusLabel = (status) => {
  return WorkflowStatus.getLabel(status)
}

const getPlanStatusType = (status) => {
  const typeMap = {
    'draft': 'info',
    'pending': 'info',
    'approved': 'success',
    'running': 'primary',
    'completed': 'success',
    'failed': 'danger',
    'cancelled': 'warning'
  }
  return typeMap[status?.toLowerCase()] || 'info'
}

const getPlanStatusLabel = (status) => {
  const labelMap = {
    'draft': '草稿',
    'pending': '待执行',
    'approved': '已批准',
    'running': '执行中',
    'completed': '已完成',
    'failed': '失败',
    'cancelled': '已取消'
  }
  return labelMap[status?.toLowerCase()] || status || '未知'
}

const getPriorityType = (priority) => {
  if (priority <= 1) return 'danger'
  if (priority <= 3) return 'warning'
  return 'success'
}

watch(() => props.planningData, (newData) => {
  if (newData?.steps) {
    newData.steps.forEach((_, index) => {
      if (expandedStepItems[index] === undefined) {
        expandedStepItems[index] = false
      }
    })
  }
}, { immediate: true })
</script>

<style scoped>
.task-planning-display {
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

.planning-card {
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

.planning-info {
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

.description-section,
.steps-section,
.dependencies-section,
.resources-section,
.metadata-section {
  margin-top: 16px;
}

.description-content {
  padding: 12px;
  background: #f5f7fa;
  border-radius: 4px;
  line-height: 1.6;
  color: #606266;
}

.steps-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.step-item {
  border: 1px solid #e4e7ed;
  border-radius: 4px;
  overflow: hidden;
}

.step-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px;
  background: #fafafa;
  cursor: pointer;
}

.step-left {
  display: flex;
  align-items: center;
  gap: 8px;
}

.step-right {
  display: flex;
  align-items: center;
  gap: 8px;
}

.step-number {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 24px;
  height: 24px;
  background: #409EFF;
  color: #fff;
  border-radius: 50%;
  font-size: 12px;
  font-weight: 600;
}

.step-name {
  font-weight: 500;
  color: #303133;
}

.step-detail {
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
}

.detail-row .detail-value {
  color: #303133;
  font-size: 13px;
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

.dependencies-content {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.dependency-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  background: #f5f7fa;
  border-radius: 4px;
}

.dep-from {
  font-weight: 500;
  color: #409EFF;
}

.dep-arrow {
  color: #909399;
}

.dep-to {
  font-weight: 500;
  color: #67C23A;
}

.dep-condition {
  font-size: 12px;
  color: #909399;
  margin-left: 8px;
}

.resources-content {
  padding: 0;
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
