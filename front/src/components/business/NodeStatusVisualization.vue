<template>
  <div class="node-status-visualization">
    <div v-if="loading" class="loading-container">
      <el-icon class="is-loading" :size="32"><Loading /></el-icon>
      <span>加载节点状态...</span>
    </div>

    <template v-else-if="nodes.length > 0">
      <div class="visualization-header">
        <div class="header-left">
          <el-icon><Share /></el-icon>
          <span class="title">节点状态可视化</span>
          <el-tag size="small" type="info">{{ nodes.length }} 节点</el-tag>
        </div>
        <div class="header-right">
          <el-radio-group v-model="viewMode" size="small">
            <el-radio-button value="grid">网格</el-radio-button>
            <el-radio-button value="flow">流程图</el-radio-button>
            <el-radio-button value="tree">树形</el-radio-button>
          </el-radio-group>
          <el-button size="small" @click="refreshNodes">
            <el-icon><Refresh /></el-icon>
            刷新
          </el-button>
        </div>
      </div>

      <div class="status-legend">
        <div class="legend-item" @click="filterByStatus('all')">
          <span class="legend-dot all"></span>
          <span>全部 ({{ nodes.length }})</span>
        </div>
        <div class="legend-item" @click="filterByStatus('completed')">
          <span class="legend-dot completed"></span>
          <span>已完成 ({{ completedCount }})</span>
        </div>
        <div class="legend-item" @click="filterByStatus('running')">
          <span class="legend-dot running"></span>
          <span>运行中 ({{ runningCount }})</span>
        </div>
        <div class="legend-item" @click="filterByStatus('failed')">
          <span class="legend-dot failed"></span>
          <span>失败 ({{ failedCount }})</span>
        </div>
        <div class="legend-item" @click="filterByStatus('pending')">
          <span class="legend-dot pending"></span>
          <span>等待中 ({{ pendingCount }})</span>
        </div>
      </div>

      <div v-if="viewMode === 'grid'" class="grid-view">
        <div class="nodes-grid">
          <div
            v-for="node in filteredNodes"
            :key="node.id"
            :class="['node-card', `status-${node.status}`, { 'is-selected': selectedNode?.id === node.id }]"
            @click="selectNode(node)"
          >
            <div class="node-status-indicator">
              <div :class="['status-icon', node.status]">
                <el-icon v-if="node.status === 'running'" class="is-loading"><Loading /></el-icon>
                <el-icon v-else-if="node.status === 'completed'"><CircleCheckFilled /></el-icon>
                <el-icon v-else-if="node.status === 'failed'"><CircleCloseFilled /></el-icon>
                <el-icon v-else><Clock /></el-icon>
              </div>
            </div>
            <div class="node-info">
              <div class="node-name">{{ node.name }}</div>
              <div class="node-meta">
                <span class="node-type">{{ node.type || 'default' }}</span>
                <span v-if="node.duration" class="node-duration">{{ formatDuration(node.duration) }}</span>
              </div>
            </div>
            <div v-if="node.subgraph" class="node-subgraph">
              <el-tag size="small" type="info" effect="plain">{{ node.subgraph }}</el-tag>
            </div>
          </div>
        </div>
      </div>

      <div v-else-if="viewMode === 'flow'" class="flow-view">
        <div class="flow-container">
          <div
            v-for="(subgraph, index) in subgraphs"
            :key="subgraph.id || index"
            class="subgraph-section"
          >
            <div class="subgraph-header">
              <el-icon><FolderOpened /></el-icon>
              <span class="subgraph-name">{{ subgraph.name }}</span>
              <el-tag :type="getStatusType(subgraph.status)" size="small">
                {{ getStatusLabel(subgraph.status) }}
              </el-tag>
            </div>
            <div class="subgraph-nodes">
              <div class="flow-line"></div>
              <div
                v-for="node in subgraph.nodes"
                :key="node.id"
                :class="['flow-node', `status-${node.status}`]"
                @click="selectNode(node)"
              >
                <div class="flow-node-connector before"></div>
                <div class="flow-node-content">
                  <div :class="['node-status-icon', node.status]">
                    <el-icon v-if="node.status === 'running'" class="is-loading"><Loading /></el-icon>
                    <el-icon v-else-if="node.status === 'completed'"><CircleCheckFilled /></el-icon>
                    <el-icon v-else-if="node.status === 'failed'"><CircleCloseFilled /></el-icon>
                    <el-icon v-else><Clock /></el-icon>
                  </div>
                  <div class="flow-node-name">{{ node.name }}</div>
                  <div v-if="node.duration" class="flow-node-duration">{{ formatDuration(node.duration) }}</div>
                </div>
                <div class="flow-node-connector after"></div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div v-else-if="viewMode === 'tree'" class="tree-view">
        <el-tree
          :data="treeData"
          :props="treeProps"
          node-key="id"
          default-expand-all
          :expand-on-click-node="false"
        >
          <template #default="{ node, data }">
            <div :class="['tree-node', `status-${data.status}`]">
              <div class="tree-node-content">
                <div :class="['tree-status-icon', data.status]">
                  <el-icon v-if="data.status === 'running'" class="is-loading"><Loading /></el-icon>
                  <el-icon v-else-if="data.status === 'completed'"><CircleCheckFilled /></el-icon>
                  <el-icon v-else-if="data.status === 'failed'"><CircleCloseFilled /></el-icon>
                  <el-icon v-else><Clock /></el-icon>
                </div>
                <span class="tree-node-label">{{ node.label }}</span>
                <el-tag v-if="data.status" :type="getStatusType(data.status)" size="small">
                  {{ getStatusLabel(data.status) }}
                </el-tag>
                <span v-if="data.duration" class="tree-node-duration">{{ formatDuration(data.duration) }}</span>
              </div>
            </div>
          </template>
        </el-tree>
      </div>

      <el-drawer
        v-model="drawerVisible"
        :title="selectedNode?.name || '节点详情'"
        direction="rtl"
        size="400px"
      >
        <div v-if="selectedNode" class="node-detail">
          <el-descriptions :column="1" border>
            <el-descriptions-item label="节点ID">{{ selectedNode.id }}</el-descriptions-item>
            <el-descriptions-item label="节点名称">{{ selectedNode.name }}</el-descriptions-item>
            <el-descriptions-item label="状态">
              <el-tag :type="getStatusType(selectedNode.status)">
                {{ getStatusLabel(selectedNode.status) }}
              </el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="类型">{{ selectedNode.type || 'default' }}</el-descriptions-item>
            <el-descriptions-item v-if="selectedNode.duration" label="执行时间">
              {{ formatDuration(selectedNode.duration) }}
            </el-descriptions-item>
            <el-descriptions-item v-if="selectedNode.subgraph" label="所属子图">
              {{ selectedNode.subgraph }}
            </el-descriptions-item>
          </el-descriptions>

          <div v-if="selectedNode.inputParams && Object.keys(selectedNode.inputParams).length > 0" class="detail-section">
            <div class="section-title">输入参数</div>
            <pre class="section-content">{{ JSON.stringify(selectedNode.inputParams, null, 2) }}</pre>
          </div>

          <div v-if="selectedNode.outputData && Object.keys(selectedNode.outputData).length > 0" class="detail-section">
            <div class="section-title">输出数据</div>
            <pre class="section-content">{{ JSON.stringify(selectedNode.outputData, null, 2) }}</pre>
          </div>

          <div v-if="selectedNode.error" class="detail-section error">
            <div class="section-title">错误信息</div>
            <div class="error-content">{{ selectedNode.error }}</div>
          </div>
        </div>
      </el-drawer>
    </template>

    <el-empty v-else description="暂无节点数据" />
  </div>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { 
  Loading, 
  Share, 
  Refresh,
  CircleCheckFilled, 
  CircleCloseFilled, 
  Clock,
  FolderOpened
} from '@element-plus/icons-vue'
import { 
  WorkflowStatus, 
  WorkflowDataProcessor,
  formatDuration as formatDurationUtil
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

const emit = defineEmits(['node-select', 'refresh'])

const viewMode = ref('grid')
const statusFilter = ref('all')
const selectedNode = ref(null)
const drawerVisible = ref(false)

const treeProps = {
  children: 'children',
  label: 'name'
}

const processedData = computed(() => {
  if (!props.executionData) return null
  return WorkflowDataProcessor.processWorkflowData(props.executionData)
})

const graphData = computed(() => {
  if (!processedData.value) return null
  return WorkflowDataProcessor.getGraphVisualizationData(processedData.value)
})

const nodes = computed(() => {
  return graphData.value?.nodes || []
})

const subgraphs = computed(() => {
  if (!processedData.value?.graph_flow?.subgraphs) return []
  
  return processedData.value.graph_flow.subgraphs.map(sg => ({
    id: sg.subgraph_id,
    name: sg.subgraph_name,
    status: sg.status,
    nodes: (sg.nodes || []).map(node => ({
      id: node.node_id,
      name: node.node_name,
      status: node.status,
      duration: node.execution_time,
      subgraph: sg.subgraph_name,
      inputParams: node.input_params,
      outputData: node.output_data
    }))
  }))
})

const treeData = computed(() => {
  return subgraphs.value.map(sg => ({
    id: sg.id || `sg-${Math.random()}`,
    name: sg.name,
    status: sg.status,
    children: sg.nodes.map(node => ({
      id: node.id,
      name: node.name,
      status: node.status,
      duration: node.duration
    }))
  }))
})

const filteredNodes = computed(() => {
  if (statusFilter.value === 'all') return nodes.value
  return nodes.value.filter(n => n.status === statusFilter.value)
})

const completedCount = computed(() => 
  nodes.value.filter(n => n.status === 'completed').length
)

const runningCount = computed(() => 
  nodes.value.filter(n => n.status === 'running').length
)

const failedCount = computed(() => 
  nodes.value.filter(n => n.status === 'failed').length
)

const pendingCount = computed(() => 
  nodes.value.filter(n => n.status === 'pending').length
)

const filterByStatus = (status) => {
  statusFilter.value = status
}

const selectNode = (node) => {
  selectedNode.value = node
  drawerVisible.value = true
  emit('node-select', node)
}

const refreshNodes = () => {
  emit('refresh')
}

const getStatusType = (status) => WorkflowStatus.getType(status)
const getStatusLabel = (status) => WorkflowStatus.getLabel(status)
const formatDuration = (seconds) => formatDurationUtil(seconds)
</script>

<style scoped>
.node-status-visualization {
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

.visualization-header {
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

.status-legend {
  display: flex;
  gap: 16px;
  margin-bottom: 20px;
  padding: 12px 16px;
  background: #f5f7fa;
  border-radius: 6px;
  flex-wrap: wrap;
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 6px;
  cursor: pointer;
  font-size: 13px;
  color: #606266;
  transition: all 0.2s ease;
}

.legend-item:hover {
  color: #409EFF;
}

.legend-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
}

.legend-dot.all { background: #909399; }
.legend-dot.completed { background: #67C23A; }
.legend-dot.running { background: #409EFF; }
.legend-dot.failed { background: #F56C6C; }
.legend-dot.pending { background: #E6A23C; }

.grid-view {
  margin-top: 8px;
}

.nodes-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
  gap: 12px;
}

.node-card {
  position: relative;
  padding: 16px;
  background: #fafafa;
  border-radius: 8px;
  border: 2px solid transparent;
  cursor: pointer;
  transition: all 0.2s ease;
}

.node-card:hover {
  background: #f0f2f5;
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.node-card.is-selected {
  border-color: #409EFF;
  background: #ecf5ff;
}

.node-card.status-completed { border-left: 4px solid #67C23A; }
.node-card.status-running { border-left: 4px solid #409EFF; }
.node-card.status-failed { border-left: 4px solid #F56C6C; }
.node-card.status-pending { border-left: 4px solid #E6A23C; }

.node-status-indicator {
  position: absolute;
  top: 12px;
  right: 12px;
}

.status-icon {
  width: 24px;
  height: 24px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 14px;
}

.status-icon.completed { background: #67C23A; color: #fff; }
.status-icon.running { background: #409EFF; color: #fff; }
.status-icon.failed { background: #F56C6C; color: #fff; }
.status-icon.pending { background: #E6A23C; color: #fff; }

.node-info {
  padding-right: 32px;
}

.node-name {
  font-weight: 600;
  color: #303133;
  margin-bottom: 6px;
  font-size: 14px;
}

.node-meta {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  color: #909399;
}

.node-type {
  padding: 2px 6px;
  background: #e4e7ed;
  border-radius: 3px;
}

.node-duration {
  color: #606266;
}

.node-subgraph {
  margin-top: 8px;
}

.flow-view {
  margin-top: 8px;
}

.flow-container {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.subgraph-section {
  border: 1px solid #e4e7ed;
  border-radius: 8px;
  padding: 16px;
  background: #fafafa;
}

.subgraph-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 16px;
  padding-bottom: 12px;
  border-bottom: 1px solid #e4e7ed;
}

.subgraph-name {
  font-weight: 600;
  color: #303133;
  flex: 1;
}

.subgraph-nodes {
  position: relative;
  display: flex;
  flex-wrap: wrap;
  gap: 16px;
}

.flow-line {
  position: absolute;
  top: 50%;
  left: 0;
  right: 0;
  height: 2px;
  background: #e4e7ed;
  z-index: 0;
}

.flow-node {
  position: relative;
  z-index: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  min-width: 120px;
}

.flow-node-connector {
  width: 2px;
  height: 12px;
  background: #e4e7ed;
}

.flow-node-connector.before { background: #e4e7ed; }
.flow-node-connector.after { background: #e4e7ed; }

.flow-node.status-completed .flow-node-connector { background: #67C23A; }
.flow-node.status-running .flow-node-connector { background: #409EFF; }
.flow-node.status-failed .flow-node-connector { background: #F56C6C; }

.flow-node-content {
  background: #fff;
  border-radius: 8px;
  padding: 12px 16px;
  text-align: center;
  border: 2px solid #e4e7ed;
  transition: all 0.2s ease;
  cursor: pointer;
}

.flow-node-content:hover {
  transform: scale(1.05);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.flow-node.status-completed .flow-node-content { border-color: #67C23A; }
.flow-node.status-running .flow-node-content { border-color: #409EFF; }
.flow-node.status-failed .flow-node-content { border-color: #F56C6C; }
.flow-node.status-pending .flow-node-content { border-color: #E6A23C; }

.node-status-icon {
  width: 32px;
  height: 32px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  margin: 0 auto 8px;
  font-size: 16px;
}

.node-status-icon.completed { background: #67C23A; color: #fff; }
.node-status-icon.running { background: #409EFF; color: #fff; }
.node-status-icon.failed { background: #F56C6C; color: #fff; }
.node-status-icon.pending { background: #E6A23C; color: #fff; }

.flow-node-name {
  font-size: 13px;
  font-weight: 500;
  color: #303133;
  margin-bottom: 4px;
}

.flow-node-duration {
  font-size: 11px;
  color: #909399;
}

.tree-view {
  margin-top: 8px;
}

.tree-node {
  width: 100%;
  padding: 4px 0;
}

.tree-node-content {
  display: flex;
  align-items: center;
  gap: 8px;
}

.tree-status-icon {
  width: 18px;
  height: 18px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 12px;
}

.tree-status-icon.completed { background: #67C23A; color: #fff; }
.tree-status-icon.running { background: #409EFF; color: #fff; }
.tree-status-icon.failed { background: #F56C6C; color: #fff; }
.tree-status-icon.pending { background: #E6A23C; color: #fff; }

.tree-node-label {
  flex: 1;
  font-size: 13px;
}

.tree-node-duration {
  font-size: 12px;
  color: #909399;
}

.node-detail {
  padding: 0 16px;
}

.detail-section {
  margin-top: 16px;
}

.section-title {
  font-size: 13px;
  font-weight: 500;
  color: #606266;
  margin-bottom: 8px;
}

.section-content {
  margin: 0;
  padding: 12px;
  background: #f5f7fa;
  border-radius: 4px;
  font-size: 12px;
  font-family: 'Consolas', 'Monaco', monospace;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 200px;
  overflow: auto;
}

.detail-section.error .section-title {
  color: #F56C6C;
}

.error-content {
  padding: 12px;
  background: #fef0f0;
  border-radius: 4px;
  color: #F56C6C;
  font-size: 13px;
  border: 1px solid #fbc4c4;
}
</style>
