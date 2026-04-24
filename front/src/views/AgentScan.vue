<template>
  <div class="agent-scan">
    <div class="page-header">
      <h1>AI Agent智能扫描</h1>
      <p class="subtitle">使用AI Agent进行自动化安全扫描和漏洞发现</p>
    </div>

    <div class="scan-layout">
      <div class="form-section">
        <div v-if="isLoading" class="loading-overlay">
          <div class="loading-content">
            <el-icon class="loading-icon" :size="40">
              <svg viewBox="0 0 1024 1024" xmlns="http://www.w3.org/2000/svg">
                <path fill="currentColor" d="M512 64a32 32 0 0 1 32 32v192a32 32 0 0 1-64 0V96a32 32 0 0 1 32-32zm0 640a32 32 0 0 1 32 32v192a32 32 0 0 1-64 0V736a32 32 0 0 1 32-32zm448-192a32 32 0 0 1-32 32H736a32 32 0 0 1 0-64h192a32 32 0 0 1 32 32zm-640 0a32 32 0 0 1-32 32H96a32 32 0 0 1 0-64h192a32 32 0 0 1 32 32zM195.2 195.2a32 32 0 0 1 45.248 0L376.32 331.008a32 32 0 0 1-45.248 45.248L195.2 240.448a32 32 0 0 1 0-45.248zm452.544 452.544a32 32 0 0 1 45.248 0L828.8 783.552a32 32 0 0 1-45.248 45.248L647.744 692.992a32 32 0 0 1 0-45.248zM828.8 195.2a32 32 0 0 1 0 45.248L692.992 376.32a32 32 0 0 1-45.248-45.248L783.552 195.2a32 32 0 0 1 45.248 0zM376.32 647.744a32 32 0 0 1 0 45.248L240.448 828.8a32 32 0 0 1-45.248-45.248l135.808-135.808a32 32 0 0 1 45.248 0z"/>
              </svg>
            </el-icon>
            <span class="loading-text">正在创建扫描任务...</span>
          </div>
        </div>
        
        <AgentScanForm
          @submit="handleSubmit"
          @success="handleSuccess"
          @error="handleError"
        />
        
        <div class="strategy-section">
          <h3>扫描策略</h3>
          <div class="strategy-options">
            <el-select v-model="scanStrategy" placeholder="选择扫描策略" style="width: 200px;">
              <el-option label="快速扫描" value="quick" />
              <el-option label="标准扫描" value="standard" />
              <el-option label="深度扫描" value="deep" />
            </el-select>
            
            <el-input-number v-model="concurrency" :min="1" :max="20" label="并发数" style="width: 120px;" />
            
            <el-input-number v-model="timeout" :min="30" :max="600" :step="30" label="超时(秒)" style="width: 120px;" />
          </div>
        </div>
        
        <div v-if="toolRecommendations.length > 0" class="recommendations-section">
          <h3>AI工具推荐</h3>
          <div class="recommendations-list">
            <div 
              v-for="rec in toolRecommendations" 
              :key="rec.tool_name" 
              class="recommendation-item"
              :class="{ selected: selectedTools.includes(rec.tool_name) }"
              @click="toggleToolSelection(rec.tool_name)"
            >
              <div class="rec-header">
                <el-checkbox :model-value="selectedTools.includes(rec.tool_name)" />
                <span class="rec-name">{{ rec.tool_name }}</span>
                <span class="rec-priority" :class="`priority-${rec.priority}`">
                  优先级: {{ rec.priority }}
                </span>
              </div>
              <div class="rec-reason">{{ rec.reason }}</div>
              <div class="rec-confidence">置信度: {{ (rec.confidence * 100).toFixed(0) }}%</div>
            </div>
          </div>
        </div>
        
        <div class="ai-chat-section">
          <AIChatPanel 
            :target="currentTarget"
            @scan-started="handleAIChatScanStarted"
            @scan-completed="handleAIChatScanCompleted"
            @report-ready="handleReportReady"
          />
        </div>
      </div>

      <div class="right-section">
        <div v-if="currentExecution" class="execution-status-section">
          <h3>执行状态</h3>
          <div class="subgraph-status">
            <div 
              v-for="subgraph in subgraphList" 
              :key="subgraph.type" 
              class="subgraph-item"
              :class="getSubgraphStatus(subgraph.type)"
            >
              <div class="subgraph-header">
                <span class="subgraph-name">{{ subgraph.name }}</span>
                <span class="subgraph-status-text">{{ getSubgraphStatusText(subgraph.type) }}</span>
              </div>
              <div v-if="getSubgraphProgress(subgraph.type) > 0" class="subgraph-progress">
                <el-progress :percentage="getSubgraphProgress(subgraph.type)" :stroke-width="6" />
              </div>
              <div v-if="getSubgraphTime(subgraph.type)" class="subgraph-time">
                耗时: {{ getSubgraphTime(subgraph.type) }}s
              </div>
            </div>
          </div>
        </div>
        
        <div v-if="recentTasks && recentTasks.length > 0" class="recent-section">
          <h3>最近任务</h3>
          <div class="tasks-list">
            <div
              v-for="task in recentTasks"
              :key="task.task_id"
              class="task-item"
              @click="handleViewTask(task.task_id)"
            >
              <div class="task-header">
                <span class="task-id">{{ String(task.task_id).substring(0, 8) }}...</span>
                <span class="task-status" :class="`status-${task.status}`">
                  {{ getStatusText(task.status) }}
                </span>
              </div>
              <div class="task-info">
                <span class="task-target">{{ task.target }}</span>
                <span class="task-time">{{ formatDate(task.created_at) }}</span>
              </div>
              <div v-if="task.status === 'running' || task.status === 'queued'" class="task-progress">
                <div class="progress-bar">
                  <div class="progress-fill" :style="{ width: `${task.progress || 0}%` }"></div>
                </div>
                <span class="progress-text">{{ task.progress || 0 }}%</span>
              </div>
              <div v-if="task.stages" class="stage-mini-summary">
               <span v-for="(stageData, stageName) in task.stages" :key="stageName" 
                     class="stage-dot" 
                     :class="stageData.status"
                     :title="`${stageName}: ${stageData.status}`">
               </span>
              </div>
            </div>
          </div>
        </div>
        
        <div v-if="pluginResults.length > 0" class="plugin-results-section">
          <h3>插件执行结果</h3>
          <div class="plugin-results-list">
            <div v-for="result in pluginResults" :key="result.plugin_name" class="plugin-result-item">
              <div class="plugin-header">
                <span class="plugin-name">{{ result.plugin_name }}</span>
                <span class="plugin-status" :class="result.status">{{ result.status }}</span>
              </div>
              <div class="plugin-time">执行时间: {{ result.execution_time?.toFixed(2) }}s</div>
              <el-button size="small" @click="viewPluginResult(result)">查看详情</el-button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div v-if="selectedTask" class="task-detail-modal" @click.self="selectedTask = null">
      <div class="modal-content" @click.stop>
        <div class="modal-header">
          <h2>任务详情</h2>
          <button class="btn-close" @click="selectedTask = null">×</button>
        </div>
        <div class="modal-body">
          <div class="detail-section">
            <h3>基本信息</h3>
            <div class="detail-grid">
              <div class="detail-item">
                <span class="detail-label">任务ID:</span>
                <span class="detail-value">{{ selectedTask.task_id }}</span>
              </div>
              <div class="detail-item">
                <span class="detail-label">目标:</span>
                <span class="detail-value">{{ selectedTask.target }}</span>
              </div>
              <div class="detail-item">
                <span class="detail-label">状态:</span>
                <span class="detail-value" :class="`status-${selectedTask.status}`">
                  {{ getStatusText(selectedTask.status) }}
                </span>
              </div>
              <div class="detail-item">
                <span class="detail-label">创建时间:</span>
                <span class="detail-value">{{ formatDate(selectedTask.created_at) }}</span>
              </div>
              <div class="detail-item">
                <span class="detail-label">完成时间:</span>
                <span class="detail-value">{{ formatDate(selectedTask.completed_at) }}</span>
              </div>
            </div>
          </div>

          <div class="detail-section" v-if="selectedTask.stages">
            <h3>执行阶段</h3>
            <div class="stages-container">
              <div v-for="(stageData, stageName) in selectedTask.stages" :key="stageName" class="stage-item" :class="stageData.status">
                <div class="stage-header" @click="toggleStageDetails(stageName)">
                  <span class="stage-name">{{ formatStageName(stageName) }}</span>
                  <span class="stage-status-text">{{ getStatusText(stageData.status) }}</span>
                  <span class="stage-progress" v-if="stageData.progress">{{ stageData.progress }}%</span>
                  <span class="expand-icon">{{ expandedStages[stageName] ? '▼' : '▶' }}</span>
                </div>
                <div class="stage-details" v-if="expandedStages[stageName]">
                   <div v-if="stageData.sub_status" class="sub-status">当前步骤: {{ stageData.sub_status }}</div>
                   <div v-if="stageData.log" class="stage-log">{{ stageData.log }}</div>
                   <div v-if="stageData.logs && stageData.logs.length" class="stage-logs">
                     <div v-for="(log, idx) in stageData.logs" :key="idx" class="log-entry">
                       <span class="log-time">{{ log.timestamp }}</span>
                       <span class="log-msg">{{ log.message }}</span>
                     </div>
                   </div>
                </div>
              </div>
            </div>
          </div>

          <div class="detail-section" v-if="selectedTask.target_context && Object.keys(selectedTask.target_context).length">
            <h3>目标上下文</h3>
            <div class="context-grid">
              <div v-for="(value, key) in selectedTask.target_context" :key="key" class="context-item">
                <span class="context-label">{{ formatContextKey(key) }}:</span>
                <span class="context-value">{{ value || '-' }}</span>
              </div>
            </div>
          </div>

          <div class="detail-section" v-if="selectedTask.execution_history && selectedTask.execution_history.length">
            <h3>执行历史</h3>
            <div class="history-list">
              <div v-for="(step, idx) in selectedTask.execution_history" :key="idx" class="history-item">
                <div class="history-header">
                  <span class="history-node">{{ step.node || step.task || 'Unknown' }}</span>
                  <span class="history-status" :class="step.status">{{ step.status }}</span>
                  <span class="history-time">{{ step.timestamp }}</span>
                </div>
                <div class="history-action" v-if="step.action">{{ step.action }}</div>
                <div class="history-result" v-if="step.result">
                  <pre>{{ typeof step.result === 'object' ? JSON.stringify(step.result, null, 2) : step.result }}</pre>
                </div>
              </div>
            </div>
          </div>

          <div class="detail-section" v-if="selectedTask.scan_summary && Object.keys(selectedTask.scan_summary).length">
            <h3>扫描摘要</h3>
            <div class="summary-grid">
              <div v-for="(value, key) in selectedTask.scan_summary" :key="key" class="summary-item">
                <span class="summary-label">{{ formatSummaryKey(key) }}:</span>
                <span class="summary-value">{{ value }}</span>
              </div>
            </div>
          </div>

          <div v-if="selectedTask.result" class="detail-section">
            <h3>扫描结果</h3>
            <div class="result-content">
              <div v-if="selectedTask.result.final_output" class="result-json">
                <pre>{{ JSON.stringify(selectedTask.result.final_output, null, 2) }}</pre>
              </div>
              <div v-if="selectedTask.result.execution_time" class="result-info">
                <span class="info-label">执行时间:</span>
                <span class="info-value">{{ selectedTask.result.execution_time }}秒</span>
              </div>
            </div>
          </div>

          <div v-if="selectedTask.error_message" class="detail-section error-section">
            <h3>错误信息</h3>
            <div class="error-message">{{ selectedTask.error_message }}</div>
          </div>
        </div>
      </div>
    </div>
    
    <el-dialog v-model="showPluginResultDialog" :title="currentPluginResult?.plugin_name + ' 结果详情'" width="600px">
      <pre class="plugin-result-detail">{{ JSON.stringify(currentPluginResult?.data, null, 2) }}</pre>
    </el-dialog>

    <Alert
      v-if="errorMessage"
      type="error"
      :message="errorMessage"
      :show-retry="canRetry"
      @close="errorMessage = ''"
      @retry="handleRetry"
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
import { ref, onMounted, onUnmounted, reactive, computed } from 'vue'
import { aiAgentsApi, ProgressWatcher } from '@/utils/aiAgents'
import AgentScanForm from '@/components/business/AgentScanForm.vue'
import AIChatPanel from '@/components/business/AIChatPanel.vue'
import Alert from '@/components/common/Alert.vue'
import { formatDate } from '@/utils/date'
import { useWebSocket } from '@/utils/websocket'
import { useTaskStore } from '@/store/tasks'
import toast from '@/utils/toast'

export default {
  name: 'AgentScan',
  components: {
    AgentScanForm,
    AIChatPanel,
    Alert
  },
  setup() {
    const taskStore = useTaskStore()
    const errorMessage = ref('')
    const successMessage = ref('')
    const recentTasks = computed(() => taskStore.tasks)
    const selectedTask = ref(null)
    const scanStrategy = ref('standard')
    const concurrency = ref(5)
    const timeout = ref(3600)
    const toolRecommendations = ref([])
    const selectedTools = ref([])
    const currentExecution = ref(null)
    const pluginResults = ref([])
    const showPluginResultDialog = ref(false)
    const currentPluginResult = ref(null)
    const isLoading = ref(false)
    const lastSubmitData = ref(null)
    const retryCount = ref(0)
    const maxRetryCount = 3
    const expandedStages = ref({})
    const currentTarget = ref('')
    
    const subgraphState = reactive({
      planning: { status: 'pending', progress: 0, time: 0 },
      tool_execution: { status: 'pending', progress: 0, time: 0 },
      poc_verification: { status: 'pending', progress: 0, time: 0 },
      report: { status: 'pending', progress: 0, time: 0 }
    })
    
    const subgraphList = [
      { type: 'planning', name: 'AI分析规划' },
      { type: 'tool_execution', name: '工具执行' },
      { type: 'poc_verification', name: 'POC验证' },
      { type: 'report', name: '报告生成' }
    ]

    const { connect, on, disconnect } = useWebSocket('ws://localhost:8888/api/ws')
    
    let progressWatcher = null

    const loadRecentTasks = async () => {
      try {
        const response = await aiAgentsApi.getTasks({ page: 1, page_size: 10 })
        let tasks = []
        if (response && response.data && response.data.tasks) {
          tasks = response.data.tasks
        } else if (response && response.tasks) {
          tasks = response.tasks
        } else if (response && Array.isArray(response)) {
          tasks = response
        }
        
        const normalizedTasks = tasks.map(task => ({
          ...task,
          id: String(task.task_id || task.id),
          task_id: String(task.task_id || task.id),
          stages: task.stages || {
            planning: { status: 'pending' },
            tool_execution: { status: 'pending' },
            poc_verification: { status: 'pending' },
            report: { status: 'pending' }
          }
        }))
        
        taskStore.setTasks(normalizedTasks)
      } catch (error) {
        console.error('加载最近任务失败:', error)
      }
    }
    

    
    const toggleToolSelection = (toolName) => {
      const index = selectedTools.value.indexOf(toolName)
      if (index > -1) {
        selectedTools.value.splice(index, 1)
      } else {
        selectedTools.value.push(toolName)
      }
    }

    const handleSubmit = async (eventData) => {
      console.log('提交Agent扫描', eventData)
      
      if (isLoading.value) return
      
      isLoading.value = true
      errorMessage.value = ''
      
      const formData = eventData.formData || eventData
      const scanData = eventData.scanData || {}
      
      lastSubmitData.value = { formData, scanData }
      
      try {
        const requestData = {
          target: formData.target || scanData.target,
          enable_llm_planning: formData.enableLLMPlanning ?? scanData.enable_llm_planning ?? true,
          custom_tasks: formData.useCustomTasks ? formData.customTasks : null,
          need_custom_scan: formData.needCustomScan ?? scanData.need_custom_scan ?? false,
          custom_scan_type: formData.customScanType || scanData.custom_scan_type || 'web',
          custom_scan_requirements: formData.customScanRequirements || scanData.custom_scan_requirements || '',
          custom_scan_language: formData.customScanLanguage || scanData.custom_scan_language || 'python',
          need_capability_enhancement: formData.needCapabilityEnhancement ?? scanData.need_capability_enhancement ?? false,
          capability_requirement: formData.capabilityRequirement || scanData.capability_requirement || '',
          strategy: scanStrategy.value,
          concurrency: concurrency.value,
          timeout: timeout.value,
          selected_tools: selectedTools.value
        }
        
        const response = await aiAgentsApi.startScan(requestData)
        
        if (response && response.task_id) {
          currentExecution.value = response
          resetSubgraphState()
          retryCount.value = 0
          
          const newTask = {
            task_id: String(response.task_id),
            id: String(response.task_id),
            target: requestData.target,
            task_name: 'AI Agent 扫描',
            task_type: 'agent_scan',
            status: 'queued',
            progress: 0,
            created_at: new Date().toISOString(),
            stages: {
              planning: { status: 'pending' },
              tool_execution: { status: 'pending' },
              poc_verification: { status: 'pending' },
              report: { status: 'pending' }
            }
          }
          taskStore.addTask(newTask)
          
          toast.success('任务创建成功', `扫描任务 ${String(response.task_id).substring(0, 8)}... 已创建`)
          
          if (progressWatcher) {
            progressWatcher.subscribeTask(response.task_id)
          }
        }
      } catch (error) {
        errorMessage.value = error.message || '创建扫描任务失败'
        toast.error('任务创建失败', error.message || '创建扫描任务失败')
        retryCount.value++
      } finally {
        isLoading.value = false
      }
    }
    
    const handleRetry = async () => {
      if (!lastSubmitData.value) {
        errorMessage.value = '没有可重试的任务'
        return
      }
      
      if (retryCount.value >= maxRetryCount) {
        errorMessage.value = `已达到最大重试次数(${maxRetryCount}次)，请稍后再试`
        return
      }
      
      await handleSubmit(lastSubmitData.value)
    }
    
    const canRetry = computed(() => {
      return lastSubmitData.value && retryCount.value < maxRetryCount
    })
    
    const resetSubgraphState = () => {
      Object.keys(subgraphState).forEach(key => {
        subgraphState[key] = { status: 'pending', progress: 0, time: 0 }
      })
    }
    
    const getSubgraphStatus = (type) => {
      return subgraphState[type]?.status || 'pending'
    }
    
    const getSubgraphStatusText = (type) => {
      const status = subgraphState[type]?.status || 'pending'
      const statusMap = {
        pending: '等待中',
        running: '执行中',
        completed: '已完成',
        failed: '失败'
      }
      return statusMap[status] || status
    }
    
    const getSubgraphProgress = (type) => {
      return subgraphState[type]?.progress || 0
    }
    
    const getSubgraphTime = (type) => {
      return subgraphState[type]?.time || 0
    }
    
    const viewPluginResult = (result) => {
      currentPluginResult.value = result
      showPluginResultDialog.value = true
    }

    const handleSuccess = () => {
      successMessage.value = 'AI Agent扫描任务创建成功'
    }

    const handleError = (error) => {
      errorMessage.value = error.message || '创建AI Agent扫描任务失败'
    }

    const handleViewTask = (taskId) => {
      const task = recentTasks.value.find(t => t.task_id === taskId)
      if (task) {
        selectedTask.value = task
        
        const stageMapping = {
          openai: 'planning',
          plugins: 'tool_execution',
          awvs: 'poc_verification',
          pocsuite3: 'poc_verification',
          planning: 'planning',
          tool_execution: 'tool_execution',
          poc_verification: 'poc_verification',
          report: 'report',
          info_collection: 'planning',
          vuln_scan: 'tool_execution'
        }
        
        Object.keys(subgraphState).forEach(key => {
          subgraphState[key] = { status: 'pending', progress: 0, time: 0 }
        })
        
        if (task.stages) {
          Object.keys(task.stages).forEach(backendKey => {
            const frontendKey = stageMapping[backendKey] || backendKey
            if (subgraphState[frontendKey]) {
              const stageData = task.stages[backendKey]
              subgraphState[frontendKey] = {
                status: stageData.status || 'pending',
                progress: stageData.progress || 0,
                time: stageData.execution_time || stageData.time || 0
              }
            }
          })
        }
        
        if (task.status === 'completed') {
          Object.keys(subgraphState).forEach(key => {
            if (subgraphState[key].status === 'pending') {
              subgraphState[key].status = 'completed'
              subgraphState[key].progress = 100
            }
          })
        }
        
        if (task.result) {
          if (task.result.scan_summary) {
            selectedTask.value = {
              ...selectedTask.value,
              scan_summary: task.result.scan_summary
            }
          }
          if (task.result.final_output) {
            selectedTask.value = {
              ...selectedTask.value,
              result: {
                ...selectedTask.value.result,
                final_output: task.result.final_output
              }
            }
          }
          if (task.result.vulnerabilities) {
            selectedTask.value = {
              ...selectedTask.value,
              vulnerabilities: task.result.vulnerabilities
            }
          }
          if (task.result.report) {
            selectedTask.value = {
              ...selectedTask.value,
              report: task.result.report
            }
          }
        }
      }
    }

    const getStatusText = (status) => {
      const statusMap = {
        pending: '等待中',
        queued: '队列中',
        running: '运行中',
        completed: '已完成',
        failed: '失败',
        cancelled: '已取消'
      }
      return statusMap[status] || status
    }

    const formatStageName = (name) => {
      const map = {
        openai: 'AI分析规划',
        plugins: '插件执行',
        awvs: '漏洞扫描',
        pocsuite3: 'POC验证',
        planning: 'AI分析规划',
        tool_execution: '工具执行',
        poc_verification: 'POC验证',
        report: '报告生成',
        info_collection: '信息收集',
        vuln_scan: '漏洞扫描'
      }
      return map[name] || name
    }

    const toggleStageDetails = (stageName) => {
      expandedStages.value[stageName] = !expandedStages.value[stageName]
    }

    const formatContextKey = (key) => {
      const map = {
        cms_type: 'CMS类型',
        server_type: '服务器类型',
        waf_detected: 'WAF检测',
        open_ports: '开放端口',
        tech_stack: '技术栈',
        framework: '框架',
        language: '编程语言',
        os_info: '操作系统'
      }
      return map[key] || key
    }

    const formatSummaryKey = (key) => {
      const map = {
        total_requests: '总请求数',
        total_vulnerabilities: '发现漏洞数',
        high_risk_count: '高危漏洞',
        medium_risk_count: '中危漏洞',
        low_risk_count: '低危漏洞',
        execution_time: '执行时间',
        tools_used: '使用工具数',
        pocs_executed: 'POC执行数'
      }
      return map[key] || key
    }

    const updateTaskStatus = (taskId, payload) => {
      taskId = String(taskId)
      const existingTask = taskStore.getTaskById(taskId)
      
      if (!existingTask && payload.status === 'queued') {
        const newTask = {
          task_id: taskId,
          id: taskId,
          target: payload.target || 'Unknown',
          status: 'queued',
          created_at: new Date().toISOString(),
          progress: 0,
          stages: {
            planning: { status: 'pending' },
            tool_execution: { status: 'pending' },
            poc_verification: { status: 'pending' },
            report: { status: 'pending' }
          }
        }
        taskStore.addTask(newTask)
      } else {
        taskStore.updateTaskStatus(taskId, payload.status, payload)
      }
      
      if (selectedTask.value && String(selectedTask.value.task_id) === taskId) {
        const updatedTask = taskStore.getTaskById(taskId)
        if (updatedTask) {
          selectedTask.value = { ...updatedTask }
        }
      }
    }

    const updateTaskProgress = (taskId, progress) => {
      taskId = String(taskId)
      taskStore.updateTaskProgress(taskId, progress)
      
      if (selectedTask.value && String(selectedTask.value.task_id) === taskId) {
        const updatedTask = taskStore.getTaskById(taskId)
        if (updatedTask) {
          selectedTask.value = { ...updatedTask }
        }
      }
    }

    const updateTaskCompleted = (taskId, payload) => {
      taskId = String(taskId)
      const result = payload.result || {}
      
      if (payload.stages) {
        Object.keys(payload.stages).forEach(stage => {
          if (subgraphState[stage]) {
            subgraphState[stage] = {
              status: payload.stages[stage].status || 'completed',
              progress: payload.stages[stage].progress || 100,
              time: payload.stages[stage].execution_time || 0
            }
          }
        })
      }
      
      taskStore.completeTask(taskId, {
        ...result,
        scan_summary: payload.scan_summary,
        final_output: payload.final_output,
        vulnerabilities: payload.vulnerabilities,
        report: payload.report,
        execution_time: payload.execution_time
      })
      
      toast.success('任务完成', `扫描任务 ${taskId.substring(0, 8)}... 已完成`)
      
      if (selectedTask.value && String(selectedTask.value.task_id) === taskId) {
        const updatedTask = taskStore.getTaskById(taskId)
        if (updatedTask) {
          selectedTask.value = { ...updatedTask }
        }
      }
    }
    
    const updateTaskFailed = (taskId, error) => {
      taskId = String(taskId)
      
      taskStore.failTask(taskId, error)
      
      toast.error('任务失败', `扫描任务 ${taskId.substring(0, 8)}... 执行失败`)
      
      if (selectedTask.value && String(selectedTask.value.task_id) === taskId) {
        const updatedTask = taskStore.getTaskById(taskId)
        if (updatedTask) {
          selectedTask.value = { ...updatedTask }
        }
      }
    }

    const updateTaskStage = (taskId, stage, data) => {
      taskId = String(taskId)
      const task = taskStore.getTaskById(taskId)
      if (task) {
        const newStages = { ...task.stages }
        if (!newStages[stage]) newStages[stage] = {}
        newStages[stage] = { ...newStages[stage], ...data }
        taskStore.updateTask(taskId, { stages: newStages })
        
        if (selectedTask.value && String(selectedTask.value.task_id) === taskId) {
           const updatedTask = taskStore.getTaskById(taskId)
           if (updatedTask) {
             selectedTask.value = { ...updatedTask }
           }
        }
      }
    }
    
    const updateSubgraphProgress = (payload) => {
      const subgraphType = payload.subgraph_type || payload.stage
      if (subgraphType && subgraphState[subgraphType]) {
        subgraphState[subgraphType] = {
          status: payload.status || 'running',
          progress: payload.progress || 0,
          time: payload.execution_time || subgraphState[subgraphType].time
        }
      }
      
      if (payload.task_id) {
        updateTaskStage(payload.task_id, subgraphType, {
          status: payload.status || 'running',
          progress: payload.progress || 0,
          execution_time: payload.execution_time || 0
        })
      }
    }
    
    const updateToolExecution = (payload) => {
      if (payload.plugin_name) {
        const existingIndex = pluginResults.value.findIndex(r => r.plugin_name === payload.plugin_name)
        const resultItem = {
          plugin_name: payload.plugin_name,
          status: payload.status || 'running',
          execution_time: payload.execution_time,
          data: payload.data
        }
        
        if (existingIndex > -1) {
          pluginResults.value[existingIndex] = resultItem
        } else {
          pluginResults.value.push(resultItem)
        }
      }
    }
    
    const handleAIChatScanStarted = (data) => {
      currentTarget.value = data.target
      currentExecution.value = { task_id: data.task_id || Date.now().toString() }
      resetSubgraphState()
      toast.success('AI对话扫描开始', `正在扫描: ${data.target}`)
    }
    
    const handleAIChatScanCompleted = (data) => {
      toast.success('AI对话扫描完成', '扫描任务已完成')
      loadRecentTasks()
    }
    
    const handleReportReady = (report) => {
      toast.success('报告已生成', '点击下载报告')
    }

    onMounted(() => {
      loadRecentTasks()
      
      connect()
      
      on('task:update', (payload) => {
        const data = payload.payload || payload
        updateTaskStatus(data.task_id, data)
      })
      
      on('task:progress', (payload) => {
        const data = payload.payload || payload
        updateTaskProgress(data.task_id, data.progress)
      })
      
      on('task:completed', (payload) => {
        const data = payload.payload || payload
        updateTaskCompleted(data.task_id, data)
      })
      
      on('task:failed', (payload) => {
        const data = payload.payload || payload
        updateTaskFailed(data.task_id, data.error || data.message)
      })

      on('stage:update', (payload) => {
         const data = payload.payload || payload
         updateTaskStage(data.task_id, data.stage, data.data)
         
         if (data.stage && subgraphState[data.stage]) {
           subgraphState[data.stage] = {
             status: data.data?.status || 'running',
             progress: data.data?.progress || 0,
             time: data.data?.execution_time || 0
           }
         }
      })
      
      on('subgraph:progress', (payload) => {
        const data = payload.payload || payload
        updateSubgraphProgress(data)
      })
      
      on('tool:execution', (payload) => {
        updateToolExecution(payload)
      })
      
      progressWatcher = new ProgressWatcher('ws://localhost:8888/api/ws/progress')
      progressWatcher.connect()
    })
    
    onUnmounted(() => {
      disconnect()
      if (progressWatcher) {
        progressWatcher.disconnect()
      }
    })

    return {
      errorMessage,
      successMessage,
      recentTasks,
      selectedTask,
      scanStrategy,
      concurrency,
      timeout,
      toolRecommendations,
      selectedTools,
      currentExecution,
      pluginResults,
      showPluginResultDialog,
      currentPluginResult,
      subgraphList,
      subgraphState,
      isLoading,
      retryCount,
      maxRetryCount,
      canRetry,
      expandedStages,
      currentTarget,
      handleSubmit,
      handleRetry,
      handleSuccess,
      handleError,
      handleViewTask,
      getStatusText,
      formatDate,
      formatStageName,
      formatContextKey,
      formatSummaryKey,
      toggleStageDetails,
      toggleToolSelection,
      getSubgraphStatus,
      getSubgraphStatusText,
      getSubgraphProgress,
      getSubgraphTime,
      viewPluginResult,
      handleAIChatScanStarted,
      handleAIChatScanCompleted,
      handleReportReady
    }
  }
}
</script>

<style scoped>
.agent-scan {
  padding: var(--spacing-xl);
  --card-bg: var(--card-background);
  --bg-secondary: var(--el-fill-color-light);
  --bg-primary: var(--el-fill-color);
  --color-primary: var(--el-color-primary);
  --color-success: var(--el-color-success);
  --color-warning: var(--el-color-warning);
  --color-error: var(--el-color-danger);
  --color-info: var(--el-color-info);
  --color-primary-bg: var(--el-color-primary-light-9);
  --color-success-bg: var(--el-color-success-light-9);
  --color-warning-bg: var(--el-color-warning-light-9);
  --color-error-bg: var(--el-color-danger-light-9);
  --color-info-bg: var(--el-color-info-light-9);
  --color-accent: #9b59b6;
}

.page-header {
  margin-bottom: var(--spacing-xl);
}

.page-header h1 {
  margin: 0 0 var(--spacing-sm) 0;
  font-size: 2rem;
  color: var(--text-primary);
}

.subtitle {
  margin: 0;
  color: var(--text-secondary);
  font-size: 1rem;
}

.scan-layout {
  display: grid;
  grid-template-columns: 1fr 400px;
  gap: var(--spacing-xl);
}

.form-section {
  min-width: 0;
  position: relative;
}

.loading-overlay {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(255, 255, 255, 0.9);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 100;
  border-radius: var(--border-radius-lg);
}

.loading-content {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--spacing-md);
}

.loading-icon {
  animation: spin 1s linear infinite;
  color: var(--color-primary);
}

.loading-text {
  font-size: 1rem;
  color: var(--text-secondary);
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

.strategy-section {
  background-color: var(--card-bg);
  border: 1px solid var(--border-color);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-lg);
  margin-top: var(--spacing-lg);
}

.strategy-section h3 {
  margin: 0 0 var(--spacing-md) 0;
  font-size: 1rem;
  color: var(--text-primary);
}

.strategy-options {
  display: flex;
  gap: var(--spacing-md);
  flex-wrap: wrap;
}

.recommendations-section {
  background-color: var(--card-bg);
  border: 1px solid var(--border-color);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-lg);
  margin-top: var(--spacing-lg);
}

.recommendations-section h3 {
  margin: 0 0 var(--spacing-md) 0;
  font-size: 1rem;
  color: var(--text-primary);
}

.recommendations-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.recommendation-item {
  padding: var(--spacing-md);
  background-color: var(--bg-secondary);
  border-radius: var(--border-radius);
  cursor: pointer;
  border: 2px solid transparent;
  transition: all 0.3s;
}

.recommendation-item:hover {
  background-color: var(--color-primary-bg);
}

.recommendation-item.selected {
  border-color: var(--color-primary);
  background-color: var(--color-primary-bg);
}

.rec-header {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-xs);
}

.rec-name {
  font-weight: 600;
  color: var(--text-primary);
}

.rec-priority {
  margin-left: auto;
  font-size: 0.75rem;
  padding: 2px 8px;
  border-radius: var(--border-radius-sm);
}

.priority-high { background-color: var(--color-error-bg); color: var(--color-error); }
.priority-medium { background-color: var(--color-warning-bg); color: var(--color-warning); }
.priority-low { background-color: var(--color-info-bg); color: var(--color-info); }

.rec-reason {
  font-size: 0.875rem;
  color: var(--text-secondary);
  margin-bottom: var(--spacing-xs);
}

.rec-confidence {
  font-size: 0.75rem;
  color: var(--text-secondary);
}

.right-section {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.execution-status-section {
  background-color: var(--card-bg);
  border: 1px solid var(--border-color);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-lg);
}

.execution-status-section h3 {
  margin: 0 0 var(--spacing-md) 0;
  font-size: 1rem;
  color: var(--text-primary);
}

.subgraph-status {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.subgraph-item {
  padding: var(--spacing-sm) var(--spacing-md);
  background-color: var(--bg-secondary);
  border-radius: var(--border-radius);
  border-left: 4px solid var(--border-color);
}

.subgraph-item.running { border-left-color: var(--color-info); }
.subgraph-item.completed { border-left-color: var(--color-success); }
.subgraph-item.failed { border-left-color: var(--color-error); }

.subgraph-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.subgraph-name {
  font-weight: 500;
  color: var(--text-primary);
}

.subgraph-status-text {
  font-size: 0.75rem;
  color: var(--text-secondary);
}

.subgraph-progress {
  margin-top: var(--spacing-xs);
}

.subgraph-time {
  font-size: 0.75rem;
  color: var(--text-secondary);
  margin-top: var(--spacing-xs);
}

.recent-section {
  background-color: var(--card-bg);
  border: 1px solid var(--border-color);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-lg);
}

.recent-section h3 {
  margin: 0 0 var(--spacing-lg) 0;
  font-size: 1.25rem;
  color: var(--text-primary);
  padding-bottom: var(--spacing-md);
  border-bottom: 1px solid var(--border-color);
}

.tasks-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
  margin-top: var(--spacing-md);
}

.task-item {
  padding: var(--spacing-md);
  background-color: var(--bg-secondary);
  border-radius: var(--border-radius);
  cursor: pointer;
  transition: all 0.3s;
  border: 1px solid transparent;
}

.task-item:hover {
  background-color: var(--color-primary-bg);
  border-color: var(--color-primary);
  transform: translateX(4px);
  box-shadow: var(--shadow-sm);
}

.task-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-sm);
}

.task-id {
  font-family: monospace;
  font-size: 0.875rem;
  color: var(--text-secondary);
}

.task-status {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-sm);
  font-size: 0.75rem;
  font-weight: 500;
}

.status-pending { background-color: var(--color-warning-bg); color: var(--color-warning); }
.status-queued { background-color: var(--color-info-bg); color: var(--color-info); opacity: 0.8; }
.status-running { background-color: var(--color-info-bg); color: var(--color-info); }
.status-completed { background-color: var(--color-success-bg); color: var(--color-success); }
.status-failed, .status-cancelled { background-color: var(--color-error-bg); color: var(--color-error); }

.task-info {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 0.875rem;
  margin-bottom: var(--spacing-sm);
}

.task-target {
  color: var(--text-primary);
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.task-time { color: var(--text-secondary); }

.task-progress {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
}

.progress-bar {
  flex: 1;
  height: 6px;
  background-color: var(--border-color);
  border-radius: 3px;
  overflow: hidden;
}

.progress-fill {
  height: 100%;
  background: linear-gradient(90deg, var(--color-primary), var(--color-accent));
  transition: width 0.3s;
}

.progress-text {
  min-width: 40px;
  font-size: 0.75rem;
  color: var(--text-secondary);
  text-align: right;
}

.stage-mini-summary {
  display: flex;
  gap: 4px;
  margin-top: 8px;
}

.stage-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background-color: var(--border-color);
}

.stage-dot.running { background-color: var(--color-info); animation: pulse 1.5s infinite; }
.stage-dot.completed { background-color: var(--color-success); }
.stage-dot.failed { background-color: var(--color-error); }

@keyframes pulse {
  0% { opacity: 0.5; transform: scale(0.9); }
  50% { opacity: 1; transform: scale(1.1); }
  100% { opacity: 0.5; transform: scale(0.9); }
}

.plugin-results-section {
  background-color: var(--card-bg);
  border: 1px solid var(--border-color);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-lg);
}

.plugin-results-section h3 {
  margin: 0 0 var(--spacing-md) 0;
  font-size: 1rem;
  color: var(--text-primary);
}

.plugin-results-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.plugin-result-item {
  padding: var(--spacing-sm);
  background-color: var(--bg-secondary);
  border-radius: var(--border-radius);
}

.plugin-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-xs);
}

.plugin-name {
  font-weight: 500;
  color: var(--text-primary);
}

.plugin-status {
  font-size: 0.75rem;
  padding: 2px 6px;
  border-radius: var(--border-radius-sm);
}

.plugin-status.success { background-color: var(--color-success-bg); color: var(--color-success); }
.plugin-status.failed { background-color: var(--color-error-bg); color: var(--color-error); }
.plugin-status.running { background-color: var(--color-info-bg); color: var(--color-info); }

.plugin-time {
  font-size: 0.75rem;
  color: var(--text-secondary);
  margin-bottom: var(--spacing-xs);
}

.plugin-result-detail {
  max-height: 400px;
  overflow: auto;
  background-color: var(--bg-primary);
  padding: var(--spacing-md);
  border-radius: var(--border-radius);
  font-size: 0.875rem;
}

.task-detail-modal {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: rgba(0, 0, 0, 0.5);
  display: flex;
  justify-content: center;
  align-items: center;
  z-index: 1000;
  padding: var(--spacing-lg);
}

.modal-content {
  background-color: var(--card-bg);
  border-radius: var(--border-radius-lg);
  max-width: 800px;
  width: 100%;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: var(--shadow-lg);
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
  font-size: 1.25rem;
  color: var(--text-primary);
}

.btn-close {
  background: none;
  border: none;
  font-size: 2rem;
  color: var(--text-secondary);
  cursor: pointer;
  padding: 0;
  line-height: 1;
  transition: color 0.3s;
}

.btn-close:hover { color: var(--text-primary); }

.modal-body { padding: var(--spacing-lg); }

.detail-section { margin-bottom: var(--spacing-lg); }

.detail-section h3 {
  margin: 0 0 var(--spacing-md) 0;
  font-size: 1rem;
  color: var(--text-primary);
  padding-bottom: var(--spacing-sm);
  border-bottom: 1px solid var(--border-color);
}

.detail-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: var(--spacing-md);
}

.detail-item {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
}

.detail-label {
  font-size: 0.875rem;
  color: var(--text-secondary);
  font-weight: 500;
}

.detail-value {
  font-size: 1rem;
  color: var(--text-primary);
  word-break: break-all;
}

.stages-container {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.stage-item {
  border: 1px solid var(--border-color);
  border-radius: 6px;
  padding: 12px;
  background: var(--bg-secondary);
}

.stage-item.running { border-left: 4px solid var(--color-info); }
.stage-item.completed { border-left: 4px solid var(--color-success); }
.stage-item.failed { border-left: 4px solid var(--color-error); }

.stage-header {
  display: flex;
  justify-content: space-between;
  font-weight: 600;
  margin-bottom: 4px;
}

.sub-status {
  font-size: 0.85rem;
  color: var(--text-secondary);
}

.stage-log {
  margin-top: 8px;
  font-family: monospace;
  font-size: 0.8rem;
  background: var(--bg-primary);
  padding: 8px;
  border-radius: 4px;
  white-space: pre-wrap;
  max-height: 100px;
  overflow-y: auto;
}

.stage-progress {
  font-size: 0.8rem;
  color: var(--text-secondary);
  margin-left: auto;
  margin-right: 8px;
}

.expand-icon {
  font-size: 0.7rem;
  color: var(--text-secondary);
  cursor: pointer;
}

.stage-logs {
  margin-top: 8px;
  max-height: 150px;
  overflow-y: auto;
}

.log-entry {
  display: flex;
  gap: 8px;
  font-size: 0.75rem;
  padding: 4px 0;
  border-bottom: 1px solid var(--border-color);
}

.log-time {
  color: var(--text-secondary);
  font-family: monospace;
  min-width: 60px;
}

.log-msg {
  color: var(--text-primary);
  flex: 1;
}

.context-grid,
.summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: var(--spacing-sm);
}

.context-item,
.summary-item {
  display: flex;
  flex-direction: column;
  padding: var(--spacing-sm);
  background: var(--bg-secondary);
  border-radius: var(--border-radius);
}

.context-label,
.summary-label {
  font-size: 0.75rem;
  color: var(--text-secondary);
  margin-bottom: 4px;
}

.context-value,
.summary-value {
  font-size: 0.875rem;
  color: var(--text-primary);
  font-weight: 500;
}

.history-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
  max-height: 300px;
  overflow-y: auto;
}

.history-item {
  border: 1px solid var(--border-color);
  border-radius: var(--border-radius);
  padding: var(--spacing-sm);
  background: var(--bg-secondary);
}

.history-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 4px;
}

.history-node {
  font-weight: 600;
  font-size: 0.875rem;
  color: var(--text-primary);
}

.history-status {
  font-size: 0.7rem;
  padding: 2px 6px;
  border-radius: var(--border-radius-sm);
}

.history-status.completed { background: var(--color-success-bg); color: var(--color-success); }
.history-status.running { background: var(--color-info-bg); color: var(--color-info); }
.history-status.failed { background: var(--color-error-bg); color: var(--color-error); }

.history-time {
  font-size: 0.7rem;
  color: var(--text-secondary);
}

.history-action {
  font-size: 0.8rem;
  color: var(--text-secondary);
  margin-bottom: 4px;
}

.history-result {
  margin-top: 8px;
}

.history-result pre {
  margin: 0;
  padding: var(--spacing-sm);
  background: var(--bg-primary);
  border-radius: var(--border-radius);
  font-size: 0.75rem;
  overflow-x: auto;
  max-height: 150px;
}

.result-content {
  background-color: var(--bg-secondary);
  border-radius: var(--border-radius);
  padding: var(--spacing-md);
}

.result-json { margin-bottom: var(--spacing-md); }

.result-json pre {
  margin: 0;
  padding: var(--spacing-md);
  background-color: var(--bg-primary);
  border-radius: var(--border-radius);
  font-size: 0.875rem;
  overflow-x: auto;
}

.result-info {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
}

.info-label {
  font-size: 0.875rem;
  color: var(--text-secondary);
  font-weight: 500;
}

.info-value {
  font-size: 1rem;
  color: var(--text-primary);
  font-weight: 600;
}

.error-section {
  background-color: var(--color-error-bg);
  border: 1px solid var(--color-error);
  border-radius: var(--border-radius);
  padding: var(--spacing-md);
}

.error-section h3 { color: var(--color-error); }

.error-message {
  color: var(--color-error);
  font-size: 0.875rem;
  line-height: 1.6;
}

@media (max-width: 1024px) {
  .scan-layout {
    grid-template-columns: 1fr;
  }
}

.ai-chat-section {
  margin-top: var(--spacing-lg);
  background-color: var(--card-bg);
  border: 1px solid var(--border-color);
  border-radius: var(--border-radius-lg);
  overflow: hidden;
}
</style>
