<template>
  <div id="page-tools" class="page active">
    <div class="page-header">
      <h2>安全工具</h2>
    </div>

    <div class="tools-filter">
      <button 
        class="filter-btn" 
        :class="{ active: currentCategory === 'all' }" 
        @click="filterTools('all')"
      >全部</button>
      <button 
        class="filter-btn" 
        :class="{ active: currentCategory === 'info' }" 
        @click="filterTools('info')"
      >信息收集</button>
      <button 
        class="filter-btn" 
        :class="{ active: currentCategory === 'vuln' }" 
        @click="filterTools('vuln')"
      >漏洞扫描</button>
      <button 
        class="filter-btn" 
        :class="{ active: currentCategory === 'custom' }" 
        @click="filterTools('custom')"
      >自定义工具</button>
    </div>

    <!-- 默认分类：普通工具列表 -->
    <template v-if="currentCategory !== 'custom'">
      <div class="tools-grid" id="toolsGrid">
        <div v-if="isLoading" class="loading" style="grid-column: 1 / -1;">加载工具列表...</div>
        <div v-else-if="errorMsg" class="error" style="grid-column: 1 / -1; color: var(--error-color);">{{ errorMsg }}</div>
        <div v-else-if="filteredTools.length === 0" class="loading" style="grid-column: 1 / -1;">暂无工具</div>
        
        <div 
          v-else 
          v-for="tool in filteredTools" 
          :key="tool.name" 
          class="tool-card" 
          :class="{ 'custom-tool': tool.name.startsWith('custom_') || tool.name.startsWith('ai_gen_') }"
          @click="openExecution(tool)"
        >
          <h4>{{ formatToolName(tool.name) }}</h4>
          <p>
            <template v-if="tool.description">
              名称：{{ parsedDescription(tool.description).name }}<br>
              简介：{{ parsedDescription(tool.description).brief || '无简介' }}
            </template>
            <template v-else>安全扫描工具</template>
          </p>
          <span class="tool-category" :class="tool.category">{{ getToolCategoryLabel(tool) }}</span>
        </div>
      </div>
    </template>

    <!-- 自定义工具分类：专用渲染，列表 + 新建卡片 -->
    <template v-if="currentCategory === 'custom'">
      <div v-if="isLoading" class="loading">加载工具列表...</div>
      <div v-else-if="errorMsg" class="error" style="color: var(--error-color);">{{ errorMsg }}</div>
      <template v-else>
        <div v-if="customTools.length > 0" class="tools-grid">
          <div v-for="tool in customTools" :key="tool.name"
            class="tool-card custom-tool" @click="openExecution(tool)">
            <h4>{{ formatToolName(tool.name) }}</h4>
            <p>
              <template v-if="tool.description">
                名称：{{ parsedDescription(tool.description).name }}<br>
                简介：{{ parsedDescription(tool.description).brief || '无简介' }}
              </template>
              <template v-else>自定义扫描工具</template>
            </p>
            <span class="tool-category custom">自定义</span>
          </div>
          <div class="tool-card new-custom-tool-card" @click="openNewToolModal">
            <div class="new-tool-icon">+</div>
            <h4>新建自定义工具</h4>
            <p>上传脚本或通过 AI 生成扫描工具</p>
          </div>
        </div>
        <div v-else class="tools-grid">
          <div class="tool-card new-custom-tool-card" @click="openNewToolModal">
            <div class="new-tool-icon">+</div>
            <h4>新建自定义工具</h4>
            <p>上传脚本或通过 AI 生成扫描工具</p>
          </div>
        </div>
      </template>
    </template>

    <Transition name="overlay-fade">
      <div v-if="execution.show" class="tool-execution-overlay" @click.self="closeExecution"></div>
    </Transition>

    <Transition name="panel-slide">
      <div v-if="execution.show" class="tool-execution" id="toolExecution">
        <div class="execution-header">
          <h3 id="executionTitle">执行工具: {{ formatToolName(execution.toolName) }}</h3>
          <button class="close-btn" id="closeExecution" @click="closeExecution">×</button>
        </div>
        <div class="execution-form">
          <input 
            type="text" 
            id="toolTarget" 
            v-model="execution.target" 
            placeholder="输入目标URL或IP"
            @keydown.enter="runTool"
          >
          <button 
            id="executeToolBtn" 
            class="primary-btn" 
            @click="runTool" 
            :disabled="execution.isExecuting"
          >
            {{ execution.isExecuting ? '执行中...' : '执行' }}
          </button>
        </div>
        <div class="execution-result" v-show="execution.resultText || execution.resultData">

          <div v-if="execution.resultText" class="result-text">{{ execution.resultText }}</div>

          <div v-if="execution.resultData" class="result-structured">

            <!-- 基础信息：目标 / 工具 / 时间 -->
            <div class="result-section">
              <div class="result-row">
                <span class="result-label">目标</span>
                <span class="result-value mono">{{ execution.resultData.target }}</span>
              </div>
              <div class="result-row">
                <span class="result-label">工具</span>
                <span class="result-value">{{ formatToolName(execution.resultData.tool_name) }}</span>
              </div>
              <div class="result-row">
                <span class="result-label">时间</span>
                <span class="result-value">{{ formatTimestamp(execution.resultData.timestamp) }}</span>
              </div>
            </div>

            <!-- 分析报告：总结 + 详细分析，均以 Markdown 渲染 -->
            <div v-if="analysisContent" class="result-report-section">
              <div class="report-summary markdown-body" v-html="renderedSummary"></div>
              <div class="report-analysis markdown-body" v-html="renderedAnalysis"></div>
            </div>

          </div>
        </div>
      </div>
    </Transition>

    <!-- 新建自定义工具遮罩 -->
    <Transition name="overlay-fade">
      <div v-if="newToolModal.show" class="tool-execution-overlay" @click.self="closeNewToolModal"></div>
    </Transition>

    <!-- 新建自定义工具弹窗 -->
    <Transition name="panel-slide">
      <div v-if="newToolModal.show" class="tool-execution new-tool-modal">
        <div class="execution-header">
          <h3>新建自定义工具</h3>
          <button class="close-btn" @click="closeNewToolModal">×</button>
        </div>

        <!-- 步骤 1：选择操作类型 -->
        <div v-if="newToolModal.step === 'select'" class="new-tool-options">
          <div class="option-card" @click="newToolModal.step = 'upload'">
            <h4>上传脚本</h4>
            <p>粘贴你的 Python 扫描脚本代码</p>
          </div>
          <div class="option-card" @click="newToolModal.step = 'generate'">
            <h4>生成脚本</h4>
            <p>描述需求，AI 自动生成扫描脚本</p>
          </div>
        </div>

        <!-- 步骤 2a：上传脚本表单 -->
        <div v-if="newToolModal.step === 'upload'" class="new-tool-form">
          <div class="form-group">
            <label>脚本名称 <span class="required">*</span></label>
            <input type="text" v-model="uploadForm.scriptName"
              placeholder="例如: custom_port_scanner" maxlength="64">
            <div v-if="uploadForm.errors.name" class="form-error">{{ uploadForm.errors.name }}</div>
          </div>
          <div class="form-group">
            <label>脚本内容 <span class="required">*</span></label>
            <textarea v-model="uploadForm.scriptContent" class="script-editor"
              placeholder="def run(target: str):&#10;    # 在此编写扫描逻辑&#10;    return {&quot;success&quot;: True}"
              rows="12" spellcheck="false"></textarea>
            <div v-if="uploadForm.errors.content" class="form-error">{{ uploadForm.errors.content }}</div>
          </div>
          <div class="form-actions">
            <button class="secondary-btn" @click="newToolModal.step = 'select'">返回</button>
            <button class="primary-btn" @click="submitUploadScript"
              :disabled="uploadForm.submitting">
              {{ uploadForm.submitting ? '上传中...' : '提交脚本' }}
            </button>
          </div>
          <div v-if="uploadForm.statusMsg" class="form-status"
            :class="uploadForm.statusType">{{ uploadForm.statusMsg }}</div>
        </div>

        <!-- 步骤 2b：生成脚本表单 -->
        <div v-if="newToolModal.step === 'generate'" class="new-tool-form">
          <div class="form-group">
            <label>功能描述 <span class="required">*</span></label>
            <textarea v-model="generateForm.description" class="desc-input"
              placeholder="例如：检测目标网站是否存在敏感文件泄露，扫描常见的备份文件路径..."
              rows="5"></textarea>
            <div class="char-count">{{ generateForm.description.length }}/500</div>
            <div v-if="generateForm.errors.description" class="form-error">{{ generateForm.errors.description }}</div>
          </div>
          <div class="form-actions">
            <button class="secondary-btn" @click="newToolModal.step = 'select'">返回</button>
            <button class="primary-btn" @click="submitGenerateScript"
              :disabled="generateForm.submitting">
              {{ generateForm.submitting ? '生成中...' : '生成脚本' }}
            </button>
          </div>
          <div v-if="generateForm.statusMsg" class="form-status"
            :class="generateForm.statusType">{{ generateForm.statusMsg }}</div>

          <!-- 生成预览 -->
          <div v-if="generateForm.generatedCode" class="generated-preview">
            <div class="preview-header">
              <h4>生成结果预览：{{ generateForm.generatedToolName }}</h4>
              <p class="preview-desc">{{ generateForm.generatedDesc }}</p>
            </div>
            <textarea v-model="generateForm.generatedCode" class="script-editor"
              rows="12" spellcheck="false"></textarea>
            <div class="form-actions">
              <button class="secondary-btn" @click="resetGenerateForm">重新生成</button>
              <button class="primary-btn" @click="confirmGeneratedScript"
                :disabled="generateForm.confirming">
                {{ generateForm.confirming ? '确认中...' : '确认并注册' }}
              </button>
            </div>
          </div>
        </div>
      </div>
    </Transition>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, onBeforeUnmount } from 'vue'
import { API } from '../../services/api.js'
import { showToast } from '../../store.js'
import { marked } from 'marked'
import { ws } from '../../services/websocket.js'

marked.setOptions({ breaks: true, gfm: true })

// === 状态管理 ===
const currentCategory = ref('all')
const isLoading = ref(false)
const errorMsg = ref('')

const toolsList = ref([])
const categoriesDict = reactive({
  info: [],
  vuln: []
})

const execution = reactive({
  show: false,
  toolName: '',
  target: '',
  resultText: '',
  resultData: null,
  analysisData: null,
  isExecuting: false
})

// === 新建自定义工具弹窗状态 ===
const newToolModal = reactive({
  show: false,
  step: 'select' // 'select' | 'upload' | 'generate'
})

// === 上传脚本表单 ===
const uploadForm = reactive({
  scriptName: '',
  scriptContent: '',
  errors: { name: '', content: '' },
  submitting: false,
  statusMsg: '',
  statusType: ''
})

// === 生成脚本表单 ===
const generateForm = reactive({
  description: '',
  errors: { description: '' },
  submitting: false,
  confirming: false,
  statusMsg: '',
  statusType: '',
  generatedCode: '',
  generatedToolName: '',
  generatedDesc: ''
})

// === WebSocket 连接管理 ===
const ensureWsConnected = async () => {
  if (ws.isConnected()) return true
  try {
    await ws.connect()
    return true
  } catch (e) {
    showToast('WebSocket 连接失败，请检查后端服务', 'error')
    return false
  }
}

// 保存 handler 引用用于清理
const wsHandlers = {
  scriptRegistered: null,
  scriptGenerated: null,
  scriptError: null
}

const setupWsHandlers = () => {
  wsHandlers.scriptRegistered = (payload) => {
    if (uploadForm.submitting) {
      uploadForm.submitting = false
      uploadForm.statusMsg = `脚本 "${payload.tool_name}" 注册成功！`
      uploadForm.statusType = 'success'
      showToast('脚本上传成功', 'success')
      loadTools()
      setTimeout(() => {
        resetUploadForm()
        newToolModal.step = 'select'
      }, 1500)
    }
    if (generateForm.confirming) {
      generateForm.confirming = false
      generateForm.statusMsg = `脚本 "${payload.tool_name}" 确认注册成功！`
      generateForm.statusType = 'success'
      showToast('脚本注册成功', 'success')
      loadTools()
      setTimeout(() => {
        resetGenerateForm()
        newToolModal.step = 'select'
      }, 1500)
    }
  }
  ws.on('script_registered', wsHandlers.scriptRegistered)

  wsHandlers.scriptGenerated = (payload) => {
    if (!generateForm.submitting) return
    generateForm.submitting = false
    generateForm.generatedToolName = payload.tool_name || ''
    generateForm.generatedCode = payload.script_code || ''
    generateForm.generatedDesc = payload.description || ''
    generateForm.statusMsg = ''
    showToast('脚本生成成功，请预览确认', 'success')
  }
  ws.on('script_generated', wsHandlers.scriptGenerated)

  wsHandlers.scriptError = (payload) => {
    const errMsg = payload?.error || payload?.message || '未知错误'
    if (uploadForm.submitting) {
      uploadForm.submitting = false
      uploadForm.statusMsg = `上传失败: ${errMsg}`
      uploadForm.statusType = 'error'
      showToast('脚本上传失败', 'error')
    }
    if (generateForm.submitting) {
      generateForm.submitting = false
      generateForm.statusMsg = `生成失败: ${errMsg}`
      generateForm.statusType = 'error'
      showToast('脚本生成失败', 'error')
    }
    if (generateForm.confirming) {
      generateForm.confirming = false
      generateForm.statusMsg = `注册失败: ${errMsg}`
      generateForm.statusType = 'error'
      showToast('脚本注册失败', 'error')
    }
  }
  ws.on('script_error', wsHandlers.scriptError)
}

const teardownWsHandlers = () => {
  if (wsHandlers.scriptRegistered) {
    ws.off('script_registered', wsHandlers.scriptRegistered)
    wsHandlers.scriptRegistered = null
  }
  if (wsHandlers.scriptGenerated) {
    ws.off('script_generated', wsHandlers.scriptGenerated)
    wsHandlers.scriptGenerated = null
  }
  if (wsHandlers.scriptError) {
    ws.off('script_error', wsHandlers.scriptError)
    wsHandlers.scriptError = null
  }
}

// === 弹窗控制 ===
const openNewToolModal = () => {
  newToolModal.show = true
  newToolModal.step = 'select'
  resetUploadForm()
  resetGenerateForm()
}

const closeNewToolModal = () => {
  newToolModal.show = false
  newToolModal.step = 'select'
  resetUploadForm()
  resetGenerateForm()
}

// === 上传脚本 — 验证 ===
const validateUploadForm = () => {
  const errors = { name: '', content: '' }
  let valid = true

  if (!uploadForm.scriptName.trim()) {
    errors.name = '脚本名称不能为空'
    valid = false
  }
  if (uploadForm.scriptName.length > 64) {
    errors.name = '脚本名称不能超过 64 个字符'
    valid = false
  }
  if (!uploadForm.scriptContent.trim()) {
    errors.content = '脚本内容不能为空'
    valid = false
  } else {
    if (!/def\s+run\s*\(\s*target(\s*:\s*str)?\s*\)/.test(uploadForm.scriptContent)) {
      errors.content = '脚本必须包含 def run(target: str) 函数定义'
      valid = false
    }
    if (!/return\s*\{/.test(uploadForm.scriptContent)) {
      errors.content = '脚本必须返回 Dict 类型结果（return {...}）'
      valid = false
    }
  }

  uploadForm.errors = errors
  return valid
}

const submitUploadScript = async () => {
  if (!validateUploadForm()) return
  if (!await ensureWsConnected()) return

  uploadForm.submitting = true
  uploadForm.statusMsg = '正在上传脚本...'
  uploadForm.statusType = 'info'

  const sent = ws.send('script_content', {
    script_content: uploadForm.scriptContent,
    script_name: uploadForm.scriptName.trim()
  })

  if (!sent) {
    uploadForm.submitting = false
    uploadForm.statusMsg = '发送失败，WebSocket 未连接'
    uploadForm.statusType = 'error'
  }
}

const resetUploadForm = () => {
  uploadForm.scriptName = ''
  uploadForm.scriptContent = ''
  uploadForm.errors = { name: '', content: '' }
  uploadForm.submitting = false
  uploadForm.statusMsg = ''
  uploadForm.statusType = ''
}

// === 生成脚本 — 验证 ===
const validateGenerateForm = () => {
  const errors = { description: '' }
  let valid = true

  if (!generateForm.description.trim()) {
    errors.description = '功能描述不能为空'
    valid = false
  }
  if (generateForm.description.length > 500) {
    errors.description = '功能描述不能超过 500 个字符'
    valid = false
  }

  generateForm.errors = errors
  return valid
}

const submitGenerateScript = async () => {
  if (!validateGenerateForm()) return
  if (!await ensureWsConnected()) return

  generateForm.submitting = true
  generateForm.statusMsg = 'AI 正在生成脚本...'
  generateForm.statusType = 'info'
  generateForm.generatedCode = ''
  generateForm.generatedToolName = ''

  const sent = ws.send('script_description', {
    description: generateForm.description.trim()
  })

  if (!sent) {
    generateForm.submitting = false
    generateForm.statusMsg = '发送失败，WebSocket 未连接'
    generateForm.statusType = 'error'
  }
}

const confirmGeneratedScript = async () => {
  if (!await ensureWsConnected()) return

  generateForm.confirming = true
  generateForm.statusMsg = '正在注册脚本...'
  generateForm.statusType = 'info'

  const sent = ws.send('script_content', {
    script_content: generateForm.generatedCode,
    script_name: generateForm.generatedToolName
  })

  if (!sent) {
    generateForm.confirming = false
    generateForm.statusMsg = '注册失败，WebSocket 未连接'
    generateForm.statusType = 'error'
    showToast('注册失败，WebSocket 未连接', 'error')
  }
}

const resetGenerateForm = () => {
  generateForm.description = ''
  generateForm.errors = { description: '' }
  generateForm.submitting = false
  generateForm.confirming = false
  generateForm.statusMsg = ''
  generateForm.statusType = ''
  generateForm.generatedCode = ''
  generateForm.generatedToolName = ''
  generateForm.generatedDesc = ''
}

// === 核心数据加载 ===
const loadTools = async () => {
  isLoading.value = true
  errorMsg.value = ''
  try {
    const [toolsResult, categoriesResult] = await Promise.all([
      API.getTools(),
      API.getToolsByCategory()
    ])

    // 根据后端实际数据结构进行赋值
    toolsList.value = toolsResult.data?.tools || []
    categoriesDict.info = categoriesResult.data?.info_collection || []
    categoriesDict.vuln = categoriesResult.data?.vuln_scan || []

  } catch (error) {
    errorMsg.value = `加载失败: ${error.message}`
    showToast('获取工具列表失败', 'error')
  } finally {
    isLoading.value = false
  }
}

// 页面挂载时拉取数据并初始化 WebSocket
onMounted(() => {
  loadTools()
  setupWsHandlers()
})

// 页面销毁时清理 WebSocket 监听器
onBeforeUnmount(() => {
  teardownWsHandlers()
})

// === 计算属性：动态过滤工具列表 ===
const filteredTools = computed(() => {
  const tools = toolsList.value
  if (currentCategory.value === 'all') return tools
  
  if (currentCategory.value === 'info') {
    return tools.filter(t => t.category === 'info_collection' || categoriesDict.info.includes(t.name))
  } 
  if (currentCategory.value === 'vuln') {
    return tools.filter(t => t.category === 'vuln_scan' || categoriesDict.vuln.includes(t.name))
  } 
  if (currentCategory.value === 'custom') {
    return tools.filter(t => t.name.startsWith('custom_') || t.name.startsWith('ai_gen_'))
  }
  return tools
})

// 自定义工具列表（用于专用渲染）
const customTools = computed(() => {
  return toolsList.value.filter(t =>
    t.name.startsWith('custom_') || t.name.startsWith('ai_gen_')
  )
})

// === 过滤器切换 ===
const filterTools = (cat) => {
  currentCategory.value = cat
}

// === 格式化辅助方法 ===
const formatToolName = (name) => {
  if (!name) return ''
  return name.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

const getToolCategoryLabel = (tool) => {
  if (tool.name?.startsWith('custom_') || tool.name?.startsWith('ai_gen_')) return '自定义'
  if (tool.category === 'info_collection') return '信息收集'
  if (tool.category === 'vuln_scan') return '漏洞扫描'
  if (tool.category === 'poc') return 'POC验证'
  return '其他'
}

const parseDescription = (desc) => {
  if (!desc) return { name: '', brief: '' }
  const beforeArgs = desc.split(/Args:/i)[0]
  const paragraphs = beforeArgs
    .split(/\n\s*\n/)
    .map(p => p.replace(/\n/g, ' ').trim())
    .filter(p => p.length > 0)
  return {
    name: paragraphs[0] || '',
    brief: paragraphs[1] || ''
  }
}

const descriptionCache = new Map()

const parsedDescription = (desc) => {
  if (!desc) return { name: '', brief: '' }
  if (!descriptionCache.has(desc)) {
    descriptionCache.set(desc, parseDescription(desc))
  }
  return descriptionCache.get(desc)
}

const formatTimestamp = (ts) => {
  if (!ts) return '-'
  try {
    const d = new Date(ts)
    return d.toLocaleString('zh-CN', {
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit'
    })
  } catch {
    return ts
  }
}

const analysisContent = computed(() => {
  if (!execution.analysisData) return null
  return {
    toolTitle: execution.analysisData.tool_title || execution.toolName,
    target: execution.analysisData.target || execution.resultData?.target || '',
    analysis: execution.analysisData.analysis || '',
    summary: execution.analysisData.summary || '',
    formatted: execution.analysisData.formatted || '',
    hasError: !!execution.analysisData.error
  }
})

const renderedSummary = computed(() => {
  const text = analysisContent.value?.summary
  if (!text) return ''
  return marked.parse(text)
})

const renderedAnalysis = computed(() => {
  const text = analysisContent.value?.analysis
  if (!text) return ''
  return marked.parse(text)
})

// === 执行弹窗逻辑 ===
const openExecution = (tool) => {
  execution.toolName = tool.name
  execution.target = ''
  execution.resultText = ''
  execution.isExecuting = false
  execution.show = true
}

const closeExecution = () => {
  execution.show = false
  execution.toolName = ''
  execution.target = ''
  execution.resultText = ''
  execution.resultData = null
  execution.analysisData = null
}

const runTool = async () => {
  if (!execution.toolName) return
  
  const target = execution.target.trim()
  if (!target) {
    showToast('请输入目标', 'warning')
    return
  }

  execution.isExecuting = true
  execution.resultText = '正在向服务器下发执行指令...'
  execution.resultData = null

  try {
    const result = await API.executeTool(execution.toolName, target)
    const outputData = result.data || result
    execution.resultData = outputData
    execution.analysisData = outputData.analysis || null
    execution.resultText = ''
    
    showToast('执行完成', 'success')
  } catch (error) {
    execution.resultText = '执行失败: \n' + error.message
    execution.resultData = null
    execution.analysisData = null
    showToast('执行失败', 'error')
  } finally {
    execution.isExecuting = false
  }
}
</script>

<style scoped>
.custom-tool {
  border-left: 4px solid var(--warning-color);
}

.tool-execution-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.45);
  z-index: 999;
}

.overlay-fade-enter-active,
.overlay-fade-leave-active {
  transition: opacity 0.3s ease;
}

.overlay-fade-enter-from,
.overlay-fade-leave-to {
  opacity: 0;
}

.panel-slide-enter-active {
  transition: opacity 0.35s cubic-bezier(0.4, 0, 0.2, 1), transform 0.35s cubic-bezier(0.4, 0, 0.2, 1);
}

.panel-slide-leave-active {
  transition: opacity 0.25s cubic-bezier(0.4, 0, 0.2, 1), transform 0.25s cubic-bezier(0.4, 0, 0.2, 1);
}

.panel-slide-enter-from {
  opacity: 0;
  transform: translate(-50%, calc(-50% - 40px));
}

.panel-slide-leave-to {
  opacity: 0;
  transform: translate(-50%, calc(-50% + 30px));
}

.result-text {
  white-space: pre-wrap;
  word-break: break-word;
  font-family: monospace;
  font-size: 13px;
}

.result-structured {
  display: flex;
  flex-direction: column;
}

/* 基础信息区域 — 左对齐、字体放大 */
.result-section {
  padding: 16px 0;
  border-bottom: 1px solid var(--border-color, #e5e7eb);
}

.result-section:last-child {
  border-bottom: none;
}

.result-row {
  display: flex;
  justify-content: flex-start;
  align-items: baseline;
  padding: 8px 0;
  gap: 16px;
}

.result-label {
  font-size: 14px;
  color: var(--text-secondary, #666);
  flex-shrink: 0;
  min-width: 50px;
  font-weight: 500;
}

.result-value {
  font-size: 15px;
  color: var(--text-primary, #111);
  word-break: break-all;
  text-align: left;
}

.result-value.mono {
  font-family: 'Consolas', 'Monaco', monospace;
  font-size: 14px;
}

/* 分析报告容器 — 统一背景，无 AI 装饰 */
.result-report-section {
  background: var(--card-bg, #ffffff);
  border: 1px solid var(--border-color, #e5e7eb);
  border-radius: 8px;
  padding: 24px 28px;
  margin-top: 16px;
}

.report-summary {
  margin-bottom: 24px;
  padding-bottom: 20px;
  border-bottom: 1px solid var(--border-color, #e5e7eb);
}

.report-summary::before {
  content: '总结';
  display: block;
  font-size: 16px;
  font-weight: 600;
  color: var(--text-primary);
  margin-bottom: 12px;
  padding-bottom: 8px;
  border-bottom: 2px solid var(--primary-color, #1677ff);
}

.report-analysis::before {
  content: '详细分析';
  display: block;
  font-size: 16px;
  font-weight: 600;
  color: var(--text-primary);
  margin-bottom: 12px;
  padding-bottom: 8px;
  border-bottom: 2px solid var(--primary-color, #1677ff);
}

/* Markdown 渲染主题 — 统一左对齐，专业文档风格 */
.markdown-body {
  font-size: 14px;
  line-height: 1.8;
  color: var(--text-primary);
  text-align: left;
}

.markdown-body :deep(h1),
.markdown-body :deep(h2),
.markdown-body :deep(h3),
.markdown-body :deep(h4) {
  color: var(--text-primary);
  margin: 16px 0 8px;
  font-weight: 600;
}

.markdown-body :deep(h1) { font-size: 20px; }
.markdown-body :deep(h2) { font-size: 18px; }
.markdown-body :deep(h3) { font-size: 16px; }

.markdown-body :deep(p) {
  margin: 8px 0;
  text-align: left;
}

.markdown-body :deep(strong) {
  font-weight: 600;
  color: var(--text-primary);
}

.markdown-body :deep(code) {
  background: #f5f5f5;
  padding: 2px 6px;
  border-radius: 4px;
  font-family: 'Consolas', 'Monaco', monospace;
  font-size: 13px;
}

.markdown-body :deep(pre) {
  background: #1e293b;
  color: #e2e8f0;
  padding: 16px;
  border-radius: 8px;
  overflow-x: auto;
  font-size: 13px;
  line-height: 1.6;
  margin: 12px 0;
}

.markdown-body :deep(pre code) {
  background: none;
  padding: 0;
  color: inherit;
}

.markdown-body :deep(blockquote) {
  border-left: 4px solid var(--primary-color, #1677ff);
  padding: 8px 16px;
  margin: 12px 0;
  background: #f8fafc;
  color: var(--text-secondary);
}

.markdown-body :deep(ul),
.markdown-body :deep(ol) {
  padding-left: 24px;
  margin: 8px 0;
}

.markdown-body :deep(li) {
  margin: 4px 0;
  text-align: left;
}

.markdown-body :deep(table) {
  width: 100%;
  border-collapse: collapse;
  margin: 12px 0;
}

.markdown-body :deep(th),
.markdown-body :deep(td) {
  border: 1px solid var(--border-color);
  padding: 8px 12px;
  text-align: left;
}

.markdown-body :deep(th) {
  background: #f5f7fa;
  font-weight: 600;
}

/* 响应式适配 */
@media (max-width: 768px) {
  .result-row {
    flex-direction: column;
    gap: 2px;
  }

  .result-value {
    text-align: left;
  }

  .result-report-section {
    padding: 16px;
  }

  .markdown-body {
    font-size: 13px;
  }
}

/* 新建自定义工具卡片 */
.new-custom-tool-card {
  border: 2px dashed var(--border-color, #d9d9d9);
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  cursor: pointer;
  transition: all 0.3s ease;
  min-height: 180px;
}

.new-custom-tool-card:hover {
  border-color: var(--primary-color, #1677ff);
  background: #f0f5ff;
}

.new-tool-icon {
  font-size: 36px;
  color: var(--primary-color, #1677ff);
  font-weight: 300;
  margin-bottom: 12px;
}

/* 新建工具弹窗选项 */
.new-tool-options {
  display: flex;
  gap: 20px;
  padding: 8px 0;
  justify-content: center;
}

.option-card {
  flex: 0 1 240px;
  padding: 24px;
  border: 1px solid var(--border-color, #e5e7eb);
  border-radius: 10px;
  cursor: pointer;
  transition: all 0.25s ease;
  text-align: center;
}

.option-card:hover {
  border-color: var(--primary-color, #1677ff);
  box-shadow: 0 4px 16px rgba(22, 119, 255, 0.12);
  transform: translateY(-2px);
}

.option-icon {
  font-size: 32px;
  margin-bottom: 10px;
}

.option-card h4 {
  font-size: 16px;
  margin-bottom: 6px;
  color: var(--text-primary);
}

.option-card p {
  font-size: 13px;
  color: var(--text-secondary);
}

/* 新建工具弹窗专用覆盖 */
.new-tool-modal {
  width: 650px !important;
}

.new-tool-modal .execution-header h3 {
  text-align: center;
  flex: 1;
}

/* 新建工具表单 */
.new-tool-form {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.form-group label {
  font-size: 16px;
  font-weight: 500;
  color: var(--text-primary);
}

.required {
  color: var(--error-color, #ff4d4f);
}

.form-group input[type="text"] {
  height: 40px;
  padding: 0 12px;
  border: 1px solid var(--border-color);
  border-radius: 6px;
  font-size: 14px;
  outline: none;
  transition: border-color 0.2s;
}

.form-group input[type="text"]:focus,
.form-group textarea:focus {
  border-color: var(--primary-color);
}

.script-editor {
  padding: 12px;
  border: 1px solid var(--border-color);
  border-radius: 6px;
  font-size: 13px;
  font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
  line-height: 1.6;
  resize: vertical;
  outline: none;
  background: #fafbfc;
  tab-size: 4;
}

.desc-input {
  padding: 12px;
  border: 1px solid var(--border-color);
  border-radius: 6px;
  font-size: 14px;
  line-height: 1.6;
  resize: vertical;
  outline: none;
}

.char-count {
  font-size: 12px;
  color: var(--text-secondary);
  text-align: right;
}

.form-error {
  font-size: 12px;
  color: var(--error-color, #ff4d4f);
  padding: 4px 0;
}

.form-actions {
  display: flex;
  gap: 12px;
  justify-content: flex-end;
}

.form-status {
  padding: 10px 14px;
  border-radius: 6px;
  font-size: 13px;
}

.form-status.info {
  background: #e6f4ff;
  color: #1677ff;
  border: 1px solid #91caff;
}

.form-status.success {
  background: #f6ffed;
  color: #52c41a;
  border: 1px solid #b7eb8f;
}

.form-status.error {
  background: #fff2f0;
  color: #ff4d4f;
  border: 1px solid #ffccc7;
}

/* 生成预览 */
.generated-preview {
  margin-top: 16px;
  padding: 16px;
  background: #fafbfc;
  border: 1px solid var(--border-color);
  border-radius: 8px;
}

.preview-header h4 {
  font-size: 15px;
  color: var(--text-primary);
  margin-bottom: 4px;
}

.preview-desc {
  font-size: 13px;
  color: var(--text-secondary);
  margin-bottom: 12px;
}

/* 响应式 */
@media (max-width: 768px) {
  .new-tool-options {
    flex-direction: column;
  }

  .option-card {
    padding: 16px;
  }
}
</style>

<style scoped>
.tool-card {
  border: 1px solid var(--border-light);
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  padding: 24px;
}

.tool-card:hover {
  border-color: var(--text-primary);
  transform: translateY(-2px);
}

.filter-btn {
  background: transparent;
  border: 1px solid var(--border-light);
  border-radius: 20px;
  color: var(--text-secondary);
}

.filter-btn.active {
  background: var(--text-primary);
  color: #fff;
  border-color: var(--text-primary);
}

/* 弹窗尺寸覆盖 — 覆盖全局 style.css 中的 500px / 300px 限制 */
.tool-execution {
  width: 600px !important;
  max-width: 95vw !important;
  max-height: 92vh;
  overflow-y: auto;
  padding: 32px !important;
}

.execution-result {
  max-height: 70vh !important;
  overflow: auto;
  padding: 20px !important;
  font-family: inherit !important;
  white-space: normal !important;
}

@media (max-width: 1200px) {
  .tool-execution {
    width: 90vw !important;
    padding: 24px !important;
  }
  .execution-result {
    max-height: 60vh !important;
  }
}

@media (max-width: 768px) {
  .tool-execution {
    width: 95vw !important;
    padding: 16px !important;
  }
  .execution-result {
    max-height: 55vh !important;
    padding: 12px !important;
  }
}
</style>