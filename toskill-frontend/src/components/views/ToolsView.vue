<template>
  <div id="page-tools" class="page active">
    <div class="page-header">
      <div>
        <h2>安全工具</h2>
      </div>
      <button class="primary-btn create-tool-btn" @click="openNewToolModal">+ 新建工具</button>
    </div>

    <div class="tools-controls">
      <div class="tools-filter primary-filter" aria-label="工具类型">
        <button
          class="filter-btn"
          :class="{ active: currentCategory === 'info_collection' }"
          @click="filterTools('info_collection')"
        >信息收集 <span>{{ categoryCounts.info_collection }}</span></button>
        <button
          class="filter-btn"
          :class="{ active: currentCategory === 'vuln_scan' }"
          @click="filterTools('vuln_scan')"
        >漏洞扫描 <span>{{ categoryCounts.vuln_scan }}</span></button>
      </div>

      <div class="source-switch" role="group" aria-label="工具来源">
        <button
          class="source-switch-btn"
          :class="{ active: currentSource === 'system' }"
          @click="currentSource = 'system'"
        >系统工具 <span>{{ sourceCounts.system }}</span></button>
        <button
          class="source-switch-btn"
          :class="{ active: currentSource === 'custom' }"
          @click="currentSource = 'custom'"
        >自定义工具 <span>{{ sourceCounts.custom }}</span></button>
      </div>
    </div>

    <div class="tools-grid" id="toolsGrid">
      <div v-if="isLoading" class="loading empty-state">加载工具列表...</div>
      <div v-else-if="errorMsg" class="error empty-state">{{ errorMsg }}</div>
      <div v-else-if="filteredTools.length === 0" class="empty-state">
        <strong>暂无{{ currentSource === 'system' ? '系统' : '自定义' }}工具</strong>
        <span v-if="currentSource === 'custom'">点击右上角“新建工具”添加到当前分类</span>
      </div>
      <article
        v-for="tool in filteredTools"
        :key="tool.name"
        class="tool-card"
        :class="{ 'custom-tool': tool.source === 'custom', highlighted: highlightedTool === tool.name }"
        @click="openExecution(tool)"
      >
        <div class="tool-card-header">
          <h4>{{ formatToolName(tool.name) }}</h4>
          <button v-if="tool.source === 'custom'" class="tool-delete-btn"
            title="删除自定义工具" aria-label="删除自定义工具" @click.stop="deleteCustomTool(tool)">×</button>
        </div>
        <p>{{ parsedDescription(tool.description).brief || parsedDescription(tool.description).name || '安全扫描工具' }}</p>
        <div class="tool-card-meta">
          <span class="tool-category" :class="tool.category">{{ getToolCategoryLabel(tool) }}</span>
          <span class="tool-source" :class="tool.source">{{ getToolSourceLabel(tool) }}</span>
          <span v-if="tool.created_at" class="tool-created">{{ formatDate(tool.created_at) }}</span>
        </div>
      </article>
    </div>

    <Transition name="overlay-fade">
      <div v-if="execution.show" class="tool-execution-overlay" @click.self="closeExecution"></div>
    </Transition>

    <Transition name="panel-slide">
      <div v-if="execution.show" class="tool-execution" id="toolExecution">
        <div class="execution-header">
          <div class="execution-title">
            <h3 id="executionTitle">{{ formatToolName(execution.toolName) }}</h3>
            <p>{{ executionToolDescription }}</p>
          </div>
          <button class="close-btn" id="closeExecution" aria-label="关闭执行窗口" @click="closeExecution">×</button>
        </div>
        <div class="execution-form-field">
          <div class="execution-form">
            <input
              type="text"
              id="toolTarget"
              v-model="execution.target"
              placeholder="输入目标 URL 或 IP"
              @keydown.enter="runTool"
            >
            <button
              id="executeToolBtn"
              class="primary-btn execute-tool-btn"
              @click="runTool"
              :disabled="execution.isExecuting"
            >
              {{ execution.isExecuting ? '执行中...' : '执行' }}
            </button>
          </div>
        </div>

        <div v-if="execution.isExecuting" class="execution-pending" role="status">
          <span class="pending-spinner" aria-hidden="true"></span>
          <span>正在执行工具，请稍候…</span>
        </div>

        <div v-else-if="execution.resultText" class="execution-error" role="alert">
          {{ execution.resultText }}
        </div>

        <div v-if="execution.resultData" class="execution-result">
          <div class="execution-status" :class="{ failed: !executionSucceeded }">
            <span class="status-icon" aria-hidden="true">{{ executionSucceeded ? '✓' : '!' }}</span>
            <p class="status-line">
              <strong>{{ executionSucceeded ? '执行完成' : '执行未完成' }}</strong>
              <span aria-hidden="true"> · </span>
              <span>{{ executionStatusText }}</span>
            </p>
          </div>

          <div class="result-structured">

            <div class="result-meta" aria-label="本次执行信息">
              <span><b>目标</b>{{ execution.resultData.target }}</span>
              <span><b>执行时间</b>{{ formatTimestamp(execution.resultData.timestamp) }}</span>
            </div>

            <div v-if="executionCategory === 'info_collection'" class="result-report-section information-output">
              <h4>收集结果</h4>
              <div v-if="executionInformationGroups.length" class="information-groups">
                <section v-for="group in executionInformationGroups" :key="group.title || 'default'" class="information-group">
                  <h5 v-if="group.title">{{ group.title }}</h5>
                  <dl class="information-list">
                    <div v-for="item in group.items" :key="`${group.title}-${item.label}`" class="result-row">
                      <dt class="result-label">{{ item.label }}</dt>
                      <dd class="result-value">
                        <a v-if="item.href" :href="item.href" target="_blank" rel="noopener noreferrer">{{ item.value }}</a>
                        <span v-else>{{ item.value }}</span>
                      </dd>
                    </div>
                  </dl>
                </section>
              </div>
              <p v-else class="result-empty">本次执行完成，工具未返回可展示的信息。</p>
            </div>

            <!-- 漏洞类工具才展示漏洞分析，避免信息工具出现“未发现漏洞”。 -->
            <div v-else-if="analysisContent" class="result-report-section">
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
      <div v-if="newToolModal.show" class="tool-execution new-tool-modal"
        :class="{ 'generated-preview-modal': isGeneratedPreview }">
        <div v-if="!isGeneratedPreview" class="execution-header">
          <h3>新建自定义工具</h3>
          <button class="close-btn" @click="closeNewToolModal">×</button>
        </div>

        <div v-if="!isGeneratedPreview" class="tool-type-picker" role="group" aria-label="工具类型">
          <button v-for="option in toolTypeOptions" :key="option.value"
            type="button"
            :class="{ active: newToolModal.category === option.value }"
            @click="newToolModal.category = option.value">{{ option.label }}</button>
        </div>

        <!-- 步骤 1：选择创建方式 -->
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
        <div v-if="newToolModal.step === 'generate' && !isGeneratedPreview" class="new-tool-form">
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
        </div>

        <section v-else-if="isGeneratedPreview" class="generated-script-preview">
          <header class="generated-preview-header">
            <div>
              <h3>AI 生成脚本</h3>
              <p class="generated-preview-state">
                <span class="generated-type-badge">{{ generatedToolCategoryLabel }}</span>
                <span>已生成，等待确认注册</span>
              </p>
            </div>
            <button class="close-btn" aria-label="关闭脚本预览" @click="closeNewToolModal">×</button>
          </header>

          <div class="generated-script-summary">
            <h4>{{ generateForm.generatedToolName }}</h4>
            <p v-if="generateForm.generatedDesc">{{ generateForm.generatedDesc }}</p>
          </div>

          <p v-if="generateForm.statusType === 'error'" class="generated-preview-error">
            {{ generateForm.statusMsg }}
          </p>

          <div class="generated-code-panel">
            <div class="generated-code-panel-header">
              <span>脚本代码</span>
              <span>可编辑</span>
            </div>
            <textarea v-model="generateForm.generatedCode" class="script-editor generated-code-editor"
              spellcheck="false" aria-label="生成的脚本代码"></textarea>
          </div>

          <footer class="generated-preview-actions">
            <button class="secondary-btn" @click="returnToGenerateForm" :disabled="generateForm.confirming">重新生成</button>
            <button class="primary-btn" @click="confirmGeneratedScript" :disabled="generateForm.confirming">
              {{ generateForm.confirming ? '确认中...' : '确认并注册' }}
            </button>
          </footer>
        </section>
      </div>
    </Transition>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { API } from '../../services/api.js'
import { showToast } from '../../store.js'
import { marked } from 'marked'
import { formatInformationResult } from '../../utils/informationResultFormatter.js'
import { generateLocalScript } from '../../utils/localScriptGenerator.js'

marked.setOptions({ breaks: true, gfm: true })

// === 状态管理 ===
const currentCategory = ref('info_collection')
const currentSource = ref('system')
const highlightedTool = ref('')
const isLoading = ref(false)
const errorMsg = ref('')

const toolsList = ref([])
const toolTypeOptions = [
  { value: 'info_collection', label: '信息收集脚本' },
  { value: 'vuln_scan', label: '漏洞扫描脚本' }
]

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
  step: 'select', // 'select' | 'upload' | 'generate'
  category: 'info_collection'
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

const isGeneratedPreview = computed(() =>
  newToolModal.step === 'generate' && Boolean(generateForm.generatedCode)
)

const generatedToolCategoryLabel = computed(() =>
  toolTypeOptions.find(option => option.value === newToolModal.category)?.label || '自定义脚本'
)

// === 弹窗控制 ===
const openNewToolModal = () => {
  newToolModal.show = true
  newToolModal.step = 'select'
  newToolModal.category = currentCategory.value
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

  uploadForm.submitting = true
  uploadForm.statusMsg = '正在校验并注册脚本...'
  uploadForm.statusType = 'info'

  try {
    const result = await API.registerCustomTool({
      tool_name: uploadForm.scriptName.trim(),
      script_content: uploadForm.scriptContent,
      description: `${getCategoryLabel(newToolModal.category)}自定义工具`,
      category: newToolModal.category,
      creation_method: 'upload',
      include_in_default_scan: false
    })
    await handleRegisteredTool(result.data?.tool)
  } catch (error) {
    uploadForm.submitting = false
    uploadForm.statusMsg = `注册失败：${error.message}`
    uploadForm.statusType = 'error'
    showToast('脚本注册失败', 'error')
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

const submitGenerateScript = () => {
  if (!validateGenerateForm()) return

  generateForm.submitting = true
  generateForm.statusMsg = '正在本地生成脚本...'
  generateForm.statusType = 'info'
  generateForm.generatedCode = ''
  generateForm.generatedToolName = ''

  const generated = generateLocalScript({
    placement: 'tools',
    description: generateForm.description,
    category: newToolModal.category
  })
  generateForm.submitting = false
  generateForm.generatedToolName = generated.toolName
  generateForm.generatedCode = generated.scriptCode
  generateForm.generatedDesc = generated.description
  generateForm.statusMsg = '脚本已在本地生成，请预览后确认注册'
  generateForm.statusType = 'success'
  showToast('脚本已在本地生成，请预览确认', 'success')
}

const confirmGeneratedScript = async () => {
  generateForm.confirming = true
  generateForm.statusMsg = '正在注册脚本...'
  generateForm.statusType = 'info'

  try {
    const result = await API.registerCustomTool({
      tool_name: generateForm.generatedToolName,
      script_content: generateForm.generatedCode,
      description: generateForm.generatedDesc || generateForm.description.trim(),
      category: newToolModal.category,
      creation_method: 'ai_generate',
      include_in_default_scan: false
    })
    await handleRegisteredTool(result.data?.tool)
  } catch (error) {
    generateForm.confirming = false
    generateForm.statusMsg = `注册失败：${error.message}`
    generateForm.statusType = 'error'
    showToast('脚本注册失败', 'error')
  }
}

const handleRegisteredTool = async (tool) => {
  const toolName = tool?.name || uploadForm.scriptName || generateForm.generatedToolName
  currentCategory.value = tool?.category || newToolModal.category
  currentSource.value = 'custom'
  highlightedTool.value = toolName
  await loadTools()
  uploadForm.submitting = false
  generateForm.confirming = false
  showToast(`工具“${formatToolName(toolName)}”已添加到自定义工具`, 'success')
  closeNewToolModal()
  setTimeout(() => {
    if (highlightedTool.value === toolName) highlightedTool.value = ''
  }, 4000)
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

const returnToGenerateForm = () => {
  generateForm.errors = { description: '' }
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
    const toolsResult = await API.getTools()
    toolsList.value = toolsResult.data?.tools || []

  } catch (error) {
    errorMsg.value = `加载失败: ${error.message}`
    showToast('获取工具列表失败', 'error')
  } finally {
    isLoading.value = false
  }
}

// 页面挂载时拉取工具数据
onMounted(() => {
  loadTools()
})

// === 计算属性：动态过滤工具列表 ===
const filteredTools = computed(() => {
  return toolsList.value.filter(tool =>
    tool.category === currentCategory.value && tool.source === currentSource.value
  )
})

const categoryCounts = computed(() => ({
  info_collection: toolsList.value.filter(tool => tool.category === 'info_collection').length,
  vuln_scan: toolsList.value.filter(tool => tool.category === 'vuln_scan').length
}))

const sourceCounts = computed(() => ({
  system: toolsList.value.filter(tool =>
    tool.category === currentCategory.value && tool.source === 'system'
  ).length,
  custom: toolsList.value.filter(tool =>
    tool.category === currentCategory.value && tool.source === 'custom'
  ).length
}))

const deleteCustomTool = async (tool) => {
  if (!window.confirm(`确定删除自定义工具“${formatToolName(tool.name)}”吗？`)) return
  try {
    await API.deleteCustomTool(tool.name)
    await loadTools()
    showToast('自定义工具已删除', 'success')
  } catch (error) {
    showToast(`删除失败：${error.message}`, 'error')
  }
}

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
  if (tool.category === 'info_collection') return '信息收集'
  if (tool.category === 'vuln_scan') return '漏洞扫描'
  if (tool.category === 'poc') return 'POC验证'
  return '其他'
}

const getCategoryLabel = (category) => category === 'vuln_scan' ? '漏洞扫描' : '信息收集'

const getToolSourceLabel = (tool) => {
  if (tool.source !== 'custom') return '系统工具'
  return tool.creation_method === 'ai_generate' ? 'AI 生成' : '上传脚本'
}

const formatDate = (ts) => {
  if (!ts) return ''
  return new Date(ts).toLocaleDateString('zh-CN')
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

const executionCategory = computed(() => {
  if (execution.resultData?.tool_category) return execution.resultData.tool_category
  return toolsList.value.find(tool => tool.name === execution.toolName)?.category || 'vuln_scan'
})

const executionToolDescription = computed(() => {
  const tool = toolsList.value.find(item => item.name === execution.toolName)
  const description = parsedDescription(tool?.description).brief || parsedDescription(tool?.description).name
  const categoryLabel = executionCategory.value === 'info_collection' ? '信息收集工具' : '漏洞扫描工具'
  return description ? `${categoryLabel} · ${description}` : categoryLabel
})

const executionInformationGroups = computed(() =>
  formatInformationResult(execution.toolName, execution.resultData)
)

const executionInformationItemsCount = computed(() =>
  executionInformationGroups.value.reduce((total, group) => total + group.items.length, 0)
)

const executionSucceeded = computed(() => execution.resultData?.success !== false)

const executionStatusText = computed(() => {
  if (!executionSucceeded.value) {
    return execution.resultData?.error || '工具未能完成本次执行，请检查目标或稍后重试。'
  }
  if (executionCategory.value === 'info_collection') {
    const count = executionInformationItemsCount.value
    const label = execution.toolName === 'baseinfo_scan' ? '基础信息' : '信息'
    return count ? `已收集 ${count} 项${label}` : '工具已完成执行'
  }
  return '扫描已完成，请查看分析结果'
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
.page-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 24px;
}

.create-tool-btn {
  flex-shrink: 0;
  padding-inline: 18px;
  background: var(--primary-color);
}

.create-tool-btn:hover {
  background: var(--primary-hover);
}

.tools-controls {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 26px;
}

.primary-filter {
  margin-bottom: 0;
}

.source-switch {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 4px;
  border-radius: 10px;
  background: #FFFFFF;
  border: 1px solid #E5E7EB;
  flex-shrink: 0;
}

.source-switch-btn {
  border: 1px solid transparent;
  border-radius: 7px;
  background: transparent;
  color: var(--text-secondary);
  padding: 7px 12px;
  font-size: 13px;
  cursor: pointer;
  transition: color 0.2s ease, background 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
}

.source-switch-btn:hover {
  color: #047857;
  background: #FFFFFF;
}

.source-switch-btn.active {
  background: #047857;
  color: #FFFFFF;
  border-color: #047857;
  box-shadow: none;
}

.filter-btn span {
  margin-left: 5px;
  opacity: 0.72;
  font-size: 12px;
}

.empty-state {
  grid-column: 1 / -1;
  min-height: 190px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 8px;
  color: var(--text-secondary);
  border: 1px dashed var(--border-color);
  border-radius: 12px;
}

.custom-tool {
  border-left: 4px solid #10B981;
}

.tool-card.highlighted {
  border-color: #10B981;
  box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.14), 0 10px 28px rgba(16, 185, 129, 0.12);
}

.tool-category {
  color: #047857;
  background: #FFFFFF;
  border: 1px solid #047857;
  border-radius: 999px;
}

.tool-card-header {
  display: flex;
  align-items: flex-start;
  justify-content: center;
  gap: 12px;
  position: relative;
  width: 100%;
}

.tool-card-header h4 {
  text-align: center;
}

.tool-delete-btn {
  position: absolute;
  top: -4px;
  right: -4px;
  width: 24px;
  height: 24px;
  border: 0;
  border-radius: 50%;
  background: transparent;
  color: var(--error-color, #ff4d4f);
  font-size: 20px;
  line-height: 20px;
  cursor: pointer;
  padding: 0;
  opacity: 0.62;
  transition: background 0.2s ease, opacity 0.2s ease;
}

.tool-delete-btn:hover {
  background: #FFF1F0;
  opacity: 1;
}

.tool-card-meta {
  display: flex;
  align-items: center;
  justify-content: center;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 16px;
}

.tool-source {
  font-size: 12px;
  padding: 3px 9px;
  border-radius: 999px;
  color: #4B5563;
  background: #FFFFFF;
  border: 1px solid #E5E7EB;
}

.tool-source.custom {
  color: #FFFFFF;
  background: #047857;
  border-color: #047857;
}

.tool-created {
  color: var(--text-secondary);
  font-size: 12px;
}

.tool-execution-overlay {
  position: fixed;
  inset: 0;
  background: rgba(15, 23, 42, 0.4);
  z-index: 999;
}

.tool-execution {
  border-radius: 16px;
  box-shadow: 0 20px 48px rgba(15, 23, 42, 0.18);
}

.execution-header {
  align-items: flex-start;
  margin-bottom: 24px;
}

.execution-title h3 {
  margin: 0;
  font-size: 20px;
  line-height: 1.35;
}

.execution-title p {
  margin: 0px 0 0;
  color: #6B7280;
  font-size: 13px;
  line-height: 1.6;
}

.close-btn {
  flex: 0 0 auto;
  color: #374151;
  background: #F3F4F6;
  font-size: 19px;
  transition: background 0.2s ease, color 0.2s ease;
}

.close-btn:hover {
  color: #B91C1C;
  background: #FFF1F0;
}

.execution-form-field > label {
  display: block;
  margin-bottom: 8px;
  color: #374151;
  font-size: 13px;
  font-weight: 600;
}

.execution-form {
  gap: 10px;
  margin-bottom: 0;
}

.execution-form input {
  color: #111827;
  background: #FFFFFF;
  border-color: #E5E7EB;
  transition: border-color 0.2s ease, box-shadow 0.2s ease;
}

.execution-form input:focus {
  outline: none;
  border-color: #10B981;
  box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.12);
}

.execution-form input:-webkit-autofill,
.form-group input[type="text"]:-webkit-autofill {
  -webkit-text-fill-color: #111827;
  box-shadow: 0 0 0 1000px #FFFFFF inset;
  caret-color: #111827;
}

.execute-tool-btn {
  min-width: 78px;
  padding-inline: 18px;
  background: var(--primary-color);
}

.execute-tool-btn:hover:not(:disabled) {
  background: var(--primary-hover);
}

.execute-tool-btn:disabled {
  background: var(--primary-disabled);
  color: var(--primary-disabled-text);
}

.execution-pending,
.execution-status,
.execution-error {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-top: 20px;
  padding: 12px 14px;
  border-radius: 10px;
  font-size: 13px;
}

.execution-pending {
  color: #047857;
  background: #ECFDF5;
}

.pending-spinner {
  width: 15px;
  height: 15px;
  border: 2px solid #A7F3D0;
  border-top-color: #10B981;
  border-radius: 50%;
  animation: execution-spin 0.75s linear infinite;
}

.execution-error {
  align-items: flex-start;
  color: #B91C1C;
  background: #FFF1F0;
  white-space: pre-wrap;
  word-break: break-word;
}

.execution-result {
  max-height: 62vh !important;
  margin-top: 20px;
  padding: 0 !important;
  overflow: auto;
  background: transparent !important;
  border-radius: 0;
  font-family: inherit !important;
  white-space: normal !important;
}

.execution-status {
  margin-top: 0;
  color: #047857;
  background: #ECFDF5;
}

.execution-status.failed {
  color: #B91C1C;
  background: #FFF1F0;
}

.status-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 20px;
  height: 20px;
  border-radius: 50%;
  color: #FFFFFF;
  background: #10B981;
  font-size: 13px;
  font-weight: 700;
}

.execution-status.failed .status-icon {
  background: #EF4444;
}

.status-line {
  min-width: 0;
  margin: 0;
  color: inherit;
  line-height: 1.5;
}

.execution-status:not(.failed) .status-line {
  white-space: nowrap;
}

.status-line strong {
  font-weight: 700;
}

.result-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 24px;
  padding: 16px 2px 18px;
  color: #6B7280;
  font-size: 13px;
  border-bottom: 1px solid #E5E7EB;
}

.result-meta span {
  display: inline-flex;
  gap: 8px;
  min-width: 0;
  overflow-wrap: anywhere;
}

.result-meta b {
  color: #374151;
  font-weight: 600;
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

.result-row {
  display: flex;
  align-items: flex-start;
  padding: 13px 0;
  gap: 20px;
  border-bottom: 1px solid #F0F1F3;
}

.result-row:last-child {
  border-bottom: 0;
}

.result-label {
  width: 112px;
  min-width: 112px;
  font-size: 13px;
  color: #6B7280;
  flex-shrink: 0;
  font-weight: 500;
}

.result-value {
  min-width: 0;
  font-size: 14px;
  line-height: 1.65;
  color: #111827;
  overflow-wrap: anywhere;
  text-align: left;
}

.result-value.mono {
  font-family: 'Consolas', 'Monaco', monospace;
  font-size: 14px;
}

.result-report-section {
  padding: 22px 0 0;
  margin-top: 0;
}
.information-output h4 {
  margin-bottom: 6px;
  color: #111827;
  font-size: 16px;
}
.information-list { margin: 0; }
.information-list dd { margin: 0; overflow-wrap: anywhere; }
.information-group + .information-group { margin-top: 22px; }
.information-group h5 {
  margin: 0 0 2px;
  color: #374151;
  font-size: 14px;
  font-weight: 600;
}
.result-value a {
  color: #047857;
  text-decoration: none;
}
.result-value a:hover { text-decoration: underline; }
.result-empty {
  margin: 12px 0 0;
  padding: 14px;
  color: #6B7280;
  background: #F9FAFB;
  border-radius: 8px;
  font-size: 13px;
}

@keyframes execution-spin {
  to { transform: rotate(360deg); }
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
  border-bottom: 2px solid #10B981;
}

.report-analysis::before {
  content: '详细分析';
  display: block;
  font-size: 16px;
  font-weight: 600;
  color: var(--text-primary);
  margin-bottom: 12px;
  padding-bottom: 8px;
  border-bottom: 2px solid #10B981;
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
  border-left: 4px solid #10B981;
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
    padding: 18px 0 0;
  }

  .result-meta {
    align-items: flex-start;
    flex-direction: column;
    gap: 8px;
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
  border-color: #10B981;
  background: #F0FDF4;
}

.new-tool-icon {
  font-size: 36px;
  color: #10B981;
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

.tool-type-picker {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  margin: 2px 0 24px;
}

.tool-type-picker button {
  flex: 0 1 210px;
  min-height: 44px;
  padding: 10px 18px;
  border: 1px solid #D1D5DB;
  border-radius: 8px;
  background: #FFFFFF;
  color: #4B5563;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  transition: color 0.2s ease, background 0.2s ease, border-color 0.2s ease;
}

.tool-type-picker button:hover:not(.active) {
  color: #047857;
  border-color: #047857;
}

.tool-type-picker button.active {
  border-color: #047857;
  color: #FFFFFF;
  background: #047857;
}

.tool-type-picker button:focus-visible {
  outline: 3px solid rgba(16, 185, 129, 0.22);
  outline-offset: 2px;
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
  border-color: #10B981;
  box-shadow: 0 4px 16px rgba(16, 185, 129, 0.12);
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

.new-tool-modal.generated-preview-modal {
  width: min(1180px, 94vw) !important;
  max-width: 94vw !important;
  height: min(780px, 90vh);
  max-height: 90vh;
  padding: 0 !important;
  overflow: hidden !important;
  display: flex;
  flex-direction: column;
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
  background: #FFFFFF;
}

.form-group input[type="text"]:focus,
.form-group textarea:focus {
  border-color: #10B981;
  box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.1);
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
  background: #FFFFFF;
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
  background: #ECFDF5;
  color: #047857;
  border: 1px solid #A7F3D0;
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

/* AI 脚本预览 */
.generated-script-preview {
  display: flex;
  flex: 1;
  flex-direction: column;
  min-height: 0;
  padding: 26px 30px 22px;
}

.generated-preview-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 20px;
  padding-bottom: 18px;
  border-bottom: 1px solid #E5E7EB;
}

.generated-preview-header h3 {
  margin: 0;
  color: #111827;
  font-size: 20px;
  line-height: 1.35;
}

.generated-preview-state {
  display: flex;
  align-items: center;
  gap: 10px;
  margin: 8px 0 0;
  color: #6B7280;
  font-size: 13px;
}

.generated-type-badge {
  padding: 3px 8px;
  border: 1px solid #047857;
  border-radius: 999px;
  color: #047857;
  font-size: 12px;
  font-weight: 600;
}

.generated-script-summary {
  padding: 18px 0 14px;
}

.generated-script-summary h4 {
  margin: 0;
  color: #111827;
  font-size: 16px;
  line-height: 1.45;
}

.generated-script-summary p {
  margin: 5px 0 0;
  color: #6B7280;
  font-size: 13px;
  line-height: 1.55;
}

.generated-preview-error {
  margin: 0 0 12px;
  padding: 9px 12px;
  border: 1px solid #FECACA;
  border-radius: 8px;
  color: #B91C1C;
  background: #FEF2F2;
  font-size: 13px;
}

.generated-code-panel {
  display: flex;
  flex: 1;
  flex-direction: column;
  min-height: 0;
  overflow: hidden;
  border: 1px solid #D1D5DB;
  border-radius: 10px;
  background: #F9FAFB;
}

.generated-code-panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 14px;
  border-bottom: 1px solid #E5E7EB;
  color: #374151;
  font-size: 13px;
  font-weight: 600;
}

.generated-code-panel-header span:last-child {
  color: #047857;
  font-size: 12px;
  font-weight: 500;
}

.generated-code-editor {
  flex: 1;
  min-height: 0;
  width: 100%;
  margin: 0;
  border: 0;
  border-radius: 0;
  background: #F9FAFB;
  resize: none;
  overflow: auto;
}

.generated-code-editor:focus {
  box-shadow: inset 0 0 0 2px #047857;
}

.generated-preview-actions {
  display: flex;
  flex-shrink: 0;
  justify-content: flex-end;
  gap: 12px;
  padding-top: 18px;
}

.generated-preview-actions .secondary-btn {
  margin-left: 0;
  background: #FFFFFF;
  border: 1px solid #047857;
  color: #047857;
}

.generated-preview-actions .secondary-btn:hover:not(:disabled) {
  background: #FFFFFF;
  color: #065F46;
  border-color: #065F46;
}

/* 响应式 */
@media (max-width: 768px) {
  .page-header {
    align-items: stretch;
    flex-direction: column;
  }

  .create-tool-btn {
    align-self: flex-start;
  }

  .tools-controls {
    align-items: stretch;
    flex-direction: column;
  }

  .source-switch {
    align-self: flex-start;
  }

  .tool-type-picker {
    align-items: stretch;
    flex-direction: column;
  }

  .tool-type-picker button { flex-basis: auto; }

  .new-tool-modal.generated-preview-modal {
    width: 95vw !important;
    max-width: 95vw !important;
    height: 92vh;
    max-height: 92vh;
  }

  .generated-script-preview { padding: 20px 18px 16px; }
  .generated-preview-state { align-items: flex-start; flex-direction: column; gap: 6px; }

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
  min-height: 210px;
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
}

.tool-card:hover {
  border-color: #10B981;
  box-shadow: 0 8px 22px rgba(16, 185, 129, 0.12);
  transform: translateY(-2px);
}

.tool-card p {
  width: 100%;
  flex: 1;
  margin-bottom: 12px;
  text-align: center;
  display: -webkit-box;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 3;
  overflow: hidden;
}

.filter-btn {
  background: #FFFFFF;
  border: 1px solid var(--border-color);
  border-radius: 20px;
  color: var(--text-secondary);
}

.filter-btn:hover {
  border-color: #047857;
  color: #047857;
  background: #FFFFFF;
}

.filter-btn.active {
  background: #047857;
  color: #FFFFFF;
  border-color: #047857;
}

.filter-btn:focus-visible,
.source-switch-btn:focus-visible {
  outline: 3px solid rgba(16, 185, 129, 0.22);
  outline-offset: 2px;
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
  padding: 0 !important;
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
    padding: 0 !important;
  }

  .execution-form {
    align-items: stretch;
    flex-direction: column;
  }

  .execute-tool-btn {
    width: 100%;
  }
}
</style>
