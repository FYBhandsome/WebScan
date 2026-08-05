import { ref, watch, onMounted, onUnmounted, nextTick } from 'vue'
import { ws } from '../services/websocket.js'
import { showToast, globalState, scanProgressState, scanStatusState } from '../store.js'
import { API } from '../services/api.js'
import { storageService } from '../services/storageService.js'
import { addLog } from './useLogBus.js'

export function useAgentChat() {
  const inputText = ref('')
  const workspaceBlocks = ref([])
  const isTyping = ref(false)
  const waitingForChoice = ref(false)
  const currentThinking = ref('')
  const isThinking = ref(false)
  const thinkingExpanded = ref(true)
  const scanProgress = scanProgressState
  const pendingInputRequest = ref(null)
  const scanStatus = scanStatusState

  const scanActive = ref(false)
  const pendingModeSelect = ref(null)
  const showModeSelect = ref(false)
  const scriptQueue = ref([])
  const currentScriptIndex = ref(0)
  const scriptLoopActive = ref(false)
  const overallPlan = ref(null)
  const pendingUploadScript = ref(false)
  const pendingGenerateScript = ref(false)
  const pendingScanConfirm = ref(null)
  const showScanConfirm = ref(false)
  const activeSessionId = ref(storageService.getActiveSessionId())
  
  const scriptUploadProgress = ref({ stage: '', progress: 0, message: '' })
  const scriptGenerationProgress = ref({ stage: '', progress: 0, message: '' })
  const scriptHistory = ref([])
  const MAX_SCRIPT_SIZE = 500 * 1024
  let persistTimer = null
  
  const validateScriptFile = (file) => {
    if (!file) return { valid: false, error: '未选择文件' }
    
    const ext = file.name.toLowerCase().split('.').pop()
    if (ext !== 'py') {
      return { valid: false, error: `不支持的文件类型: .${ext}，仅支持 .py 文件` }
    }
    
    if (file.size > MAX_SCRIPT_SIZE) {
      const sizeKB = Math.round(file.size / 1024)
      return { valid: false, error: `文件大小超过限制 (${sizeKB}KB > 500KB)` }
    }
    
    return { valid: true }
  }
  
  const handleScriptFileSelect = async (file) => {
    const validation = validateScriptFile(file)
    if (!validation.valid) {
      addErrorBlock(validation.error, { source: 'frontend' })
      return null
    }
    
    scriptUploadProgress.value = { stage: 'reading', progress: 10, message: '正在读取文件...' }
    
    try {
      const content = await readFileContent(file)
      scriptUploadProgress.value = { stage: 'validating', progress: 20, message: '正在验证脚本...' }
      return { name: file.name.replace('.py', ''), content }
    } catch (error) {
      scriptUploadProgress.value = { stage: 'failed', progress: 100, message: error.message }
      addErrorBlock(`文件读取失败: ${error.message}`, { source: 'frontend' })
      return null
    }
  }
  
  const readFileContent = (file) => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader()
      reader.onload = (e) => resolve(e.target.result)
      reader.onerror = (e) => reject(new Error('文件读取失败'))
      reader.readAsText(file)
    })
  }
  
  const loadScriptHistory = () => {
    try {
      const saved = localStorage.getItem('toskill_script_history')
      if (saved) {
        scriptHistory.value = JSON.parse(saved)
      }
    } catch (e) {
      console.warn('加载脚本历史失败:', e)
    }
  }
  
  const saveScriptHistory = (script) => {
    const history = scriptHistory.value.filter(s => s.tool_name !== script.tool_name)
    history.unshift({
      ...script,
      timestamp: new Date().toISOString()
    })
    scriptHistory.value = history.slice(0, 50)
    localStorage.setItem('toskill_script_history', JSON.stringify(scriptHistory.value))
  }

  const restoreConsoleState = (sessionId) => {
    if (!sessionId) return
    const saved = storageService.getConsoleState(sessionId)
    if (!saved) return

    workspaceBlocks.value = Array.isArray(saved.workspaceBlocks)
      ? saved.workspaceBlocks.filter(block => {
          const emptyRun = block.type === 'agent_run' && !block.target && !block.total && !block.completed
          const transientStatus = block.type === 'agent_text' && /^会话状态: (空闲|扫描中|已完成)$/.test(block.content || '')
          return !emptyRun && !transientStatus
        })
      : []
    scanActive.value = Boolean(saved.scanActive)
    waitingForChoice.value = Boolean(saved.waitingForChoice)
    pendingScanConfirm.value = saved.pendingScanConfirm || null
    showScanConfirm.value = Boolean(saved.showScanConfirm && saved.pendingScanConfirm)
    if (saved.currentTarget) globalState.currentTarget = saved.currentTarget
    if (saved.scanProgress) scanProgress.value = saved.scanProgress
    if (saved.scanStatus) scanStatus.value = saved.scanStatus
  }

  const persistConsoleState = () => {
    const sessionId = activeSessionId.value || ws.getSessionId()
    if (!sessionId) return
    storageService.saveConsoleState(sessionId, {
      workspaceBlocks: workspaceBlocks.value,
      scanActive: scanActive.value,
      waitingForChoice: waitingForChoice.value,
      pendingScanConfirm: pendingScanConfirm.value,
      showScanConfirm: showScanConfirm.value,
      currentTarget: globalState.currentTarget,
      scanProgress: scanProgress.value,
      scanStatus: scanStatus.value
    })
  }

  const scheduleConsolePersist = () => {
    if (persistTimer) clearTimeout(persistTimer)
    persistTimer = setTimeout(persistConsoleState, 200)
  }

  restoreConsoleState(activeSessionId.value)

  // === UI 辅助方法 ===
  const addBlock = (type, data = {}) => {
    const createdAt = new Date().toISOString()
    workspaceBlocks.value.push({
      id: Date.now() + Math.random(),
      timestamp: new Date(createdAt).toLocaleTimeString('en-US', { hour12: false }),
      createdAt,
      type,
      ...data
    })
  }

  const syncChatHistory = (history = []) => {
    const messages = history.filter(item => ['user', 'assistant'].includes(item?.role) && item?.content)
    if (!messages.length) return

    const signature = (role, content) => `${role}\u0000${String(content).trim()}`
    const existingCounts = new Map()
    for (const block of workspaceBlocks.value) {
      const role = block.type === 'user_command' ? 'user' : block.type === 'agent_text' ? 'assistant' : null
      if (!role || !block.content) continue
      const key = signature(role, block.content)
      existingCounts.set(key, (existingCounts.get(key) || 0) + 1)
    }

    const seenCounts = new Map()
    const missingBlocks = []
    messages.forEach((message, index) => {
      const key = signature(message.role, message.content)
      const occurrence = (seenCounts.get(key) || 0) + 1
      seenCounts.set(key, occurrence)
      if (occurrence <= (existingCounts.get(key) || 0)) return

      const createdAt = message.timestamp || new Date().toISOString()
      missingBlocks.push({
        id: `history:${createdAt}:${index}`,
        timestamp: new Date(createdAt).toLocaleTimeString('en-US', { hour12: false }),
        createdAt,
        type: message.role === 'user' ? 'user_command' : 'agent_text',
        content: message.content,
        restored: true
      })
    })

    if (!missingBlocks.length) return
    const hasLocalChat = workspaceBlocks.value.some(block =>
      block.type === 'user_command' || block.type === 'agent_text'
    )
    workspaceBlocks.value = hasLocalChat
      ? [...workspaceBlocks.value, ...missingBlocks]
      : [...missingBlocks, ...workspaceBlocks.value]
  }

  const findInteraction = (interactionId) => {
    if (!interactionId) return null
    for (const run of workspaceBlocks.value.filter(block => block.type === 'agent_run')) {
      for (const step of run.steps || []) {
        if (step.interaction?.interactionId === interactionId) return step.interaction
      }
    }
    return null
  }

  const hasOpenInteraction = (interactionId) => Boolean(
    findInteraction(interactionId) && !findInteraction(interactionId).resolved
  )

  const lastRunSequences = new Map()

  const getRunId = (payload = {}) => {
    if (payload.run_id) return payload.run_id
    const activeRun = [...workspaceBlocks.value].reverse().find(
      block => block.type === 'agent_run' && !['completed', 'failed', 'cancelled'].includes(block.status)
    )
    return activeRun?.runId || ws.getSessionId() || 'active-run'
  }

  const acceptRunEvent = (payload = {}) => {
    const sequence = Number(payload.sequence)
    if (!Number.isFinite(sequence)) return true
    const runId = getRunId(payload)
    const lastSequence = lastRunSequences.get(runId) || 0
    if (sequence <= lastSequence) return false
    lastRunSequences.set(runId, sequence)
    return true
  }

  const ensureRunBlock = (payload = {}) => {
    const runId = getRunId(payload)
    let run = workspaceBlocks.value.find(block => block.type === 'agent_run' && block.runId === runId)
    if (!run && payload.run_id) {
      run = [...workspaceBlocks.value].reverse().find(
        block => block.type === 'agent_run' && block.provisional && !['completed', 'failed', 'cancelled'].includes(block.status)
      )
      if (run) {
        run.runId = runId
        run.id = `run:${runId}`
        run.provisional = false
      }
    }
    if (!run) {
      run = {
        id: `run:${runId}`,
        timestamp: new Date().toLocaleTimeString('en-US', { hour12: false }),
        type: 'agent_run',
        runId,
        provisional: !payload.run_id,
        title: '智能体扫描',
        target: payload.target || globalState.currentTarget || '',
        mode: payload.mode || '',
        status: 'running',
        completed: 0,
        total: 0,
        steps: [],
        summary: ''
      }
      workspaceBlocks.value.push(run)
    }
    if (payload.target) run.target = payload.target
    if (payload.mode) run.mode = payload.mode
    return run
  }

  const updateRun = (payload = {}, patch = {}) => {
    const run = ensureRunBlock(payload)
    Object.assign(run, patch)
    return run
  }

  const upsertRunStep = (payload = {}, patch = {}) => {
    const run = ensureRunBlock(payload)
    const stepId = payload.step_id || patch.stepId || payload.tool || payload.node || payload.event || 'workflow'
    let step = run.steps.find(item => item.stepId === stepId)
    if (!step) {
      step = {
        stepId,
        title: patch.title || payload.tool || payload.node || stepId,
        status: 'pending',
        message: '',
        analysis: '',
        logs: [],
        rawResult: null
      }
      run.steps.push(step)
    }
    Object.assign(step, patch)
    return step
  }

  const attachRunInteraction = (payload = {}, interaction = {}) => {
    const interactionId = interaction.interactionId || payload.interaction_id ||
      `local:${interaction.actionSource || interaction.type || 'action'}:${payload.step_id || payload.next_task || payload.tool || Date.now()}`
    const existing = findInteraction(interactionId)
    if (existing) {
      Object.assign(existing, interaction)
      return existing
    }

    const stepId = interaction.stepId || payload.step_id ||
      (payload.next_task ? `decision:${payload.next_task}` : `interaction:${interactionId}`)
    const step = upsertRunStep({ ...payload, step_id: stepId }, {
      title: interaction.stepTitle || interaction.title || payload.next_task || payload.tool || '等待用户操作',
      status: 'waiting',
      message: interaction.description || ''
    })
    step.interaction = {
      type: interaction.type || 'actions',
      ...interaction,
      interactionId,
      resolved: false,
      selectedChoice: ''
    }
    updateRun(payload, { status: 'waiting' })
    scanStatus.value = 'waiting'
    return step.interaction
  }

  const resolveRunInteraction = (interaction, choiceLabel = '') => {
    if (!interaction) return
    interaction.resolved = true
    interaction.selectedChoice = choiceLabel
    for (const run of workspaceBlocks.value.filter(block => block.type === 'agent_run')) {
      const step = (run.steps || []).find(item => item.interaction === interaction)
      if (step) {
        step.status = choiceLabel.includes('停止') || choiceLabel.includes('终止') ? 'cancelled' : 'completed'
        break
      }
    }
    scanStatus.value = choiceLabel.includes('停止') || choiceLabel.includes('取消') ? 'idle' : 'scanning'
  }

  const appendRunLog = (payload = {}) => {
    const step = upsertRunStep(payload, {
      title: payload.tool || payload.node || payload.step_id || '执行过程',
      status: payload.status === 'failed' ? 'failed' : 'running'
    })
    const entry = {
      id: payload.id || `${payload.sequence || Date.now()}:${payload.message || ''}`,
      level: String(payload.level || 'info').toLowerCase(),
      message: payload.message || '',
      timestamp: payload.timestamp || new Date().toISOString()
    }
    if (!step.logs.some(item => item.id === entry.id)) {
      step.logs.push(entry)
      if (step.logs.length > 100) step.logs.splice(0, step.logs.length - 100)
    }
  }

  const addStreamText = (content) => {
    const lastBlock = workspaceBlocks.value[workspaceBlocks.value.length - 1]
    if (lastBlock && lastBlock.streaming && lastBlock.type === 'agent_text') {
      lastBlock.content += content
    } else {
      addBlock('agent_text', { content, streaming: true })
    }
  }

  const stopStreaming = () => {
    const lastBlock = workspaceBlocks.value[workspaceBlocks.value.length - 1]
    if (lastBlock && lastBlock.streaming) {
      lastBlock.streaming = false
    }
  }

  const addInfoBlock = (message) => {
    const activeRun = [...workspaceBlocks.value].reverse().find(
      block => block.type === 'agent_run' && !['completed', 'failed', 'cancelled'].includes(block.status)
    )
    if (activeRun) {
      appendRunLog({ run_id: activeRun.runId, step_id: 'workflow', node: '工作流', message, level: 'info' })
    } else {
      addBlock('agent_text', { content: message, tone: 'info' })
    }
  }

  const addErrorBlock = (message, errorData = {}) => {
    const { code, source, category, suggestion, details } = errorData
    let fullMessage = message
    
    if (source) {
      const sourceLabels = {
        'frontend': '前端',
        'backend': '后端服务',
        'network': '网络',
        'tool': '工具执行',
        'ai_model': 'AI模型',
        'database': '数据库',
        'websocket': 'WebSocket连接',
        'unknown': '未知'
      }
      fullMessage = `[${sourceLabels[source] || source}] ${message}`
    }
    
    if (code) {
      fullMessage = `(${code}) ${fullMessage}`
    }
    
    if (suggestion) {
      fullMessage = `${fullMessage}\n💡 建议: ${suggestion}`
    }

    const activeRun = [...workspaceBlocks.value].reverse().find(
      block => block.type === 'agent_run' && !['completed', 'failed', 'cancelled'].includes(block.status)
    )
    if (activeRun) {
      appendRunLog({
        run_id: activeRun.runId,
        step_id: 'workflow',
        node: '工作流',
        message: fullMessage,
        level: 'error'
      })
      return
    }
    
    addBlock('agent_text', {
      content: fullMessage,
      tone: 'error',
      code,
      source,
      category,
      suggestion,
      details
    })
  }

  const streamingTypes = ['script_analyzing', 'script_generating', 'ai_thinking', 'ai_thinking_start']
  const checkStopStreaming = (data) => {
    if (!streamingTypes.includes(data.type)) stopStreaming()
  }

  // === 核心业务逻辑 (纯 WebSocket 驱动) ===
  const sendMessage = async (textOverride) => {
    const text = textOverride || inputText.value.trim()
    if (!text) return

    inputText.value = ''
    addBlock('user_command', { content: text })

    if (waitingForChoice.value) {
      if (text.toLowerCase() === 'stop' || text.toLowerCase() === '停止') {
        ws.sendConfirm('2')
        waitingForChoice.value = false
      } else if (ws.isConnected()) {
        ws.sendChat(text)
      }
      return
    }

    isTyping.value = true

    if (ws.isConnected()) {
      try {
        const intentResult = await API.parseIntent(text)
        const intentData = intentResult?.data
        
        if (intentData?.should_start_scan && intentData?.target) {
          const target = intentData.target
          const mode = intentData.mode || 'full'
          const confidence = intentData.confidence || 0.8
          const explanation = intentData.explanation || ''
          
          pendingScanConfirm.value = { target, mode, confidence, explanation }
          showScanConfirm.value = true
          
          attachRunInteraction({ target, step_id: 'scan-setup' }, {
            type: 'actions',
            actionSource: 'scan_confirm',
            stepTitle: '确认扫描方案',
            title: 'AI 解析结果',
            description: explanation || `已识别目标 ${target}，请选择扫描模式。`,
            params: {
              目标: target,
              推荐模式: mode === 'info' ? '信息收集' : mode === 'vuln' ? '漏洞扫描' : '完整扫描',
              置信度: `${Math.round(confidence * 100)}%`
            },
            options: [
              { key: 'info', label: '信息收集' },
              { key: 'vuln', label: '漏洞扫描' },
              { key: 'full', label: '完整扫描', primary: true },
              { key: 'cancel', label: '取消', danger: true }
            ]
          })
          
          isTyping.value = false
          return
        }
        
        if (intentData?.action === 'help') {
          addBlock('agent_text', { 
            content: `**帮助信息**\n\n您可以输入以下类型的指令：\n\n1. **扫描目标**：输入URL或域名，如 \`http://example.com\` 或 \`example.com\`\n2. **指定模式**：\n   - \`信息收集\` 或 \`info\` - 端口扫描、子域名发现等\n   - \`漏洞扫描\` 或 \`vuln\` - XSS、SQL注入检测等\n   - \`完整扫描\` 或 \`full\` - 全面安全检测\n3. **组合指令**：\`扫描 example.com 进行漏洞检测\`\n4. **其他操作**：\`停止\`、\`状态\`、\`帮助\`\n\n**示例**：\n- \`扫描 http://testphp.vulnweb.com\`\n- \`对 example.com 进行完整扫描\`\n- \`检测 target.com 的漏洞\`` 
          })
          isTyping.value = false
          return
        }
        
        if (intentData?.action === 'status') {
          if (scanActive.value) {
            addBlock('agent_text', { content: `**当前状态**\n\n扫描状态: 进行中\n目标: ${globalState.currentTarget || '未知'}\n已完成: ${scanProgress.value.current}/${scanProgress.value.total}\n当前工具: ${scanProgress.value.activeTool || '无'}` })
          } else {
            addBlock('agent_text', { content: `**当前状态**\n\n扫描状态: 空闲\n等待新的扫描指令...` })
          }
          isTyping.value = false
          return
        }
        
        if (intentData?.action === 'stop') {
          if (scanActive.value) {
            ws.sendConfirm('2')
            scanActive.value = false
            addBlock('agent_text', { content: '扫描已停止' })
          } else {
            addBlock('agent_text', { content: '当前没有正在进行的扫描' })
          }
          isTyping.value = false
          return
        }
        
        ws.sendChat(text)
        
      } catch (error) {
        console.error('Intent parsing failed:', error)
        addBlock('agent_text', { 
          content: `**解析失败**\n\n无法理解您的指令，请尝试以下格式：\n\n- \`扫描 http://example.com\`\n- \`对 target.com 进行漏洞扫描\`\n- \`帮助\` 查看更多指令` 
        })
        isTyping.value = false
      }
    } else {
      isTyping.value = false
      addBlock('agent_text', { content: '实时连接未就绪，无法发送指令。请检查网络或后端状态。' })
    }
  }
  
  const handleScanConfirm = async (block, selectedMode) => {
    console.log('[handleScanConfirm] 开始执行', { block, selectedMode })
    
    resolveRunInteraction(block, selectedMode === 'info' ? '信息收集' : selectedMode === 'vuln' ? '漏洞扫描' : '完整扫描')
    showScanConfirm.value = false
    
    const { target, mode } = pendingScanConfirm.value || {}
    if (!target) {
      showToast('扫描目标丢失', 'error')
      isTyping.value = false
      return
    }
    
    const finalMode = selectedMode || mode || 'full'
    
    console.log('[handleScanConfirm] 确认扫描:', { target, finalMode, selectedMode, mode })
    
    if (!ws.isConnected()) {
      console.log('[handleScanConfirm] WebSocket 未连接，尝试重新连接...')
      addInfoBlock('正在重新建立连接...')
      
      try {
        await ws.connect()
        console.log('[handleScanConfirm] WebSocket 重新连接成功')
      } catch (connError) {
        console.error('[handleScanConfirm] WebSocket 连接失败:', connError)
        addErrorBlock('无法建立连接，请刷新页面重试', { source: 'websocket' })
        isTyping.value = false
        return
      }
    }
    
    scanActive.value = true
    isTyping.value = true
    currentThinking.value = ''
    isThinking.value = true
    
    const payload = { target, scan_mode: finalMode }
    console.log('[handleScanConfirm] 准备发送 start_scan:', payload)
    
    const sent = ws.startScan(target, finalMode)
    console.log('[handleScanConfirm] startScan 发送结果:', sent)
    
    if (!sent) {
      console.error('[handleScanConfirm] startScan 发送失败')
      addErrorBlock('发送扫描请求失败，请重试', { source: 'websocket' })
      isTyping.value = false
      scanActive.value = false
      return
    }
    
    upsertRunStep({ target, step_id: 'scan-setup' }, {
      title: '扫描准备',
      status: 'completed',
      message: `已选择${finalMode === 'info' ? '信息收集' : finalMode === 'vuln' ? '漏洞扫描' : '完整扫描'}模式，正在启动扫描。`
    })
    pendingScanConfirm.value = null
  }
  
  const handleScanCancel = (block) => {
    resolveRunInteraction(block, '取消')
    showScanConfirm.value = false
    pendingScanConfirm.value = null
    updateRun({}, { status: 'cancelled', summary: '已取消扫描' })
    isTyping.value = false
  }

  const handleQuickAction = (mode) => {
    const target = inputText.value.trim()
    if (!target) {
      showToast('请先在输入框中填入扫描目标URL', 'warning')
      return
    }
    addBlock('user_command', { content: `[执行参数]: mode=${mode}, target=${target}` })
    isTyping.value = true
    
    if (ws.isConnected()) {
      ws.startScan(target, mode)
    } else {
      isTyping.value = false
      addBlock('agent_text', { content: `实时连接未就绪，无法执行任务。` })
    }
    inputText.value = ''
  }

  const handleModeSelect = (block, mode) => {
    block.resolved = true
    showModeSelect.value = false
    const target = pendingModeSelect.value?.target || ''
    pendingModeSelect.value = null
    isTyping.value = true
    scanActive.value = true
    currentThinking.value = ''
    isThinking.value = true
    const planLines = [
      `## 思考过程`,
      ``,
      `正在为目标 **${target}** 制定扫描策略...`,
      ``,
      `**意图识别**: 扫描 → 模式: ${mode === 'info' ? '信息收集' : mode === 'vuln' ? '漏洞扫描' : '完整扫描'}`,
      ``,
      `## 总体规划`,
      ``,
      `扫描模式: **${mode === 'info' ? '信息收集' : mode === 'vuln' ? '漏洞扫描' : '完整扫描'}**`,
      ``,
      `### 可用脚本清单`,
    ]
    const infoScripts = ['port_scan', 'subdomain_scan', 'dir_brute', 'waf_detect_scan', 'cdn_detect_scan', 'cms_detect_scan', 'infoleak_scan', 'ip_locate_scan', 'webside_query_scan', 'web_weight_scan', 'baseinfo_scan']
    const vulnScripts = ['sqli_scan', 'xss_scan', 'csrf_scan', 'fileupload_scan', 'cmdi_scan', 'ssrf_scan', 'lfi_scan', 'weakpass_scan']
    let scripts = []
    if (mode === 'info') scripts = infoScripts
    else if (mode === 'vuln') scripts = [...vulnScripts]
    else scripts = [...infoScripts, ...vulnScripts]
    scripts.forEach((s, i) => { planLines.push(`${i + 1}. \`${s}\``) })
    planLines.push('', `> 如需执行自定义脚本，可点击下方【上传脚本】或【生成脚本】`)
    isThinking.value = false
    addBlock('agent_text', { thought: `目标分析: ${target}\n模式: ${mode}`, content: planLines.join('\n') })
    scriptQueue.value = scripts.map(s => ({ tool_name: s, status: 'pending', target }))
    currentScriptIndex.value = 0
    scriptLoopActive.value = true
    setTimeout(() => triggerScriptConfirm(), 500)
  }

  const triggerScriptConfirm = () => {
    if (!scriptLoopActive.value) return
    if (currentScriptIndex.value >= scriptQueue.value.length) {
      scriptLoopActive.value = false
      scanActive.value = false
      isTyping.value = false
      addBlock('agent_text', { content: '## 所有脚本执行完毕\n\n扫描流程已完成。如需查看详细报告，请前往**报告页面**。' })
      return
    }
    const script = scriptQueue.value[currentScriptIndex.value]
    script.status = 'confirming'
    isTyping.value = false
    attachRunInteraction({
      target: script.target,
      tool: script.tool_name,
      step_id: `script:${currentScriptIndex.value}:${script.tool_name}`
    }, {
      type: 'actions',
      actionSource: 'script_confirm',
      interactionId: `script:${currentScriptIndex.value}:${script.tool_name}`,
      stepTitle: script.tool_name,
      title: `确认执行：${script.tool_name}`,
      description: `目标: ${script.target}`,
      params: {
        'Script': script.tool_name,
        'Target': script.target,
        'Progress': `${currentScriptIndex.value + 1}/${scriptQueue.value.length}`
      },
      guideText: '如需执行自定义脚本，可点击下方【上传脚本】或【生成脚本】',
      options: [
        { key: 'execute', label: '执行', style: 'btn-primary' },
        { key: 'skip', label: '跳过', style: 'btn-ghost' },
        { key: 'stop_loop', label: '停止循环', style: 'btn-danger' },
        { key: 'upload_script', label: '上传脚本', style: 'btn-outline' },
        { key: 'generate_script', label: '生成脚本', style: 'btn-outline' }
      ],
      resolved: false
    })
  }

  const showUploadScriptForm = (block) => {
    attachRunInteraction({ step_id: `upload-script:${Date.now()}` }, {
      type: 'input',
      actionSource: 'input_request',
      stepTitle: '上传自定义脚本',
      title: '上传自定义脚本',
      description: '请粘贴你的 Python 脚本代码。脚本必须包含 `run(target: str)` 函数并返回 `Dict` 类型结果。系统将自动进行安全审查。',
      fields: [{
        field: 'script_name',
        label: '脚本名称',
        description: '为脚本起一个名字（可选，不填则自动生成）',
        placeholder: '例如: custom_scan',
        required: false,
        validation: '',
        options: [],
        value: ''
      }, {
        field: 'script_content',
        label: '脚本内容',
        description: '脚本必须包含 def run(target): 函数',
        placeholder: 'def run(target):\n    # your code here\n    return {"success": True}',
        required: true,
        validation: 'python_code',
        options: [],
        value: ''
      }],
      resolved: false,
      context: 'upload_script',
      sourceInteraction: block
    })
  }

  const showGenerateScriptForm = (block) => {
    attachRunInteraction({ step_id: `generate-script:${Date.now()}` }, {
      type: 'input',
      actionSource: 'input_request',
      stepTitle: 'AI 生成扫描脚本',
      title: 'AI 生成扫描脚本',
      description: '请描述你需要的脚本功能，AI 将自动生成对应的 Python 扫描脚本。',
      fields: [{
        field: 'script_description',
        label: '脚本功能描述',
        description: '详细描述脚本需要检测的内容，例如"检测目标网站是否存在敏感文件泄露"',
        placeholder: '检测目标网站是否存在敏感文件泄露',
        required: true,
        validation: 'text',
        options: [],
        value: ''
      }],
      resolved: false,
      context: 'generate_script',
      sourceInteraction: block
    })
  }

  const handleStop = () => {
    if (scriptLoopActive.value) scriptLoopActive.value = false
    scanActive.value = false
    isTyping.value = false
    isThinking.value = false
    showModeSelect.value = false
    ws.send('stop_scan', {})
    updateRun({}, { status: 'cancelled', summary: '已发送停止请求' })
  }

  // === 交互卡片事件分发 ===
  const handleBlockAction = (block, choiceKey, choiceLabel) => {
    resolveRunInteraction(block, choiceLabel)
    isTyping.value = true
    updateRun({}, { status: 'running' })

    if (block.actionSource === 'scan_confirm') {
      if (choiceKey === 'cancel') handleScanCancel(block)
      else handleScanConfirm(block, choiceKey)
      return
    }

    if (!ws.isConnected()) {
        isTyping.value = false
        return showToast('WebSocket 已断开', 'error')
    }

    switch (block.actionSource) {
      case 'interaction_required':
        waitingForChoice.value = false
        ws.sendConfirm(choiceKey, block.interactionId)
        break
      case 'high_risk':
        waitingForChoice.value = false
        ws.send('high_risk_confirm', { choice: choiceKey, interaction_id: block.interactionId })
        break
      case 'tool_confirm':
        waitingForChoice.value = false
        ws.sendToolConfirm(choiceKey === 'approve', block.interactionId)
        break
      case 'alternative_options':
        ws.sendAlternativeSelected(choiceKey, choiceLabel)
        break
      case 'script_confirm':
        if (choiceKey === 'execute') {
          const script = scriptQueue.value[currentScriptIndex.value]
          script.status = 'running'
          isTyping.value = true
          upsertRunStep({ tool: script.tool_name, target: script.target }, {
            title: script.tool_name,
            status: 'running',
            message: `正在执行脚本：${script.tool_name}`
          })
          ws.send('execute_tool', { tool_name: script.tool_name, target: script.target })
        } else if (choiceKey === 'skip') {
          const skippedScript = scriptQueue.value[currentScriptIndex.value]
          currentScriptIndex.value++
          upsertRunStep({ tool: skippedScript?.tool_name, target: skippedScript?.target }, {
            title: skippedScript?.tool_name || '脚本',
            status: 'skipped',
            message: '用户已跳过'
          })
          triggerScriptConfirm()
        } else if (choiceKey === 'stop_loop') {
          scriptLoopActive.value = false
          scanActive.value = false
          isTyping.value = false
          updateRun({}, { status: 'cancelled', summary: '脚本循环已终止' })
        } else if (choiceKey === 'upload_script') {
          pendingUploadScript.value = true
          showUploadScriptForm(block)
          updateRun({}, { status: 'waiting' })
        } else if (choiceKey === 'generate_script') {
          pendingGenerateScript.value = true
          showGenerateScriptForm(block)
          updateRun({}, { status: 'waiting' })
        }
        break
    }
  }

  const submitBlockInput = (block, val) => {
    if (!val) return showToast('内容不能为空', 'warning')
    resolveRunInteraction(block, '已提交')
    isTyping.value = true
    ws.send('input_response', { field: block.payload.field, value: val })
  }

  const handleInputResponse = (block, value) => {
    if (Array.isArray(value)) {
      const fields = value
      for (const field of fields) {
        if (field.required && !field.value) {
          return showToast(`${field.label} 为必填项`, 'warning')
        }
      }
      resolveRunInteraction(block, '已提交')
      pendingInputRequest.value = null

      if (block.context === 'upload_script') {
        pendingUploadScript.value = false
        const scriptName = fields.find(f => f.field === 'script_name')?.value || null
        const scriptContent = fields.find(f => f.field === 'script_content')?.value || ''
        const name = scriptName || `custom_${Date.now().toString(36)}`
        isTyping.value = true
        ws.send('script_content', { script_content: scriptContent, script_name: name })
        return
      } else if (block.context === 'generate_script') {
        pendingGenerateScript.value = false
        const description = fields.find(f => f.field === 'script_description')?.value || ''
        isTyping.value = true
        ws.send('script_description', { description: description })
        return
      }

      isTyping.value = true
      for (const field of fields) {
        if (field.value) {
          ws.send('input_response', { field: field.field, value: field.value })
        }
      }
      return
    }
    if (!value && block.required) return showToast('此字段为必填项', 'warning')
    resolveRunInteraction(block, '已提交')
    pendingInputRequest.value = null
    isTyping.value = true
    ws.send('input_response', { field: block.field, value })
  }

  // === WebSocket 消息路由 ===
  const handleWSMessage = (data) => {
    checkStopStreaming(data)

    switch (data.type) {
      case 'connected':
        if (data.payload?.session_id) {
          const connectedSessionId = data.payload.session_id
          if (activeSessionId.value !== connectedSessionId) {
            activeSessionId.value = connectedSessionId
            restoreConsoleState(connectedSessionId)
          }
          storageService.setActiveSessionId(connectedSessionId)
          ws.sendGetHistory()
          ws.sendGetStatus()
        }
        addLog({
          level: 'INFO',
          message: `已连接到 AI Agent 引擎 (${data.payload?.session_id || 'Active'})`,
          timestamp: new Date().toISOString()
        })
        break

      case 'ai_thinking_start':
        isThinking.value = true
        currentThinking.value = ''
        if (!isTyping.value) isTyping.value = true
        break

      case 'ai_thinking':
        currentThinking.value += data.payload?.token || ''
        break

      case 'ai_chat':
      case 'ai_message':
        isTyping.value = false
        isThinking.value = false
        const msgContent = data.payload?.content?.trim()
        const msgThought = currentThinking.value || data.payload?.thought?.trim()
        if (msgContent || msgThought) {
          addBlock('agent_text', { thought: msgThought || '', content: msgContent || '' })
        }
        currentThinking.value = ''
        break

      case 'interaction_required': {
        isTyping.value = false
        waitingForChoice.value = true
        const interactionId = data.payload?.interaction_id || data.interaction_id
        if (hasOpenInteraction(interactionId)) break
        updateRun(data.payload || {}, { status: 'waiting' })
        attachRunInteraction(data.payload || {}, {
          type: 'actions',
          actionSource: 'interaction_required',
          interactionId,
          stepId: `decision:${data.payload?.next_task || interactionId}`,
          stepTitle: data.payload?.next_task ? `下一步：${data.payload.next_task}` : '等待用户操作',
          title: '需要进一步指令',
          description: `目标: ${data.payload.target} | 规划节点: ${data.payload.next_task}`,
          options: (data.payload.options || []).map(opt => ({
            key: opt.key,
            label: opt.label,
            primary: String(opt.key) === '1',
            danger: String(opt.key) === '2'
          })),
          resolved: false
        })
        break
      }

      case 'high_risk_vulnerability_detected': {
        isTyping.value = false
        waitingForChoice.value = true
        const highRiskPayload = data.payload || data
        const interactionId = highRiskPayload.interaction_id || data.interaction_id
        if (hasOpenInteraction(interactionId)) break
        updateRun(highRiskPayload, { status: 'waiting' })
        attachRunInteraction(highRiskPayload, {
          type: 'actions',
          actionSource: 'high_risk',
          interactionId,
          stepId: `decision:high-risk:${interactionId}`,
          stepTitle: '高危漏洞处置',
          title: '高危漏洞确认 (CRITICAL)',
          description: highRiskPayload.message || '系统检测到高危漏洞，请指示下一步动作。',
          params: { 'Vuln count': highRiskPayload.vulnerabilities?.length || 1, 'Severity': highRiskPayload.highest_risk_level?.toUpperCase() || 'HIGH' },
          options: [
            { key: 'continue', label: '继续扫描', style: 'btn-primary' },
            { key: 'poc_verify', label: 'POC验证', style: 'btn-secondary' },
            { key: 'stop', label: '中止并阻断', style: 'btn-danger' }
          ],
          resolved: false
        })
        break
      }

      case 'scan_started':
        if (!acceptRunEvent(data.payload || {})) break
        scanStatus.value = 'scanning'
        isThinking.value = false
        currentThinking.value = ''
        scanProgress.value = { current: 0, total: data.payload?.total_tasks || 0, activeTool: '' }
        updateRun(data.payload || {}, {
          title: '智能体扫描',
          target: data.payload?.target || '',
          status: 'running'
        })
        break

      case 'scan_flow_started':
        if (!acceptRunEvent(data.payload || {})) break
        scanProgress.value = { current: 0, total: data.payload?.total_tasks || 0, activeTool: '' }
        updateRun(data.payload || {}, {
          mode: data.payload?.mode || '',
          total: data.payload?.total_tasks || 0,
          status: 'running'
        })
        break

      case 'scan_completed':
        if (!acceptRunEvent(data.payload || {})) break
        scanStatus.value = 'completed'
        scanProgress.value.activeTool = ''
        scanActive.value = false
        isTyping.value = false
        isThinking.value = false
        const tasks = data.payload?.completed_tasks || []
        const vulnCount = data.payload?.vulnerabilities_count ?? 0
        let summary = `扫描完成\n目标: ${data.payload?.target || '-'}\n已完成工具: ${tasks.length} 个\n发现漏洞: ${vulnCount} 个`
        if (data.payload?.report) summary += `\n报告: ${data.payload.report}`
        const completedRun = updateRun(data.payload || {}, { status: 'completed', completed: tasks.length, summary })
        const workflowStep = completedRun.steps.find(step => step.stepId === 'workflow')
        if (workflowStep?.status === 'running') workflowStep.status = 'completed'
        break

      case 'scan_cancelled':
        if (!acceptRunEvent(data.payload || {})) break
        scanStatus.value = 'idle'
        scanProgress.value.activeTool = ''
        scanActive.value = false
        isTyping.value = false
        updateRun(data.payload || {}, { status: 'cancelled', summary: '扫描已取消' })
        break

      case 'scan_terminated':
        if (!acceptRunEvent(data.payload || {})) break
        scanStatus.value = 'error'
        scanProgress.value.activeTool = ''
        scanActive.value = false
        isTyping.value = false
        updateRun(data.payload || {}, { status: 'failed', summary: `扫描终止：${data.payload?.reason || '未知原因'}` })
        break

      case 'workflow_progress':
        if (!acceptRunEvent(data.payload || {})) break
        scanProgress.value.current = data.payload?.completed ?? scanProgress.value.current
        scanProgress.value.total = data.payload?.total ?? scanProgress.value.total
        updateRun(data.payload || {}, {
          completed: data.payload?.completed ?? scanProgress.value.current,
          total: data.payload?.total ?? scanProgress.value.total,
          status: data.payload?.status === 'completed' ? 'completed' : 'running'
        })
        break

      case 'task_started':
        if (!acceptRunEvent(data.payload || {})) break
        scanProgress.value.activeTool = data.payload?.tool || ''
        isTyping.value = true
        isThinking.value = false
        currentThinking.value = ''
        updateRun(data.payload || {}, { status: 'running' })
        upsertRunStep(data.payload || {}, {
          title: data.payload?.tool || '扫描工具',
          status: 'running',
          message: `正在扫描 ${data.payload?.target || ''}`,
          startedAt: data.payload?.timestamp || new Date().toISOString()
        })
        break

      case 'task_completed':
        if (!acceptRunEvent(data.payload || {})) break
        isTyping.value = false
        const analysis = data.payload?.analysis || ''
        const vuln = data.payload?.vulnerable ? '发现漏洞' : '未发现漏洞'
        const auth = data.payload?.auth_obtained ? ' | 已获取认证' : ''
        upsertRunStep(data.payload || {}, {
          title: data.payload?.tool || '扫描工具',
          status: 'completed',
          message: `${vuln}${auth}`,
          analysis,
          rawResult: data.payload?.raw_result || {},
          completedAt: data.payload?.timestamp || new Date().toISOString()
        })
        if (scriptLoopActive.value && currentScriptIndex.value < scriptQueue.value.length) {
          const script = scriptQueue.value[currentScriptIndex.value]
          script.status = 'completed'
          currentScriptIndex.value++
          setTimeout(() => triggerScriptConfirm(), 800)
        }
        break

      case 'task_analysis_updated':
        if (!acceptRunEvent(data.payload || {})) break
        upsertRunStep(data.payload || {}, { analysis: data.payload?.analysis || '' })
        break

      case 'task_error':
        if (!acceptRunEvent(data.payload || {})) break
        isTyping.value = false
        const taskError = data.payload || {}
        upsertRunStep(taskError, {
          title: taskError.tool || '扫描工具',
          status: 'failed',
          message: taskError.error || '工具执行失败',
          analysis: taskError.ai_analysis || taskError.suggestion || ''
        })
        break

      case 'task_skipped':
        if (!acceptRunEvent(data.payload || {})) break
        upsertRunStep(data.payload || {}, {
          title: data.payload?.tool || '扫描工具',
          status: 'skipped',
          message: data.payload?.reason || '已跳过'
        })
        break

      case 'ai_decision':
        if (!acceptRunEvent(data.payload || {})) break
        upsertRunStep(data.payload || {}, {
          title: '智能体决策',
          status: 'completed',
          message: `下一步：${data.payload?.next_task || '-'}`,
          analysis: data.payload?.react_thought || ''
        })
        break

      case 'ai_decision_complete':
        addInfoBlock('所有任务决策完成')
        break

      case 'intent_recognized':
        addInfoBlock(`意图识别: ${data.payload?.intent_type || '-'}${data.payload?.tool_name ? ' → ' + data.payload.tool_name : ''} | 置信度: ${data.payload?.confidence ?? '-'}`)
        break

      case 'intent_validation_error':
        addErrorBlock(`校验错误: ${data.payload?.error || '-'}`)
        break

      case 'input_request':
        isTyping.value = false
        const field = data.payload
        const inputBlock = attachRunInteraction(field, {
          type: 'input',
          actionSource: 'input_request',
          interactionId: field.interaction_id || `input:${field.field}`,
          stepTitle: '参数输入',
          title: '参数输入',
          description: field.description || '请补充以下信息',
          fields: [{
            field: field.field,
            label: field.label,
            description: field.description || '',
            placeholder: field.placeholder || '',
            required: field.required !== false,
            validation: field.validation || '',
            options: field.options || [],
            value: ''
          }],
          resolved: false
        })
        pendingInputRequest.value = inputBlock
        break

      case 'multi_field_input_request':
        isTyping.value = false
        const multiFields = (data.payload?.fields || []).map(f => ({
          field: f.field,
          label: f.label,
          description: f.description || '',
          placeholder: f.placeholder || '',
          required: f.required !== false,
          validation: f.validation || '',
          options: f.options || [],
          value: ''
        }))
        const multiBlock = attachRunInteraction(data.payload || {}, {
          type: 'input',
          actionSource: 'input_request',
          interactionId: data.payload?.interaction_id || `input:multi:${Date.now()}`,
          stepTitle: '参数输入',
          title: '参数输入',
          description: data.payload?.message || '请补充以下信息',
          fields: multiFields,
          resolved: false
        })
        pendingInputRequest.value = multiBlock
        break

      case 'tool_confirm_required': {
        isTyping.value = false
        const interactionId = data.payload?.interaction_id || data.interaction_id
        if (hasOpenInteraction(interactionId)) break
        attachRunInteraction(data.payload || {}, {
          type: 'actions',
          actionSource: 'tool_confirm',
          interactionId,
          stepId: `decision:${data.payload?.tool_name || interactionId}`,
          stepTitle: data.payload?.tool_name || '工具确认',
          title: `确认执行: ${data.payload?.tool_name || '-'}`,
          description: data.payload?.description || `目标: ${data.payload?.target || '-'}`,
          params: { 'Tool': data.payload?.tool_name || '-', 'Target': data.payload?.target || '-' },
          options: [
            { key: 'approve', label: '确认执行', style: 'btn-primary' },
            { key: 'reject', label: '拒绝', style: 'btn-ghost' }
          ],
          resolved: false
        })
        break
      }

      case 'tool_not_found':
        isTyping.value = false
        const notFoundOpts = (data.payload?.options || []).map(o => ({ key: o.key, label: o.label, style: 'btn-secondary' }))
        attachRunInteraction(data.payload || {}, {
          type: 'actions',
          actionSource: 'interaction_required',
          interactionId: data.payload?.interaction_id || `tool-not-found:${data.payload?.tool_name || 'unknown'}`,
          stepId: `decision:tool-not-found:${data.payload?.tool_name || 'unknown'}`,
          stepTitle: '选择替代工具',
          title: `工具未找到: ${data.payload?.tool_name || '-'}`,
          description: data.payload?.message || '请选择替代工具',
          options: notFoundOpts,
          resolved: false
        })
        break

      case 'tool_execution_started':
        addInfoBlock(`工具执行开始: ${data.payload?.tool_name || '-'}`)
        break

      case 'tool_execution_completed':
        addInfoBlock(`工具执行完成: ${data.payload?.tool_name || '-'}`)
        break

      case 'direct_tool_started':
        if (!acceptRunEvent(data.payload || {})) break
        isTyping.value = true
        upsertRunStep(data.payload || {}, {
          title: data.payload?.tool || '直接工具',
          status: 'running',
          message: `正在扫描 ${data.payload?.target || ''}`
        })
        break

      case 'direct_tool_completed':
        if (!acceptRunEvent(data.payload || {})) break
        isTyping.value = false
        upsertRunStep(data.payload || {}, {
          title: data.payload?.tool || '直接工具',
          status: 'completed',
          message: data.payload?.formatted_result || '执行完成',
          analysis: data.payload?.analysis || '',
          rawResult: data.payload?.raw_result || null
        })
        break

      case 'direct_tool_error':
        if (!acceptRunEvent(data.payload || {})) break
        isTyping.value = false
        upsertRunStep(data.payload || {}, {
          title: data.payload?.tool || '直接工具',
          status: 'failed',
          message: data.payload?.error || '未知错误'
        })
        break

      case 'report_generation_started':
        if (!acceptRunEvent(data.payload || {})) break
        isTyping.value = true
        upsertRunStep(data.payload || {}, {
          title: '生成扫描报告',
          status: 'running',
          message: `正在汇总 ${data.payload?.tool_count || 0} 个工具、${data.payload?.vulnerability_count || 0} 个漏洞`
        })
        break

      case 'report_generated':
        if (!acceptRunEvent(data.payload || {})) break
        isTyping.value = false
        const reportUrl = data.payload?.report_url || ''
        const htmlReportUrl = data.payload?.html_report_url || ''
        const preview = data.payload?.report_preview || ''
        let reportContent = `报告已生成\n报告ID: ${data.payload?.report_id || '-'}`
        if (htmlReportUrl) {
          reportContent += `\n📄 HTML报告: ${htmlReportUrl}`
        }
        if (reportUrl) {
          reportContent += `\n📝 Markdown报告: ${reportUrl}`
        }
        if (preview) {
          reportContent += `\n\n${preview}`
        }
        upsertRunStep(data.payload || {}, {
          title: '生成扫描报告',
          status: 'completed',
          message: reportContent,
          analysis: preview
        })
        break

      case 'report_error':
        if (!acceptRunEvent(data.payload || {})) break
        isTyping.value = false
        upsertRunStep(data.payload || {}, {
          title: '生成扫描报告',
          status: 'failed',
          message: data.payload?.error || '未知错误'
        })
        break

      case 'run_snapshot': {
        if (!acceptRunEvent(data.payload || {})) break
        const snapshot = data.payload || {}
        const completedTasks = snapshot.completed_tasks || []
        const failedTasks = snapshot.failed_tasks || []
        if (!snapshot.target && !completedTasks.length && !failedTasks.length && !snapshot.total_tasks) break
        updateRun(snapshot, {
          target: snapshot.target || '',
          mode: snapshot.mode || '',
          status: snapshot.is_complete ? 'completed' : 'running',
          completed: completedTasks.length,
          total: snapshot.total_tasks || scanProgress.value.total || 0
        })
        completedTasks.forEach(tool => upsertRunStep({ ...snapshot, step_id: `tool:${tool}`, tool }, {
          title: tool,
          status: 'completed',
          rawResult: snapshot.tool_results?.[tool] || null
        }))
        failedTasks.forEach(tool => upsertRunStep({ ...snapshot, step_id: `tool:${tool}`, tool }, {
          title: tool,
          status: 'failed',
          message: '此前执行失败'
        }))
        ;(snapshot.logs || []).forEach(entry => appendRunLog({ ...snapshot, ...entry }))
        break
      }

      case 'alternative_options':
        isTyping.value = false
        const altOpts = (data.payload?.alternatives || []).map(a => ({ key: a.action, label: a.label, style: 'btn-secondary' }))
        attachRunInteraction(data.payload || {}, {
          type: 'actions',
          actionSource: 'alternative_options',
          interactionId: data.payload?.interaction_id || `alternative:${data.payload?.rejected_tool || Date.now()}`,
          stepId: `decision:alternative:${data.payload?.rejected_tool || 'tool'}`,
          stepTitle: '选择替代方案',
          title: `替代方案 (已拒绝: ${data.payload?.rejected_tool || '-'})`,
          description: '请选择一个替代方案',
          options: altOpts,
          resolved: false
        })
        break

      case 'auth_unavailable':
        addInfoBlock(`认证不可用 | ${data.payload?.message || '继续无认证执行'}`)
        break

      case 'auth_refresh_required':
        addInfoBlock(`认证刷新中... | 重试: ${data.payload?.retry_count || 0}/${data.payload?.max_retries || 3} | 原因: ${data.payload?.reason || '-'}`)
        break

      case 'auth_refresh_success':
        addInfoBlock(`认证刷新成功 | 来源: ${data.payload?.source_tool || '-'} | 类型: ${data.payload?.auth_type || '-'}`)
        break

      case 'auth_retry_exhausted':
        addErrorBlock(`认证重试耗尽 | ${data.payload?.message || '-'}`)
        break

      case 'auth_info_obtained':
        addInfoBlock(`已获取认证信息 | 来源: ${data.payload?.source_tool || '-'} | 类型: ${data.payload?.auth_type || '-'}`)
        break

      case 'workflow_resumed':
        scanStatus.value = 'scanning'
        addInfoBlock(`工作流已恢复 | 已完成任务: ${(data.payload?.completed_tasks || []).length} 个`)
        break

      case 'script_registered':
        const regToolName = data.payload?.tool_name || ''
        scriptUploadProgress.value = { stage: 'completed', progress: 100, message: '脚本注册成功' }
        addInfoBlock(`脚本已注册: ${regToolName} | ${data.payload?.message || ''}`)
        saveScriptHistory({
          tool_name: regToolName,
          description: data.payload?.description || '',
          source: 'upload',
          script_content: data.payload?.script_content || ''
        })
        if (pendingUploadScript.value) {
          const target = scriptQueue.value[currentScriptIndex.value]?.target || ''
          scriptQueue.value.splice(currentScriptIndex.value + 1, 0, { tool_name: regToolName, status: 'pending', target })
          addInfoBlock(`新脚本 "${regToolName}" 已加入执行队列`)
        }
        break
      
      case 'script_upload_progress':
        scriptUploadProgress.value = {
          stage: data.payload?.stage || '',
          progress: data.payload?.progress || 0,
          message: data.payload?.message || ''
        }
        if (data.payload?.stage === 'validating') {
          addInfoBlock(`验证脚本中...`)
        } else if (data.payload?.stage === 'analyzing') {
          addInfoBlock(`分析脚本中...`)
        } else if (data.payload?.stage === 'registering') {
          addInfoBlock(`注册工具中...`)
        } else if (data.payload?.stage === 'failed') {
          addErrorBlock(`脚本上传失败: ${data.payload?.message || '未知错误'}`, { source: 'backend' })
        }
        break

      case 'script_generating':
        scriptGenerationProgress.value = { stage: 'generating', progress: 30, message: data.payload?.message || '' }
        addInfoBlock(`AI 生成脚本中: ${data.payload?.message || ''}`)
        break
      
      case 'script_generation_progress':
        scriptGenerationProgress.value = {
          stage: data.payload?.stage || '',
          progress: data.payload?.progress || 0,
          message: data.payload?.message || ''
        }
        if (data.payload?.stage === 'analyzing') {
          addInfoBlock(`分析需求中...`)
        } else if (data.payload?.stage === 'generating') {
          addInfoBlock(`AI 生成代码中...`)
        } else if (data.payload?.stage === 'validating') {
          addInfoBlock(`安全审查中...`)
        } else if (data.payload?.stage === 'registering') {
          addInfoBlock(`注册工具中...`)
        } else if (data.payload?.stage === 'failed') {
          addErrorBlock(`脚本生成失败: ${data.payload?.message || '未知错误'}`, { source: 'backend' })
        }
        break

      case 'script_generated':
        const genToolName = data.payload?.tool_name || ''
        scriptGenerationProgress.value = { stage: 'completed', progress: 100, message: '脚本生成成功' }
        addInfoBlock(`脚本生成完成: ${genToolName} | ${data.payload?.message || ''}`)
        saveScriptHistory({
          tool_name: genToolName,
          description: data.payload?.description || '',
          source: 'generate',
          script_content: data.payload?.script_code || ''
        })
        isTyping.value = false
        if (pendingGenerateScript.value) {
          const target = scriptQueue.value[currentScriptIndex.value]?.target || ''
          scriptQueue.value.splice(currentScriptIndex.value + 1, 0, { tool_name: genToolName, status: 'pending', target })
          addInfoBlock(`新脚本 "${genToolName}" 已加入执行队列，继续循环`)
          pendingGenerateScript.value = false
          currentScriptIndex.value++
          setTimeout(() => triggerScriptConfirm(), 500)
        }
        break

      case 'script_analyzing':
        addInfoBlock(`分析脚本中: ${data.payload?.message || ''}`)
        break

      case 'script_upload_request':
        addInfoBlock(`${data.payload?.message || '请在输入框中粘贴脚本内容'}`)
        break

      case 'script_error':
        addErrorBlock(`脚本错误: ${data.payload?.error || '未知错误'}`)
        break

      case 'script_generate_request':
        addInfoBlock(`${data.payload?.message || '请描述需要生成的脚本功能'}`)
        break

      case 'node_retry':
        addInfoBlock('节点重试中...')
        break

      case 'input_received':
        addInfoBlock(`输入已接收 | ${data.payload?.field || ''} = ${data.payload?.value || ''}`)
        break

      case 'user_message_received':
        break

      case 'subscribed':
        addInfoBlock(`已订阅会话 | Session: ${data.payload?.session_id || '-'}`)
        if (data.payload?.state) {
          const subscribedState = data.payload.state
          const hasScan = Boolean(subscribedState.target || subscribedState.completed_tasks?.length)
          scanStatus.value = !hasScan ? 'idle' : subscribedState.is_complete ? 'completed' : 'scanning'
          scanActive.value = scanStatus.value === 'scanning'
        }
        break

      case 'history':
        syncChatHistory(data.payload?.history || [])
        addLog({ level: 'INFO', message: `已同步 ${(data.payload?.history || []).length} 条历史记录` })
        break

      case 'status':
        const state = data.payload?.state
        if (state) {
          const hasScan = Boolean(state.target || state.planned_tasks?.length || state.completed_tasks?.length)
          scanStatus.value = !hasScan ? 'idle' : state.is_complete ? 'completed' : 'scanning'
          scanActive.value = scanStatus.value === 'scanning'
          scanProgress.value.current = (state.completed_tasks || []).length
          scanProgress.value.total = state.total_tasks || state.planned_tasks?.length || state.completed_tasks?.length || 0
          if (scanStatus.value !== 'idle') {
            addInfoBlock(`会话状态: ${scanStatus.value === 'completed' ? '已完成' : '扫描中'}`)
          }
        } else {
          addInfoBlock('会话状态: 空闲')
        }
        break

      case 'high_risk_confirmed':
        addInfoBlock(`高危决策已确认 | 选择: ${data.payload?.choice || '-'}`)
        break

      case 'workflow_error':
        isTyping.value = false
        isThinking.value = false
        scanStatus.value = 'error'
        addErrorBlock(`工作流错误: ${data.payload?.error || '未知错误'}`, {
          source: 'backend',
          category: data.payload?.code || 'WORKFLOW_ERROR',
          suggestion: data.payload?.suggestion || '请刷新页面重试',
          details: JSON.stringify(data.payload, null, 2)
        })
        break

      case 'workflow_timeout':
        isTyping.value = false
        isThinking.value = false
        scanStatus.value = 'idle'
        addErrorBlock(`工作流超时: ${data.payload?.message || '已超过30分钟未响应，自动结束'}`, {
          source: 'backend',
          category: 'WORKFLOW_TIMEOUT',
          suggestion: '请重新发起扫描',
          details: `超时时间: ${data.payload?.elapsed_seconds || 'N/A'}秒`
        })
        break

      case 'tool_execution_proceed':
        addInfoBlock('工具已确认执行')
        break

      case 'tool_rejected_processing':
        addInfoBlock('正在生成替代方案...')
        break

      case 'alternative_applied':
        addInfoBlock(`已应用替代方案: ${data.payload?.choice_label || '-'}`)
        break

      case 'error':
        isTyping.value = false
        scanStatus.value = 'error'
        const errorPayload = data.payload || {}
        addErrorBlock(
          errorPayload.message || errorPayload.error || '未知错误',
          {
            code: errorPayload.code,
            source: errorPayload.source,
            category: errorPayload.category,
            suggestion: errorPayload.suggestion,
            details: errorPayload.details
          }
        )
        break

      case 'execution_plan':
        addInfoBlock(`执行计划: ${JSON.stringify(data.payload || {})}`)
        break

      case 'workflow_log':
        addLog({
          level: data.payload?.level || 'INFO',
          message: data.payload?.message || '',
          timestamp: data.payload?.timestamp || data.timestamp || null
        })
        if (acceptRunEvent(data.payload || {})) appendRunLog(data.payload || {})
        break

      case 'tool_progress':
        addLog({
          level: data.payload?.level || 'INFO',
          message: data.payload?.message || '',
          timestamp: data.payload?.timestamp || data.timestamp || null
        })
        if (acceptRunEvent(data.payload || {})) appendRunLog(data.payload || {})
        break

      default:
        break
    }
  }

  watch(
    [
      workspaceBlocks,
      scanActive,
      waitingForChoice,
      pendingScanConfirm,
      showScanConfirm,
      scanProgress,
      scanStatus,
      () => globalState.currentTarget
    ],
    scheduleConsolePersist,
    { deep: true }
  )

  onMounted(() => {
    ws.on('*', handleWSMessage)
    
    ws.onConnect(() => {
      addLog({ level: 'INFO', message: 'WebSocket 连接成功', timestamp: new Date().toISOString() })
    })
    
    ws.onDisconnect((event) => {
      const reason = event?.reason || '连接已关闭'
      addLog({ level: 'WARNING', message: `WebSocket 连接断开，正在重连：${reason}`, timestamp: new Date().toISOString() })
    })
    
    ws.onError((error) => {
      addLog({ level: 'ERROR', message: `WebSocket 连接错误：${error?.message || '未知错误'}`, timestamp: new Date().toISOString() })
    })
    
    ws.onReconnect((sessionId) => {
      addLog({ level: 'INFO', message: `WebSocket 已恢复：${sessionId}`, timestamp: new Date().toISOString() })
      ws.sendGetHistory()
      ws.sendGetStatus()
    })
  })

  onUnmounted(() => {
    ws.off('*', handleWSMessage)
    if (persistTimer) clearTimeout(persistTimer)
    persistConsoleState()
  })

  return {
    inputText,
    workspaceBlocks,
    isTyping,
    waitingForChoice,
    currentThinking,
    isThinking,
    thinkingExpanded,
    scanProgress,
    pendingInputRequest,
    scanStatus,
    scanActive,
    sendMessage,
    handleQuickAction,
    handleBlockAction,
    handleInputResponse,
    handleStop,
    handleModeSelect,
    handleScanConfirm,
    handleScanCancel,
    showUploadScriptForm,
    showGenerateScriptForm,
    submitBlockInput,
    scriptUploadProgress,
    scriptGenerationProgress,
    scriptHistory,
    validateScriptFile,
    handleScriptFileSelect,
    loadScriptHistory,
    saveScriptHistory
  }
}
