import { ref, onMounted, onUnmounted, nextTick } from 'vue'
import { ws } from '../services/websocket.js'
import { showToast, globalState } from '../store.js'
import { API } from '../services/api.js'
import { addLog } from './useLogBus.js'

export function useAgentChat() {
  const inputText = ref('')
  const workspaceBlocks = ref([])
  const isTyping = ref(false)
  const waitingForChoice = ref(false)
  const currentThinking = ref('')
  const isThinking = ref(false)
  const thinkingExpanded = ref(true)
  const scanProgress = ref({ current: 0, total: 0, activeTool: '' })
  const pendingInputRequest = ref(null)
  const scanStatus = ref('idle')

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
  
  const scriptUploadProgress = ref({ stage: '', progress: 0, message: '' })
  const scriptGenerationProgress = ref({ stage: '', progress: 0, message: '' })
  const scriptHistory = ref([])
  const MAX_SCRIPT_SIZE = 500 * 1024
  
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

  // === UI 辅助方法 ===
  const addBlock = (type, data = {}) => {
    workspaceBlocks.value.push({
      id: Date.now() + Math.random(),
      timestamp: new Date().toLocaleTimeString('en-US', { hour12: false }),
      type,
      ...data
    })
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
    addBlock('agent_info', { content: message })
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
    
    addBlock('agent_error', { 
      content: fullMessage,
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
          
          addBlock('agent_scan_confirm', {
            target,
            mode,
            confidence,
            explanation,
            modes: [
              { key: 'info', label: '信息收集', desc: '端口扫描、子域名发现等', icon: 'target' },
              { key: 'vuln', label: '漏洞扫描', desc: 'XSS、SQL注入检测等', icon: 'shield' },
              { key: 'full', label: '完整扫描', desc: '信息收集+漏洞扫描', icon: 'layers' }
            ],
            resolved: false
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
    
    block.resolved = true
    showScanConfirm.value = false
    
    const { target, mode } = pendingScanConfirm.value || {}
    if (!target) {
      showToast('扫描目标丢失', 'error')
      isTyping.value = false
      return
    }
    
    const finalMode = selectedMode || mode || 'full'
    
    console.log('[handleScanConfirm] 确认扫描:', { target, finalMode, selectedMode, mode })
    
    addBlock('user_command', { content: `[确认执行] 目标: ${target} | 模式: ${finalMode === 'info' ? '信息收集' : finalMode === 'vuln' ? '漏洞扫描' : '完整扫描'}` })
    
    if (!ws.isConnected()) {
      console.log('[handleScanConfirm] WebSocket 未连接，尝试重新连接...')
      addBlock('agent_text', { content: '正在重新建立连接...' })
      
      try {
        await ws.connect()
        console.log('[handleScanConfirm] WebSocket 重新连接成功')
      } catch (connError) {
        console.error('[handleScanConfirm] WebSocket 连接失败:', connError)
        addBlock('agent_error', { content: '无法建立连接，请刷新页面重试' })
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
      addBlock('agent_error', { content: '发送扫描请求失败，请重试' })
      isTyping.value = false
      scanActive.value = false
      return
    }
    
    addBlock('agent_text', { content: `正在启动扫描...` })
    pendingScanConfirm.value = null
  }
  
  const handleScanCancel = (block) => {
    block.resolved = true
    showScanConfirm.value = false
    pendingScanConfirm.value = null
    addBlock('agent_text', { content: '已取消扫描' })
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
    addBlock('user_command', { content: `[选择模式]: ${mode === 'info' ? '信息收集' : mode === 'vuln' ? '漏洞扫描' : '完整扫描'} | 目标: ${target}` })
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
    addBlock('agent_action_request', {
      actionSource: 'script_confirm',
      title: `确认执行: ${script.tool_name}`,
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
    addBlock('agent_input_request', {
      type: 'agent_input_request',
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
      sourceBlock: block
    })
  }

  const showGenerateScriptForm = (block) => {
    addBlock('agent_input_request', {
      type: 'agent_input_request',
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
      sourceBlock: block
    })
  }

  const handleStop = () => {
    if (scriptLoopActive.value) scriptLoopActive.value = false
    scanActive.value = false
    isTyping.value = false
    isThinking.value = false
    showModeSelect.value = false
    ws.send('stop_scan', {})
    addBlock('agent_info', { content: '已发送停止请求' })
  }

  // === 交互卡片事件分发 ===
  const handleBlockAction = (block, choiceKey, choiceLabel) => {
    block.resolved = true
    addBlock('user_command', { content: `[授权决策]: ${choiceLabel}` })
    isTyping.value = true

    if (!ws.isConnected()) {
        isTyping.value = false
        return showToast('WebSocket 已断开', 'error')
    }

    switch (block.actionSource) {
      case 'interaction_required':
        waitingForChoice.value = false
        ws.sendConfirm(choiceKey)
        break
      case 'high_risk':
        ws.send('high_risk_confirm', { choice: choiceKey })
        break
      case 'tool_confirm':
        ws.sendToolConfirm(choiceKey === 'approve')
        break
      case 'alternative_options':
        ws.sendAlternativeSelected(choiceKey, choiceLabel)
        break
      case 'script_confirm':
        if (choiceKey === 'execute') {
          const script = scriptQueue.value[currentScriptIndex.value]
          script.status = 'running'
          isTyping.value = true
          addBlock('agent_info', { content: `正在执行脚本: ${script.tool_name}` })
          ws.send('execute_tool', { tool_name: script.tool_name, target: script.target })
        } else if (choiceKey === 'skip') {
          currentScriptIndex.value++
          addBlock('agent_info', { content: `已跳过: ${scriptQueue.value[currentScriptIndex.value - 1]?.tool_name || '-'}` })
          triggerScriptConfirm()
        } else if (choiceKey === 'stop_loop') {
          scriptLoopActive.value = false
          scanActive.value = false
          isTyping.value = false
          addBlock('agent_info', { content: '脚本循环已终止' })
        } else if (choiceKey === 'upload_script') {
          pendingUploadScript.value = true
          showUploadScriptForm(block)
        } else if (choiceKey === 'generate_script') {
          pendingGenerateScript.value = true
          showGenerateScriptForm(block)
        }
        break
    }
  }

  const submitBlockInput = (block, val) => {
    if (!val) return showToast('内容不能为空', 'warning')
    block.resolved = true
    addBlock('user_command', { content: `[参数输入]: ${val}` })
    isTyping.value = true
    ws.send('input_response', { field: block.payload.field, value: val })
  }

  const handleInputResponse = (block, value) => {
    if (block.type === 'agent_input_request' && Array.isArray(value)) {
      const fields = value
      for (const field of fields) {
        if (field.required && !field.value) {
          return showToast(`${field.label} 为必填项`, 'warning')
        }
      }
      block.resolved = true
      pendingInputRequest.value = null

      if (block.context === 'upload_script') {
        pendingUploadScript.value = false
        const scriptName = fields.find(f => f.field === 'script_name')?.value || null
        const scriptContent = fields.find(f => f.field === 'script_content')?.value || ''
        const name = scriptName || `custom_${Date.now().toString(36)}`
        addBlock('user_command', { content: `[上传脚本]: ${name}` })
        isTyping.value = true
        ws.send('script_content', { script_content: scriptContent, script_name: name })
        return
      } else if (block.context === 'generate_script') {
        pendingGenerateScript.value = false
        const description = fields.find(f => f.field === 'script_description')?.value || ''
        addBlock('user_command', { content: `[生成脚本]: ${description}` })
        isTyping.value = true
        ws.send('script_description', { description: description })
        return
      }

      const fieldLabels = fields.map(f => `${f.label}=${f.value}`).join(', ')
      addBlock('user_command', { content: `[参数提交]: ${fieldLabels}` })
      isTyping.value = true
      for (const field of fields) {
        if (field.value) {
          ws.send('input_response', { field: field.field, value: field.value })
        }
      }
      return
    }
    if (!value && block.required) return showToast('此字段为必填项', 'warning')
    block.resolved = true
    pendingInputRequest.value = null
    addBlock('user_command', { content: `[参数提交]: ${block.label} = ${value}` })
    isTyping.value = true
    ws.send('input_response', { field: block.field, value })
  }

  // === WebSocket 消息路由 ===
  const handleWSMessage = (data) => {
    checkStopStreaming(data)

    switch (data.type) {
      case 'connected':
        addBlock('agent_text', { content: `已连接到 AI Agent 引擎\nSession: ${data.payload?.session_id || 'Active'}\n可用工具: ${data.payload?.available_tools?.length || 0} 个` })
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

      case 'interaction_required':
        isTyping.value = false
        waitingForChoice.value = true
        addBlock('agent_action_request', {
          actionSource: 'interaction_required',
          title: '需要进一步指令',
          description: `目标: ${data.payload.target} | 规划节点: ${data.payload.next_task}`,
          options: data.payload.options.map(opt => ({ key: opt.key, label: opt.label, style: 'btn-secondary' })),
          resolved: false
        })
        break

      case 'high_risk_vulnerability_detected':
        isTyping.value = false
        addBlock('agent_action_request', {
          actionSource: 'high_risk',
          title: '高危漏洞确认 (CRITICAL)',
          description: data.payload.message || '系统检测到高危漏洞，请指示下一步动作。',
          params: { 'Vuln count': data.payload.vulnerabilities?.length || 1, 'Severity': 'HIGH' },
          options: [
            { key: 'continue', label: '继续扫描', style: 'btn-primary' },
            { key: 'poc_verify', label: 'POC验证', style: 'btn-secondary' },
            { key: 'stop', label: '中止并阻断', style: 'btn-danger' }
          ],
          resolved: false
        })
        break

      case 'scan_started':
        scanStatus.value = 'scanning'
        addInfoBlock(`扫描已启动 | 目标: ${data.payload?.target || '-'}`)
        break

      case 'scan_flow_started':
        scanProgress.value = { current: 0, total: data.payload?.total_tasks || 0, activeTool: '' }
        addInfoBlock(`工作流启动 | 模式: ${data.payload?.mode || '-'} | 计划任务: ${data.payload?.total_tasks || 0} 个`)
        break

      case 'scan_completed':
        scanStatus.value = 'completed'
        isTyping.value = false
        const tasks = data.payload?.completed_tasks || []
        const vulnCount = data.payload?.vulnerabilities_count ?? 0
        let summary = `扫描完成\n目标: ${data.payload?.target || '-'}\n已完成工具: ${tasks.length} 个\n发现漏洞: ${vulnCount} 个`
        if (data.payload?.report) summary += `\n报告: ${data.payload.report}`
        addBlock('agent_text', { content: summary })
        break

      case 'scan_cancelled':
        scanStatus.value = 'idle'
        isTyping.value = false
        addInfoBlock('扫描已取消')
        break

      case 'scan_terminated':
        scanStatus.value = 'error'
        isTyping.value = false
        addErrorBlock(`扫描终止 | 原因: ${data.payload?.reason || '-'} | 建议: ${data.payload?.suggestion || '-'}`)
        break

      case 'workflow_progress':
        scanProgress.value.current = data.payload?.completed ?? scanProgress.value.current
        scanProgress.value.total = data.payload?.total ?? scanProgress.value.total
        addInfoBlock(`进度: ${data.payload?.stage || '...'} (${data.payload?.completed || 0}/${data.payload?.total || 0})`)
        break

      case 'task_started':
        scanProgress.value.activeTool = data.payload?.tool || ''
        addInfoBlock(`执行工具: ${data.payload?.tool || '-'} → ${data.payload?.target || '-'}`)
        break

      case 'task_completed':
        isTyping.value = false
        const analysis = data.payload?.analysis || ''
        const vuln = data.payload?.vulnerable ? '发现漏洞' : '未发现漏洞'
        const auth = data.payload?.auth_obtained ? ' | 已获取认证' : ''
        if (scriptLoopActive.value && currentScriptIndex.value < scriptQueue.value.length) {
          const script = scriptQueue.value[currentScriptIndex.value]
          script.status = 'completed'
          addBlock('agent_script_result', {
            tool_name: data.payload?.tool || script.tool_name,
            target: script.target,
            status: 'completed',
            vulnerable: data.payload?.vulnerable || false,
            analysis: analysis,
            raw_result: data.payload?.raw_result || {},
            auth_obtained: data.payload?.auth_obtained || false,
            timestamp: data.payload?.timestamp || new Date().toISOString()
          })
          currentScriptIndex.value++
          setTimeout(() => triggerScriptConfirm(), 800)
        } else {
          addBlock('agent_text', { content: `工具完成: ${data.payload?.tool || '-'}\n${vuln}${auth}\n${analysis}` })
        }
        break

      case 'task_error':
        isTyping.value = false
        const taskError = data.payload || {}
        addErrorBlock(
          `工具执行失败: ${taskError.tool || '-'}`,
          {
            source: 'tool',
            suggestion: taskError.suggestion || '请检查目标是否可达，或尝试其他工具',
            details: { 
              tool: taskError.tool,
              error: taskError.error,
              target: taskError.target
            }
          }
        )
        break

      case 'task_skipped':
        addInfoBlock(`跳过工具: ${data.payload?.tool || '-'} | 原因: ${data.payload?.reason || '-'}`)
        break

      case 'ai_decision':
        const reactInfo = data.payload?.react_selected ? ` | ReACT: ${data.payload?.react_thought || ''}` : ''
        addInfoBlock(`AI 决策: ${data.payload?.next_task || '-'} | 进度: ${data.payload?.progress || ''}${reactInfo}`)
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
        const inputBlock = {
          type: 'agent_input_request',
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
        }
        addBlock('agent_input_request', inputBlock)
        pendingInputRequest.value = workspaceBlocks.value[workspaceBlocks.value.length - 1]
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
        const multiBlock = {
          type: 'agent_input_request',
          title: '参数输入',
          description: data.payload?.message || '请补充以下信息',
          fields: multiFields,
          resolved: false
        }
        addBlock('agent_input_request', multiBlock)
        pendingInputRequest.value = workspaceBlocks.value[workspaceBlocks.value.length - 1]
        break

      case 'tool_confirm_required':
        isTyping.value = false
        addBlock('agent_action_request', {
          actionSource: 'tool_confirm',
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

      case 'tool_not_found':
        isTyping.value = false
        const notFoundOpts = (data.payload?.options || []).map(o => ({ key: o.key, label: o.label, style: 'btn-secondary' }))
        addBlock('agent_action_request', {
          actionSource: 'interaction_required',
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
        addInfoBlock(`直接执行工具: ${data.payload?.tool || '-'} → ${data.payload?.target || '-'}`)
        break

      case 'direct_tool_completed':
        isTyping.value = false
        addBlock('agent_text', { content: `直接执行完成: ${data.payload?.tool || '-'}\n${data.payload?.formatted_result || data.payload?.analysis || ''}` })
        break

      case 'direct_tool_error':
        isTyping.value = false
        addErrorBlock(`直接执行失败 | ${data.payload?.tool || '-'}: ${data.payload?.error || '未知错误'}`)
        break

      case 'report_generation_started':
        isTyping.value = true
        addInfoBlock(`报告生成中... | 工具数: ${data.payload?.tool_count || 0} | 漏洞数: ${data.payload?.vulnerability_count || 0}`)
        break

      case 'report_generated':
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
        addBlock('agent_text', { content: reportContent })
        break

      case 'report_error':
        isTyping.value = false
        addErrorBlock(`报告生成失败: ${data.payload?.error || '未知错误'}`)
        break

      case 'alternative_options':
        isTyping.value = false
        const altOpts = (data.payload?.alternatives || []).map(a => ({ key: a.action, label: a.label, style: 'btn-secondary' }))
        addBlock('agent_action_request', {
          actionSource: 'alternative_options',
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
          scanStatus.value = data.payload.state.is_complete ? 'completed' : 'scanning'
        }
        break

      case 'history':
        const historyItems = data.payload?.history || []
        if (historyItems.length > 0) {
          addInfoBlock(`加载了 ${historyItems.length} 条历史记录`)
        }
        break

      case 'status':
        const state = data.payload?.state
        if (state) {
          scanStatus.value = state.is_complete ? 'completed' : 'scanning'
          scanProgress.value.current = (state.completed_tasks || []).length
          scanProgress.value.total = state.completed_tasks?.length || 0
          addInfoBlock(`会话状态: ${scanStatus.value === 'completed' ? '已完成' : '扫描中'}`)
        } else {
          addInfoBlock('会话状态: 空闲')
        }
        break

      case 'high_risk_confirmed':
        addInfoBlock(`高危决策已确认 | 选择: ${data.payload?.choice || '-'}`)
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
        break

      default:
        break
    }
  }

  onMounted(() => {
    ws.on('*', handleWSMessage)
    
    ws.onConnect(() => {
      addInfoBlock('✅ WebSocket 连接成功')
    })
    
    ws.onDisconnect((event) => {
      const reason = event?.reason || '连接已关闭'
      addErrorBlock(`WebSocket 连接断开: ${reason}`, { 
        source: 'websocket',
        suggestion: '正在尝试重新连接...'
      })
    })
    
    ws.onError((error) => {
      addErrorBlock('WebSocket 连接错误', { 
        source: 'websocket',
        suggestion: '请检查网络连接，或刷新页面重试'
      })
    })
    
    ws.onReconnect((sessionId) => {
      addInfoBlock('🔄 WebSocket 重新连接成功')
    })
  })

  onUnmounted(() => {
    ws.off('*', handleWSMessage)
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