import { reactive, ref } from 'vue'

// 1. 全局状态
export const globalState = reactive({
  currentTarget: '',
  toasts: [],
  modal: {
    show: false,
    title: '',
    body: '',
    onConfirm: null
  }
})

// 控制台与顶部栏共享同一份扫描状态，避免各组件重复维护进度。
export const scanProgressState = ref({ current: 0, total: 0, activeTool: '' })
export const scanStatusState = ref('idle')

// 控制台注册脚本后，工具页在下次打开时定位到对应的自定义工具。
const pendingCustomToolFocus = reactive({ name: '', category: '' })

export const focusCustomTool = (name, category) => {
  pendingCustomToolFocus.name = name || ''
  pendingCustomToolFocus.category = category || 'info_collection'
}

export const consumeCustomToolFocus = () => {
  if (!pendingCustomToolFocus.name) return null
  const focus = { ...pendingCustomToolFocus }
  pendingCustomToolFocus.name = ''
  pendingCustomToolFocus.category = ''
  return focus
}

// 2. Toast 提示系统
let toastIdCounter = 0
export const showToast = (message, type = 'info') => {
  const id = toastIdCounter++
  globalState.toasts.push({ id, message, type })
  
  // 3秒后自动移除
  setTimeout(() => {
    globalState.toasts = globalState.toasts.filter(t => t.id !== id)
  }, 3000)
}

// 3. 全局 Modal 弹窗系统
export const showModal = (title, body, onConfirmCallback) => {
  globalState.modal.title = title
  globalState.modal.body = body
  globalState.modal.onConfirm = onConfirmCallback
  globalState.modal.show = true
}

export const closeModal = () => {
  globalState.modal.show = false
  globalState.modal.onConfirm = null
}

export const addScanHistory = (target) => {
  try {
    const raw = localStorage.getItem('scan_history')
    const history = raw ? JSON.parse(raw) : []
    const filtered = history.filter(item => item !== target)
    filtered.unshift(target)
    const trimmed = filtered.slice(0, 5)
    localStorage.setItem('scan_history', JSON.stringify(trimmed))
  } catch (e) {
    // localStorage 不可用或数据损坏时静默失败
  }
}

export const getScanHistory = () => {
  try {
    const raw = localStorage.getItem('scan_history')
    return raw ? JSON.parse(raw) : []
  } catch (e) {
    return []
  }
}

// ============ 多会话管理 ============
export const conversationState = reactive({
  conversations: [],   // [{ id, title, createdAt, lastActiveAt, userRenamed, status }]
  currentId: null,
})

const MAX_CONVERSATIONS = 20
const CONV_INDEX_KEY = 'toskill_conversations'
const CONV_BLOCKS_PREFIX = 'toskill_conv_blocks_'
const DATA_TTL = 24 * 60 * 60 * 1000  // 24 小时

// localStorage 安全写入：捕获 QuotaExceededError，自动淘汰最老会话后重试
let _lastQuotaToastAt = 0
export const safeSetItem = (key, value) => {
  try {
    localStorage.setItem(key, value)
    return true
  } catch (e) {
    // 容量超限：尝试淘汰最老的会话数据后重试一次
    if (e && (e.name === 'QuotaExceededError' || e.code === 22)) {
      try {
        _evictOldestConversationData()
        localStorage.setItem(key, value)
        return true
      } catch (e2) {
        // 仍失败：30 秒防抖提示用户
        const now = Date.now()
        if (now - _lastQuotaToastAt > 30000) {
          _lastQuotaToastAt = now
          showToast('浏览器存储空间不足，请清理记忆数据', 'warning')
        }
        return false
      }
    }
    return false
  }
}

// 淘汰最老的会话数据（按 lastActiveAt 升序）
const _evictOldestConversationData = () => {
  const conversations = [...conversationState.conversations]
    .sort((a, b) => new Date(a.lastActiveAt) - new Date(b.lastActiveAt))
  if (conversations.length === 0) {
    // 没有会话索引，直接遍历清理最老的 blocks 键
    const blockKeys = []
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i)
      if (k && k.startsWith(CONV_BLOCKS_PREFIX)) blockKeys.push(k)
    }
    if (blockKeys.length > 0) localStorage.removeItem(blockKeys[0])
    return
  }
  // 删除最老会话的 blocks 数据（保留索引，仅清数据）
  const oldest = conversations[0]
  localStorage.removeItem(CONV_BLOCKS_PREFIX + oldest.id)
}

export const loadConversationIndex = () => {
  try {
    const raw = localStorage.getItem(CONV_INDEX_KEY)
    if (raw) {
      const data = JSON.parse(raw)
      conversationState.conversations = data.conversations || []
      conversationState.currentId = data.currentId || null
    }
  } catch (e) { /* ignore */ }
}

export const persistConversationIndex = () => {
  try {
    safeSetItem(CONV_INDEX_KEY, JSON.stringify({
      conversations: conversationState.conversations,
      currentId: conversationState.currentId
    }))
  } catch (e) { /* ignore */ }
}

// 持久化单个会话的 workspaceBlocks 与 inputText
const MAX_BLOCKS_PER_CONV = 200
export const saveConversationBlocks = (id, blocks, inputText) => {
  if (!id) return false
  // 截断至 200 条，保留 agent_run 完整性
  const trimmed = Array.isArray(blocks) && blocks.length > MAX_BLOCKS_PER_CONV
    ? blocks.slice(blocks.length - MAX_BLOCKS_PER_CONV)
    : (Array.isArray(blocks) ? blocks : [])
  const payload = {
    id,
    blocks: trimmed,
    inputText: inputText || '',
    savedAt: new Date().toISOString(),
    version: 1
  }
  return safeSetItem(CONV_BLOCKS_PREFIX + id, JSON.stringify(payload))
}

// 从 localStorage 恢复指定会话的 blocks（带 TTL 校验）
export const loadConversationBlocks = (id) => {
  if (!id) return null
  try {
    const raw = localStorage.getItem(CONV_BLOCKS_PREFIX + id)
    if (!raw) return null
    const data = JSON.parse(raw)
    // 版本校验
    if (data.version !== 1) {
      localStorage.removeItem(CONV_BLOCKS_PREFIX + id)
      return null
    }
    // TTL 校验
    const savedAt = data.savedAt ? new Date(data.savedAt).getTime() : 0
    if (Date.now() - savedAt > DATA_TTL) {
      localStorage.removeItem(CONV_BLOCKS_PREFIX + id)
      return null
    }
    return {
      blocks: Array.isArray(data.blocks) ? data.blocks : [],
      inputText: data.inputText || ''
    }
  } catch (e) {
    return null
  }
}

// 清理所有过期的记忆数据（应用启动时调用）
export const clearExpiredData = () => {
  const now = Date.now()
  // 1. 清理过期会话索引与对应 blocks
  try {
    const raw = localStorage.getItem(CONV_INDEX_KEY)
    if (raw) {
      const data = JSON.parse(raw)
      const validConversations = []
      for (const conv of (data.conversations || [])) {
        const lastActive = conv.lastActiveAt ? new Date(conv.lastActiveAt).getTime() : 0
        if (now - lastActive > DATA_TTL) {
          // 过期：删除该会话的 blocks 数据
          localStorage.removeItem(CONV_BLOCKS_PREFIX + conv.id)
        } else {
          validConversations.push(conv)
        }
      }
      // 若有过期清理，回写索引
      if (validConversations.length !== (data.conversations || []).length) {
        data.conversations = validConversations
        safeSetItem(CONV_INDEX_KEY, JSON.stringify(data))
      }
    }
  } catch (e) { /* ignore */ }

  // 2. 遍历清理过期的 toskill_conv_blocks_* 键
  const keysToRemove = []
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i)
    if (!k) continue
    if (k.startsWith(CONV_BLOCKS_PREFIX)) {
      try {
        const data = JSON.parse(localStorage.getItem(k))
        const savedAt = data?.savedAt ? new Date(data.savedAt).getTime() : 0
        if (now - savedAt > DATA_TTL) keysToRemove.push(k)
      } catch (e) {
        keysToRemove.push(k)  // 解析失败的也删除
      }
    }
  }
  keysToRemove.forEach(k => localStorage.removeItem(k))

  // 3. 清理过期的扫描页状态
  try {
    const scanRaw = localStorage.getItem('toskill_scan_workspace')
    if (scanRaw) {
      const scanData = JSON.parse(scanRaw)
      const savedAt = scanData?.savedAt ? new Date(scanData.savedAt).getTime() : 0
      if (now - savedAt > DATA_TTL) {
        localStorage.removeItem('toskill_scan_workspace')
      }
    }
  } catch (e) { /* ignore */ }

  // 4. 清理已废弃的 toskill_console_* 键（旧版数据）
  const legacyKeys = []
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i)
    if (k && k.startsWith('toskill_console_')) legacyKeys.push(k)
  }
  legacyKeys.forEach(k => localStorage.removeItem(k))
}

// 手动清除所有记忆数据（供 SettingsView 调用）
export const clearAllMemoryData = () => {
  // 收集所有需要清除的键
  const keysToRemove = []
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i)
    if (!k) continue
    if (
      k === CONV_INDEX_KEY ||
      k.startsWith(CONV_BLOCKS_PREFIX) ||
      k === 'toskill_scan_workspace' ||
      k.startsWith('toskill_console_') ||
      k === 'toskill_active_session_id' ||
      k === 'toskill_ui_prefs'
    ) {
      keysToRemove.push(k)
    }
  }
  keysToRemove.forEach(k => localStorage.removeItem(k))
  // 重置会话状态
  conversationState.conversations = []
  conversationState.currentId = null
}

// 统计记忆数据占用空间
export const getStorageUsage = () => {
  let bytes = 0
  const prefixes = [CONV_BLOCKS_PREFIX, 'toskill_conv', 'toskill_scan_workspace', 'toskill_console_']
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i)
    if (!k) continue
    const isMemoryKey =
      k === CONV_INDEX_KEY ||
      k === 'toskill_scan_workspace' ||
      k === 'toskill_ui_prefs' ||
      prefixes.some(p => k.startsWith(p))
    if (isMemoryKey) {
      const v = localStorage.getItem(k) || ''
      // 键名 + 值的字符数近似字节数（UTF-16 占 2 字节/字符，简化用字符数）
      bytes += (k.length + v.length) * 2
    }
  }
  let label
  if (bytes < 1024) label = bytes + ' B'
  else if (bytes < 1024 * 1024) label = (bytes / 1024).toFixed(1) + ' KB'
  else label = (bytes / (1024 * 1024)).toFixed(2) + ' MB'
  return { bytes, label }
}

export const createEmptyConversation = () => ({
  id: `conv_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
  title: '新对话',
  createdAt: new Date().toISOString(),
  lastActiveAt: new Date().toISOString(),
  userRenamed: false,
  status: 'idle',
  sessionId: null
})

export const createNewConversation = (sessionId = null) => {
  if (conversationState.conversations.length >= MAX_CONVERSATIONS) {
    return { success: false, error: '已达到最大会话数限制（20个）' }
  }
  const conv = createEmptyConversation()
  conv.sessionId = sessionId
  conversationState.conversations.unshift(conv)
  conversationState.currentId = conv.id
  persistConversationIndex()
  return { success: true, conversation: conv }
}

export const deleteConversation = (id) => {
  const idx = conversationState.conversations.findIndex(c => c.id === id)
  if (idx === -1) return
  conversationState.conversations.splice(idx, 1)
  // 同步清理该会话的 blocks 数据（统一键名）
  localStorage.removeItem(CONV_BLOCKS_PREFIX + id)
  // 兼容旧版键名清理
  localStorage.removeItem(`toskill_conv_${id}`)
  if (conversationState.currentId === id) {
    conversationState.currentId = conversationState.conversations[0]?.id || null
  }
  persistConversationIndex()
}

// 设置对话的后端 session_id（WebSocket connected 消息回填时调用）
export const setConversationSessionId = (convId, sessionId) => {
  const conv = conversationState.conversations.find(c => c.id === convId)
  if (conv && !conv.sessionId) {
    conv.sessionId = sessionId
    persistConversationIndex()
  }
}

export const renameConversation = (id, title) => {
  const conv = conversationState.conversations.find(c => c.id === id)
  if (conv) {
    conv.title = title
    conv.userRenamed = true
    persistConversationIndex()
  }
}

export const updateConversationStatus = (id, status) => {
  const conv = conversationState.conversations.find(c => c.id === id)
  if (conv) {
    conv.status = status
    conv.lastActiveAt = new Date().toISOString()
    persistConversationIndex()
  }
}

export const setCurrentConversation = (id) => {
  conversationState.currentId = id
  persistConversationIndex()
}
