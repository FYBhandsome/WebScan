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
