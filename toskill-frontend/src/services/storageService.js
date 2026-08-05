class StorageService {
  constructor() {
    this.prefix = 'toskill_'
    this.maxConsoleBlocks = 200
  }
  
  _getKey(key) {
    return `${this.prefix}${key}`
  }
  
  _parseJSON(value, defaultValue = null) {
    if (!value) return defaultValue
    try {
      return JSON.parse(value)
    } catch {
      return defaultValue
    }
  }
  
  set(key, value) {
    try {
      const serialized = typeof value === 'string' ? value : JSON.stringify(value)
      localStorage.setItem(this._getKey(key), serialized)
      return true
    } catch (e) {
      console.error(`StorageService.set failed: ${e.message}`)
      return false
    }
  }
  
  get(key, defaultValue = null) {
    const value = localStorage.getItem(this._getKey(key))
    if (value === null) return defaultValue
    return this._parseJSON(value, value)
  }
  
  remove(key) {
    localStorage.removeItem(this._getKey(key))
  }
  
  clear() {
    const keys = Object.keys(localStorage)
    keys.forEach(key => {
      if (key.startsWith(this.prefix)) {
        localStorage.removeItem(key)
      }
    })
  }
  
  getScanHistory() {
    return this.get('scan_history', [])
  }
  
  addScanHistory(scan) {
    const history = this.getScanHistory()
    const exists = history.findIndex(s => s.target === scan.target && s.mode === scan.mode)
    if (exists >= 0) {
      history[exists] = { ...history[exists], ...scan, timestamp: new Date().toISOString() }
    } else {
      history.unshift({ ...scan, timestamp: new Date().toISOString() })
    }
    this.set('scan_history', history.slice(0, 100))
    return history
  }
  
  getScriptHistory() {
    return this.get('script_history', [])
  }
  
  addScriptHistory(script) {
    const history = this.getScriptHistory()
    const exists = history.findIndex(s => s.tool_name === script.tool_name)
    if (exists >= 0) {
      history[exists] = { ...history[exists], ...script, timestamp: new Date().toISOString() }
    } else {
      history.unshift({ ...script, timestamp: new Date().toISOString() })
    }
    this.set('script_history', history.slice(0, 50))
    return history
  }
  
  getPreferences() {
    return this.get('preferences', {
      theme: 'dark',
      autoScan: false,
      notifications: true,
      language: 'zh-CN'
    })
  }
  
  setPreferences(prefs) {
    const current = this.getPreferences()
    this.set('preferences', { ...current, ...prefs })
  }
  
  getSessionData(sessionId) {
    return this.get(`session_${sessionId}`, null)
  }
  
  saveSessionData(sessionId, data) {
    this.set(`session_${sessionId}`, data)
  }
  
  clearSessionData(sessionId) {
    this.remove(`session_${sessionId}`)
  }

  getActiveSessionId() {
    return this.get('active_session_id', '') || ''
  }

  setActiveSessionId(sessionId) {
    if (sessionId) this.set('active_session_id', sessionId)
  }

  getConsoleState(sessionId) {
    if (!sessionId) return null
    return this.get(`console_${sessionId}`, null)
  }

  saveConsoleState(sessionId, state) {
    if (!sessionId || !state) return false
    const workspaceBlocks = Array.isArray(state.workspaceBlocks)
      ? state.workspaceBlocks.slice(-this.maxConsoleBlocks)
      : []
    return this.set(`console_${sessionId}`, {
      ...state,
      workspaceBlocks,
      savedAt: new Date().toISOString()
    })
  }

  getScanState() {
    return this.get('scan_workspace', null)
  }

  saveScanState(state) {
    if (!state) return false
    return this.set('scan_workspace', {
      ...state,
      savedAt: new Date().toISOString()
    })
  }
  
  getRecentTargets() {
    return this.get('recent_targets', [])
  }
  
  addRecentTarget(target) {
    const targets = this.getRecentTargets().filter(t => t !== target)
    targets.unshift(target)
    this.set('recent_targets', targets.slice(0, 20))
  }
}

export const storageService = new StorageService()
export default storageService
