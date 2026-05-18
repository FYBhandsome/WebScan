class StorageService {
  constructor() {
    this.prefix = 'toskill_'
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
