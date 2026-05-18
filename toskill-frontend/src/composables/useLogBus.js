import { reactive } from 'vue'

const MAX_LOG_ENTRIES = 200

export const logState = reactive({
  logs: [],
  collapsed: false
})

let logIdCounter = 0

export function addLog(entry) {
  const id = ++logIdCounter
  const level = (entry.level || 'INFO').toUpperCase()
  const levels = ['INFO', 'WARNING', 'ERROR']
  if (!levels.includes(level)) {
    entry.level = 'INFO'
  }

  logState.logs.push({
    id,
    timestamp: entry.timestamp || new Date().toLocaleTimeString('en-US', { hour12: false }),
    level,
    message: entry.message || ''
  })

  while (logState.logs.length > MAX_LOG_ENTRIES) {
    logState.logs.shift()
  }
}

export function clearLogs() {
  logState.logs.splice(0, logState.logs.length)
}