const TERMINAL_STEP_STATUSES = new Set(['completed', 'failed', 'skipped', 'cancelled'])

const taskFromMessage = (message = '') => {
  const match = String(message).match(/任务(?:开始|完成|失败):\s*([^,，\s]+)/)
  return match?.[1] || ''
}

export const normalizeRunLogPayload = (payload = {}) => {
  const details = payload.details && typeof payload.details === 'object' ? payload.details : {}
  const tool = payload.tool || payload.tool_name || details.tool || (
    payload.node === 'execute_task' ? taskFromMessage(payload.message) : ''
  )
  return {
    ...payload,
    tool,
    step_id: payload.step_id || details.step_id || (tool ? `tool:${tool}` : '')
  }
}

export const appendLogWithoutChangingStepStatus = (step, payload = {}) => {
  const entry = {
    id: payload.id || `${payload.sequence || Date.now()}:${payload.message || ''}`,
    level: String(payload.level || 'info').toLowerCase(),
    message: payload.message || '',
    timestamp: payload.timestamp || new Date().toISOString()
  }
  step.logs ||= []
  if (!step.logs.some(item => item.id === entry.id)) {
    step.logs.push(entry)
    if (step.logs.length > 100) step.logs.splice(0, step.logs.length - 100)
  }
  return step
}

export const settleOtherRunningToolSteps = (run, activeStepId) => {
  for (const step of run?.steps || []) {
    if (
      step.stepId !== activeStepId
      && step.stepId?.startsWith('tool:')
      && step.status === 'running'
    ) {
      step.status = 'completed'
    }
  }
}

export const removeLegacyExecuteTaskSteps = (run) => {
  if (!run?.steps?.length) return
  const legacySteps = run.steps.filter(step => (
    step.stepId === 'workflow:execute_task'
    || (step.title === 'execute_task' && !step.stepId?.startsWith('tool:'))
  ))
  if (!legacySteps.length) return

  for (const legacy of legacySteps) {
    for (const log of legacy.logs || []) {
      const normalized = normalizeRunLogPayload({ ...log, node: 'execute_task' })
      if (!normalized.tool) continue
      const stepId = `tool:${normalized.tool}`
      let target = run.steps.find(step => step.stepId === stepId)
      if (!target) {
        target = {
          stepId,
          title: normalized.tool,
          status: TERMINAL_STEP_STATUSES.has(legacy.status) ? legacy.status : 'pending',
          message: '',
          analysis: '',
          logs: [],
          rawResult: null
        }
        run.steps.push(target)
      }
      appendLogWithoutChangingStepStatus(target, normalized)
    }
  }
  run.steps = run.steps.filter(step => !legacySteps.includes(step))
}
