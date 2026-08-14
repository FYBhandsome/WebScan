import { describe, expect, it } from 'vitest'

import {
  appendLogWithoutChangingStepStatus,
  normalizeRunLogPayload,
  removeLegacyExecuteTaskSteps,
  settleOtherRunningToolSteps
} from './runStepState.js'

describe('run step state', () => {
  it('keeps a completed tool completed when its completion log arrives later', () => {
    const step = { stepId: 'tool:port_scan', status: 'completed', logs: [] }

    appendLogWithoutChangingStepStatus(step, {
      id: 'late-log',
      status: 'running',
      message: '任务完成: port_scan'
    })

    expect(step.status).toBe('completed')
    expect(step.logs).toHaveLength(1)
  })

  it('normalizes execute_task logs to the matching tool step', () => {
    expect(normalizeRunLogPayload({
      node: 'execute_task',
      message: '任务开始: port_scan, 目标=https://example.com'
    })).toMatchObject({ tool: 'port_scan', step_id: 'tool:port_scan' })
  })

  it('keeps only the active sequential tool in running state', () => {
    const run = {
      steps: [
        { stepId: 'tool:first', status: 'running' },
        { stepId: 'tool:second', status: 'running' },
        { stepId: 'decision:next', status: 'completed' }
      ]
    }

    settleOtherRunningToolSteps(run, 'tool:second')

    expect(run.steps.map(step => step.status)).toEqual(['completed', 'running', 'completed'])
  })

  it('merges a restored legacy execute_task node into its tool node', () => {
    const run = {
      steps: [{
        stepId: 'workflow:execute_task',
        title: 'execute_task',
        status: 'running',
        logs: [{ id: 'legacy', message: '任务完成: port_scan', timestamp: '2026-08-13T00:00:00' }]
      }]
    }

    removeLegacyExecuteTaskSteps(run)

    expect(run.steps).toHaveLength(1)
    expect(run.steps[0]).toMatchObject({ stepId: 'tool:port_scan', title: 'port_scan', status: 'pending' })
    expect(run.steps[0].logs).toHaveLength(1)
  })
})
