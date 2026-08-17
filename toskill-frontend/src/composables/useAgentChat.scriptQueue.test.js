import { readFile } from 'node:fs/promises'
import { describe, expect, it } from 'vitest'

const source = await readFile('src/composables/useAgentChat.js', 'utf8')

describe('generated-script queue lifecycle', () => {
  it('does not turn local queue exhaustion into a report-complete message', () => {
    expect(source).not.toContain('所有脚本执行完毕')
    expect(source).toContain('本地脚本队列已执行完毕。未生成扫描报告。')
    expect(source).toContain('本地脚本队列已处理完毕，扫描工作流仍在继续。')
    expect(source).toContain('const hasActiveBackendWorkflow = () =>')
    expect(source).toContain('const scriptLoopResumeState = ref(null)')
  })

  it('keeps the tool that requested generation pending after the generated script', () => {
    expect(source).toContain('scriptQueue.value.splice(currentScriptIndex.value, 0, queuedScript)')
    expect(source).toContain('scriptQueue.value.splice(currentScriptIndex.value, 0, { tool_name: genToolName, status: \'pending\', target })')

    const continueAfterGeneratedScript = source.match(
      /const continueAfterGeneratedScript = \(\) => \{([\s\S]*?)\n  \}/
    )?.[1] || ''
    expect(continueAfterGeneratedScript).not.toContain('currentScriptIndex.value++')
  })

  it('accepts the backend workflow-completed event as a real completion signal', () => {
    expect(source).toMatch(/case 'workflow_completed':\s*\n\s*case 'scan_completed':/)
  })

  it('uses the fixed local template even when the form originated from the backend workflow', () => {
    expect(source).not.toContain('workflowManaged: Boolean(request.interaction_id)')
    expect(source).not.toContain("ws.send('script_description', {")
    expect(source).toContain("generateLocalScript({\n          placement: 'console'")
    expect(source).toContain('never use it\n      // to send the prompt back to the server for an ai_gen_* script')
  })
})
