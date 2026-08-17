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

  it('returns locally generated scripts to the backend workflow that requested them', () => {
    expect(source).toContain('const workflowManaged = request.workflow_managed === true || block.workflowManaged === true')
    expect(source).toContain('if (interaction.workflowManaged) {')
    expect(source).toContain("ws.send('script_description', {")
    expect(source).toContain('interaction_id: interaction.workflowInteractionId')
    expect(source).toContain("script_action: action")
    expect(source).toContain("script_action: 'discard'")
    expect(source).toContain('registered_tool_name: registeredName')
    expect(source).toContain('workflow_managed: true')
  })

  it('keeps the fixed local template for standalone generation', () => {
    expect(source).toContain("generateLocalScript({\n          placement: 'console'")
  })

  it('does not reopen or expire an interaction that the user already submitted', () => {
    expect(source).toContain('interaction.submitted = true')
    expect(source).toContain('const submittedState = existing.submitted === true || Boolean(existing.selectedChoice)')
    expect(source).toContain('if (interaction.submitted || interaction.selectedChoice)')
    expect(source).toContain("interaction.resolutionMessage === '该交互已过期'")
  })

  it('records generated scripts for the custom tools view', () => {
    expect(source).toContain("focusCustomTool(registeredName, interaction.scriptCategory || 'info_collection')")
    expect(source).toContain('已保存到自定义工具')
  })
})
