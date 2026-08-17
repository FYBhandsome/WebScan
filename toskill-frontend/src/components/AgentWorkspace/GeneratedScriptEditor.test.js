import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import GeneratedScriptEditor from './GeneratedScriptEditor.vue'

const interaction = () => ({
  description: '已根据当前需求生成本地信息收集脚本。',
  scriptName: 'console_http_headers_test',
  scriptCategory: 'info_collection',
  scriptCode: "def run(target: str):\n    return {'success': True}",
  isRegistering: false,
  error: ''
})

describe('GeneratedScriptEditor', () => {
  it('keeps generated script fields editable and requests queueing', async () => {
    const current = interaction()
    const wrapper = mount(GeneratedScriptEditor, { props: { interaction: current } })

    await wrapper.get('input').setValue('editable_script')
    await wrapper.get('select').setValue('vuln_scan')
    await wrapper.get('.code-editor').setValue("def run(target: str):\n    return {'success': False}")
    await wrapper.get('.editor-button.primary').trigger('click')

    expect(current.scriptName).toBe('editable_script')
    expect(current.scriptCategory).toBe('vuln_scan')
    expect(current.scriptCode).toContain("'success': False")
    expect(wrapper.emitted('action')[0]).toEqual(['queue', '加入本次扫描队列'])
  })
})
