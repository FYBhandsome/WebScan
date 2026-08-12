import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import AgentRunTimeline from './AgentRunTimeline.vue'

describe('AgentRunTimeline script category field', () => {
  it('renders object options with stable values and emits the selected category', async () => {
    const interaction = {
      type: 'input',
      fields: [{
        field: 'tool_category',
        label: '脚本类型',
        required: true,
        options: [
          { value: 'info_collection', label: '信息收集工具' },
          { value: 'vuln_scan', label: '漏洞扫描工具' }
        ],
        value: 'info_collection'
      }],
      resolved: false
    }
    const wrapper = mount(AgentRunTimeline, {
      props: {
        run: {
          status: 'waiting',
          steps: [{ stepId: 'script-form', status: 'waiting', interaction }]
        }
      }
    })

    const select = wrapper.get('select')
    expect(select.findAll('option').map(option => option.text())).toContain('漏洞扫描工具')
    await select.setValue('vuln_scan')
    await wrapper.get('button').trigger('click')

    const emittedFields = wrapper.emitted('submit-input')[0][1]
    expect(emittedFields[0].value).toBe('vuln_scan')
  })
})
