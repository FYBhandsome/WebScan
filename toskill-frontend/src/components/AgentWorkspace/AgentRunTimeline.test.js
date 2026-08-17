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

  it('renders a consistent SVG check for completed steps', () => {
    const wrapper = mount(AgentRunTimeline, {
      props: {
        run: {
          status: 'running',
          steps: [
            { stepId: 'tool:done', title: 'done', status: 'completed' },
            { stepId: 'tool:active', title: 'active', status: 'running' }
          ]
        }
      }
    })

    const completedDot = wrapper.get('[data-step-id="tool:done"] .step-dot')
    expect(completedDot.find('svg.step-check-icon').exists()).toBe(true)
    expect(completedDot.text()).not.toContain('✓')
    expect(wrapper.findAll('.step-dot.status-running')).toHaveLength(1)
  })

  it('renders not-applicable collection results without a failure symbol', () => {
    const wrapper = mount(AgentRunTimeline, {
      props: {
        run: {
          status: 'completed',
          steps: [{
            stepId: 'tool:ip_locate_scan',
            title: 'ip_locate_scan',
            status: 'not_applicable',
            message: '本地地址不提供公网地理归属信息'
          }]
        }
      }
    })

    const step = wrapper.get('[data-step-id="tool:ip_locate_scan"]')
    expect(step.text()).toContain('不适用')
    expect(step.get('.step-dot').text()).toBe('−')
    expect(step.text()).not.toContain('失败')
    expect(step.text()).not.toContain('×')
  })
})
