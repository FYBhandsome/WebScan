import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const tools = [
  { name: 'port_scan', description: '端口扫描', category: 'info_collection', source: 'system', creation_method: 'builtin' },
  { name: 'custom_assets', description: '资产收集', category: 'info_collection', source: 'custom', creation_method: 'upload', created_at: '2026-08-12T00:00:00' },
  { name: 'sqli_scan', description: 'SQL注入检测', category: 'vuln_scan', source: 'system', creation_method: 'builtin' },
]

const apiMock = vi.hoisted(() => ({
  getTools: vi.fn(),
  registerCustomTool: vi.fn(),
  deleteCustomTool: vi.fn(),
  executeTool: vi.fn(),
}))

const wsMock = vi.hoisted(() => ({
  handlers: new Map(),
  isConnected: vi.fn(() => true),
  connect: vi.fn(),
  send: vi.fn(() => true),
  on: vi.fn((type, handler) => wsMock.handlers.set(type, handler)),
  off: vi.fn((type) => wsMock.handlers.delete(type)),
}))

vi.mock('../../services/api.js', () => ({ API: apiMock }))
vi.mock('../../services/websocket.js', () => ({ ws: wsMock }))
vi.mock('../../store.js', () => ({ showToast: vi.fn() }))

import ToolsView from './ToolsView.vue'

const mountView = async () => {
  const wrapper = mount(ToolsView, { attachTo: document.body })
  await flushPromises()
  return wrapper
}

describe('ToolsView', () => {
  beforeEach(() => {
    apiMock.getTools.mockReset().mockResolvedValue({ data: { tools } })
    apiMock.registerCustomTool.mockReset()
    apiMock.deleteCustomTool.mockReset().mockResolvedValue({ data: {} })
    wsMock.handlers.clear()
    wsMock.send.mockClear()
    vi.spyOn(window, 'confirm').mockReturnValue(true)
  })

  it('uses category and source as two independent filters', async () => {
    const wrapper = await mountView()
    expect(wrapper.text()).toContain('Port Scan')
    expect(wrapper.text()).not.toContain('Custom Assets')

    await wrapper.get('.source-filter button:nth-child(2)').trigger('click')
    expect(wrapper.text()).toContain('Custom Assets')
    expect(wrapper.text()).not.toContain('Port Scan')

    await wrapper.get('.primary-filter button:nth-child(2)').trigger('click')
    expect(wrapper.text()).toContain('暂无自定义工具')
    wrapper.unmount()
  })

  it('registers an uploaded tool through the canonical REST endpoint', async () => {
    apiMock.registerCustomTool.mockResolvedValue({
      data: { tool: { name: 'custom_probe', category: 'vuln_scan', source: 'custom' } }
    })
    const wrapper = await mountView()
    await wrapper.get('.create-tool-btn').trigger('click')
    await wrapper.get('.tool-type-picker button:nth-child(3)').trigger('click')
    await wrapper.get('.option-card:first-child').trigger('click')
    const inputs = wrapper.findAll('.new-tool-form input')
    await inputs[0].setValue('custom_probe')
    await wrapper.get('.script-editor').setValue(
      "def run(target):\n    return {'success': True, 'data': {}, 'error': None}"
    )
    await wrapper.get('.new-tool-form .primary-btn').trigger('click')
    await flushPromises()

    expect(apiMock.registerCustomTool).toHaveBeenCalledWith(expect.objectContaining({
      tool_name: 'custom_probe',
      category: 'vuln_scan',
      creation_method: 'upload',
      include_in_default_scan: false,
    }))
    wrapper.unmount()
  })

  it('keeps generated code as preview until explicit confirmation', async () => {
    apiMock.registerCustomTool.mockResolvedValue({
      data: { tool: { name: 'ai_probe', category: 'info_collection', source: 'custom' } }
    })
    const wrapper = await mountView()
    await wrapper.get('.create-tool-btn').trigger('click')
    await wrapper.get('.option-card:nth-child(2)').trigger('click')
    await wrapper.get('.desc-input').setValue('收集页面标题')
    await wrapper.get('.new-tool-form > .form-actions .primary-btn').trigger('click')

    expect(wsMock.send).toHaveBeenCalledWith('script_description', expect.objectContaining({
      preview_only: true,
      tool_category: 'info_collection',
    }))
    expect(apiMock.registerCustomTool).not.toHaveBeenCalled()

    wsMock.handlers.get('script_generated')({
      tool_name: 'ai_probe',
      script_code: "def run(target):\n    return {'success': True, 'data': {}}",
      description: '收集页面标题',
    })
    await wrapper.vm.$nextTick()
    await wrapper.get('.generated-preview .primary-btn').trigger('click')
    await flushPromises()
    expect(apiMock.registerCustomTool).toHaveBeenCalledTimes(1)
    expect(apiMock.registerCustomTool).toHaveBeenCalledWith(expect.objectContaining({
      creation_method: 'ai_generate',
    }))
    wrapper.unmount()
  })
})
