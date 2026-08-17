import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { generateLocalScript } from '../../utils/localScriptGenerator.js'

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

const storeMock = vi.hoisted(() => ({
  showToast: vi.fn(),
  consumeCustomToolFocus: vi.fn(() => null),
}))

vi.mock('../../services/api.js', () => ({ API: apiMock }))
vi.mock('../../services/websocket.js', () => ({ ws: wsMock }))
vi.mock('../../store.js', () => storeMock)

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
    apiMock.executeTool.mockReset()
    wsMock.handlers.clear()
    wsMock.send.mockClear()
    storeMock.consumeCustomToolFocus.mockReset().mockReturnValue(null)
    vi.spyOn(window, 'confirm').mockReturnValue(true)
  })

  it('uses category and source as two independent filters', async () => {
    const wrapper = await mountView()
    expect(wrapper.text()).toContain('Port Scan')
    expect(wrapper.text()).not.toContain('Custom Assets')

    await wrapper.get('.source-switch button:nth-child(2)').trigger('click')
    expect(wrapper.text()).toContain('Custom Assets')
    expect(wrapper.text()).not.toContain('Port Scan')

    await wrapper.get('.primary-filter button:nth-child(2)').trigger('click')
    expect(wrapper.text()).toContain('暂无自定义工具')
    wrapper.unmount()
  })

  it('opens the category custom list for a tool registered from the console', async () => {
    storeMock.consumeCustomToolFocus.mockReturnValue({
      name: 'technology_fingerprint',
      category: 'vuln_scan',
    })
    apiMock.getTools.mockResolvedValue({
      data: {
        tools: [
          ...tools,
          {
            name: 'technology_fingerprint',
            description: '技术指纹识别',
            category: 'vuln_scan',
            source: 'custom',
            creation_method: 'ai_generate',
          },
        ],
      },
    })

    const wrapper = await mountView()

    expect(wrapper.get('.primary-filter button:nth-child(2)').classes()).toContain('active')
    expect(wrapper.get('.source-switch button:nth-child(2)').classes()).toContain('active')
    expect(wrapper.text()).toContain('Technology Fingerprint')
    wrapper.unmount()
  })

  it('shows the global custom count and switches to the category that contains custom tools', async () => {
    apiMock.getTools.mockResolvedValue({
      data: {
        tools: [
          ...tools.filter(tool => tool.source === 'system'),
          {
            name: 'technology_fingerprint',
            description: '技术指纹识别',
            category: 'vuln_scan',
            source: 'custom',
            creation_method: 'ai_generate',
          },
        ],
      },
    })
    const wrapper = await mountView()
    const customButton = wrapper.get('.source-switch button:nth-child(2)')

    expect(customButton.text()).toContain('1')
    await customButton.trigger('click')

    expect(wrapper.get('.primary-filter button:nth-child(2)').classes()).toContain('active')
    expect(wrapper.text()).toContain('Technology Fingerprint')
    wrapper.unmount()
  })

  it('registers an uploaded tool through the canonical REST endpoint', async () => {
    apiMock.registerCustomTool.mockResolvedValue({
      data: { tool: { name: 'custom_probe', category: 'vuln_scan', source: 'custom' } }
    })
    const wrapper = await mountView()
    await wrapper.get('.create-tool-btn').trigger('click')
    await wrapper.get('.tool-type-picker button:nth-child(2)').trigger('click')
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

  it('generates a local preview without using WebSocket until explicit confirmation', async () => {
    apiMock.registerCustomTool.mockResolvedValue({
      data: { tool: { name: 'ai_probe', category: 'info_collection', source: 'custom' } }
    })
    const wrapper = await mountView()
    await wrapper.get('.create-tool-btn').trigger('click')
    await wrapper.get('.option-card:nth-child(2)').trigger('click')
    await wrapper.get('.desc-input').setValue('收集页面标题')
    await wrapper.get('.new-tool-form > .form-actions .primary-btn').trigger('click')

    expect(wrapper.get('.generated-script-preview').exists()).toBe(true)
    expect(wrapper.text()).not.toContain('功能描述')
    expect(wrapper.get('.generated-code-editor').element.value).toContain('def run(target: str)')
    expect(wsMock.send).not.toHaveBeenCalled()
    expect(apiMock.registerCustomTool).not.toHaveBeenCalled()

    await wrapper.get('.generated-preview-actions .primary-btn').trigger('click')
    await flushPromises()
    expect(apiMock.registerCustomTool).toHaveBeenCalledTimes(1)
    expect(apiMock.registerCustomTool).toHaveBeenCalledWith(expect.objectContaining({
      creation_method: 'ai_generate',
    }))
    wrapper.unmount()
  })

  it('uses distinct safe templates for console and tools generation', () => {
    const consoleScript = generateLocalScript({ placement: 'console', description: '收集响应头' })
    const toolsScript = generateLocalScript({ placement: 'tools', description: '收集页面标题' })

    expect(consoleScript.scriptCode).not.toBe(toolsScript.scriptCode)
    expect(consoleScript.toolName).toBe('technology_fingerprint')
    expect(toolsScript.toolName).toBe('page_metadata_summary')
    expect(consoleScript.description).toBe('识别目标页面暴露的服务端与前端技术特征。')
    expect(toolsScript.description).toBe('快速采集页面标题、描述、链接数量和表单数量。')
    for (const script of [consoleScript.scriptCode, toolsScript.scriptCode]) {
      expect(script).toContain('def run(target: str)')
      expect(script).toContain('return {')
      expect(script).not.toContain('import os')
      expect(script).not.toContain('import subprocess')
      expect(script).not.toContain('eval(')
      expect(script).not.toContain('exec(')
    }
  })

  it('shows collected fields instead of vulnerability analysis for information tools', async () => {
    apiMock.executeTool.mockResolvedValue({
      data: {
        tool_name: 'port_scan',
        tool_category: 'info_collection',
        target: 'example.test',
        timestamp: '2026-08-13T00:00:00',
        information_summary: [{ label: '开放端口', value: '80、443' }],
        analysis: { summary: '未发现任何漏洞', analysis: '未发现漏洞' }
      }
    })
    const wrapper = await mountView()
    await wrapper.get('.tool-card').trigger('click')
    await wrapper.get('#toolTarget').setValue('example.test')
    await wrapper.get('#executeToolBtn').trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('收集结果')
    expect(wrapper.text()).toContain('执行完成')
    expect(wrapper.get('.execution-status .status-line').text()).toContain('执行完成 · 已收集 1 项信息')
    expect(wrapper.text()).not.toContain('收集到的信息')
    expect(wrapper.text()).toContain('开放端口')
    expect(wrapper.text()).toContain('80、443')
    expect(wrapper.text()).not.toContain('未发现漏洞')
    wrapper.unmount()
  })

  it('renders base information as readable groups instead of transport fields', async () => {
    apiMock.getTools.mockResolvedValue({
      data: {
        tools: [{
          name: 'baseinfo_scan',
          description: '基础信息收集',
          category: 'info_collection',
          source: 'system',
          creation_method: 'builtin',
        }],
      },
    })
    apiMock.executeTool.mockResolvedValue({
      data: {
        tool_name: 'baseinfo_scan',
        tool_category: 'info_collection',
        target: 'http://testasp.vulnweb.com',
        timestamp: '2026-08-17T10:27:05',
        information_summary: [
          { label: 'success', value: '是' },
          { label: 'data', value: 'code: 200; msg: 查询成功' },
          { label: 'metadata', value: 'tool: baseinfo' },
        ],
        result: {
          success: true,
          data: {
            success: true,
            data: {
              code: 200,
              msg: '查询成功',
              domain: 'testasp.vulnweb.com',
              server: 'Microsoft-IIS/8.5',
              language: 'ASP.NET',
              ip: ['44.238.29.244 (物理地址: United States, Oregon, Portland, Amazon.com)  '],
              os: 'Windows Server',
              register: 'http://whois.chinaz.com/testasp.vulnweb.com',
            },
            metadata: { tool: 'baseinfo' },
          },
        },
      },
    })
    const wrapper = await mountView()
    await wrapper.get('.tool-card').trigger('click')
    await wrapper.get('#toolTarget').setValue('http://testasp.vulnweb.com')
    await wrapper.get('#executeToolBtn').trigger('click')
    await flushPromises()

    expect(wrapper.get('.execution-status .status-line').text()).toContain('执行完成 · 已收集 8 项基础信息')
    expect(wrapper.text()).toContain('服务与响应')
    expect(wrapper.text()).toContain('网站可正常访问（HTTP 200）')
    expect(wrapper.text()).toContain('网站技术')
    expect(wrapper.text()).toContain('IP 归属信息')
    expect(wrapper.text()).toContain('注册信息查询入口')
    expect(wrapper.text()).not.toContain('metadata')
    expect(wrapper.text()).not.toContain('查询成功')
    wrapper.unmount()
  })
})
