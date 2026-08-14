import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'

import AppHeader from './AppHeader.vue'

const mountHeader = (scanStatus, total = 15) => mount(AppHeader, {
  props: {
    showScanProgress: true,
    scanStatus,
    scanProgress: { current: 0, total, activeTool: '' }
  }
})

describe('AppHeader scan progress', () => {
  it('does not show a tool-library total for an idle session', () => {
    const wrapper = mountHeader('idle')

    expect(wrapper.find('.header-scan-progress').exists()).toBe(false)
    expect(wrapper.text()).not.toContain('0 / 15')
  })

  it('shows progress after a scan enters its lifecycle', () => {
    const wrapper = mountHeader('scanning')

    expect(wrapper.find('.header-scan-progress').exists()).toBe(true)
    expect(wrapper.text()).toContain('0 / 15')
  })
})
