import { readFile } from 'node:fs/promises'
import { describe, expect, it } from 'vitest'

const source = await readFile('src/composables/useAgentChat.js', 'utf8')

describe('workflow decision timeline', () => {
  it('anchors each decision card by its interaction ID', () => {
    expect(source).toMatch(/stepId:\s*`decision:\$\{interactionId\}`/)
    expect(source).not.toMatch(/stepId:\s*`decision:\$\{data\.payload\?\.next_task \|\| interactionId\}`/)
  })
})
