import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const appSource = await readFile(new URL('./App.vue', import.meta.url), 'utf8')

test('sidebar navigation keeps ConsoleView mounted', () => {
  assert.match(appSource, /<ConsoleView[\s\S]*?v-show="currentPage === 'console'"[\s\S]*?\/>/)
  assert.doesNotMatch(appSource, /<ConsoleView\s+v-if="currentPage === 'console'"\s*\/>/)
})

test('console report link navigates to the report page', () => {
  assert.match(appSource, /@open-report="openReportPage"/)
  assert.match(appSource, /:initial-report-filename="selectedReportFilename"/)
})
