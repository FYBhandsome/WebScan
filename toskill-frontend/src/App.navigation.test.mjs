import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const appSource = await readFile(new URL('./App.vue', import.meta.url), 'utf8')
const agentChatSource = await readFile(new URL('./composables/useAgentChat.js', import.meta.url), 'utf8')
const timelineSource = await readFile(new URL('./components/AgentWorkspace/AgentRunTimeline.vue', import.meta.url), 'utf8')
const reportsViewSource = await readFile(new URL('./components/views/ReportsView.vue', import.meta.url), 'utf8')

test('sidebar navigation keeps ConsoleView mounted', () => {
  assert.match(appSource, /<ConsoleView[\s\S]*?v-show="currentPage === 'console'"[\s\S]*?\/>/)
  assert.doesNotMatch(appSource, /<ConsoleView\s+v-if="currentPage === 'console'"\s*\/>/)
})

test('console report link navigates to the report page', () => {
  assert.match(appSource, /@open-report="openReportPage"/)
  assert.match(appSource, /:initial-report-filename="selectedReportFilename"/)
})

test('console report completion exposes both saved report formats', () => {
  assert.match(agentChatSource, /label: '查看 HTML 报告', url: htmlReportUrl/)
  assert.match(agentChatSource, /label: '查看 Markdown 报告', url: reportUrl/)
  assert.match(agentChatSource, /reportLinks: createReportLinks\(reportUrl, htmlReportUrl\)/)
  assert.match(timelineSource, /v-for="reportLink in step\.reportLinks \|\| \(step\.reportLink \? \[step\.reportLink\] : \[\]\)"/)
})

test('console scan summary is rendered as Markdown', () => {
  assert.match(timelineSource, /v-html="renderMarkdown\(run\.summary\)"/)
  assert.match(timelineSource, /marked\.parse\(text \|\| '', \{ breaks: true, gfm: true \}\)/)
})

test('HTML report iframe uses an unobtrusive scrolling state', () => {
  assert.match(reportsViewSource, /FRAME_SCROLL_ACTIVE_DURATION = 650/)
  assert.match(reportsViewSource, /html\.is-scrolling::\-webkit-scrollbar-thumb/)
  assert.match(reportsViewSource, /frameDocument\.addEventListener\('scroll', markScrolling/)
})
