import assert from 'node:assert/strict'
import test from 'node:test'

import {
  createScanConfirmationIdentity,
  shouldRouteWaitingInputToInteraction,
} from './scanRequestState.js'

test('repeated scans receive different confirmation and local run identities', () => {
  const first = createScanConfirmationIdentity('first-request')
  const second = createScanConfirmationIdentity('second-request')

  assert.notEqual(first.interactionId, second.interactionId)
  assert.notEqual(first.localRunId, second.localRunId)
  assert.notEqual(first.stepId, second.stepId)
})

test('a stale waiting flag does not intercept input after completion', () => {
  assert.equal(shouldRouteWaitingInputToInteraction(true, 'completed'), false)
  assert.equal(shouldRouteWaitingInputToInteraction(true, 'waiting'), true)
})
