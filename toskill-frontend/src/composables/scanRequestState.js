const TERMINAL_SCAN_STATUSES = new Set(['completed', 'idle', 'error'])

export const createScanConfirmationIdentity = (requestId) => ({
  requestId,
  interactionId: `scan-confirm:${requestId}`,
  localRunId: `scan:${requestId}`,
  stepId: `scan-setup:${requestId}`,
})

export const shouldRouteWaitingInputToInteraction = (waitingForChoice, scanStatus) => (
  Boolean(waitingForChoice) && !TERMINAL_SCAN_STATUSES.has(scanStatus)
)
