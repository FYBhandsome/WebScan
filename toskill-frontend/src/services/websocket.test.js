import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

class MockWebSocket {
  static CONNECTING = 0
  static OPEN = 1
  static CLOSING = 2
  static CLOSED = 3
  static instances = []

  constructor(url) {
    this.url = url
    this.readyState = MockWebSocket.CONNECTING
    this.send = vi.fn()
    this.close = vi.fn((code = 1000, reason = '') => {
      this.readyState = MockWebSocket.CLOSED
      this.onclose?.({ code, reason })
    })
    MockWebSocket.instances.push(this)
  }

  open() {
    this.readyState = MockWebSocket.OPEN
    this.onopen?.()
  }

  receive(data) {
    this.onmessage?.({ data: JSON.stringify(data) })
  }
}

describe('WSManager heartbeat', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(0)
    vi.resetModules()
    MockWebSocket.instances = []
    globalThis.WebSocket = MockWebSocket
    localStorage.clear()
  })

  afterEach(() => {
    vi.useRealTimers()
    delete globalThis.WebSocket
  })

  it('sends ping messages while a long scan is otherwise idle', async () => {
    const { ws } = await import('./websocket.js')
    ws.heartbeatInterval = 1000
    ws.heartbeatStaleAfter = 3000

    const connected = ws.connect()
    const socket = MockWebSocket.instances[0]
    socket.open()
    socket.receive({ type: 'connected', payload: { session_id: 'session-1' } })
    await connected

    vi.advanceTimersByTime(1000)

    expect(socket.send).toHaveBeenCalledWith(JSON.stringify({
      type: 'ping',
      payload: { timestamp: 1000 },
    }))
    ws.disconnect()
  })

  it('closes a stale socket so the existing reconnect flow can recover', async () => {
    const { ws } = await import('./websocket.js')
    ws.heartbeatInterval = 1000
    ws.heartbeatStaleAfter = 2500

    const connected = ws.connect()
    const socket = MockWebSocket.instances[0]
    socket.open()
    socket.receive({ type: 'connected', payload: { session_id: 'session-1' } })
    await connected

    vi.advanceTimersByTime(3000)

    expect(socket.close).toHaveBeenCalledWith(4000, 'Heartbeat timeout')
    ws.disconnect()
  })
})
