// src/services/websocket.js
import { API } from './api.js';

const isDev = import.meta.env.DEV;
const LOG = {
    log: (...args) => isDev && console.log(...args),
    error: (...args) => isDev && console.error(...args),
    warn: (...args) => isDev && console.warn(...args),
};

const SESSION_KEY = 'toskill_ws_session_id';
const MAX_OFFLINE_QUEUE = 200;
const QUEUEABLE_TYPES = new Set(['chat', 'scan_chat', 'get_history', 'get_status', 'subscribe']);
const CRITICAL_CONTROL_TYPES = new Set([
    'start_scan',
    'stop_scan',
    'user_choice',
    'tool_confirmed',
    'tool_rejected',
    'alternative_selected',
    'decision_override',
    'execute_tool',
    'script_content',
    'script_description',
    'input_response',
    'interaction_chat',
]);

class WSManager {
    constructor() {
        this.url = '';
        this.ws = null;
        this.connected = false;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 10;
        this.reconnectDelay = 1000;
        this.maxReconnectDelay = 30000;
        this.reconnectTimer = null;
        this.connectResolve = null;
        this.connectReject = null;
        this.messageHandlers = new Map();
        this.onConnectCallback = null;
        this.onDisconnectCallback = null;
        this.onErrorCallback = null;
        this.onReconnectCallback = null;
        this.onReconnectFailedCallback = null;
        this.sessionId = null;
        this._firstConnect = true;
        this._shouldReconnect = true;
        this._offlineQueue = [];

        this._restoreSession();
    }

    _restoreSession() {
        try {
            const saved = sessionStorage.getItem(SESSION_KEY);
            if (saved) {
                this.sessionId = saved;
                LOG.log('Restored session_id from sessionStorage:', saved);
            }
        } catch (e) {
            LOG.warn('Failed to restore session:', e);
        }
    }

    _saveSession() {
        try {
            if (this.sessionId) {
                sessionStorage.setItem(SESSION_KEY, this.sessionId);
            } else {
                sessionStorage.removeItem(SESSION_KEY);
            }
        } catch (e) {
            LOG.warn('Failed to save session:', e);
        }
    }

    setUrl(url) {
        this.url = url;
    }

    _buildConnectUrl() {
        const rawUrl = this.url || API.getWebSocketUrl();
        const baseUrl = rawUrl.includes(API.WS_PATH)
            ? rawUrl
            : rawUrl.replace(/\/$/, '') + API.WS_PATH;

        if (this.sessionId && !this._firstConnect) {
            const sep = baseUrl.includes('?') ? '&' : '?';
            return `${baseUrl}${sep}session_id=${encodeURIComponent(this.sessionId)}`;
        }
        return baseUrl;
    }

    /* Heartbeats intentionally removed; WebSocket close/error events drive reconnects. */
    _startHeartbeat() {
        return;
    }
    _stopHeartbeat() {
        return;
    }

    _flushOfflineQueue() {
        if (this._offlineQueue.length === 0) return;
        const queue = [...this._offlineQueue];
        this._offlineQueue = [];
        let flushed = 0;
        for (const msg of queue) {
            if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                try {
                    this.ws.send(JSON.stringify(msg));
                    flushed++;
                } catch (e) {
                    LOG.error('Failed to flush message:', e);
                    this._offlineQueue.unshift(msg, ...queue.slice(flushed + 1));
                    break;
                }
            } else {
                this._offlineQueue.unshift(msg, ...queue.slice(flushed + 1));
                break;
            }
        }
        if (flushed > 0) {
            LOG.log(`Flushed ${flushed} offline messages`);
        }
    }

    _notifyError(error, context = {}) {
        if (this.onErrorCallback) {
            this.onErrorCallback(error, context);
        }
    }

    connect() {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            return Promise.resolve(this.sessionId);
        }

        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }

        if (this.connectResolve) {
            return new Promise((resolve) => {
                const check = setInterval(() => {
                    if (this.connected) {
                        clearInterval(check);
                        resolve(this.sessionId);
                    }
                }, 100);
            });
        }

        return new Promise((resolve, reject) => {
            this.connectResolve = resolve;
            this.connectReject = reject;

            try {
                const targetUrl = this._buildConnectUrl();
                LOG.log('Connecting to:', targetUrl);
                this.ws = new WebSocket(targetUrl);

                this.ws.onopen = () => {
                    LOG.log('WebSocket connected');
                    this.connected = true;
                    this.reconnectAttempts = 0;
                    this._shouldReconnect = true;


                    if (this.onConnectCallback) {
                        this.onConnectCallback();
                    }

                    if (!this._firstConnect && this.sessionId && this.onReconnectCallback) {
                        this.onReconnectCallback(this.sessionId);
                        this.sendGetStatus();
                    }
                    this._firstConnect = false;

                    this._flushOfflineQueue();
                };

                this.ws.onmessage = (event) => {
                    try {
                        const data = JSON.parse(event.data);
                        if (!data || typeof data !== 'object') {
                            throw new Error('WebSocket message must be a JSON object');
                        }

                        this.handleMessage(data);

                        if (data.type === 'connected' && data.payload?.session_id) {
                            this.sessionId = data.payload.session_id;
                            this._saveSession();
                            if (this.connectResolve) {
                                this.connectResolve(this.sessionId);
                                this.connectResolve = null;
                                this.connectReject = null;
                            }
                        }
                    } catch (error) {
                        LOG.error('Failed to parse WebSocket message:', error);
                        this.handleMessage({
                            type: 'client_message_error',
                            payload: {
                                message: '收到无法解析的 WebSocket 消息，已忽略该消息。',
                                raw: String(event.data || '').slice(0, 500),
                                error: error.message,
                            },
                        });
                    }
                };

                this.ws.onclose = (event) => {
                    LOG.log('WebSocket closed:', event.code, event.reason);
                    this.connected = false;
                    this._stopHeartbeat();

                    if (this.onDisconnectCallback) {
                        this.onDisconnectCallback(event);
                    }

                    const canReconnect = this._shouldReconnect && ![1000, 1008].includes(event.code);
                    if (canReconnect && this.reconnectAttempts < this.maxReconnectAttempts) {
                        const baseDelay = Math.min(
                            this.reconnectDelay * Math.pow(2, this.reconnectAttempts),
                            this.maxReconnectDelay
                        );
                        const delay = baseDelay * (0.5 + Math.random() * 0.5);
                        this.reconnectAttempts++;
                        LOG.log(`Reconnecting... Attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts} in ${Math.round(delay)}ms`);
                        this.reconnectTimer = setTimeout(() => {
                            this.reconnectTimer = null;
                            this.connect();
                        }, delay);
                    } else {
                        LOG.log('Max reconnect attempts reached');
                        this.cleanupConnectPromise(new Error('Max reconnect attempts reached'));
                        if (this.onReconnectFailedCallback) {
                            this.onReconnectFailedCallback(event);
                        }
                    }
                };

                this.ws.onerror = (error) => {
                    LOG.error('WebSocket error:', error);
                    this._notifyError(error, { url: this._buildConnectUrl(), attempts: this.reconnectAttempts });
                };

            } catch (error) {
                this.cleanupConnectPromise(error);
            }
        });
    }

    cleanupConnectPromise(error) {
        if (this.connectReject) {
            this.connectReject(error);
            this.connectResolve = null;
            this.connectReject = null;
        }
    }

    disconnect() {
        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }
        this._shouldReconnect = false;
        this._offlineQueue = [];
        this.cleanupConnectPromise(new Error('Disconnected'));
        if (this.ws) {
            this.ws.close();
            this.ws = null;
            this.connected = false;
        }
        this.sessionId = null;
        this._saveSession();
    }

    send(type, payload = {}) {
        const message = { type, payload };

        if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
            if (this._shouldReconnect && QUEUEABLE_TYPES.has(type)) {
                this._offlineQueue.push(message);
                if (this._offlineQueue.length > MAX_OFFLINE_QUEUE) {
                    this._offlineQueue = this._offlineQueue.slice(-MAX_OFFLINE_QUEUE);
                }
                LOG.warn(`WebSocket offline, queued message: ${type}`);
            } else if (CRITICAL_CONTROL_TYPES.has(type)) {
                this._notifyError(new Error(`WebSocket 未连接，控制消息 ${type} 未发送。`), {
                    type,
                    critical: true,
                });
            }
            return false;
        }
        try {
            this.ws.send(JSON.stringify(message));
            return true;
        } catch (error) {
            this._notifyError(error, { type, critical: CRITICAL_CONTROL_TYPES.has(type) });
            return false;
        }
    }

    handleMessage(data) {
        const type = data?.type || 'unknown';
        const payload = data && typeof data.payload === 'object' && data.payload !== null ? data.payload : {};
        const normalized = { ...data, type, payload };
        const handlers = this.messageHandlers.get(type) || [];
        handlers.forEach(handler => {
            try {
                handler(payload, normalized);
            } catch (error) {
                LOG.error(`WebSocket handler failed for ${type}:`, error);
            }
        });

        const allHandlers = this.messageHandlers.get('*') || [];
        allHandlers.forEach(handler => {
            try {
                handler(normalized);
            } catch (error) {
                LOG.error('WebSocket wildcard handler failed:', error);
            }
        });
    }

    on(messageType, callback) {
        if (!this.messageHandlers.has(messageType)) {
            this.messageHandlers.set(messageType, []);
        }
        this.messageHandlers.get(messageType).push(callback);
    }

    off(messageType, callback) {
        if (!this.messageHandlers.has(messageType)) return;
        const handlers = this.messageHandlers.get(messageType);
        const index = handlers.indexOf(callback);
        if (index !== -1) {
            handlers.splice(index, 1);
        }
    }

    onConnect(callback) { this.onConnectCallback = callback; }
    onDisconnect(callback) { this.onDisconnectCallback = callback; }
    onError(callback) { this.onErrorCallback = callback; }
    onReconnectFailed(callback) { this.onReconnectFailedCallback = callback; }
    onReconnect(callback) { this.onReconnectCallback = callback; }
    isConnected() { return this.connected && this.ws && this.ws.readyState === WebSocket.OPEN; }
    getSessionId() { return this.sessionId; }

    startScan(target, scanMode = 'info', params = {}) {
        const intentParams = typeof API.consumeIntentParams === 'function'
            ? API.consumeIntentParams()
            : {};
        const payload = {
            target,
            scan_mode: scanMode,
            params: { ...intentParams, ...(params || {}) },
        };
        console.log('[WS] startScan 发送:', { type: 'start_scan', payload });
        const result = this.send('start_scan', payload);
        console.log('[WS] startScan 发送结果:', result);
        return result;
    }
    sendConfirm(choice = 'confirm') {
        // Choice 2 is the visible Stop action; use the dedicated backend
        // command so it cancels the running task instead of resuming the graph.
        if (String(choice) === '2') return this.sendStopScan();
        return this.send('user_choice', { choice });
    }
    sendToolConfirm(confirmed = true, params = {}) {
        if (confirmed) { return this.send('tool_confirmed', { confirmed: true, params }); }
        else { return this.send('tool_rejected', { confirmed: false, params }); }
    }
    sendAlternativeChoice(choiceIndex, choiceLabel) {
        return this.send('alternative_selected', { choice_index: choiceIndex, choice_label: choiceLabel });
    }
    sendAlternativeSelected(choiceIndex, choiceLabel) { return this.sendAlternativeChoice(choiceIndex, choiceLabel); }
    sendChat(content) { return this.send('chat', { content }); }
    sendScanChat(content) { return this.send('scan_chat', { content }); }
    sendDecisionOverride(nextTask, params = {}, reason = '') {
        return this.send('decision_override', { next_task: nextTask, params, reason });
    }
    sendExecuteTool(toolName, target, params = {}) {
        return this.send('execute_tool', { tool_name: toolName, target, params });
    }
    sendStopScan() { return this.send('stop_scan', {}); }
    sendInputResponse(field, value) { return this.send('input_response', { field, value }); }
    sendSubscribe(sessionId) { return this.send('subscribe', { session_id: sessionId }); }
    sendGetHistory() { return this.send('get_history', {}); }
    sendGetStatus() { return this.send('get_status', {}); }
}

export const ws = new WSManager();
