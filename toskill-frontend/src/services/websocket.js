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
        this.sessionId = null;
        this._firstConnect = true;
        this._shouldReconnect = true;
        this._offlineQueue = [];
        this._heartbeatTimer = null;
        this._heartbeatInterval = 30000;
        this._missedHeartbeats = 0;
        this._maxMissedHeartbeats = 3;

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

    _startHeartbeat() {
        this._stopHeartbeat();
        this._missedHeartbeats = 0;
        this._heartbeatTimer = setInterval(() => {
            if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                this._missedHeartbeats++;
                if (this._missedHeartbeats > this._maxMissedHeartbeats) {
                    LOG.warn('Heartbeat timeout, closing connection');
                    this.ws.close();
                    return;
                }
                try {
                    this.ws.send(JSON.stringify({ type: 'ping' }));
                } catch (e) {
                    LOG.error('Heartbeat send failed:', e);
                }
            }
        }, this._heartbeatInterval);
    }

    _stopHeartbeat() {
        if (this._heartbeatTimer) {
            clearInterval(this._heartbeatTimer);
            this._heartbeatTimer = null;
        }
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

                    this._startHeartbeat();

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

                        if (data.type === 'pong') {
                            this._missedHeartbeats = 0;
                            return;
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
                    }
                };

                this.ws.onclose = (event) => {
                    LOG.log('WebSocket closed:', event.code, event.reason);
                    this.connected = false;
                    this._stopHeartbeat();

                    if (this.onDisconnectCallback) {
                        this.onDisconnectCallback(event);
                    }

                    if (this._shouldReconnect && this.reconnectAttempts < this.maxReconnectAttempts) {
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
                    }
                };

                this.ws.onerror = (error) => {
                    LOG.error('WebSocket error:', error);
                    if (this.onErrorCallback) {
                        this.onErrorCallback(error);
                    }
                    this.cleanupConnectPromise(error);
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
        this._stopHeartbeat();
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
            if (this._shouldReconnect && type !== 'ping' && type !== 'pong') {
                this._offlineQueue.push(message);
                if (this._offlineQueue.length > MAX_OFFLINE_QUEUE) {
                    this._offlineQueue = this._offlineQueue.slice(-MAX_OFFLINE_QUEUE);
                }
                LOG.warn(`WebSocket offline, queued message: ${type}`);
            }
            return false;
        }
        this.ws.send(JSON.stringify(message));
        return true;
    }

    handleMessage(data) {
        const handlers = this.messageHandlers.get(data.type) || [];
        handlers.forEach(handler => handler(data.payload, data));

        const allHandlers = this.messageHandlers.get('*') || [];
        allHandlers.forEach(handler => handler(data));
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
    onReconnect(callback) { this.onReconnectCallback = callback; }
    isConnected() { return this.connected && this.ws && this.ws.readyState === WebSocket.OPEN; }
    getSessionId() { return this.sessionId; }

    startScan(target, scanMode = 'info', params = {}) {
        const payload = { target, scan_mode: scanMode, params };
        console.log('[WS] startScan 发送:', { type: 'start_scan', payload });
        const result = this.send('start_scan', payload);
        console.log('[WS] startScan 发送结果:', result);
        return result;
    }
    sendConfirm(choice = 'confirm') { return this.send('user_choice', { choice }); }
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
