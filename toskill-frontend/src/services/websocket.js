// src/services/websocket.js
import { API } from './api.js';
import { storageService } from './storageService.js';

const isDev = import.meta.env.DEV;
const LOG = {
    log: (...args) => isDev && console.log(...args),
    error: (...args) => isDev && console.error(...args),
    warn: (...args) => isDev && console.warn(...args),
};

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
        this.sessionId = storageService.getActiveSessionId() || null;
        this._firstConnect = true;
        this._shouldReconnect = true;
    }

    // 设置或者更新 WS 地址
    setUrl(url) {
        this.url = url;
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
                const rawUrl = this.url || API.getWebSocketUrl();
                let targetUrl = rawUrl.includes(API.WS_PATH)
                    ? rawUrl
                    : rawUrl.replace(/\/$/, '') + API.WS_PATH;
                if (this.sessionId) {
                    const separator = targetUrl.includes('?') ? '&' : '?';
                    targetUrl += `${separator}session_id=${encodeURIComponent(this.sessionId)}`;
                }
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
                };

                this.ws.onmessage = (event) => {
                    try {
                        const data = JSON.parse(event.data);
                        if (data.type === 'connected' && data.payload?.session_id) {
                            this.sessionId = data.payload.session_id;
                            storageService.setActiveSessionId(this.sessionId);
                            if (this.connectResolve) {
                                this.connectResolve(this.sessionId);
                                this.connectResolve = null;
                                this.connectReject = null;
                            }
                        }
                        this.handleMessage(data);
                    } catch (error) {
                        LOG.error('Failed to parse WebSocket message:', error);
                    }
                };

                this.ws.onclose = (event) => {
                    LOG.log('WebSocket closed:', event.code, event.reason);
                    this.connected = false;

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
        this.cleanupConnectPromise(new Error('Disconnected'));
        if (this.ws) {
            this.ws.close();
            this.ws = null;
            this.connected = false;
        }
    }

    send(type, payload = {}) {
        if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
            LOG.error('WebSocket is not connected');
            return false;
        }
        const message = { type, payload };
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
    
    // 移除监听器的方法（在 Vue 组件销毁时非常重要，防止内存泄漏）
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

    startScan(target, scanMode = 'info') {
        const payload = { target, scan_mode: scanMode };
        console.log('[WS] startScan 发送:', { type: 'start_scan', payload });
        const result = this.send('start_scan', payload);
        console.log('[WS] startScan 发送结果:', result);
        return result;
    }
    sendConfirm(choice = 'confirm', interactionId = null) {
        return this.send('user_choice', { choice, ...(interactionId ? { interaction_id: interactionId } : {}) });
    }
    sendToolConfirm(confirmed = true, interactionId = null) {
        const interaction = interactionId ? { interaction_id: interactionId } : {};
        if (confirmed) { return this.send('tool_confirmed', { confirmed: true, ...interaction }); }
        else { return this.send('tool_rejected', { confirmed: false, ...interaction }); }
    }
    sendAlternativeChoice(choiceIndex, choiceLabel) {
        return this.send('alternative_selected', { choice_index: choiceIndex, choice_label: choiceLabel });
    }
    sendChat(content) { return this.send('chat', { content }); }
    sendInputResponse(field, value) { return this.send('input_response', { field, value }); }
    sendSubscribe(sessionId) { return this.send('subscribe', { session_id: sessionId }); }
    sendGetHistory() { return this.send('get_history', {}); }
    sendGetStatus() { return this.send('get_status', {}); }
}

// 导出单例，确保整个项目使用的是同一个 WebSocket 连接
export const ws = new WSManager();
