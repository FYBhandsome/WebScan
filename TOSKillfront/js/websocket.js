class WSManager {
    constructor(url) {
        this.url = url;
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
                this.ws = new WebSocket(this.url);

                this.ws.onopen = () => {
                    console.log('WebSocket connected');
                    this.connected = true;
                    this.reconnectAttempts = 0;

                    if (this.onConnectCallback) {
                        this.onConnectCallback();
                    }

                    if (this.onReconnectCallback && this.ws && this.ws.readyState === WebSocket.OPEN) {
                        this.onReconnectCallback(this.sessionId);
                    }
                };

                this.ws.onmessage = (event) => {
                    try {
                        const data = JSON.parse(event.data);
                        this.handleMessage(data);

                        if (data.type === 'connected' && data.payload?.session_id) {
                            this.sessionId = data.payload.session_id;
                            if (this.connectResolve) {
                                this.connectResolve(this.sessionId);
                                this.connectResolve = null;
                                this.connectReject = null;
                            }
                        }
                    } catch (error) {
                        console.error('Failed to parse WebSocket message:', error);
                    }
                };

                this.ws.onclose = (event) => {
                    console.log('WebSocket closed:', event.code, event.reason);
                    this.connected = false;

                    if (this.onDisconnectCallback) {
                        this.onDisconnectCallback(event);
                    }

                    if (this.reconnectAttempts < this.maxReconnectAttempts) {
                        const delay = Math.min(
                            this.reconnectDelay * Math.pow(2, this.reconnectAttempts),
                            this.maxReconnectDelay
                        );
                        this.reconnectAttempts++;
                        console.log(`Reconnecting... Attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts} in ${delay}ms`);
                        this.reconnectTimer = setTimeout(() => {
                            this.reconnectTimer = null;
                            this.connect();
                        }, delay);
                    } else {
                        console.log('Max reconnect attempts reached');
                        this.cleanupConnectPromise(new Error('Max reconnect attempts reached'));
                    }
                };

                this.ws.onerror = (error) => {
                    console.error('WebSocket error:', error);
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
        this.reconnectAttempts = this.maxReconnectAttempts;
        this.cleanupConnectPromise(new Error('Disconnected'));
        if (this.ws) {
            this.ws.close();
            this.ws = null;
            this.connected = false;
            this.sessionId = null;
        }
    }

    send(type, payload = {}) {
        if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
            console.error('WebSocket is not connected');
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

    onConnect(callback) {
        this.onConnectCallback = callback;
    }

    onDisconnect(callback) {
        this.onDisconnectCallback = callback;
    }

    onError(callback) {
        this.onErrorCallback = callback;
    }

    onReconnect(callback) {
        this.onReconnectCallback = callback;
    }

    isConnected() {
        return this.connected && this.ws && this.ws.readyState === WebSocket.OPEN;
    }

    getSessionId() {
        return this.sessionId;
    }

    startScan(target, scanMode = 'info') {
        return this.send('start_scan', { target, scan_mode: scanMode });
    }

    sendConfirm(choice = 'confirm') {
        return this.send('user_choice', { choice });
    }

    sendChat(content) {
        return this.send('chat', { content });
    }

}

window.WSManager = WSManager;
