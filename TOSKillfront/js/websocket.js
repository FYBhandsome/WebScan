class WSManager {
    constructor(url) {
        this.url = url;
        this.ws = null;
        this.connected = false;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 2000;
        this.messageHandlers = new Map();
        this.onConnectCallback = null;
        this.onDisconnectCallback = null;
        this.onErrorCallback = null;
        this.sessionId = null;
    }

    connect() {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            return Promise.resolve(this.sessionId);
        }

        return new Promise((resolve, reject) => {
            try {
                this.ws = new WebSocket(this.url);

                this.ws.onopen = () => {
                    console.log('WebSocket connected');
                    this.connected = true;
                    this.reconnectAttempts = 0;
                    if (this.onConnectCallback) {
                        this.onConnectCallback();
                    }
                };

                this.ws.onmessage = (event) => {
                    try {
                        const data = JSON.parse(event.data);
                        this.handleMessage(data);
                        
                        if (data.type === 'connected' && data.payload?.session_id) {
                            this.sessionId = data.payload.session_id;
                            resolve(this.sessionId);
                        }
                    } catch (error) {
                        console.error('Failed to parse WebSocket message:', error);
                    }
                };

                this.ws.onclose = (event) => {
                    console.log('WebSocket closed:', event.code, event.reason);
                    this.connected = false;
                    this.sessionId = null;
                    
                    if (this.onDisconnectCallback) {
                        this.onDisconnectCallback(event);
                    }

                    if (this.reconnectAttempts < this.maxReconnectAttempts) {
                        this.reconnectAttempts++;
                        console.log(`Reconnecting... Attempt ${this.reconnectAttempts}`);
                        setTimeout(() => this.connect(), this.reconnectDelay);
                    }
                };

                this.ws.onerror = (error) => {
                    console.error('WebSocket error:', error);
                    if (this.onErrorCallback) {
                        this.onErrorCallback(error);
                    }
                    reject(error);
                };

            } catch (error) {
                reject(error);
            }
        });
    }

    disconnect() {
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

    off(messageType, callback) {
        if (!this.messageHandlers.has(messageType)) return;
        
        const handlers = this.messageHandlers.get(messageType);
        const index = handlers.indexOf(callback);
        if (index > -1) {
            handlers.splice(index, 1);
        }
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

    isConnected() {
        return this.connected && this.ws && this.ws.readyState === WebSocket.OPEN;
    }

    getSessionId() {
        return this.sessionId;
    }

    sendUserInput(content) {
        return this.send('user_input', { content });
    }

    startScan(target, scanMode = 'info') {
        return this.send('start_scan', { target, scan_mode: scanMode });
    }

    sendConfirm(choice = 'confirm') {
        return this.send('user_confirm', { choice });
    }

    sendChat(content) {
        return this.send('chat', { content });
    }

    executeTool(toolName, target) {
        return this.send('execute_tool', { tool_name: toolName, target });
    }

    getHistory() {
        return this.send('get_history');
    }

    getStatus() {
        return this.send('get_status');
    }
}

window.WSManager = WSManager;
