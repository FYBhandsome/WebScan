const API = {
    baseUrl: 'http://localhost:8081/api',
    wsUrl: 'ws://localhost:8081',
    
    setBaseUrl(url) {
        this.baseUrl = url + '/api';
    },
    
    setWsUrl(url) {
        this.wsUrl = url;
    },

    async request(endpoint, options = {}) {
        const url = this.baseUrl + endpoint;
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
            },
        };
        
        const config = { ...defaultOptions, ...options };
        
        try {
            const response = await fetch(url, config);
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.detail || `HTTP ${response.status}`);
            }
            
            return data;
        } catch (error) {
            console.error('API Error:', error);
            throw error;
        }
    },

    async get(endpoint) {
        return this.request(endpoint, { method: 'GET' });
    },

    async post(endpoint, body) {
        return this.request(endpoint, {
            method: 'POST',
            body: JSON.stringify(body),
        });
    },

    async delete(endpoint) {
        return this.request(endpoint, { method: 'DELETE' });
    },

    async createSession(target = '', mode = 'full_scan') {
        return this.post('/toskill/sessions', { target, mode });
    },

    async getSession(sessionId) {
        return this.get(`/toskill/sessions/${sessionId}`);
    },

    async deleteSession(sessionId) {
        return this.delete(`/toskill/sessions/${sessionId}`);
    },

    async startInfoScan(target, sessionId = null) {
        const body = { target };
        if (sessionId) body.session_id = sessionId;
        return this.post('/toskill/scan/info', body);
    },

    async startVulnScan(target, sessionId = null) {
        const body = { target };
        if (sessionId) body.session_id = sessionId;
        return this.post('/toskill/scan/vuln', body);
    },

    async startFullScan(target, sessionId = null) {
        const body = { target };
        if (sessionId) body.session_id = sessionId;
        return this.post('/toskill/scan/full', body);
    },

    async getTools() {
        return this.get('/toskill/tools');
    },

    async getToolsByCategory() {
        return this.get('/toskill/tools/categories');
    },

    async executeTool(toolName, target) {
        return this.post('/toskill/tools/execute', {
            tool_name: toolName,
            target: target,
        });
    },

    async executeToolsBatch(toolNames, target) {
        return this.post('/toskill/tools/execute/batch', {
            tool_names: toolNames,
            target: target,
        });
    },

    async getReports() {
        return this.get('/reports/list');
    },

    getReportDownloadUrl(filename) {
        return `${this.baseUrl}/reports/download/${filename}`;
    },

    async getReportContent(filename) {
        return this.get(`/reports/${filename}/content`);
    },

    async deleteReport(filename) {
        return this.delete(`/reports/${filename}`);
    },

    async generateReport(sessionId) {
        return this.post(`/toskill/reports/generate/${sessionId}`);
    },

    async sendChatMessage(sessionId, content, role = 'user') {
        return this.post('/toskill/chat/message', {
            session_id: sessionId,
            role: role,
            content: content,
        });
    },

    async getChatHistory(sessionId, limit = 20) {
        return this.get(`/toskill/chat/history/${sessionId}?limit=${limit}`);
    },

    async healthCheck() {
        return this.get('/toskill/health');
    },

    getWebSocketUrl() {
        return `${this.wsUrl}/api/ai-chat/ws`;
    },
};

window.API = API;
