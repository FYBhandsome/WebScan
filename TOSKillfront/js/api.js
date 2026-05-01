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

    async createSession(target = '', tools = null) {
        const body = { target };
        if (tools) body.tools = tools;
        return this.post('/toskill/sessions', body);
    },

    async startInfoScan(target, tools = null, generateReport = true) {
        const body = { target, generate_report: generateReport };
        if (tools) body.tools = tools;
        return this.post('/toskill/scan/info', body);
    },

    async startVulnScan(target, tools = null, generateReport = true) {
        const body = { target, generate_report: generateReport };
        if (tools) body.tools = tools;
        return this.post('/toskill/scan/vuln', body);
    },

    async startFullScan(target, tools = null, generateReport = true) {
        const body = { target, generate_report: generateReport };
        if (tools) body.tools = tools;
        return this.post('/toskill/scan/full', body);
    },

    async getTools() {
        return this.get('/toskill/tools');
    },

    async getToolsByCategory() {
        return this.get('/toskill/tools/categories');
    },

    async executeTool(toolName, target, params = null) {
        const body = { tool_name: toolName, target: target };
        if (params) body.params = params;
        return this.post('/toskill/tools/execute', body);
    },

    async executeToolsBatch(toolNames, target, parallel = true) {
        return this.post('/toskill/tools/execute/batch', {
            tool_names: toolNames,
            target: target,
            parallel: parallel,
        });
    },

    async getReports() {
        const response = await this.get('/reports/list');
        if (response.success !== undefined) {
            return { 
                code: 200, 
                message: 'success', 
                data: { 
                    reports: response.reports, 
                    total: response.total 
                } 
            };
        }
        return response;
    },

    getReportDownloadUrl(filename) {
        return `${this.baseUrl}/reports/download/${filename}`;
    },

    async getReportContent(filename) {
        const response = await this.get(`/reports/${filename}/content`);
        if (response.success !== undefined) {
            return { 
                code: 200, 
                message: 'success', 
                data: { 
                    filename: response.filename, 
                    content: response.content 
                } 
            };
        }
        return response;
    },

    async deleteReport(filename) {
        const response = await this.delete(`/reports/${filename}`);
        if (response.success !== undefined) {
            return { code: 200, message: response.message || '删除成功', data: null };
        }
        return response;
    },

    async getReportBySession(sessionId) {
        const response = await this.get(`/reports/session/${sessionId}`);
        if (response.success !== undefined) {
            return { 
                code: 200, 
                message: 'success', 
                data: { 
                    report: response.report 
                } 
            };
        }
        return response;
    },

    async healthCheck() {
        return this.get('/toskill/health');
    },

    getWebSocketUrl() {
        return `${this.wsUrl}/api/ai-chat/ws`;
    },

    async sendChatMessage(sessionId, message) {
        return this.post('/chat/send', {
            session_id: sessionId,
            message: message,
        });
    },

    async getChatHistory(sessionId) {
        return this.get(`/chat/history/${sessionId}`);
    },
};

window.API = API;
