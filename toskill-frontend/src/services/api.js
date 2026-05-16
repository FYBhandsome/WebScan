class ApiService {
  constructor() {
    this.baseUrl = 'http://localhost:8081/api';
    this.wsUrl = 'ws://localhost:8081';
  }

  setBaseUrl(url) {
    this.baseUrl = `${url}/api`;
  }

  setWsUrl(url) {
    this.wsUrl = url;
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseUrl}${endpoint}`;
    const defaultOptions = {
      headers: { 'Content-Type': 'application/json' },
    };
    const config = { ...defaultOptions, ...options };

    try {
      const response = await fetch(url, config);
      const data = await response.json();

      if (!response.ok) {
        // ✅ 增强版错误解析：精准翻译 FastAPI 的报错
        let errorMsg = `HTTP ${response.status}`;
        
        if (Array.isArray(data.detail)) {
          // 处理 422 验证错误，提取出具体是哪个字段报错
          errorMsg = data.detail.map(err => {
            const field = err.loc[err.loc.length - 1]; // 获取报错的字段名
            return `字段 [${field}] 错误: ${err.msg}`;
          }).join(' | ');
        } else if (data.detail) {
          // 处理常规错误字符串
          errorMsg = data.detail;
        } else if (data.message) {
          errorMsg = data.message;
        }
        
        throw new Error(errorMsg);
      }

      return data;
    } catch (error) {
      console.error('API Error:', error);
      throw error;
    }
  }

  async get(endpoint) {
    return this.request(endpoint, { method: 'GET' });
  }

  async post(endpoint, body) {
    return this.request(endpoint, {
      method: 'POST',
      body: JSON.stringify(body),
    });
  }

  async delete(endpoint) {
    return this.request(endpoint, { method: 'DELETE' });
  }

  // --- Session ---
  // 修正：接口路径改为 /sessions，参数改为 target 和 mode
  async createSession(target = '', mode = 'full_scan') {
    return this.post('/sessions', { target, mode });
  }

  async getSessionStatus(sessionId) {
    return this.get(`/sessions/${sessionId}`);
  }

  async deleteSession(sessionId) {
    return this.delete(`/sessions/${sessionId}`);
  }

  // --- Scan ---
  async startInfoScan(target) {
    return this.post('/scan/info', { target });
  }

  async startVulnScan(target) {
    return this.post('/scan/vuln', { target });
  }

  async startFullScan(target) {
    return this.post('/scan/full', { target });
  }

  // --- Tools ---
  // 修正：移除多余的 /toskill 前缀
  async getTools() {
    return this.get('/tools');
  }

  async getToolsByCategory() {
    return this.get('/tools/categories');
  }

  async executeTool(toolName, target) {
    return this.post('/tools/execute', { tool_name: toolName, target });
  }

  async executeToolsBatch(toolNames, target) {
    return this.post('/tools/execute/batch', { tool_names: toolNames, target });
  }

  // --- Reports ---
  async getReports() {
    return this.get('/reports/list');
  }

  getReportDownloadUrl(filename) {
    return `${this.baseUrl}/reports/download/${filename}`;
  }

  async getReportContent(filename) {
    return this.get(`/reports/${filename}/content`);
  }

  async deleteReport(filename) {
    return this.delete(`/reports/${filename}`);
  }

  // --- System/Other ---
  async healthCheck() {
    return this.get('/health');
  }

  getWebSocketUrl() {
    return `${this.wsUrl}/api/ai-chat/ws`;
  }

  // --- Chat ---
  async sendChatMessage(sessionId, message) {
    return this.post('/chat/send', {
      session_id: sessionId,
      message: message,
    });
  }

  async getChatHistory(sessionId, limit = 20) {
    return this.get(`/chat/history/${sessionId}?limit=${limit}`);
  }
}

// 导出一个单例实例
export const API = new ApiService();