class ApiService {
  constructor() {
    this.baseUrl = '/api';
    this.wsUrl = '';
    this.wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    this.WS_PATH = '/api/ai-chat/ws';
  }

  setBaseUrl(url) {
    if (url.startsWith('http://') || url.startsWith('https://')) {
      this.baseUrl = `${url}/api`;
    } else {
      this.baseUrl = '/api';
    }
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
    if (config.body instanceof FormData) {
      const headers = { ...(config.headers || {}) };
      delete headers['Content-Type'];
      delete headers['content-type'];
      config.headers = headers;
    }

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
      if (import.meta.env.DEV) console.error('API Error:', error);
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
  async startInfoScan(target, params = {}) {
    return this.post('/scan/info', { target, params });
  }

  async startVulnScan(target, params = {}) {
    return this.post('/scan/vuln', { target, params });
  }

  async startFullScan(target, params = {}) {
    return this.post('/scan/full', { target, params });
  }

  /**
   * 获取扫描任务状态（轮询端点，不依赖 WebSocket）。
   * 对应后端 GET /api/scan/tasks/{task_id}/status。
   *
   * @param {string} taskId - 任务 ID
   * @returns {Promise<Object>} 任务状态对象，结构如：
   *   { task_id, status, progress, stage,
   *     waiting_input?: { fields: [{name,type,description,required,default}] },
   *     waiting_script?: { capability, params: [{name,type,description}] },
   *     result?, error? }
   *   status 枚举: queued | planning | waiting_user_input | waiting_script_upload | running | completed | exception
   */
  async getTaskStatus(taskId) {
    return this.get(`/scan/tasks/${taskId}/status`);
  }

  async generateScanReport(sessionId) {
    if (!sessionId) throw new Error('sessionId is required');
    return this.post(`/reports/generate/${encodeURIComponent(sessionId)}`, {});
  }

  // --- Tools ---
  // 修正：移除多余的 /toskill 前缀
  async getTools() {
    return this.get('/tools');
  }

  async getToolsByCategory() {
    return this.get('/tools/categories');
  }

  async executeTool(toolName, target, params = {}, analyze = true) {
    return this.post('/tools/execute', { tool_name: toolName, target, params, analyze });
  }

  async executeToolsBatch(toolNames, target, params = {}) {
    return this.post('/tools/execute/batch', { tool_names: toolNames, target, params });
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

  // --- RAG Knowledge Base ---
  async getRagConfig() {
    return this.get('/rag/config');
  }

  async setRagMode(mode) {
    return this.request('/rag/config', {
      method: 'PUT',
      body: JSON.stringify({ mode }),
    });
  }

  async getRagDocuments() {
    return this.get('/rag/documents');
  }

  async getRagDocument(filename) {
    return this.get(`/rag/documents/${encodeURIComponent(filename)}`);
  }

  async uploadRagDocument(file) {
    const formData = new FormData();
    formData.append('file', file);
    return this.request('/rag/documents', {
      method: 'POST',
      body: formData,
    });
  }

  async rebuildRagIndex() {
    return this.post('/rag/index/rebuild');
  }

  async getRagRebuildStatus(operationId) {
    return this.get(`/rag/index/rebuild/${encodeURIComponent(operationId)}`);
  }

  // --- System/Other ---
  async healthCheck() {
    return this.get('/health');
  }

  getWebSocketUrl() {
    if (this.wsUrl) {
      return this.wsUrl;
    }
    const host = window.location.host;
    return `${this.wsProtocol}//${host}${this.WS_PATH}`;
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

  // --- Intent Parsing ---
  async parseIntent(message) {
    return this.post('/parse-intent', { message });
  }
}

// 导出一个单例实例
export const API = new ApiService();
