/**
 * API 基础配置
 */

// API 基础 URL
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8888/api'

/**
 * API 请求封装
 */
class ApiClient {
  constructor(baseURL) {
    this.baseURL = baseURL
    this.defaultHeaders = {
      'Content-Type': 'application/json'
    }
  }

  /**
   * 通用请求方法
   */
  async request(url, options = {}) {
    const fullUrl = `${this.baseURL}${url}`
    
    const config = {
      ...options,
      headers: {
        ...this.defaultHeaders,
        ...options.headers
      }
    }

    try {
      const response = await fetch(fullUrl, config)
      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.message || '请求失败')
      }

      return data
    } catch (error) {
      console.error('API 请求错误:', error)
      throw error
    }
  }

  /**
   * GET 请求
   */
  get(url, params = {}) {
    const queryString = new URLSearchParams(params).toString()
    const fullUrl = queryString ? `${url}?${queryString}` : url
    return this.request(fullUrl, { method: 'GET' })
  }

  /**
   * POST 请求
   */
  post(url, data = {}) {
    return this.request(url, {
      method: 'POST',
      body: JSON.stringify(data)
    })
  }

  /**
   * PUT 请求
   */
  put(url, data = {}) {
    return this.request(url, {
      method: 'PUT',
      body: JSON.stringify(data)
    })
  }

  /**
   * DELETE 请求
   */
  delete(url) {
    return this.request(url, { method: 'DELETE' })
  }
}

// 创建 API 客户端实例
const apiClient = new ApiClient(API_BASE_URL)

/**
 * 扫描相关 API
 */
export const scanApi = {
  // 端口扫描
  portScan: (data) => apiClient.post('/scan/port-scan', data),
  
  // 信息泄露检测
  infoLeak: (data) => apiClient.post('/scan/info-leak', data),
  
  // 旁站扫描
  webSide: (data) => apiClient.post('/scan/web-side', data),
  
  // 网站基本信息
  baseInfo: (data) => apiClient.post('/scan/baseinfo', data),
  
  // 网站权重
  webWeight: (data) => apiClient.post('/scan/web-weight', data),
  
  // IP定位
  ipLocating: (data) => apiClient.post('/scan/ip-locating', data),
  
  // CDN检测
  cdnCheck: (data) => apiClient.post('/scan/cdn-check', data),
  
  // WAF检测
  wafCheck: (data) => apiClient.post('/scan/waf-check', data),
  
  // CMS指纹识别
  whatCms: (data) => apiClient.post('/scan/what-cms', data),
  
  // 子域名扫描
  subdomain: (data) => apiClient.post('/scan/subdomain', data),
  
  // 目录扫描
  dirScan: (data) => apiClient.post('/scan/dir-scan', data),
  
  // 综合扫描
  comprehensive: (data) => apiClient.post('/scan/comprehensive', data)
}

/**
 * 任务管理 API
 */
export const taskApi = {
  // 获取任务列表
  list: (params) => apiClient.get('/tasks/', params),
  
  // 创建任务
  create: (data) => apiClient.post('/tasks/', data),
  
  // 获取任务详情
  get: (taskId) => apiClient.get(`/tasks/${taskId}/`),
  
  // 更新任务
  update: (taskId, data) => apiClient.put(`/tasks/${taskId}/`, data),
  
  // 删除任务
  delete: (taskId) => apiClient.delete(`/tasks/${taskId}/`),
  
  // 取消任务
  cancel: (taskId) => apiClient.post(`/tasks/${taskId}/cancel/`)
}

/**
 * 报告管理 API
 */
export const reportApi = {
  // 获取报告列表
  list: (params) => apiClient.get('/reports', params),
  
  // 创建报告
  create: (data) => apiClient.post('/reports', data),
  
  // 获取报告详情
  get: (reportId) => apiClient.get(`/reports/${reportId}`),
  
  // 更新报告
  update: (reportId, data) => apiClient.put(`/reports/${reportId}`, data),
  
  // 删除报告
  delete: (reportId) => apiClient.delete(`/reports/${reportId}`),
  
  // 导出报告
  export: (reportId, format = 'json') => apiClient.get(`/reports/${reportId}/export`, { format })
}

/**
 * 系统设置 API
 */
export const settingsApi = {
  // 获取系统设置
  get: () => apiClient.get('/settings'),
  
  // 更新系统设置
  update: (data) => apiClient.put('/settings', data),
  
  // 获取系统信息
  getSystemInfo: () => apiClient.get('/settings/system-info'),
  
  // 获取统计信息
  getStatistics: () => apiClient.get('/settings/statistics')
}

/**
 * POC 扫描相关 API
 */
export const pocApi = {
  // 获取可用的POC类型列表
  getTypes: () => apiClient.get('/poc/types'),
  
  // 执行POC扫描
  scan: (data) => apiClient.post('/poc/scan', data),
  
  // 获取POC扫描结果
  getResults: (params) => apiClient.get('/poc/results', params),
  
  // 获取POC扫描详情
  getResult: (resultId) => apiClient.get(`/poc/results/${resultId}`),
  
  // 导出POC扫描报告
  exportReport: (resultId, format = 'json') => apiClient.get(`/poc/results/${resultId}/export`, { format })
}

/**
 * 健康检查
 */
export const healthCheck = () => apiClient.get('/health')

export default apiClient

