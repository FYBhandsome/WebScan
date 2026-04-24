import axios from 'axios'
import { errorHandler } from './errorHandler'
import { handleResponse, handleApiError } from './apiResponse'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8888/api'
const REQUEST_TIMEOUT = parseInt(import.meta.env.VITE_REQUEST_TIMEOUT) || 30000

const instance = axios.create({
  baseURL: API_BASE_URL,
  timeout: REQUEST_TIMEOUT,
  headers: {
    'Content-Type': 'application/json'
  }
})

instance.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

instance.interceptors.response.use(
  (response) => {
    const handled = handleResponse(response.data)
    if (!handled.success) {
      errorHandler.handle(handled)
      return Promise.reject(new Error(handled.message || '操作失败'))
    }
    return handled
  },
  (error) => {
    if (error.response && error.response.status === 404) {
      return Promise.reject(new Error('资源不存在'))
    }
    const handled = handleApiError(error)
    errorHandler.handle(handled)
    return Promise.reject(new Error(handled.message || '请求失败'))
  }
)

export function request(config) {
  return instance(config)
}

export const scanApi = {
  portScan: async (data) => {
    return request({
      url: '/scan/port-scan',
      method: 'post',
      data
    })
  },

  infoLeak: async (data) => {
    return request({
      url: '/scan/info-leak',
      method: 'post',
      data
    })
  },

  dirScan: async (data) => {
    return request({
      url: '/scan/dir-scan',
      method: 'post',
      data
    })
  },

  webSideScan: async (data) => {
    return request({
      url: '/scan/web-side',
      method: 'post',
      data
    })
  },

  baseInfo: async (data) => {
    return request({
      url: '/scan/baseinfo',
      method: 'post',
      data
    })
  },

  subdomainScan: async (data) => {
    return request({
      url: '/scan/subdomain',
      method: 'post',
      data
    })
  },

  comprehensiveScan: async (data) => {
    return request({
      url: '/scan/comprehensive',
      method: 'post',
      data
    })
  },

  webWeight: async (data) => {
    return request({
      url: '/scan/web-weight',
      method: 'post',
      data
    })
  },

  ipLocating: async (data) => {
    return request({
      url: '/scan/ip-locating',
      method: 'post',
      data
    })
  },

  cdnCheck: async (data) => {
    return request({
      url: '/scan/cdn-check',
      method: 'post',
      data
    })
  },

  wafCheck: async (data) => {
    return request({
      url: '/scan/waf-check',
      method: 'post',
      data
    })
  },

  whatCms: async (data) => {
    return request({
      url: '/scan/what-cms',
      method: 'post',
      data
    })
  }
}

export const tasksApi = {
  createTask: async (data) => {
    return request({
      url: '/tasks/create',
      method: 'post',
      data
    })
  },

  getTasks: async (params = {}) => {
    return request({
      url: '/tasks/',
      method: 'get',
      params
    })
  },

  getTask: async (taskId) => {
    return request({
      url: `/tasks/${taskId}`,
      method: 'get'
    })
  },

  updateTask: async (taskId, data) => {
    return request({
      url: `/tasks/${taskId}`,
      method: 'put',
      data
    })
  },

  deleteTask: async (taskId) => {
    return request({
      url: `/tasks/${taskId}`,
      method: 'delete'
    })
  },

  getTaskResults: async (taskId) => {
    return request({
      url: `/tasks/${taskId}/results`,
      method: 'get'
    })
  },

  cancelTask: async (taskId) => {
    return request({
      url: `/tasks/${taskId}/cancel`,
      method: 'post'
    })
  },

  getTaskLogs: async (taskId, params = {}) => {
    return request({
      url: `/tasks/${taskId}/logs`,
      method: 'get',
      params
    })
  },

  getTaskVulnerabilities: async (taskId, params = {}) => {
    return request({
      url: `/tasks/${taskId}/vulnerabilities`,
      method: 'get',
      params
    })
  },

  getStatisticsOverview: async () => {
    return request({
      url: '/tasks/statistics/overview',
      method: 'get'
    })
  },

  getFrozenTasks: async () => {
    return request({
      url: '/tasks/frozen',
      method: 'get'
    })
  }
}

export const reportsApi = {
  getReports: async (params = {}) => {
    return request({
      url: '/reports/',
      method: 'get',
      params
    })
  },

  createReport: async (data) => {
    return request({
      url: '/reports/',
      method: 'post',
      data
    })
  },

  getReport: async (reportId) => {
    return request({
      url: `/reports/${reportId}`,
      method: 'get'
    })
  },

  getReportDetail: async (reportId) => {
    return request({
      url: `/reports/${reportId}`,
      method: 'get'
    })
  },

  updateReport: async (reportId, data) => {
    return request({
      url: `/reports/${reportId}`,
      method: 'put',
      data
    })
  },

  deleteReport: async (reportId) => {
    return request({
      url: `/reports/${reportId}`,
      method: 'delete'
    })
  },

  exportReport: async (reportId, format = 'json') => {
    const token = localStorage.getItem('token')
    const baseUrl = API_BASE_URL
    return fetch(`${baseUrl}/reports/${reportId}/export?format=${format}`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    })
  },

  downloadReport: async (reportId, format = 'json') => {
    const token = localStorage.getItem('token')
    const baseUrl = API_BASE_URL
    return fetch(`${baseUrl}/reports/${reportId}/export?format=${format}`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    })
  },

  regenerateReport: async (reportId) => {
    return request({
      url: `/reports/${reportId}/regenerate`,
      method: 'post'
    })
  },

  previewReport: async (reportId) => {
    return request({
      url: `/reports/${reportId}/preview`,
      method: 'get'
    })
  },

  getLatestReportByTask: async (taskId) => {
    return request({
      url: `/reports/task/${taskId}/latest`,
      method: 'get'
    })
  }
}

export const settingsApi = {
  getSettings: async () => {
    return request({
      url: '/settings/',
      method: 'get'
    })
  },

  updateSettings: async (data) => {
    return request({
      url: '/settings/',
      method: 'put',
      data
    })
  },

  getSettingItem: async (category, key) => {
    return request({
      url: `/settings/item/${category}/${key}`,
      method: 'get'
    })
  },

  updateSettingItem: async (data) => {
    return request({
      url: '/settings/item',
      method: 'put',
      data
    })
  },

  deleteSettingItem: async (category, key) => {
    return request({
      url: `/settings/item/${category}/${key}`,
      method: 'delete'
    })
  },

  getSystemInfo: async () => {
    return request({
      url: '/settings/system-info',
      method: 'get'
    })
  },

  getStatistics: async (period = 7) => {
    return request({
      url: '/settings/statistics',
      method: 'get',
      params: { period }
    })
  },

  getCategories: async () => {
    return request({
      url: '/settings/categories',
      method: 'get'
    })
  },

  getCategorySettings: async (category) => {
    return request({
      url: `/settings/category/${category}`,
      method: 'get'
    })
  },

  resetSettings: async () => {
    return request({
      url: '/settings/reset',
      method: 'post'
    })
  },

  resetCategorySettings: async (category) => {
    return request({
      url: `/settings/reset/${category}`,
      method: 'post'
    })
  },

  getApiKeys: async () => {
    return request({
      url: '/settings/api-keys',
      method: 'get'
    })
  },

  createApiKey: async (data) => {
    return request({
      url: '/settings/api-keys',
      method: 'post',
      data
    })
  },

  deleteApiKey: async (keyId) => {
    return request({
      url: `/settings/api-keys/${keyId}`,
      method: 'delete'
    })
  },

  regenerateApiKey: async (keyId) => {
    return request({
      url: `/settings/api-keys/${keyId}/regenerate`,
      method: 'put'
    })
  }
}

export const pocApi = {
  getPOCTypes: async () => {
    return request({
      url: '/poc/types',
      method: 'get'
    })
  },

  runPOC: async (data) => {
    return request({
      url: '/poc/scan',
      method: 'post',
      data
    })
  },

  getPOCInfo: async (pocType) => {
    return request({
      url: `/poc/info/${pocType}`,
      method: 'get'
    })
  },

  downloadPOC: async (pocType) => {
    return request({
      url: `/poc/download/${pocType}`,
      method: 'get'
    })
  }
}

export const awvsApi = {
  getTargets: async () => {
    return request({
      url: '/awvs/targets',
      method: 'get'
    })
  },

  getTarget: async (targetId) => {
    return request({
      url: `/awvs/target/${targetId}`,
      method: 'get'
    })
  },

  createTarget: async (data) => {
    return request({
      url: '/awvs/target',
      method: 'post',
      data
    })
  },

  deleteTarget: async (targetId) => {
    return request({
      url: `/awvs/target/${targetId}`,
      method: 'delete'
    })
  },

  getScans: async (targetId) => {
    return request({
      url: '/awvs/scans',
      method: 'get',
      params: targetId ? { target_id: targetId } : {}
    })
  },

  startScan: async (data) => {
    return request({
      url: '/awvs/scan',
      method: 'post',
      data
    })
  },

  getVulnerabilities: async (targetId) => {
    return request({
      url: `/awvs/vulnerabilities/${targetId}`,
      method: 'get'
    })
  },

  getVulnerabilityDetail: async (vulnId) => {
    return request({
      url: `/awvs/vulnerability/${vulnId}`,
      method: 'get'
    })
  },

  getVulnerabilitiesRank: async () => {
    return request({
      url: '/awvs/vulnerabilities/rank',
      method: 'get'
    })
  },

  getVulnerabilitiesStats: async () => {
    return request({
      url: '/awvs/vulnerabilities/stats',
      method: 'get'
    })
  },

  getMiddlewarePOCList: async () => {
    return request({
      url: '/awvs/middleware/poc-list',
      method: 'get'
    })
  },

  getMiddlewareScans: async () => {
    return request({
      url: '/awvs/middleware/scans',
      method: 'get'
    })
  },

  middlewareScan: async (data) => {
    return request({
      url: '/awvs/middleware/scan',
      method: 'post',
      data
    })
  },

  middlewareScanStart: async (data) => {
    return request({
      url: '/awvs/middleware/scan/start',
      method: 'post',
      data
    })
  },

  healthCheck: async () => {
    return request({
      url: '/awvs/health',
      method: 'get'
    })
  }
}

export const aiApi = {
  chat: async (data) => {
    return request({
      url: '/ai/chat',
      method: 'post',
      data
    })
  },

  getChatInstances: async () => {
    return request({
      url: '/ai/chat/instances',
      method: 'get'
    })
  },

  createChatInstance: async (data) => {
    return request({
      url: '/ai/chat/instances',
      method: 'post',
      data
    })
  },

  getChatInstance: async (instanceId) => {
    return request({
      url: `/ai/chat/instances/${instanceId}`,
      method: 'get'
    })
  },

  deleteChatInstance: async (instanceId) => {
    return request({
      url: `/ai/chat/instances/${instanceId}`,
      method: 'delete'
    })
  },

  getChatMessages: async (instanceId) => {
    return request({
      url: `/ai/chat/instances/${instanceId}/messages`,
      method: 'get'
    })
  },

  sendChatMessage: async (instanceId, data) => {
    return request({
      url: `/ai/chat/instances/${instanceId}/messages`,
      method: 'post',
      data
    })
  },

  closeChatInstance: async (instanceId) => {
    return request({
      url: `/ai/chat/instances/${instanceId}/close`,
      method: 'post'
    })
  }
}

export const kbApi = {
  getVulnerabilities: async (params) => {
    return request({
      url: '/kb/vulnerabilities',
      method: 'get',
      params
    })
  },

  search: async (params) => {
    return request({
      url: '/kb/vulnerabilities',
      method: 'get',
      params
    })
  },

  getKnowledge: async (knowledgeId) => {
    return request({
      url: `/kb/vulnerabilities/${knowledgeId}`,
      method: 'get'
    })
  },

  sync: async () => {
    return request({
      url: '/kb/sync',
      method: 'post'
    })
  },

  searchFromSeebug: async (data) => {
    return request({
      url: '/kb/search-from-seebug',
      method: 'post',
      data
    })
  },

  searchPOC: async (data) => {
    return request({
      url: '/kb/seebug/poc/search',
      method: 'post',
      data
    })
  },

  downloadPOC: async (ssvid, options = {}) => {
    return request({
      url: '/kb/seebug/poc/download',
      method: 'post',
      data: { 
        ssvid,
        save_to_local: options.save_to_local || false,
        category: options.category || 'seebug',
        cve_id: options.cve_id || null,
        vuln_name: options.vuln_name || null
      }
    })
  },

  getPOCDetail: async (ssvid) => {
    return request({
      url: `/kb/seebug/poc/${ssvid}/detail`,
      method: 'get'
    })
  }
}

export const userApi = {
  getProfile: async (userId = 1) => {
    return request({
      url: '/user/profile',
      method: 'get',
      params: { user_id: userId }
    })
  },

  updateProfile: async (userId, data) => {
    return request({
      url: '/user/profile',
      method: 'put',
      params: { user_id: userId },
      data
    })
  },

  getPermissions: async (userId = 1) => {
    return request({
      url: '/user/permissions',
      method: 'get',
      params: { user_id: userId }
    })
  },

  getList: async (params = {}) => {
    return request({
      url: '/user/list',
      method: 'get',
      params
    })
  }
}

export const notificationsApi = {
  getNotifications: async (params = {}) => {
    return request({
      url: '/notifications/',
      method: 'get',
      params
    })
  },

  getNotification: async (notificationId) => {
    return request({
      url: `/notifications/${notificationId}`,
      method: 'get'
    })
  },

  createNotification: async (data) => {
    return request({
      url: '/notifications/',
      method: 'post',
      data
    })
  },

  markAsRead: async (notificationId) => {
    return request({
      url: `/notifications/${notificationId}/read`,
      method: 'put'
    })
  },

  markAllAsRead: async () => {
    return request({
      url: '/notifications/read-all',
      method: 'put'
    })
  },

  deleteNotification: async (notificationId) => {
    return request({
      url: `/notifications/${notificationId}`,
      method: 'delete'
    })
  },

  deleteReadNotifications: async () => {
    return request({
      url: '/notifications/',
      method: 'delete'
    })
  },

  getUnreadCount: async () => {
    return request({
      url: '/notifications/count/unread',
      method: 'get'
    })
  }
}



export const pocVerificationApi = {
  createTask: async (data) => {
    return request({
      url: '/poc/verification/tasks',
      method: 'post',
      data
    })
  },

  createBatchTasks: async (data) => {
    return request({
      url: '/poc/verification/tasks/batch',
      method: 'post',
      data
    })
  },

  getTasks: async (params = {}) => {
    return request({
      url: '/poc/verification/tasks',
      method: 'get',
      params
    })
  },

  getTask: async (taskId) => {
    return request({
      url: `/poc/verification/tasks/${taskId}`,
      method: 'get'
    })
  },

  pauseTask: async (taskId) => {
    return request({
      url: `/poc/verification/tasks/${taskId}/pause`,
      method: 'post'
    })
  },

  resumeTask: async (taskId) => {
    return request({
      url: `/poc/verification/tasks/${taskId}/resume`,
      method: 'post'
    })
  },

  cancelTask: async (taskId) => {
    return request({
      url: `/poc/verification/tasks/${taskId}/cancel`,
      method: 'post'
    })
  },

  generateReport: async (taskId, format = 'html') => {
    return request({
      url: `/poc/verification/tasks/${taskId}/report`,
      method: 'post',
      params: { format }
    })
  },

  healthCheck: async () => {
    return request({
      url: '/poc/verification/health',
      method: 'get'
    })
  }
}

export const seebugAgentApi = {
  getStatus: async () => {
    return request({
      url: '/seebug/status',
      method: 'get'
    })
  },

  search: async (data) => {
    return request({
      url: '/seebug/search',
      method: 'post',
      data
    })
  },

  getVulnerabilityDetail: async (ssvid) => {
    return request({
      url: `/seebug/poc/${ssvid}/detail`,
      method: 'get'
    })
  },

  testConnection: async () => {
    return request({
      url: '/seebug/test-connection',
      method: 'get'
    })
  }
}

export const aiAgentsApi = {
  startScan: async (data) => {
    return request({
      url: '/ai_agents/scan',
      method: 'post',
      data
    })
  },

  scan: async (data) => {
    return request({
      url: '/ai_agents/scan',
      method: 'post',
      data
    })
  },

  getTask: async (taskId) => {
    return request({
      url: `/ai_agents/tasks/${taskId}`,
      method: 'get'
    })
  },

  getTasks: async (params = {}) => {
    return request({
      url: '/ai_agents/tasks',
      method: 'get',
      params
    })
  },

  getFrozenTasks: async () => {
    return request({
      url: '/ai_agents/tasks/frozen',
      method: 'get'
    })
  },

  cancelTask: async (taskId) => {
    return request({
      url: `/ai_agents/tasks/${taskId}/cancel`,
      method: 'post'
    })
  },

  deleteTask: async (taskId) => {
    return request({
      url: `/ai_agents/tasks/${taskId}`,
      method: 'delete'
    })
  },

  getTools: async (category) => {
    return request({
      url: '/ai_agents/tools',
      method: 'get',
      params: category ? { category } : {}
    })
  },

  getConfig: async () => {
    return request({
      url: '/ai_agents/config',
      method: 'get'
    })
  },

  updateConfig: async (data) => {
    return request({
      url: '/ai_agents/config',
      method: 'post',
      data
    })
  },

  generateCode: async (data) => {
    return request({
      url: '/ai_agents/code/generate',
      method: 'post',
      data
    })
  },

  executeCode: async (data) => {
    return request({
      url: '/ai_agents/code/execute',
      method: 'post',
      data
    })
  },

  generateAndExecuteCode: async (data) => {
    return request({
      url: '/ai_agents/code/generate-and-execute',
      method: 'post',
      data
    })
  },

  enhanceCapability: async (data) => {
    return request({
      url: '/ai_agents/capabilities/enhance',
      method: 'post',
      data
    })
  },

  listCapabilities: async () => {
    return request({
      url: '/ai_agents/capabilities/list',
      method: 'get'
    })
  },

  getCapability: async (capabilityName) => {
    return request({
      url: `/ai_agents/capabilities/${capabilityName}`,
      method: 'get'
    })
  },

  deleteCapability: async (capabilityName) => {
    return request({
      url: `/ai_agents/capabilities/${capabilityName}`,
      method: 'delete'
    })
  },

  getEnvironmentInfo: async () => {
    return request({
      url: '/ai_agents/environment/info',
      method: 'get'
    })
  },

  getEnvironmentTools: async () => {
    return request({
      url: '/ai_agents/environment/tools',
      method: 'get'
    })
  },

  getToolDetail: async (toolName) => {
    return request({
      url: `/ai_agents/environment/tools/${toolName}`,
      method: 'get'
    })
  },

  getResourceUsage: async () => {
    return request({
      url: '/ai_agents/resources/usage',
      method: 'get'
    })
  },

  getResourceStatistics: async () => {
    return request({
      url: '/ai_agents/resources/statistics',
      method: 'get'
    })
  },

  getWorkflowMetrics: async () => {
    return request({
      url: '/ai_agents/workflow/metrics',
      method: 'get'
    })
  },

  executePOC: async (data) => {
    return request({
      url: '/ai_agents/poc/execute',
      method: 'post',
      data
    })
  },

  batchExecutePOC: async (data) => {
    return request({
      url: '/ai_agents/poc/batch-execute',
      method: 'post',
      data
    })
  },

  searchPOC: async (data) => {
    return request({
      url: '/ai_agents/poc/search',
      method: 'post',
      data
    })
  },

  updateTaskPluginHeartbeat: async (taskId, pluginId) => {
    return request({
      url: `/ai_agents/tasks/${taskId}/plugin/${pluginId}/heartbeat`,
      method: 'put'
    })
  },

  finishTaskPlugin: async (taskId, pluginId) => {
    return request({
      url: `/ai_agents/tasks/${taskId}/plugin/${pluginId}/finish`,
      method: 'post'
    })
  },

  getAIAnalysis: async (taskId) => {
    return request({
      url: `/ai_agents/tasks/${taskId}/ai-analysis`,
      method: 'get'
    })
  },

  getExecutionDetails: async (taskId) => {
    return request({
      url: `/ai_agents/tasks/${taskId}/execution-details`,
      method: 'get'
    })
  },

  generateReport: async (data) => {
    return request({
      url: '/ai_agents/reports/generate',
      method: 'post',
      data
    })
  },

  getReports: async (params = {}) => {
    return request({
      url: '/ai_agents/reports',
      method: 'get',
      params
    })
  },

  getReport: async (reportId) => {
    return request({
      url: `/ai_agents/reports/${reportId}`,
      method: 'get'
    })
  },

  deleteReport: async (reportId) => {
    return request({
      url: `/ai_agents/reports/${reportId}`,
      method: 'delete'
    })
  }
}

export default {
  request,
  scan: scanApi,
  tasks: tasksApi,
  reports: reportsApi,
  settings: settingsApi,
  poc: pocApi,
  awvs: awvsApi,
  ai: aiApi,
  kb: kbApi,
  user: userApi,
  notifications: notificationsApi,
  pocVerification: pocVerificationApi,
  seebugAgent: seebugAgentApi,
  aiAgents: aiAgentsApi
}
