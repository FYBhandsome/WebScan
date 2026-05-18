export class AppError extends Error {
  constructor(code, message, details = {}) {
    super(message)
    this.name = 'AppError'
    this.code = code
    this.details = details
    this.timestamp = new Date().toISOString()
  }
  
  toObject() {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      details: this.details,
      timestamp: this.timestamp
    }
  }
}

export const ErrorCodes = {
  NETWORK_ERROR: 'E001',
  WEBSOCKET_DISCONNECT: 'E002',
  WEBSOCKET_ERROR: 'E003',
  VALIDATION_ERROR: 'E100',
  INVALID_TARGET: 'E101',
  INVALID_SCRIPT: 'E102',
  FILE_TOO_LARGE: 'E103',
  UNSUPPORTED_FORMAT: 'E104',
  AUTH_ERROR: 'E200',
  UNAUTHORIZED: 'E201',
  FORBIDDEN: 'E202',
  SERVER_ERROR: 'E500',
  UNKNOWN_ERROR: 'E999'
}

export const ErrorMessages = {
  [ErrorCodes.NETWORK_ERROR]: '网络连接失败',
  [ErrorCodes.WEBSOCKET_DISCONNECT]: 'WebSocket连接断开',
  [ErrorCodes.WEBSOCKET_ERROR]: 'WebSocket连接错误',
  [ErrorCodes.VALIDATION_ERROR]: '输入验证失败',
  [ErrorCodes.INVALID_TARGET]: '目标地址格式无效',
  [ErrorCodes.INVALID_SCRIPT]: '脚本验证失败',
  [ErrorCodes.FILE_TOO_LARGE]: '文件大小超过限制',
  [ErrorCodes.UNSUPPORTED_FORMAT]: '不支持的文件格式',
  [ErrorCodes.AUTH_ERROR]: '认证失败',
  [ErrorCodes.UNAUTHORIZED]: '未授权访问',
  [ErrorCodes.FORBIDDEN]: '禁止访问',
  [ErrorCodes.SERVER_ERROR]: '服务器内部错误',
  [ErrorCodes.UNKNOWN_ERROR]: '未知错误'
}

export const handleError = (error, context = {}) => {
  console.error('[ErrorHandler]', error, context)
  
  let appError
  
  if (error instanceof AppError) {
    appError = error
  } else if (error instanceof TypeError) {
    appError = new AppError(ErrorCodes.VALIDATION_ERROR, error.message, { originalError: error.toString() })
  } else if (error instanceof SyntaxError) {
    appError = new AppError(ErrorCodes.VALIDATION_ERROR, `语法错误: ${error.message}`, { originalError: error.toString() })
  } else if (error.name === 'NetworkError' || error.message?.includes('network')) {
    appError = new AppError(ErrorCodes.NETWORK_ERROR, ErrorMessages[ErrorCodes.NETWORK_ERROR], { originalError: error.toString() })
  } else {
    appError = new AppError(ErrorCodes.UNKNOWN_ERROR, error.message || ErrorMessages[ErrorCodes.UNKNOWN_ERROR], { originalError: error.toString() })
  }
  
  return appError
}

export const getUserFriendlyMessage = (error) => {
  if (error instanceof AppError) {
    const baseMessage = ErrorMessages[error.code] || error.message
    return baseMessage
  }
  
  if (error.code && ErrorMessages[error.code]) {
    return ErrorMessages[error.code]
  }
  
  return error.message || ErrorMessages[ErrorCodes.UNKNOWN_ERROR]
}

export const createErrorToast = (error) => {
  const message = getUserFriendlyMessage(error)
  const code = error instanceof AppError ? error.code : error.code || ErrorCodes.UNKNOWN_ERROR
  
  return {
    type: 'error',
    title: `错误 (${code})`,
    message,
    duration: 5000
  }
}

export const isRecoverableError = (error) => {
  const recoverableCodes = [
    ErrorCodes.NETWORK_ERROR,
    ErrorCodes.WEBSOCKET_DISCONNECT,
    ErrorCodes.AUTH_ERROR
  ]
  
  if (error instanceof AppError) {
    return recoverableCodes.includes(error.code)
  }
  
  return false
}

export const getErrorSuggestion = (error) => {
  const suggestions = {
    [ErrorCodes.NETWORK_ERROR]: '请检查网络连接后重试',
    [ErrorCodes.WEBSOCKET_DISCONNECT]: '正在尝试重新连接...',
    [ErrorCodes.WEBSOCKET_ERROR]: '请刷新页面重试',
    [ErrorCodes.INVALID_TARGET]: '请输入有效的URL或域名，如 http://example.com',
    [ErrorCodes.INVALID_SCRIPT]: '请检查脚本语法和内容，确保包含 run(target) 函数',
    [ErrorCodes.FILE_TOO_LARGE]: '请上传小于500KB的文件',
    [ErrorCodes.UNSUPPORTED_FORMAT]: '仅支持 .py 格式的Python脚本文件',
    [ErrorCodes.SERVER_ERROR]: '请稍后重试，或联系技术支持'
  }
  
  const code = error instanceof AppError ? error.code : error.code
  return suggestions[code] || '请稍后重试'
}

export default {
  AppError,
  ErrorCodes,
  ErrorMessages,
  handleError,
  getUserFriendlyMessage,
  createErrorToast,
  isRecoverableError,
  getErrorSuggestion
}
