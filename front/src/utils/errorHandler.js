/**
 * 全局错误处理工具
 */

/**
 * 错误类型枚举
 */
export const ErrorType = {
  NETWORK_ERROR: 'NETWORK_ERROR',
  API_ERROR: 'API_ERROR',
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  AUTH_ERROR: 'AUTH_ERROR',
  UNKNOWN_ERROR: 'UNKNOWN_ERROR'
}

/**
 * 错误类
 */
export class AppError extends Error {
  constructor(message, type = ErrorType.UNKNOWN_ERROR, statusCode = null, details = null) {
    super(message)
    this.name = 'AppError'
    this.type = type
    this.statusCode = statusCode
    this.details = details
  }
}

/**
 * 错误处理器类
 */
class ErrorHandler {
  constructor() {
    this.errorHandlers = new Map()
    this.globalErrorHandler = null
  }

  /**
   * 注册错误处理器
   */
  register(errorType, handler) {
    this.errorHandlers.set(errorType, handler)
  }

  /**
   * 设置全局错误处理器
   */
  setGlobalHandler(handler) {
    this.globalErrorHandler = handler
  }

  /**
   * 处理错误
   */
  handle(error) {
    console.error('发生错误:', error)

    // 转换为AppError
    const appError = this.normalizeError(error)

    // 调用特定类型的错误处理器
    const handler = this.errorHandlers.get(appError.type)
    if (handler) {
      return handler(appError)
    }

    // 调用全局错误处理器
    if (this.globalErrorHandler) {
      return this.globalErrorHandler(appError)
    }

    // 默认处理
    return this.defaultHandler(appError)
  }

  /**
   * 标准化错误
   */
  normalizeError(error) {
    // 网络错误
    if (error.name === 'TypeError' && error.message.includes('fetch')) {
      return new AppError(
        '网络连接失败，请检查网络设置',
        ErrorType.NETWORK_ERROR
      )
    }

    // API错误
    if (error.response) {
      const statusCode = error.response.status
      let message = error.response.data?.message || '请求失败'
      let type = ErrorType.API_ERROR

      if (statusCode === 401) {
        message = '未授权，请重新登录'
        type = ErrorType.AUTH_ERROR
      } else if (statusCode === 403) {
        message = '没有权限访问'
        type = ErrorType.AUTH_ERROR
      } else if (statusCode === 422) {
        message = '请求数据验证失败'
        type = ErrorType.VALIDATION_ERROR
      } else if (statusCode >= 500) {
        message = '服务器错误，请稍后重试'
      }

      return new AppError(message, type, statusCode, error.response.data)
    }

    // 已经是AppError
    if (error instanceof AppError) {
      return error
    }

    // 其他错误
    return new AppError(
      error.message || '发生未知错误',
      ErrorType.UNKNOWN_ERROR,
      null,
      error
    )
  }

  /**
   * 默认错误处理器
   */
  defaultHandler(error) {
    // 显示用户友好的错误消息
    if (typeof window !== 'undefined') {
      // 在浏览器环境中显示错误
      this.showErrorToast(error.message)
    }

    return error
  }

  /**
   * 显示错误提示
   */
  showErrorToast(message) {
    // 如果使用了toast库，可以在这里调用
    // 这里使用简单的alert作为后备
    if (typeof alert !== 'undefined') {
      alert(message)
    }
  }
}

// 创建全局错误处理器实例
export const errorHandler = new ErrorHandler()

// 设置默认的全局错误处理器
errorHandler.setGlobalHandler((error) => {
  console.error('全局错误:', error)
  
  // 根据错误类型进行不同处理
  switch (error.type) {
    case ErrorType.NETWORK_ERROR:
      errorHandler.showErrorToast('网络连接失败，请检查您的网络设置')
      break
    case ErrorType.AUTH_ERROR:
      errorHandler.showErrorToast(error.message)
      // 可以在这里跳转到登录页面
      // window.location.href = '/login'
      break
    case ErrorType.VALIDATION_ERROR:
      errorHandler.showErrorToast('输入数据有误，请检查后重试')
      break
    default:
      errorHandler.showErrorToast(error.message || '操作失败，请稍后重试')
  }
})

/**
 * Vue插件：全局错误处理
 */
export const ErrorHandlerPlugin = {
  install(app) {
    // 提供全局错误处理器
    app.config.errorHandler = (err, vm, info) => {
      console.error('Vue错误:', err, info)
      errorHandler.handle(err)
    }

    // 提供全局属性
    app.provide('errorHandler', errorHandler)
  }
}

/**
 * 异步错误处理装饰器
 */
export function withErrorHandler(asyncFn) {
  return async function(...args) {
    try {
      return await asyncFn.apply(this, args)
    } catch (error) {
      errorHandler.handle(error)
      throw error // 重新抛出错误，让调用者可以处理
    }
  }
}

export default errorHandler
