/**
 * 全局加载状态管理工具
 */

import { ref, reactive } from 'vue'

/**
 * 加载状态管理器类
 */
class LoadingManager {
  constructor() {
    this.loadingStates = reactive(new Map())
    this.globalLoading = ref(false)
    this.loadingCount = 0
  }

  /**
   * 开始加载
   */
  start(key = 'global') {
    this.loadingStates.set(key, true)
    this.loadingCount++
    this.updateGlobalLoading()
  }

  /**
   * 结束加载
   */
  end(key = 'global') {
    this.loadingStates.set(key, false)
    this.loadingCount = Math.max(0, this.loadingCount - 1)
    this.updateGlobalLoading()
  }

  /**
   * 获取加载状态
   */
  isLoading(key = 'global') {
    return this.loadingStates.get(key) || false
  }

  /**
   * 更新全局加载状态
   */
  updateGlobalLoading() {
    this.globalLoading.value = this.loadingCount > 0
  }

  /**
   * 包装异步函数，自动管理加载状态
   */
  async withLoading(asyncFn, key = 'global') {
    try {
      this.start(key)
      return await asyncFn()
    } finally {
      this.end(key)
    }
  }

  /**
   * 清除所有加载状态
   */
  clear() {
    this.loadingStates.clear()
    this.loadingCount = 0
    this.globalLoading.value = false
  }
}

// 创建全局加载状态管理器实例
export const loadingManager = new LoadingManager()

/**
 * Vue组合式函数：使用加载状态
 */
export function useLoading(key = 'global') {
  const isLoading = ref(false)
  const error = ref(null)

  const start = () => {
    isLoading.value = true
    error.value = null
    loadingManager.start(key)
  }

  const end = () => {
    isLoading.value = false
    loadingManager.end(key)
  }

  const setError = (err) => {
    error.value = err
  }

  const withLoading = async (asyncFn) => {
    try {
      start()
      return await asyncFn()
    } catch (err) {
      setError(err)
      throw err
    } finally {
      end()
    }
  }

  return {
    isLoading,
    error,
    start,
    end,
    setError,
    withLoading
  }
}

/**
 * Vue插件：全局加载状态管理
 */
export const LoadingPlugin = {
  install(app) {
    // 提供全局加载状态管理器
    app.provide('loadingManager', loadingManager)
    
    // 添加全局属性
    app.config.globalProperties.$loading = loadingManager
  }
}

export default loadingManager
