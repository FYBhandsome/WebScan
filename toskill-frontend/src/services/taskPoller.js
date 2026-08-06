// src/services/taskPoller.js
//
// 任务状态轮询模块（Task 6.1）
//
// 用途：作为 WebSocket 推送的【补充/兜底】通道，按 task_id 周期性拉取
// GET /api/scan/tasks/{task_id}/status。WebSocket 断开时轮询仍可独立工作，
// 保证前端不丢失任务状态可见性。
//
// 设计要点：
//  - 轮询是 WS 的补充，不替换 WS；组件应同时保留 WS 监听。
//  - 首次拉取立即执行（不等第一个 interval），让 UI 尽快拿到初态。
//  - status 命中终态（completed / exception）时自动停止轮询。
//  - fetch 失败不中断轮询（网络抖动容错），仅 console.warn 并继续。
//  - 通过 _pollingPromise 串行化，避免上一次 fetch 未返回时重复发起。
//  - 组件卸载时必须调用 stop() / stopPolling() 防止泄漏。

import { API } from './api.js';

/** 命中后自动停止轮询的终态状态集合 */
const TERMINAL_STATUSES = ['completed', 'exception'];

/**
 * 任务轮询器。
 *
 * 用法（实例化）：
 *   const poller = new TaskPoller({ interval: 2000 });
 *   poller.start(taskId, (statusObj) => { ... });
 *   // ...
 *   poller.stop();
 *
 * 或使用模块级便捷函数 startPolling / stopPolling（单例）。
 */
export class TaskPoller {
  /**
   * @param {Object} [options]
   * @param {number} [options.interval=2000] 轮询间隔（毫秒）
   * @param {(err: Error) => void} [options.onError] 每次 fetch 失败时的回调（可选）
   */
  constructor(options = {}) {
    /** 轮询间隔（毫秒） */
    this.interval = options.interval || 2000;
    /** fetch 失败回调 */
    this.onError = options.onError || null;

    /** 当前轮询的任务 ID（停止后置 null） */
    this.taskId = null;
    /** 状态回调 */
    this.onStatus = null;

    this._timerId = null;
    this._isPolling = false;
    /** 串行化守卫：指向正在进行的 fetch Promise，避免重叠请求 */
    this._inflight = null;
  }

  /** 是否正在轮询 */
  get isPolling() {
    return this._isPolling;
  }

  /**
   * 启动轮询。若当前已在轮询，会先停止旧轮询再启动新的。
   *
   * @param {string} taskId 任务 ID
   * @param {(status: Object) => void} onStatus 每次拿到状态的回调
   * @param {Object} [options] 运行时覆盖配置
   * @param {number} [options.interval] 覆盖轮询间隔
   * @param {(err: Error) => void} [options.onError] 覆盖错误回调
   * @returns {TaskPoller} this（便于链式调用）
   */
  start(taskId, onStatus, options = {}) {
    if (!taskId) {
      console.warn('[TaskPoller] start: taskId 为空，已忽略');
      return this;
    }
    // 若已在轮询，先停止（切换任务）
    if (this._isPolling) {
      this.stop();
    }
    this.taskId = taskId;
    this.onStatus = typeof onStatus === 'function' ? onStatus : null;
    if (typeof options.interval === 'number' && options.interval > 0) {
      this.interval = options.interval;
    }
    if (typeof options.onError === 'function') {
      this.onError = options.onError;
    }

    this._isPolling = true;
    // 首次立即拉取一次，让 UI 尽快拿到初态
    this._fetchOnce();
    this._timerId = setInterval(() => this._fetchOnce(), this.interval);
    return this;
  }

  /**
   * 停止轮询并清理定时器。可在 onStatus 回调内部安全调用。
   */
  stop() {
    this._isPolling = false;
    if (this._timerId !== null) {
      clearInterval(this._timerId);
      this._timerId = null;
    }
    this.taskId = null;
    this.onStatus = null;
  }

  /**
   * 执行一次状态拉取。串行化，不会与上一次请求重叠。
   * @private
   */
  _fetchOnce() {
    if (!this._isPolling || !this.taskId) return;
    if (this._inflight) return; // 上一次还没返回，跳过本轮

    const taskId = this.taskId;
    this._inflight = (async () => {
      try {
        const status = await API.getTaskStatus(taskId);
        // fetch 期间可能已被 stop()
        if (!this._isPolling) return;

        if (this.onStatus) {
          try {
            this.onStatus(status);
          } catch (cbErr) {
            // 回调异常不应中断轮询
            console.warn('[TaskPoller] onStatus 回调抛错:', cbErr);
          }
        }

        // 命中终态自动停止（completed / exception）
        const st = status && status.status;
        if (TERMINAL_STATUSES.includes(st)) {
          this.stop();
        }
      } catch (err) {
        // 网络抖动 / 端点临时不可用 —— 不中断轮询，仅告警
        console.warn(`[TaskPoller] 拉取任务 ${taskId} 状态失败:`, err);
        if (this.onError) {
          try {
            this.onError(err);
          } catch (e) {
            /* 吞掉错误回调自身的异常 */
          }
        }
      } finally {
        this._inflight = null;
      }
    })();
  }
}

// ===========================================================================
// 模块级单例便捷函数（适合一个页面只跟踪一个任务的简单场景）
// 组件需要跟踪多个任务时请直接 new TaskPoller()。
// ===========================================================================

let _defaultPoller = null;

/**
 * 启动轮询（单例）。复用同一个 TaskPoller 实例，切换任务时自动停止旧的。
 *
 * @param {string} taskId 任务 ID
 * @param {(status: Object) => void} onStatus 状态回调
 * @param {Object} [options] { interval?, onError? }
 * @returns {TaskPoller}
 */
export function startPolling(taskId, onStatus, options = {}) {
  if (!_defaultPoller) {
    _defaultPoller = new TaskPoller();
  }
  return _defaultPoller.start(taskId, onStatus, options);
}

/**
 * 停止单例轮询。
 */
export function stopPolling() {
  if (_defaultPoller) {
    _defaultPoller.stop();
  }
}

/**
 * 查询单例是否正在轮询。
 * @returns {boolean}
 */
export function isPolling() {
  return _defaultPoller ? _defaultPoller.isPolling : false;
}
