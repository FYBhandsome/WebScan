<template>
  <div class="app-container">
    <AppHeader :status="connectionStatus" />

    <div class="app-body">
      <AppSidebar :currentPage="currentPage" @navigate="handleNavigation" />

      <main class="main-content">
        <!-- 页面路由 -->
        <ConsoleView v-show="currentPage === 'console'" />
        <ScanView v-show="currentPage === 'scan'" />
        <ToolsView v-show="currentPage === 'tools'" />
        <ReportsView v-show="currentPage === 'reports'" />
        <SettingsView v-show="currentPage === 'settings'" />
      </main>
    </div>

    <footer class="app-footer">
      <div class="target-bar">
        <span class="target-label">当前目标:</span>
        <span class="target-value">{{ globalState.currentTarget || '未设置' }}</span>
      </div>
    </footer>

    <!-- 全局 Modal 弹窗 -->
    <div class="modal-overlay" :class="{ show: globalState.modal.show }" @click.self="closeModal">
      <div class="modal-box">
        <div class="modal-header">
          <span class="modal-title">{{ globalState.modal.title }}</span>
          <span class="modal-close" @click="closeModal">×</span>
        </div>
        <!-- 使用 v-html 允许渲染 HTML 格式的提示体 -->
        <div class="modal-body" v-html="globalState.modal.body"></div>
        <div class="modal-footer">
          <button class="modal-btn cancel" @click="closeModal">取消</button>
          <button class="modal-btn confirm" @click="handleModalConfirm">确认</button>
        </div>
      </div>
    </div>

    <!-- 全局 Toast 提示 -->
    <div class="toast-container">
      <div 
        v-for="toast in globalState.toasts" 
        :key="toast.id" 
        class="toast" 
        :class="toast.type"
      >
        <span>{{ getToastIcon(toast.type) }}</span>
        <span>{{ toast.message }}</span>
      </div>
    </div>

    <!-- 浮动日志面板 -->
    <FloatingLogPanel />
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { ws } from './services/websocket.js'
import { API } from './services/api.js'
import { globalState, closeModal } from './store.js'

// 组件引入
import AppHeader from './components/AppHeader.vue'
import AppSidebar from './components/AppSidebar.vue'
import ConsoleView from './components/views/ConsoleView.vue'
import ScanView from './components/views/ScanView.vue'
import ToolsView from './components/views/ToolsView.vue'
import ReportsView from './components/views/ReportsView.vue'
import SettingsView from './components/views/SettingsView.vue'
import FloatingLogPanel from './components/FloatingLogPanel.vue'

const connectionStatus = ref('未连接')
const currentPage = ref('console')

const handleNavigation = (page) => {
  currentPage.value = page
}

const getToastIcon = (type) => {
  const icons = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' }
  return icons[type] || 'ℹ️'
}

const handleModalConfirm = () => {
  if (globalState.modal.onConfirm) {
    globalState.modal.onConfirm()
  }
  closeModal()
}

// === 应用初始化逻辑 (原 app.js init 的核心) ===
onMounted(() => {
  // 1. 加载本地设置
  const savedSettings = localStorage.getItem('toskill_settings')
  if (savedSettings) {
    try {
      const parsed = JSON.parse(savedSettings)
      if (parsed.apiUrl) API.setBaseUrl(parsed.apiUrl)
      if (parsed.wsUrl) {
        const finalWsUrl = parsed.wsUrl.includes(API.WS_PATH)
          ? parsed.wsUrl
          : parsed.wsUrl.replace(/\/$/, '') + API.WS_PATH
        ws.setUrl(finalWsUrl)
      }
    } catch (e) {
      if (import.meta.env.DEV) console.error('配置加载失败:', e)
    }
  }

  // 2. 初始化 WebSocket 连接
  connectionStatus.value = '连接中...'
  
  ws.onConnect(() => { connectionStatus.value = '已连接' })
  ws.onDisconnect(() => { connectionStatus.value = '未连接' })
  
  ws.connect().then(sessionId => {
    if (import.meta.env.DEV) console.log('应用启动: WS 连接成功，Session:', sessionId)
  }).catch(err => {
    connectionStatus.value = '连接失败'
  })
})

onUnmounted(() => {
  ws.disconnect()
})
</script>

<style>
@import './assets/style.css';
</style>
