import { createApp } from 'vue'
import './style.css'
import App from './App.vue'
import { clearExpiredData } from './store.js'

// 启动前清理过期记忆数据（TTL 24 小时）
clearExpiredData()

createApp(App).mount('#app')
