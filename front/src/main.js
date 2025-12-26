import { createApp } from 'vue'
import './style.css'
import App from './App.vue'
import router from './router'
import { ErrorHandlerPlugin } from './utils/errorHandler.js'
import { LoadingPlugin } from './utils/loading.js'

const app = createApp(App)

// 注册全局插件
app.use(router)
app.use(ErrorHandlerPlugin)
app.use(LoadingPlugin)

// 全局错误捕获
window.addEventListener('unhandledrejection', (event) => {
  console.error('未处理的Promise拒绝:', event.reason)
  event.preventDefault()
})

window.addEventListener('error', (event) => {
  console.error('全局错误:', event.error)
})

app.mount('#app')