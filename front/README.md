# WebScan AI - 前端项目

> ⚠️ **注意**: 这是旧版前端项目，已不再维护。建议使用新版前端项目 [TOSKillfront](../TOSKillfront/)。

<div align="center">

![Vue](https://img.shields.io/badge/vue-3.5+-brightgreen.svg)
![Vite](https://img.shields.io/badge/vite-5.4+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)
![Status](https://img.shields.io/badge/status-deprecated-red.svg)

**WebScan AI Security Platform 前端界面（旧版）**

基于 Vue 3 + Vite + Element Plus 构建的现代化Web应用安全扫描平台前端

[功能特性](#-功能特性) • [快速开始](#-快速开始) • [项目结构](#-项目结构) • [开发指南](#-开发指南)

</div>

---

## 📋 目录

- [项目简介](#-项目简介)
- [功能特性](#-功能特性)
- [技术栈](#-技术栈)
- [快速开始](#-快速开始)
- [项目结构](#-项目结构)
- [开发指南](#-开发指南)
- [组件说明](#-组件说明)
- [API集成](#api集成)
- [样式系统](#-样式系统)
- [部署指南](#-部署指南)
- [常见问题](#-常见问题)

---

## 🎯 项目简介

WebScan AI 前端是 WebScan AI Security Platform 的用户界面部分，提供直观、专业的安全扫描管理界面。采用现代化的 Vue 3 框架构建，具有响应式设计，支持桌面、平板和手机设备。

### 核心特点

- 🎨 **专业简洁的界面设计** - 符合安全工具的专业形象
- 📊 **智能数据可视化** - 直观的图表和统计信息
- 🚀 **高性能渲染** - 基于 Vite 的快速构建和热更新
- 📱 **完全响应式** - 适配各种屏幕尺寸
- 🔧 **模块化架构** - 组件化开发，易于维护和扩展
- 🤖 **AI 集成** - 集成 AI Agent 和智能对话功能

---

## ✨ 功能特性

### 核心功能模块

| 模块 | 功能描述 | 状态 |
|------|---------|------|
| **仪表盘** | 实时显示扫描统计、漏洞趋势、最新结果 | ✅ 已实现 |
| **扫描任务管理** | 创建、监控、管理扫描任务 | ✅ 已实现 |
| **POC扫描** | POC 漏洞扫描和验证 | ✅ 已实现 |
| **漏洞结果展示** | 按优先级展示漏洞，支持筛选和搜索 | ✅ 已实现 |
| **漏洞详情** | 详细的漏洞信息、技术细节、修复建议 | ✅ 已实现 |
| **报告生成** | 支持HTML、PDF、JSON多种格式报告 | ✅ 已实现 |
| **系统设置** | 灵活的配置选项和规则管理 | ✅ 已实现 |
| **AWVS扫描** | 集成Acunetix Web Vulnerability Scanner | ✅ 已实现 |
| **AI Agent扫描** | 基于LangGraph的智能代理扫描 | ✅ 已实现 |
| **漏洞知识库** | 查询和管理漏洞知识库信息 | ✅ 已实现 |
| **通知中心** | 实时通知和消息管理 | ✅ 已实现 |
| **个人资料** | 用户信息管理 | ✅ 已实现 |

### 交互特性

- 🔔 **实时通知** - 扫描进度和结果实时推送
- 🔍 **智能搜索** - 快速查找漏洞和任务
- 📋 **批量操作** - 支持多选和批量处理
- 🎯 **快捷操作** - 一键跳转和快速访问
- 💾 **本地缓存** - 提升用户体验和性能
- 🤖 **AI 对话** - 智能安全咨询和分析

---

## 🛠 技术栈

### 核心框架

```json
{
  "vue": "^3.5.24",           // Vue 3 核心框架
  "vue-router": "^4.5.24",     // 官方路由管理器
  "pinia": "^2.3.0",          // 状态管理库
  "axios": "^1.7.9",          // HTTP 客户端
  "element-plus": "^2.8.0"    // UI 组件库
}
```

### 构建工具

```json
{
  "vite": "^5.4.0",                    // 下一代前端构建工具
  "@vitejs/plugin-vue": "^5.2.1"      // Vue 3 插件
}
```

### 开发工具

```json
{
  "eslint": "^9.17.0",                // 代码检查工具
  "eslint-plugin-vue": "^9.31.0",     // Vue 代码规范插件
  "vitest": "^2.1.8",                 // 单元测试框架
  "@vue/test-utils": "^2.4.6"        // Vue 测试工具
}
```

### 数据可视化

```json
{
  "chart.js": "^4.4.0"                // 图表库
}
```

### 技术特点

- **Composition API** - 使用 Vue 3 的组合式 API
- **单文件组件** - .vue 文件格式
- **模块化路由** - 基于文件的路由配置
- **CSS 变量** - 现代化的样式系统
- **ES6+** - 使用现代 JavaScript 特性
- **Axios** - HTTP 请求封装
- **Pinia** - 状态管理
- **Element Plus** - UI 组件库

---

## 🚀 快速开始

### 环境要求

- Node.js 16.0 或更高版本
- npm 7.0 或更高版本（或 yarn 1.22+）

### 安装步骤

#### 1. 安装依赖

```bash
npm install
```

或使用 yarn：

```bash
yarn install
```

#### 2. 开发模式

```bash
npm run dev
```

开发服务器将运行在：http://localhost:5173

#### 3. 构建生产版本

```bash
npm run build
```

构建产物将输出到 `dist/` 目录

#### 4. 预览生产版本

```bash
npm run preview
```

#### 5. 运行测试

```bash
npm run test              # 运行测试
npm run test:ui          # 运行测试 UI
npm run test:coverage     # 生成覆盖率报告
```

#### 6. 代码检查

```bash
npm run lint              # 运行 ESLint
```

---

## 📁 项目结构

```
front/
├── public/                      # 静态资源
│   └── favicon.ico             # 网站图标
├── src/                        # 源代码目录
│   ├── components/             # 组件
│   │   ├── business/          # 业务组件
│   │   │   ├── AWVSScanForm.vue      # AWVS扫描表单
│   │   │   ├── AgentScanForm.vue     # Agent扫描表单
│   │   │   ├── POCScanForm.vue       # POC扫描表单
│   │   │   ├── TaskCard.vue          # 任务卡片
│   │   │   └── VulnerabilityCard.vue # 漏洞卡片
│   │   ├── common/            # 通用组件
│   │   │   ├── Alert.vue            # 提示组件
│   │   │   ├── AppIcon.vue          # 图标组件
│   │   │   ├── BaseForm.vue         # 基础表单
│   │   │   ├── BaseModal.vue        # 基础模态框
│   │   │   ├── DataTable.vue        # 数据表格
│   │   │   ├── Loading.vue          # 加载组件
│   │   │   ├── StatCard.vue         # 统计卡片
│   │   │   └── Toast.vue            # 提示消息
│   │   └── layout/            # 布局组件
│   │       └── AppLayout.vue        # 主布局
│   ├── views/                  # 页面视图
│   │   ├── Dashboard.vue           # 仪表盘页面
│   │   ├── ScanTasks.vue           # 扫描任务管理
│   │   ├── POCScan.vue             # POC扫描页面
│   │   ├── VulnerabilityResults.vue # 漏洞结果列表
│   │   ├── VulnerabilityDetail.vue  # 漏洞详情
│   │   ├── Reports.vue             # 报告管理
│   │   ├── ReportDetail.vue        # 报告详情
│   │   ├── Settings.vue            # 系统设置
│   │   ├── AWVSScan.vue            # AWVS扫描页面
│   │   ├── AgentScan.vue           # AI Agent扫描页面
│   │   ├── KnowledgeBase.vue       # 漏洞知识库
│   │   ├── Notifications.vue        # 通知中心
│   │   ├── NotificationDetail.vue   # 通知详情
│   │   ├── Profile.vue             # 个人资料
│   │   └── NotFound.vue            # 404页面
│   ├── router/                 # 路由配置
│   │   └── index.js            # 路由定义
│   ├── store/                  # 状态管理
│   │   ├── index.js            # Store入口
│   │   ├── tasks.js            # 任务状态
│   │   ├── vulnerabilities.js  # 漏洞状态
│   │   └── settings.js         # 设置状态
│   ├── styles/                 # 样式文件
│   │   ├── buttons.css         # 按钮样式
│   │   ├── icons.css           # 图标样式
│   │   ├── responsive.css      # 响应式样式
│   │   ├── theme.js            # 主题配置
│   │   └── transitions.css     # 过渡动画
│   ├── utils/                  # 工具函数
│   │   ├── api.js              # API请求封装
│   │   ├── apiResponse.js      # API响应处理
│   │   ├── date.js             # 日期工具
│   │   ├── errorHandler.js     # 错误处理
│   │   ├── helpers.js          # 辅助函数
│   │   ├── icons.js            # 图标工具
│   │   ├── loading.js          # 加载工具
│   │   ├── toast.js            # 提示工具
│   │   ├── validators.js       # 表单验证
│   │   ├── websocket.js        # WebSocket
│   │   └── aiAgents.js         # AI Agent工具
│   ├── App.vue                 # 根组件
│   ├── main.js                 # 应用入口
│   ├── style.css               # 全局样式
│   ├── auto-imports.d.ts       # 自动导入类型
│   └── components.d.ts          # 组件类型
├── tests/                      # 测试文件
│   ├── unit/                   # 单元测试
│   │   ├── api.test.js
│   │   ├── notifications.test.js
│   │   ├── profile.test.js
│   │   └── vulnerability-results.test.js
│   ├── api.test.js             # API测试
│   ├── components.test.js      # 组件测试
│   ├── setup.js                # 测试配置
│   └── README.md               # 测试文档
├── .env                        # 环境变量
├── .env.development            # 开发环境变量
├── .env.production             # 生产环境变量
├── .env.test                   # 测试环境变量
├── .gitignore                  # Git忽略文件
├── index.html                  # HTML模板
├── package.json                # 项目配置
├── vite.config.js              # Vite配置
├── vitest.config.js            # Vitest配置
├── eslint.config.js            # ESLint配置
└── README.md                   # 项目说明
```

---

## 💻 开发指南

### 开发环境配置

#### 1. 配置 API 地址

在 `.env.development` 文件中配置后端 API 地址：

```env
VITE_API_BASE_URL=http://127.0.0.1:8888/api
VITE_REQUEST_TIMEOUT=8880
```

在 `.env.production` 文件中配置生产环境 API 地址：

```env
VITE_API_BASE_URL=https://your-api-domain.com/api
VITE_REQUEST_TIMEOUT=8880
```

#### 2. 开发模式启动

```bash
npm run dev
```

访问 http://localhost:5173 查看应用

### 添加新页面

#### 1. 创建页面组件

在 `src/views/` 目录下创建新的 Vue 组件：

```vue
<template>
  <div class="page-container">
    <div class="page-header">
      <h1>新页面标题</h1>
      <p class="subtitle">页面描述</p>
    </div>
    <!-- 页面内容 -->
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'

// 组件逻辑
const data = ref([])

onMounted(() => {
  // 组件挂载后执行
})
</script>

<style scoped>
/* 页面样式 */
</style>
```

#### 2. 配置路由

在 `src/router/index.js` 中添加路由：

```javascript
import NewPage from '../views/NewPage.vue'

const routes = [
  // 其他路由...
  {
    path: '/new-page',
    name: 'NewPage',
    component: NewPage,
    meta: {
      title: '新页面',
      requiresAuth: false
    }
  }
]
```

### 添加新组件

#### 1. 创建组件

在 `src/components/` 目录下创建组件：

```vue
<template>
  <div class="my-component">
    <!-- 组件内容 -->
  </div>
</template>

<script setup>
import { defineProps, defineEmits } from 'vue'

const props = defineProps({
  // 组件属性
})

const emit = defineEmits(['event-name'])
</script>

<style scoped>
/* 组件样式 */
</style>
```

#### 2. 使用组件

在页面中引入和使用：

```vue
<template>
  <div>
    <MyComponent @event-name="handleEvent" />
  </div>
</template>

<script setup>
import MyComponent from '@/components/MyComponent.vue'

const handleEvent = (data) => {
  // 处理事件
}
</script>
```

---

## 📦 组件说明

### 布局组件

#### AppLayout.vue
主布局组件，包含：
- 顶部导航栏
- 侧边菜单
- 内容区域
- 页脚

### 业务组件

#### AWVSScanForm.vue
AWVS 扫描表单组件，功能：
- 输入扫描目标 URL
- 选择扫描类型
- 配置扫描选项
- 提交扫描任务

#### AgentScanForm.vue
AI Agent 扫描表单组件，功能：
- 输入扫描目标
- 配置 Agent 参数
- 选择扫描策略
- 提交 Agent 任务

#### POCScanForm.vue
POC 扫描表单组件，功能：
- 选择 POC 类型
- 配置扫描参数
- 上传自定义 POC
- 提交扫描任务

#### TaskCard.vue
任务卡片组件，显示：
- 任务基本信息
- 任务状态
- 任务进度
- 快速操作按钮

#### VulnerabilityCard.vue
漏洞卡片组件，显示：
- 漏洞基本信息
- 严重程度
- 漏洞状态
- 查看详情链接

### 通用组件

#### Alert.vue
提示组件，支持：
- 成功、警告、错误、信息提示
- 可关闭
- 自动消失

#### DataTable.vue
数据表格组件，支持：
- 排序
- 筛选
- 分页
- 多选

#### Loading.vue
加载组件，支持：
- 骨架屏
- 加载动画
- 自定义加载文案

#### StatCard.vue
统计卡片组件，显示：
- 统计数值
- 图标
- 标签
- 趋势

#### Toast.vue
提示消息组件，支持：
- 多种类型提示
- 位置配置
- 自动消失

### 页面组件

#### Dashboard.vue
仪表盘页面，展示：
- 统计数据卡片
- 趋势图表
- 最新扫描结果
- 快速操作按钮

#### ScanTasks.vue
扫描任务管理页面，功能：
- 任务列表展示
- 创建新任务
- 任务状态监控
- 批量操作

#### POCScan.vue
POC 扫描页面，功能：
- POC 扫描表单
- 扫描结果展示
- POC 验证
- 结果导出

#### VulnerabilityResults.vue
漏洞结果列表页面，功能：
- 漏洞列表展示
- 多维度筛选
- 关键词搜索
- 状态管理

#### VulnerabilityDetail.vue
漏洞详情页面，展示：
- 基本信息
- 技术细节
- AI 分析结果
- 修复建议

#### Reports.vue
报告管理页面，功能：
- 报告列表
- 生成新报告
- 下载报告
- 报告预览

#### ReportDetail.vue
报告详情页面，展示：
- 报告内容
- 漏洞统计
- 修复建议
- 导出选项

#### Settings.vue
系统设置页面，功能：
- 基本配置
- 扫描规则
- 通知设置
- 用户信息

#### AWVSScan.vue
AWVS 扫描页面，功能：
- 创建 AWVS 扫描任务
- 监控扫描进度
- 查看扫描结果
- 管理扫描配置

#### AgentScan.vue
AI Agent 扫描页面，功能：
- 创建 Agent 扫描任务
- 监控 Agent 执行
- 查看 Agent 结果
- 任务历史记录

#### KnowledgeBase.vue
漏洞知识库页面，功能：
- 搜索漏洞
- 查看漏洞详情
- 同步漏洞数据
- 管理知识库

#### Notifications.vue
通知中心页面，功能：
- 通知列表
- 标记已读
- 删除通知
- 通知筛选

#### NotificationDetail.vue
通知详情页面，展示：
- 通知内容
- 相关链接
- 操作按钮

#### Profile.vue
个人资料页面，功能：
- 用户信息编辑
- 密码修改
- 偏好设置

---

## 🔌 API 集成

### API 请求封装

在 `src/utils/api.js` 中封装了 API 请求：

```javascript
import axios from 'axios'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8888/api'
const REQUEST_TIMEOUT = parseInt(import.meta.env.VITE_REQUEST_TIMEOUT) || 8880

const instance = axios.create({
  baseURL: API_BASE_URL,
  timeout: REQUEST_TIMEOUT,
  headers: {
    'Content-Type': 'application/json'
  }
})

// 请求拦截器
instance.interceptors.request.use(config => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// 响应拦截器
instance.interceptors.response.use(
  response => response.data,
  error => {
    // 错误处理
    return Promise.reject(error)
  }
)

export function request(config) {
  return instance(config)
}
```

### API 模块

#### scanApi - 扫描相关 API
```javascript
export const scanApi = {
  startScan: async (data) => request({ url: '/scan/start', method: 'post', data }),
  getScanStatus: async (scanId) => request({ url: `/scan/status/${scanId}`, method: 'get' }),
  getScanResults: async (scanId) => request({ url: `/scan/results/${scanId}`, method: 'get' }),
  stopScan: async (scanId) => request({ url: `/scan/stop/${scanId}`, method: 'post' }),
  portScan: async (data) => request({ url: '/scan/port-scan', method: 'post', data }),
  infoLeak: async (data) => request({ url: '/scan/info-leak', method: 'post', data }),
  dirScan: async (data) => request({ url: '/scan/dir-scan', method: 'post', data })
}
```

#### awvsApi - AWVS 相关 API
```javascript
export const awvsApi = {
  getScans: async () => request({ url: '/awvs/scans', method: 'get' }),
  createScan: async (data) => request({ url: '/awvs/scan', method: 'post', data }),
  getVulnerabilities: async (targetId) => request({ url: `/awvs/vulnerabilities/${targetId}`, method: 'get' }),
  getVulnerabilityDetail: async (vulnId) => request({ url: `/awvs/vulnerability/${vulnId}`, method: 'get' }),
  getTargets: async () => request({ url: '/awvs/targets', method: 'get' }),
  addTarget: async (data) => request({ url: '/awvs/target', method: 'post', data })
}
```

#### agentApi - AI Agent 相关 API
```javascript
export const agentApi = {
  startScan: async (data) => request({ url: '/agent/scan', method: 'post', data }),
  getTasks: async () => request({ url: '/agent/tasks', method: 'get' }),
  getTaskDetail: async (taskId) => request({ url: `/agent/tasks/${taskId}`, method: 'get' }),
  getTaskResult: async (taskId) => request({ url: `/agent/tasks/${taskId}/result`, method: 'get' })
}
```

#### kbApi - 知识库相关 API
```javascript
export const kbApi = {
  getVulnerabilities: async (params) => request({ url: '/kb/vulnerabilities', method: 'get', params }),
  getVulnerabilityDetail: async (vulnId) => request({ url: `/kb/vulnerabilities/${vulnId}`, method: 'get' }),
  syncVulnerabilities: async () => request({ url: '/kb/sync', method: 'post' })
}
```

#### notificationsApi - 通知相关 API
```javascript
export const notificationsApi = {
  getNotifications: async (params) => request({ url: '/notifications', method: 'get', params }),
  markAsRead: async (id) => request({ url: `/notifications/${id}/read`, method: 'put' }),
  markAllAsRead: async () => request({ url: '/notifications/read-all', method: 'put' }),
  deleteNotification: async (id) => request({ url: `/notifications/${id}`, method: 'delete' })
}
```

### 状态管理 (Pinia)

#### tasks.js - 任务状态管理
```javascript
import { defineStore } from 'pinia'

export const useTaskStore = defineStore('tasks', {
  state: () => ({
    tasks: [],
    currentTask: null,
    loading: false
  }),
  actions: {
    async fetchTasks() { },
    async createTask(data) { },
    async updateTask(id, data) { },
    async deleteTask(id) { }
  }
})
```

#### vulnerabilities.js - 漏洞状态管理
```javascript
import { defineStore } from 'pinia'

export const useVulnerabilityStore = defineStore('vulnerabilities', {
  state: () => ({
    vulnerabilities: [],
    currentVulnerability: null,
    filters: {},
    loading: false
  }),
  actions: {
    async fetchVulnerabilities() { },
    async fetchVulnerabilityDetail(id) { },
    setFilters(filters) { }
  }
})
```

#### settings.js - 设置状态管理
```javascript
import { defineStore } from 'pinia'

export const useSettingsStore = defineStore('settings', {
  state: () => ({
    settings: {},
    loading: false
  }),
  actions: {
    async fetchSettings() { },
    async updateSettings(data) { }
  }
})
```

---

## 🎨 样式系统

### CSS 变量

在 `src/styles/theme.js` 中定义了主题变量：

```javascript
export const theme = {
  colors: {
    primary: '#1a3a6c',
    secondary: '#4a90e2',
    success: '#2ecc71',
    warning: '#f5a623',
    danger: '#e74c3c',
    info: '#3498db',
    highRisk: '#e74c3c',
    mediumRisk: '#f5a623',
    lowRisk: '#f1c40f'
  },
  spacing: {
    xs: '4px',
    sm: '8px',
    md: '16px',
    lg: '24px',
    xl: '32px'
  },
  borderRadius: {
    sm: '4px',
    md: '8px',
    lg: '12px'
  }
}
```

### 响应式断点

```css
/* 移动设备 */
@media (max-width: 768px) {
  /* 移动端样式 */
}

/* 平板设备 */
@media (min-width: 769px) and (max-width: 1024px) {
  /* 平板样式 */
}

/* 桌面设备 */
@media (min-width: 1025px) {
  /* 桌面样式 */
}
```

---

## 🚀 部署指南

### 构建生产版本

```bash
npm run build
```

构建产物将输出到 `dist/` 目录

### 部署到 Nginx

#### 1. 安装 Nginx

```bash
# Ubuntu/Debian
sudo apt-get install nginx

# CentOS/RHEL
sudo yum install nginx
```

#### 2. 配置 Nginx

创建配置文件 `/etc/nginx/sites-available/webscan-ai`：

```nginx
server {
    listen 80;
    server_name your-domain.com;

    root /path/to/front/dist;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api {
        proxy_pass http://127.0.0.1:8888;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### 3. 启用配置

```bash
sudo ln -s /etc/nginx/sites-available/webscan-ai /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 部署到 Vercel

#### 1. 安装 Vercel CLI

```bash
npm install -g vercel
```

#### 2. 部署

```bash
vercel
```

### 部署到 Docker

创建 `Dockerfile`：

```dockerfile
# 构建阶段
FROM node:18-alpine as build-stage
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

# 生产阶段
FROM nginx:stable-alpine as production-stage
COPY --from=build-stage /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

构建和运行：

```bash
docker build -t webscan-ai-front .
docker run -d -p 80:80 webscan-ai-front
```

---

## ❓ 常见问题

### 1. 安装依赖失败

**问题**: npm install 报错

**解决方案**:
```bash
# 清除缓存
npm cache clean --force

# 删除 node_modules 和 package-lock.json
rm -rf node_modules package-lock.json

# 重新安装
npm install
```

### 2. 开发服务器启动失败

**问题**: 端口 5173 被占用

**解决方案**:
```bash
# 修改 vite.config.js 中的端口配置
export default defineConfig({
  server: {
    port: 8888  // 修改为其他端口
  }
})
```

### 3. 构建失败

**问题**: npm run build 报错

**解决方案**:
```bash
# 检查 Node.js 版本
node --version  # 应该 >= 16.0

# 更新依赖
npm update

# 清除缓存重新构建
npm run build
```

### 4. API 请求失败

**问题**: 前端无法连接后端

**解决方案**:
1. 检查后端服务是否正常运行
2. 检查 API 地址配置是否正确
3. 检查 CORS 配置
4. 查看浏览器控制台错误信息

### 5. 样式不生效

**问题**: 修改样式后没有效果

**解决方案**:
```bash
# 清除浏览器缓存
# 或使用硬刷新 Ctrl + Shift + R

# 清除构建缓存
rm -rf node_modules/.vite
npm run dev
```

### 6. 路由刷新404

**问题**: 刷新页面时出现404错误

**解决方案**:
确保 Nginx 或其他 Web 服务器配置了 SPA 路由回退：

```nginx
location / {
    try_files $uri $uri/ /index.html;
}
```

---

## 📚 相关文档

- [Vue 3 官方文档](https://vuejs.org/)
- [Vite 官方文档](https://vitejs.dev/)
- [Vue Router 文档](https://router.vuejs.org/)
- [Pinia 文档](https://pinia.vuejs.org/)
- [Element Plus 文档](https://element-plus.org/)
- [Axios 文档](https://axios-http.com/)
- [Chart.js 文档](https://www.chartjs.org/)
- [后端 API 文档](../backend/README.md)
- [项目根目录 README](../README.md)

---

## 🤝 贡献指南

我们欢迎任何形式的贡献！

### 贡献流程

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

### 代码规范

- 使用 ESLint 进行代码检查
- 遵循 Vue 3 风格指南
- 组件命名使用 PascalCase
- 文件命名使用 kebab-case

---

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](../LICENSE) 文件了解详情

---

## 📞 联系方式

- 项目主页: https://github.com/yourusername/webscan-ai
- 问题反馈: https://github.com/yourusername/webscan-ai/issues
- 邮箱: your.email@example.com

---

<div align="center">

**如果这个项目对您有帮助，请给我们一个 ⭐️**

Made with ❤️ by WebScan AI Team

</div>
