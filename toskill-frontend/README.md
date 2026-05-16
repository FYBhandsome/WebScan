# TOSKill Frontend

基于 **Vue 3 + Vite** 构建的 Web 安全扫描器前端界面，为 [TOSKill](https://github.com/your-org/toskill) 安全扫描系统提供现代化的交互式 UI。

---

## 项目概述

TOSKill Frontend 是一个面向 Web 安全测试人员与安全工程师的单页面应用（SPA），通过与 TOSKill 后端 API 和 WebSocket 的深度集成，实现了从目标输入、扫描模式选择、AI 决策可视化、工具执行监控到报告生成的全流程交互体验。

### 核心理念

- **AI 驱动的扫描工作流**：通过 WebSocket 实时双向通信，用户可与 AI Agent 进行自然语言交互，实现意图识别、脚本生成、漏洞确认等智能化操作。
- **极简专业的设计语言**：采用纯黑/白/极客绿配色体系，去除多余的视觉噪音，专注于安全扫描的数据呈现与决策传达。

---

## 功能特性

### 五大核心页面

| 页面 | 路由标识 | 功能描述 |
|------|----------|----------|
| **控制台** (Console) | `console` | AI Agent 对话交互界面，支持自然语言指令、扫描模式选择、脚本上传与生成 |
| **扫描** (Scan) | `scan` | 标准扫描任务管理，支持目标输入、模式选择、进度监控、漏洞结果展示 |
| **工具** (Tools) | `tools` | 安全工具目录与分类过滤，支持工具执行、自定义脚本上传与 AI 脚本生成 |
| **报告** (Reports) | `reports` | 扫描报告列表管理，支持在线预览（Markdown 渲染）、下载与删除 |
| **设置** (Settings) | `settings` | 服务器连接配置（API 地址 / WebSocket 地址）、扫描超时参数、连接测试 |

### AI Agent 交互特性

- **自然语言指令解析**：在控制台中输入自然语言描述的目标和意图，AI 自动识别并执行
- **Chain of Thought 可视化**：Agent 的思考过程以可折叠面板形式展示
- **交互式决策确认**：高危漏洞检测、工具确认、替代方案选择均以深色终端风格卡片呈现
- **脚本生态闭环**：
  - **上传脚本**：粘贴自定义 Python 扫描脚本，系统自动进行安全审查与注册
  - **AI 生成脚本**：描述需求后 AI 自动生成扫描脚本，支持预览、编辑、确认注册
- **扫描模式选择器**：目标输入后自动弹出三种模式卡片（信息收集 / 漏洞扫描 / 完整扫描）
- **脚本循环执行**：选定模式后自动生成脚本队列，逐个确认执行

### 辅助功能

- **全局 Toast 通知系统**：成功/错误/警告/信息四种类型的轻量级消息提示
- **全局 Modal 弹窗系统**：支持 HTML 渲染的可确认弹窗
- **扫描历史记录**：最近 5 个扫描目标，以标签形式快速填入
- **连接状态指示**：顶栏实时显示 WebSocket 连接状态
- **隐藏式历史导航栏**：右侧悬浮导航（hover 展开），可快速定位工作区关键节点

---

## 技术栈

| 类别 | 技术 | 版本 |
|------|------|------|
| **框架** | Vue 3 (Composition API + `<script setup>`) | ^3.5.32 |
| **构建工具** | Vite | ^8.0.10 |
| **编译插件** | @vitejs/plugin-vue | ^6.0.6 |
| **图标库** | Lucide Vue Next | ^1.0.0 |
| **Markdown 渲染** | marked | ^18.0.3 |
| **语言** | JavaScript (ES Module) | — |
| **样式** | Scoped CSS + CSS Variables | — |

### 架构模式

- **单例服务模式**：`API` 和 `WebSocket` 管理器均为全局单例
- **Composition API (Composables)**：核心业务逻辑封装在 `useAgentChat()` 中，页面组件纯净消费
- **全局响应式状态**：Vue `reactive()` 驱动的 `globalState` 管理 Toast、Modal、当前目标
- **WebSocket 事件驱动**：所有 AI 交互通过 WebSocket 消息类型路由分发

---

## 环境配置指南

### 前置要求

- **Node.js** >= 18.0.0
- **npm** >= 9.0.0（或 yarn / pnpm）
- **TOSKill 后端服务**：需确保后端服务在 `http://localhost:8081` 启动

### 安装步骤

```bash
# 1. 进入前端项目目录
cd toskill-frontend

# 2. 安装依赖
npm install

# 3. 确认后端服务已启动（默认 8081 端口）
# 可通过设置页面的"测试连接"按钮验证
```

### 后端连接配置

默认连接地址：
- **API 地址**：`http://localhost:8081/api`
- **WebSocket 地址**：`ws://localhost:8081/api/ai-chat/ws`

如需更改，可在 **设置页面** 修改并保存，配置将持久化到浏览器 `localStorage` 中。保存后会自动断开并重建 WebSocket 连接。

---

## 开发与构建流程

### 开发模式

```bash
npm run dev
```

启动 Vite 开发服务器（默认 `http://localhost:5173`），支持热模块替换（HMR）。

### 生产构建

```bash
npm run build
```

构建产物输出至 `dist/` 目录，可直接部署到任意静态文件服务器（Nginx / Caddy / IIS 等）。

### 本地预览

```bash
npm run preview
```

本地预览生产构建结果。

### Windows 编译脚本

项目提供了 `build.ps1` 脚本用于 Windows 环境下的 MSVC 编译（当需要将前端嵌入后端静态服务时使用）：

```powershell
.\build.ps1
```

---

## 目录结构说明

```
toskill-frontend/
├── index.html                      # 入口 HTML
├── package.json                    # 项目配置与依赖
├── vite.config.js                  # Vite 构建配置
├── README.md                       # 本文档
├── build.ps1                       # Windows MSVC 编译脚本
├── public/
│   ├── favicon.svg                 # 网站图标
│   └── icons.svg                   # SVG 图标资源
└── src/
    ├── main.js                     # 应用入口（createApp + mount）
    ├── App.vue                     # 根组件（布局、路由、Modal、Toast、WebSocket 初始化）
    ├── store.js                    # 全局响应式状态（globalState、Toast、Modal、扫描历史）
    ├── style.css                   # 全局样式（theme.css，应用于整个 #app）
    ├── services/
    │   ├── api.js                  # API 服务（HTTP 客户端，Session / Scan / Tools / Reports / Chat）
    │   └── websocket.js            # WebSocket 管理器（自动重连、消息分发、类型化 send 方法）
    ├── composables/
    │   └── useAgentChat.js         # Agent 对话核心逻辑（工作区块管理、消息路由、脚本循环）
    ├── components/
    │   ├── AppHeader.vue           # 顶栏（品牌 Logo + 连接状态指示）
    │   ├── AppSidebar.vue          # 侧边导航（5 个页面入口 + 激活态细线指示器）
    │   ├── AgentWorkspace/
    │   │   ├── ChatArea.vue        # 对话区（消息气泡、AI 头像、思考链、Proposal Card）
    │   │   ├── CommandInput.vue    # 命令输入舱（隐藏式折叠菜单 + 发送/停止按钮）
    │   │   └── HistoryRail.vue     # 历史导航栏（hover 展开、自动滚动、节点定位）
    │   └── views/
    │       ├── ConsoleView.vue     # 控制台页面（Agent 工作区主布局）
    │       ├── ScanView.vue        # 扫描页面（目标输入、模式选择、进度/结果展示）
    │       ├── ToolsView.vue       # 工具页面（分类过滤、执行弹窗、脚本上传/生成）
    │       ├── ReportsView.vue     # 报告页面（列表管理、Markdown 预览、下载/删除）
    │       └── SettingsView.vue    # 设置页面（连接配置、超时参数、连接测试）
    └── assets/
        ├── style.css               # 全局组件样式（按钮、表单、弹窗、动画、响应式）
        ├── hero.png                # 页面装饰图
        ├── vite.svg                # Vite 标志
        └── vue.svg                 # Vue 标志
```

### 模块职责

| 文件 | 职责 | 关键导出 |
|------|------|----------|
| `services/api.js` | REST API 封装（HTTP 请求、错误解析、快捷方法） | `API` (单例) |
| `services/websocket.js` | WebSocket 连接管理（自动重连、消息类型路由、事件回调） | `ws` (单例) |
| `store.js` | 全局状态管理（Toast 通知、Modal 弹窗、扫描历史持久化） | `globalState`, `showToast`, `showModal` |
| `composables/useAgentChat.js` | Agent 对话业务逻辑（工作区块、消息路由、脚本循环） | `useAgentChat()` 组合函数 |

---

## 使用方法

### 启动应用

1. 确保 TOSKill 后端服务已在 `localhost:8081` 运行
2. 执行 `npm run dev` 启动开发服务器
3. 浏览器访问 `http://localhost:5173`

### 基本操作流程

#### 方式一：Agent 对话（控制台）

1. 在底部输入框中输入目标 URL，例如 `https://example.com`
2. 系统弹出扫描模式选择卡片，选择 **信息收集** / **漏洞扫描** / **完整扫描**
3. AI 展示思考过程和总体计划（脚本清单）
4. 逐个确认脚本执行，或使用 **上传脚本** / **生成脚本** 添加自定义扫描能力
5. 扫描完成后前往 **报告页面** 查看结果

#### 方式二：标准扫描（扫描页面）

1. 在左侧表单输入 **扫描目标**（URL 或 IP）
2. 下拉选择 **扫描模式**（信息收集 / 漏洞扫描 / 完整扫描）
3. 点击 **开始扫描**
4. 实时查看进度（初始化 → 工具执行 → 报告生成）
5. 扫描完成后查看漏洞详情卡片（严重级别标识、CVE/CVSS 信息）

#### 工具页面

1. 通过顶部分类按钮过滤（全部 / 信息收集 / 漏洞扫描 / 自定义工具）
2. 点击工具卡片 → 在弹窗中输入目标 → 执行
3. 在 **自定义工具** 分类下可 **新建自定义工具**（上传脚本或 AI 生成）

#### 报告页面

1. 查看所有已生成的扫描报告列表
2. 点击 **查看** 在线预览 Markdown 渲染的报告内容
3. 点击 **下载** 保存报告文件到本地
4. 点击 **删除** 移除不需要的报告（需二次确认）

---

## 贡献指南

### 代码风格

- 使用 **Composition API + `<script setup>`** 语法
- 样式使用 **Scoped CSS** + CSS 自定义属性（`var(--xxx)`）
- 组件命名采用 **PascalCase**
- 目录 / 文件名采用 **camelCase**（JavaScript 模块）或 **PascalCase**（Vue 组件）

### 提交规范

```
feat: 新增 XXX 功能
fix: 修复 XXX 问题
refactor: 重构 XXX 模块
style: 优化 XXX 组件样式
docs: 更新 README
```

### 开发约定

- 所有 API 调用通过 `services/api.js` 单例进行，不直接使用 `fetch`
- 所有 WebSocket 消息通过 `services/websocket.js` 单例进行，在 `onUnmounted` 中必须取消监听
- 新的 WebSocket 消息类型在 `composables/useAgentChat.js` 的 `handleWSMessage` 中注册
- 全局通知使用 `showToast(message, type)`，type 可选 `success / error / warning / info`
- 全局弹窗使用 `showModal(title, body, onConfirmCallback)`

### 添加新页面

1. 在 `src/components/views/` 下新建 `.vue` 文件
2. 在 `App.vue` 中导入组件并添加条件渲染 (`v-if="currentPage === 'xxx'"`)
3. 在 `AppSidebar.vue` 中添加导航项，使用 Lucide 图标

---

## 许可证

本项目基于 [TOSKill](https://github.com/your-org/toskill) 项目开发，许可证信息请参阅项目根目录的 LICENSE 文件。