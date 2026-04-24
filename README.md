# WebScan AI Security Platform

<div align="center">

![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green.svg)
![Vue](https://img.shields.io/badge/vue-3.5+-brightgreen.svg)
![Vite](https://img.shields.io/badge/vite-5.4+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

**AI驱动的Web应用安全扫描平台**

一个功能强大的Web应用安全扫描平台，集成POC漏洞扫描、端口扫描、AWVS集成、AI Agent等多种安全检测能力

[功能特性](#-功能特性) • [快速开始](#-快速开始) • [项目结构](#-项目结构) • [API文档](#-api文档)

</div>

---

## 目录
- [项目简介](#-项目简介)
- [功能特性](#-功能特性)
- [技术栈](#-技术栈)
- [快速开始](#-快速开始)
- [项目结构](#-项目结构)
- [配置说明](#-配置说明)
- [API文档](#-api文档)
- [API兼容性分析](#-api兼容性分析)
- [开发指南](#-开发指南)
- [部署指南](#-部署指南)
- [常见问题](#-常见问题)

---

## 项目简介

WebScan AI Security Platform 是一个基于AI技术的Web应用安全扫描平台，旨在帮助开发者和安全专业人员快速发现和修复Web应用中的安全漏洞。

### 核心特点

- **全面的漏洞检测** - 支持POC漏洞扫描、端口扫描、AWVS集成、AI Agent等多种扫描方式
- **AI智能分析** - 利用LangGraph和LangChain进行智能漏洞分析和风险评估
- **可视化报告** - 提供直观的扫描结果和详细的漏洞报告
- **高性能架构** - 基于FastAPI和Vue 3构建，提供快速响应和流畅体验
- **易于扩展** - 模块化设计，支持自定义扫描插件和规则
- **Seebug集成** - 集成Seebug Agent进行POC智能生成和验证

---

## 功能特性

### 核心功能

| 功能模块 | 描述 | 状态 |
|---------|------|------|
| **POC漏洞扫描** | 基于POC的漏洞检测，支持多种常见漏洞类型 | ✅ 已实现 |
| **端口扫描** | 快速扫描目标端口，识别开放服务和潜在风险 | ✅ 已实现 |
| **AWVS集成** | 集成Acunetix Web Vulnerability Scanner进行深度扫描 | ✅ 已实现 |
| **AI Agent扫描** | 基于LangGraph的智能代理自动化扫描 | ✅ 已实现 |
| **Seebug Agent** | 智能POC生成和验证 | ✅ 已实现 |
| **漏洞管理** | 统一管理扫描发现的漏洞，支持分类和优先级排序 | ✅ 已实现 |
| **扫描报告** | 生成详细的扫描报告，支持多种格式导出 | ✅ 已实现 |
| **实时监控** | 实时监控扫描进度和结果 | ✅ 已实现 |
| **漏洞知识库** | 查询和管理漏洞知识库信息 | ✅ 已实现 |
| **通知中心** | 实时通知和消息管理 | ✅ 已实现 |

### 高级特性

- **智能扫描策略** - 根据目标类型自动选择最优扫描策略
- **实时通知** - 扫描完成和发现高危漏洞时及时通知
- **趋势分析** - 漏洞趋势分析和安全评分
- **定时扫描** - 支持定时任务和周期性扫描
- **多用户支持** - 支持多用户和权限管理
- **响应式界面** - 适配桌面、平板和移动设备
- **AI对话** - 智能安全咨询和漏洞分析
- **API测试** - 完整的API测试套件

---

## 技术栈

### 后端技术

```yaml
核心框架:
  - FastAPI: 0.115.6          # 现代化Python Web框架
  - Uvicorn: 0.34.0           # ASGI服务器
  - Python-Multipart: 0.0.20  # 文件上传支持

数据库:
  - Tortoise-ORM: 0.21.7      # 异步ORM框架
  - Aerich: 0.7.2             # 数据库迁移工具
  - SQLite                    # 默认数据库（支持MySQL/PostgreSQL）

数据验证:
  - Pydantic: 2.10.4          # 数据验证和序列化
  - Pydantic-Settings: 2.7.0 # 配置管理

AI框架:
  - LangChain: 0.3.14         # AI应用框架
  - LangGraph: 0.2.59         # AI工作流框架
  - OpenAI: 1.59.6            # OpenAI API客户端

HTTP客户端:
  - HTTPX: 0.28.1             # 异步HTTP客户端
  - Requests: 2.32.3          # 同步HTTP客户端

安全扫描:
  - Nmap: 0.7.1               # 端口扫描
  - BeautifulSoup4: 4.12.3    # HTML解析
  - LXML: 5.3.0               # XML/HTML处理
  - DNSLib: 0.9.24            # DNS解析
  - GeoIP2: 4.8.0             # IP地理位置
  - Pocsuite3: 2.1.0          # POC验证框架

工具库:
  - Loguru: 0.7.3             # 日志记录
  - Python-Dotenv: 1.0.1     # 环境变量管理
  - Colorama: 0.4.6           # 终端彩色输出
  - TQDM: 4.67.1              # 进度条
```

### 前端技术

```yaml
核心框架:
  - Vue: 3.5.24               # Vue 3核心框架
  - Vue Router: 4.5.24         # 官方路由管理器
  - Pinia: 2.3.0              # 状态管理库
  - Element Plus: 2.8.0        # UI组件库

构建工具:
  - Vite: 5.4.0               # 下一代前端构建工具
  - @Vitejs/Plugin-Vue: 5.2.1 # Vue 3插件

HTTP客户端:
  - Axios: 1.7.9              # HTTP请求库

数据可视化:
  - Chart.js: 4.4.0            # 图表库

开发工具:
  - ESLint: 9.17.0            # 代码检查
  - ESLint-Plugin-Vue: 9.31.0 # Vue代码规范
  - Vitest: 2.1.8             # 单元测试框架
```

---

## 快速开始

### 环境要求

- Python 3.8 或更高版本
- Node.js 16.0 或更高版本
- npm 7.0 或更高版本（或 yarn 1.22+）

### 安装步骤

#### 1. 克隆项目

```bash
git clone https://github.com/yourusername/webscan-ai.git
cd webscan-ai
```

#### 2. 后端安装

```bash
# 进入后端目录
cd backend

# 创建虚拟环境（推荐）
python -m venv venv

# 激活虚拟环境
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# 安装依赖
pip install -r requirements.txt
```

#### 3. 配置后端

编辑 `backend/.env` 文件，根据需要修改配置：

```bash
# 应用配置
APP_NAME=WebScan AI Security Platform
APP_VERSION=1.0.0
DEBUG=False
HOST=127.0.0.1
PORT=8888

# 数据库配置
DATABASE_URL=sqlite://./data/webscan.db

# CORS配置
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173

# 日志配置
LOG_LEVEL=INFO
LOG_FILE=logs/app.log

# AI API配置
OPENAI_API_KEY=your_openai_api_key
OPENAI_BASE_URL=https://maas-api.cn-huabei-1.xf-yun.com/v2
MODEL_ID=xop3qwen1b7

# AWVS配置
AWVS_API_URL=https://127.0.0.1:3443
AWVS_API_KEY=your_awvs_api_key

# Seebug配置
SEEBUG_API_KEY=your_seebug_api_key
SEEBUG_API_BASE_URL=https://www.seebug.org/api

# 扫描配置
MAX_CONCURRENT_SCANS=5
SCAN_TIMEOUT=300

# 代码执行配置
CODE_EXECUTOR_ENABLED=True
CODE_EXECUTOR_TIMEOUT=30
CODE_EXECUTOR_WORKSPACE=executor_workspace

# AI Agent配置
AGENT_MAX_EXECUTION_TIME=300
AGENT_MAX_RETRIES=3

# POC验证配置
POC_VERIFICATION_ENABLED=True
POC_MAX_CONCURRENT_EXECUTIONS=5
POC_EXECUTION_TIMEOUT=60
POC_RETRY_MAX_COUNT=3
```

#### 4. 启动后端服务

```bash
# 开发模式
cd backend
python main.py

# 或使用uvicorn
uvicorn backend.main:app --host 127.0.0.1 --port 8888 --reload
```

后端服务将运行在：http://127.0.0.1:8888

**停止服务：**
- 按 `Ctrl+C` 可优雅关闭服务
- 系统会自动完成以下操作：
  1. 停止接受新任务
  2. 等待当前任务完成或超时(最多30秒)
  3. 关闭所有WebSocket连接
  4. 关闭数据库连接
  5. 输出正常退出日志

#### 5. 前端安装

```bash
# 打开新终端，进入前端目录
cd front

# 安装依赖
npm install
```

#### 6. 配置前端

编辑 `front/.env.development` 文件：

```env
VITE_API_BASE_URL=http://127.0.0.1:8888/api
VITE_REQUEST_TIMEOUT=8880
```

#### 7. 启动前端服务

```bash
npm run dev
```

前端服务将运行在：http://localhost:5173

#### 8. 访问应用

在浏览器中打开 http://localhost:5173 即可使用WebScan AI Security Platform

#### 9. 运行测试（可选）

```bash
# 后端测试
cd backend
pytest

# 前端测试
cd front
npm run test

# API测试
cd api_tests
python run_tests.py
```

---

## 项目结构

```
AI_WebSecurity/
├── backend/                      # 后端项目
│   ├── api/                     # API路由
│   │   ├── __init__.py         # 路由注册
│   │   ├── scan.py             # 扫描功能API
│   │   ├── poc.py              # POC扫描API
│   │   ├── awvs.py             # AWVS集成API
│   │   ├── ai.py               # AI对话API
│   │   ├── agent.py            # AI Agent API
│   │   ├── settings.py         # 系统设置API
│   │   ├── tasks.py            # 任务管理API
│   │   ├── reports.py          # 报告生成API
│   │   ├── kb.py               # 知识库API
│   │   ├── poc_gen.py          # POC智能生成API
│   │   ├── poc_verification.py # POC验证API
│   │   ├── poc_files.py        # POC文件管理API
│   │   ├── seebug_agent.py     # Seebug Agent API
│   │   ├── user.py             # 用户管理API
│   │   ├── notifications.py    # 通知管理API
│   │   └── workflow_schemas.py # 工作流数据标准化模块（合并自execution_optimizer.py）
│   │
│   ├── ai_agents/              # AI Agents智能代理系统
│   │   ├── core/              # 核心组件
│   │   ├── analyzers/         # 分析器模块
│   │   ├── code_execution/     # 代码执行模块
│   │   ├── poc_system/        # POC系统模块
│   │   │   ├── poc_manager.py      # POC管理器（简化重构）
│   │   │   ├── verification_engine.py # 验证引擎（简化重构）
│   │   │   └── utils.py            # POC工具函数
│   │   ├── tools/             # 工具模块
│   │   ├── utils/             # 工具函数
│   │   └── api/               # AI Agents API
│   │
│   ├── utils/                 # 工具模块
│   │   └── seebug_utils.py    # Seebug工具模块（统一接口）
│   │
│   ├── plugins/               # 扫描插件模块
│   │   ├── portscan/          # 端口扫描
│   │   ├── infoleak/          # 信息泄露扫描
│   │   ├── webside/           # 网站侧边栏扫描
│   │   ├── baseinfo/          # 基础信息收集
│   │   ├── webweight/         # 网站权重查询
│   │   ├── iplocating/        # IP定位
│   │   ├── cdnexist/          # CDN检测
│   │   ├── waf/               # WAF检测
│   │   ├── whatcms/           # CMS识别
│   │   ├── subdomain/         # 子域名扫描
│   │   ├── loginfo/           # 日志处理
│   │   ├── randheader/        # 随机请求头生成
│   │   └── common/            # 通用工具
│   │
│   ├── AVWS/                  # AWVS API封装
│   ├── geoip/                 # GeoIP数据库
│   ├── poc/                   # POC漏洞库
│   ├── data/                  # 数据目录
│   ├── logs/                  # 日志目录
│   ├── main.py                # 应用入口
│   ├── config.py              # 配置管理
│   ├── models.py              # 数据模型
│   ├── database.py            # 数据库连接
│   ├── task_executor.py       # 任务执行器
│   ├── requirements.txt       # Python依赖
│   ├── pyproject.toml         # 项目配置
│   ├── .env                   # 环境变量
│   ├── AWVS_API_README.md     # AWVS API文档
│   └── README.md              # 后端说明文档
│
├── front/                      # 前端项目
│   ├── src/
│   │   ├── components/       # 组件
│   │   ├── views/            # 页面视图
│   │   ├── router/           # 路由配置
│   │   ├── store/            # 状态管理
│   │   ├── styles/           # 样式文件
│   │   ├── utils/            # 工具函数
│   │   ├── App.vue           # 根组件
│   │   └── main.js           # 应用入口
│   ├── tests/                 # 测试文件
│   ├── .env                   # 环境变量
│   ├── .env.development       # 开发环境变量
│   ├── .env.production        # 生产环境变量
│   ├── index.html             # HTML模板
│   ├── package.json           # 项目配置
│   ├── vite.config.js         # Vite配置
│   ├── vitest.config.js       # Vitest配置
│   ├── eslint.config.js       # ESLint配置
│   └── README.md              # 前端说明文档
│
├── api_tests/                 # API测试
│   ├── api_tester.py          # API测试工具
│   ├── config.py              # 测试配置
│   ├── run_tests.py           # 测试运行脚本
│   ├── test_dashboard.py      # 仪表盘测试
│   ├── test_tasks.py          # 任务测试
│   ├── test_poc.py            # POC测试
│   ├── test_awvs.py           # AWVS测试
│   ├── test_agent.py          # Agent测试
│   ├── test_reports.py        # 报告测试
│   ├── test_scan.py           # 扫描测试
│   ├── test_user_notification.py # 用户和通知测试
│   ├── test_ai_chat.py        # AI对话测试
│   ├── requirements.txt       # 测试依赖
│   └── README.md              # 测试说明文档
│
├── Seebug_Agent/              # Seebug Agent独立模块
│   ├── client.py             # Seebug客户端
│   ├── generator.py          # POC生成器
│   ├── config.py             # 配置管理
│   ├── main.py               # 主程序
│   ├── requirements.txt       # Python依赖
│   └── README.md             # Seebug Agent文档
│
├── docs/                     # 文档目录
│   ├── architecture_design.md # 架构设计文档
│   └── ci_cd_pipeline.md     # CI/CD流水线文档
│
├── API_DOCUMENTATION.md       # API文档
├── CHANGELOG.md               # 更新日志
├── README.md                 # 项目说明文档
└── .gitignore                # Git忽略文件
```

### 重构变更说明

#### 模块合并

1. **workflow_schemas.py** (合并自 `execution_optimizer.py`)
   - 合并了 `NodeExecutionMetrics`, `ExecutionMetricsCollector`, `NodeExecutionOptimizer`
   - 合并了 `optimized_node` 装饰器和 `get_execution_optimizer` 函数
   - 统一了工作流数据的格式定义和转换逻辑

2. **seebug_utils.py** (统一接口)
   - 整合了 Seebug_Agent 的导入和配置
   - 提供统一的 `SeebugUtils` 类访问 Seebug 功能
   - 内置缓存和统计功能

#### 接口简化

1. **poc_manager.py**
   - 移除重复的 `seebug_client` 和 `seebug_agent` 实例
   - 统一使用 `seebug_utils` 访问 Seebug_Agent 功能
   - 合并 `sync_from_seebug` 和 `search_seebug_pocs` 的重复逻辑
   - 使用 `_search_seebug_pocs_internal` 统一处理搜索

2. **verification_engine.py**
   - `ResourceMonitor`: 移除复杂回调，使用简单阈值检查
   - `ExecutionQueue`: 简化队列管理，移除不必要的锁竞争
   - `ProgressCallback`: 统一使用简单的 Callable 类型
   - 合并 `ResourceLimits` 和 `ExecutionConfig` 的重复配置

---

## 配置说明

### 后端配置

主要配置文件：`backend/config.py` 和 `backend/.env`

```python
class Settings(BaseSettings):
    # 应用基础配置
    APP_NAME: str = "WebScan AI Security Platform"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # 服务器配置
    HOST: str = "127.0.0.1"
    PORT: int = 8888
    
    # CORS配置
    CORS_ORIGINS: list = ["http://localhost:5173", "http://127.0.0.1:5173"]
    
    # 数据库配置
    DATABASE_URL: str = "sqlite://./data/webscan.db"
    
    # 日志配置
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "logs/app.log"
    
    # AI API配置
    OPENAI_API_KEY: str = "your_openai_api_key"
    OPENAI_BASE_URL: str = "https://maas-api.cn-huabei-1.xf-yun.com/v2"
    MODEL_ID: str = "xop3qwen1b7"
    
    # AWVS配置
    AWVS_API_URL: str = "https://127.0.0.1:3443"
    AWVS_API_KEY: str = "your_awvs_api_key"
    
    # Seebug配置
    SEEBUG_API_KEY: str = "your_seebug_api_key"
    SEEBUG_API_BASE_URL: str = "https://www.seebug.org/api"
    
    # 扫描配置
    MAX_CONCURRENT_SCANS: int = 5
    SCAN_TIMEOUT: int = 300
    
    # 代码执行配置
    CODE_EXECUTOR_ENABLED: bool = True
    CODE_EXECUTOR_TIMEOUT: int = 30
    CODE_EXECUTOR_WORKSPACE: str = "executor_workspace"
    
    # AI Agent配置
    AGENT_MAX_EXECUTION_TIME: int = 300
    AGENT_MAX_RETRIES: int = 3
    
    # POC验证配置
    POC_VERIFICATION_ENABLED: bool = True
    POC_MAX_CONCURRENT_EXECUTIONS: int = 5
    POC_EXECUTION_TIMEOUT: int = 60
    POC_RETRY_MAX_COUNT: int = 3
```

### 前端配置

主要配置文件：`front/vite.config.js` 和 `front/.env.development`

```javascript
export default defineConfig({
  server: {
    port: 5173,
    open: true,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8888',
        changeOrigin: true,
        secure: false
      }
    }
  }
})
```

环境变量配置：`front/.env.development`

```env
VITE_API_BASE_URL=http://127.0.0.1:8888/api
VITE_REQUEST_TIMEOUT=8880
```

### WebSocket配置

系统使用WebSocket实现实时通信：

| 配置项 | 默认值 | 说明 |
|-------|--------|------|
| WebSocket URL | `ws://localhost:8888/api/ws` | WebSocket连接地址 |
| 重连次数 | 5 | 最大自动重连次数 |
| 重连延迟 | 1-30秒 | 指数退避重连策略 |
| 心跳间隔 | 30秒 | 心跳检测间隔 |

**前端WebSocket使用：**
```javascript
import { useWebSocket } from '@/utils/websocket'

const { connect, on, disconnect } = useWebSocket('ws://localhost:8888/api/ws')
connect()
on('task:update', (payload) => { /* 处理任务更新 */ })
```

### 端口配置

| 服务 | 默认端口 | 配置位置 |
|-----|---------|---------|
| 后端API | 8888 | `backend/.env` → `PORT` |
| 前端开发 | 5173 | `front/vite.config.js` |
| WebSocket | 8888 | 与后端API共用 |

---

## API文档

### 启动API文档

启动后端服务后，访问以下地址查看自动生成的API文档：

- **Swagger UI**: http://127.0.0.1:8888/docs
- **ReDoc**: http://127.0.0.1:8888/redoc

### 主要API端点

#### 健康检查
```http
GET /health
```

#### POC扫描
```http
POST /api/poc/scan
Content-Type: application/json

{
  "target": "http://example.com",
  "poc_list": ["poc1", "poc2"]
}
```

#### 端口扫描
```http
POST /api/port/scan
Content-Type: application/json

{
  "target": "example.com",
  "ports": [80, 443, 8080]
}
```

#### AWVS扫描
```http
POST /api/awvs/scan
Content-Type: application/json

{
  "url": "http://example.com",
  "scan_type": "full_scan"
}
```

#### AI Agent扫描
```http
POST /api/ai_agents/scan
Content-Type: application/json

{
  "target": "http://example.com",
  "enable_llm_planning": true
}
```

#### 获取扫描任务
```http
GET /api/tasks
```

#### 获取漏洞列表
```http
GET /api/vulnerabilities
```

### 重构后模块使用示例

#### 工作流数据标准化
```python
from backend.api.workflow_schemas import (
    WorkflowDataConverter,
    StandardizedWorkflowData,
    get_execution_optimizer
)

# 转换工作流数据
converter = WorkflowDataConverter()
workflow_data = converter.from_agent_state(agent_state)

# 使用执行优化器
optimizer = get_execution_optimizer()
result, success = await optimizer.execute_with_optimization(
    node_func, "node_name", "task_id"
)
```

#### Seebug 工具模块
```python
from backend.utils.seebug_utils import seebug_utils

# 检查可用性
if seebug_utils.is_available():
    # 搜索 POC
    response = await seebug_utils.search_poc("nginx", page=1, page_size=10)
    
    # 下载 POC
    response = await seebug_utils.download_poc(ssvid=12345)
    
    # 获取统计信息
    stats = seebug_utils.get_statistics()
```

#### POC 管理器
```python
from backend.ai_agents.poc_system.poc_manager import poc_manager

# 从 Seebug 同步 POC
pocs = await poc_manager.sync_from_seebug("nginx", limit=10)

# 获取 POC 代码
poc_code = await poc_manager.get_poc_code("seebug_12345")

# 搜索本地 POC
results = poc_manager.search_pocs("wordpress")

# 获取统计信息
stats = poc_manager.get_poc_statistics()
```

#### 验证引擎
```python
from backend.ai_agents.poc_system.verification_engine import (
    VerificationEngine,
    ExecutionPriority
)

# 创建引擎实例
engine = VerificationEngine(max_concurrent=10)
await engine.start()

# 执行单个验证任务
result = await engine.execute_verification_task(verification_task)

# 批量执行
results = await engine.execute_batch_verification(
    verification_tasks,
    max_concurrent=5
)

# 获取执行统计
stats = engine.get_execution_statistics()

await engine.shutdown()
```

详细API文档请参考：
- [API_DOCUMENTATION.md](API_DOCUMENTATION.md)
- 运行 `python analyze_all_apis_fixed.py` 查看完整的API兼容性分析

---
## API兼容性分析

### 概述
本项目前后端API接口已实现100%兼容性匹配，确保前端所有功能都能正确调用后端服务。

### 统计数据（最新更新：2026-03-13）

| 指标 | 数量 | 说明 |
|------|------|------|
| **后端API总数** | 141 | 后端FastAPI提供的所有接口 |
| **前端API总数** | 91 | 前端Vue3项目使用的API接口 |
| **匹配成功** | 91 | 前后端接口完全匹配 |
| **前端未匹配** | 0 | 前端所有API都有对应的后端实现 |
| **后端未匹配** | 51 | 后端有51个接口前端暂未使用 |

### 匹配成功率
- **前端API匹配率**: 100% (91/91) ✅
- **后端API使用率**: 64.5% (91/141)

### API模块分布

#### 已匹配的API模块
| 模块 | 接口数量 | 状态 |
|------|---------|------|
| scanApi | 11 | ✅ 全部匹配 |
| tasksApi | 4 | ✅ 全部匹配 |
| reportsApi | 3 | ✅ 全部匹配 |
| settingsApi | 8 | ✅ 全部匹配 |
| pocApi | 2 | ✅ 全部匹配 |
| awvsApi | 9 | ✅ 全部匹配 |
| aiApi | 3 | ✅ 全部匹配 |
| kbApi | 4 | ✅ 全部匹配 |
| userApi | 4 | ✅ 全部匹配 |
| notificationsApi | 5 | ✅ 全部匹配 |
| pocVerificationApi | 7 | ✅ 全部匹配 |
| pocFilesApi | 5 | ✅ 全部匹配 |
| seebugAgentApi | 3 | ✅ 全部匹配 |
| aiAgentsApi | 18 | ✅ 全部匹配 |

### 主要API端点示例

#### 扫描功能
- `POST /api/scan/port-scan` - 端口扫描
- `POST /api/scan/info-leak` - 信息泄露扫描
- `POST /api/scan/dir-scan` - 目录扫描
- `POST /api/scan/web-side` - 网站侧边栏扫描
- `POST /api/scan/baseinfo` - 基础信息收集
- `POST /api/scan/subdomain` - 子域名扫描
- `POST /api/scan/comprehensive` - 综合扫描
- `POST /api/scan/web-weight` - 网站权重查询
- `POST /api/scan/ip-locating` - IP定位
- `POST /api/scan/cdn-check` - CDN检测
- `POST /api/scan/waf-check` - WAF检测
- `POST /api/scan/what-cms` - CMS识别

#### 任务管理
- `POST /api/tasks/create` - 创建任务
- `GET /api/tasks/` - 获取任务列表
- `GET /api/tasks/statistics/overview` - 获取统计概览
- `GET /api/tasks/frozen` - 获取冻结任务

#### 报告管理
- `GET /api/reports/` - 获取报告列表
- `POST /api/reports/` - 创建报告
- `POST /api/reports/compare` - 比较报告

#### AWVS集成
- `GET /api/awvs/targets` - 获取目标列表
- `POST /api/awvs/target` - 创建目标
- `GET /api/awvs/scans` - 获取扫描列表
- `POST /api/awvs/scan` - 创建扫描
- `GET /api/awvs/vulnerabilities/rank` - 获取漏洞排名
- `GET /api/awvs/vulnerabilities/stats` - 获取漏洞统计
- `GET /api/awvs/middleware/poc-list` - 获取中间件POC列表
- `GET /api/awvs/middleware/scans` - 获取中间件扫描
- `POST /api/awvs/middleware/scan` - 中间件扫描
- `POST /api/awvs/middleware/scan/start` - 启动中间件扫描
- `GET /api/awvs/health` - 健康检查

#### AI功能
- `POST /api/ai/chat` - AI对话
- `GET /api/ai/chat/instances` - 获取对话实例
- `POST /api/ai/chat/instances` - 创建对话实例

#### 知识库管理
- `GET /api/kb/vulnerabilities` - 获取漏洞列表
- `POST /api/kb/sync` - 同步知识库
- `POST /api/kb/seebug/poc/search` - 搜索POC
- `POST /api/kb/seebug/poc/download` - 下载POC

#### POC验证
- `POST /api/poc/verification/tasks` - 创建验证任务
- `POST /api/poc/verification/tasks/batch` - 批量创建任务
- `GET /api/poc/verification/tasks` - 获取任务列表
- `GET /api/poc/verification/tasks/{task_id}` - 获取任务详情(含验证结果)
- `POST /api/poc/verification/tasks/{task_id}/pause` - 暂停任务
- `POST /api/poc/verification/tasks/{task_id}/resume` - 继续任务
- `POST /api/poc/verification/tasks/{task_id}/cancel` - 取消任务
- `POST /api/poc/verification/tasks/{task_id}/report` - 生成报告
- `GET /api/poc/verification/health` - 健康检查(含统计信息)

#### POC文件管理
- `GET /api/poc/files/list` - 获取文件列表
- `GET /api/poc/files/directories` - 获取目录列表
- `POST /api/poc/files/sync` - 同步文件
- `GET /api/poc/files/sync/status` - 获取同步状态

#### AI Agents
- `POST /api/ai_agents/scan` - 启动扫描
- `GET /api/ai_agents/tasks` - 获取任务列表
- `GET /api/ai_agents/tasks/frozen` - 获取冻结任务
- `GET /api/ai_agents/tools` - 获取工具列表
- `GET /api/ai_agents/config` - 获取配置
- `POST /api/ai_agents/config` - 更新配置
- `POST /api/ai_agents/code/generate` - 生成代码
- `POST /api/ai_agents/code/execute` - 执行代码
- `POST /api/ai_agents/code/generate-and-execute` - 生成并执行代码
- `POST /api/ai_agents/capabilities/enhance` - 增强能力
- `GET /api/ai_agents/capabilities/list` - 获取能力列表
- `GET /api/ai_agents/environment/info` - 获取环境信息
- `GET /api/ai_agents/environment/tools` - 获取环境工具
- `GET /api/ai_agents/resources/usage` - 获取资源使用情况
- `GET /api/ai_agents/resources/statistics` - 获取资源统计
- `GET /api/ai_agents/workflow/metrics` - 获取工作流指标
- `POST /api/ai_agents/poc/execute` - 执行POC
- `POST /api/ai_agents/poc/batch-execute` - 批量执行POC
- `POST /api/ai_agents/poc/search` - 搜索POC

### API兼容性保证
- 所有前端API调用都经过严格测试，确保与后端接口完全兼容
- 前端API定义文件：`front/src/utils/api.js`
- 后端API路由文件：`backend/api/` 目录
- API文档自动生成：访问 http://127.0.0.1:8888/docs

### API分析工具
项目提供了完整的API分析工具：
- `analyze_all_apis_fixed.py` - 完整的前后端API兼容性分析脚本
- 运行命令：`python analyze_all_apis_fixed.py`
- 分析结果保存在：`.trae/documents/all_apis_analysis_fixed.json`

---

## 开发指南

### 后端开发

#### 添加新的API端点

1. 在 `backend/api/` 目录下创建或编辑API模块
2. 定义路由和处理函数
3. 在 `backend/api/__init__.py` 中注册路由

示例：

```python
# backend/api/my_feature.py
from fastapi import APIRouter
from models import APIResponse

router = APIRouter()

@router.get("/my-feature")
async def get_my_feature():
    return APIResponse(
        code=200,
        message="Success",
        data={"feature": "data"}
    )
```

#### 添加新的扫描插件

1. 在 `backend/plugins/` 目录下创建插件文件
2. 实现扫描逻辑
3. 在主程序中注册插件

#### 扩展AI Agents功能

1. 在 `backend/ai_agents/core/nodes.py` 中添加新的节点
2. 在 `backend/ai_agents/core/graph.py` 中集成到工作流
3. 添加相应的工具函数

### 前端开发

#### 添加新页面

1. 在 `front/src/views/` 目录下创建Vue组件
2. 在 `front/src/router/index.js` 中添加路由

示例：

```vue
<!-- front/src/views/NewPage.vue -->
<template>
  <div class="page-container">
    <h1>新页面</h1>
  </div>
</template>

<script>
export default {
  name: 'NewPage'
}
</script>
```

```javascript
// front/src/router/index.js
import NewPage from '../views/NewPage.vue'

const routes = [
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

#### 添加新组件

1. 在 `front/src/components/` 目录下创建组件
2. 在页面中引入和使用

### 测试

#### 后端测试

项目采用模块化的测试结构，测试文件按照功能模块组织：

```bash
# 运行所有测试
cd backend
pytest

# 运行特定模块的测试
pytest ai_agents/core/tests/ -v
pytest ai_agents/tools/tests/ -v
pytest api/tests/ -v

# 运行带覆盖率的测试
pytest --cov=backend --cov-report=html

# 运行集成测试（需要外部服务）
pytest --run-integration -v
```

#### 测试目录结构

```
backend/
├── tests/                    # 集成测试
│   ├── conftest.py          # 测试配置和fixtures
│   ├── test_integration.py  # 综合集成测试
│   ├── test_ai_model.py     # AI模型连接测试
│   └── test_report_generator.py # 报告生成器测试
├── ai_agents/
│   ├── core/tests/          # 核心模块测试
│   ├── tools/tests/         # 工具适配器测试
│   ├── poc_system/tests/    # POC系统测试
│   └── analyzers/tests/     # 分析器测试
├── api/tests/               # API模块测试
└── plugins/tests/           # 插件测试
```

#### 测试要求

- 所有新功能必须包含单元测试
- 测试覆盖率应不低于70%
- 测试应包含正常流程和异常情况
- 使用pytest和pytest-asyncio进行测试
- 涉及外部服务的测试使用`@pytest.mark.integration`标记

#### 前端测试

```bash
cd front
npm run test

# 运行测试UI
npm run test:ui

# 生成覆盖率报告
npm run test:coverage
```

#### API测试

```bash
cd api_tests
python run_tests.py

# 运行特定模块
python run_tests.py test_dashboard
python run_tests.py test_tasks
```

---

## 部署指南

### 生产环境部署

#### 后端部署

1. **使用Gunicorn部署**

```bash
pip install gunicorn

# 启动服务
gunicorn backend.main:app -w 4 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8888
```

2. **使用Nginx反向代理**

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:8888;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

3. **配置SSL/TLS**

```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:8888;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

#### 前端部署

1. **构建生产版本**

```bash
cd front
npm run build
```

2. **使用Nginx部署**

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
    }
}
```

### Docker部署

#### 后端Dockerfile

```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .

CMD ["python", "main.py"]
```

#### 前端Dockerfile

```dockerfile
FROM node:16-alpine as builder

WORKDIR /app
COPY front/package*.json ./
RUN npm install
COPY front/ .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
```

#### Docker Compose

```yaml
version: '3.8'

services:
  backend:
    build: ./backend
    ports:
      - "8888:8888"
    environment:
      - DATABASE_URL=sqlite:///data/webscan.db
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs

  frontend:
    build: ./front
    ports:
      - "80:80"
    depends_on:
      - backend
```

---

## 常见问题

### 1. 后端服务启动失败

**问题**: 后端服务无法启动，报错"Address already in use"

**解决方案**:
```bash
# 检查端口占用
netstat -ano | findstr :8888

# 更改端口或终止占用进程
```

### 2. 前端无法连接后端API

**问题**: 前端页面显示"Network Error"

**解决方案**:
- 检查后端服务是否正常运行
- 检查 `front/.env.development` 中的 `VITE_API_BASE_URL` 配置
- 检查CORS配置是否正确

### 3. AWVS连接失败

**问题**: AWVS扫描功能无法使用，提示连接失败

**解决方案**:
- 检查AWVS服务是否正常运行
- 检查 `backend/.env` 中的 `AWVS_API_URL` 和 `AWVS_API_KEY` 配置
- 确保AWVS API地址可访问

### 4. AI Agent执行超时

**问题**: AI Agent任务执行时间过长导致超时

**解决方案**:
- 增加 `backend/.env` 中的 `AGENT_MAX_EXECUTION_TIME` 配置
- 减少扫描任务数量
- 优化工具超时时间

### 5. POC验证失败

**问题**: POC验证任务总是失败

**解决方案**:
- 检查目标URL/IP是否可访问
- 检查POC脚本是否正确
- 查看日志中的详细错误信息
- 增加 `POC_EXECUTION_TIMEOUT` 配置

### 6. 数据库连接错误

**问题**: 应用启动时报数据库连接错误

**解决方案**:
- 检查数据库配置是否正确
- 确保数据库服务正在运行
- 检查数据库文件权限
- 尝试删除数据库文件重新初始化

### 7. 前端构建失败

**问题**: `npm run build` 命令执行失败

**解决方案**:
```bash
# 清除缓存
rm -rf node_modules package-lock.json
npm install

# 检查Node.js版本
node -v  # 应该 >= 16.0
```

### 8. 日志文件过大

**问题**: 日志文件占用过多磁盘空间

**解决方案**:
- 配置日志轮转
- 定期清理旧日志文件
- 调整日志级别为WARNING或ERROR

### 9. WebSocket连接断开

**问题**: 前端WebSocket连接频繁断开

**解决方案**:
- 检查网络连接是否稳定
- 前端会自动重连(最多5次)
- 查看浏览器控制台的WebSocket错误信息
- 确认后端服务正常运行

### 10. 任务状态丢失

**问题**: 服务重启后任务状态丢失

**解决方案**:
- 任务状态会自动持久化到 `data/task_states.json`
- 服务启动时会自动恢复未完成的任务
- 如需手动恢复，检查数据库中任务状态

### 11. API端点404错误

**问题**: 前端调用API返回404

**解决方案**:
- 确认API端点路径正确
- AI Agent扫描使用 `/api/ai_agents/scan`
- WebSocket使用 `ws://localhost:8888/api/ws`
- 查看后端Swagger文档确认端点: http://127.0.0.1:8888/docs

---

## 相关文档

- [后端文档](backend/README.md)
- [前端文档](front/README.md)
- [AI Agents文档](backend/ai_agents/README.md)
- [API测试文档](api_tests/README.md)
- [Seebug Agent文档](Seebug_Agent/README.md)
- [插件文档](backend/plugins/README.md)
- [POC文档](backend/poc/README.md)
- [API文档](API_DOCUMENTATION.md)
- [架构设计](docs/architecture_design.md)
- [CI/CD流水线](docs/ci_cd_pipeline.md)

---

## 许可证

本项目采用 MIT 许可证。详见 [LICENSE](LICENSE) 文件。

---

## 贡献指南

我们欢迎任何形式的贡献！

### 贡献流程

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

### 代码规范

- 遵循 PEP 8 代码风格（Python）
- 遵循 Vue 风格指南（Vue.js）
- 添加详细的文档字符串和注释
- 使用有意义的变量和函数名
- 保持代码简洁清晰

---

## 联系方式

- 项目主页: https://github.com/yourusername/webscan-ai
- 问题反馈: https://github.com/yourusername/webscan-ai/issues
- 邮箱: your.email@example.com

---

<div align="center">

**如果这个项目对您有帮助，请给我们一个 ⭐️**

Made with ❤️ by WebScan AI Team

</div>
