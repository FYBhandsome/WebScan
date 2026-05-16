# WebScan AI Security Platform

<div align="center">

![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green.svg)
![Vue](https://img.shields.io/badge/vue-3.5+-brightgreen.svg)
![Vite](https://img.shields.io/badge/vite-5.4+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

**AI驱动的Web应用安全扫描平台**

一个功能强大的Web应用安全扫描平台，集成POC漏洞扫描、端口扫描、AI Agent等多种安全检测能力

[功能特性](#-功能特性) • [快速开始](#-快速开始) • [项目结构](#-项目结构) • [API文档](#-api文档)

</div>

---

## 目录
- [项目简介](#-项目简介)
- [项目版本说明](#-项目版本说明)
- [功能特性](#-功能特性)
- [技术栈](#-技术栈)
- [快速开始](#-快速开始)
- [项目结构](#-项目结构)
- [配置说明](#-配置说明)
- [API文档](#-api文档)
- [开发指南](#-开发指南)
- [部署指南](#-部署指南)
- [常见问题](#-常见问题)

---

## 项目简介

WebScan AI Security Platform 是一个基于AI技术的Web应用安全扫描平台，旨在帮助开发者和安全专业人员快速发现和修复Web应用中的安全漏洞。

### 核心特点

- **全面的漏洞检测** - 支持POC漏洞扫描、端口扫描、AI Agent等多种扫描方式
- **AI智能分析** - 利用LangGraph和LangChain进行智能漏洞分析和风险评估
- **RAG知识库增强** - 集成LlamaIndex实现专业知识库检索增强
- **可视化报告** - 提供直观的扫描结果和详细的漏洞报告
- **高性能架构** - 基于FastAPI和原生JavaScript构建，提供快速响应和流畅体验
- **易于扩展** - 模块化设计，支持自定义扫描插件和规则
- **实时通信** - WebSocket实时推送扫描进度和结果

---

## 项目版本说明

本项目包含新旧两个版本的项目代码：

### 新版项目（推荐使用）

| 项目 | 目录 | 描述 | 端口 |
|------|------|------|------|
| **TOSKill** | `TOSKill/` | 重构版后端项目，基于LangGraph的AI驱动安全扫描服务 | 8081 |
| **TOSKillfront** | `TOSKillfront/` | 重构版前端项目，轻量级原生JavaScript实现 | 静态文件 |

**新版特点：**
- 基于LangGraph的ReACT推理框架
- RAG知识库增强的智能决策
- WebSocket实时通信
- 用户交互中断/恢复机制
- 认证信息自动提取与复用
- AI脚本生成与安全审查
- 简化的部署架构（单服务）

### 旧版项目（已废弃）

| 项目 | 目录 | 描述 | 端口 |
|------|------|------|------|
| **backend** | `backend/` | 旧版后端项目，功能较重，依赖较多 | 8888 |
| **front** | `front/` | 旧版前端项目，Vue 3 + Element Plus | 5173 |

> **注意**: 旧版项目（backend/front）已不再维护，建议使用新版项目（TOSKill/TOSKillfront）。

---

## 功能特性

### 核心功能

| 功能模块 | 描述 | 状态 |
|---------|------|------|
| **信息收集** | 端口扫描、子域名枚举、CMS识别、WAF检测、CDN检测等 | ✅ 已实现 |
| **漏洞扫描** | SQL注入、XSS、命令注入、文件上传、SSRF、CSRF、LFI等 | ✅ 已实现 |
| **POC验证** | Struts2、ThinkPHP、Weblogic等框架漏洞POC | ✅ 已实现 |
| **AI Agent扫描** | 基于LangGraph的智能代理自动化扫描 | ✅ 已实现 |
| **RAG知识库** | LlamaIndex驱动的专业知识检索增强 | ✅ 已实现 |
| **AI对话** | 智能安全咨询和漏洞分析 | ✅ 已实现 |
| **脚本管理** | 自定义脚本上传、AI脚本生成、安全审查 | ✅ 已实现 |
| **扫描报告** | 生成详细的扫描报告，支持Markdown格式 | ✅ 已实现 |
| **实时监控** | WebSocket实时推送扫描进度和结果 | ✅ 已实现 |

### 高级特性

- **ReACT推理决策** - AI使用Thought-Action-Reason模式进行智能决策
- **用户交互中断** - 工作流支持暂停等待用户确认
- **认证信息管理** - 自动提取、加密存储、复用认证信息
- **智能工具选择** - 根据端口扫描结果推荐合适的扫描工具
- **脚本安全审查** - 上传和生成的脚本自动进行安全检查
- **会话状态管理** - 支持TTL过期清理、版本控制、状态恢复

---

## 技术栈

### 新版后端 (TOSKill)

```yaml
核心框架:
  - FastAPI: 0.115+           # 现代化Python Web框架
  - Uvicorn: 0.34+            # ASGI服务器
  - Pydantic: 2.10+           # 数据验证和序列化

AI框架:
  - LangChain: 0.3+           # AI应用框架
  - LangGraph: 0.2+           # AI工作流框架（StateGraph + interrupt）
  - OpenAI: 1.59+             # OpenAI API客户端

RAG知识库:
  - LlamaIndex: 最新版        # RAG检索增强生成框架

安全扫描:
  - Nmap: 0.7+                # 端口扫描
  - BeautifulSoup4: 4.12+     # HTML解析
  - Requests: 2.32+           # HTTP请求
```

### 新版前端 (TOSKillfront)

```yaml
技术选型:
  - 原生JavaScript            # 无框架依赖，轻量高效
  - CSS3                      # 现代样式
  - WebSocket API             # 实时通信

模块结构:
  - app.js                    # 应用主入口
  - api.js                    # API请求封装
  - websocket.js              # WebSocket管理
  - scanner.js                # 扫描器模块
  - chat.js                   # AI对话模块
  - tools.js                  # 工具管理
  - reports.js                # 报告管理
```

---

## 快速开始

### 环境要求

- Python 3.8 或更高版本
- 现代浏览器（Chrome、Firefox、Edge等）

### 新版项目启动

#### 1. 克隆项目

```bash
git clone https://github.com/yourusername/webscan-ai.git
cd webscan-ai
```

#### 2. 后端安装与启动

```bash
# 进入新版后端目录
cd TOSKill

# 创建虚拟环境（推荐）
python -m venv venv

# 激活虚拟环境
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# 安装依赖
pip install -r requirements.txt

# 启动服务
python main.py
```

后端服务将运行在：http://localhost:8081

#### 3. 访问前端

新版前端由后端直接提供静态文件服务，启动后端后直接访问：

http://localhost:8081/frontend

或使用首页跳转：

http://localhost:8081 → 点击"前端页面"

#### 4. API文档

启动后端后，访问以下地址查看自动生成的API文档：

- **Swagger UI**: http://localhost:8081/docs
- **ReDoc**: http://localhost:8081/redoc

### 旧版项目启动（已废弃）

如需运行旧版项目，请参考：

```bash
# 后端
cd backend
pip install -r requirements.txt
python main.py  # 端口 8888

# 前端
cd front
npm install
npm run dev  # 端口 5173
```

---

## 项目结构

```
AI_WebSecurity/
├── TOSKill/                      # 新版后端项目（推荐）
│   ├── AI/                       # AI核心模块
│   │   ├── core.py              # 核心业务逻辑
│   │   ├── graph.py             # LangGraph工作流定义
│   │   ├── state.py             # 状态定义
│   │   ├── tools.py             # 工具函数
│   │   ├── validators.py        # 输入验证器
│   │   └── script_safety.py     # 脚本安全审查
│   │
│   ├── RAG/                      # RAG知识库模块
│   │   ├── rag_engine.py        # RAG引擎
│   │   ├── retriever.py         # 检索器
│   │   ├── knowledge/           # 知识文档
│   │   └── storage/             # 向量存储
│   │
│   ├── api/                      # API路由
│   │   ├── ai_chat_websocket.py # AI对话WebSocket
│   │   ├── scan_api.py          # 扫描API
│   │   └── report.py            # 报告API
│   │
│   ├── tools/                    # 扫描工具
│   │   ├── info_collection/     # 信息收集工具
│   │   │   ├── portscan.py      # 端口扫描
│   │   │   ├── subdomain.py     # 子域名扫描
│   │   │   ├── waf.py           # WAF检测
│   │   │   ├── whatcms.py       # CMS识别
│   │   │   └── ...
│   │   │
│   │   ├── vuln_scan/           # 漏洞扫描工具
│   │   │   ├── sqli.py          # SQL注入
│   │   │   ├── xss.py           # XSS扫描
│   │   │   ├── cmdi.py          # 命令注入
│   │   │   └── ...
│   │   │
│   │   ├── poc/                 # POC验证
│   │   │   ├── struts2.py
│   │   │   ├── thinkphp.py
│   │   │   └── weblogic.py
│   │   │
│   │   └── report/              # 报告生成
│   │       ├── report_manager.py
│   │       └── ai_analyzer.py
│   │
│   ├── main.py                   # 应用入口
│   ├── config.py                 # 配置管理
│   ├── cli.py                    # 命令行接口
│   ├── README.md                 # 后端文档
│   └── API_DOCUMENTATION.md      # API文档
│
├── TOSKillfront/                 # 新版前端项目（推荐）
│   ├── index.html               # 主页面
│   ├── demo.html                # 演示页面
│   ├── css/
│   │   └── style.css            # 样式文件
│   └── js/
│       ├── app.js               # 应用主入口
│       ├── api.js               # API封装
│       ├── websocket.js         # WebSocket管理
│       ├── scanner.js           # 扫描器模块
│       ├── chat.js              # AI对话模块
│       ├── tools.js             # 工具管理
│       └── reports.js           # 报告管理
│
├── backend/                      # 旧版后端项目（已废弃）
│   ├── api/                     # API路由
│   ├── ai_agents/               # AI代理系统
│   ├── plugins/                 # 扫描插件
│   ├── poc/                     # POC库
│   └── ...
│
├── front/                        # 旧版前端项目（已废弃）
│   ├── src/                     # Vue 3源码
│   └── ...
│
├── Seebug_Agent/                # Seebug Agent模块
│   ├── client.py                # Seebug客户端
│   ├── generator.py             # POC生成器
│   └── README.md                # 模块文档
│
├── tests/                        # 测试文件
│   ├── unit/                    # 单元测试
│   ├── integration/             # 集成测试
│   └── e2e/                     # 端到端测试
│
├── reports/                      # 生成的报告
├── logs/                         # 日志文件
├── README.md                     # 项目说明文档
└── .gitignore                    # Git忽略文件
```

---

## 配置说明

### 新版后端配置 (TOSKill)

主要配置文件：`TOSKill/config.py`

```python
class TOSKillSettings(BaseSettings):
    # 应用基础配置
    APP_NAME: str = "TOSKill Security Scanner"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # 服务器配置
    HOST: str = "127.0.0.1"
    PORT: int = 8081
    
    # CORS配置
    CORS_ORIGINS: list = ["*"]
    
    # 日志配置
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "logs/toskill.log"
    
    # AI API配置
    OPENAI_API_KEY: str = "your_api_key"
    OPENAI_BASE_URL: str = "https://maas-api.cn-huabei-1.xf-yun.com/v2"
    MODEL_ID: str = "xop3qwen1b7"
    LLM_TEMPERATURE: float = 0.1
    
    # 扫描配置
    SCAN_TIMEOUT: int = 300
    MAX_CONCURRENT_SCANS: int = 5
    
    # 目录配置
    REPORTS_DIR: str = "reports"
    UPLOAD_DIR: str = "uploads"
```

### 环境变量配置

创建 `.env` 文件：

```env
# 应用配置
APP_NAME=TOSKill Security Scanner
APP_VERSION=1.0.0
DEBUG=False
HOST=127.0.0.1
PORT=8081

# AI配置
OPENAI_API_KEY=your_api_key
OPENAI_BASE_URL=https://maas-api.cn-huabei-1.xf-yun.com/v2
MODEL_ID=xop3qwen1b7
LLM_TEMPERATURE=0.1

# 日志配置
LOG_LEVEL=INFO
LOG_FILE=logs/toskill.log
```

### WebSocket配置

| 配置项 | 默认值 | 说明 |
|-------|--------|------|
| WebSocket URL | `ws://localhost:8081/api/ai-chat/ws` | WebSocket连接地址 |
| 重连次数 | 5 | 最大自动重连次数 |
| 重连延迟 | 1-30秒 | 指数退避重连策略 |
| 心跳间隔 | 30秒 | 心跳检测间隔 |

---

## API文档

### 新版API端点 (TOSKill)

启动后端服务后，访问：
- **Swagger UI**: http://localhost:8081/docs
- **ReDoc**: http://localhost:8081/redoc

### 主要API端点

#### 健康检查
```http
GET /health
```

#### WebSocket连接
```http
WebSocket /api/ai-chat/ws
```

#### 开始扫描
```http
WebSocket消息:
{
  "type": "start_scan",
  "payload": {
    "target": "http://example.com",
    "scan_mode": "full"
  }
}
```

#### 执行工具
```http
WebSocket消息:
{
  "type": "execute_tool",
  "payload": {
    "tool_name": "portscan",
    "target": "example.com"
  }
}
```

#### AI对话
```http
WebSocket消息:
{
  "type": "chat",
  "payload": {
    "content": "请分析这个网站的安全状况"
  }
}
```

### WebSocket消息类型

| 类型 | 方向 | 描述 |
|------|------|------|
| `connected` | 服务端→客户端 | 连接成功，返回session_id |
| `start_scan` | 客户端→服务端 | 开始扫描任务 |
| `scan_started` | 服务端→客户端 | 扫描已启动 |
| `task_started` | 服务端→客户端 | 单个任务开始 |
| `task_completed` | 服务端→客户端 | 单个任务完成 |
| `ai_decision` | 服务端→客户端 | AI决策结果 |
| `interaction_required` | 服务端→客户端 | 需要用户交互 |
| `user_confirm` | 客户端→服务端 | 用户确认选择 |
| `workflow_resumed` | 服务端→客户端 | 工作流已恢复 |
| `scan_completed` | 服务端→客户端 | 扫描完成 |
| `report_generated` | 服务端→客户端 | 报告已生成 |

详细API文档请参考：[TOSKill/API_DOCUMENTATION.md](TOSKill/API_DOCUMENTATION.md)

---

## 开发指南

### 后端开发

#### 添加新的扫描工具

1. 在 `TOSKill/tools/` 对应目录下创建工具文件
2. 实现工具函数并添加 `@tool` 装饰器
3. 在 `TOSKill/AI/tools.py` 中注册工具

```python
from langchain_core.tools import tool

@tool
def my_new_scanner(target: str) -> dict:
    """新扫描工具描述"""
    result = do_scan(target)
    return {"vulnerable": False, "data": result}
```

#### 扩展AI工作流

1. 在 `TOSKill/AI/graph.py` 中添加新节点
2. 定义节点函数和路由逻辑
3. 更新工作流图结构

### 前端开发

#### 添加新消息处理器

在对应的JS模块中添加消息处理：

```javascript
// 在 scanner.js 或 chat.js 中
case 'new_message_type':
    this.handleNewMessage(data.payload);
    break;
```

### 测试

```bash
# 运行测试
cd tests
pytest

# 运行特定测试
pytest test_toskill_workflow.py -v
```

---

## 部署指南

### 生产环境部署

#### 使用Gunicorn部署

```bash
pip install gunicorn

gunicorn TOSKill.main:app -w 4 -k uvicorn.workers.UvicornWorker -b 127.0.0.1:8081
```

#### 使用Nginx反向代理

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:8081;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        
        # WebSocket支持
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

### Docker部署

```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY TOSKill/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY TOSKill/ .

CMD ["python", "main.py"]
```

---

## 常见问题

### 1. 后端服务启动失败

**问题**: 端口被占用

**解决方案**:
```bash
# Windows
netstat -ano | findstr :8081

# Linux/Mac
lsof -i :8081
```

### 2. WebSocket连接失败

**问题**: 前端无法建立WebSocket连接

**解决方案**:
- 检查后端服务是否正常运行
- 确认WebSocket URL配置正确
- 检查防火墙设置

### 3. AI模型连接失败

**问题**: AI决策功能不可用

**解决方案**:
- 检查 `OPENAI_API_KEY` 配置
- 确认 `OPENAI_BASE_URL` 可访问
- 查看日志中的错误信息

### 4. RAG知识库检索失败

**问题**: 知识库检索返回空结果

**解决方案**:
- 确认 `TOSKill/RAG/knowledge/` 目录下有知识文档
- 检查向量存储文件是否存在
- 重新构建向量索引

---

## 相关文档

### 新版项目文档
- [TOSKill后端文档](TOSKill/README.md)
- [TOSKill API文档](TOSKill/API_DOCUMENTATION.md)
- [TOSKill工具文档](TOSKill/TOOLS_DOCUMENTATION.md)

### 旧版项目文档（已废弃）
- [旧版后端文档](backend/README.md)
- [旧版前端文档](front/README.md)
- [AI Agents文档](backend/ai_agents/README.md)
- [插件文档](backend/plugins/README.md)
- [POC文档](backend/poc/README.md)

### 其他文档
- [Seebug Agent文档](Seebug_Agent/README.md)

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
- 遵循 JavaScript Standard Style（JavaScript）
- 添加详细的文档字符串和注释
- 使用有意义的变量和函数名
- 保持代码简洁清晰

---

## 联系方式

- 项目主页: https://github.com/yourusername/webscan-ai
- 问题反馈: https://github.com/yourusername/webscan-ai/issues

---

<div align="center">

**如果这个项目对您有帮助，请给我们一个 ⭐️**

Made with ❤️ by WebScan AI Team

</div>
