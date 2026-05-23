# Backend - Web安全扫描平台后端服务

<div align="center">

![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

**企业级Web应用安全扫描平台后端服务**

</div>

---

## 📖 项目简介

Backend 是 WebScan AI Security Platform 的企业级后端服务，提供完整的漏洞扫描、POC验证、AI Agent分析等功能。基于 FastAPI 构建，支持异步处理和高并发扫描任务。

### 核心特点

- 🤖 **Multi-Agent协作系统** - 多Agent协作的任务规划与执行
- 🔌 **可扩展插件系统** - 支持自定义漏洞扫描插件
- 🛡️ **丰富POC库** - 内置多种框架漏洞验证脚本
- 📊 **企业级报告** - 多格式报告生成与管理
- 🔗 **第三方集成** - AWVS、Seebug等平台对接
- ⚡ **高性能架构** - 异步处理，支持大规模扫描

---

## 🏗️ 项目结构

```
backend/
├── ai_agents/                    # AI代理系统
│   ├── core/                     # 核心模块
│   │   ├── graph.py              # Agent工作流图
│   │   ├── nodes.py              # 节点定义
│   │   └── state.py              # 状态定义
│   ├── analyzers/                # 分析器
│   │   ├── ai_analyzer.py        # AI分析器
│   │   └── vuln_analyzer.py      # 漏洞分析器
│   ├── poc_system/               # POC系统
│   │   ├── poc_manager.py        # POC管理器
│   │   └── verification_engine.py
│   └── tools/                    # Agent工具
│       ├── registry.py           # 工具注册
│       └── wrappers.py           # 工具包装器
│
├── api/                          # API路由
│   ├── ai.py                     # AI对话API
│   ├── tasks.py                  # 任务API
│   ├── reports.py                # 报告API
│   ├── poc.py                    # POC API
│   ├── seebug.py                 # Seebug API
│   ├── awvs.py                   # AWVS API
│   └── websocket.py              # WebSocket
│
├── vulnerability_scan_plugins/   # 漏洞扫描插件
│   ├── sqli/                     # SQL注入
│   ├── xss/                      # XSS扫描
│   ├── csrf/                     # CSRF扫描
│   ├── fileupload/               # 文件上传
│   ├── ssrf/                     # SSRF扫描
│   ├── lfi/                      # 本地文件包含
│   ├── cmdi/                     # 命令注入
│   └── infoleak/                 # 信息泄露
│
├── plugins/                      # 信息收集插件
│   ├── baseinfo/                 # 基础信息收集
│   ├── portscan/                 # 端口扫描
│   ├── subdomain/                # 子域名枚举
│   ├── waf/                      # WAF检测
│   └── whatcms/                  # CMS识别
│
├── poc/                          # POC库
│   ├── struts2/                  # Struts2 POC
│   ├── thinkphp/                 # ThinkPHP POC
│   ├── weblogic/                 # Weblogic POC
│   └── tomcat/                   # Tomcat POC
│
├── services/                     # 业务服务
│   ├── report_service.py         # 报告服务
│   └── notification_service.py   # 通知服务
│
├── tests/                        # 测试文件
├── main.py                       # 应用入口
├── config.py                     # 配置管理
├── models.py                     # 数据模型
└── requirements.txt              # 依赖列表
```

---

## 🚀 快速开始

### 环境要求

- Python 3.8+
- SQLite / MySQL / PostgreSQL

### 安装步骤

```bash
# 进入backend目录
cd backend

# 创建虚拟环境
python -m venv venv

# 激活虚拟环境
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# 安装依赖
pip install -r requirements.txt
```

### 配置

创建 `.env` 文件：

```env
# 应用配置
APP_NAME=WebScan Backend
HOST=127.0.0.1
PORT=8888

# 数据库配置
DATABASE_URL=sqlite://db.sqlite3

# AI配置
OPENAI_API_KEY=your_api_key
OPENAI_BASE_URL=https://api.openai.com/v1

# AWVS配置（可选）
AWVS_URL=https://awvs.example.com
AWVS_API_KEY=your_awvs_key

# Seebug配置（可选）
SEEBUG_API_KEY=your_seebug_key
```

### 启动服务

```bash
python main.py
```

服务将在 `http://127.0.0.1:8888` 启动。

---

## 📚 API文档

启动后访问：
- **Swagger UI**: http://localhost:8888/docs
- **ReDoc**: http://localhost:8888/redoc

### 主要API端点

#### 扫描任务

```http
POST /api/tasks/              # 创建扫描任务
GET  /api/tasks/{id}          # 获取任务详情
DELETE /api/tasks/{id}        # 删除任务
```

#### 报告管理

```http
GET  /api/reports/            # 获取报告列表
POST /api/reports/            # 创建报告
GET  /api/reports/{id}        # 获取报告详情
GET  /api/reports/{id}/export # 导出报告
```

#### POC管理

```http
GET  /api/poc/list            # 获取POC列表
POST /api/poc/execute         # 执行POC
```

#### AI Agent

```http
POST /api/ai_agents/scan      # 启动Agent扫描
GET  /api/ai_agents/tasks     # 获取任务列表
```

---

## 🔌 插件开发

### 添加新的漏洞扫描插件

```python
from vulnerability_scan_plugins.base import BaseScanner

class MyScanner(BaseScanner):
    name = "my_scanner"
    description = "自定义漏洞扫描器"
    
    async def scan(self, target: str) -> dict:
        # 扫描逻辑
        return {
            "vulnerable": False,
            "details": {}
        }
```

### 注册插件

在 `vulnerability_scan_plugins/__init__.py` 中注册：

```python
from .my_scanner import MyScanner

PLUGINS["my_scanner"] = MyScanner
```

---

## 🧪 测试

```bash
# 运行所有测试
pytest tests/ -v

# 运行特定测试
pytest tests/api/test_tasks.py -v

# 生成覆盖率报告
pytest --cov=backend --cov-report=html
```

---

## 📦 依赖说明

### 核心依赖

| 包名 | 版本 | 用途 |
|------|------|------|
| fastapi | 0.115+ | Web框架 |
| uvicorn | 0.34+ | ASGI服务器 |
| tortoise-orm | 最新版 | 异步ORM |
| langchain | 0.3+ | AI框架 |
| langgraph | 0.2+ | AI工作流 |

### 安全扫描依赖

| 包名 | 用途 |
|------|------|
| requests | HTTP请求 |
| beautifulsoup4 | HTML解析 |
| aiohttp | 异步HTTP |

---

## 🔗 相关项目

- [TOSKill](../TOSKill/) - 轻量级AI驱动安全扫描服务
- [front](../front/) - Vue3前端界面
- [toskill-frontend](../toskill-frontend/) - TOSKill前端界面

---

## 📄 许可证

本项目采用 MIT 许可证。详见 [LICENSE](../LICENSE) 文件。

---

## 📬 联系方式

- 邮箱: fybfyb0801@qq.com
- 微信: fyb15227908455
- GitHub: [FYBhandsome/WebScan](https://github.com/FYBhandsome/WebScan)
