# TOSKill - AI驱动的Web安全扫描平台

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/python-3.8+-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-orange.svg" alt="License">
  <img src="https://img.shields.io/badge/tools-22-brightgreen.svg" alt="Tools">
</p>

## 项目简介

TOSKill 是重构版的AI驱动Web安全扫描后端服务，基于LangGraph工作流引擎和WebSocket实时通信，提供智能化的渗透测试体验。

### 核心特性

- **AI驱动决策** - 基于LangGraph的ReACT推理框架，AI使用Thought-Action-Reason模式进行智能决策
- **RAG知识库增强** - 集成LlamaIndex实现专业知识库检索增强
- **22个安全工具** - 覆盖信息收集、漏洞扫描、POC验证全流程
- **用户交互中断** - 工作流支持interrupt暂停等待用户确认
- **认证信息共享** - 工具间自动传递认证信息，支持深度扫描
- **WebSocket实时通信** - 双向通信，实时获取扫描进度
- **AI脚本生成** - 支持自定义脚本上传和AI生成，自动安全审查
- **报告自动生成** - AI分析扫描结果，生成Markdown格式报告

---

## 快速开始

### 环境要求

- Python 3.8+
- FastAPI
- LangChain / LangGraph
- LlamaIndex (RAG)

### 安装

```bash
# 克隆项目
git clone https://github.com/your-repo/AI_WebSecurity.git
cd AI_WebSecurity/TOSKill

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

### 启动服务

```bash
# 启动 TOSKill 服务（端口 8081）
python main.py
```

服务启动后访问：
- **前端界面**: http://localhost:8081/frontend
- **API文档**: http://localhost:8081/docs
- **ReDoc**: http://localhost:8081/redoc
- **健康检查**: http://localhost:8081/health

---

## 架构设计

### LangGraph工作流

TOSKill使用LangGraph构建三个主要子图：

```
┌─────────────────────────────────────────────────────────────┐
│                    IntentRecognitionGraph                    │
│  用户意图识别入口 → 意图校验 → 工具存在性检查 → 执行/聊天/扫描  │
└─────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│InfoCollectionGraph│ │  VulnScanGraph  │ │   ReportGraph   │
│  信息收集子图     │ │  漏洞扫描子图   │ │  报告生成子图   │
└─────────────────┘ └─────────────────┘ └─────────────────┘
```

### ReACT推理循环

```
ai_decision → user_interact → router → execute_task → vulnerability_check → ai_decision
     │            │            │           │                  │
     ▼            ▼            ▼           ▼                  ▼
  AI决策      用户交互      路由分发    执行工具           漏洞检查
  (RAG增强)   (interrupt)             (认证共享)         (高危中断)
```

### 核心组件

| 组件 | 文件 | 描述 |
|------|------|------|
| **AgentOrchestrator** | `AI/graph.py` | Agent编排器，管理多个子图的执行 |
| **MemoryStore** | `AI/graph.py` | 会话状态存储，支持TTL过期清理 |
| **ScanState** | `AI/state.py` | 扫描状态定义，TypedDict类型 |
| **RAG Retriever** | `RAG/retriever.py` | RAG知识库检索器 |
| **AIChatManager** | `api/ai_chat_websocket.py` | WebSocket连接管理器 |

---

## 工具列表

### 信息收集工具 (11个)

| 工具名称 | 功能描述 |
|---------|---------|
| `baseinfo` | 基础信息收集（标题、服务器、技术栈） |
| `portscan` | 端口扫描与服务识别 |
| `subdomain` | 子域名发现 |
| `dirscan` | 目录扫描与敏感文件发现 |
| `waf` | WAF检测与绕过建议 |
| `cdnexist` | CDN检测与真实IP发现 |
| `whatcms` | CMS识别与版本检测 |
| `infoleak` | 信息泄露扫描 |
| `iplocating` | IP地理位置定位 |
| `webside` | ICP备案查询 |
| `webweight` | 搜索引擎权重查询 |

### 漏洞扫描工具 (8个)

| 工具名称 | 功能描述 | 风险等级 |
|---------|---------|---------|
| `sqli` | SQL注入扫描 | 高危 |
| `xss` | XSS跨站脚本扫描 | 中危 |
| `csrf` | CSRF跨站请求伪造扫描 | 中危 |
| `fileupload` | 文件上传漏洞扫描 | 严重 |
| `cmdi` | 命令注入扫描 | 严重 |
| `ssrf` | SSRF服务端请求伪造扫描 | 高危 |
| `lfi` | LFI本地文件包含扫描 | 高危 |
| `weakpass` | 弱口令扫描 | 高危 |

### POC验证工具 (3个)

| 工具名称 | 功能描述 | CVE |
|---------|---------|-----|
| `thinkphp` | ThinkPHP远程代码执行 | CVE-2019-9082 |
| `struts2` | Struts2系列漏洞 | CVE-2017-5638等 |
| `weblogic` | WebLogic系列漏洞 | CVE-2020-2551等 |

---

## API接口

### REST API

```bash
# 健康检查
GET /health

# 获取工具列表
GET /api/tools

# 执行单个工具
POST /api/tools/execute
{
    "tool_name": "sqli",
    "target": "http://example.com/page?id=1"
}

# 信息收集扫描
POST /api/scan/info
{
    "target": "example.com"
}

# 漏洞扫描
POST /api/scan/vuln
{
    "target": "http://example.com"
}

# 完整扫描
POST /api/scan/full
{
    "target": "example.com"
}

# 生成报告
POST /api/report/generate
{
    "session_id": "abc12345"
}
```

### WebSocket API

```javascript
// 连接 WebSocket
const ws = new WebSocket('ws://localhost:8081/api/ai-chat/ws');

// 连接成功后接收session_id
ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    if (data.type === 'connected') {
        console.log('Session ID:', data.payload.session_id);
    }
};

// 发送扫描请求
ws.send(JSON.stringify({
    type: 'start_scan',
    payload: {
        target: 'example.com',
        scan_mode: 'full'
    }
}));

// 用户确认交互
ws.send(JSON.stringify({
    type: 'user_confirm',
    payload: {
        choice: '1'  // 1=执行, 2=停止, 3=聊天
    }
}));

// AI对话
ws.send(JSON.stringify({
    type: 'chat',
    payload: {
        content: '请分析这个网站的安全状况'
    }
}));
```

### WebSocket消息类型

| 类型 | 方向 | 描述 |
|------|------|------|
| `connected` | 服务端→客户端 | 连接成功，返回session_id |
| `start_scan` | 客户端→服务端 | 开始扫描任务 |
| `scan_started` | 服务端→客户端 | 扫描已启动 |
| `task_started` | 服务端→客户端 | 单个任务开始 |
| `task_completed` | 服务端→客户端 | 单个任务完成 |
| `task_skipped` | 服务端→客户端 | 任务跳过 |
| `ai_decision` | 服务端→客户端 | AI决策结果 |
| `workflow_progress` | 服务端→客户端 | 工作流进度 |
| `interaction_required` | 服务端→客户端 | 需要用户交互 |
| `user_confirm` | 客户端→服务端 | 用户确认选择 |
| `workflow_resumed` | 服务端→客户端 | 工作流已恢复 |
| `high_risk_vulnerability_detected` | 服务端→客户端 | 高危漏洞检测 |
| `scan_completed` | 服务端→客户端 | 扫描完成 |
| `report_generated` | 服务端→客户端 | 报告已生成 |
| `ai_message` | 服务端→客户端 | AI对话消息 |
| `error` | 服务端→客户端 | 错误消息 |

---

## 认证机制

### 认证信息共享流程

```
1. weakpass扫描成功登录 → 获取Cookie/Token
2. 系统加密存储到auth_info → 自动传递给后续工具
3. 后续工具自动使用认证信息 → 实现深度扫描
```

### 认证信息提取

系统自动从扫描结果中提取以下认证信息：
- Cookies
- Authorization Header
- Bearer Token
- Session Token

### 认证重试机制

- 最大重试次数：3次
- 检测401/403响应自动触发重试
- 重试失败后通知用户手动认证

---

## RAG知识库

### 知识文档

TOSKill内置7个专业知识文档：

| 文档 | 内容 |
|------|------|
| `01_vulnerability_types.md` | 漏洞类型分类 |
| `02_attack_vectors.md` | 攻击向量说明 |
| `03_tool_mapping.md` | 工具映射关系 |
| `04_remediation_guide.md` | 修复建议指南 |
| `05_severity_classification.md` | 严重程度分类 |
| `06_owasp_top10.md` | OWASP Top 10 |
| `07_scanning_workflow.md` | 扫描工作流程 |

### 添加自定义知识

将Markdown文档放入 `TOSKill/RAG/knowledge/` 目录，系统会自动索引。

---

## 用户交互机制

### 工作流中断

使用LangGraph的`interrupt()`机制实现用户交互：

```python
# 工作流暂停等待用户输入
user_choice = interrupt({
    "type": "interaction_required",
    "options": [
        {"key": "1", "label": "执行"},
        {"key": "2", "label": "停止"},
        {"key": "3", "label": "聊天"}
    ]
})

# 用户确认后恢复工作流
result = await orchestrator.resume_workflow(session_id, user_choice)
```

### 高危漏洞确认

检测到高危漏洞时自动中断：

```python
# 高危漏洞检测中断
user_decision = interrupt({
    "type": "high_risk_vulnerability_detected",
    "options": [
        {"key": "continue", "label": "继续扫描"},
        {"key": "stop", "label": "停止并报告"},
        {"key": "poc_verify", "label": "POC验证"}
    ]
})
```

---

## 项目结构

```
TOSKill/
├── AI/                        # AI核心模块
│   ├── core.py               # 核心业务逻辑
│   ├── graph.py              # LangGraph工作流定义
│   ├── state.py              # 状态定义
│   ├── tools.py              # 工具函数与包装
│   ├── validators.py         # 输入验证器
│   └── script_safety.py      # 脚本安全审查
│
├── RAG/                       # RAG知识库模块
│   ├── rag_engine.py         # RAG引擎
│   ├── retriever.py          # 检索器
│   ├── knowledge/            # 知识文档
│   └── storage/              # 向量存储
│
├── api/                       # API接口
│   ├── ai_chat_websocket.py  # WebSocket处理
│   ├── scan_api.py           # 扫描接口
│   └── report.py             # 报告接口
│
├── tools/                     # 扫描工具
│   ├── info_collection/      # 信息收集工具
│   ├── vuln_scan/            # 漏洞扫描工具
│   ├── poc/                  # POC验证工具
│   └── report/               # 报告生成
│
├── config.py                 # 配置文件
├── main.py                   # 入口文件
├── cli.py                    # 命令行接口
├── API_DOCUMENTATION.md      # API文档
├── TOOLS_DOCUMENTATION.md    # 工具文档
└── README.md                 # 项目说明
```

---

## 配置

### 环境变量

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `APP_NAME` | TOSKill Security Scanner | 应用名称 |
| `APP_VERSION` | 1.0.0 | 应用版本 |
| `HOST` | 127.0.0.1 | 监听地址 |
| `PORT` | 8081 | 监听端口 |
| `LOG_LEVEL` | INFO | 日志级别 |
| `LOG_FILE` | logs/toskill.log | 日志文件 |
| `OPENAI_API_KEY` | - | AI模型API密钥 |
| `OPENAI_BASE_URL` | - | AI模型API地址 |
| `MODEL_ID` | xop3qwen1b7 | 模型ID |
| `LLM_TEMPERATURE` | 0.1 | 模型温度 |
| `SCAN_TIMEOUT` | 300 | 扫描超时时间 |
| `MAX_CONCURRENT_SCANS` | 5 | 最大并发扫描数 |

### 配置文件示例

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

---

## 测试

```bash
# 运行所有测试
cd tests
pytest

# 运行特定测试
pytest test_toskill_workflow.py -v
pytest test_toskill_websocket.py -v
pytest test_toskill_api.py -v

# 生成覆盖率报告
pytest --cov=TOSKill --cov-report=html
```

---

## 安全注意事项

1. **授权要求**: 使用前请确保已获得目标系统所有者的明确授权
2. **测试环境**: 建议先在测试环境中验证工具行为
3. **数据保护**: 扫描过程中获取的敏感数据应妥善保管
4. **法律合规**: 遵守当地法律法规，不得用于非法目的
5. **脚本审查**: 自定义脚本会自动进行安全审查

---

## 相关项目

- **TOSKillfront** - 重构版前端项目（`../TOSKillfront/`）
- **backend** - 旧版后端项目（已废弃，`../backend/`）
- **front** - 旧版前端项目（已废弃，`../front/`）

---

## 许可证

本项目采用 MIT 许可证。详见 [LICENSE](../LICENSE) 文件。

---

## 贡献

欢迎提交 Issue 和 Pull Request！

### 贡献流程

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

---

## 联系方式

- 项目主页: https://github.com/your-repo/AI_WebSecurity
- 问题反馈: https://github.com/your-repo/AI_WebSecurity/issues

---

*版本: 1.0.0 | 更新日期: 2026-05-01*
