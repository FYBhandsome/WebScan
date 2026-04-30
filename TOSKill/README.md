# TOSKill - AI驱动的Web安全扫描平台

<p align="center">
  <img src="https://img.shields.io/badge/version-2.3.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/python-3.10+-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-orange.svg" alt="License">
  <img src="https://img.shields.io/badge/tools-22-brightgreen.svg" alt="Tools">
</p>

## 📖 项目简介

TOSKill 是一个基于 AI 的 Web 安全扫描平台，集成了 22 个安全扫描工具，支持信息收集、漏洞扫描和 POC 验证。通过 LangGraph 工作流引擎和 WebSocket 实时通信，提供智能化的渗透测试体验。

### ✨ 核心特性

- **🤖 AI 驱动**: 基于 LangGraph 的智能工作流编排
- **🔧 22 个工具**: 覆盖信息收集、漏洞扫描、POC验证全流程
- **🔐 认证共享**: 工具间自动传递认证信息，支持深度扫描
- **📡 实时通信**: WebSocket 双向通信，实时获取扫描进度
- **📊 报告生成**: 自动生成 Markdown 格式的扫描报告
- **🧪 完整测试**: 320+ 测试用例，覆盖率 > 90%

---

## 🚀 快速开始

### 环境要求

- Python 3.10+
- FastAPI
- LangChain / LangGraph

### 安装

```bash
# 克隆项目
git clone https://github.com/your-repo/TOSKill.git
cd TOSKill

# 安装依赖
pip install -r requirements.txt
```

### 启动服务

```bash
# 启动 TOSKill 服务（端口 8081）
python -m TOSKill.main
```

服务启动后访问：
- **前端界面**: http://localhost:8081/
- **API 文档**: http://localhost:8081/docs
- **健康检查**: http://localhost:8081/api/toskill/health

---

## 📚 工具列表

### 信息收集工具 (11个)

| 工具名称 | 功能描述 |
|---------|---------|
| `baseinfo_scan` | 基础信息收集（标题、服务器、技术栈） |
| `port_scan` | 端口扫描与服务识别 |
| `subdomain_scan` | 子域名发现 |
| `dir_brute` | 目录扫描与敏感文件发现 |
| `waf_detect_scan` | WAF 检测与绕过建议 |
| `cdn_detect_scan` | CDN 检测与真实 IP 发现 |
| `cms_detect_scan` | CMS 识别与版本检测 |
| `infoleak_scan` | 信息泄露扫描 |
| `ip_locate_scan` | IP 地理位置定位 |
| `webside_query_scan` | ICP 备案查询 |
| `web_weight_scan` | 搜索引擎权重查询 |

### 漏洞扫描工具 (8个)

| 工具名称 | 功能描述 | 风险等级 |
|---------|---------|---------|
| `sqli_scan` | SQL 注入扫描 | 高危 |
| `xss_scan` | XSS 跨站脚本扫描 | 中危 |
| `csrf_scan` | CSRF 跨站请求伪造扫描 | 中危 |
| `fileupload_scan` | 文件上传漏洞扫描 | 严重 |
| `cmdi_scan` | 命令注入扫描 | 严重 |
| `ssrf_scan` | SSRF 服务端请求伪造扫描 | 高危 |
| `lfi_scan` | LFI 本地文件包含扫描 | 高危 |
| `weakpass_scan` | 弱口令扫描 | 高危 |

### POC 验证工具 (3个)

| 工具名称 | 功能描述 | CVE |
|---------|---------|-----|
| `thinkphp_rce_scan` | ThinkPHP 远程代码执行 | CVE-2019-9082 |
| `struts2_scan` | Struts2 系列漏洞 | CVE-2017-5638 等 |
| `weblogic_scan` | WebLogic 系列漏洞 | CVE-2020-2551 等 |

---

## 🔌 API 接口

### REST API

```bash
# 健康检查
GET /api/toskill/health

# 获取工具列表
GET /api/toskill/tools

# 执行单个工具
POST /api/toskill/tools/execute
{
    "tool_name": "sqli_scan",
    "target": "http://example.com/page?id=1",
    "cookies": {"session": "abc123"}
}

# 信息收集扫描
POST /api/toskill/scan/info
{
    "target": "example.com"
}

# 漏洞扫描
POST /api/toskill/scan/vuln
{
    "target": "http://example.com"
}

# 完整扫描
POST /api/toskill/scan/full
{
    "target": "example.com"
}
```

### WebSocket API

```javascript
// 连接 WebSocket
const ws = new WebSocket('ws://localhost:8081/api/ai-chat/ws');

// 发送扫描请求
ws.send(JSON.stringify({
    type: 'user_message',
    payload: { content: '扫描 example.com' }
}));

// 接收扫描结果
ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    console.log(data.message_type, data.payload);
};
```

---

## 🔐 认证机制

### 认证信息共享

TOSKill 支持在工作流节点间自动传递认证信息：

```
1. weakpass_scan 成功登录 → 获取 Cookie/Token
2. 系统存储到 auth_info → 自动传递
3. 后续工具自动使用 → 深度扫描
```

### 认证参数

所有漏洞扫描工具支持以下认证参数：

```json
{
    "cookies": {"session": "abc123"},
    "headers": {"Authorization": "Bearer xxx"},
    "auth_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

---

## 📡 WebSocket 数据传输

### 标准消息格式

```json
{
    "message_id": "uuid",
    "timestamp": "2026-04-26T12:00:00.000Z",
    "message_type": "task_completed",
    "message_hash": "a1b2c3d4e5f6g7h8",
    "payload": { ... }
}
```

### 消息类型

| 消息类型 | 说明 |
|---------|------|
| `task_completed` | 工具执行完成 |
| `task_progress` | 执行进度更新 |
| `auth_info_obtained` | 认证信息获取成功 |
| `user_interaction_required` | 需要用户交互 |

---

## 📁 项目结构

```
TOSKill/
├── AI/                     # AI 工作流引擎
│   ├── graph.py           # LangGraph 工作流定义
│   ├── tools.py           # 工具函数与包装
│   ├── state.py           # 状态定义
│   └── core.py            # 核心逻辑
├── api/                    # API 接口
│   ├── scan_api.py        # 扫描接口
│   ├── ai_chat_websocket.py  # WebSocket 处理
│   └── report.py          # 报告接口
├── config.py              # 配置文件
├── main.py                # 入口文件
├── API_DOCUMENTATION.md   # API 文档
├── TOOLS_DOCUMENTATION.md # 工具文档
└── README.md              # 项目说明
```

---

## 🧪 测试

```bash
# 运行所有测试
pytest

# 运行特定标记的测试
pytest -m api
pytest -m workflow
pytest -m websocket
pytest -m auth

# 生成覆盖率报告
pytest --cov=TOSKill --cov-report=html
```

---

## 📋 配置

### 环境变量

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `APP_NAME` | TOSKill Security Scanner | 应用名称 |
| `APP_VERSION` | 2.3.0 | 应用版本 |
| `HOST` | 0.0.0.0 | 监听地址 |
| `PORT` | 8081 | 监听端口 |
| `LOG_LEVEL` | INFO | 日志级别 |
| `SESSION_TTL` | 3600 | 会话过期时间（秒） |

---

## 🛡️ 安全注意事项

1. **授权要求**: 使用前请确保已获得目标系统所有者的明确授权
2. **测试环境**: 建议先在测试环境中验证工具行为
3. **数据保护**: 扫描过程中获取的敏感数据应妥善保管
4. **法律合规**: 遵守当地法律法规，不得用于非法目的

---

## 📄 许可证

本项目采用 MIT 许可证。详见 [LICENSE](LICENSE) 文件。

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

---

## 📞 联系方式

- 项目主页: https://github.com/your-repo/TOSKill
- 问题反馈: https://github.com/your-repo/TOSKill/issues

---

*版本: 2.3.0 | 更新日期: 2026-04-26*
