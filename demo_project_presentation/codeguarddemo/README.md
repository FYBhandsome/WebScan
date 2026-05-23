# CodeGuard-AST 代码审计智能体

基于 ReACT 架构的 Python 代码安全审计工具，通过 AST 语法树分析自动检测代码中的安全漏洞。

## 功能特性

- **ReACT 智能体工作流**：Reason → Act → Observe 循环，实现智能审计流程
- **AST 漏洞扫描**：检测高危函数、SQL 注入、硬编码密钥等安全问题
- **代码标准化差异对比**：使用 difflib 生成原始代码与标准化代码的差异
- **可视化前端页面**：原生 HTML/JS/CSS，上传代码即可查看审计结果
- **数据库持久化**：SQLite + Tortoise-ORM 存储审计历史

## 技术栈

| 组件 | 技术 |
|------|------|
| 后端框架 | FastAPI + Uvicorn |
| 数据库 | SQLite + Tortoise-ORM |
| 智能体 | LangGraph + ReACT 工作流 |
| 代码分析 | AST (Python 标准库) |
| 差异对比 | difflib (Python 标准库) |
| 前端 | 原生 HTML/JS/CSS |

## 项目结构

```
codeguard/
├── core/
│   └── config.py           # 应用配置
├── models/
│   └── models.py           # 数据库模型（AuditTask、Vulnerability 等）
├── services/
│   ├── ast_service.py      # AST 审计引擎
│   ├── diff_service.py     # 代码差异生成
│   └── react_agent.py      # ReACT 智能体工作流
├── api/
│   └── audit_api.py        # API 接口
├── utils/
│   └── tools.py            # 工具函数
├── static/
│   └── index.html          # 前端页面
├── tests/                  # 测试套件
│   ├── conftest.py
│   ├── test_ast_service.py
│   ├── test_diff_service.py
│   ├── test_react_agent.py
│   ├── test_audit_api.py
│   └── test_tools.py
├── main.py                 # 应用入口
├── requirements.txt        # 依赖清单
└── pytest.ini              # 测试配置
```

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 启动服务

```bash
python main.py
```

服务将在 `http://127.0.0.1:8000` 启动。

### 3. 访问前端

打开浏览器访问 `http://127.0.0.1:8000`，上传 `.py` 文件即可进行代码审计。

## API 接口

### POST /upload

上传 Python 代码文件进行审计。

**请求**：
- Content-Type: `multipart/form-data`
- 参数: `file` - Python 文件

**响应**：
```json
{
  "code": 200,
  "msg": "审计完成",
  "data": {
    "task_id": 1
  }
}
```

### GET /result/{task_id}

获取审计结果。

**响应**：
```json
{
  "code": 200,
  "msg": "成功",
  "data": {
    "filename": "test.py",
    "status": "SUCCESS",
    "vulns": [
      {
        "type": "硬编码密钥",
        "level": "HIGH",
        "line": 1,
        "code": "password = \"Admin@123456\"",
        "desc": "检测到硬编码密码/密钥，极易泄露"
      }
    ],
    "diff_html": "<table>...</table>"
  }
}
```

## 漏洞检测类型

| 漏洞类型 | 级别 | 检测规则 |
|----------|------|----------|
| 命令/代码执行 | HIGH | `eval()`、`exec()`、`os.system()`、`popen`、`subprocess` |
| SQL 注入风险 | MEDIUM | `cursor.execute()`、`cursor.executemany()` |
| 硬编码密钥 | HIGH | 变量名含 password/token/key/secret 且赋值为字符串常量 |
| 语法错误 | HIGH | 代码无法通过 AST 解析 |

## 测试

运行完整测试套件：

```bash
pytest -v
```

测试覆盖：
- AST 审计引擎（12 个测试）
- 差异服务（5 个测试）
- ReACT 智能体（7 个测试）
- API 接口（6 个测试）
- 工具函数（4 个测试）

## 示例

上传以下测试代码：

```python
# test_vuln.py
password = "Admin@123456"
user_input = input()
eval(user_input)
import os
os.system("ls")
cursor.execute(f"SELECT * FROM user WHERE name={user_input}")
```

审计结果将检测到：
- **高危**：硬编码密码 `password`
- **高危**：`eval()` 代码执行
- **高危**：`os.system()` 命令执行
- **中危**：SQL 注入风险

## 配置

环境变量：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CODE_GUARD_DB_URL` | `sqlite://codeguard.db` | 数据库连接 URL |

## 依赖

- fastapi==0.115.4
- uvicorn==0.32.0
- tortoise-orm==0.21.6
- pydantic==2.10.4
- pydantic-settings==2.7.0
- langgraph
- langchain-core
- python-multipart==0.0.15
- aiofiles==24.1.0

## License

MIT
