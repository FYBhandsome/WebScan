# AI Agents - Web安全漏洞扫描智能体编排系统

## 项目概述

基于LangGraph框架构建的Web安全漏洞扫描Agent智能体编排系统，实现自主任务规划、工具调用、结果迭代验证、漏洞分析与报告生成的端到端自动化扫描流程。

### 核心特性

✅ **完整的LangGraph工作流**：环境感知 → 任务规划 → 智能决策 → 工具执行 → 结果验证 → 漏洞分析 → 报告生成
✅ **10个功能节点**：覆盖扫描全流程的完整节点体系
✅ **统一的工具管理**：集成所有现有扫描插件和POC
✅ **智能决策优化**：基于优先级、资源分配、策略自适应
✅ **代码生成与执行**：支持动态生成和执行扫描脚本
✅ **灵活的配置系统**：支持动态配置和扩展
✅ **完善的API接口**：RESTful API，易于集成
✅ **可扩展的架构**：预留插件注册接口，易于扩展

### 技术栈

- **LangGraph**：构建有向图工作流
- **LangChain**：LLM增强任务规划
- **FastAPI**：异步API接口
- **Tortoise-ORM**：数据持久化
- **asyncio**：异步任务执行

***

## 目录结构

```
ai_agents/
├── __init__.py              # 模块入口
├── agent_config.py          # Agent配置管理
├── core/                    # 核心框架
│   ├── __init__.py
│   ├── state.py             # Agent状态管理
│   ├── graph.py             # LangGraph图构建
│   ├── nodes.py             # 节点定义
│   └── workflow_logger.py   # 工作流日志追踪
├── tools/                   # 工具集成
│   ├── __init__.py
│   ├── registry.py          # 工具注册表
│   ├── wrappers.py          # 工具异步封装
│   └── adapters.py          # 工具适配器
├── code_execution/          # 代码执行模块
│   ├── __init__.py
│   ├── code_generator.py    # 代码生成器
│   ├── executor.py          # 代码执行器
│   ├── environment.py       # 环境感知
│   └── capability_enhancer.py # 功能增强器
├── poc_system/              # POC管理系统
│   ├── __init__.py
│   ├── poc_manager.py       # POC管理器
│   ├── verification_engine.py # 验证引擎
│   └── result_analyzer.py   # 结果分析器
├── analyzers/               # 结果分析
│   ├── __init__.py
│   ├── vuln_analyzer.py     # 漏洞分析器
│   └── report_gen.py        # 报告生成器
├── utils/                   # 工具函数
│   ├── __init__.py
│   ├── priority.py          # 优先级管理
│   └── retry.py             # 重试策略
├── README.md                # 功能说明文档
└── PERFORMANCE_REPORT.md    # 性能测试报告
```

***

## 图工作流节点详解

AIAgent工作流包含**10个功能节点**，形成完整的扫描链路：

### 节点列表

| 序号 | 节点名称                    | 节点类                       | 功能描述                       |
| -- | ----------------------- | ------------------------- | -------------------------- |
| 1  | environment\_awareness  | EnvironmentAwarenessNode  | 环境感知，检测操作系统、Python版本、可用工具等 |
| 2  | task\_planning          | TaskPlanningNode          | 任务规划，支持规则化和LLM增强两种模式       |
| 3  | intelligent\_decision   | IntelligentDecisionNode   | 智能决策，基于环境信息和目标特征决定扫描策略     |
| 4  | tool\_execution         | ToolExecutionNode         | 工具执行，调用插件和POC进行扫描          |
| 5  | code\_generation        | CodeGenerationNode        | 代码生成，根据需求动态生成扫描脚本          |
| 6  | code\_execution         | CodeExecutionNode         | 代码执行，在沙箱环境中执行生成的代码         |
| 7  | capability\_enhancement | CapabilityEnhancementNode | 功能增强，动态安装依赖和扩展能力           |
| 8  | result\_verification    | ResultVerificationNode    | 结果验证，验证扫描结果并补充任务           |
| 9  | vulnerability\_analysis | VulnerabilityAnalysisNode | 漏洞分析，去重、排序和严重度评估           |
| 10 | report\_generation      | ReportGenerationNode      | 报告生成，生成JSON/HTML格式报告       |

### 工作流程图

```
┌─────────────────────────────────────────────────────────────────┐
│                        AIAgent 工作流                            │
└─────────────────────────────────────────────────────────────────┘

    ┌──────────────────┐
    │ environment_     │
    │   awareness      │ ──── 检测OS、Python版本、可用工具
    └────────┬─────────┘
             │
             ▼
    ┌──────────────────┐
    │ task_planning    │ ──── 规划扫描任务（规则化/LLM增强）
    └────────┬─────────┘
             │
             ▼
    ┌──────────────────┐
    │ intelligent_     │
    │   decision       │ ──── 智能决策下一步操作
    └────────┬─────────┘
             │
    ┌────────┼────────┬────────────┐
    │        │        │            │
    ▼        ▼        ▼            ▼
┌────────┐┌────────┐┌────────┐┌────────┐
│ tool_  ││ code_  ││capabil-││        │
│execu-  ││genera-││ ity_   ││        │
│ tion   ││ tion   ││enhance ││        │
└───┬────┘└───┬────┘└───┬────┘└────────┘
    │         │         │
    │         ▼         │
    │    ┌────────┐     │
    │    │ code_  │◄────┘
    │    │execu-  │
    │    │ tion   │
    │    └───┬────┘
    │        │
    └────────┼────────
             │
             ▼
    ┌──────────────────┐
    │ result_          │
    │ verification     │ ──── 验证结果并补充任务
    └────────┬─────────┘
             │
    ┌────────┼────────┐
    │        │        │
    ▼        ▼        ▼
┌────────┐┌────────┐┌────────┐
│工具执行││        ││分析    │
│(循环)  ││        ││        │
│        ││        ││        │
└───┬────┘└────────┘└────────┘
    │
    └────┬────┘
         │
         ▼
┌──────────────────┐
│ vulnerability_   │
│   analysis       │ ──── 去重、排序、POC匹配
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ report_          │
│ generation       │ ──── 生成扫描报告
└──────────────────┘
```

### 节点详细说明

#### 1. EnvironmentAwarenessNode（环境感知节点）

**功能**：检测运行环境信息，为后续决策提供依据

**输出**：

- 操作系统信息（Windows/Linux/Darwin）
- Python版本
- 可用工具列表（nmap、masscan等）
- 网络配置信息
- 系统资源状态

#### 2. TaskPlanningNode（任务规划节点）

**功能**：根据目标特征生成扫描任务列表

**两种模式**：

- **规则化规划**：基于预设规则快速生成任务
- **LLM增强规划**：使用大语言模型智能规划

**输出**：

- 规划的任务列表
- 任务优先级

#### 3. IntelligentDecisionNode（智能决策节点）

**功能**：基于环境信息和目标特征智能决定下一步操作

**决策依据**：

- 操作系统类型
- 可用工具
- 目标CMS类型
- 网络状态

#### 4. ToolExecutionNode（工具执行节点）

**功能**：执行插件和POC工具

**特性**：

- 并发控制（最大并发数可配置）
- 超时控制
- 重试机制
- 结果缓存

#### 5. CodeGenerationNode（代码生成节点）

**功能**：根据扫描需求动态生成扫描脚本

**特性**：

- 支持多种语言（Python、Bash、PowerShell）
- LLM驱动的代码生成
- 自动保存生成的代码文件
- 支持Pocsuite3 POC生成

**输出**：

- 生成的代码
- 代码语言
- 依赖列表
- 代码文件路径

#### 6. CodeExecutionNode（代码执行节点）

**功能**：在沙箱环境中执行生成的代码

**特性**：

- 沙箱隔离执行
- 超时控制
- 输出捕获
- 错误处理

**安全措施**：

- 启用沙箱模式
- 限制执行时间
- 限制资源使用

#### 7. CapabilityEnhancementNode（功能增强节点）

**功能**：动态增强AI Agent能力

**特性**：

- 自动安装缺失依赖
- 动态加载新功能
- 能力版本管理

#### 8. ResultVerificationNode（结果验证节点）

**功能**：验证扫描结果，决定是否继续执行

**特性**：

- 基于CMS补充POC任务
- 基于端口补充POC任务
- 迭代验证支持

#### 9. VulnerabilityAnalysisNode（漏洞分析节点）

**功能**：分析发现的漏洞

**特性**：

- 漏洞去重
- 按严重度排序
- AI智能POC匹配
- 自动生成验证任务

#### 10. ReportGenerationNode（报告生成节点）

**功能**：生成最终扫描报告

**输出格式**：

- JSON格式报告
- HTML格式报告
- 执行轨迹报告

***

## 节点参数详解

### 节点输入/输出参数

#### 1. EnvironmentAwarenessNode

```python
# 输入参数
state.target          # 目标URL/IP
state.task_id         # 任务ID

# 输出参数
state.target_context["environment_info"]   # 环境报告
state.target_context["os_system"]          # 操作系统类型
state.target_context["python_version"]     # Python版本
state.target_context["available_tools"]    # 可用工具列表
```

#### 2. TaskPlanningNode

```python
# 输入参数
state.target              # 目标URL/IP
state.target_context      # 目标上下文（包含环境信息）

# 输出参数
state.planned_tasks       # 规划的任务列表 ["baseinfo", "portscan", ...]
state.current_task        # 当前任务名称
```

#### 3. IntelligentDecisionNode

```python
# 输入参数
state.target_context      # 目标上下文
state.planned_tasks       # 计划任务列表

# 输出参数
state.target_context["intelligent_decisions"]  # 决策列表

# 路由决策结果
# "fixed_tool"      → 使用现有工具扫描
# "custom_code"     → 生成自定义代码扫描
# "enhance_first"   → 先增强功能再扫描
```

#### 4. ToolExecutionNode

```python
# 输入参数
state.current_task        # 当前要执行的工具名称
state.target              # 目标URL/IP

# 输出参数
state.tool_results[tool_name]  # 工具执行结果
state.completed_tasks          # 已完成任务列表
state.target_context           # 更新的上下文（如CMS、端口等）
```

#### 5. CodeGenerationNode

```python
# 输入参数
state.target_context["need_custom_scan"]        # 是否需要自定义扫描
state.target_context["custom_scan_type"]        # 扫描类型
state.target_context["custom_scan_requirements"] # 扫描需求描述
state.target_context["custom_scan_language"]    # 代码语言

# 输出参数
state.tool_results["generated_code"]  # 生成的代码信息
  # - code: 代码内容
  # - language: 语言类型
  # - dependencies: 依赖列表
  # - file_path: 代码文件路径
```

#### 6. CodeExecutionNode

```python
# 输入参数
state.target_context["generated_code"]  # 生成的代码信息

# 输出参数
state.tool_results["code_execution"]  # 执行结果
  # - status: success/failed
  # - output: 执行输出
  # - error: 错误信息
```

#### 7. VulnerabilityAnalysisNode

```python
# 输入参数
state.vulnerabilities  # 发现的漏洞列表

# 输出参数
state.vulnerabilities           # 去重排序后的漏洞列表
state.poc_verification_tasks    # 生成的POC验证任务
```

### 条件路由逻辑

#### result\_verification → 3种分支

```python
def _should_continue_or_verify(state):
    # 1. 达到最大工具执行轮次(50次) → analyze
    # 2. 有待执行的任务 → continue
    # 3. 所有任务完成 → analyze
```

#### vulnerability\_analysis → 1种分支

```python
def _post_analysis_routing(state):
    # 直接进入报告生成
    # → report_generation
```

***

## 数据流转路径

### 主流程数据流

```
┌──────────────────────────────────────────────────────────────────┐
│                        数据流转路径                               │
└──────────────────────────────────────────────────────────────────┘

1. 初始化阶段
   target → AgentState
   └─→ task_id: 自动生成
   └─→ target: 用户输入
   └─→ target_context: {}

2. 环境感知阶段
   AgentState → EnvironmentAwarenessNode
   └─→ target_context["environment_info"]: 环境报告
   └─→ target_context["os_system"]: 操作系统
   └─→ target_context["available_tools"]: 可用工具

3. 任务规划阶段
   AgentState → TaskPlanningNode
   └─→ planned_tasks: ["baseinfo", "portscan", ...]
   └─→ current_task: "baseinfo"

4. 智能决策阶段
   AgentState → IntelligentDecisionNode
   └─→ target_context["intelligent_decisions"]: 决策列表
   └─→ 路由决策: fixed_tool/custom_code/enhance_first/...

5. 工具执行阶段
   AgentState → ToolExecutionNode
   └─→ tool_results[tool_name]: 执行结果
   └─→ completed_tasks: 已完成任务
   └─→ target_context["cms"]: CMS信息
   └─→ target_context["open_ports"]: 开放端口

6. 结果验证阶段
   AgentState → ResultVerificationNode
   └─→ should_continue: True/False
   └─→ planned_tasks: 更新的任务列表

7. 漏洞分析阶段
   AgentState → VulnerabilityAnalysisNode
   └─→ vulnerabilities: 去重排序后的漏洞
   └─→ poc_verification_tasks: 生成的验证任务

8. 报告生成阶段
   AgentState → ReportGenerationNode
   └─→ tool_results["final_report"]: 标准报告
   └─→ tool_results["execution_trace_report"]: 执行轨迹
   └─→ tool_results["html_execution_trace"]: HTML报告
```

***

## 工具列表

### 插件工具

| 工具名称            | 功能描述               | 类别   |
| --------------- | ------------------ | ---- |
| baseinfo        | 基础信息收集（服务器、IP、域名等） | 信息收集 |
| portscan        | 端口扫描，识别开放端口和服务     | 端口扫描 |
| waf\_detect     | WAF检测，识别Web应用防火墙   | 安全检测 |
| cdn\_detect     | CDN检测，判断是否使用CDN    | 网络分析 |
| cms\_identify   | CMS识别，识别网站使用的CMS系统 | 指纹识别 |
| infoleak\_scan  | 信息泄露扫描，检测敏感信息泄露    | 安全检测 |
| subdomain\_scan | 子域名扫描，枚举子域名        | 域名分析 |
| webside\_scan   | 站点信息收集，获取网站基本信息    | 信息收集 |
| webweight\_scan | 网站权重查询，获取网站权重信息    | 信息收集 |
| iplocating      | IP定位，获取IP地理位置信息    | 信息收集 |

### POC工具

#### WebLogic POC

| POC名称                      | CVE编号          | 漏洞类型   | 严重度      |
| -------------------------- | -------------- | ------ | -------- |
| poc\_weblogic\_2020\_2551  | CVE-2020-2551  | RCE    | Critical |
| poc\_weblogic\_2018\_2628  | CVE-2018-2628  | RCE    | Critical |
| poc\_weblogic\_2018\_2894  | CVE-2018-2894  | 任意文件上传 | High     |
| poc\_weblogic\_2020\_14756 | CVE-2020-14756 | RCE    | Critical |
| poc\_weblogic\_2023\_21839 | CVE-2023-21839 | RCE    | Critical |

#### Struts2 POC

| POC名称             | CVE编号         | 漏洞类型 | 严重度      |
| ----------------- | ------------- | ---- | -------- |
| struts2\_009\_poc | CVE-2013-1965 | RCE  | Critical |
| struts2\_032\_poc | CVE-2016-3081 | RCE  | Critical |

#### Tomcat POC

| POC名称                 | CVE编号          | 漏洞类型             | 严重度      |
| --------------------- | -------------- | ---------------- | -------- |
| cve\_2017\_12615\_poc | CVE-2017-12615 | 任意文件写入           | High     |
| CVE-2022-22965        | CVE-2022-22965 | Spring4Shell RCE | Critical |
| CVE-2022-47986        | CVE-2022-47986 | RCE              | Critical |

#### 其他POC

| POC名称                 | CVE编号          | 漏洞类型       | 严重度      |
| --------------------- | -------------- | ---------- | -------- |
| cve\_2017\_12149\_poc | CVE-2017-12149 | JBoss RCE  | Critical |
| cve\_2020\_10199\_poc | CVE-2020-10199 | Nexus RCE  | High     |
| cve\_2018\_7600\_poc  | CVE-2018-7600  | Drupal RCE | Critical |

### 代码生成能力

| 扫描类型           | 支持语言                   | 功能描述            |
| -------------- | ---------------------- | --------------- |
| vuln\_scan     | Python                 | 漏洞扫描脚本生成        |
| pocsuite3\_poc | Python                 | Pocsuite3 POC生成 |
| custom\_scan   | Python/Bash/PowerShell | 自定义扫描脚本         |

***

## 代码生成与执行节点

### 集成状态

✅ **CodeGenerationNode** 已正确集成到图结构中
✅ **CodeExecutionNode** 已正确集成到图结构中

### 功能测试

#### 代码生成节点测试

```python
# 测试代码生成功能
from ai_agents.core.nodes import CodeGenerationNode
from ai_agents.core.state import AgentState

state = AgentState(
    target="http://example.com",
    task_id="test_codegen",
    target_context={
        "need_custom_scan": True,
        "custom_scan_type": "vuln_scan",
        "custom_scan_requirements": "检测SQL注入漏洞"
    }
)

node = CodeGenerationNode()
result = await node(state)

# 验证结果
assert "generated_code" in result.tool_results
assert "code" in result.tool_results["generated_code"]
```

#### 代码执行节点测试

```python
# 测试代码执行功能
from ai_agents.core.nodes import CodeExecutionNode
from ai_agents.core.state import AgentState

state = AgentState(
    target="http://example.com",
    task_id="test_codeexec",
    target_context={
        "generated_code": {
            "code": "print('Hello, World!')",
            "language": "python"
        }
    }
)

node = CodeExecutionNode()
result = await node(state)

# 验证结果
assert "code_execution" in result.tool_results
```

### 安全注意事项

1. **沙箱执行**：代码在沙箱环境中执行，限制系统访问
2. **超时控制**：默认60秒超时，防止无限循环
3. **资源限制**：限制内存和CPU使用
4. **网络隔离**：可选的网络隔离执行

***

## 快速开始

### 1. 安装依赖

```bash
cd backend
pip install -r requirements.txt
```

### 2. 配置环境变量

在`.env`文件中添加以下配置：

```bash
# AI Agent 配置
AGENT_MAX_EXECUTION_TIME=300
AGENT_MAX_RETRIES=3
MAX_CONCURRENT_TOOLS=5
TOOL_TIMEOUT=60
ENABLE_LLM_PLANNING=true
ENABLE_MEMORY=true
ENABLE_KB_INTEGRATION=true

# OpenAI 配置
OPENAI_API_KEY=your_api_key
OPENAI_BASE_URL=https://api.openai.com/v1
MODEL_ID=gpt-4

# AWVS 配置
AWVS_API_URL=https://awvs.example.com
AWVS_API_KEY=your_awvs_key

# Seebug 配置
SEEBUG_API_KEY=your_seebug_key
```

### 3. 启动服务

```bash
python main.py
```

服务将在 `http://127.0.0.1:8888` 启动。

### 4. 使用Agent扫描

```bash
# 启动Agent扫描
curl -X POST "http://127.0.0.1:8888/api/ai_agents/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://www.baidu.com"
  }'

# 查询任务状态
curl "http://127.0.0.1:8888/api/ai_agents/tasks/{task_id}"
```

***

## API接口

### 启动Agent扫描

**端点**：`POST /api/ai_agents/scan`

**请求示例**：

```json
{
  "target": "https://www.baidu.com",
  "enable_llm_planning": true,
  "custom_tasks": ["baseinfo", "portscan"]
}
```

**响应示例**：

```json
{
  "task_id": "123e4567-e89b-12d3-a456-426614174000",
  "status": "running",
  "message": "Agent扫描任务已启动"
}
```

### 获取任务详情

**端点**：`GET /api/ai_agents/tasks/{task_id}`

**响应示例**：

```json
{
  "task_id": "123e4567-e89b-12d3-a456-426614174000",
  "status": "completed",
  "final_output": {
    "task_id": "123e4567-e89b-12d3-a456-426614174000",
    "target": "https://www.baidu.com",
    "vulnerabilities": {
      "list": [...],
      "total": 5,
      "summary": "共发现 5 个漏洞: Critical: 1, High: 2, Medium: 2"
    }
  }
}
```

### 其他API

- `GET /api/ai_agents/tasks`：获取任务列表
- `DELETE /api/ai_agents/tasks/{task_id}`：取消任务
- `GET /api/ai_agents/tools`：获取可用工具列表
- `GET /api/ai_agents/config`：获取配置
- `POST /api/ai_agents/config`：更新配置

***

## 测试

### 测试目录结构

```
ai_agents/
├── core/tests/               # 核心模块测试
│   ├── test_graph.py         # 图构建和执行测试
│   ├── test_state.py         # 状态管理测试
│   ├── test_nodes.py         # 节点实现测试
│   └── test_agent_graph_workflow.py # 工作流测试
├── tools/tests/              # 工具适配器测试
│   └── test_adapters.py      # 适配器功能测试
├── poc_system/tests/         # POC系统测试
└── analyzers/tests/          # 分析器测试
```

### 运行测试

```bash
# 运行所有AI Agents测试
pytest ai_agents/ -v

# 运行特定模块测试
pytest ai_agents/core/tests/ -v
pytest ai_agents/tools/tests/ -v

# 运行带覆盖率的测试
pytest ai_agents/ --cov=ai_agents --cov-report=html
```

### 测试要求

- 所有新功能必须包含单元测试
- 测试覆盖率应不低于70%
- 涉及外部服务的测试使用`@pytest.mark.integration`标记

***

## 配置说明

### 核心配置

| 配置项                     | 默认值    | 说明             |
| ----------------------- | ------ | -------------- |
| MAX\_EXECUTION\_TIME    | 300    | Agent最大执行时间（秒） |
| MAX\_RETRIES            | 3      | 工具执行最大重试次数     |
| MAX\_CONCURRENT\_TOOLS  | 5      | 最大并发工具执行数      |
| TOOL\_TIMEOUT           | 60     | 单个工具执行超时时间（秒）  |
| ENABLE\_LLM\_PLANNING   | true   | 是否启用LLM增强任务规划  |
| DEFAULT\_SCAN\_TASKS    | \[...] | 默认扫描任务列表       |
| ENABLE\_MEMORY          | true   | 是否启用记忆机制       |
| ENABLE\_KB\_INTEGRATION | true   | 是否启用漏洞知识库集成    |

***

## 扩展开发

### 添加新工具

1. 创建工具函数：

```python
async def my_scan_tool(target: str) -> dict:
    return {"status": "success", "data": {...}}
```

1. 注册工具：

```python
from ai_agents.tools import register_tool

@register_tool(
    name="my_tool",
    description="我的扫描工具",
    category="plugin",
    timeout=30
)
async def my_tool(target: str):
    return await my_scan_tool(target)
```

### 添加新节点

1. 创建节点类：

```python
from ai_agents.core.state import AgentState

class MyCustomNode:
    async def __call__(self, state: AgentState) -> AgentState:
        return state
```

1. 在graph.py中添加节点：

```python
from my_node import MyCustomNode

def _build_graph(self) -> StateGraph:
    workflow = StateGraph(AgentState)
    workflow.add_node("my_custom_node", MyCustomNode())
    return workflow
```

***

## 故障排查

### 常见问题

1. **工具执行失败**
   - 检查工具是否正确注册
   - 检查目标URL/IP是否可访问
   - 查看日志中的详细错误信息
2. **LLM规划失败**
   - 检查OPENAI\_API\_KEY和OPENAI\_BASE\_URL配置
   - 检查网络连接
   - 可以禁用LLM规划使用规则化规划
3. **任务超时**
   - 增加MAX\_EXECUTION\_TIME配置
   - 减少扫描任务数量
   - 优化工具超时时间
4. **代码执行失败**
   - 检查生成的代码语法是否正确
   - 检查依赖是否已安装
   - 查看沙箱执行日志

### 日志查看

所有Agent执行日志记录在`logs/app.log`：

```bash
# 查看实时日志
tail -f logs/app.log

# 搜索特定任务的日志
grep "task_id: 123e4567" logs/app.log
```

***

## 性能指标

根据性能测试报告：

| 指标      | 数值       | 说明         |
| ------- | -------- | ---------- |
| 单目标扫描时间 | 45.2秒    | 比传统扫描快34%  |
| 多目标并发效率 | 42.9秒/目标 | 比传统扫描快26%  |
| 漏洞发现准确率 | 92%      | 比传统扫描高18%  |
| 内存占用    | 245MB    | 比传统扫描低21%  |
| 自动化程度   | 95%      | 比传统扫描高111% |

***

## 许可证

本项目遵循原项目的许可证。

***

## 贡献

欢迎提交Issue和Pull Request来改进本项目。

***

## 总结

AI Agents智能体编排系统提供了完整的Web安全漏洞扫描解决方案，具备：

✅ **完整的LangGraph工作流**：12个功能节点覆盖扫描全流程
✅ **代码生成与执行**：支持动态生成和执行扫描脚本
✅ **统一的工具管理**：集成所有现有插件和POC
✅ **智能决策优化**：基于优先级、资源分配、策略自适应
✅ **灵活的配置系统**：支持动态配置和扩展
✅ **完善的API接口**：RESTful API，易于集成
✅ **可扩展的架构**：预留插件注册接口，易于扩展

通过本系统，可以实现自动化、智能化的Web安全漏洞扫描，大幅提升扫描效率和准确性。
