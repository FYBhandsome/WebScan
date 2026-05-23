# Tests - 测试套件

本目录包含 WebScan AI Security Platform 的集成测试和端到端测试。

## 📁 目录结构

```
tests/
├── e2e/                          # 端到端测试
│   └── test_full_workflow.py     # 完整工作流测试
│
├── integration/                  # 集成测试
│   ├── test_ai_agent_workflow.py # AI Agent工作流测试
│   ├── test_ai_endpoints.py      # AI端点测试
│   ├── test_api_endpoints.py     # API端点测试
│   ├── test_frontend_proxy.py    # 前端代理测试
│   ├── test_frontend_scenarios.py# 前端场景测试
│   ├── test_full_backend_api.py  # 完整后端API测试
│   └── test_toskill_bridge.py    # TOSKill桥接测试
│
├── performance/                  # 性能测试
│   └── test_concurrent.py        # 并发测试
│
├── unit/                         # 单元测试
│   ├── test_ai_analyzer.py       # AI分析器测试
│   ├── test_api_response.py      # API响应测试
│   ├── test_api_validation.py    # API验证测试
│   ├── test_graph_decision.py    # 图决策测试
│   ├── test_model_consistency.py # 模型一致性测试
│   └── test_tool_mapping.py      # 工具映射测试
│
├── conftest.py                   # pytest配置
├── mock_toskill_server.py        # 模拟TOSKill服务器
└── __init__.py
```

## 🚀 运行测试

### 运行所有测试

```bash
pytest tests/ -v
```

### 运行特定类型的测试

```bash
# 单元测试
pytest tests/unit/ -v

# 集成测试
pytest tests/integration/ -v

# 端到端测试
pytest tests/e2e/ -v

# 性能测试
pytest tests/performance/ -v
```

### 生成覆盖率报告

```bash
pytest tests/ --cov=. --cov-report=html
```

## 📋 测试分类

| 类型 | 描述 | 运行条件 |
|------|------|----------|
| 单元测试 | 测试单个函数/类 | 随时可运行 |
| 集成测试 | 测试模块间交互 | 需要后端服务 |
| 端到端测试 | 测试完整流程 | 需要完整环境 |
| 性能测试 | 测试并发性能 | 需要完整环境 |

## 🔧 测试配置

测试配置在 `conftest.py` 中定义，包括：

- 测试数据库配置
- 测试客户端fixture
- 模拟数据fixture
- 测试环境设置

## 📝 编写测试

### 单元测试示例

```python
def test_api_response_format():
    """测试API响应格式"""
    response = {"code": 200, "data": {}}
    assert response["code"] == 200
    assert "data" in response
```

### 集成测试示例

```python
@pytest.mark.asyncio
async def test_scan_workflow(client):
    """测试扫描工作流"""
    response = await client.post("/api/tasks/", json={
        "target": "http://example.com",
        "scan_type": "full"
    })
    assert response.status_code == 200
```

## 📄 许可证

MIT License
