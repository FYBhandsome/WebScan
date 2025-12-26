# AWVS API 使用说明

## 概述

AWVS（Acunetix Web Vulnerability Scanner）集成模块提供了与AWVS扫描器交互的完整API接口。

## 配置

在 `config.py` 中配置AWVS连接信息：

```python
AWVS_API_URL: str = "https://127.0.0.1:3443"
AWVS_API_KEY: str = "1986ad8c0a5b3df4d7028d5f3c06e936cc23a5d4737044dc18935d8a6f0199a50"
```

## API 端点

### 1. 健康检查
**GET** `/api/awvs/health`

检查AWVS服务连接状态

**响应示例：**
```json
{
  "code": 200,
  "message": "AWVS服务连接正常",
  "data": {
    "status": "connected"
  }
}
```

### 2. 获取所有扫描任务
**GET** `/api/awvs/scans`

获取所有扫描任务列表

**响应示例：**
```json
{
  "code": 200,
  "message": "获取成功",
  "data": [
    {
      "target_id": "xxx",
      "profile_name": "full_scan",
      "current_session": {
        "status": "completed",
        "severity_counts": {
          "high": 0,
          "medium": 0,
          "low": 0,
          "info": 0
        },
        "start_date": "2025-12-26T20:00:00"
      },
      "target": {
        "address": "http://example.com"
      }
    }
  ]
}
```

### 3. 创建扫描任务
**POST** `/api/awvs/scan`

创建新的扫描任务

**请求体：**
```json
{
  "url": "http://example.com",
  "scan_type": "full_scan"
}
```

**扫描类型：**
- `full_scan`: 完整扫描
- `high_risk_vuln`: 高风险漏洞扫描
- `xss_vuln`: XSS漏洞扫描
- `sqli_vuln`: SQL注入漏洞扫描
- `weak_passwords`: 弱密码扫描
- `crawl_only`: 仅爬取

**响应示例：**
```json
{
  "code": 200,
  "message": "扫描任务创建成功",
  "data": {
    "target_id": "xxx"
  }
}
```

### 4. 获取目标漏洞列表
**GET** `/api/awvs/vulnerabilities/{target_id}`

获取指定目标的漏洞列表

**响应示例：**
```json
{
  "code": 200,
  "message": "获取成功",
  "data": [
    {
      "id": 1,
      "severity": "High",
      "target": "http://example.com",
      "vuln_id": "xxx",
      "vuln_name": "SQL Injection",
      "time": "2025-12-26 20:00:00"
    }
  ]
}
```

### 5. 获取漏洞详情
**GET** `/api/awvs/vulnerability/{vuln_id}`

获取指定漏洞的详细信息

**响应示例：**
```json
{
  "code": 200,
  "message": "获取成功",
  "data": {
    "affects_url": "http://example.com",
    "last_seen": "2025-12-26 20:00:00",
    "vt_name": "SQL Injection",
    "details": "漏洞详细信息...",
    "request": "HTTP请求详情...",
    "recommendation": "修复建议...",
    "tests_performed": "测试内容..."
  }
}
```

### 6. 获取漏洞排名
**GET** `/api/awvs/vulnerabilities/rank`

获取漏洞排名（前5名）

**响应示例：**
```json
{
  "code": 200,
  "message": "获取成功",
  "data": [
    {
      "name": "SQL Injection",
      "value": 10
    },
    {
      "name": "XSS",
      "value": 5
    }
  ]
}
```

### 7. 获取漏洞统计
**GET** `/api/awvs/vulnerabilities/stats`

获取漏洞统计信息

**响应示例：**
```json
{
  "code": 200,
  "message": "获取成功",
  "data": {
    "high": [10, 5, 2],
    "normal": [20, 10, 5]
  }
}
```

### 8. 获取所有目标
**GET** `/api/awvs/targets`

获取所有目标列表

**响应示例：**
```json
{
  "code": 200,
  "message": "获取成功",
  "data": [
    {
      "target_id": "xxx",
      "address": "http://example.com",
      "description": "测试站点",
      "criticality": 10
    }
  ]
}
```

### 9. 添加目标
**POST** `/api/awvs/target`

添加新的扫描目标

**请求体：**
```json
{
  "address": "http://example.com",
  "description": "测试站点"
}
```

**响应示例：**
```json
{
  "code": 200,
  "message": "添加成功",
  "data": {
    "target_id": "xxx"
  }
}
```

## 使用示例

### PowerShell 示例

```powershell
# 健康检查
Invoke-WebRequest -Uri "http://127.0.0.1:8888/api/awvs/health" -Method GET -UseBasicParsing

# 获取所有扫描任务
Invoke-WebRequest -Uri "http://127.0.0.1:8888/api/awvs/scans" -Method GET -UseBasicParsing

# 创建扫描任务
$body = @{
    url = "http://example.com"
    scan_type = "full_scan"
} | ConvertTo-Json

Invoke-WebRequest -Uri "http://127.0.0.1:8888/api/awvs/scan" -Method POST -Body $body -ContentType "application/json" -UseBasicParsing
```

### Python 示例

```python
import requests

BASE_URL = "http://127.0.0.1:8888/api/awvs"

# 健康检查
response = requests.get(f"{BASE_URL}/health")
print(response.json())

# 获取所有扫描任务
response = requests.get(f"{BASE_URL}/scans")
print(response.json())

# 创建扫描任务
data = {
    "url": "http://example.com",
    "scan_type": "full_scan"
}
response = requests.post(f"{BASE_URL}/scan", json=data)
print(response.json())
```

## 注意事项

1. 确保AWVS服务正在运行并且可以访问
2. 确保API密钥配置正确
3. 扫描任务可能需要较长时间完成
4. 建议定期检查扫描任务状态
5. 漏洞详情可能包含敏感信息，请妥善保管

## 错误处理

所有API端点都遵循统一的错误响应格式：

```json
{
  "code": 500,
  "message": "错误描述",
  "data": null
}
```

常见错误码：
- `200`: 成功
- `400`: 请求参数错误
- `404`: 资源不存在
- `500`: 服务器内部错误
- `503`: AWVS服务连接失败
