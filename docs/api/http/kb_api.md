# 知识库API文档

## 接口列表

### 1. 获取漏洞列表

**接口**: `GET /api/kb/vulnerabilities`

**描述**: 获取漏洞知识库列表

**请求参数**:

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| page | int | 否 | 页码，默认1 |
| page_size | int | 否 | 每页数量，默认20 |
| severity | string | 否 | 严重程度过滤 |
| keyword | string | 否 | 关键词搜索 |

**请求示例**:

```bash
GET /api/kb/vulnerabilities?page=1&page_size=20&severity=high
```

**响应示例**:

```json
{
  "code": 200,
  "message": "获取成功",
  "data": {
    "total": 100,
    "page": 1,
    "page_size": 20,
    "items": [
      {
        "id": 1,
        "name": "SQL注入漏洞",
        "severity": "high",
        "description": "存在SQL注入漏洞",
        "solution": "使用参数化查询",
        "references": ["https://owasp.org"],
        "created_at": "2024-01-01T00:00:00"
      }
    ]
  }
}
```

---

### 2. 获取漏洞详情

**接口**: `GET /api/kb/vulnerabilities/{id}`

**描述**: 根据ID获取漏洞详情

**路径参数**:

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| id | int | 是 | 漏洞ID |

**请求示例**:

```bash
GET /api/kb/vulnerabilities/1
```

**响应示例**:

```json
{
  "id": 1,
  "name": "SQL注入漏洞",
  "severity": "high",
  "description": "存在SQL注入漏洞",
  "solution": "使用参数化查询",
  "references": ["https://owasp.org"],
  "created_at": "2024-01-01T00:00:00"
}
```

---

### 3. 从Seebug搜索

**接口**: `POST /api/kb/search-from-seebug`

**描述**: 从Seebug平台搜索漏洞信息

**请求体**:

```json
{
  "keyword": "SQL注入",
  "page": 1
}
```

**请求参数说明**:

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| keyword | string | 是 | 搜索关键词 |
| page | int | 否 | 页码，默认1 |

**响应示例**:

```json
{
  "code": 200,
  "message": "搜索成功",
  "data": {
    "total": 50,
    "page": 1,
    "items": [
      {
        "ssvid": "SSVID-12345",
        "name": "CVE-2020-1234",
        "type": "SQL注入",
        "level": "高危",
        "publish_time": "2024-01-01"
      }
    ]
  }
}
```

---

### 4. 搜索POC

**接口**: `POST /api/kb/seebug/poc/search`

**描述**: 搜索Seebug平台的POC

**请求体**:

```json
{
  "keyword": "CVE-2020",
  "page": 1
}
```

**响应示例**:

```json
{
  "code": 200,
  "message": "搜索成功",
  "data": {
    "total": 20,
    "items": [
      {
        "ssvid": "SSVID-12345",
        "name": "CVE-2020-1234 POC",
        "type": "远程代码执行",
        "level": "严重"
      }
    ]
  }
}
```

---

### 5. 下载POC

**接口**: `POST /api/kb/seebug/poc/download`

**描述**: 下载指定的POC代码

**请求体**:

```json
{
  "ssvid": "SSVID-12345",
  "save_to_local": true,
  "category": "seebug",
  "cve_id": "CVE-2020-1234",
  "vuln_name": "SQL注入漏洞"
}
```

**请求参数说明**:

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| ssvid | string | 是 | Seebug漏洞ID |
| save_to_local | boolean | 否 | 是否保存到本地，默认false |
| category | string | 否 | 分类，默认seebug |
| cve_id | string | 否 | CVE编号 |
| vuln_name | string | 否 | 漏洞名称 |

**响应示例**:

```json
{
  "code": 200,
  "message": "下载成功",
  "data": {
    "poc_content": "POC代码内容...",
    "file_path": "/path/to/poc.py"
  }
}
```

## 错误码

| 错误码 | 说明 |
|--------|------|
| 200 | 成功 |
| 400 | 请求参数错误 |
| 404 | 漏洞不存在 |
| 500 | 服务器内部错误 |
