# WebScan 信息收集插件模块

## 目录结构

```
plugins/
├── api_discovery/          # API接口发现
├── baseinfo/               # 基础信息收集
├── brute_force/            # 弱口令爆破
├── cdnexist/               # CDN检测
├── cloud_detect/           # 云服务识别
├── common/                 # 公共模块
├── crawler/                # 爬虫模块
├── ct_logs/                # 证书透明度查询
├── dirscan/                # 目录扫描
├── dns_history/            # 被动DNS历史
├── dns_query/              # DNS记录查询
├── fingerprint/            # 指纹识别增强
├── github_sensitive/       # GitHub敏感信息
├── infoleak/               # 信息泄露检测
├── iplocating/             # IP定位
├── loginfo/                # 日志分析
├── mail_server/            # 邮件服务器检测
├── portscan/               # 端口扫描
├── randheader/             # 随机Header
├── screenshot/             # 网站截图
├── search_engine/          # 搜索引擎发现
├── sensitive_dir/          # 敏感目录扫描增强
├── sensitive_param/        # 敏感参数发现
├── ssl_analyzer/           # SSL证书分析
├── subdomain/              # 子域名枚举
├── tech_stack/             # 技术栈识别
├── tests/                  # 测试模块
├── waf/                    # WAF检测
├── webside/                # 旁站查询
├── webweight/              # 权重查询
├── whatcms/                # CMS识别
└── whois/                  # Whois查询
```

## 插件列表

### 基础信息收集

| 插件名称 | 路径 | 功能描述 |
|----------|------|----------|
| 基础信息收集 | `baseinfo/baseinfo.py` | 收集网站基础信息，包括标题、描述、关键词、响应头、服务器类型等 |
| IP定位 | `iplocating/iplocating.py` | 查询IP地址的地理位置信息，支持多API备份和IPv6 |
| Whois查询 | `whois/scanner.py` | 查询域名和IP的Whois注册信息，支持多数据源聚合 |
| 权重查询 | `webweight/webweight.py` | 查询网站在搜索引擎中的权重 |
| 旁站查询 | `webside/webside.py` | 查询同IP服务器上的其他网站 |
| 日志分析 | `loginfo/loginfo.py` | 分析网站日志信息 |

### 域名与DNS

| 插件名称 | 路径 | 功能描述 |
|----------|------|----------|
| 子域名枚举 | `subdomain/subdomain.py` | 枚举目标域名的子域名，支持多数据源 |
| DNS记录查询 | `dns_query/scanner.py` | 查询域名的各种DNS记录类型 |
| 被动DNS历史 | `dns_history/scanner.py` | 查询域名的历史DNS记录 |
| 证书透明度查询 | `ct_logs/scanner.py` | 查询证书透明度日志，发现子域名 |

### 网络与服务

| 插件名称 | 路径 | 功能描述 |
|----------|------|----------|
| 端口扫描 | `portscan/portscan.py` | 扫描目标主机开放端口和服务识别 |
| CDN检测 | `cdnexist/cdnexist.py` | 检测目标网站是否使用CDN服务 |
| WAF检测 | `waf/waf.py` | 检测目标网站是否使用Web应用防火墙 |
| 云服务识别 | `cloud_detect/scanner.py` | 识别网站使用的云服务商和CDN |
| 邮件服务器检测 | `mail_server/scanner.py` | 检测邮件服务器配置和安全状态 |

### Web技术识别

| 插件名称 | 路径 | 功能描述 |
|----------|------|----------|
| CMS识别 | `whatcms/whatcms.py` | 识别目标网站使用的CMS系统类型和版本 |
| 指纹识别增强 | `fingerprint/scanner.py` | 增强版指纹识别，识别更多技术栈 |
| 技术栈识别 | `tech_stack/scanner.py` | 识别网站使用的技术栈、框架、库等 |

### 安全检测

| 插件名称 | 路径 | 功能描述 |
|----------|------|----------|
| 信息泄露 | `infoleak/infoleak.py` | 检测网站敏感信息泄露，支持智能404检测 |
| 目录扫描 | `dirscan/dirscan.py` | 扫描网站敏感目录和文件 |
| 敏感目录扫描增强 | `sensitive_dir/scanner.py` | 增强版敏感目录扫描 |
| 敏感参数发现 | `sensitive_param/scanner.py` | 发现URL和表单中的敏感参数 |
| SSL证书分析 | `ssl_analyzer/scanner.py` | 分析SSL/TLS证书安全状态，检测漏洞 |
| 弱口令爆破 | `brute_force/scanner.py` | 多服务弱口令爆破，支持SSH/FTP/MySQL/Redis等 |

### 信息发现

| 插件名称 | 路径 | 功能描述 |
|----------|------|----------|
| 爬虫模块 | `crawler/crawler.py` | 爬取网站页面，提取链接和表单 |
| API接口发现 | `api_discovery/scanner.py` | 发现网站隐藏的API接口和端点 |
| GitHub敏感信息 | `github_sensitive/scanner.py` | 在GitHub上搜索目标相关的敏感信息 |
| 搜索引擎发现 | `search_engine/scanner.py` | 通过搜索引擎发现相关信息 |
| 网站截图 | `screenshot/scanner.py` | 对网站进行多设备截图 |

### 辅助工具

| 插件名称 | 路径 | 功能描述 |
|----------|------|----------|
| 随机Header | `randheader/randheader.py` | 生成随机HTTP请求头 |
| 公共模块 | `common/common.py` | 提供公共工具函数和代理过滤功能 |

## 插件开发规范

### 目录结构

每个插件应包含以下文件：

```
plugin_name/
├── __init__.py      # 模块初始化
├── scanner.py       # 主扫描器实现
└── README.md        # 插件说明文档（可选）
```

### 基类继承

```python
from backend.plugins.base import BasePlugin

class MyScanner(BasePlugin):
    def __init__(self, target: str, config: dict = None):
        super().__init__(target, config)
    
    def scan(self) -> dict:
        # 实现扫描逻辑
        return {"success": True, "data": {}}
```

### 返回格式

插件应返回统一的字典格式：

```python
{
    "success": True,          # 是否成功
    "data": {},               # 返回数据
    "error": "",              # 错误信息
    "duration": 1.5           # 执行时间（秒）
}
```

## 使用示例

### 单独使用插件

```python
from backend.plugins.baseinfo.baseinfo import getbaseinfo

result = getbaseinfo("https://example.com")
print(result)
```

### 批量扫描

```python
from backend.plugins.portscan.portscan import PortScanner

scanner = PortScanner("192.168.1.1", {"ports": "1-1000"})
result = scanner.scan()
print(result)
```

## 依赖安装

```bash
pip install requests beautifulsoup4 lxml cryptography
pip install paramiko pymysql psycopg2-binary redis pymongo
pip install bcrypt argon2-cffi
```

## 注意事项

1. **请求频率**: 请合理控制请求频率，避免对目标服务器造成压力
2. **授权许可**: 在对目标进行扫描前，请确保已获得授权
3. **数据安全**: 扫描结果可能包含敏感信息，请妥善保管
4. **法律合规**: 请遵守当地法律法规，仅用于合法的安全测试

## 更新日志

### v2.0.0 (2026-04-24)
- 新增16个信息收集插件
- 优化现有插件代码结构
- 添加弱口令爆破模块
- 添加SSL证书分析模块
- 添加技术栈识别模块
- 完善文档和测试用例

## 贡献指南

1. Fork 本仓库
2. 创建新的功能分支 (`git checkout -b feature/new-plugin`)
3. 提交更改 (`git commit -am 'Add new plugin'`)
4. 推送到分支 (`git push origin feature/new-plugin`)
5. 创建 Pull Request

## 许可证

本项目采用 MIT 许可证，详见 LICENSE 文件。
