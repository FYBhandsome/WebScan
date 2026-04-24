# POC 包说明文档

## 简介

`poc` 是 AI_WebSecurity 项目的漏洞验证模块集合，提供了多种常见漏洞的 Proof of Concept (POC) 脚本。这些脚本用于验证目标系统是否存在特定漏洞，为安全测试和漏洞评估提供工具支持。

## 功能模块列表

| 目标系统 | 漏洞编号 | 文件位置 | 漏洞描述 |
|---------|---------|---------|----------|
| **drupal** | CVE-2018-7600 | `drupal/cve_2018_7600_poc.py` | drupal 远程代码执行漏洞 |
| **JBoss** | CVE-2017-12149 | `jboss/cve_2017_12149_poc.py` | JBoss 反序列化漏洞 |
| **Nexus** | CVE-2020-10199 | `nexus/cve_2020_10199_poc.py` | Nexus Repository Manager 远程代码执行漏洞 |
| **Struts2** | S2-009 | `struts2/struts2_009_poc.py` | Struts2 远程代码执行漏洞 |
| **Struts2** | S2-032 | `struts2/struts2_032_poc.py` | Struts2 远程代码执行漏洞 |
| **Tomcat** | CVE-2017-12615 | `tomcat/cve_2017_12615_poc.py` | Tomcat PUT方法任意文件上传漏洞 |
| **Tomcat** | CVE-2022-22965 | `tomcat/CVE-2022-22965.py` | Spring Cloud Gateway 远程代码执行漏洞 |
| **Tomcat** | CVE-2022-47986 | `tomcat/CVE-2022-47986.py` | Tomcat 文件包含漏洞 |
| **WebLogic** | CVE-2018-2628 | `weblogic/cve_2018_2628_poc.py` | WebLogic 反序列化漏洞 |
| **WebLogic** | CVE-2018-2894 | `weblogic/cve_2018_2894_poc.py` | WebLogic 反序列化漏洞 |
| **WebLogic** | CVE-2020-2551 | `weblogic/cve_2020_2551_poc.py` | WebLogic IIOP 反序列化漏洞 |
| **WebLogic** | CVE-2020-14756 | `weblogic/CVE-2020-14756.py` | WebLogic 远程代码执行漏洞 |
| **WebLogic** | CVE-2023-21839 | `weblogic/CVE-2023-21839.py` | WebLogic 远程代码执行漏洞 |

## 核心功能说明

### 1. 漏洞验证

- 提供针对特定漏洞的验证脚本
- 检测目标系统是否存在相应漏洞
- 输出验证结果和详细信息

### 2. 按系统分类

- 按目标系统类型组织POC脚本
- 便于查找和使用特定系统的漏洞验证工具
- 每个系统目录包含该系统的多个漏洞POC

### 3. 详细的漏洞信息

- 包含漏洞编号（如CVE编号）
- 提供漏洞的基本描述
- 实现漏洞的验证逻辑

## 依赖项

- Python 3.7+
- requests: 用于HTTP请求
- 各POC可能有额外的依赖，具体请参考各POC的实现文件

## 使用方法

### 导入并使用单个POC

```python
# 示例：导入Tomcat CVE-2017-12615漏洞POC
from backend.poc.tomcat.cve_2017_12149_poc import check_vulnerability

# 使用示例
target_url = "https://www.baidu.com:8080"
result = check_vulnerability(target_url)
print(f"漏洞验证结果: {result}")
```

### POC调用示例

#### 1. 验证Tomcat PUT方法任意文件上传漏洞 (CVE-2017-12615)

```python
from backend.poc.tomcat.cve_2017_12615_poc import check_vulnerability

target = "http://192.168.1.100:8080"
result = check_vulnerability(target)
print(f"Tomcat CVE-2017-12615 漏洞验证结果: {result}")
```

#### 2. 验证Struts2 S2-009漏洞

```python
from backend.poc.struts2.struts2_009_poc import check_vulnerability

target = "http://192.168.1.101:8080"
result = check_vulnerability(target)
print(f"Struts2 S2-009 漏洞验证结果: {result}")
```

## POC开发规范

### 新增POC的步骤

1. 在 `poc` 目录下创建目标系统的子目录（如不存在）
2. 在子目录中创建 `__init__.py` 文件（可以为空）
3. 创建POC文件，命名为 `[漏洞编号]_poc.py` 或 `[漏洞编号].py`
4. 实现漏洞验证函数，通常命名为 `check_vulnerability`
5. 提供详细的文档字符串和注释

### 代码规范

- 使用 UTF-8 编码
- 遵循 PEP 8 代码风格
- 提供详细的文档字符串
- 实现错误处理和异常捕获
- 考虑网络波动等情况，添加超时处理
- 验证完成后清理测试文件或会话

## 注意事项

1. **法律合规**：使用POC进行测试时，请确保遵守相关法律法规，仅对授权的目标进行测试
2. **安全风险**：POC可能会对目标系统造成影响，请谨慎使用
3. **网络环境**：确保测试环境的网络连接正常
4. **目标系统**：确保目标系统的IP地址和端口正确
5. **权限要求**：部分漏洞验证可能需要特定的权限

## 版本历史

- **v1.0.0**：初始版本，包含基础POC模块
- **v1.1.0**：添加了更多漏洞的POC
- **v1.2.0**：优化了部分POC的性能和稳定性

## 贡献指南

欢迎提交Issue和Pull Request，共同改进POC功能。提交代码时，请确保：

1. 代码符合项目的编码规范
2. 添加了必要的测试用例
3. 更新了相关文档
4. 提供了漏洞的详细信息和验证方法

## 联系信息

如有问题或建议，请联系项目维护者。

---

*本文档由 AI_WebSecurity 项目组维护*
*最后更新时间：2026-01-22*