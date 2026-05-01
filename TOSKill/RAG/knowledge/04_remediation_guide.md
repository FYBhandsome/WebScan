# 漏洞修复方案（Remediation Guide）

## XSS修复方案

### 根本措施

1. **输出编码**: 根据输出上下文选择编码（HTML实体、JS编码、URL编码）
2. **CSP策略**: `Content-Security-Policy: default-src 'self'; script-src 'self'`
3. **HttpOnly Cookie**: 防止Cookie被JS读取
4. **输入验证**: 白名单验证，拒绝非法字符

### 框架级方案

- React: 默认转义，避免 `dangerouslySetInnerHTML`
- Vue: 避免 `v-html`，使用模板语法
- Django: 使用 `escape()` 或 `{% autoescape on %}`
- Spring: 使用 `HtmlUtils.htmlEscape()`

### 检测绕过修复

- 不要仅黑名单过滤 `<script>` 标签
- 不要仅检测一次编码后的值
- 对所有输出点（URL参数、Header、JSON、XML）都编码

***

## SQL注入修复方案

### 根本措施

1. **参数化查询（Prepared Statement）**: 所有数据库操作使用预编译
2. **ORM框架**: Hibernate、SQLAlchemy、Entity Framework
3. **存储过程**: 定义好接口，限制SQL注入面
4. **最小权限**: 数据库账号仅授予必要权限

### 各语言实现

```java
// Java (JDBC PreparedStatement)
String sql = "SELECT * FROM users WHERE id = ?";
PreparedStatement stmt = conn.prepareStatement(sql);
stmt.setInt(1, userId);
```

```python
# Python (参数化)
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

```php
// PHP (PDO)
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute(['id' => $userId]);
```

### WAF规则

- 拦截 `UNION SELECT`、`1=1`、`sleep(`、`information_schema` 等关键字
- 限制请求参数长度
- IP频率限制

***

## 文件上传修复方案

1. **白名单扩展名**: 仅允许 .jpg/.png/.pdf 等安全类型
2. **文件内容检测**: 检查MIME Magic Number，不看Content-Type
3. **重命名文件**: 使用UUID/时间戳重命名，不保留原始文件名
4. **存储隔离**: 上传目录与Web目录分离，或设置不执行权限
5. **文件大小限制**: 设置合理的上传大小上限
6. **病毒扫描**: 集成ClamAV等扫描引擎
7. **访问控制**: 上传文件通过脚本读取而非直接访问

***

## 命令执行修复方案

1. **避免直接调用系统命令**: 使用语言内置函数代替 `system()`/`exec()`
2. **参数数组化**: 使用数组传参而非字符串拼接
   ```python
   # 错误: os.system("ping " + user_input)
   # 正确: subprocess.run(["ping", user_input], shell=False)
   ```
3. **输入白名单**: 仅允许字母数字
4. **权限限制**: 使用受限用户运行服务（如www-data）
5. **沙箱**: Docker/jail/chroot隔离

***

## 弱口令修复方案

1. **密码复杂度策略**: 最小8位，含大小写+数字+特殊字符
2. **账户锁定**: 连续N次失败后锁定
3. **多因素认证(MFA)**: TOTP/SMS/硬件Key
4. **密码哈希**: bcrypt/argon2/scrypt，加盐
5. **禁止默认口令**: 首次登录强制修改
6. **密码管理器**: 鼓励使用密码管理工具

***

## SSRF修复方案

1. **URL白名单**: 仅允许访问指定域名/IP
2. **禁用危险协议**: 禁止 file://、gopher://、dict://
3. **DNS解析后检查**: 解析域名后检查IP是否为内网地址
4. **禁用302跟随**: 或严格限制跳转目标
5. **网络隔离**: 服务所在网络与内网隔离

***

## CSRF修复方案

1. **CSRF Token**: 每个表单/请求携带不可预测的Token
2. **SameSite Cookie**: `Set-Cookie: SameSite=Strict` 或 `Lax`
3. **自定义Header**: 验证 `X-Requested-With: XMLHttpRequest`
4. **Referer/Origin校验**: 检查请求来源
5. **二次确认**: 敏感操作要求输入密码

***

## LFI/目录遍历修复方案

1. **路径规范化**: 使用真实路径后白名单比对
2. **禁用用户输入**: 不将用户输入直接作为文件路径
3. **白名单映射**: 数字ID映射到文件，不用文件名
   ```php
   $pages = [1=>'home.php', 2=>'about.php'];
   include($pages[$id]);
   ```
4. **open\_basedir**: PHP限制文件访问目录
5. **禁用PHP封装器**: 配置 `allow_url_include=Off`

***

## 通用安全加固

### HTTP安全头

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000
Content-Security-Policy: default-src 'self'
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=()
```

### 日志安全

- 记录所有安全事件（登录失败、权限变更）
- 日志不记录敏感信息（密码、Token）
- 日志异地备份，防篡改

### 定期安全活动

- 季度渗透测试
- 月度漏洞扫描
- 每周安全更新
- 每日日志审计

