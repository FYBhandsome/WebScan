# Migrations - 数据库迁移

本目录包含 WebScan AI Security Platform 的数据库迁移文件。

## 📁 目录结构

```
migrations/
└── models/
    └── 4_20260520092810_None.py  # 初始迁移文件
```

## 🔧 使用说明

### 迁移工具

项目使用 [Aerich](https://github.com/tortoise/aerich) 进行数据库迁移管理。

### 常用命令

```bash
# 初始化迁移
aerich init -t backend.config.TORTOISE_ORM

# 初始化数据库
aerich init-db

# 生成迁移文件
aerich migrate --name "description"

# 执行迁移
aerich upgrade

# 回滚迁移
aerich downgrade

# 查看迁移历史
aerich history
```

### 配置文件

迁移配置在 `aerich.ini` 中：

```ini
[aerich]
tortoise_orm = backend.config.TORTOISE_ORM
location = ./migrations
src_folder = ./backend
```

## 📝 创建新迁移

1. 修改 `backend/models.py` 中的模型定义
2. 生成迁移文件：
   ```bash
   aerich migrate --name "add_new_table"
   ```
3. 执行迁移：
   ```bash
   aerich upgrade
   ```

## ⚠️ 注意事项

- 在生产环境执行迁移前，请先备份数据库
- 迁移文件应该纳入版本控制
- 避免直接修改已执行的迁移文件

## 📄 许可证

MIT License
