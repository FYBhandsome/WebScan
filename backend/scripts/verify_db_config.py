"""
验证数据库配置和路径

检查：
1. Backend数据库路径
2. TOSKill数据库路径
3. 数据库文件是否存在
"""
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

print("=" * 60)
print("验证数据库配置")
print("=" * 60)

print("\n1. Backend数据库配置:")
from backend.config import settings as backend_settings
print(f"   DATABASE_URL: {backend_settings.DATABASE_URL}")
print(f"   DATABASE_PATH: {backend_settings.DATABASE_PATH}")
print(f"   文件存在: {backend_settings.DATABASE_PATH.exists()}")
if backend_settings.DATABASE_PATH.exists():
    size = backend_settings.DATABASE_PATH.stat().st_size
    print(f"   文件大小: {size / 1024 / 1024:.2f} MB")

print("\n2. TOSKill数据库配置:")
from TOSKill.config import settings as toskill_settings
print(f"   DB_PATH: {toskill_settings.DB_PATH}")
print(f"   DATABASE_PATH: {toskill_settings.DATABASE_PATH}")
print(f"   文件存在: {toskill_settings.DATABASE_PATH.exists()}")
if toskill_settings.DATABASE_PATH.exists():
    size = toskill_settings.DATABASE_PATH.stat().st_size
    print(f"   文件大小: {size / 1024 / 1024:.2f} MB")

print("\n3. 数据库目录结构:")
backend_data_dir = project_root / "backend" / "data"
toskill_data_dir = project_root / "TOSKill" / "data"

print(f"   backend/data 存在: {backend_data_dir.exists()}")
print(f"   TOSKill/data 存在: {toskill_data_dir.exists()}")

if backend_data_dir.exists():
    files = list(backend_data_dir.glob("*"))
    print(f"   backend/data 文件: {[f.name for f in files]}")

if toskill_data_dir.exists():
    files = list(toskill_data_dir.glob("*"))
    print(f"   TOSKill/data 文件: {[f.name for f in files]}")

print("\n" + "=" * 60)
print("验证完成")
print("=" * 60)
print("\n数据库路径配置总结:")
print(f"  - Backend: {backend_settings.DATABASE_PATH}")
print(f"  - TOSKill: {toskill_settings.DATABASE_PATH}")
