"""
API 接口测试脚本
测试后端 API 接口功能是否正常
"""
import asyncio
import sys
import os

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database import init_db, close_db
from backend.models import Task, Report, User
from backend.api.seebug import get_status, test_connection
from backend.api.reports import get_report
from backend.utils.seebug_utils import seebug_utils


async def create_test_data():
    """创建测试数据"""
    print("\n" + "="*50)
    print("创建测试数据")
    print("="*50)
    
    # 创建测试用户
    user, created = await User.get_or_create(
        username="test_user",
        defaults={
            "email": "test@example.com",
            "hashed_password": "test_hash",
            "is_active": True
        }
    )
    if created:
        print(f"✅ 创建测试用户: {user.username}")
    else:
        print(f"ℹ️  测试用户已存在: {user.username}")
    
    # 创建测试任务
    task, created = await Task.get_or_create(
        task_name="测试任务_001",
        defaults={
            "task_type": "test",
            "target": "https://test.example.com",
            "status": "completed"
        }
    )
    if created:
        print(f"✅ 创建测试任务: {task.task_name} (ID: {task.id})")
    else:
        print(f"ℹ️  测试任务已存在: {task.task_name} (ID: {task.id})")
    
    # 创建测试报告
    try:
        report, created = await Report.get_or_create(
            report_name="测试报告",
            defaults={
                "task_id": task.id,
                "report_type": "html",
                "content": "<html><body><h1>测试报告</h1></body></html>"
            }
        )
        if created:
            print(f"✅ 创建测试报告: {report.report_name} (ID: {report.id})")
        else:
            print(f"ℹ️  测试报告已存在: {report.report_name} (ID: {report.id})")
    except Exception as e:
        print(f"⚠️  创建测试报告失败（数据库架构可能需要迁移）: {e}")
        report = await Report.first()
        if report:
            print(f"ℹ️  使用现有报告: {report.report_name} (ID: {report.id})")
        else:
            print("⚠️  没有找到现有报告，跳过报告测试")
            report = None
    
    return user, task, report


async def test_seebug_api():
    """测试 Seebug API 接口"""
    print("\n" + "="*50)
    print("测试 Seebug API 接口")
    print("="*50)
    
    # 测试状态接口
    print("\n1. 测试 /api/seebug/status 接口:")
    try:
        response = await get_status()
        print(f"   状态码: {response.code}")
        print(f"   消息: {response.message}")
        print(f"   数据: {response.data}")
        if response.code == 200:
            print("   ✅ 状态接口测试通过")
        else:
            print("   ❌ 状态接口测试失败")
    except Exception as e:
        print(f"   ❌ 状态接口测试失败: {e}")
    
    # 测试连接接口
    print("\n2. 测试 /api/seebug/test-connection 接口:")
    try:
        response = await test_connection()
        print(f"   状态码: {response.code}")
        print(f"   消息: {response.message}")
        print(f"   数据: {response.data}")
        if response.code == 200:
            print("   ✅ 连接接口测试通过")
        else:
            print("   ❌ 连接接口测试失败")
    except Exception as e:
        print(f"   ❌ 连接接口测试失败: {e}")


async def test_report_api(report):
    """测试报告 API 接口"""
    print("\n" + "="*50)
    print("测试报告 API 接口")
    print("="*50)
    
    if not report:
        print("   ⚠️  没有可用的报告数据，跳过报告测试")
        return
    
    print(f"\n1. 测试 /api/reports/{report.id} 接口:")
    try:
        response = await get_report(report.id)
        print(f"   状态码: {response.code}")
        print(f"   消息: {response.message}")
        if response.code == 200:
            print(f"   报告名称: {response.data.get('report_name')}")
            print("   ✅ 报告接口测试通过")
        else:
            print("   ❌ 报告接口测试失败")
    except Exception as e:
        print(f"   ❌ 报告接口测试失败: {e}")


async def test_database_operations():
    """测试数据库操作"""
    print("\n" + "="*50)
    print("测试数据库操作")
    print("="*50)
    
    # 测试任务查询
    print("\n1. 测试任务查询:")
    tasks = await Task.all().limit(5)
    print(f"   查询到 {len(tasks)} 个任务")
    for task in tasks:
        print(f"   - 任务ID: {task.id}, 名称: {task.task_name}, 类型: {task.task_type}, 状态: {task.status}")
    print("   ✅ 任务查询测试通过")
    
    # 测试报告查询
    print("\n2. 测试报告查询:")
    reports = await Report.all().limit(5)
    print(f"   查询到 {len(reports)} 个报告")
    for report in reports:
        print(f"   - 报告ID: {report.id}, 名称: {report.report_name}")
    print("   ✅ 报告查询测试通过")


async def main():
    """主测试函数"""
    print("\n" + "="*70)
    print(" "*20 + "后端 API 接口测试")
    print("="*70)
    
    try:
        # 初始化数据库
        print("\n初始化数据库...")
        await init_db()
        print("✅ 数据库初始化成功")
        
        # 创建测试数据
        user, task, report = await create_test_data()
        
        # 测试 Seebug API
        await test_seebug_api()
        
        # 测试报告 API
        await test_report_api(report)
        
        # 测试数据库操作
        await test_database_operations()
        
        print("\n" + "="*70)
        print(" "*20 + "测试完成")
        print("="*70)
        
    except Exception as e:
        print(f"\n❌ 测试过程中发生错误: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # 关闭数据库
        await close_db()
        print("\n✅ 数据库连接已关闭")


if __name__ == "__main__":
    asyncio.run(main())
