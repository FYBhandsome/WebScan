"""
测试报告目录配置

验证：
1. backend报告目录配置正确
2. TOSKill报告目录配置正确
3. 报告可以正确保存到对应目录
"""
import asyncio
import sys
import os
from pathlib import Path

project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))
os.chdir(project_root)

print("=" * 60)
print("测试报告目录配置")
print("=" * 60)

print("\n1. 检查backend报告目录配置...")
from backend.config import settings as backend_settings
print(f"   REPORTS_DIR: {backend_settings.REPORTS_DIR}")
print(f"   REPORTS_PATH: {backend_settings.REPORTS_PATH}")
print(f"   目录存在: {backend_settings.REPORTS_PATH.exists()}")

print("\n2. 检查TOSKill报告目录配置...")
from TOSKill.config import settings as toskill_settings
print(f"   REPORTS_DIR: {toskill_settings.REPORTS_DIR}")
print(f"   REPORTS_PATH: {toskill_settings.REPORTS_PATH}")
print(f"   目录存在: {toskill_settings.REPORTS_PATH.exists()}")

print("\n3. 测试backend报告服务...")
from backend.services.report_service import report_service
print(f"   报告服务输出目录: {report_service.output_dir}")
print(f"   目录存在: {report_service.output_dir.exists()}")

print("\n4. 测试TOSKill报告管理器...")
from TOSKill.tools.report.report_manager import get_report_manager
rm = get_report_manager()
print(f"   报告管理器输出目录: {rm.reports_dir}")
print(f"   目录存在: {rm.reports_dir.exists()}")

print("\n5. 创建测试报告...")

async def test_backend_report():
    from backend.services.report_service import report_service
    
    report_data = await report_service.generate_report(
        task_id="test-task-001",
        task_name="测试任务",
        target="https://example.com",
        vulnerabilities=[],
        include_ai_analysis=True,
        scan_time="2026-05-20T12:00:00Z"
    )
    
    report_id = await report_service.save_report_to_db(
        report_data=report_data,
        task_id=999999,
        report_name="测试报告 - Backend",
        report_type="json"
    )
    
    return report_id

def test_toskill_report():
    from TOSKill.tools.report.report_manager import get_report_manager
    
    rm = get_report_manager()
    
    report_info = rm.save_html_report(
        session_id="test-session-001",
        target="https://example.com",
        scan_time="2026-05-20T12:00:00Z",
        vulnerabilities=[],
        tool_results={},
        ai_analysis={"summary": "测试AI分析", "risk_level": "info"}
    )
    
    return report_info

print("\n   生成backend测试报告...")
try:
    backend_report_id = asyncio.run(test_backend_report())
    print(f"   ✅ Backend报告ID: {backend_report_id}")
except Exception as e:
    print(f"   ❌ Backend报告生成失败: {e}")

print("\n   生成TOSKill测试报告...")
try:
    toskill_report_info = test_toskill_report()
    print(f"   ✅ TOSKill报告ID: {toskill_report_info.get('report_id')}")
    print(f"   ✅ TOSKill报告文件: {toskill_report_info.get('report_file')}")
except Exception as e:
    print(f"   ❌ TOSKill报告生成失败: {e}")

print("\n6. 检查报告文件...")
backend_reports = list(Path("backend/reports").glob("*")) if Path("backend/reports").exists() else []
toskill_reports = list(Path("TOSKill/reports").glob("*")) if Path("TOSKill/reports").exists() else []

print(f"   Backend报告目录文件数: {len(backend_reports)}")
print(f"   TOSKill报告目录文件数: {len(toskill_reports)}")

print("\n" + "=" * 60)
print("测试完成")
print("=" * 60)
print("\n报告目录配置总结:")
print(f"  - Backend报告目录: {backend_settings.REPORTS_PATH}")
print(f"  - TOSKill报告目录: {toskill_settings.REPORTS_PATH}")
print(f"  - Front前端连接: http://127.0.0.1:8888/api (Backend)")
print(f"  - TOSKill-Front前端连接: http://127.0.0.1:8081/api (TOSKill)")
