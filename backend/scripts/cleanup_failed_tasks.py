"""
清理失败任务的脚本

删除状态为 'failed' 的任务及其所有关联数据：
- reports
- vulnerabilities
- scan_results
- poc_results
"""
import asyncio
import sys
import os
from pathlib import Path

project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))
os.chdir(project_root)

from tortoise import Tortoise
from backend.config import settings
from backend.models import Task, Report, Vulnerability, ScanResult, POCScanResult


async def cleanup_failed_tasks(auto_confirm=False):
    """清理所有失败的任务及其关联数据"""
    
    await Tortoise.init(
        db_url=settings.DATABASE_URL,
        modules={"models": ["backend.models"]}
    )
    
    failed_tasks = await Task.filter(status="failed").all()
    
    if not failed_tasks:
        print("没有找到状态为 'failed' 的任务")
        return
    
    print(f"找到 {len(failed_tasks)} 个失败的任务:")
    print("-" * 60)
    for task in failed_tasks:
        print(f"  ID: {task.id}, 名称: {task.task_name}, 目标: {task.target}")
    print("-" * 60)
    
    if not auto_confirm:
        confirm = input("\n确认删除这些任务及其所有关联数据? (yes/no): ")
        
        if confirm.lower() != 'yes':
            print("操作已取消")
            return
    else:
        print("\n自动确认删除...")
    
    deleted_counts = {
        'tasks': 0,
        'reports': 0,
        'vulnerabilities': 0,
        'scan_results': 0,
        'poc_results': 0
    }
    
    for task in failed_tasks:
        task_id = task.id
        
        reports_count = await Report.filter(task_id=task_id).count()
        vulnerabilities_count = await Vulnerability.filter(task_id=task_id).count()
        scan_results_count = await ScanResult.filter(task_id=task_id).count()
        poc_results_count = await POCScanResult.filter(task_id=task_id).count()
        
        print(f"\n正在删除任务 {task_id} ({task.task_name})...")
        
        deleted_reports = await Report.filter(task_id=task_id).delete()
        deleted_vulnerabilities = await Vulnerability.filter(task_id=task_id).delete()
        deleted_scan_results = await ScanResult.filter(task_id=task_id).delete()
        deleted_poc_results = await POCScanResult.filter(task_id=task_id).delete()
        
        deleted_counts['reports'] += deleted_reports
        deleted_counts['vulnerabilities'] += deleted_vulnerabilities
        deleted_counts['scan_results'] += deleted_scan_results
        deleted_counts['poc_results'] += deleted_poc_results
        
        await task.delete()
        deleted_counts['tasks'] += 1
        
        print(f"  - 删除报告: {deleted_reports}")
        print(f"  - 删除漏洞: {deleted_vulnerabilities}")
        print(f"  - 删除扫描结果: {deleted_scan_results}")
        print(f"  - 删除POC结果: {deleted_poc_results}")
    
    print("\n" + "=" * 60)
    print("清理完成!")
    print("=" * 60)
    print(f"总计删除:")
    print(f"  - 任务: {deleted_counts['tasks']}")
    print(f"  - 报告: {deleted_counts['reports']}")
    print(f"  - 漏洞: {deleted_counts['vulnerabilities']}")
    print(f"  - 扫描结果: {deleted_counts['scan_results']}")
    print(f"  - POC结果: {deleted_counts['poc_results']}")
    
    await Tortoise.close_connections()


if __name__ == "__main__":
    auto_confirm = "--yes" in sys.argv or "-y" in sys.argv
    asyncio.run(cleanup_failed_tasks(auto_confirm=auto_confirm))
