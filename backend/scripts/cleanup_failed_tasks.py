"""
清理数据库中失败的案例，保留成功案例
"""
import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from tortoise import Tortoise, run_async
from backend.config import TORTOISE_ORM
from backend.models import (
    Task, Vulnerability, POCScanResult, ScanResult, Report,
    AgentTask, AgentResult,
)


async def cleanup():
    await Tortoise.init(config=TORTOISE_ORM)

    failed_tasks = await Task.filter(status__in=["failed", "error"]).all()
    failed_task_count = len(failed_tasks)
    if failed_task_count == 0:
        print("没有发现失败的Task案例，无需清理。")

    total_reports = 0
    total_vulnerabilities = 0
    total_scan_results = 0
    total_poc_results = 0

    for task in failed_tasks:
        task_name = task.task_name or "unnamed"
        reports_count = await Report.filter(task=task).count()
        total_reports += reports_count
        await Report.filter(task=task).delete()

        vuln_count = await Vulnerability.filter(task=task).count()
        total_vulnerabilities += vuln_count
        await Vulnerability.filter(task=task).delete()

        scan_count = await ScanResult.filter(task=task).count()
        total_scan_results += scan_count
        await ScanResult.filter(task=task).delete()

        poc_count = await POCScanResult.filter(task=task).count()
        total_poc_results += poc_count
        await POCScanResult.filter(task=task).delete()

        await task.delete()
        print(f"  已删除 Task[{task.id}]: {task_name} | "
              f"关联: {reports_count}R / {vuln_count}V / {scan_count}S / {poc_count}P")

    old_failed = await AgentTask.filter(status__in=["failed", "error"]).all()
    old_agent_count = len(old_failed)
    old_result_count = 0
    for agent_task in old_failed:
        result_count = await AgentResult.filter(task=agent_task).count()
        old_result_count += result_count
        await AgentResult.filter(task=agent_task).delete()
        await agent_task.delete()
        print(f"  已删除 AgentTask[{agent_task.task_id}] | 关联AgentResult: {result_count} 条")

    print(f"\n{'=' * 50}")
    print(f"清理结果汇总:")
    print(f"  删除失败 Task:         {failed_task_count} 条")
    print(f"    └ 关联 Report:       {total_reports} 条")
    print(f"    └ 关联 Vulnerability: {total_vulnerabilities} 条")
    print(f"    └ 关联 ScanResult:   {total_scan_results} 条")
    print(f"    └ 关联 POCScanResult:{total_poc_results} 条")
    print(f"  删除失败 AgentTask:    {old_agent_count} 条")
    print(f"    └ 关联 AgentResult:  {old_result_count} 条")

    completed_count = await Task.filter(status="completed").count()
    running_count = await Task.filter(status="running").count()
    pending_count = await Task.filter(status="pending").count()
    cancelled_count = await Task.filter(status="cancelled").count()
    processing_count = await Task.filter(status="processing").count()

    agent_completed = await AgentTask.filter(status="completed").count()
    agent_running = await AgentTask.filter(status="running").count()
    agent_pending = await AgentTask.filter(status="pending").count()

    print(f"\n保留的案例:")
    print(f"  Task:")
    print(f"    completed:  {completed_count} 条")
    print(f"    running:    {running_count} 条")
    print(f"    pending:    {pending_count} 条")
    print(f"    cancelled:  {cancelled_count} 条")
    print(f"    processing: {processing_count} 条")
    print(f"  AgentTask:")
    print(f"    completed:  {agent_completed} 条")
    print(f"    running:    {agent_running} 条")
    print(f"    pending:    {agent_pending} 条")
    print(f"{'=' * 50}")

    await Tortoise.close_connections()


if __name__ == "__main__":
    run_async(cleanup())