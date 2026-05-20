"""
测试报告生成和AI分析流程

验证：
1. 扫描任务完成后是否生成报告
2. 报告是否包含AI分析
3. AI分析结果是否正确保存到数据库
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
from backend.models import Task, Report, Vulnerability
from backend.services.report_service import report_service
from datetime import datetime, timezone
import json


async def test_report_generation():
    """测试报告生成流程"""
    
    print("=" * 60)
    print("测试报告生成和AI分析流程")
    print("=" * 60)
    
    await Tortoise.init(
        db_url=settings.DATABASE_URL,
        modules={"models": ["backend.models"]}
    )
    
    completed_tasks = await Task.filter(status="completed").order_by('-created_at').limit(5).all()
    
    print(f"\n找到 {len(completed_tasks)} 个已完成的任务")
    
    if not completed_tasks:
        print("没有已完成的任务，创建测试任务...")
        task = await Task.create(
            task_name="测试任务",
            task_type="ai_agent_scan",
            target="https://example.com",
            status="completed",
            result=json.dumps({"vulnerabilities": []})
        )
        completed_tasks = [task]
    
    for task in completed_tasks:
        print(f"\n{'=' * 60}")
        print(f"任务ID: {task.id}")
        print(f"任务名称: {task.task_name}")
        print(f"任务类型: {task.task_type}")
        print(f"目标: {task.target}")
        print(f"状态: {task.status}")
        print(f"创建时间: {task.created_at}")
        
        reports = await Report.filter(task_id=task.id).all()
        print(f"\n关联报告数量: {len(reports)}")
        
        if not reports:
            print("⚠️ 该任务没有关联报告，尝试生成报告...")
            
            vulnerabilities = []
            if task.result:
                try:
                    result_data = json.loads(task.result)
                    vulnerabilities = result_data.get('vulnerabilities', [])
                except:
                    pass
            
            try:
                report_data = await report_service.generate_report(
                    task_id=str(task.id),
                    task_name=task.task_name,
                    target=task.target,
                    vulnerabilities=vulnerabilities,
                    include_ai_analysis=True,
                    scan_time=str(task.created_at)
                )
                
                report_id = await report_service.save_report_to_db(
                    report_data=report_data,
                    task_id=task.id,
                    report_name=f"Scan Report - {task.target}",
                    report_type="json"
                )
                
                print(f"✅ 报告生成成功 | 报告ID: {report_id}")
                print(f"   风险评分: {report_data.risk_assessment.score}")
                print(f"   风险等级: {report_data.risk_assessment.label}")
                
                if report_data.ai_analysis:
                    print(f"   AI分析: ✅ 已完成")
                    print(f"   AI风险等级: {report_data.ai_analysis.risk_level}")
                    print(f"   AI总结: {report_data.ai_analysis.summary[:100]}...")
                else:
                    print(f"   AI分析: ⚠️ 未生成")
                
                reports = await Report.filter(task_id=task.id).all()
                
            except Exception as e:
                print(f"❌ 报告生成失败: {e}")
                continue
        
        for report in reports:
            print(f"\n--- 报告详情 ---")
            print(f"报告ID: {report.id}")
            print(f"报告名称: {report.report_name}")
            print(f"报告类型: {report.report_type}")
            print(f"创建时间: {report.created_at}")
            
            if report.ai_analysis:
                try:
                    ai_data = json.loads(report.ai_analysis)
                    print(f"AI分析: ✅ 已完成")
                    print(f"AI风险等级: {ai_data.get('risk_level', 'N/A')}")
                    print(f"AI总结: {ai_data.get('summary', 'N/A')[:100]}...")
                except:
                    print(f"AI分析: ⚠️ 解析失败")
            else:
                print(f"AI分析: ⚠️ 未存储")
            
            if report.content:
                try:
                    content = json.loads(report.content)
                    if 'ai_analysis' in content and content['ai_analysis']:
                        print(f"内容中AI分析: ✅ 存在")
                    else:
                        print(f"内容中AI分析: ⚠️ 不存在")
                except:
                    print(f"报告内容: ⚠️ 解析失败")
    
    total_reports = await Report.all().count()
    reports_with_ai = await Report.filter(ai_analysis__isnull=False).count()
    
    print(f"\n{'=' * 60}")
    print("统计信息")
    print("=" * 60)
    print(f"总报告数: {total_reports}")
    print(f"包含AI分析的报告数: {reports_with_ai}")
    print(f"AI分析覆盖率: {reports_with_ai / total_reports * 100:.1f}%" if total_reports > 0 else "N/A")
    
    await Tortoise.close_connections()


if __name__ == "__main__":
    asyncio.run(test_report_generation())
