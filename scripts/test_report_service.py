"""
报告生成功能测试脚本
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import asyncio
from backend.services.report_service import report_service, ReportFormat, Language


async def test_report_generation():
    """测试报告生成功能"""
    print("\n" + "="*60)
    print("📊 报告生成功能测试")
    print("="*60 + "\n")
    
    test_vulnerabilities = [
        {
            "title": "SQL 注入漏洞",
            "name": "SQL Injection",
            "severity": "critical",
            "url": "https://example.com/search?id=1",
            "description": "在搜索功能中发现 SQL 注入漏洞，攻击者可以执行任意 SQL 语句。",
            "remediation": "使用参数化查询，对用户输入进行严格过滤。"
        },
        {
            "title": "XSS 跨站脚本漏洞",
            "name": "Cross-Site Scripting",
            "severity": "high",
            "url": "https://example.com/comment",
            "description": "在评论功能中发现存储型 XSS 漏洞。",
            "remediation": "对用户输入进行 HTML 实体编码。"
        },
        {
            "title": "敏感信息泄露",
            "name": "Information Disclosure",
            "severity": "medium",
            "url": "https://example.com/debug",
            "description": "调试信息暴露了服务器内部路径和配置。",
            "remediation": "生产环境禁用调试模式。"
        },
        {
            "title": "弱密码策略",
            "name": "Weak Password Policy",
            "severity": "low",
            "url": "https://example.com/login",
            "description": "系统允许设置弱密码。",
            "remediation": "强制要求密码复杂度。"
        },
        {
            "title": "版本信息泄露",
            "name": "Version Disclosure",
            "severity": "info",
            "url": "https://example.com/",
            "description": "HTTP 响应头中包含服务器版本信息。",
            "remediation": "配置服务器隐藏版本信息。"
        }
    ]
    
    print("1️⃣ 测试报告数据生成...")
    report_data = await report_service.generate_report(
        task_id="test_task_001",
        task_name="安全扫描测试任务",
        target="https://example.com",
        vulnerabilities=test_vulnerabilities,
        include_ai_analysis=False,
        scan_time="2025-01-01T10:00:00Z"
    )
    
    print(f"   ✅ 报告数据生成成功")
    print(f"   - 任务ID: {report_data.task_id}")
    print(f"   - 任务名称: {report_data.task_name}")
    print(f"   - 目标: {report_data.target}")
    print(f"   - 漏洞总数: {report_data.summary.total_vulnerabilities}")
    print(f"   - 风险评分: {report_data.risk_assessment.score}")
    print(f"   - 风险等级: {report_data.risk_assessment.label}")
    
    print("\n2️⃣ 测试 JSON 格式报告生成...")
    json_report = report_service.generate_json_report(report_data)
    print(f"   ✅ JSON 报告生成成功，大小: {len(json_report)} 字节")
    
    print("\n3️⃣ 测试 HTML 格式报告生成...")
    html_report = report_service.generate_html_report(report_data, Language.ZH_CN)
    print(f"   ✅ HTML 报告生成成功，大小: {len(html_report)} 字节")
    
    print("\n4️⃣ 测试 Markdown 格式报告生成...")
    md_report = report_service.generate_markdown_report(report_data, Language.ZH_CN)
    print(f"   ✅ Markdown 报告生成成功，大小: {len(md_report)} 字节")
    
    print("\n5️⃣ 测试报告保存功能...")
    
    json_path = report_service.save_report(report_data, ReportFormat.JSON)
    print(f"   ✅ JSON 报告已保存: {json_path}")
    
    html_path = report_service.save_report(report_data, ReportFormat.HTML)
    print(f"   ✅ HTML 报告已保存: {html_path}")
    
    md_path = report_service.save_report(report_data, ReportFormat.MARKDOWN)
    print(f"   ✅ Markdown 报告已保存: {md_path}")
    
    print("\n6️⃣ 测试风险评分计算...")
    risk = report_service.calculate_risk_score(test_vulnerabilities)
    print(f"   ✅ 风险评分: {risk.score}")
    print(f"   ✅ 风险等级: {risk.label}")
    print(f"   ✅ 风险颜色: {risk.color}")
    
    print("\n7️⃣ 测试摘要计算...")
    summary = report_service.calculate_summary(test_vulnerabilities)
    print(f"   ✅ 严重: {summary.critical_count}")
    print(f"   ✅ 高危: {summary.high_count}")
    print(f"   ✅ 中危: {summary.medium_count}")
    print(f"   ✅ 低危: {summary.low_count}")
    print(f"   ✅ 信息: {summary.info_count}")
    
    print("\n" + "="*60)
    print("✅ 所有测试通过！")
    print("="*60 + "\n")
    
    return True


if __name__ == "__main__":
    try:
        result = asyncio.run(test_report_generation())
        sys.exit(0 if result else 1)
    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
