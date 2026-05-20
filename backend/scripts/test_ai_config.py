"""
测试配置加载和AI分析器初始化
"""
import asyncio
import sys
import os
import logging
from pathlib import Path

project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))
os.chdir(project_root)

logging.basicConfig(level=logging.DEBUG)

print("=" * 60)
print("测试配置加载")
print("=" * 60)

from backend.config import settings

print(f"\n配置文件路径: {Path(__file__).parent.parent / '.env'}")
print(f"OPENAI_API_KEY: {settings.OPENAI_API_KEY[:20] + '...' if settings.OPENAI_API_KEY else 'None'}")
print(f"OPENAI_BASE_URL: {settings.OPENAI_BASE_URL}")
print(f"MODEL_ID: {settings.MODEL_ID}")

print("\n" + "=" * 60)
print("测试AI分析器初始化")
print("=" * 60)

from backend.ai_agents.analyzers.ai_analyzer import AIAnalyzer

analyzer = AIAnalyzer()

print(f"\nLLM客户端: {'已初始化' if analyzer.llm_client else '未初始化'}")
print(f"模型ID: {analyzer.model_id}")
print(f"API Base URL: {analyzer.api_base_url}")

if analyzer.llm_client:
    print("\n✅ AI分析器已正确初始化，可以使用LLM进行智能分析")
else:
    print("\n⚠️ AI分析器未初始化LLM客户端，将使用规则分析")

print("\n" + "=" * 60)
print("测试AI分析功能")
print("=" * 60)

async def test_analyze():
    vulnerabilities = [
        {
            "id": "vuln-001",
            "type": "SQLInjection",
            "severity": "critical",
            "title": "SQL注入漏洞",
            "url": "https://example.com?id=1",
            "description": "发现SQL注入漏洞"
        }
    ]
    
    tool_results = {
        "sqli_scan": {"success": True, "key_findings": ["SQL injection found"]}
    }
    
    target_context = {
        "target": "https://example.com",
        "scan_time": "2026-05-20T12:00:00Z",
        "strategy": "standard"
    }
    
    print("\n开始AI分析...")
    result = await analyzer.analyze_scan_results(vulnerabilities, tool_results, target_context)
    
    print(f"\n分析结果:")
    print(f"  风险等级: {result.risk_level}")
    print(f"  总结: {result.summary}")
    print(f"  成因数量: {len(result.vulnerability_causes)}")
    print(f"  风险数量: {len(result.exploitation_risks)}")
    print(f"  优先级数量: {len(result.remediation_priorities)}")
    print(f"  证据: {result.analysis_evidence}")
    
    return result

result = asyncio.run(test_analyze())

print("\n" + "=" * 60)
print("测试完成")
print("=" * 60)
