# -*- coding:utf-8 -*-
"""
置信度评估诊断脚本 - 定位真实失败原因
"""
import sys
import os
import asyncio
import traceback

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.dirname(project_root))

print("=" * 60)
print("置信度评估诊断")
print("=" * 60)

# 1. 检查配置
print("\n--- 1. 配置检查 ---")
try:
    from TOSKill.config import settings
    print(f"  CONFIDENCE_ASSESSMENT_ENABLED = {settings.CONFIDENCE_ASSESSMENT_ENABLED}")
    print(f"  CONFIDENCE_AI_TIMEOUT = {settings.CONFIDENCE_AI_TIMEOUT}")
    print(f"  MLPS_STANDARD_LEVEL = {settings.MLPS_STANDARD_LEVEL}")
    print(f"  MODEL_ID = {settings.MODEL_ID}")
    print(f"  OPENAI_API_KEY = {settings.OPENAI_API_KEY[:20]}...")
    print(f"  OPENAI_BASE_URL = {settings.OPENAI_BASE_URL}")
    print(f"  RAG_ENABLED = {settings.RAG_ENABLED}")
    print("  [OK] 配置读取正常")
except Exception as e:
    print(f"  [FAIL] 配置读取失败: {e}")
    traceback.print_exc()

# 2. 检查 _get_llm
print("\n--- 2. LLM实例创建检查 ---")
try:
    from TOSKill.tools.report.report_manager import _get_llm
    llm = _get_llm()
    print(f"  LLM类型: {type(llm).__name__}")
    print(f"  model: {llm.model_name}")
    print("  [OK] LLM实例创建成功")
except Exception as e:
    print(f"  [FAIL] LLM实例创建失败: {e}")
    traceback.print_exc()

# 3. 检查RAG检索
print("\n--- 3. RAG等保上下文检索检查 ---")
try:
    from TOSKill.RAG.retriever import get_mlps_assessment_context, get_confidence_rules, get_kb_version
    test_vulns = [{"type": "sqli", "severity": "high", "url": "http://test.com"}]
    test_tools = {"sqli_scan": {"vulnerable": True}}

    mlps_ctx = get_mlps_assessment_context("http://test.com", test_vulns, test_tools)
    print(f"  MLPS上下文长度: {len(mlps_ctx)}")
    if mlps_ctx:
        print(f"  前100字符: {mlps_ctx[:100]}")
    else:
        print("  [WARN] MLPS上下文为空（RAG可能未就绪）")

    rules = get_confidence_rules()
    print(f"  置信度规则长度: {len(rules)}")

    version = get_kb_version()
    print(f"  知识库版本: {version}")
    print("  [OK] RAG检索调用完成")
except Exception as e:
    print(f"  [FAIL] RAG检索失败: {e}")
    traceback.print_exc()

# 4. 检查提示词构建
print("\n--- 4. 提示词构建检查 ---")
try:
    from TOSKill.tools.report.confidence_assessor import ConfidenceAssessor
    assessor = ConfidenceAssessor()
    prompt = assessor._build_prompt(
        vulnerabilities=test_vulns,
        tool_results=test_tools,
        target="http://test.com",
        scan_mode="人机交互",
        mlps_context="测试等保上下文",
        confidence_rules="测试置信度规则"
    )
    print(f"  提示词长度: {len(prompt)}")
    print(f"  前200字符: {prompt[:200]}")
    print("  [OK] 提示词构建成功")
except Exception as e:
    print(f"  [FAIL] 提示词构建失败: {e}")
    traceback.print_exc()

# 5. 实际LLM调用测试
print("\n--- 5. LLM实际调用测试 ---")
try:
    from TOSKill.tools.report.report_manager import _get_llm
    llm = _get_llm()
    print("  正在调用LLM（简单测试）...")
    response = llm.invoke("请回复JSON: {\"test\": true}")
    raw = response.content
    print(f"  响应长度: {len(raw)}")
    print(f"  前200字符: {raw[:200]}")
    print("  [OK] LLM调用成功")
except Exception as e:
    print(f"  [FAIL] LLM调用失败: {e}")
    traceback.print_exc()

# 6. 完整置信度评估测试
print("\n--- 6. 完整置信度评估测试 ---")
try:
    from TOSKill.tools.report.confidence_assessor import get_confidence_assessor
    assessor = get_confidence_assessor()
    print("  正在执行完整置信度评估...")
    print(f"  超时设置: {assessor.timeout}s")
    result = asyncio.run(assessor.assess_async(
        vulnerabilities=test_vulns,
        tool_results=test_tools,
        target="http://test.com",
        scan_mode="人机交互"
    ))
    if result:
        print(f"  [OK] 评估成功!")
        print(f"  overall_score: {result.get('overall_score')}")
        print(f"  level: {result.get('level')}")
        print(f"  dimensions: {len(result.get('dimensions', []))}")
    else:
        print("  [FAIL] 评估返回None")
        print("  可能原因: LLM调用超时、异常、或漏洞数据为空")
except asyncio.TimeoutError:
    print(f"  [FAIL] 评估超时（{assessor.timeout}s）")
except Exception as e:
    print(f"  [FAIL] 评估异常: {e}")
    traceback.print_exc()

print("\n" + "=" * 60)
print("诊断完成")
print("=" * 60)
