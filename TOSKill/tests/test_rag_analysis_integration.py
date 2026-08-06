import asyncio
import json
from unittest.mock import patch


def test_extract_knowledge_sources_accepts_spacing_and_deduplicates():
    from TOSKill.RAG.retriever import extract_knowledge_sources

    context = """
    [知识1] 来源:07_scanning_workflow.md 相关度:0.91
    [知识2] 来源: 16_dengbao_standard.md | 相关度:0.82
    [知识3] 来源:07_scanning_workflow.md 相关度:0.75
    """

    assert extract_knowledge_sources(context) == [
        "07_scanning_workflow.md",
        "16_dengbao_standard.md",
    ]


def test_decision_cache_key_changes_when_latest_result_changes():
    from TOSKill.RAG.rag_engine import TOSKillRAGEngine

    engine = object.__new__(TOSKillRAGEngine)
    first = engine._get_cache_key(
        "https://example.test", "sqli_scan", ["baseinfo_scan"], {"waf_detected": False}
    )
    second = engine._get_cache_key(
        "https://example.test", "sqli_scan", ["baseinfo_scan"], {"waf_detected": True}
    )

    assert first != second


def test_result_analysis_is_structured_rag_aware_and_redacted():
    from TOSKill.analysis.result_analyzer import ResultAnalyzer

    class FakeResponse:
        content = json.dumps({
            "summary": "扫描完成，发现一个高风险注入点，需要复核。",
            "risk_level": "high",
            "key_findings": ["参数 id 疑似存在 SQL 注入"],
            "evidence": ["vulnerable=true", "parameter=id"],
            "analysis": "扫描器返回了明确的疑似注入信号，但仍需授权复测排除误报。",
            "recommendations": ["立即复核 id 参数", "修复后重新扫描"],
        }, ensure_ascii=False)

    class FakeLLM:
        def invoke(self, prompt):
            assert "07_scanning_workflow.md" in prompt
            assert "secret-token" not in prompt
            return FakeResponse()

    analyzer = ResultAnalyzer()
    analyzer._llm = FakeLLM()
    result = {"vulnerable": True, "parameter": "id", "token": "secret-token"}
    rag_context = "[知识1] 来源:07_scanning_workflow.md 相关度:0.900\nSQL注入验证指南"

    with patch(
        "TOSKill.RAG.retriever.retrieve_for_result_analysis", return_value=rag_context
    ):
        analyzed = analyzer.analyze("sqli_scan", "https://example.test", result)

    payload = analyzer.to_websocket_payload(analyzed)
    assert payload["risk_level"] == "high"
    assert payload["knowledge_used"] is True
    assert payload["knowledge_sources"] == ["07_scanning_workflow.md"]
    assert payload["key_findings"] == ["参数 id 疑似存在 SQL 注入"]
    assert "处置建议" in payload["analysis"]


def test_async_report_generation_includes_report_retrieval_context():
    from TOSKill.tools.report.report_manager import ReportManager

    prompts = []

    class FakeResponse:
        content = "# 安全分析报告\n\n已生成"

    class FakeLLM:
        async def ainvoke(self, prompt):
            prompts.append(prompt)
            return FakeResponse()

    manager = object.__new__(ReportManager)
    rag_context = "[知识1] 来源:16_dengbao_standard.md 相关度:0.880\n等保风险分级"

    with patch("TOSKill.tools.report.report_manager._get_llm", return_value=FakeLLM()), patch(
        "TOSKill.RAG.retriever.retrieve_for_report", return_value=rag_context
    ):
        report = asyncio.run(manager._generate_ai_report_async(
            tool_results={"sqli_scan": {"success": True, "vulnerable": True, "parameter": "id"}},
            vulnerabilities=[{"vuln_type": "sqli", "severity": "high"}],
            target="https://example.test",
        ))

    assert report.startswith("# 安全分析报告")
    assert prompts
    assert "16_dengbao_standard.md" in prompts[0]
    assert "知识库内容只能用于解释和建议" in prompts[0]
    assert manager._last_rag_result == rag_context


def test_report_analysis_prompt_contains_evidence_and_knowledge_boundaries():
    from TOSKill.tools.report.ai_analyzer import _build_analysis_prompt

    prompt = _build_analysis_prompt(
        vulnerabilities=[{"id": "v1", "vuln_type": "xss", "severity": "medium"}],
        tool_results={"xss_scan": {"success": True, "vulnerable": True, "url": "/search"}},
        target_context={"target": "https://example.test"},
        knowledge_context="来源:18_risk_classification_guide.md",
    )

    assert "18_risk_classification_guide.md" in prompt
    assert "工具成功不代表目标安全" in prompt
    assert "不能作为本次扫描发现漏洞的证据" in prompt
