import asyncio
import importlib.util
import sys
import tempfile
import types
from pathlib import Path


TEST_REPORTS_DIR = tempfile.TemporaryDirectory()
PREVIOUS_CONFIG = sys.modules.get("TOSKill.config")
FAKE_CONFIG = types.ModuleType("TOSKill.config")
FAKE_CONFIG.settings = types.SimpleNamespace(
    REPORT_AI_TIMEOUT=0.01,
    REPORTS_PATH=Path(TEST_REPORTS_DIR.name),
)
sys.modules["TOSKill.config"] = FAKE_CONFIG

MODULE_PATH = Path(__file__).parents[1] / "TOSKill" / "tools" / "report" / "report_manager.py"
SPEC = importlib.util.spec_from_file_location("toskill_report_manager_test", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
if PREVIOUS_CONFIG is None:
    sys.modules.pop("TOSKill.config", None)
else:
    sys.modules["TOSKill.config"] = PREVIOUS_CONFIG
ReportManager = MODULE.ReportManager


def build_manager() -> ReportManager:
    return object.__new__(ReportManager)


def test_async_report_generation_falls_back_after_hard_timeout(monkeypatch):
    manager = build_manager()

    async def never_finishes(*args, **kwargs):
        await asyncio.sleep(60)

    fake_config = types.ModuleType("TOSKill.config")
    fake_config.settings = types.SimpleNamespace(REPORT_AI_TIMEOUT=0.01)
    monkeypatch.setitem(sys.modules, "TOSKill.config", fake_config)
    monkeypatch.setattr(manager, "_generate_ai_report_async", never_finishes)
    monkeypatch.setattr(manager, "_generate_fallback_report", lambda *args: "fallback report")

    result = asyncio.run(
        manager.generate_ai_report_content_async(
            tool_results={"scanner": {"status": "completed"}},
            vulnerabilities=[],
            target="https://example.test",
        )
    )

    assert result == "fallback report"


def test_html_analysis_reuses_existing_report_without_llm(monkeypatch):
    manager = build_manager()
    monkeypatch.setattr(
        manager,
        "_generate_ai_report_sync",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("LLM must not be called")),
    )

    analysis = manager.generate_html_analysis(
        vulnerabilities=[{
            "title": "SQL 注入",
            "severity": "high",
            "description": "查询参数未过滤",
            "solution": "使用参数化查询",
        }],
        target="https://example.test",
        report_content="# 风险摘要\n\n发现高风险注入入口。",
    )

    assert analysis["risk_assessment"]["overall_risk"] == "high"
    assert "发现高风险注入入口" in analysis["executive_summary"]
    assert analysis["remediation_recommendations"][0]["recommendation"] == "使用参数化查询"


def test_async_report_always_appends_structured_vulnerability_details(monkeypatch):
    manager = build_manager()

    async def generate_summary(*args, **kwargs):
        return "# 风险摘要\n\n发现 SQL 注入风险。"

    fake_config = types.ModuleType("TOSKill.config")
    fake_config.settings = types.SimpleNamespace(REPORT_AI_TIMEOUT=1)
    monkeypatch.setitem(sys.modules, "TOSKill.config", fake_config)
    monkeypatch.setattr(manager, "_generate_ai_report_async", generate_summary)

    result = asyncio.run(
        manager.generate_ai_report_content_async(
            tool_results={"sqli_scan": {"status": "completed"}},
            vulnerabilities=[
                {
                    "title": "SQL注入漏洞(Union注入)",
                    "vuln_type": "SQL Injection",
                    "severity": "medium",
                    "url": "https://example.test/search",
                    "method": "POST",
                    "parameter": "keyword",
                    "source_tool": "sqli_scan",
                    "description": "搜索参数未经过滤。",
                    "payload": "' UNION SELECT NULL--",
                    "evidence": "响应中出现数据库版本。",
                    "solution": "使用参数化查询。",
                },
                {
                    "title": "SQL注入漏洞(Union注入)",
                    "severity": "critical",
                    "url": "https://example.test/item",
                    "parameter": "id",
                    "description": "商品 ID 可被注入。",
                },
            ],
            target="https://example.test",
        )
    )

    assert "## 漏洞明细（按风险优先级排序）" in result
    assert "本次扫描产生 **2** 条原始命中，归并为 **2** 个安全问题" in result
    assert result.index("受影响参数**：id") < result.index("受影响参数**：keyword")
    assert "**请求方法**：POST" in result
    assert "**来源工具**：sqli\\_scan" in result
    assert "' UNION SELECT NULL--" in result
    assert "响应中出现数据库版本。" in result
    assert "使用参数化查询。" in result


def test_fallback_report_uses_the_same_complete_vulnerability_details():
    manager = build_manager()

    result = manager._generate_fallback_report(
        tool_results={},
        vulnerabilities=[{
            "title": "跨站脚本漏洞",
            "severity": "high",
            "url": "https://example.test/?q=x",
            "parameter": "q",
            "payload": "<script>alert(1)</script>",
            "evidence": "Payload 在响应页面中原样返回",
            "remediation": "对输出进行上下文编码",
        }],
        target="https://example.test",
    )

    assert "### 1. 跨站脚本漏洞" in result
    assert "**严重程度**：高危（HIGH）" in result
    assert "**受影响参数**：q" in result
    assert "<script>alert(1)</script>" in result
    assert "Payload 在响应页面中原样返回" in result
    assert "对输出进行上下文编码" in result
