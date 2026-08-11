import importlib.util
import sys
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "TOSKill" / "tools" / "report" / "html_report_generator.py"
SPEC = importlib.util.spec_from_file_location("toskill_html_report_generator_test", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
HTMLReportGenerator = MODULE.HTMLReportGenerator


def _sample_kwargs():
    return {
        "target": "https://example.test",
        "scan_time": "2026-08-05 12:00:00",
        "session_id": "session-123",
        "vulnerabilities": [{
            "title": "SQL 注入",
            "severity": "high",
            "url": "https://example.test/item?id=1",
            "parameter": "id",
            "description": "查询参数未过滤",
            "solution": "使用参数化查询",
            "payload": "1' OR '1'='1",
            "evidence": "响应包含数据库错误",
        }],
        "tool_results": {
            "baseinfo_scan": {"success": True, "data": {"server": "nginx", "title": "Example"}},
            "port_scan": {"success": True, "data": {"open_ports": [80, 443], "total_count": 2}},
            "sqli_scan": {"success": True, "data": {"vulnerabilities": []}},
        },
        "ai_analysis": {
            "executive_summary": "存在需要优先修复的高风险入口。",
            "risk_assessment": {"risk_score": 75, "overall_risk": "high"},
            "remediation_recommendations": [{
                "priority": 1,
                "vulnerability": "SQL 注入",
                "recommendation": "立即切换为参数化查询。",
            }],
        },
        "confidence": {
            "overall_score": 85,
            "level": "high",
            "standard_text": "基于等保 2.0 三级标准",
            "dimensions": [{"label": "漏洞检测准确性", "value": 85}],
        },
    }


def test_report_type_selects_information_collection_template():
    html = HTMLReportGenerator().generate_report(**_sample_kwargs(), report_type="info_collection")

    assert "信息收集报告" in html
    assert "信息收集结果" in html
    assert "目标与服务" in html
    assert "网络暴露面" in html
    assert "漏洞扫描风险概览" not in html
    assert "确认的问题" not in html
    assert "攻击链路" not in html
    assert "合规影响" not in html
    assert "未发现漏洞" not in html


def test_report_type_selects_vulnerability_template_with_blue_progress_bar():
    html = HTMLReportGenerator().generate_report(**_sample_kwargs(), report_type="vuln_scan")

    assert "安全分析研判报告" in html
    assert "漏洞扫描风险概览" in html
    assert "确认的问题（按受影响位置展示）" in html
    assert "SQL 注入" in html
    assert "分层加固整改方案" in html
    assert "AI 智能分析" in html
    assert "攻击链路" not in html
    assert "合规影响" not in html
    assert ".item-bar-fill { display:block;" in html
    assert 'style="width:85.0%"' in html


def test_report_type_selects_full_template_and_keeps_categories_separate():
    html = HTMLReportGenerator().generate_report(**_sample_kwargs(), report_type="full_scan")

    assert "完整扫描报告" in html
    assert "扫描执行概览" in html
    assert "信息收集结果" in html
    assert "漏洞扫描风险概览" in html
    assert html.index("信息收集结果") < html.index("漏洞扫描风险概览")
    assert "攻击链路" not in html
    assert "合规影响" not in html


def test_toskill_html_report_escapes_untrusted_scan_data():
    attack = "<img src=x onerror=alert(1)>"
    kwargs = _sample_kwargs()
    kwargs["target"] = attack
    kwargs["vulnerabilities"][0]["title"] = attack
    kwargs["tool_results"]["baseinfo_scan"] = {"success": True, "data": {"title": attack}}

    html = HTMLReportGenerator().generate_report(**kwargs, report_type="full_scan")

    assert attack not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
