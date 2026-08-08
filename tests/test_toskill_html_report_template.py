import importlib.util
import sys
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "TOSKill" / "tools" / "report" / "html_report_generator.py"
SPEC = importlib.util.spec_from_file_location("toskill_html_report_generator_test", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
HTMLReportGenerator = MODULE.HTMLReportGenerator


def test_toskill_html_report_uses_new_template_and_preserves_ai_sections():
    generator = HTMLReportGenerator()
    html = generator.generate_report(
        target="https://example.test",
        scan_time="2026-08-05 12:00:00",
        session_id="session-123",
        vulnerabilities=[{
            "title": "SQL 注入",
            "severity": "high",
            "url": "https://example.test/item?id=1",
            "description": "查询参数未过滤",
            "solution": "使用参数化查询",
            "payload": "1' OR '1'='1",
            "evidence": "响应包含数据库错误",
        }],
        tool_results={"sqli_scan": {"status": "completed"}},
        ai_analysis={
            "executive_summary": "存在需要优先修复的高风险入口。",
            "risk_assessment": {"risk_score": 75, "overall_risk": "high"},
            "vulnerability_analysis": [{
                "vuln_name": "SQL 注入",
                "technical_analysis": "攻击者可修改后端查询语义。",
            }],
            "attack_chain_analysis": {
                "description": "攻击者可能从公开查询入口进入。",
                "attack_paths": ["参数注入 -> 数据读取"],
            },
            "remediation_recommendations": [{
                "priority": 1,
                "vulnerability": "SQL 注入",
                "recommendation": "立即切换为参数化查询。",
            }],
            "security_hardening": {
                "short_term": ["限制数据库账户权限。"],
                "long_term": ["建立代码安全审查机制。"],
            },
        },
    )

    assert "安全分析研判报告" in html
    assert "综合风险概览" in html
    assert "攻击链路研判" in html
    assert "攻击者可能从公开查询入口进入" in html
    assert "分层加固整改方案" in html
    assert "立即切换为参数化查询" in html
    assert "Payload: 1&#x27; OR &#x27;1&#x27;=&#x27;1" in html
    assert "工具执行结果" in html
    assert 'risk-summary-module' in html
    assert 'class="risk-summary-content text-body md-content"' in html
    assert "session-123" in html


def test_toskill_html_report_escapes_untrusted_scan_data():
    generator = HTMLReportGenerator()
    attack = "<img src=x onerror=alert(1)>"

    html = generator.generate_report(
        target=attack,
        scan_time="2026-08-05",
        session_id="unsafe/id",
        vulnerabilities=[{
            "title": attack,
            "severity": "high",
            "description": attack,
            "solution": attack,
            "payload": attack,
        }],
        tool_results={"raw": attack},
    )

    assert attack not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
