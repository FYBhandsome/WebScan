import importlib.util
import sys
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "TOSKill" / "tools" / "report" / "html_report_generator.py"
SPEC = importlib.util.spec_from_file_location("toskill_html_report_generator_test", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
HTMLReportGenerator = MODULE.HTMLReportGenerator

from TOSKill.tools.report.vulnerability_normalizer import consolidate_vulnerabilities


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


def test_full_report_classifies_dynamic_information_tool_by_runtime_category(monkeypatch):
    from TOSKill.tools.report import scan_report_template

    original_is_information = scan_report_template.is_information_tool
    original_information_items = scan_report_template.information_items
    monkeypatch.setattr(
        scan_report_template,
        "is_information_tool",
        lambda name: name == "custom_asset_probe" or original_is_information(name),
    )
    monkeypatch.setattr(
        scan_report_template,
        "information_items",
        lambda name, result: (
            [{"label": "资产线索", "value": "admin.example.test"}]
            if name == "custom_asset_probe"
            else original_information_items(name, result)
        ),
    )
    kwargs = _sample_kwargs()
    kwargs["tool_results"]["custom_asset_probe"] = {
        "success": True,
        "data": {"assets": ["admin.example.test"]},
    }

    html = HTMLReportGenerator().generate_report(**kwargs, report_type="full_scan")

    assert "custom_asset_probe" in html
    assert "资产线索" in html
    assert "admin.example.test" in html


def test_toskill_html_report_escapes_untrusted_scan_data():
    attack = "<img src=x onerror=alert(1)>"
    kwargs = _sample_kwargs()
    kwargs["target"] = attack
    kwargs["vulnerabilities"][0]["title"] = attack
    kwargs["tool_results"]["baseinfo_scan"] = {"success": True, "data": {"title": attack}}

    html = HTMLReportGenerator().generate_report(**kwargs, report_type="full_scan")

    assert attack not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_vulnerability_report_merges_duplicate_hits_into_one_issue_card():
    kwargs = _sample_kwargs()
    common = {
        "source_tool": "lfi_scan",
        "vuln_type": "lfi",
        "title": "文件包含漏洞 - id (log_injection)",
        "severity": "high",
        "url": "http://example.test/list?id=1",
        "method": "GET",
        "parameter": "id",
        "description": "参数可能读取本地文件",
    }
    kwargs["vulnerabilities"] = [
        {**common, "id": "v-1", "payload": "../../etc/passwd", "evidence": "root:x:0:0"},
        {**common, "id": "v-2", "payload": "../../etc/passwd", "evidence": "root:x:0:0"},
        {**common, "id": "v-3", "payload": "php://filter/resource=index.php", "evidence": "PD9waHA="},
    ]

    html = HTMLReportGenerator().generate_report(**kwargs, report_type="vuln_scan")

    assert "本次漏洞扫描共确认 1 个问题" in html
    assert html.count('class="vuln-item"') == 1
    assert "保留 2 条独立验证证据" in html
    assert "已合并 1 条完全重复命中" in html
    assert "../../etc/passwd" in html
    assert "php://filter/resource=index.php" in html


def test_vulnerability_report_keeps_different_input_positions_separate():
    kwargs = _sample_kwargs()
    common = {
        "source_tool": "sqli_scan",
        "vuln_type": "sqli",
        "title": "SQL 注入",
        "severity": "high",
        "url": "http://example.test/list?id=1",
        "method": "GET",
        "payload": "' OR 1=1 --",
        "evidence": "database error",
    }
    kwargs["vulnerabilities"] = [
        {**common, "parameter": "User-Agent"},
        {**common, "parameter": "Referer"},
    ]

    html = HTMLReportGenerator().generate_report(**kwargs, report_type="vuln_scan")

    assert "本次漏洞扫描共确认 2 个问题" in html
    assert html.count('class="vuln-item"') == 2
    assert "输入位置：User-Agent" in html
    assert "输入位置：Referer" in html


def _lfi_result(payload: str, evidence: str, vuln_id: str):
    return {
        "id": vuln_id,
        "source_tool": "lfi_scan",
        "vuln_type": "lfi",
        "title": "文件包含漏洞 - id (log_injection)",
        "severity": "high",
        "url": "http://example.test/list?id=1",
        "method": "GET",
        "parameter": "id",
        "payload": payload,
        "evidence": evidence,
    }


def test_vulnerability_consolidation_preserves_evidence_and_is_idempotent():
    first = _lfi_result("../../etc/passwd", "root:x:0:0", "v-1")
    duplicate = _lfi_result("../../etc/passwd", "root:x:0:0", "v-2")
    second_payload = _lfi_result("php://filter/resource=index.php", "PD9waHA=", "v-3")

    grouped = consolidate_vulnerabilities([first, duplicate, second_payload])
    regrouped = consolidate_vulnerabilities(grouped)

    assert len(regrouped) == 1
    assert regrouped[0]["occurrence_count"] == 3
    assert regrouped[0]["evidence_count"] == 2
    assert regrouped[0]["deduplicated_count"] == 1
    assert regrouped[0]["payloads"] == ["../../etc/passwd", "php://filter/resource=index.php"]
    assert regrouped[0]["source_ids"] == ["v-1", "v-2", "v-3"]


def test_vulnerability_consolidation_does_not_merge_distinct_locations_or_tools():
    first = _lfi_result("payload", "evidence", "v-1")
    other_parameter = _lfi_result("payload", "evidence", "v-2")
    other_path = _lfi_result("payload", "evidence", "v-3")
    other_tool = _lfi_result("payload", "evidence", "v-4")
    other_parameter["parameter"] = "page"
    other_path["url"] = "http://example.test/profile?id=1"
    other_tool["source_tool"] = "custom_lfi_scan"

    result = consolidate_vulnerabilities([first, other_parameter, other_path, other_tool])

    assert len(result) == 4


def test_html_report_metadata_uses_logical_issue_counts(tmp_path):
    from TOSKill.tools.report.report_manager import ReportManager

    manager = object.__new__(ReportManager)
    manager.reports_dir = tmp_path
    manager.mapping_file = tmp_path / "mapping.json"
    manager._mapping = {}
    first = _lfi_result("../../etc/passwd", "root:x:0:0", "v-1")
    duplicate = _lfi_result("../../etc/passwd", "root:x:0:0", "v-2")
    second_payload = _lfi_result("php://filter/resource=index.php", "PD9waHA=", "v-3")

    report_info = manager.save_html_report(
        session_id="session-dedup",
        target="http://example.test",
        scan_time="2026-08-14 12:00:00",
        vulnerabilities=[first, duplicate, second_payload],
        tool_results={"lfi_scan": {"success": True}},
        report_type="vuln_scan",
    )

    assert report_info["vulnerabilities_count"] == 1
    assert report_info["raw_vulnerabilities_count"] == 3
    assert report_info["vulnerability_evidence_count"] == 2
    assert len(report_info["vulnerabilities"]) == 1
