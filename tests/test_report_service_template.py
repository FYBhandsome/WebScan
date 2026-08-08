from backend.services.report_service import (
    AIAnalysisData,
    Language,
    ReportData,
    ReportService,
    ReportSummary,
    RiskAssessment,
    WorkflowData,
    WorkflowExecutionRecord,
)


def build_service() -> ReportService:
    return ReportService.__new__(ReportService)


def test_html_report_uses_new_security_analysis_layout():
    service = build_service()
    report_data = ReportData(
        task_id="42",
        task_name="Web 安全扫描",
        target="https://example.test",
        scan_time="2026-08-05 10:00:00",
        generated_at="2026-08-05 10:30:00",
        summary=ReportSummary(
            total_vulnerabilities=2,
            high_count=1,
            low_count=1,
            vulnerability_rate=100,
        ),
        risk_assessment=RiskAssessment(
            score=55,
            level="medium",
            label="中等风险",
            color="#f39c12",
        ),
        vulnerabilities=[
            {
                "title": "低风险配置",
                "severity": "low",
                "url": "https://example.test/low",
                "description": "安全响应头缺失",
                "remediation": "添加响应头",
            },
            {
                "title": "SQL 注入",
                "severity": "high",
                "url": "https://example.test/item?id=1",
                "description": "参数未过滤",
                "remediation": "使用参数化查询",
                "payload": "1' OR '1'='1",
                "evidence": "HTTP 200",
            },
        ],
        ai_analysis=AIAnalysisData(
            summary="高风险入口需要优先处置。",
            risks=["数据库数据可能被未授权读取。"],
            recommendations=["复测全部修复项。"],
        ),
        workflow=WorkflowData(
            progress=100,
            execution_history=[
                WorkflowExecutionRecord(
                    node_name="漏洞扫描",
                    node_type="scan",
                    status="success",
                    execution_time=1.5,
                )
            ],
        ),
    )

    html = service.generate_html_report(report_data, Language.ZH_CN)

    assert "安全分析研判报告" in html
    assert "综合风险概览" in html
    assert "攻击链路研判" in html
    assert "合规影响说明" in html
    assert "分层加固整改方案" in html
    assert "查看原始扫描完整数据" in html
    assert "工作流执行详情" in html
    assert "AI 智能分析" in html
    assert 'risk-summary-module' in html
    assert 'class="risk-summary-content text-body md-content"' in html
    assert 'analysis-block"><h3>风险总结' not in html
    assert html.index('<section class="card ai-section">') < html.index('<section class="card risk-summary-module">') < html.index('<section class="appendix-card">')
    assert "SEC-20260805-42" in html
    assert html.index("SQL 注入") < html.index("低风险配置")
    assert "linear-gradient" not in html


def test_html_report_escapes_scan_controlled_content():
    service = build_service()
    attack = '<script>alert("xss")</script>'
    report_data = ReportData(
        task_id="unsafe/id",
        task_name=attack,
        target=attack,
        scan_time="2026-08-05",
        generated_at="2026-08-05",
        summary=ReportSummary(total_vulnerabilities=1, high_count=1),
        risk_assessment=RiskAssessment(score=80, level="high", label="高风险", color="#e74c3c"),
        vulnerabilities=[{
            "title": attack,
            "severity": "high",
            "url": attack,
            "description": attack,
            "remediation": attack,
            "payload": attack,
            "evidence": attack,
        }],
        tool_results={"raw": attack},
    )

    html = service.generate_html_report(report_data)

    assert attack not in html
    assert "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;" in html
    assert "SEC-20260805-unsafeid" in html


def test_html_report_has_complete_empty_state():
    service = build_service()
    report_data = ReportData(
        task_id="7",
        task_name="空扫描",
        target="https://example.test",
        scan_time="2026-08-05",
        generated_at="2026-08-05",
    )

    html = service.generate_html_report(report_data)

    assert "未发现漏洞" in html
    assert "本次扫描未形成可研判的漏洞攻击链" in html
    assert "暂无原始漏洞数据" in html
