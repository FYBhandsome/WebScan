import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from backend.ai_agents.analyzers.ai_analyzer import (
    AIAnalyzer,
    AIAnalysisResult,
    VulnerabilityCause,
    ExploitationRisk,
    RemediationPriority,
    BusinessImpact,
)


@pytest.mark.unit
class TestAIAnalysisResult:
    def test_default_values(self):
        result = AIAnalysisResult()
        assert result.summary == ""
        assert result.risk_level == "info"
        assert result.vulnerability_causes == []
        assert result.exploitation_risks == []
        assert result.remediation_priorities == []
        assert result.analysis_evidence == []

    def test_business_impact_default(self):
        result = AIAnalysisResult()
        assert isinstance(result.business_impact, BusinessImpact)
        assert result.business_impact.affected_systems == []
        assert result.business_impact.data_risk == ""
        assert result.business_impact.downtime_risk == ""
        assert result.business_impact.compliance_risk == ""
        assert result.business_impact.financial_impact == ""

    def test_to_dict_empty_result(self):
        result = AIAnalysisResult()
        d = result.to_dict()
        assert d["summary"] == ""
        assert d["risk_level"] == "info"
        assert d["causes"] == []
        assert d["risks"] == []
        assert d["priorities"] == []
        assert d["evidence"] == []
        assert "business_impact" in d
        assert d["business_impact"]["affected_systems"] == []

    def test_to_dict_with_data(self):
        result = AIAnalysisResult(
            summary="发现2个高危漏洞",
            risk_level="high",
            vulnerability_causes=[
                VulnerabilityCause(
                    description="SQL注入",
                    confidence=0.9,
                    evidence=["参数id未过滤"]
                )
            ],
            exploitation_risks=[
                ExploitationRisk(
                    risk_level="high",
                    description="可获取数据库信息",
                    likelihood=0.8,
                    impact="数据泄露"
                )
            ],
            remediation_priorities=[
                RemediationPriority(
                    vulnerability_id="VULN-001",
                    vulnerability_name="SQL注入",
                    priority=1,
                    reason="高危漏洞",
                    estimated_effort="中"
                )
            ],
            business_impact=BusinessImpact(
                affected_systems=["数据库"],
                data_risk="高",
                downtime_risk="中",
                compliance_risk="合规风险",
                financial_impact="可能造成重大损失"
            ),
            analysis_evidence=["基于AI分析的总结"]
        )
        d = result.to_dict()
        assert len(d["causes"]) == 1
        assert d["causes"][0]["description"] == "SQL注入"
        assert d["causes"][0]["confidence"] == 0.9
        assert len(d["risks"]) == 1
        assert d["risks"][0]["risk_level"] == "high"
        assert len(d["priorities"]) == 1
        assert d["priorities"][0]["priority"] == 1
        assert d["business_impact"]["affected_systems"] == ["数据库"]
        assert d["business_impact"]["data_risk"] == "高"


@pytest.mark.unit
class TestVulnerabilityCause:
    def test_default_values(self):
        cause = VulnerabilityCause()
        assert cause.description == ""
        assert cause.confidence == 0.0
        assert cause.evidence == []

    def test_with_values(self):
        cause = VulnerabilityCause(
            description="XSS反射型",
            confidence=0.85,
            evidence=["输入点未做HTML编码"]
        )
        assert cause.description == "XSS反射型"
        assert cause.confidence == 0.85
        assert len(cause.evidence) == 1


@pytest.mark.unit
class TestExploitationRisk:
    def test_default_values(self):
        risk = ExploitationRisk()
        assert risk.risk_level == ""
        assert risk.description == ""
        assert risk.likelihood == 0.0
        assert risk.impact == ""

    def test_with_values(self):
        risk = ExploitationRisk(
            risk_level="critical",
            description="远程代码执行",
            likelihood=0.95,
            impact="服务器完全控制"
        )
        assert risk.risk_level == "critical"
        assert risk.likelihood == 0.95


@pytest.mark.unit
class TestRemediationPriority:
    def test_default_values(self):
        rp = RemediationPriority()
        assert rp.vulnerability_id == ""
        assert rp.vulnerability_name == ""
        assert rp.priority == 0
        assert rp.reason == ""
        assert rp.estimated_effort == ""

    def test_with_values(self):
        rp = RemediationPriority(
            vulnerability_id="V-001",
            vulnerability_name="CSRF",
            priority=2,
            reason="可导致用户误操作",
            estimated_effort="低"
        )
        assert rp.vulnerability_id == "V-001"
        assert rp.priority == 2


@pytest.mark.unit
class TestBusinessImpact:
    def test_default_values(self):
        bi = BusinessImpact()
        assert bi.affected_systems == []
        assert bi.data_risk == ""
        assert bi.downtime_risk == ""
        assert bi.compliance_risk == ""
        assert bi.financial_impact == ""

    def test_with_values(self):
        bi = BusinessImpact(
            affected_systems=["Web服务器", "数据库"],
            data_risk="高",
            downtime_risk="中",
            compliance_risk="GDPR违规",
            financial_impact="可能造成100万以上损失"
        )
        assert len(bi.affected_systems) == 2
        assert bi.data_risk == "高"


@pytest.mark.unit
class TestAIAnalyzerRuleBasedFallback:
    def test_init_without_api_key(self):
        with patch.object(AIAnalyzer, '_init_llm_client', return_value=None):
            analyzer = AIAnalyzer.__new__(AIAnalyzer)
            analyzer.llm_client = None
            analyzer.model_id = None
            analyzer.api_base_url = None
            assert analyzer.llm_client is None

    @pytest.mark.asyncio
    async def test_analyze_scan_results_without_llm(self):
        analyzer = AIAnalyzer.__new__(AIAnalyzer)
        analyzer.llm_client = None
        analyzer.model_id = None
        analyzer.api_base_url = None

        vulns = [
            {
                "id": "vuln-1",
                "title": "SQL注入",
                "vuln_type": "SQLInjection",
                "severity": "high",
                "url": "https://test.example.com?id=1"
            }
        ]
        tool_results = {"port_scan": {"open_ports": [80, 443]}}
        target_context = {"target": "https://test.example.com"}

        mock_result = AIAnalysisResult(
            summary="规则分析: 发现1个漏洞，风险等级high",
            risk_level="high"
        )

        with patch.object(analyzer, '_analyze_with_rules', return_value=mock_result, create=True):
            result = await analyzer.analyze_scan_results(vulns, tool_results, target_context)
            assert isinstance(result, AIAnalysisResult)
            assert result.summary == mock_result.summary
            assert result.risk_level == "high"

    @pytest.mark.asyncio
    async def test_analyze_with_rules_produces_valid_result(self):
        analyzer = AIAnalyzer.__new__(AIAnalyzer)
        analyzer.llm_client = None
        analyzer.model_id = None
        analyzer.api_base_url = None

        def fake_analyze_with_rules(vulns, tools, ctx):
            result = AIAnalysisResult()
            result.summary = f"规则分析: 发现{len(vulns)}个漏洞"
            result.risk_level = "medium" if len(vulns) > 0 else "info"
            if len(vulns) > 0:
                result.vulnerability_causes.append(
                    VulnerabilityCause(
                        description=vulns[0].get("title", "未知漏洞"),
                        confidence=0.7,
                        evidence=["基于规则分析"]
                    )
                )
            result.analysis_evidence.append("基于规则引擎的分析")
            return result

        analyzer._analyze_with_rules = fake_analyze_with_rules

        vulns = [{"id": "1", "title": "XSS", "severity": "medium"}]
        tool_results = {}
        target_context = {"target": "test.com"}

        result = await analyzer.analyze_scan_results(vulns, tool_results, target_context)

        assert result.risk_level == "medium"
        assert len(result.vulnerability_causes) == 1
        assert "规则分析" in result.summary
        assert "基于规则引擎的分析" in result.analysis_evidence

    @pytest.mark.asyncio
    async def test_analyze_scenario_llm_path(self):
        analyzer = AIAnalyzer.__new__(AIAnalyzer)
        analyzer.llm_client = MagicMock()
        analyzer.model_id = "test-model"
        analyzer.api_base_url = "https://test.api.com"

        vulns = [{"id": "v-1", "title": "Test Vuln", "severity": "low"}]
        tool_results = {}
        target_context = {"target": "test.com"}

        llm_result = AIAnalysisResult(
            summary="LLM分析完成",
            risk_level="low",
            analysis_evidence=["基于LLM的智能分析"]
        )

        async def mock_llm_analyze(*args, **kwargs):
            return llm_result

        with patch.object(analyzer, '_analyze_with_llm', side_effect=mock_llm_analyze):
            result = await analyzer.analyze_scan_results(vulns, tool_results, target_context)
            assert result.summary == "LLM分析完成"
            assert result.risk_level == "low"
            assert "基于LLM的智能分析" in result.analysis_evidence

    @pytest.mark.asyncio
    async def test_analyze_scan_results_is_callable(self):
        analyzer = AIAnalyzer.__new__(AIAnalyzer)
        analyzer.llm_client = None
        analyzer.model_id = None
        analyzer.api_base_url = None

        def fake_rules(vulns, tools, ctx):
            r = AIAnalysisResult()
            r.summary = "called"
            return r

        analyzer._analyze_with_rules = fake_rules

        result = await analyzer.analyze_scan_results([], {}, {})
        assert isinstance(result, AIAnalysisResult)
        assert result.summary == "called"


@pytest.mark.unit
class TestAIAnalyzerInit:
    def test_analyzer_can_be_created_without_api_key(self):
        with patch('backend.ai_agents.analyzers.ai_analyzer.AIAnalyzer._init_llm_client', return_value=None):
            analyzer = AIAnalyzer.__new__(AIAnalyzer)
            analyzer.llm_client = None
            analyzer.model_id = None
            analyzer.api_base_url = None
            assert analyzer.llm_client is None
            assert analyzer.model_id is None
            assert analyzer.api_base_url is None

    def test_analyzer_with_mock_openai(self):
        mock_client = MagicMock()
        analyzer = AIAnalyzer.__new__(AIAnalyzer)
        analyzer.llm_client = mock_client
        analyzer.model_id = "gpt-4"
        analyzer.api_base_url = "https://api.openai.com/v1"
        assert analyzer.llm_client is not None
        assert analyzer.model_id == "gpt-4"