"""
AI分析器

实现AI驱动的扫描结果深度分析功能。
"""
import logging
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityCause:
    """漏洞成因"""
    description: str = ""
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)


@dataclass
class ExploitationRisk:
    """利用风险"""
    risk_level: str = ""
    description: str = ""
    likelihood: float = 0.0
    impact: str = ""


@dataclass
class RemediationPriority:
    """修复优先级"""
    vulnerability_id: str = ""
    vulnerability_name: str = ""
    priority: int = 0
    reason: str = ""
    estimated_effort: str = ""


@dataclass
class BusinessImpact:
    """业务影响"""
    affected_systems: List[str] = field(default_factory=list)
    data_risk: str = ""
    downtime_risk: str = ""
    compliance_risk: str = ""
    financial_impact: str = ""


@dataclass
class AIAnalysisResult:
    """AI分析结果"""
    summary: str = ""
    risk_level: str = "info"
    vulnerability_causes: List[VulnerabilityCause] = field(default_factory=list)
    exploitation_risks: List[ExploitationRisk] = field(default_factory=list)
    remediation_priorities: List[RemediationPriority] = field(default_factory=list)
    business_impact: BusinessImpact = field(default_factory=BusinessImpact)
    analysis_evidence: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            "summary": self.summary,
            "risk_level": self.risk_level,
            "causes": [
                {
                    "description": cause.description,
                    "confidence": cause.confidence,
                    "evidence": cause.evidence
                }
                for cause in self.vulnerability_causes
            ],
            "risks": [
                {
                    "risk_level": risk.risk_level,
                    "description": risk.description,
                    "likelihood": risk.likelihood,
                    "impact": risk.impact
                }
                for risk in self.exploitation_risks
            ],
            "priorities": [
                {
                    "vulnerability_id": p.vulnerability_id,
                    "vulnerability": p.vulnerability_name,
                    "priority": p.priority,
                    "reason": p.reason,
                    "estimated_effort": p.estimated_effort
                }
                for p in self.remediation_priorities
            ],
            "business_impact": {
                "affected_systems": self.business_impact.affected_systems,
                "data_risk": self.business_impact.data_risk,
                "downtime_risk": self.business_impact.downtime_risk,
                "compliance_risk": self.business_impact.compliance_risk,
                "financial_impact": self.business_impact.financial_impact
            },
            "evidence": self.analysis_evidence
        }


class AIAnalyzer:
    """
    AI分析器
    
    提供扫描结果的AI驱动深度分析功能。
    """
    
    def __init__(self):
        self.llm_client = None
        self._init_llm_client()
    
    def _init_llm_client(self):
        """初始化LLM客户端"""
        try:
            from backend.config import settings
            
            if settings.OPENAI_API_KEY:
                from openai import OpenAI
                self.llm_client = OpenAI(
                    api_key=settings.OPENAI_API_KEY,
                    base_url=settings.OPENAI_BASE_URL
                )
                self.model_id = settings.MODEL_ID
                self.api_base_url = settings.OPENAI_BASE_URL
            else:
                logger.warning("⚠️ OPENAI_API_KEY未配置，将使用规则分析")
                self.llm_client = None
                self.model_id = None
                self.api_base_url = None
        except Exception as e:
            logger.error(f"❌ LLM客户端初始化失败: {e}，将使用规则分析")
            self.llm_client = None
            self.model_id = None
            self.api_base_url = None
    
    async def analyze_scan_results(
        self,
        vulnerabilities: List[Dict[str, Any]],
        tool_results: Dict[str, Any],
        target_context: Dict[str, Any]
    ) -> AIAnalysisResult:
        """
        分析扫描结果
        
        Args:
            vulnerabilities: 漏洞列表
            tool_results: 工具执行结果
            target_context: 目标上下文
            
        Returns:
            AIAnalysisResult: AI分析结果
        """
        result = AIAnalysisResult()
        
        if self.llm_client:
            result = await self._analyze_with_llm(
                vulnerabilities, tool_results, target_context
            )
        else:
            result = self._analyze_with_rules(
                vulnerabilities, tool_results, target_context
            )
        
        return result
    
    async def _analyze_with_llm(
        self,
        vulnerabilities: List[Dict[str, Any]],
        tool_results: Dict[str, Any],
        target_context: Dict[str, Any]
    ) -> AIAnalysisResult:
        """使用LLM进行分析"""
        result = AIAnalysisResult()
        
        try:
            prompt = self._build_analysis_prompt(vulnerabilities, tool_results, target_context)
            
            response = self.llm_client.chat.completions.create(
                model=self.model_id,
                messages=[
                    {"role": "system", "content": "你是一位专业的安全分析师，擅长分析Web漏洞扫描结果。请严格按照JSON格式输出分析结果。"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7
            )
            
            analysis_text = response.choices[0].message.content
            result = self._parse_llm_response(analysis_text)
            result.analysis_evidence.append("基于LLM的智能分析")
            
        except Exception as e:
            logger.error(f"❌ LLM分析失败: {e}")
            logger.error(f"❌ 错误类型: {type(e).__name__}")
            result.summary = "LLM分析失败"
            result.risk_level = "info"
        
        return result
    
    def _build_analysis_prompt(
        self,
        vulnerabilities: List[Dict[str, Any]],
        tool_results: Dict[str, Any],
        target_context: Dict[str, Any]
    ) -> str:
        """构建增强分析提示词，包含执行历史数据"""
        import json
        
        vulns_summary = [
            {
                "id": v.get("id"),
                "type": v.get("vuln_type", v.get("type")),
                "severity": v.get("severity"),
                "url": str(v.get("url", ""))[:100],
                "title": v.get("title", v.get("name", "Unknown"))
            }
            for v in vulnerabilities[:10]
        ]
        
        severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in vulnerabilities:
            sev = v.get("severity", "info").lower()
            if sev in severity_count:
                severity_count[sev] += 1
        
        execution_summary = []
        for tool_name, result in tool_results.items():
            if isinstance(result, dict):
                execution_summary.append({
                    "tool": tool_name,
                    "success": result.get("success", False),
                    "key_findings": result.get("key_findings", [])[:3] if result.get("key_findings") else []
                })
        
        prompt = f"""分析以下安全扫描结果，生成详细的安全分析报告。

## 目标信息
- 目标: {target_context.get('target', 'Unknown')}
- 扫描时间: {target_context.get('scan_time', 'Unknown')}
- 扫描策略: {target_context.get('strategy', 'standard')}

## 漏洞统计
- 漏洞总数: {len(vulnerabilities)}
- 严重程度分布: 严重={severity_count['critical']}, 高危={severity_count['high']}, 中危={severity_count['medium']}, 低危={severity_count['low']}, 信息={severity_count['info']}

## 执行历史
{json.dumps(execution_summary[:10], ensure_ascii=False, indent=2)}

## 主要漏洞
{json.dumps(vulns_summary, ensure_ascii=False, indent=2)}

请生成包含以下内容的分析报告：
1. 风险总结（一句话，不超过50字）
2. 风险等级（critical/high/medium/low/info）
3. 漏洞成因分析（最多3条）
4. 利用风险评估（最多3条）
5. 修复优先级建议（最多5条）

输出格式（必须严格遵循JSON格式）:
{{
  "summary": "一句话风险总结(不超过50字)",
  "risk_level": "critical/high/medium/low/info",
  "causes": ["成因1", "成因2", "成因3"],
  "risks": ["风险1", "风险2", "风险3"],
  "top_vulnerabilities": [
    {{"id": "漏洞ID", "type": "类型", "severity": "严重程度", "fix_priority": 1-5}}
  ],
  "recommendations": ["修复建议1", "修复建议2", "修复建议3"]
}}

要求:
1. summary不超过50字
2. causes最多3条
3. risks最多3条
4. top_vulnerabilities最多5条
5. recommendations最多5条
6. 只输出JSON，不要其他内容
"""
        return prompt
    
    def _parse_llm_response(self, response_text: str) -> AIAnalysisResult:
        """解析增强后的LLM响应"""
        import json
        import re
        
        result = AIAnalysisResult()
        result.summary = "分析结果解析失败"
        result.risk_level = "info"
        
        try:
            json_match = re.search(r'\{[\s\S]*\}', response_text)
            if json_match:
                json_str = json_match.group()
                
                data = json.loads(json_str)
                
                if "summary" in data:
                    result.summary = data["summary"]
                
                if "risk_level" in data:
                    result.risk_level = data["risk_level"]
                
                causes = data.get("causes", [])
                for cause in causes[:3]:
                    result.vulnerability_causes.append(VulnerabilityCause(
                        description=cause if isinstance(cause, str) else cause.get("description", str(cause)),
                        confidence=0.8,
                        evidence=["基于AI分析"]
                    ))
                
                risks = data.get("risks", [])
                for risk in risks[:3]:
                    result.exploitation_risks.append(ExploitationRisk(
                        risk_level=result.risk_level,
                        description=risk if isinstance(risk, str) else risk.get("description", str(risk)),
                        likelihood=0.7,
                        impact=result.risk_level
                    ))
                
                top_vulnerabilities = data.get("top_vulnerabilities", [])
                for vuln in top_vulnerabilities[:5]:
                    result.remediation_priorities.append(RemediationPriority(
                        vulnerability_id=str(vuln.get("id", "")),
                        vulnerability_name=vuln.get("type", ""),
                        priority=vuln.get("fix_priority", 5),
                        reason=vuln.get("severity", ""),
                        estimated_effort="中"
                    ))
                
                recommendations = data.get("recommendations", [])
                for rec in recommendations[:5]:
                    result.remediation_priorities.append(RemediationPriority(
                        vulnerability_id="",
                        vulnerability_name="通用建议",
                        priority=3,
                        reason=rec,
                        estimated_effort="低"
                    ))
                
                if not result.vulnerability_causes and result.summary:
                    result.vulnerability_causes.append(VulnerabilityCause(
                        description=result.summary,
                        confidence=0.8,
                        evidence=["基于AI分析的总结"]
                    ))
                
                if not result.exploitation_risks:
                    result.exploitation_risks.append(ExploitationRisk(
                        risk_level=result.risk_level,
                        description=f"风险等级为{result.risk_level}的安全问题",
                        likelihood=0.7,
                        impact=result.risk_level
                    ))
                
                result.analysis_evidence.append("基于AI的分析")
                
            else:
                logger.warning("⚠️ 未找到JSON结构，使用默认值")
                
        except Exception as e:
            logger.error(f"❌ 解析LLM响应失败: {e}")
            result.summary = "分析结果解析失败"
            result.risk_level = "info"
        
        return result


ai_analyzer = AIAnalyzer()
