# -*- coding:utf-8 -*-
"""
AI分析器工具

使用@tool装饰器封装AI驱动的扫描结果深度分析功能。
"""

from langchain.tools import tool
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict
import logging
import json
import re

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


def _init_llm_client() -> tuple:
    """初始化LLM客户端"""
    try:
        from backend.config import settings
        
        logger.info(f"开始初始化LLM客户端...")
        logger.info(f"   - OPENAI_API_KEY: {'已配置' if settings.OPENAI_API_KEY else '未配置'}")
        logger.info(f"   - OPENAI_BASE_URL: {settings.OPENAI_BASE_URL}")
        logger.info(f"   - MODEL_ID: {settings.MODEL_ID}")
        
        if settings.OPENAI_API_KEY:
            from openai import OpenAI
            llm_client = OpenAI(
                api_key=settings.OPENAI_API_KEY,
                base_url=settings.OPENAI_BASE_URL
            )
            model_id = settings.MODEL_ID
            api_base_url = settings.OPENAI_BASE_URL
            logger.info(f"LLM客户端初始化成功，使用模型: {model_id}")
            return llm_client, model_id, api_base_url
        else:
            logger.warning("OPENAI_API_KEY未配置，将使用规则分析")
            return None, None, None
    except Exception as e:
        logger.error(f"LLM客户端初始化失败: {e}，将使用规则分析")
        return None, None, None


def _build_analysis_prompt(
    vulnerabilities: List[Dict[str, Any]],
    tool_results: Dict[str, Any],
    target_context: Dict[str, Any],
    knowledge_context: str = ""
) -> str:
    """构建详细分析提示词"""
    vulns_summary = [
        {
            "id": v.get("id"),
            "type": v.get("vuln_type", v.get("type")),
            "severity": v.get("severity"),
            "url": str(v.get("url", ""))[:100],
            "title": v.get("title", ""),
            "description": v.get("description", "")[:200]
        }
        for v in vulnerabilities[:10]
    ]
    
    tool_summary = {}
    from TOSKill.analysis.result_analyzer import sanitize_result_for_display
    for tool_name, result in list(tool_results.items())[:10]:
        if isinstance(result, dict):
            safe_result = sanitize_result_for_display(result)
            tool_summary[tool_name] = {
                "success": result.get("success"),
                "vulnerable": result.get("vulnerable"),
                "error": result.get("error"),
                "key_findings": result.get("key_findings", [])[:5] if result.get("key_findings") else [],
                "result_excerpt": json.dumps(safe_result, ensure_ascii=False, default=str)[:700],
            }
    
    prompt = f"""作为专业安全分析师，请对以下扫描结果进行全面深入分析。

## 扫描目标信息
- 目标: {target_context.get('target', 'Unknown')}
- 扫描时间: {target_context.get('scan_time', 'Unknown')}
- 扫描策略: {target_context.get('strategy', 'standard')}

## 发现的漏洞 ({len(vulnerabilities)}个)
{json.dumps(vulns_summary, ensure_ascii=False, indent=2)}

## 工具执行结果摘要
{json.dumps(tool_summary, ensure_ascii=False, indent=2)}

## 知识库参考
{knowledge_context[:2000] if knowledge_context else "无可用知识库参考"}

请输出以下JSON格式的详细分析报告（只输出JSON，不要其他内容）:
{{
  "summary": "整体安全状况总结（100-200字）",
  "risk_level": "critical/high/medium/low/info",
  "vulnerability_analysis": [
    {{
      "id": "漏洞ID",
      "type": "漏洞类型",
      "root_cause": "漏洞根本原因分析",
      "attack_vector": "攻击向量描述",
      "potential_impact": "潜在影响"
    }}
  ],
  "exploitation_scenarios": [
    {{
      "scenario": "攻击场景描述",
      "likelihood": "高/中/低",
      "impact": "影响描述",
      "affected_assets": ["受影响资产"]
    }}
  ],
  "remediation_plan": [
    {{
      "priority": 1,
      "vulnerability_id": "漏洞ID",
      "action": "修复措施",
      "effort": "高/中/低",
      "timeline": "建议修复时间"
    }}
  ],
  "security_recommendations": [
    "安全建议1",
    "安全建议2",
    "安全建议3"
  ],
  "compliance_notes": "合规性说明",
  "next_steps": ["下一步行动建议"]
}}

分析要求:
1. summary要全面概括安全状况，包含风险等级和主要问题
2. vulnerability_analysis要对每个重要漏洞进行深入分析
3. exploitation_scenarios要描述可能的攻击路径
4. remediation_plan要给出具体可操作的修复方案
5. security_recommendations要给出中长期安全建议
6. 所有分析要基于实际扫描数据，避免泛泛而谈
7. 明确区分已证实、疑似、未发现和无法判断；工具成功不代表目标安全
8. 知识库只用于解释、定级和修复建议，不能作为本次扫描发现漏洞的证据
9. 禁止补造扫描结果中不存在的端口、URL、CVE、漏洞或业务影响
"""
    return prompt


def _parse_llm_response(response_text: str, vulnerabilities: List[Dict[str, Any]] = None) -> AIAnalysisResult:
    """解析详细LLM响应"""
    result = AIAnalysisResult()
    result.summary = "分析结果解析失败"
    result.risk_level = "info"

    try:
        logger.debug(f"开始解析LLM响应，响应长度: {len(response_text)}")

        json_match = re.search(r'\{[\s\S]*\}', response_text)
        if json_match:
            json_str = json_match.group()
            logger.debug(f"提取到JSON字符串: {json_str[:100]}...")

            data = json.loads(json_str)
            logger.info(f"解析JSON数据成功，字段: {list(data.keys())}")

            if "summary" in data:
                result.summary = data["summary"]
                logger.info(f"风险总结: {result.summary[:100]}...")

            if "risk_level" in data:
                result.risk_level = data["risk_level"]
                logger.info(f"风险等级: {result.risk_level}")

            vuln_analysis = data.get("vulnerability_analysis", [])
            # Task 6.2: 使用 confidence_calculator 计算置信度，替代硬编码 0.8
            # 旧的硬编码 confidence=0.8 仅作为 fallback 保留
            llm_confidence = 0.8  # fallback
            try:
                from TOSKill.tools.report.confidence_calculator import calculate_confidence
                state = {
                    "completed_tasks": [],
                    "planned_tasks": [],
                    "execution_history": [],
                    "decision_history": [],
                    "mode": "full_scan"
                }
                confidence_result = calculate_confidence(state, vulnerabilities or [], None)
                llm_confidence = confidence_result.get("total", 80) / 100.0
            except Exception as e:
                logger.debug(f"置信度计算失败，使用 fallback 值 0.8: {e}")

            for va in vuln_analysis[:10]:
                result.vulnerability_causes.append(VulnerabilityCause(
                    description=va.get("root_cause", ""),
                    confidence=llm_confidence,
                    evidence=[
                        va.get("attack_vector", ""),
                        va.get("potential_impact", "")
                    ]
                ))
            
            exploitation_scenarios = data.get("exploitation_scenarios", [])
            for es in exploitation_scenarios[:5]:
                likelihood_map = {"高": 0.9, "中": 0.6, "低": 0.3}
                result.exploitation_risks.append(ExploitationRisk(
                    risk_level=es.get("likelihood", "低"),
                    description=es.get("scenario", ""),
                    likelihood=likelihood_map.get(es.get("likelihood", "低"), 0.3),
                    impact=es.get("impact", "")
                ))
            
            remediation_plan = data.get("remediation_plan", [])
            for rp in remediation_plan[:10]:
                result.remediation_priorities.append(RemediationPriority(
                    vulnerability_id=str(rp.get("vulnerability_id", "")),
                    vulnerability_name="",
                    priority=rp.get("priority", 5),
                    reason=rp.get("action", ""),
                    estimated_effort=rp.get("effort", "中")
                ))
            
            recommendations = data.get("security_recommendations", [])
            for rec in recommendations[:5]:
                result.remediation_priorities.append(RemediationPriority(
                    vulnerability_id="",
                    vulnerability_name="安全建议",
                    priority=3,
                    reason=rec,
                    estimated_effort="低"
                ))
            
            if data.get("compliance_notes"):
                result.business_impact.compliance_risk = data["compliance_notes"]
            
            next_steps = data.get("next_steps", [])
            if next_steps:
                result.analysis_evidence.extend(next_steps)
            
            result.analysis_evidence.append("基于AI的深度分析")
            logger.info("LLM响应解析完成")
            
        else:
            logger.warning("未找到JSON结构，使用默认值")
            
    except Exception as e:
        logger.error(f"解析LLM响应失败: {e}")
        logger.exception(f"解析异常详情: {e}")
        result.summary = "分析结果解析失败"
        result.risk_level = "info"
    
    return result


def _analyze_with_llm(
    vulnerabilities: List[Dict[str, Any]],
    tool_results: Dict[str, Any],
    target_context: Dict[str, Any],
    llm_client,
    model_id: str,
    api_base_url: str,
    knowledge_context: str = ""
) -> AIAnalysisResult:
    """使用LLM进行分析"""
    result = AIAnalysisResult()
    
    logger.info("LLM分析开始...")
    logger.info(f"模型ID: {model_id}")
    logger.info(f"API Base URL: {api_base_url}")
    
    try:
        prompt = _build_analysis_prompt(
            vulnerabilities, tool_results, target_context, knowledge_context
        )
        logger.info(f"构建提示词完成，长度: {len(prompt)} 字符")
        logger.debug(f"提示词内容: {prompt[:500]}...")
        
        logger.info("正在调用LLM API...")
        response = llm_client.chat.completions.create(
            model=model_id,
            messages=[
                {"role": "system", "content": "你是一位专业的安全分析师，擅长分析Web漏洞扫描结果。请严格按照JSON格式输出分析结果。"},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7
        )
        
        analysis_text = response.choices[0].message.content
        logger.info(f"LLM响应成功，响应长度: {len(analysis_text)} 字符")
        logger.info(f"LLM响应内容: {analysis_text[:200]}...")
        
        result = _parse_llm_response(analysis_text, vulnerabilities)
        
        result.analysis_evidence.append("基于LLM的智能分析")
        logger.info("LLM分析完成")
        
    except Exception as e:
        logger.error(f"LLM分析失败: {e}")
        logger.error(f"错误类型: {type(e).__name__}")
        logger.warning("回退到规则分析")
        result = _analyze_with_rules(vulnerabilities, tool_results, target_context)
    
    return result


def _extract_causes_by_rules(vulnerabilities: List[Dict[str, Any]]) -> List[VulnerabilityCause]:
    """通过规则提取漏洞成因"""
    causes = []

    # Task 6.2: 使用 confidence_calculator 模块计算置信度，替代硬编码值 (0.7/0.8/0.5)
    # 旧的硬编码 confidence 值仅作为 fallback 保留
    calculated_confidence = None
    try:
        from TOSKill.tools.report.confidence_calculator import calculate_confidence
        state = {
            "completed_tasks": [],
            "planned_tasks": [],
            "execution_history": [],
            "decision_history": [],
            "mode": "full_scan"
        }
        confidence_result = calculate_confidence(state, vulnerabilities, None)
        calculated_confidence = confidence_result.get("total", 0) / 100.0
    except Exception as e:
        logger.debug(f"置信度计算失败，将使用 fallback 硬编码值: {e}")

    for vuln in vulnerabilities:
        vuln_type = vuln.get("vuln_type", "").lower()
        severity = vuln.get("severity", "")

        if "sqli" in vuln_type or "sql" in vuln_type:
            causes.append(VulnerabilityCause(
                description="可能存在输入验证不足，导致SQL注入漏洞",
                confidence=calculated_confidence if calculated_confidence is not None else 0.7,  # fallback: 0.7
                evidence=[f"发现{severity}级SQL注入漏洞"]
            ))
        elif "xss" in vuln_type:
            causes.append(VulnerabilityCause(
                description="可能存在输出编码不足，导致XSS漏洞",
                confidence=calculated_confidence if calculated_confidence is not None else 0.7,  # fallback: 0.7
                evidence=[f"发现{severity}级XSS漏洞"]
            ))
        elif "rce" in vuln_type or "command" in vuln_type:
            causes.append(VulnerabilityCause(
                description="可能存在命令执行限制不足，导致远程代码执行漏洞",
                confidence=calculated_confidence if calculated_confidence is not None else 0.8,  # fallback: 0.8
                evidence=[f"发现{severity}级命令执行漏洞"]
            ))
        elif "lfi" in vuln_type or "file" in vuln_type:
            causes.append(VulnerabilityCause(
                description="可能存在文件路径限制不足，导致文件包含漏洞",
                confidence=calculated_confidence if calculated_confidence is not None else 0.7,  # fallback: 0.7
                evidence=[f"发现{severity}级文件包含漏洞"]
            ))
        elif "ssrf" in vuln_type:
            causes.append(VulnerabilityCause(
                description="可能存在URL白名单验证不足，导致SSRF漏洞",
                confidence=calculated_confidence if calculated_confidence is not None else 0.7,  # fallback: 0.7
                evidence=[f"发现{severity}级SSRF漏洞"]
            ))

    if not causes and vulnerabilities:
        causes.append(VulnerabilityCause(
            description="发现安全漏洞，建议进行人工复核",
            confidence=calculated_confidence if calculated_confidence is not None else 0.5,  # fallback: 0.5
            evidence=[f"共发现{len(vulnerabilities)}个漏洞"]
        ))

    return causes


def _extract_risks_by_rules(vulnerabilities: List[Dict[str, Any]]) -> List[ExploitationRisk]:
    """通过规则提取利用风险"""
    risks = []
    
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "low")
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    if severity_counts["critical"] > 0:
        risks.append(ExploitationRisk(
            risk_level="critical",
            description=f"存在{severity_counts['critical']}个严重漏洞，可能导致系统被完全控制",
            likelihood=0.9,
            impact="critical"
        ))
    
    if severity_counts["high"] > 0:
        risks.append(ExploitationRisk(
            risk_level="high",
            description=f"存在{severity_counts['high']}个高危漏洞，可能导致数据泄露",
            likelihood=0.7,
            impact="high"
        ))
    
    if not risks:
        risks.append(ExploitationRisk(
            risk_level="low",
            description="当前发现的漏洞风险较低，但建议持续监控",
            likelihood=0.3,
            impact="low"
        ))
    
    return risks


def _extract_priorities_by_rules(vulnerabilities: List[Dict[str, Any]]) -> List[RemediationPriority]:
    """通过规则提取修复优先级"""
    priorities = []
    
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_vulns = sorted(
        vulnerabilities,
        key=lambda x: severity_order.get(x.get("severity", "info"), 4)
    )
    
    for i, vuln in enumerate(sorted_vulns[:10]):
        severity = vuln.get("severity", "info")
        effort = "高" if severity in ["critical", "high"] else "中" if severity == "medium" else "低"
        
        priorities.append(RemediationPriority(
            vulnerability_id=str(i),
            vulnerability_name=vuln.get("title", vuln.get("vuln_type", "Unknown")),
            priority=i + 1,
            reason=f"{severity}级漏洞，优先处理",
            estimated_effort=effort
        ))
    
    return priorities


def _extract_business_impact_by_rules(
    vulnerabilities: List[Dict[str, Any]],
    target_context: Dict[str, Any]
) -> BusinessImpact:
    """通过规则提取业务影响"""
    impact = BusinessImpact()
    
    impact.affected_systems = [target_context.get("domain", "未知系统")]
    
    has_critical = any(v.get("severity") == "critical" for v in vulnerabilities)
    has_high = any(v.get("severity") == "high" for v in vulnerabilities)
    
    if has_critical:
        impact.data_risk = "高"
        impact.downtime_risk = "高"
        impact.compliance_risk = "高"
        impact.financial_impact = "高"
    elif has_high:
        impact.data_risk = "中"
        impact.downtime_risk = "中"
        impact.compliance_risk = "中"
        impact.financial_impact = "中"
    else:
        impact.data_risk = "低"
        impact.downtime_risk = "低"
        impact.compliance_risk = "低"
        impact.financial_impact = "低"
    
    return impact


def _analyze_with_rules(
    vulnerabilities: List[Dict[str, Any]],
    tool_results: Dict[str, Any],
    target_context: Dict[str, Any]
) -> AIAnalysisResult:
    """使用规则进行分析"""
    result = AIAnalysisResult()
    
    result.vulnerability_causes = _extract_causes_by_rules(vulnerabilities)
    result.exploitation_risks = _extract_risks_by_rules(vulnerabilities)
    result.remediation_priorities = _extract_priorities_by_rules(vulnerabilities)
    result.business_impact = _extract_business_impact_by_rules(vulnerabilities, target_context)
    result.analysis_evidence.append("基于规则的分析")
    
    return result


@tool
def ai_analyzer(
    vulnerabilities: List[Dict[str, Any]],
    tool_results: Dict[str, Any],
    target_context: Dict[str, Any]
) -> Dict[str, Any]:
    """AI分析器工具，对扫描结果进行AI驱动的深度分析
    
    使用AI/LLM对扫描结果进行深度分析，包括：
    - 漏洞成因分析
    - 利用风险评估
    - 修复优先级建议
    - 业务影响分析
    
    当LLM不可用时自动回退到规则引擎分析。
    
    Args:
        vulnerabilities: 漏洞列表，每个漏洞包含id、vuln_type、severity、url等字段
        tool_results: 工具执行结果字典
        target_context: 目标上下文，包含target、domain等信息
        
    Returns:
        包含分析结果的字典，包括：
        - success: 执行状态(True/False)
        - data: 分析结果数据
        - error: 错误信息(成功时为None)
        - metadata: 元数据(工具名称、风险等级、漏洞数量等)
    """
    try:
        logger.info(f"开始AI分析...")
        logger.info(f"目标: {target_context.get('target', 'Unknown')}")
        logger.info(f"漏洞数量: {len(vulnerabilities)}")
        logger.info(f"工具结果数量: {len(tool_results) if tool_results else 0}")

        knowledge_context = ""
        knowledge_sources: List[str] = []
        try:
            from TOSKill.RAG.retriever import extract_knowledge_sources, retrieve_for_report
            knowledge_context = retrieve_for_report(
                target_context.get("target", "Unknown"), vulnerabilities
            ) or ""
            knowledge_sources = extract_knowledge_sources(knowledge_context)
            logger.info(
                "AI分析知识库检索完成: used=%s, sources=%s",
                bool(knowledge_context), knowledge_sources,
            )
        except Exception as e:
            logger.warning(f"AI分析知识库检索失败，继续无知识库分析: {e}")
        
        llm_client, model_id, api_base_url = _init_llm_client()
        
        if llm_client:
            logger.info("使用LLM进行智能分析...")
            result = _analyze_with_llm(
                vulnerabilities, tool_results, target_context,
                llm_client, model_id, api_base_url, knowledge_context
            )
        else:
            logger.info("使用规则引擎进行分析...")
            result = _analyze_with_rules(vulnerabilities, tool_results, target_context)

        if knowledge_sources:
            result.analysis_evidence.append(
                "知识库参考: " + "、".join(knowledge_sources)
            )
        
        logger.info(f"AI分析完成，结果: {result.summary}")
        
        return {
            "success": True,
            "data": result.to_dict(),
            "error": "",
            "metadata": {
                "tool": "ai_analyzer",
                "target": target_context.get("target", "Unknown"),
                "risk_level": result.risk_level,
                "vulnerability_count": len(vulnerabilities),
                "analysis_method": "LLM" if llm_client else "Rules",
                "knowledge_used": bool(knowledge_context),
                "knowledge_sources": knowledge_sources,
            }
        }
    except Exception as e:
        logger.error(f"AI分析执行失败: {str(e)}")
        return {
            "success": False,
            "data": {},
            "error": f"AI分析执行异常: {str(e)}",
            "metadata": {
                "tool": "ai_analyzer",
                "target": target_context.get("target", "Unknown") if target_context else "Unknown"
            }
        }


if __name__ == "__main__":
    test_vulns = [
        {"id": "1", "vuln_type": "sqli", "severity": "high", "url": "http://example.com/test?id=1"}
    ]
    test_context = {"target": "http://example.com", "domain": "example.com"}
    test_results = {"baseinfo": {"success": True}}
    
    result = ai_analyzer.invoke({
        "vulnerabilities": test_vulns,
        "tool_results": test_results,
        "target_context": test_context
    })
    print(json.dumps(result, indent=2, ensure_ascii=False))
