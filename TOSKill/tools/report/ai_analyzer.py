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
    target_context: Dict[str, Any]
) -> str:
    """构建精简分析提示词"""
    vulns_summary = [
        {
            "id": v.get("id"),
            "type": v.get("vuln_type", v.get("type")),
            "severity": v.get("severity"),
            "url": str(v.get("url", ""))[:100]
        }
        for v in vulnerabilities[:5]
    ]
    
    prompt = f"""分析以下安全扫描结果，输出简洁的JSON报告。

目标: {target_context.get('target', 'Unknown')}
漏洞数量: {len(vulnerabilities)}
主要漏洞:
{json.dumps(vulns_summary, ensure_ascii=False, indent=2)}

输出格式(必须严格遵循):
{{
  "summary": "一句话风险总结(不超过50字)",
  "risk_level": "critical/high/medium/low/info",
  "top_vulnerabilities": [
    {{"id": "漏洞ID", "type": "类型", "severity": "严重程度", "fix_priority": 1-5}}
  ],
  "recommendations": ["修复建议1", "修复建议2"]
}}

要求:
1. summary不超过50字
2. top_vulnerabilities最多3条
3. recommendations最多3条
4. 只输出JSON，不要其他内容
"""
    return prompt


def _parse_llm_response(response_text: str) -> AIAnalysisResult:
    """解析精简后的LLM响应"""
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
                logger.info(f"风险总结: {result.summary}")
            
            if "risk_level" in data:
                result.risk_level = data["risk_level"]
                logger.info(f"风险等级: {result.risk_level}")
            
            top_vulnerabilities = data.get("top_vulnerabilities", [])
            for vuln in top_vulnerabilities[:3]:
                result.remediation_priorities.append(RemediationPriority(
                    vulnerability_id=str(vuln.get("id", "")),
                    vulnerability_name=vuln.get("type", ""),
                    priority=vuln.get("fix_priority", 5),
                    reason=vuln.get("severity", ""),
                    estimated_effort="中"
                ))
                logger.info(f"添加优先级漏洞: {vuln.get('type', 'Unknown')}")
            
            recommendations = data.get("recommendations", [])
            for rec in recommendations[:3]:
                result.remediation_priorities.append(RemediationPriority(
                    vulnerability_id="",
                    vulnerability_name="通用建议",
                    priority=3,
                    reason=rec,
                    estimated_effort="低"
                ))
                logger.info(f"添加修复建议: {rec[:50]}...")
            
            if result.summary:
                result.vulnerability_causes.append(VulnerabilityCause(
                    description=result.summary,
                    confidence=0.8,
                    evidence=["基于AI分析的总结"]
                ))
            
            result.exploitation_risks.append(ExploitationRisk(
                risk_level=result.risk_level,
                description=f"风险等级为{result.risk_level}的安全问题",
                likelihood=0.7,
                impact=result.risk_level
            ))
            
            result.analysis_evidence.append("基于AI的分析")
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
    api_base_url: str
) -> AIAnalysisResult:
    """使用LLM进行分析"""
    result = AIAnalysisResult()
    
    logger.info("LLM分析开始...")
    logger.info(f"模型ID: {model_id}")
    logger.info(f"API Base URL: {api_base_url}")
    
    try:
        prompt = _build_analysis_prompt(vulnerabilities, tool_results, target_context)
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
        
        result = _parse_llm_response(analysis_text)
        
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
    
    for vuln in vulnerabilities:
        vuln_type = vuln.get("vuln_type", "").lower()
        severity = vuln.get("severity", "")
        
        if "sqli" in vuln_type or "sql" in vuln_type:
            causes.append(VulnerabilityCause(
                description="可能存在输入验证不足，导致SQL注入漏洞",
                confidence=0.7,
                evidence=[f"发现{severity}级SQL注入漏洞"]
            ))
        elif "xss" in vuln_type:
            causes.append(VulnerabilityCause(
                description="可能存在输出编码不足，导致XSS漏洞",
                confidence=0.7,
                evidence=[f"发现{severity}级XSS漏洞"]
            ))
        elif "rce" in vuln_type or "command" in vuln_type:
            causes.append(VulnerabilityCause(
                description="可能存在命令执行限制不足，导致远程代码执行漏洞",
                confidence=0.8,
                evidence=[f"发现{severity}级命令执行漏洞"]
            ))
        elif "lfi" in vuln_type or "file" in vuln_type:
            causes.append(VulnerabilityCause(
                description="可能存在文件路径限制不足，导致文件包含漏洞",
                confidence=0.7,
                evidence=[f"发现{severity}级文件包含漏洞"]
            ))
        elif "ssrf" in vuln_type:
            causes.append(VulnerabilityCause(
                description="可能存在URL白名单验证不足，导致SSRF漏洞",
                confidence=0.7,
                evidence=[f"发现{severity}级SSRF漏洞"]
            ))
    
    if not causes and vulnerabilities:
        causes.append(VulnerabilityCause(
            description="发现安全漏洞，建议进行人工复核",
            confidence=0.5,
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
        
        llm_client, model_id, api_base_url = _init_llm_client()
        
        if llm_client:
            logger.info("使用LLM进行智能分析...")
            result = _analyze_with_llm(
                vulnerabilities, tool_results, target_context,
                llm_client, model_id, api_base_url
            )
        else:
            logger.info("使用规则引擎进行分析...")
            result = _analyze_with_rules(vulnerabilities, tool_results, target_context)
        
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
                "analysis_method": "LLM" if llm_client else "Rules"
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
