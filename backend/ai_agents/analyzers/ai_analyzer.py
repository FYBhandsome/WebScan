"""
AI分析器

实现AI驱动的扫描结果深度分析功能。
"""
import logging
import json
import re
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
        """使用LLM进行分析（带重试和超时机制）"""
        import asyncio
        
        result = AIAnalysisResult()
        max_retries = 3
        timeout_seconds = 30
        
        for attempt in range(max_retries):
            try:
                prompt = self._build_analysis_prompt(vulnerabilities, tool_results, target_context)
                
                def _call_llm():
                    return self.llm_client.chat.completions.create(
                        model=self.model_id,
                        messages=[
                            {"role": "system", "content": "你是一位专业的安全分析师，擅长分析Web漏洞扫描结果。请严格按照JSON格式输出分析结果，不要包含任何markdown标记。"},
                            {"role": "user", "content": prompt}
                        ],
                        temperature=0.3,
                        max_tokens=1500
                    )
                
                try:
                    response = await asyncio.wait_for(
                        asyncio.to_thread(_call_llm),
                        timeout=timeout_seconds
                    )
                except asyncio.TimeoutError:
                    logger.warning(f"⚠️ LLM调用超时 (尝试 {attempt + 1}/{max_retries})")
                    if attempt < max_retries - 1:
                        await asyncio.sleep(1)
                        continue
                    raise TimeoutError("LLM调用超时，已达到最大重试次数")
                
                if not response or not response.choices:
                    logger.warning(f"⚠️ LLM返回空响应 (尝试 {attempt + 1}/{max_retries})")
                    if attempt < max_retries - 1:
                        await asyncio.sleep(1)
                        continue
                    raise ValueError("LLM返回空响应")
                
                analysis_text = response.choices[0].message.content
                
                logger.debug(f"📝 LLM原始响应: {analysis_text[:500]}...")
                
                if not analysis_text or len(analysis_text.strip()) < 10:
                    logger.warning(f"⚠️ LLM返回内容过短 (尝试 {attempt + 1}/{max_retries})")
                    if attempt < max_retries - 1:
                        await asyncio.sleep(1)
                        continue
                    raise ValueError("LLM返回内容过短")
                
                result = self._parse_llm_response(analysis_text)
                result.analysis_evidence.append(f"基于LLM的智能分析(尝试{attempt + 1}次成功)")
                logger.info(f"✅ LLM分析成功 (第{attempt + 1}次尝试)")
                break
                
            except TimeoutError as e:
                logger.error(f"❌ LLM分析超时: {e}")
                result.summary = "AI分析超时，使用规则分析"
                result.risk_level = self._estimate_risk_level(vulnerabilities)
                
            except Exception as e:
                logger.error(f"❌ LLM分析失败 (尝试 {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(1)
                    continue
                result.summary = "AI分析失败，使用规则分析"
                result.risk_level = self._estimate_risk_level(vulnerabilities)
        
        if not result.summary or result.summary == "分析结果解析失败":
            result = self._analyze_with_rules(vulnerabilities, tool_results, target_context)
        
        return result
    
    def _estimate_risk_level(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """根据漏洞列表估算风险等级"""
        if not vulnerabilities:
            return "info"
        
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        max_severity = 0
        
        for vuln in vulnerabilities:
            sev = vuln.get("severity", "info").lower()
            max_severity = max(max_severity, severity_order.get(sev, 0))
        
        if max_severity >= 4:
            return "critical"
        elif max_severity >= 3:
            return "high"
        elif max_severity >= 2:
            return "medium"
        elif max_severity >= 1:
            return "low"
        return "info"
    
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
        
        prompt = f"""# Role
你是一位资深安全分析师，拥有CISSP、OSCP等专业认证，擅长Web漏洞分析、风险评估和安全报告撰写。请基于以下扫描数据进行专业分析。

# Target Information
- 目标: {target_context.get('target', 'Unknown')}
- 扫描时间: {target_context.get('scan_time', 'Unknown')}
- 扫描策略: {target_context.get('strategy', 'standard')}

# Vulnerability Statistics
- 漏洞总数: {len(vulnerabilities)}
- 严重程度分布: 严重={severity_count['critical']}, 高危={severity_count['high']}, 中危={severity_count['medium']}, 低危={severity_count['low']}, 信息={severity_count['info']}

# Execution History
{json.dumps(execution_summary[:10], ensure_ascii=False, indent=2)}

# Key Vulnerabilities
{json.dumps(vulns_summary, ensure_ascii=False, indent=2)}

# Analysis Requirements

## 1. 风险总结 (summary)
- 一句话概括整体安全状况，不超过50字
- 需包含漏洞数量和最严重漏洞类型

## 2. 风险等级 (risk_level)
- critical: 存在可直接获取系统权限的漏洞（如RCE、SQL注入）
- high: 存在可导致数据泄露的漏洞（如XSS、敏感信息泄露）
- medium: 存在需要特定条件的漏洞（如CSRF、LFI）
- low: 存在信息泄露或配置问题
- info: 仅有信息收集结果，无安全风险

## 3. 漏洞成因 (causes)
- 分析漏洞产生的根本原因
- 最多3条，每条不超过30字
- 示例: "输入验证缺失", "危险函数使用不当", "配置错误"

## 4. 利用风险 (risks)
- 评估漏洞被利用的可能影响
- 最多3条，每条不超过50字
- 示例: "攻击者可获取数据库敏感数据", "可能导致用户会话劫持"

## 5. 修复优先级 (top_vulnerabilities)
- 按风险程度排序，最多5条
- fix_priority: 1=最高优先级, 5=最低优先级

## 6. 修复建议 (recommendations)
- 提供具体可执行的修复方案
- 最多5条，每条不超过50字

# Example Output

输入: 发现SQL注入和XSS漏洞各1个
输出:
{{
  "summary": "发现2个高危漏洞：SQL注入可导致数据泄露，XSS存在会话劫持风险",
  "risk_level": "critical",
  "causes": ["用户输入未经过滤直接拼接到SQL语句", "输出未进行HTML编码"],
  "risks": ["攻击者可获取数据库全部数据", "用户会话可能被劫持", "网站可能被植入恶意脚本"],
  "top_vulnerabilities": [
    {{"id": "vuln-001", "type": "SQLInjection", "severity": "critical", "fix_priority": 1}},
    {{"id": "vuln-002", "type": "XSS", "severity": "high", "fix_priority": 2}}
  ],
  "recommendations": ["使用参数化查询替代SQL拼接", "对所有输出进行HTML实体编码", "部署WAF进行流量过滤"]
}}

# Output Format
严格返回以下JSON格式，不要包含任何其他文字、markdown标记或代码块：
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
"""
        return prompt
    
    def _parse_llm_response(self, response_text: str) -> AIAnalysisResult:
        """解析增强后的LLM响应（多策略解析）"""
        import json
        import re
        
        result = AIAnalysisResult()
        result.summary = "分析结果解析失败"
        result.risk_level = "info"
        
        if not response_text or not isinstance(response_text, str):
            logger.warning("⚠️ 响应内容为空或类型错误")
            return result
        
        response_text = response_text.strip()
        
        parsing_strategies = [
            self._try_parse_direct_json,
            self._try_parse_markdown_code_block,
            self._try_parse_partial_json,
            self._try_extract_key_fields,
        ]
        
        for strategy in parsing_strategies:
            try:
                data = strategy(response_text)
                if data and isinstance(data, dict):
                    self._populate_result_from_data(result, data)
                    logger.info(f"✅ JSON解析成功 (策略: {strategy.__name__})")
                    return result
            except Exception as e:
                logger.debug(f"策略 {strategy.__name__} 解析失败: {e}")
                continue
        
        logger.warning("⚠️ 所有解析策略失败，使用默认值")
        result.summary = "分析结果解析失败，请检查原始响应"
        result.risk_level = "info"
        
        return result
    
    def _try_parse_direct_json(self, text: str) -> dict:
        """直接解析JSON"""
        return json.loads(text)
    
    def _try_parse_markdown_code_block(self, text: str) -> dict:
        """解析markdown代码块中的JSON"""
        patterns = [
            r'```json\s*([\s\S]*?)\s*```',
            r'```\s*([\s\S]*?)\s*```',
        ]
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return json.loads(match.group(1))
        raise ValueError("未找到markdown代码块")
    
    def _try_parse_partial_json(self, text: str) -> dict:
        """解析部分JSON（处理截断情况）"""
        json_match = re.search(r'\{[\s\S]*\}', text)
        if json_match:
            json_str = json_match.group()
            try:
                return json.loads(json_str)
            except json.JSONDecodeError:
                json_str = self._repair_json(json_str)
                return json.loads(json_str)
        raise ValueError("未找到JSON结构")
    
    def _try_extract_key_fields(self, text: str) -> dict:
        """从文本中提取关键字段"""
        data = {}
        
        summary_match = re.search(r'"summary"\s*:\s*"([^"]*)"', text)
        if summary_match:
            data["summary"] = summary_match.group(1)
        
        risk_match = re.search(r'"risk_level"\s*:\s*"(\w+)"', text)
        if risk_match:
            data["risk_level"] = risk_match.group(1)
        
        causes_match = re.search(r'"causes"\s*:\s*\[([^\]]*)\]', text)
        if causes_match:
            causes_str = causes_match.group(1)
            causes = re.findall(r'"([^"]*)"', causes_str)
            data["causes"] = causes
        
        risks_match = re.search(r'"risks"\s*:\s*\[([^\]]*)\]', text)
        if risks_match:
            risks_str = risks_match.group(1)
            risks = re.findall(r'"([^"]*)"', risks_str)
            data["risks"] = risks
        
        if data:
            return data
        raise ValueError("无法提取关键字段")
    
    def _repair_json(self, json_str: str) -> str:
        """尝试修复损坏的JSON"""
        json_str = re.sub(r',\s*}', '}', json_str)
        json_str = re.sub(r',\s*]', ']', json_str)
        open_braces = json_str.count('{') - json_str.count('}')
        open_brackets = json_str.count('[') - json_str.count(']')
        json_str += '}' * open_braces
        json_str += ']' * open_brackets
        return json_str
    
    def _populate_result_from_data(self, result: AIAnalysisResult, data: dict) -> None:
        """从解析的数据填充结果对象"""
        if "summary" in data:
            result.summary = data["summary"][:100]
        
        if "risk_level" in data:
            valid_levels = ["critical", "high", "medium", "low", "info"]
            level = data["risk_level"].lower()
            result.risk_level = level if level in valid_levels else "info"
        
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
                reason=rec if isinstance(rec, str) else str(rec),
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


ai_analyzer = AIAnalyzer()
