"""
工具扫描结果 AI 分析器

提供通用的扫描结果分析功能，调用 LLM 对工具执行结果进行结构化分析，
生成包含执行标题、原始JSON、详细分析和总结的分层展示内容。

可在任何后端模块中复用：

    from TOSKill.analysis.result_analyzer import ResultAnalyzer

    analyzer = ResultAnalyzer()
    result = analyzer.analyze("portscan", "example.com", scan_result)
    formatted = analyzer.format_display(result)
"""
import json
import logging
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

from langchain_openai import ChatOpenAI

from TOSKill.config import settings
from TOSKill.AI.tools import get_tool_by_name

logger = logging.getLogger(__name__)

RESULT_MAX_CHARS = 3000
SENSITIVE_RESULT_KEYS = {
    "authorization", "cookie", "cookies", "password", "passwd", "secret",
    "token", "access_token", "refresh_token", "api_key", "apikey",
    "session", "session_id", "set-cookie",
}


def sanitize_result_for_display(value: Any, depth: int = 0) -> Any:
    """移除认证秘密并限制深层数据量，供提示词和 WebSocket 安全展示。"""
    if depth > 6:
        return "[内容层级过深，已截断]"
    if isinstance(value, dict):
        sanitized = {}
        for key, item in list(value.items())[:100]:
            key_text = str(key)
            if key_text.lower() in SENSITIVE_RESULT_KEYS:
                sanitized[key_text] = "[已脱敏]"
            else:
                sanitized[key_text] = sanitize_result_for_display(item, depth + 1)
        return sanitized
    if isinstance(value, (list, tuple, set)):
        items = list(value)
        sanitized_items = [sanitize_result_for_display(item, depth + 1) for item in items[:100]]
        if len(items) > 100:
            sanitized_items.append(f"[另有 {len(items) - 100} 项已截断]")
        return sanitized_items
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


@dataclass
class AnalysisResult:
    tool_name: str
    tool_title: str
    target: str
    success: bool
    raw_result: Any
    analysis: str
    summary: str
    risk_level: str = "info"
    key_findings: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    knowledge_used: bool = False
    knowledge_sources: List[str] = field(default_factory=list)


class ResultAnalyzer:
    def __init__(self):
        self._llm = None

    @property
    def llm(self):
        if self._llm is None:
            self._llm = ChatOpenAI(
                model=settings.MODEL_ID,
                temperature=settings.LLM_TEMPERATURE,
                api_key=settings.OPENAI_API_KEY,
                base_url=settings.OPENAI_BASE_URL,
                timeout=30.0
            )
        return self._llm

    def _get_tool_title(self, tool_name: str) -> str:
        tool = get_tool_by_name(tool_name)
        if tool and hasattr(tool, 'description') and tool.description:
            desc = tool.description.strip()
            first_line = desc.split('\n')[0].strip()
            if first_line:
                return first_line
        return tool_name

    def _build_prompt(
        self,
        tool_title: str,
        target: str,
        result: Any,
        knowledge_context: str = ""
    ) -> str:
        safe_result = sanitize_result_for_display(result)
        result_str = json.dumps(safe_result, ensure_ascii=False, indent=2, default=str)
        if len(result_str) > RESULT_MAX_CHARS:
            result_str = result_str[:RESULT_MAX_CHARS] + "\n... (结果已截断)"

        return f"""你是资深 Web 安全扫描结果分析师。请根据工具的真实返回数据生成给用户直接阅读的结构化结论。

工具名称：{tool_title}
扫描目标：{target}
执行状态：成功

扫描结果：
{result_str}

知识库参考（可能为空）：
{knowledge_context[:1800] if knowledge_context else "无可用知识库参考"}

分析规则：
1. 先判断工具是否真正完成、结果是否为空、是否存在超时/权限/认证/网络异常，不要把“工具返回 success”直接等同于“目标安全”。
2. 保留原始结果中的端口、服务、URL、参数、状态码、漏洞类型、严重度、证据等关键值；明确区分“已证实”“疑似”“未发现”和“无法判断”。
3. 只把扫描结果中的事实作为证据。知识库只能用于解释和建议，不能当作本次扫描已发现漏洞的证据。
4. 对可能的误报、结果截断和扫描覆盖不足作出说明；禁止补造不存在的漏洞、版本、CVE、端口或业务影响。
5. 建议必须与本次结果对应，按“立即处置、进一步验证、长期加固”给出可执行动作。

请只输出以下 JSON，不要使用 Markdown 代码块：
{{
  "summary": "2-3句话总结工具是否完成、最重要发现及结论边界",
  "risk_level": "critical/high/medium/low/info/unknown",
  "key_findings": ["按重要性排列的具体发现，包含关键数值"],
  "evidence": ["仅引用扫描结果中可核验的字段和值"],
  "analysis": "详细解释结果含义、攻击面/风险、误报可能性和扫描覆盖边界",
  "recommendations": ["立即处置或进一步验证动作", "长期加固建议"]
}}"""

    def _build_failure_prompt(self, tool_title: str, target: str, error_msg: str) -> str:
        return f"""你是一个安全扫描结果分析助手。请分析以下工具执行失败情况。

工具名称：{tool_title}
扫描目标：{target}
执行状态：失败
错误信息：{error_msg}

请严格按照以下格式输出（不要输出任何额外内容）：

===ANALYSIS===
分析执行失败的可能原因，以及建议的排查方向

===SUMMARY===
提供1-2句话的简明总结"""

    def _parse_response(self, response_text: str) -> tuple:
        analysis = ""
        summary = ""
        structured = {
            "risk_level": "info",
            "key_findings": [],
            "evidence": [],
            "recommendations": [],
        }

        try:
            start = response_text.find("{")
            end = response_text.rfind("}")
            if start >= 0 and end > start:
                data = json.loads(response_text[start:end + 1])
                analysis = str(data.get("analysis", "")).strip()
                summary = str(data.get("summary", "")).strip()
                risk_level = str(data.get("risk_level", "info")).lower()
                if risk_level not in {"critical", "high", "medium", "low", "info", "unknown"}:
                    risk_level = "unknown"
                structured = {
                    "risk_level": risk_level,
                    "key_findings": self._string_list(data.get("key_findings")),
                    "evidence": self._string_list(data.get("evidence")),
                    "recommendations": self._string_list(data.get("recommendations")),
                }
                if analysis or summary:
                    return analysis, summary, structured
        except (TypeError, ValueError, json.JSONDecodeError) as e:
            logger.debug(f"结构化分析响应解析失败，尝试兼容旧格式: {e}")

        if "===ANALYSIS===" in response_text and "===SUMMARY===" in response_text:
            parts = response_text.split("===SUMMARY===")
            analysis_part = parts[0]
            summary = parts[1].strip() if len(parts) > 1 else ""

            if "===ANALYSIS===" in analysis_part:
                analysis = analysis_part.split("===ANALYSIS===", 1)[1].strip()
        else:
            text = response_text.strip()
            if "\n\n" in text:
                paragraphs = text.split("\n\n")
                analysis = "\n\n".join(paragraphs[:-1])
                summary = paragraphs[-1]
            else:
                analysis = text
                summary = "请查看详细分析内容。"

        return analysis, summary, structured

    @staticmethod
    def _string_list(value: Any, limit: int = 8) -> List[str]:
        if not isinstance(value, list):
            return []
        return [str(item).strip() for item in value if str(item).strip()][:limit]

    def _extract_fallback_findings(self, result: Any) -> List[str]:
        """从常见工具字段提取可核验摘要，确保 LLM 不可用时信息仍完整。"""
        findings: List[str] = []
        if isinstance(result, dict):
            for key in ("status", "success", "vulnerable", "severity", "status_code"):
                if key in result:
                    findings.append(f"{key}: {result.get(key)}")
            for key in ("ports", "open_ports", "services", "technologies", "directories"):
                value = result.get(key)
                if value:
                    count = len(value) if isinstance(value, (list, dict, tuple, set)) else 1
                    findings.append(f"{key}: {count} 项（{str(value)[:180]}）")
            data = result.get("data")
            if isinstance(data, dict):
                for key in ("vulnerabilities", "findings", "ports", "open_ports", "services"):
                    value = data.get(key)
                    if value:
                        count = len(value) if isinstance(value, (list, dict, tuple, set)) else 1
                        findings.append(f"data.{key}: {count} 项（{str(value)[:180]}）")
        elif isinstance(result, list):
            findings.append(f"返回记录数: {len(result)}")
        return findings[:8]

    def _fallback_analysis(self, tool_title: str, target: str, result: Any) -> tuple:
        if isinstance(result, dict):
            keys = list(result.keys())
            data_preview = f"返回了 {len(keys)} 个字段: {', '.join(keys[:5])}"
        elif isinstance(result, list):
            data_preview = f"返回了 {len(result)} 条记录"
        else:
            data_preview = "返回了数据"

        findings = self._extract_fallback_findings(result)
        vulnerable = isinstance(result, dict) and bool(result.get("vulnerable"))
        severity = str(result.get("severity", "high" if vulnerable else "info")).lower() if isinstance(result, dict) else "info"
        if severity not in {"critical", "high", "medium", "low", "info", "unknown"}:
            severity = "unknown"
        finding_text = "；".join(findings) if findings else data_preview
        analysis = (
            f"工具 {tool_title} 已对目标 {target} 完成执行。可核验结果：{finding_text}。"
            "当前为规则降级分析，未发现不等于目标不存在漏洞，仍需结合扫描覆盖范围和原始结果复核。"
        )
        summary = f"{tool_title} 扫描完成，{finding_text}。"
        structured = {
            "risk_level": severity,
            "key_findings": findings or [data_preview],
            "evidence": findings,
            "recommendations": ["复核原始扫描结果及扫描覆盖范围", "对高风险或疑似发现执行授权的人工验证"],
        }
        return analysis, summary, structured

    def analyze(
        self,
        tool_name: str,
        target: str,
        result: Any,
        error: Optional[str] = None
    ) -> AnalysisResult:
        tool_title = self._get_tool_title(tool_name)
        success = error is None
        raw = result if success else error

        analysis = ""
        summary = ""
        structured = {
            "risk_level": "unknown" if not success else "info",
            "key_findings": [],
            "evidence": [],
            "recommendations": [],
        }
        knowledge_context = ""
        knowledge_sources: List[str] = []

        try:
            if success:
                try:
                    from TOSKill.RAG.retriever import (
                        extract_knowledge_sources,
                        retrieve_for_result_analysis,
                    )
                    knowledge_context = retrieve_for_result_analysis(tool_name, target, result)
                    knowledge_sources = extract_knowledge_sources(knowledge_context)
                except Exception as e:
                    logger.warning(f"工具结果知识库检索失败，继续无知识库分析: {e}")
                prompt = self._build_prompt(tool_title, target, result, knowledge_context)
            else:
                prompt = self._build_failure_prompt(tool_title, target, error)

            response = self.llm.invoke(prompt)
            response_text = response.content if hasattr(response, 'content') else str(response)
            analysis, summary, structured = self._parse_response(response_text)
        except Exception as e:
            logger.warning(f"LLM 分析失败，降级使用模板分析: {e}")
            if success:
                analysis, summary, structured = self._fallback_analysis(tool_title, target, result)
            else:
                analysis = (
                    f"工具 {tool_title} 对目标 {target} 执行失败。"
                    f"错误信息: {error}。建议检查目标可达性或工具配置。"
                )
                summary = f"{tool_title} 执行失败。"
                structured["recommendations"] = ["检查目标可达性、认证状态和工具参数后重试"]

        return AnalysisResult(
            tool_name=tool_name,
            tool_title=tool_title,
            target=target,
            success=success,
            raw_result=raw,
            analysis=analysis,
            summary=summary,
            risk_level=structured["risk_level"],
            key_findings=structured["key_findings"],
            evidence=structured["evidence"],
            recommendations=structured["recommendations"],
            knowledge_used=bool(knowledge_context),
            knowledge_sources=knowledge_sources,
        )

    def to_websocket_payload(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """生成前端可渐进展示、同时兼容旧 analysis 字段的结构化内容。"""
        sections = [analysis_result.summary]
        if analysis_result.key_findings:
            sections.append("关键发现：\n" + "\n".join(f"- {item}" for item in analysis_result.key_findings))
        if analysis_result.analysis:
            sections.append("详细分析：\n" + analysis_result.analysis)
        if analysis_result.evidence:
            sections.append("可核验证据：\n" + "\n".join(f"- {item}" for item in analysis_result.evidence))
        if analysis_result.recommendations:
            sections.append("处置建议：\n" + "\n".join(f"- {item}" for item in analysis_result.recommendations))
        if analysis_result.knowledge_sources:
            sections.append("知识库参考：" + "、".join(analysis_result.knowledge_sources))

        return {
            "analysis": "\n\n".join(section for section in sections if section),
            "summary": analysis_result.summary,
            "risk_level": analysis_result.risk_level,
            "key_findings": analysis_result.key_findings,
            "evidence": analysis_result.evidence,
            "recommendations": analysis_result.recommendations,
            "knowledge_used": analysis_result.knowledge_used,
            "knowledge_sources": analysis_result.knowledge_sources,
        }

    def format_display(self, analysis_result: AnalysisResult) -> str:
        result_json = json.dumps(
            sanitize_result_for_display(analysis_result.raw_result),
            ensure_ascii=False,
            indent=2,
        )

        lines = []
        if analysis_result.success:
            lines.append(f"[+] 执行{analysis_result.tool_title}：{analysis_result.target}")
        else:
            lines.append(f"[-] 执行{analysis_result.tool_title}：{analysis_result.target} (失败)")

        lines.append("")
        lines.append(f"📊 【{analysis_result.tool_title}】结果：")
        lines.append(result_json)
        lines.append("")
        lines.append("🧾 分析：")
        lines.append(analysis_result.analysis)
        lines.append("")
        lines.append("### 总结：")
        lines.append(analysis_result.summary)

        return "\n".join(lines)


_global_analyzer = None


def get_analyzer() -> ResultAnalyzer:
    global _global_analyzer
    if _global_analyzer is None:
        _global_analyzer = ResultAnalyzer()
    return _global_analyzer
