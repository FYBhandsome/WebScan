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
from dataclasses import dataclass
from typing import Dict, Any, Optional

from langchain_openai import ChatOpenAI

from TOSKill.config import settings
from TOSKill.AI.tools import get_tool_by_name

logger = logging.getLogger(__name__)

RESULT_MAX_CHARS = 3000


@dataclass
class AnalysisResult:
    tool_name: str
    tool_title: str
    target: str
    success: bool
    raw_result: Any
    analysis: str
    summary: str


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

    def _build_prompt(self, tool_title: str, target: str, result: Any) -> str:
        result_str = json.dumps(result, ensure_ascii=False, indent=2)
        if len(result_str) > RESULT_MAX_CHARS:
            result_str = result_str[:RESULT_MAX_CHARS] + "\n... (结果已截断)"

        return f"""你是一个安全扫描结果分析助手。请分析以下工具扫描结果，按指定格式输出。

工具名称：{tool_title}
扫描目标：{target}
执行状态：成功

扫描结果：
{result_str}

请严格按照以下格式输出（不要输出任何额外内容）：

===ANALYSIS===
提供详细的扫描结果分析：成功状态说明、核心结果数据解读、关键发现和参数说明

===SUMMARY===
提供2-3句话的简明总结，概括本次扫描的核心发现"""

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

        return analysis, summary

    def _fallback_analysis(self, tool_title: str, target: str, result: Any) -> tuple:
        if isinstance(result, dict):
            keys = list(result.keys())
            data_preview = f"返回了 {len(keys)} 个字段: {', '.join(keys[:5])}"
        elif isinstance(result, list):
            data_preview = f"返回了 {len(result)} 条记录"
        else:
            data_preview = "返回了数据"

        analysis = f"工具 {tool_title} 对目标 {target} 执行成功。{data_preview}。"
        summary = f"{tool_title} 扫描完成，{data_preview}。"
        return analysis, summary

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

        try:
            if success:
                prompt = self._build_prompt(tool_title, target, result)
            else:
                prompt = self._build_failure_prompt(tool_title, target, error)

            response = self.llm.invoke(prompt)
            response_text = response.content if hasattr(response, 'content') else str(response)
            analysis, summary = self._parse_response(response_text)
        except Exception as e:
            logger.warning(f"LLM 分析失败，降级使用模板分析: {e}")
            if success:
                analysis, summary = self._fallback_analysis(tool_title, target, result)
            else:
                analysis = (
                    f"工具 {tool_title} 对目标 {target} 执行失败。"
                    f"错误信息: {error}。建议检查目标可达性或工具配置。"
                )
                summary = f"{tool_title} 执行失败。"

        return AnalysisResult(
            tool_name=tool_name,
            tool_title=tool_title,
            target=target,
            success=success,
            raw_result=raw,
            analysis=analysis,
            summary=summary
        )

    def format_display(self, analysis_result: AnalysisResult) -> str:
        result_json = json.dumps(
            analysis_result.raw_result, ensure_ascii=False, indent=2
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