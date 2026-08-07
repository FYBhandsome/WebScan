# -*- coding:utf-8 -*-
"""
AI等保评估置信度评估器

流程：RAG检索等保上下文 → LLM结构化评估 → 解析为dict
降级：RAG不可用时用关键词降级；LLM不可用时返回None

Bug修正：
  #1 返回dict而非ConfidenceData dataclass（与ai_analysis模式一致）
  #2 async方法，内部用await llm.ainvoke()，不阻塞事件循环
  #7 RAG未就绪时retrieve_mlps_context内部已含降级
"""
import json
import re
import logging
import asyncio
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)


class ConfidenceAssessor:
    """AI等保评估置信度评估器

    基于等保2.0三级标准，综合漏洞扫描结果与知识库内容，
    通过结构化提示词让LLM产出多维度置信度评估数据。
    """

    def __init__(self):
        from TOSKill.config import settings
        self.timeout = getattr(settings, "CONFIDENCE_AI_TIMEOUT", 20.0)
        self.enabled = getattr(settings, "CONFIDENCE_ASSESSMENT_ENABLED", True)
        self.mlps_level = getattr(settings, "MLPS_STANDARD_LEVEL", "三级")

    async def assess_async(
        self,
        vulnerabilities: List[Dict[str, Any]],
        tool_results: Dict[str, Any],
        target: str,
        scan_mode: str = "人机交互"
    ) -> Optional[Dict[str, Any]]:
        """异步评估置信度，返回dict

        【修正Bug#1】返回dict而非ConfidenceData dataclass
        【修正Bug#2】async方法，内部用await llm.ainvoke()

        Args:
            vulnerabilities: 漏洞列表
            tool_results: 工具执行结果
            target: 扫描目标URL
            scan_mode: 扫描模式（人机交互/全自动/单工具）

        Returns:
            dict: 置信度数据，失败时返回None
        """
        if not self.enabled:
            logger.info("置信度评估已禁用，跳过")
            return None

        if not vulnerabilities:
            logger.info(f"无漏洞数据，跳过置信度评估 (vulns={len(vulnerabilities)})")
            return None

        logger.info(f"[置信度] 开始评估: {len(vulnerabilities)}个漏洞, {len(tool_results)}个工具, 超时={self.timeout}s")
        try:
            result = await asyncio.wait_for(
                self._assess_inner(vulnerabilities, tool_results, target, scan_mode),
                timeout=self.timeout
            )
            logger.info(f"[置信度] 评估成功: score={result.get('overall_score', 0)}")
            return result
        except asyncio.TimeoutError:
            logger.warning(f"[置信度] 评估超时（{self.timeout}s），降级为占位")
            return None
        except Exception as e:
            logger.error(f"[置信度] 评估异常: {e}", exc_info=True)
            return None

    async def _assess_inner(
        self,
        vulnerabilities: List[Dict[str, Any]],
        tool_results: Dict[str, Any],
        target: str,
        scan_mode: str
    ) -> Dict[str, Any]:
        """内部评估逻辑：RAG检索 → LLM评估 → JSON解析"""
        # 1. RAG检索等保上下文
        logger.info("[置信度] 步骤1/4: RAG检索等保上下文...")
        mlps_context = self._get_mlps_context(target, vulnerabilities, tool_results)
        confidence_rules = self._get_confidence_rules()
        kb_version = self._get_kb_version()
        logger.info(f"[置信度] RAG完成: mlps={len(mlps_context)}字符, rules={len(confidence_rules)}字符, version={kb_version}")

        # 2. 构建结构化提示词
        logger.info("[置信度] 步骤2/4: 构建提示词...")
        prompt = self._build_prompt(
            vulnerabilities, tool_results, target, scan_mode,
            mlps_context, confidence_rules
        )
        logger.info(f"[置信度] 提示词长度: {len(prompt)}字符")

        # 3. 调用LLM（异步，与_generate_ai_report_async模式一致）
        logger.info("[置信度] 步骤3/4: 调用LLM评估...")
        from TOSKill.tools.report.report_manager import _get_llm
        llm = _get_llm()
        response = await llm.ainvoke(prompt)
        raw_text = response.content
        logger.info(f"[置信度] LLM响应: {len(raw_text)}字符, 前100: {raw_text[:100]}")

        # 4. 解析JSON（修正缺陷#2：三级健壮解析）
        logger.info("[置信度] 步骤4/4: 解析JSON...")
        confidence_dict = self._parse_confidence_json(raw_text)
        logger.info(f"[置信度] JSON解析: score={confidence_dict.get('overall_score')}, level={confidence_dict.get('level')}")

        # 5. 补充元数据
        confidence_dict["kb_version"] = kb_version
        confidence_dict["scan_mode"] = scan_mode

        logger.info(
            f"[置信度] 评估完成: {confidence_dict.get('overall_score', 0):.0f}% "
            f"({confidence_dict.get('level', 'info')})"
        )
        return confidence_dict

    # ==================== RAG检索辅助 ====================

    def _get_mlps_context(
        self,
        target: str,
        vulnerabilities: List[Dict[str, Any]],
        tool_results: Dict[str, Any]
    ) -> str:
        """获取RAG等保上下文"""
        try:
            from TOSKill.RAG.retriever import get_mlps_assessment_context
            return get_mlps_assessment_context(target, vulnerabilities, tool_results)
        except Exception as e:
            logger.warning(f"RAG等保上下文检索失败: {e}")
            return ""

    def _get_confidence_rules(self) -> str:
        """获取置信度评判规则"""
        try:
            from TOSKill.RAG.retriever import get_confidence_rules
            return get_confidence_rules()
        except Exception as e:
            logger.warning(f"置信度规则检索失败: {e}")
            return ""

    def _get_kb_version(self) -> str:
        """获取知识库版本"""
        try:
            from TOSKill.RAG.retriever import get_kb_version
            return get_kb_version()
        except Exception:
            return ""

    # ==================== 提示词构建 ====================

    def _build_prompt(
        self,
        vulnerabilities: List[Dict[str, Any]],
        tool_results: Dict[str, Any],
        target: str,
        scan_mode: str,
        mlps_context: str,
        confidence_rules: str
    ) -> str:
        """构建结构化等级分类提示词"""
        vuln_summary = self._summarize_vulnerabilities(vulnerabilities)
        tool_summary = self._summarize_tools(tool_results)
        severity_count = self._count_severity(vulnerabilities)

        return f"""你是等保2.0{self.mlps_level}评估专家和资深渗透测试工程师。

## 评估任务
基于以下扫描结果，参照等保2.0（GB/T 22239-2019）{self.mlps_level}标准，评估本次安全评估的置信度。

## 扫描信息
- 目标: {target}
- 扫描模式: {scan_mode}
- 工具数量: {len(tool_results)}
- 漏洞总数: {len(vulnerabilities)}
- 严重: {severity_count['critical']} | 高危: {severity_count['high']} | 中危: {severity_count['medium']} | 低危: {severity_count['low']} | 信息: {severity_count['info']}

## 漏洞清单
{vuln_summary}

## 工具执行摘要
{tool_summary}

## 等保知识库参考
{mlps_context or '（知识库检索无结果）'}

## 置信度评判规则
{confidence_rules or '（规则检索无结果，请参照以下标准）'}

## 评估维度（每项0-100分）
1. 漏洞检测准确性（权重30%）：工具覆盖度、交叉验证、证据充分性
2. 等保控制项映射准确度（权重25%）：漏洞→等保条款语义匹配度、RAG检索相似度
3. 风险等级判定一致性（权重25%）：与标准等级偏差、CVSS一致性
4. 整改方案合规性（权重20%）：修复建议对等保条款针对性、可操作性

## 等级标准
- >=80 高置信度(high) | 60-79 中置信度(mid) | <60 低置信度(low)

## 输出要求
严格输出以下JSON格式，不要包含markdown代码块或其他文字：
{{"overall_score": 87, "level": "high", "standard_text": "基于等保2.0三级标准", "dimensions": [{{"label": "漏洞检测准确性", "value": 92}}, {{"label": "等保控制项映射准确度", "value": 88}}, {{"label": "风险等级判定一致性", "value": 85}}, {{"label": "整改方案合规性", "value": 82}}], "compliance_estimate": 72, "compliance_margin": "±5%", "kb_refs": "15_mlps_standard,16_mlps_vuln_mapping", "note": "评估说明文字"}}"""

    # ==================== 数据摘要辅助 ====================

    @staticmethod
    def _summarize_vulnerabilities(vulns: List[Dict[str, Any]]) -> str:
        lines = []
        for v in vulns[:10]:
            sev = v.get("severity", "unknown")
            vtype = v.get("type") or v.get("vuln_type", "unknown")
            url = v.get("url") or v.get("target", "")
            lines.append(f"- [{sev}] {vtype} @ {url}")
        if len(vulns) > 10:
            lines.append(f"... 共{len(vulns)}个漏洞")
        return "\n".join(lines) if lines else "无"

    @staticmethod
    def _summarize_tools(tool_results: Dict[str, Any]) -> str:
        lines = []
        for tool, result in list(tool_results.items())[:10]:
            if isinstance(result, dict):
                status = "发现漏洞" if result.get("vulnerable") else "正常"
                lines.append(f"- {tool}: {status}")
            else:
                lines.append(f"- {tool}: 已完成")
        return "\n".join(lines) if lines else "无"

    @staticmethod
    def _count_severity(vulns: List[Dict[str, Any]]) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in vulns:
            sev = str(v.get("severity", "info")).lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    # ==================== JSON解析（修正缺陷#2） ====================

    @staticmethod
    def _parse_confidence_json(raw_text: str) -> Dict[str, Any]:
        """三级健壮JSON解析：strip markdown → raw_decode → 贪婪正则 → 默认值"""
        text = raw_text.strip()

        # 1. 去除markdown代码块
        if text.startswith("```"):
            text = re.sub(r'^```(?:json)?\s*', '', text)
            text = re.sub(r'\s*```$', '', text)

        # 2. 尝试直接解析
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # 3. 精确提取首个完整JSON对象（raw_decode）
        try:
            decoder = json.JSONDecoder()
            match = re.search(r'\{', text)
            if match:
                start = match.start()
                obj, _ = decoder.raw_decode(text[start:])
                return obj
        except (json.JSONDecodeError, ValueError):
            pass

        # 4. 贪婪正则兜底
        match = re.search(r'\{[\s\S]*\}', text)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass

        # 5. 全部失败，返回默认值
        logger.warning("LLM输出JSON解析失败，返回默认置信度")
        return {
            "overall_score": 0,
            "level": "info",
            "standard_text": "基于等保2.0（GB/T 22239-2019）三级标准",
            "dimensions": [],
            "compliance_estimate": 0,
            "compliance_margin": "",
            "kb_refs": "",
            "note": "置信度评估结果解析失败，请人工复核",
        }


# 模块级单例
confidence_assessor = ConfidenceAssessor()


def get_confidence_assessor() -> ConfidenceAssessor:
    """获取置信度评估器单例"""
    return confidence_assessor
