# -*- coding:utf-8 -*-
"""
AI 等保评估置信度计算模块

基于四个加权维度计算 0-100% 的综合置信度评分：
    - 知识库匹配度 (kb_match)            权重 60%
    - 测评覆盖率 (coverage)              权重 20%
    - 历史上下文一致性 (consistency)      权重 10%
    - 参数完整性 (completeness)          权重 10%

该模块为 Task 4 实现，供报告生成 / AI 评估流程调用，
所有函数均做了健壮性处理，输入异常时不会抛出异常。
"""

import logging
import math
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# =====================================================================
# 主入口函数
# =====================================================================
def calculate_confidence(
    state: Dict[str, Any],
    vulnerabilities: List[Dict[str, Any]],
    rag_result: Optional[str] = None,
) -> Dict[str, Any]:
    """
    计算 AI 等保评估的综合置信度评分。

    综合分 = kb_match * 0.6 + coverage * 0.2 + consistency * 0.1 + completeness * 0.1

    Args:
        state: 扫描状态字典 (ScanState)，包含 completed_tasks / planned_tasks /
               decision_history / execution_history / mode 等字段。
        vulnerabilities: 漏洞列表，每个元素为字典，包含 type / severity /
                         url / description 等字段。
        rag_result: RAG 检索返回的知识库建议文本，可为 None。

    Returns:
        Dict: {
            "total": int,          # 0-100 综合分
            "breakdown": {
                "kb_match": int,        # 0-100
                "coverage": int,        # 0-100
                "consistency": int,     # 0-100
                "completeness": int     # 0-100
            }
        }
    """
    # 兜底默认返回值，保证任何异常情况下都不抛出
    fallback = {
        "total": 0,
        "breakdown": {
            "kb_match": 0,
            "coverage": 0,
            "consistency": 0,
            "completeness": 0,
        },
    }

    try:
        # 1. 知识库匹配度 (60%)
        kb_match = _compute_kb_match(rag_result)

        # 2. 测评覆盖率 (20%)
        coverage = calculate_coverage_score(state)

        # 3. 历史上下文一致性 (10%)
        consistency = calculate_consistency_score(state)

        # 4. 参数完整性 (10%)
        completeness = calculate_completeness_score(vulnerabilities)

        # 加权汇总
        total = int(
            kb_match * 0.6
            + coverage * 0.2
            + consistency * 0.1
            + completeness * 0.1
        )
        total = max(0, min(100, total))

        result = {
            "total": total,
            "breakdown": {
                "kb_match": kb_match,
                "coverage": coverage,
                "consistency": consistency,
                "completeness": completeness,
            },
        }

        logger.info(
            "置信度计算完成: total=%d, kb_match=%d, coverage=%d, "
            "consistency=%d, completeness=%d",
            total, kb_match, coverage, consistency, completeness,
        )
        return result

    except Exception as exc:  # noqa: BLE001 - 模块要求永不抛出异常
        logger.exception("置信度计算发生异常，返回兜底结果: %s", exc)
        return fallback


# =====================================================================
# 知识库匹配度 (kb_match) —— 权重 60%
# =====================================================================
def _compute_kb_match(rag_result: Optional[str]) -> int:
    """
    计算知识库匹配度子分 (0-100)。

    逻辑：
        - 若 rag_result 为空 / None → 50 (中性)
        - 若 rag_result 长度 > 100 → 优先调用 TOSKill.RAG.retriever.get_kb_match_score
          (若该函数存在)，否则使用本地 calculate_kb_match_score 估算
        - 若 rag_result 长度 <= 100 → 交由本地估算函数处理 (通常趋近中性)

    Args:
        rag_result: RAG 检索结果文本。

    Returns:
        int: 0-100 的知识库匹配度评分。
    """
    try:
        # 无 RAG 结果 → 中性分
        if rag_result is None:
            return 50

        if not isinstance(rag_result, str):
            rag_result = str(rag_result) if rag_result else ""

        # 空字符串同样视为中性
        if len(rag_result) == 0:
            return 50

        # 长度大于阈值时，优先尝试调用 RAG 检索器提供的专业打分函数
        if len(rag_result) > 100:
            try:
                from TOSKill.RAG.retriever import get_kb_match_score  # type: ignore
                score = get_kb_match_score(rag_result)
                if score is not None:
                    score = int(score)
                    return max(0, min(100, score))
            except ImportError:
                logger.debug("TOSKill.RAG.retriever.get_kb_match_score 不可用，使用本地估算")
            except Exception as exc:  # noqa: BLE001
                logger.warning("调用 get_kb_match_score 失败，回退本地估算: %s", exc)

        # 本地估算
        return calculate_kb_match_score(rag_result)

    except Exception as exc:  # noqa: BLE001
        logger.exception("知识库匹配度计算异常，返回中性分: %s", exc)
        return 50


def calculate_kb_match_score(rag_result: Optional[str]) -> int:
    """
    基于 RAG 结果的相关性估算知识库匹配度 (0-100)。

    估算策略 (以长度作为内容丰富度的代理指标，结合关键词相关性加分)：
        - 长度 < 100  → 中性分 50 (内容过短，无法判定)
        - 长度 >= 100 → 基础分 60 起步，按对数缩放最高至 ~70
        - 含来源标记 ("来源"/"source") → +15
        - 含专业关键词 (建议/策略/扫描/漏洞/检测) → +15

    Args:
        rag_result: RAG 检索结果文本。

    Returns:
        int: 0-100 的知识库匹配度评分。
    """
    try:
        if not rag_result:
            return 50

        if not isinstance(rag_result, str):
            rag_result = str(rag_result)

        length = len(rag_result)

        # 内容过短 → 中性
        if length < 100:
            return 50

        # 基础分：对数缩放
        # length=100  → 60 ; length=500  → ~77.5 ; length=2000 → ~95 ; length>=5000 → ~100
        length_score = 60 + math.log10(length / 100.0) * 25
        length_score = min(70.0, length_score)

        # 相关性加分
        relevance_bonus = 0
        lowered = rag_result.lower()
        if ("来源" in rag_result) or ("source" in lowered):
            relevance_bonus += 15
        if any(kw in rag_result for kw in ("建议", "策略", "扫描", "漏洞", "检测")):
            relevance_bonus += 15

        score = length_score + relevance_bonus
        score = max(0, min(100, score))
        return int(round(score))

    except Exception as exc:  # noqa: BLE001
        logger.exception("本地知识库匹配度估算异常，返回中性分: %s", exc)
        return 50


# =====================================================================
# 测评覆盖率 (coverage) —— 权重 20%
# =====================================================================
def calculate_coverage_score(state: Optional[Dict[str, Any]]) -> int:
    """
    计算测评覆盖率子分 (0-100)。

    逻辑：
        - 从 state 读取 completed_tasks 与 planned_tasks。
        - 若 planned_tasks 非空：score = len(completed) / max(len(planned), 1) * 100
        - 若 planned_tasks 为空：使用 graph.py 的 TOOL_MAPPING_MATRIX 根据 mode
          估算预期工具数量作为分母。
        - 结果截断在 0-100。

    Args:
        state: 扫描状态字典。

    Returns:
        int: 0-100 的测评覆盖率评分。
    """
    try:
        if not state or not isinstance(state, dict):
            return 0

        completed = state.get("completed_tasks", []) or []
        planned = state.get("planned_tasks", []) or []

        # 保证为 list
        if not isinstance(completed, list):
            completed = list(completed) if completed else []
        if not isinstance(planned, list):
            planned = list(planned) if planned else []

        if planned:
            denominator = max(len(planned), 1)
            score = len(completed) / denominator * 100
        else:
            # 无计划任务 → 用 TOOL_MAPPING_MATRIX 估算预期工具数
            expected = _estimate_expected_tool_count(state)
            if expected > 0:
                score = len(completed) / expected * 100
            else:
                # 既无计划任务也无法估算预期工具
                # 无任何已完成任务 → 0；否则视为全部覆盖
                score = 100.0 if completed else 0.0

        score = max(0, min(100, score))
        return int(round(score))

    except Exception as exc:  # noqa: BLE001
        logger.exception("测评覆盖率计算异常，返回 0: %s", exc)
        return 0


def _estimate_expected_tool_count(state: Dict[str, Any]) -> int:
    """
    根据 state 的 mode 字段，从 graph.py 的 TOOL_MAPPING_MATRIX 估算预期工具数量。

    mode 与矩阵 key 的映射关系：
        - "full_scan" / "full"      → "full"
        - "vuln_scan" / "deep"      → "deep"
        - "info_collection" / "fast" → "fast"

    若 mode 无法匹配任何 key，则取矩阵中工具数最多的集合作为保守估计。

    Args:
        state: 扫描状态字典。

    Returns:
        int: 预期工具数量；无法获取矩阵时返回 0。
    """
    try:
        # 懒加载导入 graph.py (该模块较大，避免顶层导入带来的副作用)
        tool_mapping_matrix: Dict[str, List[str]] = {}
        try:
            from TOSKill.AI.graph import TOOL_MAPPING_MATRIX  # type: ignore
            tool_mapping_matrix = TOOL_MAPPING_MATRIX or {}
        except Exception as exc:  # noqa: BLE001
            logger.debug("无法从 TOSKill.AI.graph 导入 TOOL_MAPPING_MATRIX: %s", exc)
            try:
                from ..AI.graph import TOOL_MAPPING_MATRIX  # type: ignore
                tool_mapping_matrix = TOOL_MAPPING_MATRIX or {}
            except Exception as exc2:  # noqa: BLE001
                logger.debug("相对导入 TOOL_MAPPING_MATRIX 也失败: %s", exc2)
                return 0

        if not tool_mapping_matrix:
            return 0

        mode = (state.get("mode", "") or "") if isinstance(state, dict) else ""
        key = _map_mode_to_matrix_key(mode)

        tools = tool_mapping_matrix.get(key)
        if not tools:
            # 取工具数最多的集合作为保守估计
            try:
                tools = max(tool_mapping_matrix.values(), key=len)
            except Exception:  # noqa: BLE001
                tools = []

        return len(tools) if tools else 0

    except Exception as exc:  # noqa: BLE001
        logger.exception("估算预期工具数量异常: %s", exc)
        return 0


def _map_mode_to_matrix_key(mode: str) -> str:
    """
    将 state 中的 mode 字段映射为 TOOL_MAPPING_MATRIX 的 key。

    Args:
        mode: 扫描模式字符串。

    Returns:
        str: 矩阵 key ("fast" / "deep" / "full")，无法识别时返回空串。
    """
    if not mode or not isinstance(mode, str):
        return ""
    mode_lower = mode.lower().strip()

    mapping = {
        "full_scan": "full",
        "full": "full",
        "vuln_scan": "deep",
        "deep": "deep",
        "info_collection": "fast",
        "fast": "fast",
    }
    return mapping.get(mode_lower, "")


# =====================================================================
# 历史上下文一致性 (consistency) —— 权重 10%
# =====================================================================
def calculate_consistency_score(state: Optional[Dict[str, Any]]) -> int:
    """
    计算历史上下文一致性子分 (0-100)。

    逻辑：
        - 从 state 读取 decision_history (决策历史)。
        - 若无决策历史 → 70 (默认中性偏正)。
        - 统计 execution_history 中 success == True 的条目数作为成功决策数。
        - score = successful_decisions / max(total_decisions, 1) * 100
        - 结果截断在 0-100。

    Args:
        state: 扫描状态字典。

    Returns:
        int: 0-100 的历史上下文一致性评分。
    """
    try:
        if not state or not isinstance(state, dict):
            return 70

        decision_history = state.get("decision_history", []) or []
        if not isinstance(decision_history, list):
            decision_history = list(decision_history) if decision_history else []

        # 无决策历史 → 中性偏正
        if not decision_history:
            return 70

        total_decisions = len(decision_history)

        # 从执行历史中统计成功结果
        execution_history = state.get("execution_history", []) or []
        if not isinstance(execution_history, list):
            execution_history = list(execution_history) if execution_history else []

        successful_decisions = 0
        for entry in execution_history:
            try:
                if isinstance(entry, dict) and entry.get("success") is True:
                    successful_decisions += 1
            except Exception:  # noqa: BLE001
                continue

        score = successful_decisions / max(total_decisions, 1) * 100
        score = max(0, min(100, score))
        return int(round(score))

    except Exception as exc:  # noqa: BLE001
        logger.exception("历史上下文一致性计算异常，返回中性分: %s", exc)
        return 70


# =====================================================================
# 参数完整性 (completeness) —— 权重 10%
# =====================================================================
def calculate_completeness_score(vulnerabilities: Optional[List[Dict[str, Any]]]) -> int:
    """
    计算参数完整性子分 (0-100)。

    逻辑：
        - 对每个漏洞字典检查 4 组必填字段是否齐全：
            1) type 或 vuln_type
            2) severity
            3) url 或 target
            4) description
        - 每组只要存在任一可替换键且值非空即视为已填写。
        - score = 已填写字段数 / 总必填字段数 * 100
        - 若无漏洞 → 100 (无需评估即视为完整)。

    Args:
        vulnerabilities: 漏洞列表。

    Returns:
        int: 0-100 的参数完整性评分。
    """
    try:
        # 无漏洞 → 完整
        if not vulnerabilities:
            return 100

        if not isinstance(vulnerabilities, list):
            vulnerabilities = list(vulnerabilities) if vulnerabilities else []
            if not vulnerabilities:
                return 100

        # 每个漏洞的必填字段组 (组内任一键存在且非空即算填写)
        required_field_groups = [
            ("type", "vuln_type"),
            ("severity",),
            ("url", "target"),
            ("description",),
        ]
        total_required = len(required_field_groups) * len(vulnerabilities)
        if total_required == 0:
            return 100

        filled_fields = 0
        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                # 非字典条目视为全部缺失
                continue
            for group in required_field_groups:
                for key in group:
                    value = vuln.get(key)
                    if value is not None and str(value).strip() != "":
                        filled_fields += 1
                        break  # 该组已满足，进入下一组

        score = filled_fields / total_required * 100
        score = max(0, min(100, score))
        return int(round(score))

    except Exception as exc:  # noqa: BLE001
        logger.exception("参数完整性计算异常，返回 0: %s", exc)
        return 0


__all__ = [
    "calculate_confidence",
    "calculate_kb_match_score",
    "calculate_coverage_score",
    "calculate_consistency_score",
    "calculate_completeness_score",
]
