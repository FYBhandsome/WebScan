# -*- coding:utf-8 -*-
"""
漏洞分析器工具

使用@tool装饰器封装漏洞去重、排序和严重度评估功能。
"""

from langchain.tools import tool
from typing import Dict, Any, List, Optional
import logging
import json

logger = logging.getLogger(__name__)

SEVERITY_ORDER: Dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0
}

CVSS_SCORE_MAP: Dict[str, float] = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 5.0,
    "low": 3.0,
    "info": 1.0
}

ENABLE_KB_INTEGRATION: bool = True


def estimate_cvss(vulnerability: Dict[str, Any]) -> Dict[str, Any]:
    """估算CVSS评分 (FALLBACK - 仅在置信度计算模块不可用时使用)

    注意: 该函数使用硬编码的 CVSS_SCORE_MAP 进行评分估算。
    主流程现已优先使用 confidence_calculator 模块计算置信度，
    本函数仅作为 CVSS 评分的回退方案保留。

    Args:
        vulnerability: 漏洞数据

    Returns:
        Dict: 包含cvss_score, cvss_vector, cvss_severity的字典
    """
    severity = str(vulnerability.get("severity", "info")).lower()
    base_score = CVSS_SCORE_MAP.get(severity, 1.0)

    vuln_type = str(vulnerability.get("type") or vulnerability.get("vuln_type", "")).lower()
    has_payload = bool(vulnerability.get("payload"))
    has_evidence = bool(vulnerability.get("evidence"))
    description = str(vulnerability.get("description", "")).lower()

    if "rce" in vuln_type or "command" in vuln_type:
        base_score = max(base_score, 9.8)
    elif "sqli" in vuln_type or "sql" in vuln_type:
        base_score = max(base_score, 8.5)
    elif "xss" in vuln_type:
        base_score = max(base_score, 6.1)
    elif "lfi" in vuln_type or "file" in vuln_type:
        base_score = max(base_score, 7.5)
    elif "ssrf" in vuln_type:
        base_score = max(base_score, 7.0)
    elif "csrf" in vuln_type:
        base_score = max(base_score, 6.5)
    elif "upload" in vuln_type:
        base_score = max(base_score, 8.0)
    elif "weakpass" in vuln_type or "weak" in vuln_type:
        base_score = max(base_score, 7.0)

    if has_payload and has_evidence:
        base_score = min(base_score + 0.5, 10.0)

    if "public" in description or "exploit" in description:
        base_score = min(base_score + 0.3, 10.0)

    score = round(base_score, 1)

    if score >= 9.0:
        cvss_severity = "CRITICAL"
    elif score >= 7.0:
        cvss_severity = "HIGH"
    elif score >= 4.0:
        cvss_severity = "MEDIUM"
    else:
        cvss_severity = "LOW"

    cvss_vector = f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" if score >= 9.0 else \
                  f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" if score >= 7.0 else \
                  f"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N" if score >= 4.0 else \
                  f"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N"

    return {
        "cvss_score": score,
        "cvss_vector": cvss_vector,
        "cvss_severity": cvss_severity
    }


def deduplicate_vulnerabilities(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """漏洞去重

    基于漏洞类型和目标URL的组合进行去重。
    当同一URL存在不同类型漏洞时不合并，保留所有记录。

    Args:
        vulnerabilities: 漏洞列表

    Returns:
        List[Dict]: 去重后的漏洞列表
    """
    if not vulnerabilities:
        return []

    seen = set()
    deduped = []

    for vuln in vulnerabilities:
        vuln_type = str(vuln.get("type") or vuln.get("vuln_type", ""))
        url = str(vuln.get("url", ""))
        param = str(vuln.get("parameter", ""))
        dedup_key = f"{vuln_type}|{url}|{param}"

        if dedup_key not in seen:
            seen.add(dedup_key)
            deduped.append(vuln)

    removed = len(vulnerabilities) - len(deduped)
    if removed > 0:
        logger.info(f"漏洞去重完成: {len(vulnerabilities)} -> {len(deduped)} (移除 {removed} 个重复)")

    return deduped


def sort_by_severity(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """按严重度排序漏洞
    
    Args:
        vulnerabilities: 漏洞列表
        
    Returns:
        List[Dict]: 排序后的漏洞列表
    """
    sorted_vulns = sorted(
        vulnerabilities,
        key=lambda x: SEVERITY_ORDER.get(
            str(x.get("severity", "info")).lower(),
            0
        ),
        reverse=True
    )
    
    return sorted_vulns


def analyze_vulnerability_stats(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
    """分析漏洞列表
    
    生成漏洞统计信息。
    
    Args:
        vulnerabilities: 漏洞列表
        
    Returns:
        Dict: 分析结果,包含统计信息
    """
    if not vulnerabilities:
        return {
            "total": 0,
            "by_severity": {},
            "summary": "未发现漏洞"
        }
    
    severity_stats = {}
    for vuln in vulnerabilities:
        severity = str(vuln.get("severity", "info")).lower()
        severity_stats[severity] = severity_stats.get(severity, 0) + 1
    
    summary_parts = []
    for severity in ["critical", "high", "medium", "low", "info"]:
        count = severity_stats.get(severity, 0)
        if count > 0:
            summary_parts.append(f"{severity.capitalize()}: {count}")
    
    summary = f"共发现 {len(vulnerabilities)} 个漏洞: " + ", ".join(summary_parts)
    
    return {
        "total": len(vulnerabilities),
        "by_severity": severity_stats,
        "summary": summary
    }


async def _get_kb_info(cve: str) -> Dict[str, Any]:
    """从知识库获取漏洞信息
    
    Args:
        cve: CVE编号
        
    Returns:
        Dict: 知识库信息
    """
    try:
        from backend.models import VulnerabilityKB
        kb_entry = await VulnerabilityKB.get_or_none(cve_id=cve)
        if kb_entry:
            return {
                "name": kb_entry.name,
                "description": kb_entry.description,
                "solution": kb_entry.solution,
                "cvss_score": kb_entry.cvss_score,
                "references": kb_entry.references
            }
    except Exception as e:
        logger.error(f"查询知识库失败: {str(e)}")
    
    return {}


async def enrich_with_kb(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """使用知识库丰富漏洞信息
    
    Args:
        vulnerabilities: 漏洞列表
        
    Returns:
        List[Dict]: 丰富后的漏洞列表
    """
    if not ENABLE_KB_INTEGRATION:
        return vulnerabilities
    
    enriched = []
    
    for vuln in vulnerabilities:
        cve = vuln.get("cve", "")
        if cve:
            kb_info = await _get_kb_info(cve)
            if kb_info:
                vuln["kb_info"] = kb_info
                if kb_info.get("solution"):
                    vuln["fix_suggestion"] = kb_info["solution"]
        enriched.append(vuln)
    
    return enriched


@tool
def vuln_analyzer(
    vulnerabilities: List[Dict[str, Any]],
    enable_dedup: bool = False,
    enable_sort: bool = True,
    enable_kb: bool = True
) -> Dict[str, Any]:
    """漏洞分析器工具，对漏洞列表进行去重、排序和统计分析
    
    提供漏洞分析功能：
    - 漏洞去重（可选，默认禁用）
    - 按严重度排序
    - 统计分析（按严重度分类统计）
    - 知识库信息丰富（可选）
    
    Args:
        vulnerabilities: 漏洞列表，每个漏洞包含severity、vuln_type、target等字段
        enable_dedup: 是否启用去重，默认False（禁用去重）
        enable_sort: 是否启用排序，默认True
        enable_kb: 是否启用知识库丰富，默认True
        
    Returns:
        包含分析结果的字典，包括：
        - success: 执行状态(True/False)
        - data: 分析结果数据
        - error: 错误信息(成功时为None)
        - metadata: 元数据(工具名称、漏洞总数、统计信息等)
    """
    try:
        logger.info(f"开始漏洞分析...")
        logger.info(f"输入漏洞数量: {len(vulnerabilities)}")
        
        processed_vulns = vulnerabilities.copy()
        
        if enable_dedup:
            processed_vulns = deduplicate_vulnerabilities(processed_vulns)
            logger.info(f"去重后漏洞数量: {len(processed_vulns)}")
        
        if enable_sort:
            processed_vulns = sort_by_severity(processed_vulns)
            logger.info("已按严重度排序")

        # FALLBACK: estimate_cvss 使用硬编码 CVSS_SCORE_MAP，仅作为 CVSS 评分的回退方案
        # 主流程的置信度计算已由 confidence_calculator 模块接管 (见下方)
        for vuln in processed_vulns:
            if "cvss_score" not in vuln:
                cvss_info = estimate_cvss(vuln)
                vuln["cvss_score"] = cvss_info["cvss_score"]
                vuln["cvss_vector"] = cvss_info["cvss_vector"]
                vuln["cvss_severity"] = cvss_info["cvss_severity"]

        # Task 6.1: 使用 confidence_calculator 模块计算综合置信度
        confidence = None
        try:
            from TOSKill.tools.report.confidence_calculator import calculate_confidence
            state = {
                "completed_tasks": [],
                "planned_tasks": [],
                "execution_history": [],
                "decision_history": [],
                "mode": "full_scan"
            }
            confidence = calculate_confidence(state, processed_vulns, None)
        except Exception as e:
            logger.debug(f"置信度计算失败，回退到 estimate_cvss: {e}")
            confidence = None

        stats = analyze_vulnerability_stats(processed_vulns)
        logger.info(f"统计结果: {stats['summary']}")

        return {
            "success": True,
            "data": {
                "vulnerabilities": processed_vulns,
                "statistics": stats
            },
            "error": "",
            "metadata": {
                "tool": "vuln_analyzer",
                "total_count": len(processed_vulns),
                "original_count": len(vulnerabilities),
                "dedup_enabled": enable_dedup,
                "sort_enabled": enable_sort,
                "kb_enabled": enable_kb,
                "severity_distribution": stats["by_severity"],
                "confidence": confidence
            }
        }
    except Exception as e:
        logger.error(f"漏洞分析执行失败: {str(e)}")
        return {
            "success": False,
            "data": {},
            "error": f"漏洞分析执行异常: {str(e)}",
            "metadata": {
                "tool": "vuln_analyzer",
                "input_count": len(vulnerabilities) if vulnerabilities else 0
            }
        }


@tool
async def vuln_analyzer_async(
    vulnerabilities: List[Dict[str, Any]],
    enable_dedup: bool = False,
    enable_sort: bool = True,
    enable_kb: bool = True
) -> Dict[str, Any]:
    """异步漏洞分析器工具，支持知识库查询
    
    提供漏洞分析功能（异步版本）：
    - 漏洞去重（可选，默认禁用）
    - 按严重度排序
    - 统计分析（按严重度分类统计）
    - 知识库信息丰富（异步查询）
    
    Args:
        vulnerabilities: 漏洞列表，每个漏洞包含severity、vuln_type、target、cve等字段
        enable_dedup: 是否启用去重，默认False（禁用去重）
        enable_sort: 是否启用排序，默认True
        enable_kb: 是否启用知识库丰富，默认True
        
    Returns:
        包含分析结果的字典，包括：
        - success: 执行状态(True/False)
        - data: 分析结果数据
        - error: 错误信息(成功时为None)
        - metadata: 元数据(工具名称、漏洞总数、统计信息等)
    """
    try:
        logger.info(f"开始异步漏洞分析...")
        logger.info(f"输入漏洞数量: {len(vulnerabilities)}")
        
        processed_vulns = vulnerabilities.copy()
        
        if enable_dedup:
            processed_vulns = deduplicate_vulnerabilities(processed_vulns)
            logger.info(f"去重后漏洞数量: {len(processed_vulns)}")
        
        if enable_sort:
            processed_vulns = sort_by_severity(processed_vulns)
            logger.info("已按严重度排序")

        # FALLBACK: estimate_cvss 使用硬编码 CVSS_SCORE_MAP，仅作为 CVSS 评分的回退方案
        # 主流程的置信度计算已由 confidence_calculator 模块接管 (见下方)
        for vuln in processed_vulns:
            if "cvss_score" not in vuln:
                cvss_info = estimate_cvss(vuln)
                vuln["cvss_score"] = cvss_info["cvss_score"]
                vuln["cvss_vector"] = cvss_info["cvss_vector"]
                vuln["cvss_severity"] = cvss_info["cvss_severity"]

        if enable_kb and ENABLE_KB_INTEGRATION:
            processed_vulns = await enrich_with_kb(processed_vulns)
            logger.info("已完成知识库信息丰富")

        # Task 6.1: 使用 confidence_calculator 模块计算综合置信度
        confidence = None
        try:
            from TOSKill.tools.report.confidence_calculator import calculate_confidence
            state = {
                "completed_tasks": [],
                "planned_tasks": [],
                "execution_history": [],
                "decision_history": [],
                "mode": "full_scan"
            }
            confidence = calculate_confidence(state, processed_vulns, None)
        except Exception as e:
            logger.debug(f"置信度计算失败，回退到 estimate_cvss: {e}")
            confidence = None

        stats = analyze_vulnerability_stats(processed_vulns)
        logger.info(f"统计结果: {stats['summary']}")

        return {
            "success": True,
            "data": {
                "vulnerabilities": processed_vulns,
                "statistics": stats
            },
            "error": "",
            "metadata": {
                "tool": "vuln_analyzer_async",
                "total_count": len(processed_vulns),
                "original_count": len(vulnerabilities),
                "dedup_enabled": enable_dedup,
                "sort_enabled": enable_sort,
                "kb_enabled": enable_kb,
                "severity_distribution": stats["by_severity"],
                "confidence": confidence
            }
        }
    except Exception as e:
        logger.error(f"异步漏洞分析执行失败: {str(e)}")
        return {
            "success": False,
            "data": {},
            "error": f"异步漏洞分析执行异常: {str(e)}",
            "metadata": {
                "tool": "vuln_analyzer_async",
                "input_count": len(vulnerabilities) if vulnerabilities else 0
            }
        }


if __name__ == "__main__":
    test_vulns = [
        {"id": "1", "vuln_type": "sqli", "severity": "high", "target": "http://example.com/test?id=1"},
        {"id": "2", "vuln_type": "xss", "severity": "medium", "target": "http://example.com/search?q=test"},
        {"id": "3", "vuln_type": "rce", "severity": "critical", "target": "http://example.com/cmd"},
    ]
    
    result = vuln_analyzer.invoke({
        "vulnerabilities": test_vulns,
        "enable_dedup": False,
        "enable_sort": True,
        "enable_kb": False
    })
    print(json.dumps(result, indent=2, ensure_ascii=False))
