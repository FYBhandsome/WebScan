# -*- coding:utf-8 -*-
"""
漏洞分析器工具

使用@tool装饰器封装漏洞去重、排序和严重度评估功能。
"""

from langchain.tools import tool
from typing import Dict, Any, List, Optional
import logging
import json
import asyncio

logger = logging.getLogger(__name__)

SEVERITY_ORDER: Dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0
}

ENABLE_KB_INTEGRATION: bool = True


def deduplicate_vulnerabilities(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """漏洞去重 (已禁用)
    
    根据CVE和目标组合去重。
    当前配置：禁用去重，直接返回原列表。
    
    Args:
        vulnerabilities: 漏洞列表
        
    Returns:
        List[Dict]: 原始漏洞列表
    """
    logger.info(f"漏洞去重已禁用: {len(vulnerabilities)} 个漏洞保持不变")
    return vulnerabilities


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


def _get_vuln_key(vuln: Dict[str, Any]) -> str:
    """获取漏洞唯一键
    
    Args:
        vuln: 漏洞信息
        
    Returns:
        str: 唯一键
    """
    target = vuln.get("target", "")
    cve = vuln.get("cve", "")
    return f"{cve}_{target}"


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
        
        stats = analyze_vulnerability_stats(processed_vulns)
        logger.info(f"统计结果: {stats['summary']}")
        
        return {
            "success": True,
            "data": {
                "vulnerabilities": processed_vulns,
                "statistics": stats
            },
            "error": None,
            "metadata": {
                "tool": "vuln_analyzer",
                "total_count": len(processed_vulns),
                "original_count": len(vulnerabilities),
                "dedup_enabled": enable_dedup,
                "sort_enabled": enable_sort,
                "kb_enabled": enable_kb,
                "severity_distribution": stats["by_severity"]
            }
        }
    except Exception as e:
        logger.error(f"漏洞分析执行失败: {str(e)}")
        return {
            "success": False,
            "data": None,
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
        
        if enable_kb and ENABLE_KB_INTEGRATION:
            processed_vulns = await enrich_with_kb(processed_vulns)
            logger.info("已完成知识库信息丰富")
        
        stats = analyze_vulnerability_stats(processed_vulns)
        logger.info(f"统计结果: {stats['summary']}")
        
        return {
            "success": True,
            "data": {
                "vulnerabilities": processed_vulns,
                "statistics": stats
            },
            "error": None,
            "metadata": {
                "tool": "vuln_analyzer_async",
                "total_count": len(processed_vulns),
                "original_count": len(vulnerabilities),
                "dedup_enabled": enable_dedup,
                "sort_enabled": enable_sort,
                "kb_enabled": enable_kb,
                "severity_distribution": stats["by_severity"]
            }
        }
    except Exception as e:
        logger.error(f"异步漏洞分析执行失败: {str(e)}")
        return {
            "success": False,
            "data": None,
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
