"""
POC 系统工具函数.

提供统计计算、数据处理、POC验证等公共工具函数。
"""
from typing import Any, Dict, List, Set

from backend.models import POCVerificationResult


def parse_pocsuite_output(output: str) -> bool:
    """
    解析 Pocsuite3 输出,判断是否存在漏洞.

    Args:
        output: Pocsuite3 的输出内容.

    Returns:
        bool: 是否存在漏洞.
    """
    success_keywords = [
        "success",
        "vulnerable",
        "vuln",
        "exploit",
        "exists",
        "[+]"
    ]

    output_lower = output.lower()

    for keyword in success_keywords:
        if keyword in output_lower:
            return True

    return False


def get_poc_validation_rules() -> List[tuple]:
    """
    获取 POC 验证规则列表.

    Returns:
        List[tuple]: 验证规则列表，每个规则为(模式, 错误消息)元组.
    """
    return [
        ("class POC", "缺少POC类定义"),
        ("from pocsuite3", "缺少pocsuite3导入"),
        ("def _verify", "缺少_verify方法"),
        ("app", "缺少app属性"),
        ("vulID", "缺少vulID属性"),
        ("version", "缺少version属性"),
        ("author", "缺少author属性"),
        ("references", "缺少references属性"),
        ("name", "缺少name属性"),
        ("severity", "缺少severity属性"),
        ("appPowerLink", "缺少appPowerLink属性"),
        ("vulDate", "缺少vulDate属性"),
        ("appVersion", "缺少appVersion属性"),
        ("desc", "缺少desc属性"),
        ("samples", "缺少samples属性"),
    ]


def validate_poc_script_code(poc_code: str) -> Dict[str, Any]:
    """
    验证POC脚本是否符合pocsuite3标准格式.

    Args:
        poc_code: POC脚本代码.

    Returns:
        Dict[str, Any]: 验证结果，包含is_valid和错误信息.
    """
    validation_rules = get_poc_validation_rules()

    errors = []
    for pattern, error_msg in validation_rules:
        if pattern not in poc_code:
            errors.append(error_msg)

    is_valid = len(errors) == 0

    return {
        "is_valid": is_valid,
        "errors": errors
    }


def get_false_positive_keywords() -> List[str]:
    """
    获取误报检测关键词列表.

    Returns:
        List[str]: 误报关键词列表.
    """
    return [
        "timeout",
        "connection refused",
        "connection reset",
        "network unreachable",
        "dns resolution failed",
        "certificate error",
        "ssl error",
        "handshake failed",
        "404 not found",
        "403 forbidden",
        "401 unauthorized",
        "rate limit",
        "too many requests",
        "service unavailable",
        "gateway timeout",
        "bad gateway"
    ]


def get_success_keywords() -> List[str]:
    """
    获取成功验证关键词列表.

    Returns:
        List[str]: 成功关键词列表.
    """
    return [
        "success",
        "vulnerable",
        "exploit",
        "vuln",
        "shell",
        "code execution",
        "sql injection",
        "xss",
        "rce",
        "arbitrary file",
        "path traversal",
        "ssrf",
        "xxe",
        "deserialization"
    ]


def calculate_severity_distribution(results: List[POCVerificationResult]) -> Dict[str, int]:
    """
    计算严重度分布.

    Args:
        results: POC验证结果列表.

    Returns:
        Dict[str, int]: 严重度分布字典.
    """
    distribution: Dict[str, int] = {}
    for result in results:
        severity = result.severity or "info"
        distribution[severity] = distribution.get(severity, 0) + 1
    return distribution


def calculate_statistics(results: List[POCVerificationResult]) -> Dict[str, Any]:
    """
    计算统计信息.

    Args:
        results: POC验证结果列表.

    Returns:
        Dict[str, Any]: 统计信息字典.
    """
    if not results:
        return {
            "total": 0,
            "vulnerable": 0,
            "not_vulnerable": 0,
            "vulnerability_rate": 0,
            "average_confidence": 0.0,
            "average_cvss_score": 0.0,
            "severity_distribution": {}
        }

    total = len(results)
    vulnerable_count = sum(1 for r in results if r.vulnerable)
    not_vulnerable_count = total - vulnerable_count

    severity_distribution = calculate_severity_distribution(results)

    average_confidence = sum(r.confidence for r in results) / total
    average_cvss_score = sum(r.cvss_score or 0 for r in results) / total

    return {
        "total": total,
        "vulnerable": vulnerable_count,
        "not_vulnerable": not_vulnerable_count,
        "vulnerability_rate": (vulnerable_count / total * 100) if total > 0 else 0,
        "average_confidence": average_confidence,
        "average_cvss_score": average_cvss_score,
        "severity_distribution": severity_distribution
    }


def calculate_average_execution_time(results: List[POCVerificationResult]) -> float:
    """
    计算平均执行时间.

    Args:
        results: POC验证结果列表.

    Returns:
        float: 平均执行时间.
    """
    if not results:
        return 0.0

    total_execution_time = sum(r.execution_time for r in results)
    return total_execution_time / len(results)


def get_high_risk_targets(results: List[Any]) -> List[str]:
    """
    获取高风险目标列表.

    Args:
        results: POC验证结果列表或分析结果列表.

    Returns:
        List[str]: 高风险目标列表.
    """
    high_risk_targets: Set[str] = set()

    for result in results:
        if hasattr(result, 'vulnerable') and hasattr(result, 'severity'):
            if result.vulnerable and result.severity in ["critical", "high"]:
                high_risk_targets.add(result.target)
        elif hasattr(result, 'risk_level'):
            if result.risk_level in ["critical", "high"]:
                high_risk_targets.add(result.target)

    return list(high_risk_targets)
