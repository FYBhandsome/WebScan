"""
AI Agents 分析器模块

包含漏洞分析器和智能结果分析器。
报告生成功能已迁移到 backend/services/report_service.py
"""

__all__ = []

def __getattr__(name):
    if name == "VulnerabilityAnalyzer":
        from .vuln_analyzer import VulnerabilityAnalyzer
        return VulnerabilityAnalyzer
    elif name in ["AIAnalyzer", "AIAnalysisResult"]:
        from .ai_analyzer import AIAnalyzer, AIAnalysisResult
        if name == "AIAnalyzer":
            return AIAnalyzer
        elif name == "AIAnalysisResult":
            return AIAnalysisResult
    elif name in ["ReportGenerator", "EnhancedReportGenerator", "EnhancedReportData", "ReportFormat"]:
        from backend.services.report_service import (
            ReportService, ReportData, ReportFormat
        )
        import warnings
        warnings.warn(
            "EnhancedReportGenerator is deprecated. Use backend.services.report_service.ReportService instead.",
            DeprecationWarning,
            stacklevel=2
        )
        if name == "ReportGenerator":
            return ReportService
        elif name == "EnhancedReportGenerator":
            return ReportService
        elif name == "EnhancedReportData":
            return ReportData
        elif name == "ReportFormat":
            return ReportFormat
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
