# -*- coding:utf-8 -*-
"""
报告生成工具模块

提供AI分析和漏洞分析等报告生成工具。
"""

from typing import List, Dict, Any, Optional
import json
import os
from datetime import datetime
from pathlib import Path
import logging

from .ai_analyzer import ai_analyzer
from .vuln_analyzer import vuln_analyzer, vuln_analyzer_async

logger = logging.getLogger(__name__)

REPORT_TOOLS: List = [
    ai_analyzer,
    vuln_analyzer,
    vuln_analyzer_async,
]

__all__ = [
    "ai_analyzer",
    "vuln_analyzer",
    "vuln_analyzer_async",
    "REPORT_TOOLS",
    "save_report",
    "generate_report",
    "ReportSaver",
]


class ReportSaver:
    """报告保存器
    
    提供报告自动保存功能，支持多种格式输出。
    """
    
    def __init__(self, output_dir: str = "reports"):
        """初始化报告保存器
        
        Args:
            output_dir: 报告输出目录，默认为'reports'
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"报告保存器初始化完成，输出目录: {self.output_dir}")
    
    def _generate_filename(
        self,
        target: str,
        report_type: str = "scan",
        extension: str = "json"
    ) -> str:
        """生成报告文件名
        
        Args:
            target: 目标地址
            report_type: 报告类型
            extension: 文件扩展名
            
        Returns:
            str: 生成的文件名
        """
        safe_target = target.replace("://", "_").replace("/", "_").replace(":", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{report_type}_{safe_target}_{timestamp}.{extension}"
    
    def save_json(
        self,
        data: Dict[str, Any],
        target: str,
        report_type: str = "scan"
    ) -> str:
        """保存JSON格式报告
        
        Args:
            data: 报告数据
            target: 目标地址
            report_type: 报告类型
            
        Returns:
            str: 保存的文件路径
        """
        filename = self._generate_filename(target, report_type, "json")
        filepath = self.output_dir / filename
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        
        logger.info(f"JSON报告已保存: {filepath}")
        return str(filepath)
    
    def save_markdown(
        self,
        data: Dict[str, Any],
        target: str,
        report_type: str = "scan"
    ) -> str:
        """保存Markdown格式报告
        
        Args:
            data: 报告数据
            target: 目标地址
            report_type: 报告类型
            
        Returns:
            str: 保存的文件路径
        """
        filename = self._generate_filename(target, report_type, "md")
        filepath = self.output_dir / filename
        
        md_content = self._convert_to_markdown(data, target, report_type)
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(md_content)
        
        logger.info(f"Markdown报告已保存: {filepath}")
        return str(filepath)
    
    def _convert_to_markdown(
        self,
        data: Dict[str, Any],
        target: str,
        report_type: str
    ) -> str:
        """将报告数据转换为Markdown格式
        
        Args:
            data: 报告数据
            target: 目标地址
            report_type: 报告类型
            
        Returns:
            str: Markdown格式内容
        """
        lines = []
        
        lines.append(f"# 安全扫描报告")
        lines.append("")
        lines.append(f"**目标**: {target}")
        lines.append(f"**报告类型**: {report_type}")
        lines.append(f"**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        
        if data.get("success"):
            lines.append("## 执行状态: ✅ 成功")
        else:
            lines.append("## 执行状态: ❌ 失败")
            if data.get("error"):
                lines.append(f"**错误信息**: {data['error']}")
        lines.append("")
        
        report_data = data.get("data", {})
        
        if "statistics" in report_data:
            stats = report_data["statistics"]
            lines.append("## 漏洞统计")
            lines.append("")
            lines.append(f"- **总数**: {stats.get('total', 0)}")
            lines.append(f"- **摘要**: {stats.get('summary', 'N/A')}")
            lines.append("")
            
            by_severity = stats.get("by_severity", {})
            if by_severity:
                lines.append("### 按严重度分布")
                lines.append("")
                lines.append("| 严重度 | 数量 |")
                lines.append("|--------|------|")
                for severity, count in sorted(by_severity.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 0), reverse=True):
                    lines.append(f"| {severity} | {count} |")
                lines.append("")
        
        if "summary" in report_data:
            lines.append("## AI分析摘要")
            lines.append("")
            lines.append(f"**风险等级**: {report_data.get('risk_level', 'N/A')}")
            lines.append(f"**摘要**: {report_data.get('summary', 'N/A')}")
            lines.append("")
        
        if "vulnerabilities" in report_data:
            vulns = report_data["vulnerabilities"]
            if vulns:
                lines.append("## 漏洞列表")
                lines.append("")
                for i, vuln in enumerate(vulns[:20], 1):
                    lines.append(f"### {i}. {vuln.get('vuln_type', vuln.get('title', 'Unknown'))}")
                    lines.append("")
                    lines.append(f"- **严重度**: {vuln.get('severity', 'N/A')}")
                    lines.append(f"- **目标**: {vuln.get('target', vuln.get('url', 'N/A'))}")
                    if vuln.get("description"):
                        lines.append(f"- **描述**: {vuln['description']}")
                    lines.append("")
        
        if "priorities" in report_data:
            priorities = report_data["priorities"]
            if priorities:
                lines.append("## 修复优先级")
                lines.append("")
                lines.append("| 优先级 | 漏洞 | 原因 | 预估工作量 |")
                lines.append("|--------|------|------|------------|")
                for p in priorities:
                    lines.append(f"| {p.get('priority', 'N/A')} | {p.get('vulnerability', 'N/A')} | {p.get('reason', 'N/A')} | {p.get('estimated_effort', 'N/A')} |")
                lines.append("")
        
        if "business_impact" in report_data:
            impact = report_data["business_impact"]
            lines.append("## 业务影响")
            lines.append("")
            lines.append(f"- **数据风险**: {impact.get('data_risk', 'N/A')}")
            lines.append(f"- **停机风险**: {impact.get('downtime_risk', 'N/A')}")
            lines.append(f"- **合规风险**: {impact.get('compliance_risk', 'N/A')}")
            lines.append(f"- **财务影响**: {impact.get('financial_impact', 'N/A')}")
            lines.append("")
        
        return "\n".join(lines)
    
    def save(
        self,
        data: Dict[str, Any],
        target: str,
        report_type: str = "scan",
        formats: List[str] = ["json", "markdown"]
    ) -> Dict[str, str]:
        """保存报告（支持多格式）
        
        Args:
            data: 报告数据
            target: 目标地址
            report_type: 报告类型
            formats: 输出格式列表，支持'json'和'markdown'
            
        Returns:
            Dict[str, str]: 格式到文件路径的映射
        """
        saved_files = {}
        
        if "json" in formats:
            saved_files["json"] = self.save_json(data, target, report_type)
        
        if "markdown" in formats:
            saved_files["markdown"] = self.save_markdown(data, target, report_type)
        
        return saved_files


SEVERITY_ORDER: Dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0
}

_default_saver: Optional[ReportSaver] = None


def get_default_saver() -> ReportSaver:
    """获取默认报告保存器
    
    Returns:
        ReportSaver: 默认报告保存器实例
    """
    global _default_saver
    if _default_saver is None:
        _default_saver = ReportSaver()
    return _default_saver


def save_report(
    data: Dict[str, Any],
    target: str,
    report_type: str = "scan",
    formats: List[str] = ["json", "markdown"],
    output_dir: Optional[str] = None
) -> Dict[str, str]:
    """保存报告（便捷函数）
    
    Args:
        data: 报告数据
        target: 目标地址
        report_type: 报告类型
        formats: 输出格式列表
        output_dir: 输出目录（可选，使用默认目录）
        
    Returns:
        Dict[str, str]: 格式到文件路径的映射
    """
    if output_dir:
        saver = ReportSaver(output_dir)
    else:
        saver = get_default_saver()
    
    return saver.save(data, target, report_type, formats)


async def generate_report(
    target: str,
    vulnerabilities: List[Dict[str, Any]],
    tool_results: Dict[str, Any],
    enable_ai_analysis: bool = True,
    save_formats: List[str] = ["json", "markdown"],
    output_dir: Optional[str] = None
) -> Dict[str, Any]:
    """生成完整的安全扫描报告
    
    整合漏洞分析和AI分析，生成完整报告并自动保存。
    
    Args:
        target: 目标地址
        vulnerabilities: 漏洞列表
        tool_results: 工具执行结果
        enable_ai_analysis: 是否启用AI分析
        save_formats: 报告保存格式
        output_dir: 输出目录
        
    Returns:
        Dict[str, Any]: 完整报告数据，包含分析结果和保存路径
    """
    logger.info(f"开始生成报告: {target}")
    
    target_context = {
        "target": target,
        "domain": target.replace("http://", "").replace("https://", "").split("/")[0]
    }
    
    vuln_result = vuln_analyzer.invoke({
        "vulnerabilities": vulnerabilities,
        "enable_dedup": False,
        "enable_sort": True,
        "enable_kb": False
    })
    
    report_data = {
        "target": target,
        "generated_at": datetime.now().isoformat(),
        "vulnerability_analysis": vuln_result.get("data", {}),
        "ai_analysis": None
    }
    
    if enable_ai_analysis:
        ai_result = ai_analyzer.invoke({
            "vulnerabilities": vulnerabilities,
            "tool_results": tool_results,
            "target_context": target_context
        })
        report_data["ai_analysis"] = ai_result.get("data", {})
        report_data["risk_level"] = ai_result.get("data", {}).get("risk_level", "info")
        report_data["summary"] = ai_result.get("data", {}).get("summary", "")
    
    saved_files = save_report(
        data={"success": True, "data": report_data},
        target=target,
        report_type="security_scan",
        formats=save_formats,
        output_dir=output_dir
    )
    
    report_data["saved_files"] = saved_files
    
    logger.info(f"报告生成完成: {target}")
    logger.info(f"保存路径: {saved_files}")
    
    return {
        "success": True,
        "data": report_data,
        "error": None,
        "metadata": {
            "target": target,
            "vulnerability_count": len(vulnerabilities),
            "ai_analysis_enabled": enable_ai_analysis,
            "saved_files": saved_files
        }
    }
