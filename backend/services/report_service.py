"""
统一报告生成服务

整合所有报告生成功能，提供统一的接口：
- 多格式报告生成（HTML、JSON、PDF、Markdown）
- AI 分析集成
- 执行信息保留
- 风险评估
"""
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, field, asdict
from enum import Enum

logger = logging.getLogger(__name__)


class ReportFormat(str, Enum):
    """报告格式枚举"""
    JSON = "json"
    HTML = "html"
    PDF = "pdf"
    MARKDOWN = "markdown"


class Language(str, Enum):
    """报告语言枚举"""
    ZH_CN = "zh_CN"
    EN_US = "en_US"


SEVERITY_CONFIG = {
    "critical": {"score": 10.0, "color": "#c0392b", "label": "严重", "label_en": "Critical", "order": 0},
    "high": {"score": 8.0, "color": "#e74c3c", "label": "高危", "label_en": "High", "order": 1},
    "medium": {"score": 5.0, "color": "#f39c12", "label": "中危", "label_en": "Medium", "order": 2},
    "low": {"score": 3.0, "color": "#3498db", "label": "低危", "label_en": "Low", "order": 3},
    "info": {"score": 1.0, "color": "#95a5a6", "label": "信息", "label_en": "Info", "order": 4}
}


@dataclass
class RiskAssessment:
    """风险评估结果"""
    score: float = 0.0
    level: str = "info"
    label: str = "无风险"
    color: str = "#95a5a6"
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ReportSummary:
    """报告摘要"""
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    vulnerability_rate: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AIAnalysisData:
    """AI 分析数据"""
    summary: str = ""
    risk_level: str = "info"
    causes: List[str] = field(default_factory=list)
    risks: List[str] = field(default_factory=list)
    priorities: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WorkflowExecutionRecord:
    """工作流执行记录"""
    node_id: str = ""
    node_name: str = ""
    node_type: str = ""
    status: str = "pending"
    step_number: int = 0
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    duration_ms: Optional[float] = None
    execution_time: Optional[float] = None
    input_params: Dict[str, Any] = field(default_factory=dict)
    output_data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    tool_name: Optional[str] = None
    task: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WorkflowTaskPlan:
    """工作流任务规划"""
    plan_id: str = ""
    plan_name: str = ""
    plan_type: str = "scan"
    priority: int = 5
    status: str = "pending"
    dependencies: List[str] = field(default_factory=list)
    estimated_time: Optional[float] = None
    actual_time: Optional[float] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    result: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WorkflowData:
    """工作流数据"""
    workflow_id: str = ""
    workflow_name: str = ""
    status: str = "pending"
    progress: int = 0
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    duration: Optional[float] = None
    execution_history: List[WorkflowExecutionRecord] = field(default_factory=list)
    task_plans: List[WorkflowTaskPlan] = field(default_factory=list)
    graph_flow: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "workflow_id": self.workflow_id,
            "workflow_name": self.workflow_name,
            "status": self.status,
            "progress": self.progress,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.duration,
            "execution_history": [r.to_dict() for r in self.execution_history],
            "task_plans": [p.to_dict() for p in self.task_plans],
            "graph_flow": self.graph_flow
        }


@dataclass
class ReportData:
    """统一报告数据结构"""
    task_id: str = ""
    task_name: str = ""
    target: str = ""
    scan_time: str = ""
    generated_at: str = ""
    
    summary: ReportSummary = field(default_factory=ReportSummary)
    risk_assessment: RiskAssessment = field(default_factory=RiskAssessment)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    ai_analysis: Optional[AIAnalysisData] = None
    
    execution_history: List[Dict[str, Any]] = field(default_factory=list)
    tool_results: Dict[str, Any] = field(default_factory=dict)
    target_context: Dict[str, Any] = field(default_factory=dict)
    
    workflow: Optional[WorkflowData] = None
    
    def to_dict(self) -> Dict[str, Any]:
        data = {
            "task_id": self.task_id,
            "task_name": self.task_name,
            "target": self.target,
            "scan_time": self.scan_time,
            "generated_at": self.generated_at,
            "summary": self.summary.to_dict(),
            "risk_assessment": self.risk_assessment.to_dict(),
            "vulnerabilities": self.vulnerabilities,
            "execution_history": self.execution_history,
            "tool_results": self.tool_results,
            "target_context": self.target_context
        }
        if self.ai_analysis:
            data["ai_analysis"] = self.ai_analysis.to_dict()
        if self.workflow:
            data["workflow"] = self.workflow.to_dict()
        return data


class ReportService:
    """
    统一报告生成服务
    
    整合了 POC 报告生成器、增强版报告生成器和 API 报告生成功能。
    提供统一的报告生成、AI 分析和导出接口。
    """
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.ai_analyzer = None
        self._init_ai_analyzer()
        logger.info("📄 统一报告生成服务初始化完成")
    
    def _init_ai_analyzer(self):
        """初始化 AI 分析器"""
        try:
            from backend.ai_agents.analyzers.ai_analyzer import AIAnalyzer
            self.ai_analyzer = AIAnalyzer()
            logger.info("🧠 AI 分析器已集成")
        except Exception as e:
            logger.warning(f"AI 分析器初始化失败: {e}")
            self.ai_analyzer = None
    
    def calculate_risk_score(self, vulnerabilities: List[Dict[str, Any]]) -> RiskAssessment:
        """
        计算风险评分
        
        Args:
            vulnerabilities: 漏洞列表
            
        Returns:
            RiskAssessment: 风险评估结果
        """
        if not vulnerabilities:
            return RiskAssessment(score=0.0, level="info", label="无风险", color="#95a5a6")
        
        base_score = 0.0
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "info").lower()
            base_score += SEVERITY_CONFIG.get(severity, SEVERITY_CONFIG["info"])["score"]
        
        max_possible = len(vulnerabilities) * 10.0
        normalized_score = min(100.0, (base_score / max_possible) * 100) if max_possible > 0 else 0.0
        
        if normalized_score >= 80:
            level, label, color = "critical", "极高风险", "#c0392b"
        elif normalized_score >= 60:
            level, label, color = "high", "高风险", "#e74c3c"
        elif normalized_score >= 40:
            level, label, color = "medium", "中等风险", "#f39c12"
        elif normalized_score >= 20:
            level, label, color = "low", "低风险", "#3498db"
        else:
            level, label, color = "info", "信息", "#95a5a6"
        
        return RiskAssessment(
            score=round(normalized_score, 2),
            level=level,
            label=label,
            color=color
        )
    
    def calculate_summary(self, vulnerabilities: List[Dict[str, Any]]) -> ReportSummary:
        """
        计算报告摘要
        
        Args:
            vulnerabilities: 漏洞列表
            
        Returns:
            ReportSummary: 报告摘要
        """
        summary = ReportSummary()
        summary.total_vulnerabilities = len(vulnerabilities)
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "info").lower()
            if severity == "critical":
                summary.critical_count += 1
            elif severity == "high":
                summary.high_count += 1
            elif severity == "medium":
                summary.medium_count += 1
            elif severity == "low":
                summary.low_count += 1
            else:
                summary.info_count += 1
        
        if summary.total_vulnerabilities > 0:
            vuln_count = summary.critical_count + summary.high_count + summary.medium_count + summary.low_count
            summary.vulnerability_rate = (vuln_count / summary.total_vulnerabilities) * 100
        
        return summary
    
    async def perform_ai_analysis(
        self,
        vulnerabilities: List[Dict[str, Any]],
        tool_results: Dict[str, Any],
        target_context: Dict[str, Any]
    ) -> Optional[AIAnalysisData]:
        """
        执行 AI 分析
        
        Args:
            vulnerabilities: 漏洞列表
            tool_results: 工具执行结果
            target_context: 目标上下文
            
        Returns:
            AIAnalysisData: AI 分析数据
        """
        if not self.ai_analyzer:
            logger.warning("AI 分析器未初始化，跳过 AI 分析")
            return None
        
        try:
            ai_result = await self.ai_analyzer.analyze_scan_results(
                vulnerabilities, tool_results, target_context
            )
            
            ai_data = AIAnalysisData()
            ai_data.summary = ai_result.summary
            ai_data.risk_level = ai_result.risk_level
            
            ai_data.causes = [
                cause.description if hasattr(cause, 'description') else str(cause)
                for cause in ai_result.vulnerability_causes
            ]
            
            ai_data.risks = [
                risk.description if hasattr(risk, 'description') else str(risk)
                for risk in ai_result.exploitation_risks
            ]
            
            ai_data.priorities = [
                {
                    "vulnerability": p.vulnerability_name if hasattr(p, 'vulnerability_name') else p.get("vulnerability", ""),
                    "priority": p.priority if hasattr(p, 'priority') else p.get("priority", 0),
                    "reason": p.reason if hasattr(p, 'reason') else p.get("reason", "")
                }
                for p in ai_result.remediation_priorities
            ]
            
            logger.info("✅ AI 分析完成")
            return ai_data
            
        except Exception as e:
            logger.error(f"AI 分析失败: {e}")
            return None
    
    async def generate_report(
        self,
        task_id: str,
        task_name: str,
        target: str,
        vulnerabilities: List[Dict[str, Any]],
        execution_history: List[Dict[str, Any]] = None,
        tool_results: Dict[str, Any] = None,
        target_context: Dict[str, Any] = None,
        include_ai_analysis: bool = True,
        scan_time: str = None,
        workflow_data: Dict[str, Any] = None
    ) -> ReportData:
        """
        生成统一报告数据
        
        Args:
            task_id: 任务 ID
            task_name: 任务名称
            target: 目标
            vulnerabilities: 漏洞列表
            execution_history: 执行历史
            tool_results: 工具结果
            target_context: 目标上下文
            include_ai_analysis: 是否包含 AI 分析
            scan_time: 扫描时间
            workflow_data: 工作流数据（包含执行历史、任务规划等）
            
        Returns:
            ReportData: 报告数据
        """
        logger.info(f"📄 开始生成报告 | 任务: {task_name} | 漏洞数: {len(vulnerabilities)} | 包含AI分析: {include_ai_analysis}")
        
        report_data = ReportData()
        report_data.task_id = task_id
        report_data.task_name = task_name
        report_data.target = target
        report_data.scan_time = scan_time or datetime.now().isoformat()
        report_data.generated_at = datetime.now().isoformat()
        
        report_data.vulnerabilities = vulnerabilities
        report_data.execution_history = execution_history or []
        report_data.tool_results = tool_results or {}
        report_data.target_context = target_context or {}
        
        if workflow_data:
            report_data.workflow = self._parse_workflow_data(workflow_data)
            logger.info(f"📊 工作流数据已集成 | 执行记录: {len(report_data.workflow.execution_history)} | 任务规划: {len(report_data.workflow.task_plans)}")
        
        report_data.summary = self.calculate_summary(vulnerabilities)
        report_data.risk_assessment = self.calculate_risk_score(vulnerabilities)
        
        logger.info(f"📊 漏洞统计完成 | 严重: {report_data.summary.critical_count} | 高危: {report_data.summary.high_count} | 中危: {report_data.summary.medium_count} | 低危: {report_data.summary.low_count}")
        
        if include_ai_analysis and self.ai_analyzer:
            logger.info(f"🧠 开始执行AI分析...")
            report_data.ai_analysis = await self.perform_ai_analysis(
                vulnerabilities, tool_results or {}, target_context or {}
            )
            if report_data.ai_analysis:
                logger.info(f"✅ AI分析完成 | 风险等级: {report_data.ai_analysis.risk_level}")
            else:
                logger.warning("⚠️ AI分析返回空结果")
        elif include_ai_analysis and not self.ai_analyzer:
            logger.warning("⚠️ AI分析器未初始化，跳过AI分析")
        
        logger.info(f"📄 报告数据生成完成 | 风险评分: {report_data.risk_assessment.score} | 风险等级: {report_data.risk_assessment.label}")
        return report_data
    
    def _parse_workflow_data(self, workflow_data: Dict[str, Any]) -> WorkflowData:
        """
        解析工作流数据
        
        Args:
            workflow_data: 原始工作流数据字典
            
        Returns:
            WorkflowData: 标准化的工作流数据对象
        """
        workflow = WorkflowData()
        workflow.workflow_id = workflow_data.get("workflow_id", "")
        workflow.workflow_name = workflow_data.get("workflow_name", "AI Security Scan")
        workflow.status = workflow_data.get("status", "pending")
        workflow.progress = workflow_data.get("progress", 0)
        workflow.start_time = workflow_data.get("start_time")
        workflow.end_time = workflow_data.get("end_time")
        workflow.duration = workflow_data.get("duration")
        workflow.graph_flow = workflow_data.get("graph_flow", {})
        
        for record in workflow_data.get("execution_history", []):
            exec_record = WorkflowExecutionRecord(
                node_id=record.get("node_id", ""),
                node_name=record.get("node_name", ""),
                node_type=record.get("node_type", ""),
                status=record.get("status", "pending"),
                step_number=record.get("step_number", 0),
                start_time=record.get("start_time"),
                end_time=record.get("end_time"),
                duration_ms=record.get("duration_ms"),
                execution_time=record.get("execution_time"),
                input_params=record.get("input_params", {}),
                output_data=record.get("output_data", {}),
                error=record.get("error"),
                tool_name=record.get("tool_name"),
                task=record.get("task")
            )
            workflow.execution_history.append(exec_record)
        
        for plan in workflow_data.get("task_plans", []):
            task_plan = WorkflowTaskPlan(
                plan_id=plan.get("plan_id", ""),
                plan_name=plan.get("plan_name", ""),
                plan_type=plan.get("plan_type", "scan"),
                priority=plan.get("priority", 5),
                status=plan.get("status", "pending"),
                dependencies=plan.get("dependencies", []),
                estimated_time=plan.get("estimated_time"),
                actual_time=plan.get("actual_time"),
                parameters=plan.get("parameters", {}),
                result=plan.get("result", {})
            )
            workflow.task_plans.append(task_plan)
        
        return workflow
    
    async def save_report_to_db(
        self,
        report_data: ReportData,
        task_id: int,
        report_name: str,
        report_type: str = "json"
    ) -> int:
        """
        保存报告到数据库
        
        Args:
            report_data: 报告数据
            task_id: 任务 ID
            report_name: 报告名称
            report_type: 报告类型
            
        Returns:
            int: 报告 ID
        """
        try:
            from backend.models import Report
            
            logger.info(f"💾 开始保存报告到数据库 | 任务ID: {task_id} | 报告名称: {report_name}")
            
            ai_analysis_json = None
            analyzed_at = None
            analysis_model = None
            
            if report_data.ai_analysis:
                ai_analysis_json = json.dumps(report_data.ai_analysis.to_dict())
                analyzed_at = datetime.now()
                analysis_model = "AI_Analyzer_v1"
                logger.info(f"📝 AI分析结果已准备 | 风险等级: {report_data.ai_analysis.risk_level}")
            
            report = await Report.create(
                task_id=task_id,
                report_name=report_name,
                report_type=report_type,
                content=json.dumps(report_data.to_dict()),
                ai_analysis=ai_analysis_json,
                analyzed_at=analyzed_at,
                analysis_model=analysis_model
            )
            
            logger.info(f"✅ 报告保存成功 | 报告ID: {report.id} | 任务ID: {task_id}")
            return report.id
            
        except Exception as e:
            logger.error(f"❌ 保存报告到数据库失败: {str(e)}", exc_info=True)
            raise
    
    def generate_json_report(self, report_data: ReportData) -> str:
        """生成 JSON 格式报告"""
        return json.dumps(report_data.to_dict(), ensure_ascii=False, indent=2)
    
    def generate_html_report(self, report_data: ReportData, language: Language = Language.ZH_CN) -> str:
        """生成 HTML 格式报告"""
        return self._render_html_template(report_data, language)
    
    def generate_markdown_report(self, report_data: ReportData, language: Language = Language.ZH_CN) -> str:
        """生成 Markdown 格式报告"""
        return self._render_markdown_template(report_data, language)
    
    def generate_pdf_report(self, report_data: ReportData, language: Language = Language.ZH_CN) -> bytes:
        """生成 PDF 格式报告"""
        html_content = self.generate_html_report(report_data, language)
        
        try:
            from weasyprint import HTML
            from io import BytesIO
            buffer = BytesIO()
            HTML(string=html_content).write_pdf(buffer)
            return buffer.getvalue()
        except ImportError:
            logger.warning("weasyprint 未安装，尝试使用 reportlab")
            return self._generate_pdf_with_reportlab(report_data, language)
        except Exception as e:
            logger.error(f"PDF 生成失败: {e}")
            raise
    
    def _generate_pdf_with_reportlab(self, report_data: ReportData, language: Language) -> bytes:
        """使用 reportlab 生成 PDF"""
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib import colors
            from io import BytesIO
            
            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=A4)
            styles = getSampleStyleSheet()
            story = []
            
            story.append(Paragraph(f"安全扫描报告 - {report_data.task_name}", styles['Title']))
            story.append(Spacer(1, 20))
            
            info_data = [
                ["任务名称", report_data.task_name],
                ["目标", report_data.target],
                ["扫描时间", report_data.scan_time],
                ["风险评分", f"{report_data.risk_assessment.score}"],
                ["风险等级", report_data.risk_assessment.label]
            ]
            
            info_table = Table(info_data, colWidths=[4*cm, 10*cm])
            info_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 0), (-1, -1), 10)
            ]))
            story.append(info_table)
            story.append(Spacer(1, 20))
            
            summary_data = [
                ["严重程度", "数量"],
                ["严重", str(report_data.summary.critical_count)],
                ["高危", str(report_data.summary.high_count)],
                ["中危", str(report_data.summary.medium_count)],
                ["低危", str(report_data.summary.low_count)],
                ["信息", str(report_data.summary.info_count)]
            ]
            
            summary_table = Table(summary_data, colWidths=[6*cm, 6*cm])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 0), (-1, -1), 10)
            ]))
            story.append(summary_table)
            
            doc.build(story)
            return buffer.getvalue()
            
        except ImportError:
            raise Exception("PDF 生成需要安装 weasyprint 或 reportlab")
    
    def _render_html_template(self, report_data: ReportData, language: Language) -> str:
        """渲染 HTML 模板"""
        summary = report_data.summary
        risk = report_data.risk_assessment
        
        vuln_items_html = self._render_vulnerabilities_html(report_data.vulnerabilities, language)
        ai_analysis_html = self._render_ai_analysis_html(report_data.ai_analysis, language) if report_data.ai_analysis else ""
        workflow_html = self._render_workflow_html(report_data.workflow, language) if report_data.workflow else ""
        
        labels = {
            "report_title": "安全扫描报告" if language == Language.ZH_CN else "Security Scan Report",
            "task_name": "任务名称" if language == Language.ZH_CN else "Task Name",
            "target": "目标" if language == Language.ZH_CN else "Target",
            "scan_time": "扫描时间" if language == Language.ZH_CN else "Scan Time",
            "risk_assessment": "风险评估" if language == Language.ZH_CN else "Risk Assessment",
            "vulnerability_stats": "漏洞统计" if language == Language.ZH_CN else "Vulnerability Statistics",
            "vulnerability_details": "漏洞详情" if language == Language.ZH_CN else "Vulnerability Details",
            "ai_analysis": "AI 智能分析" if language == Language.ZH_CN else "AI Analysis"
        }
        
        return f"""<!DOCTYPE html>
<html lang="{'zh-CN' if language == Language.ZH_CN else 'en'}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report_data.task_name}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Microsoft YaHei', sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; border-radius: 10px; margin-bottom: 30px; }}
        .header h1 {{ font-size: 28px; margin-bottom: 10px; }}
        .header .meta {{ font-size: 14px; opacity: 0.9; }}
        
        .risk-gauge {{ background: white; border-radius: 10px; padding: 30px; margin-bottom: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .risk-gauge h2 {{ color: #333; margin-bottom: 20px; }}
        .gauge-container {{ display: flex; align-items: center; gap: 30px; flex-wrap: wrap; }}
        .gauge {{ width: 200px; height: 200px; position: relative; }}
        .gauge-value {{ position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-size: 48px; font-weight: bold; }}
        .risk-details {{ flex: 1; min-width: 300px; }}
        .risk-level {{ font-size: 24px; font-weight: bold; margin-bottom: 10px; }}
        
        .summary-cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .card {{ background: white; border-radius: 10px; padding: 20px; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .card .count {{ font-size: 36px; font-weight: bold; margin: 10px 0; }}
        .card .label {{ font-size: 14px; color: #666; }}
        
        .section {{ background: white; border-radius: 10px; padding: 30px; margin-bottom: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .section h2 {{ color: #333; border-bottom: 2px solid #667eea; padding-bottom: 10px; margin-bottom: 20px; }}
        
        .vuln-item {{ border: 1px solid #eee; border-radius: 8px; padding: 20px; margin-bottom: 15px; }}
        .vuln-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; flex-wrap: wrap; gap: 10px; }}
        .vuln-title {{ font-size: 18px; font-weight: bold; }}
        .vuln-severity {{ padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; color: white; }}
        .severity-critical {{ background: #c0392b; }}
        .severity-high {{ background: #e74c3c; }}
        .severity-medium {{ background: #f39c12; }}
        .severity-low {{ background: #3498db; }}
        .severity-info {{ background: #95a5a6; }}
        
        .ai-analysis {{ background: #e8f4fd; border-left: 4px solid #3498db; padding: 20px; border-radius: 8px; }}
        .ai-analysis h3 {{ color: #3498db; margin-bottom: 15px; }}
        
        .workflow-section {{ background: white; border-radius: 10px; padding: 30px; margin-bottom: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .workflow-section h2 {{ color: #333; border-bottom: 2px solid #10b981; padding-bottom: 10px; margin-bottom: 20px; }}
        
        .workflow-overview {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 25px; }}
        .workflow-stat {{ background: #f8fafc; padding: 15px; border-radius: 8px; text-align: center; }}
        .workflow-stat .value {{ font-size: 24px; font-weight: bold; color: #10b981; }}
        .workflow-stat .label {{ font-size: 12px; color: #64748b; margin-top: 5px; }}
        
        .execution-timeline {{ margin-top: 20px; }}
        .timeline-item {{ display: flex; gap: 15px; margin-bottom: 15px; padding: 15px; background: #f8fafc; border-radius: 8px; border-left: 3px solid #10b981; }}
        .timeline-item.success {{ border-left-color: #10b981; }}
        .timeline-item.failed {{ border-left-color: #ef4444; }}
        .timeline-item.running {{ border-left-color: #3b82f6; }}
        .timeline-item.pending {{ border-left-color: #94a3b8; }}
        .timeline-step {{ min-width: 30px; height: 30px; background: #10b981; color: white; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 14px; }}
        .timeline-content {{ flex: 1; }}
        .timeline-title {{ font-weight: 600; margin-bottom: 5px; }}
        .timeline-meta {{ font-size: 12px; color: #64748b; }}
        .timeline-duration {{ font-size: 12px; color: #10b981; font-weight: 500; }}
        
        .task-plans {{ margin-top: 20px; }}
        .plan-item {{ display: flex; align-items: center; gap: 15px; padding: 12px 15px; background: #f8fafc; border-radius: 8px; margin-bottom: 10px; }}
        .plan-priority {{ min-width: 30px; height: 30px; background: #667eea; color: white; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 12px; }}
        .plan-info {{ flex: 1; }}
        .plan-name {{ font-weight: 600; }}
        .plan-status {{ padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 500; }}
        .status-completed {{ background: #d1fae5; color: #065f46; }}
        .status-running {{ background: #dbeafe; color: #1e40af; }}
        .status-pending {{ background: #f1f5f9; color: #475569; }}
        .status-failed {{ background: #fee2e2; color: #991b1b; }}
        
        .progress-bar {{ width: 100%; height: 8px; background: #e2e8f0; border-radius: 4px; overflow: hidden; margin-top: 10px; }}
        .progress-fill {{ height: 100%; background: linear-gradient(90deg, #10b981, #34d399); transition: width 0.3s; }}
        
        .footer {{ text-align: center; padding: 20px; color: #666; font-size: 12px; }}
        
        @media print {{
            body {{ background: white; }}
            .section, .card, .vuln-item, .workflow-section {{ box-shadow: none; border: 1px solid #ddd; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 {labels['report_title']}</h1>
            <div class="meta">
                <p>{labels['task_name']}: {report_data.task_name}</p>
                <p>{labels['target']}: {report_data.target}</p>
                <p>{labels['scan_time']}: {report_data.scan_time}</p>
            </div>
        </div>
        
        <div class="risk-gauge">
            <h2>📊 {labels['risk_assessment']}</h2>
            <div class="gauge-container">
                <div class="gauge">
                    <svg viewBox="0 0 200 200">
                        <circle cx="100" cy="100" r="80" fill="none" stroke="#eee" stroke-width="20"/>
                        <circle cx="100" cy="100" r="80" fill="none" stroke="{risk.color}" stroke-width="20"
                            stroke-dasharray="{risk.score * 5.03} 503"
                            stroke-linecap="round" transform="rotate(-90 100 100)"/>
                    </svg>
                    <div class="gauge-value" style="color: {risk.color};">{risk.score}</div>
                </div>
                <div class="risk-details">
                    <div class="risk-level" style="color: {risk.color};">风险等级: {risk.label}</div>
                    <p>综合风险评分基于漏洞数量、严重程度计算得出。</p>
                </div>
            </div>
        </div>
        
        <div class="summary-cards">
            <div class="card" style="border-top: 4px solid #c0392b;">
                <div class="label">严重</div>
                <div class="count" style="color: #c0392b;">{summary.critical_count}</div>
            </div>
            <div class="card" style="border-top: 4px solid #e74c3c;">
                <div class="label">高危</div>
                <div class="count" style="color: #e74c3c;">{summary.high_count}</div>
            </div>
            <div class="card" style="border-top: 4px solid #f39c12;">
                <div class="label">中危</div>
                <div class="count" style="color: #f39c12;">{summary.medium_count}</div>
            </div>
            <div class="card" style="border-top: 4px solid #3498db;">
                <div class="label">低危</div>
                <div class="count" style="color: #3498db;">{summary.low_count}</div>
            </div>
            <div class="card" style="border-top: 4px solid #95a5a6;">
                <div class="label">信息</div>
                <div class="count" style="color: #95a5a6;">{summary.info_count}</div>
            </div>
        </div>
        
        {workflow_html}
        
        <div class="section">
            <h2>🔍 {labels['vulnerability_details']}</h2>
            {vuln_items_html if vuln_items_html else '<p>未发现漏洞</p>'}
        </div>
        
        {ai_analysis_html}
        
        <div class="footer">
            <p>报告由 AI_WebSecurity 自动生成 | 生成时间: {report_data.generated_at}</p>
        </div>
    </div>
</body>
</html>"""
    
    def _render_vulnerabilities_html(self, vulnerabilities: List[Dict[str, Any]], language: Language) -> str:
        """渲染漏洞列表 HTML"""
        if not vulnerabilities:
            return ""
        
        html = ""
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "info").lower()
            config = SEVERITY_CONFIG.get(severity, SEVERITY_CONFIG["info"])
            label = config["label"] if language == Language.ZH_CN else config["label_en"]
            
            html += f"""
            <div class="vuln-item">
                <div class="vuln-header">
                    <span class="vuln-title">{vuln.get('title', vuln.get('name', 'Unknown'))}</span>
                    <span class="vuln-severity severity-{severity}">{label}</span>
                </div>
                <p><strong>URL:</strong> {vuln.get('url', 'N/A')}</p>
                <p><strong>描述:</strong> {vuln.get('description', 'N/A')}</p>
                <p style="margin-top: 10px; padding: 10px; background: #e8f5e9; border-radius: 4px;">
                    <strong>修复建议:</strong> {vuln.get('remediation', 'N/A')}
                </p>
            </div>
            """
        
        return html
    
    def _render_ai_analysis_html(self, ai_analysis: AIAnalysisData, language: Language) -> str:
        """渲染 AI 分析 HTML"""
        if not ai_analysis:
            return ""
        
        labels = {
            "ai_analysis": "AI 智能分析" if language == Language.ZH_CN else "AI Analysis",
            "summary": "风险总结" if language == Language.ZH_CN else "Summary",
            "causes": "漏洞成因" if language == Language.ZH_CN else "Causes",
            "risks": "利用风险" if language == Language.ZH_CN else "Risks",
            "priorities": "修复优先级" if language == Language.ZH_CN else "Priorities"
        }
        
        html = f"""
        <div class="section">
            <h2>🤖 {labels['ai_analysis']}</h2>
            <div class="ai-analysis">
        """
        
        if ai_analysis.summary:
            html += f"""
                <h3>{labels['summary']}</h3>
                <p>{ai_analysis.summary}</p>
            """
        
        if ai_analysis.causes:
            html += f"""
                <h3 style="margin-top: 20px;">{labels['causes']}</h3>
                <ul>
                    {''.join(f'<li>{cause}</li>' for cause in ai_analysis.causes)}
                </ul>
            """
        
        if ai_analysis.risks:
            html += f"""
                <h3 style="margin-top: 20px;">{labels['risks']}</h3>
                <ul>
                    {''.join(f'<li>{risk}</li>' for risk in ai_analysis.risks)}
                </ul>
            """
        
        if ai_analysis.priorities:
            html += f"""
                <h3 style="margin-top: 20px;">{labels['priorities']}</h3>
                <ul>
                    {''.join(f'<li>{p.get("vulnerability", "")}: 优先级 {p.get("priority", 0)}</li>' for p in ai_analysis.priorities)}
                </ul>
            """
        
        html += """
            </div>
        </div>
        """
        
        return html
    
    def _render_workflow_html(self, workflow: WorkflowData, language: Language) -> str:
        """渲染工作流数据 HTML"""
        if not workflow:
            return ""
        
        labels = {
            "workflow_title": "工作流执行详情" if language == Language.ZH_CN else "Workflow Execution Details",
            "overview": "执行概览" if language == Language.ZH_CN else "Overview",
            "execution_history": "执行历史" if language == Language.ZH_CN else "Execution History",
            "task_plans": "任务规划" if language == Language.ZH_CN else "Task Plans",
            "total_steps": "总步骤数" if language == Language.ZH_CN else "Total Steps",
            "completed_steps": "已完成" if language == Language.ZH_CN else "Completed",
            "failed_steps": "失败" if language == Language.ZH_CN else "Failed",
            "duration": "执行时长" if language == Language.ZH_CN else "Duration",
            "status": "状态" if language == Language.ZH_CN else "Status",
            "priority": "优先级" if language == Language.ZH_CN else "Priority",
            "no_records": "暂无执行记录" if language == Language.ZH_CN else "No execution records",
            "no_plans": "暂无任务规划" if language == Language.ZH_CN else "No task plans"
        }
        
        status_labels = {
            "success": "成功" if language == Language.ZH_CN else "Success",
            "completed": "完成" if language == Language.ZH_CN else "Completed",
            "failed": "失败" if language == Language.ZH_CN else "Failed",
            "running": "运行中" if language == Language.ZH_CN else "Running",
            "pending": "等待中" if language == Language.ZH_CN else "Pending",
            "skipped": "已跳过" if language == Language.ZH_CN else "Skipped"
        }
        
        completed_count = sum(1 for r in workflow.execution_history if r.status in ["success", "completed"])
        failed_count = sum(1 for r in workflow.execution_history if r.status == "failed")
        total_duration = sum(r.execution_time or 0 for r in workflow.execution_history)
        
        overview_html = f"""
        <div class="workflow-overview">
            <div class="workflow-stat">
                <div class="value">{len(workflow.execution_history)}</div>
                <div class="label">{labels['total_steps']}</div>
            </div>
            <div class="workflow-stat">
                <div class="value" style="color: #10b981;">{completed_count}</div>
                <div class="label">{labels['completed_steps']}</div>
            </div>
            <div class="workflow-stat">
                <div class="value" style="color: #ef4444;">{failed_count}</div>
                <div class="label">{labels['failed_steps']}</div>
            </div>
            <div class="workflow-stat">
                <div class="value">{total_duration:.2f}s</div>
                <div class="label">{labels['duration']}</div>
            </div>
        </div>
        """
        
        timeline_html = ""
        if workflow.execution_history:
            for idx, record in enumerate(workflow.execution_history):
                status_class = record.status if record.status in ["success", "failed", "running", "pending"] else "pending"
                status_text = status_labels.get(record.status, record.status)
                duration_text = f"{record.execution_time:.2f}s" if record.execution_time else "-"
                
                timeline_html += f"""
                <div class="timeline-item {status_class}">
                    <div class="timeline-step">{idx + 1}</div>
                    <div class="timeline-content">
                        <div class="timeline-title">{record.node_name or record.task or f'步骤 {idx + 1}'}</div>
                        <div class="timeline-meta">
                            <span>类型: {record.node_type or 'N/A'}</span>
                            <span style="margin-left: 15px;">状态: {status_text}</span>
                            <span style="margin-left: 15px;">工具: {record.tool_name or 'N/A'}</span>
                        </div>
                        {f'<div class="timeline-duration">耗时: {duration_text}</div>' if record.execution_time else ''}
                        {f'<div style="color: #ef4444; margin-top: 5px; font-size: 12px;">错误: {record.error}</div>' if record.error else ''}
                    </div>
                </div>
                """
        else:
            timeline_html = f'<p style="color: #64748b; text-align: center; padding: 20px;">{labels["no_records"]}</p>'
        
        plans_html = ""
        if workflow.task_plans:
            for plan in sorted(workflow.task_plans, key=lambda x: x.priority, reverse=True):
                status_class = plan.status if plan.status in ["completed", "running", "pending", "failed"] else "pending"
                status_text = status_labels.get(plan.status, plan.status)
                
                plans_html += f"""
                <div class="plan-item">
                    <div class="plan-priority">{plan.priority}</div>
                    <div class="plan-info">
                        <div class="plan-name">{plan.plan_name}</div>
                        <div style="font-size: 12px; color: #64748b;">
                            类型: {plan.plan_type} | ID: {plan.plan_id}
                        </div>
                    </div>
                    <span class="plan-status status-{status_class}">{status_text}</span>
                </div>
                """
        else:
            plans_html = f'<p style="color: #64748b; text-align: center; padding: 20px;">{labels["no_plans"]}</p>'
        
        progress_html = ""
        if workflow.progress > 0:
            progress_html = f"""
            <div style="margin-top: 15px;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                    <span style="font-size: 12px; color: #64748b;">执行进度</span>
                    <span style="font-size: 12px; font-weight: 500;">{workflow.progress}%</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {workflow.progress}%;"></div>
                </div>
            </div>
            """
        
        return f"""
        <div class="workflow-section">
            <h2>⚡ {labels['workflow_title']}</h2>
            
            {overview_html}
            
            {progress_html}
            
            <div class="execution-timeline">
                <h3 style="margin-bottom: 15px; color: #333;">📋 {labels['execution_history']}</h3>
                {timeline_html}
            </div>
            
            <div class="task-plans">
                <h3 style="margin-bottom: 15px; color: #333;">📝 {labels['task_plans']}</h3>
                {plans_html}
            </div>
        </div>
        """
    
    def _render_markdown_template(self, report_data: ReportData, language: Language) -> str:
        """渲染 Markdown 模板"""
        summary = report_data.summary
        risk = report_data.risk_assessment
        
        md = f"""# {report_data.task_name}

## 基本信息

- **任务名称**: {report_data.task_name}
- **目标**: {report_data.target}
- **扫描时间**: {report_data.scan_time}

## 风险评估

- **风险评分**: {risk.score}
- **风险等级**: {risk.label}

## 漏洞统计

| 严重程度 | 数量 |
|---------|------|
| 严重 | {summary.critical_count} |
| 高危 | {summary.high_count} |
| 中危 | {summary.medium_count} |
| 低危 | {summary.low_count} |
| 信息 | {summary.info_count} |

"""
        
        if report_data.workflow:
            workflow = report_data.workflow
            completed_count = sum(1 for r in workflow.execution_history if r.status in ["success", "completed"])
            failed_count = sum(1 for r in workflow.execution_history if r.status == "failed")
            total_duration = sum(r.execution_time or 0 for r in workflow.execution_history)
            
            md += f"""## ⚡ 工作流执行详情

### 执行概览

| 指标 | 数值 |
|------|------|
| 总步骤数 | {len(workflow.execution_history)} |
| 已完成 | {completed_count} |
| 失败 | {failed_count} |
| 执行时长 | {total_duration:.2f}s |
| 进度 | {workflow.progress}% |

### 执行历史

"""
            if workflow.execution_history:
                md += "| 步骤 | 名称 | 类型 | 状态 | 耗时 |\n"
                md += "|------|------|------|------|------|\n"
                for idx, record in enumerate(workflow.execution_history):
                    duration_text = f"{record.execution_time:.2f}s" if record.execution_time else "-"
                    md += f"| {idx + 1} | {record.node_name or record.task or 'N/A'} | {record.node_type or 'N/A'} | {record.status} | {duration_text} |\n"
                md += "\n"
            
            if workflow.task_plans:
                md += "### 任务规划\n\n"
                md += "| 优先级 | 名称 | 类型 | 状态 |\n"
                md += "|--------|------|------|------|\n"
                for plan in sorted(workflow.task_plans, key=lambda x: x.priority, reverse=True):
                    md += f"| {plan.priority} | {plan.plan_name} | {plan.plan_type} | {plan.status} |\n"
                md += "\n"

        md += """## 漏洞详情

"""
        for vuln in report_data.vulnerabilities:
            severity = vuln.get("severity", "info").lower()
            config = SEVERITY_CONFIG.get(severity, SEVERITY_CONFIG["info"])
            label = config["label"] if language == Language.ZH_CN else config["label_en"]
            
            md += f"""### {vuln.get('title', vuln.get('name', 'Unknown'))}

- **严重程度**: {label}
- **URL**: {vuln.get('url', 'N/A')}
- **描述**: {vuln.get('description', 'N/A')}
- **修复建议**: {vuln.get('remediation', 'N/A')}

---

"""
        
        if report_data.ai_analysis:
            md += """## 🤖 AI 智能分析

"""
            if report_data.ai_analysis.summary:
                md += f"""### 风险总结

{report_data.ai_analysis.summary}

"""
        
        md += f"\n---\n*报告由 AI_WebSecurity 自动生成 | 生成时间: {report_data.generated_at}*"
        
        return md
    
    def save_report(
        self,
        report_data: ReportData,
        format: ReportFormat = ReportFormat.JSON,
        filename: Optional[str] = None,
        language: Language = Language.ZH_CN
    ) -> str:
        """
        保存报告到文件
        
        Args:
            report_data: 报告数据
            format: 报告格式
            filename: 文件名（可选）
            language: 报告语言
            
        Returns:
            str: 文件路径
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{report_data.task_id}_{timestamp}.{format.value}"
        
        filepath = self.output_dir / filename
        
        if format == ReportFormat.JSON:
            content = self.generate_json_report(report_data)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
        elif format == ReportFormat.HTML:
            content = self.generate_html_report(report_data, language)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
        elif format == ReportFormat.MARKDOWN:
            content = self.generate_markdown_report(report_data, language)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
        elif format == ReportFormat.PDF:
            content = self.generate_pdf_report(report_data, language)
            with open(filepath, "wb") as f:
                f.write(content)
        
        logger.info(f"📄 报告已保存: {filepath}")
        return str(filepath)


report_service = ReportService()
