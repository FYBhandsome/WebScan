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
from html import escape
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
class ConfidenceDimension:
    """置信度分项维度"""
    label: str = ""
    value: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ConfidenceData:
    """AI 等保评估置信度数据

    评估规则未接入前可保持默认值，模板会进行降级展示。
    """
    overall_score: float = 0.0
    level: str = "info"
    standard_text: str = "基于等保2.0（GB/T 22239-2019）三级标准"
    kb_version: str = ""
    dimensions: List[ConfidenceDimension] = field(default_factory=list)
    compliance_estimate: float = 0.0
    compliance_margin: str = ""
    kb_refs: str = ""
    scan_mode: str = ""
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_score": self.overall_score,
            "level": self.level,
            "standard_text": self.standard_text,
            "kb_version": self.kb_version,
            "dimensions": [d.to_dict() for d in self.dimensions],
            "compliance_estimate": self.compliance_estimate,
            "compliance_margin": self.compliance_margin,
            "kb_refs": self.kb_refs,
            "scan_mode": self.scan_mode,
            "note": self.note,
        }


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
    confidence: Optional[ConfidenceData] = None

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
        if self.confidence:
            data["confidence"] = self.confidence.to_dict()
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
        """按照标准安全分析研判报告模板渲染独立 HTML。"""
        summary = report_data.summary
        risk = report_data.risk_assessment
        is_zh = language == Language.ZH_CN

        def html_text(value: Any) -> str:
            return escape("" if value is None else str(value))

        labels = {
            "title": "安全分析研判报告" if is_zh else "Security Analysis Report",
            "subtitle": "标准化渗透扫描安全评估文书 | 安全合规专项检测" if is_zh else "Standardized penetration testing and security assessment",
            "report_no": "报告编号" if is_zh else "Report ID",
            "task": "任务名称" if is_zh else "Task",
            "target": "扫描目标" if is_zh else "Target",
            "scan_time": "扫描执行时间" if is_zh else "Scan Time",
            "generated_at": "报告生成时间" if is_zh else "Generated At",
            "total": "漏洞总数量" if is_zh else "Total Findings",
            "owner": "编制责任人" if is_zh else "Prepared By",
            "owner_value": "安全审计专员" if is_zh else "Security Audit Team",
            "risk_overview": "综合风险概览" if is_zh else "Risk Overview",
            "risk_level": "综合风险等级" if is_zh else "Overall Risk",
            "details": "漏洞明细（按风险优先级排序）" if is_zh else "Findings by Priority",
            "attack_chain": "攻击链路研判" if is_zh else "Attack Path Analysis",
            "compliance": "合规影响说明" if is_zh else "Compliance Impact",
            "fix_plan": "分层加固整改方案" if is_zh else "Remediation Plan",
            "appendix": "查看原始扫描完整数据（Payload、证据、服务配置详情）" if is_zh else "View complete raw scan data",
            "confidence_title": "AI等保评估置信度" if is_zh else "AI MLPS Assessment Confidence",
            "confidence_overall": "综合等保评估置信度" if is_zh else "Overall Confidence",
            "confidence_level_high": "高置信度" if is_zh else "High Confidence",
            "confidence_level_mid": "中置信度" if is_zh else "Medium Confidence",
            "confidence_level_low": "低置信度" if is_zh else "Low Confidence",
            "confidence_level_info": "待评估" if is_zh else "Pending",
            "compliance_estimate": "等保三级符合度预估" if is_zh else "MLPS L3 Compliance Estimate",
            "kb_refs": "知识库检索条目" if is_zh else "KB References",
            "scan_mode": "扫描模式" if is_zh else "Scan Mode",
            "confidence_note_title": "评估说明" if is_zh else "Assessment Note",
            "confidence_kb_ref": "等保2.0知识库" if is_zh else "MLPS 2.0 Knowledge Base",
            "confidence_placeholder": "AI等保评估置信度模块尚在规则接入中，暂未生成置信度数据" if is_zh else "Confidence module is pending rule integration, no data yet",
            "confidence_kb_version": "知识库版本" if is_zh else "KB Version",
        }

        total = max(summary.total_vulnerabilities, 1)
        severity_rows = [
            ("critical", "严重漏洞" if is_zh else "Critical", summary.critical_count),
            ("high", "高危漏洞" if is_zh else "High", summary.high_count),
            ("medium", "中危漏洞" if is_zh else "Medium", summary.medium_count),
            ("low", "低危漏洞" if is_zh else "Low", summary.low_count),
            ("info", "信息类配置缺陷" if is_zh else "Informational", summary.info_count),
        ]
        risk_bars = "".join(
            f'<div class="risk-bar-item"><div class="bar-label">{label}</div>'
            f'<div class="bar-outer"><div class="bar-inner bar-{level}" style="width:{count / total * 100:.1f}%"></div></div>'
            f'<div class="bar-count">{count}</div></div>'
            for level, label, count in severity_rows
        )

        ordered_vulns = sorted(
            report_data.vulnerabilities,
            key=lambda item: SEVERITY_CONFIG.get(str(item.get("severity", "info")).lower(), SEVERITY_CONFIG["info"])["order"]
        )
        vuln_items_html = self._render_vulnerabilities_html(ordered_vulns, language)
        workflow_html = self._render_workflow_html(report_data.workflow, language) if report_data.workflow else ""
        ai_analysis_html = self._render_ai_analysis_html(report_data.ai_analysis, language) if report_data.ai_analysis else ""
        confidence_html = self._render_confidence_html(report_data.confidence, language, labels)

        count_parts = [f"{count}{'项' if is_zh else ''}{label}" for _, label, count in severity_rows if count]
        top_vuln = ordered_vulns[0].get("title", ordered_vulns[0].get("name", "")) if ordered_vulns else ""
        if is_zh:
            risk_summary = (
                f"本次资产扫描共检出 {summary.total_vulnerabilities} 项安全风险"
                + (f"，其中{'、'.join(count_parts)}" if count_parts else "")
                + "。"
            )
            if top_vuln:
                risk_summary += f"当前最高优先级问题为“{top_vuln}”，建议优先完成验证与加固。"
        else:
            risk_summary = f"The scan identified {summary.total_vulnerabilities} finding(s)."
            if top_vuln:
                risk_summary += f" The highest-priority finding is {top_vuln}."

        attack_items = []
        if report_data.ai_analysis and report_data.ai_analysis.risks:
            attack_items.extend(report_data.ai_analysis.risks[:3])
        elif ordered_vulns:
            names = [v.get("title", v.get("name", "Unknown")) for v in ordered_vulns[:3]]
            attack_items.append(("重点风险路径：" if is_zh else "Priority path: ") + " -> ".join(names))
            attack_items.append("应结合漏洞证据和业务边界复核组合利用可能性。" if is_zh else "Validate exploit chaining against evidence and business boundaries.")
        else:
            attack_items.append("本次扫描未形成可研判的漏洞攻击链。" if is_zh else "No attack path was identified in this scan.")

        compliance_items = [
            (f"共发现 {summary.critical_count + summary.high_count} 项严重或高危问题，应纳入优先整改范围。" if is_zh else f"{summary.critical_count + summary.high_count} critical or high finding(s) require priority remediation."),
            ("扫描结果应结合适用的等保、数据安全及行业规范进行人工复核。" if is_zh else "Review findings against applicable regulatory and industry controls."),
            ("配置类问题应纳入持续监测和基线核查机制。" if is_zh else "Configuration findings should be tracked through continuous baseline reviews."),
        ]

        def list_html(items: List[Any]) -> str:
            return "".join(f"<li>{escape(str(item))}</li>" for item in items if item)

        urgent = []
        deadline = []
        long_term = []
        for vuln in ordered_vulns:
            title = vuln.get("title", vuln.get("name", "Unknown"))
            remediation = vuln.get("remediation") or ("复核并修复该漏洞" if is_zh else "Validate and remediate this finding")
            item = f"{title}：{remediation}"
            severity = str(vuln.get("severity", "info")).lower()
            if severity in {"critical", "high"}:
                urgent.append(item)
            elif severity == "medium":
                deadline.append(item)
            else:
                long_term.append(item)
        if report_data.ai_analysis:
            long_term.extend(report_data.ai_analysis.recommendations)
        urgent = urgent or (["暂无严重或高危漏洞，持续复核新增风险。"] if is_zh else ["No critical or high findings; continue monitoring."])
        deadline = deadline or (["复核中危漏洞与业务影响，按计划完成整改。"] if is_zh else ["Review medium findings and remediate on schedule."])
        long_term = long_term or (["建立周期性扫描、补丁更新与安全基线核查机制。"] if is_zh else ["Maintain recurring scans, patching, and baseline reviews."])

        appendix_rows = []
        for index, vuln in enumerate(ordered_vulns, 1):
            details = [
                f"URL: {vuln.get('url') or 'N/A'}",
                f"Payload: {vuln.get('payload') or 'N/A'}",
                f"{'证据' if is_zh else 'Evidence'}: {vuln.get('evidence') or 'N/A'}",
            ]
            appendix_rows.append(
                f'<div class="appendix-entry"><strong>{index}. {escape(str(vuln.get("title", vuln.get("name", "Unknown"))))}</strong>'
                + "".join(f"<p>{escape(str(detail))}</p>" for detail in details)
                + "</div>"
            )
        if report_data.tool_results:
            appendix_rows.append(
                f'<div class="appendix-entry"><strong>{"工具执行结果" if is_zh else "Tool Results"}</strong>'
                f'<pre>{escape(json.dumps(report_data.tool_results, ensure_ascii=False, indent=2, default=str))}</pre></div>'
            )
        if not appendix_rows:
            appendix_rows.append(f'<p>{"暂无原始漏洞数据。" if is_zh else "No raw finding data."}</p>')

        safe_task_id = "".join(ch for ch in str(report_data.task_id) if ch.isalnum() or ch in "-_") or "NA"
        date_token = "".join(ch for ch in str(report_data.generated_at)[:10] if ch.isdigit()) or datetime.now().strftime("%Y%m%d")
        report_no = f"SEC-{date_token}-{safe_task_id}"
        risk_level = str(risk.level or "info").lower()
        risk_color = SEVERITY_CONFIG.get(risk_level, SEVERITY_CONFIG["info"])["color"]
        try:
            risk_score = float(risk.score)
        except (TypeError, ValueError):
            risk_score = 0.0

        styles = """
        * { margin: 0; padding: 0; box-sizing: border-box; }
        :root { --gap-sm: 10px; --gap-md: 12px; --gap-lg: 24px; --gap-xl: 24px; --radius: 4px; --border: #e5e7eb; --primary: #165dff; --critical: #d93025; --high: #e67e22; --medium: #d4a017; --low: #165dff; --info: #888; --confidence-high: #165dff; --confidence-mid: #e67e22; --confidence-low: #d93025; }
        body { background: #f7f8fa; padding: 32px; color: #222; line-height: 1.8; font-family: "Source Han Sans CN", "Microsoft YaHei UI", "Microsoft YaHei", sans-serif; -webkit-font-smoothing: antialiased; }
        .report-shell { width: min(1440px, 100%); margin: 0 auto; }
        .card, .report-header, .appendix-card { background: #fff; border: 1px solid var(--border); border-radius: var(--radius); padding: var(--gap-lg); }
        .report-header, .risk-overview, .confidence-module, .two-col-container, .fix-plan-container, .workflow-section, .ai-section { margin-bottom: var(--gap-xl); }
        .header-top, .module-title { display: flex; align-items: center; gap: var(--gap-sm); font-weight: 700; }
        .header-top { font-size: 22px; margin-bottom: var(--gap-sm); }
        .header-subtitle { font: 13px "Source Han Serif CN", SimSun, serif; color: #666; margin-bottom: var(--gap-lg); }
        .icon-svg { width: 20px; height: 20px; fill: var(--primary); flex: 0 0 20px; }
        .meta-wrap { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: var(--gap-md); }
        .meta-item { display: flex; flex-direction: column; gap: 4px; min-width: 0; }
        .meta-label { font-weight: 500; color: #444; }
        .text-body, .text-tip { font-family: "Source Han Serif CN", SimSun, serif; color: #333; overflow-wrap: anywhere; }
        .text-body { font-size: 14px; text-align: justify; }
        .text-tip { font-size: 13px; color: #666; }
        .module-title { font-size: 18px; padding-bottom: var(--gap-sm); border-bottom: 1px solid var(--border); margin-bottom: var(--gap-lg); }
        .risk-head-row { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: var(--gap-lg); margin-bottom: var(--gap-md); }
        .risk-score-box { display: flex; align-items: baseline; gap: var(--gap-sm); }
        .score-num { font-size: 24px; font-weight: 700; }
        .score-desc { font-size: 14px; font-weight: 600; }
        .risk-bar-group { display: flex; gap: var(--gap-md); flex: 1; min-width: 520px; }
        .risk-bar-item { flex: 1; text-align: center; min-width: 72px; }
        .bar-label { min-height: 24px; font-size: 12px; color: #666; }
        .bar-outer { height: 6px; background: #eee; border-radius: 3px; overflow: hidden; }
        .bar-inner { height: 100%; } .bar-critical { background: var(--critical); } .bar-high { background: var(--high); } .bar-medium { background: var(--medium); } .bar-low { background: var(--low); } .bar-info { background: var(--info); }
        .bar-count { margin-top: 4px; font-size: 13px; font-weight: 600; }
        .risk-desc-block p + p { margin-top: var(--gap-sm); }
        .two-col-container { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: var(--gap-lg); align-items: stretch; }
        .right-col { display: flex; flex-direction: column; gap: var(--gap-lg); }
        .right-col > .card { flex: 1; }
        .vuln-list-wrap { display: flex; flex-direction: column; gap: var(--gap-md); }
        .vuln-item { border: 1px solid var(--border); border-radius: var(--radius); padding: var(--gap-md); }
        .vuln-item summary { cursor: pointer; list-style: none; }
        .vuln-item summary::-webkit-details-marker { display: none; }
        .vuln-title-row { display: flex; align-items: center; gap: var(--gap-sm); font-size: 15px; font-weight: 600; }
        .risk-tag { flex: 0 0 auto; min-width: 46px; padding: 2px 8px; border-radius: 2px; color: #fff; text-align: center; font-size: 12px; }
        .tag-critical { background: var(--critical); } .tag-high { background: var(--high); } .tag-medium { background: var(--medium); } .tag-low { background: var(--low); } .tag-info { background: var(--info); }
        .vuln-tip-text { margin-top: 6px; font: 13px "Source Han Serif CN", SimSun, serif; color: #555; overflow-wrap: anywhere; }
        .vuln-detail { margin-top: var(--gap-md); padding-top: var(--gap-md); border-top: 1px dashed var(--border); }
        .vuln-detail p + p { margin-top: 6px; }
        .list-uniform { list-style: none; }
        .list-uniform li { display: flex; gap: var(--gap-sm); margin-bottom: var(--gap-sm); font: 14px "Source Han Serif CN", SimSun, serif; overflow-wrap: anywhere; }
        .list-uniform li::before { content: "-"; color: #666; flex: 0 0 auto; }
        .fix-three-col { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: var(--gap-lg); }
        .fix-block { padding: var(--gap-lg); border-radius: var(--radius); }
        .fix-emergency { background: #fef2f2; } .fix-deadline { background: #fffbeb; } .fix-longterm { background: #f9fafb; }
        .fix-block-title { margin-bottom: var(--gap-md); font-size: 15px; font-weight: 700; }
        .ai-grid, .workflow-overview { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: var(--gap-md); }
        .analysis-block, .workflow-stat { padding: var(--gap-md); background: #f9fafb; border: 1px solid var(--border); border-radius: var(--radius); }
        .analysis-block h3 { margin-bottom: 8px; font-size: 15px; }
        .workflow-stat { text-align: center; } .workflow-stat .value { font-size: 22px; font-weight: 700; color: var(--primary); } .workflow-stat .label { font-size: 12px; color: #666; }
        .execution-timeline, .task-plans { margin-top: var(--gap-lg); }
        .timeline-item, .plan-item { display: flex; gap: var(--gap-md); padding: var(--gap-md); margin-top: var(--gap-sm); background: #f9fafb; border-left: 3px solid var(--primary); }
        .timeline-step, .plan-priority { width: 30px; height: 30px; flex: 0 0 30px; display: grid; place-items: center; background: var(--primary); color: #fff; font-size: 12px; font-weight: 700; }
        .timeline-content, .plan-info { min-width: 0; flex: 1; } .timeline-title, .plan-name { font-weight: 600; } .timeline-meta, .timeline-duration { font-size: 12px; color: #666; }
        .plan-status { align-self: center; padding: 2px 8px; border: 1px solid var(--border); font-size: 11px; }
        .progress-bar { width: 100%; height: 6px; margin-top: var(--gap-md); background: #eee; overflow: hidden; } .progress-fill { height: 100%; background: var(--primary); }
        .appendix-summary { display: flex; align-items: center; gap: var(--gap-sm); cursor: pointer; font-size: 14px; color: var(--primary); }
        .appendix-content { margin-top: var(--gap-md); padding-top: var(--gap-md); border-top: 1px dashed var(--border); font: 13px "Source Han Serif CN", SimSun, serif; color: #555; }
        .appendix-entry + .appendix-entry { margin-top: var(--gap-md); padding-top: var(--gap-md); border-top: 1px solid var(--border); }
        pre { max-height: 360px; overflow: auto; margin-top: 8px; padding: 12px; background: #f7f8fa; border: 1px solid var(--border); white-space: pre-wrap; overflow-wrap: anywhere; font: 12px Consolas, monospace; }
        .empty-state { padding: 24px; color: #666; text-align: center; }
        .footer { padding: 20px; color: #666; text-align: center; font-size: 12px; }
        .confidence-header { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: var(--gap-sm); margin-bottom: var(--gap-md); padding-bottom: var(--gap-sm); border-bottom: 1px solid var(--border); }
        .confidence-header .standard-badge { font-size: 13px; background: #e8f0fe; color: var(--primary); padding: 2px 12px; border-radius: 12px; border: 1px solid rgba(22, 93, 255, 0.15); white-space: nowrap; font-weight: 500; }
        .confidence-standard-text { font-size: 14px; color: #555; font-weight: 500; }
        .confidence-summary { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: var(--gap-lg); margin-bottom: var(--gap-md); }
        .confidence-score-wrap { display: flex; align-items: baseline; gap: var(--gap-sm); }
        .confidence-number { font-size: 28px; font-weight: 700; color: var(--confidence-high); }
        .confidence-number-label { font-size: 14px; color: #444; font-weight: 500; }
        .confidence-level-badge { padding: 4px 14px; border-radius: 20px; font-size: 14px; font-weight: 600; letter-spacing: 0.3px; background: #e8f0fe; color: var(--confidence-high); border: 1px solid rgba(22, 93, 255, 0.2); white-space: nowrap; }
        .confidence-level-badge.level-high { background: #e8f0fe; color: var(--confidence-high); border-color: rgba(22, 93, 255, 0.25); }
        .confidence-level-badge.level-mid { background: #fef3e8; color: var(--confidence-mid); border-color: rgba(230, 126, 34, 0.25); }
        .confidence-level-badge.level-low { background: #fde8e8; color: var(--confidence-low); border-color: rgba(217, 48, 37, 0.25); }
        .confidence-level-badge.level-info { background: #f0f2f5; color: var(--info); border-color: var(--border); }
        .confidence-details { display: flex; flex-direction: column; gap: var(--gap-md); margin-bottom: var(--gap-md); }
        .confidence-item { display: flex; align-items: center; gap: var(--gap-sm); }
        .confidence-item .item-label { font-size: 14px; color: #444; font-family: "Source Han Serif CN", SimSun, serif; min-width: 140px; flex-shrink: 0; }
        .confidence-item .item-bar-track { flex: 1; height: 6px; background: #eee; border-radius: 3px; overflow: hidden; }
        .confidence-item .item-bar-fill { height: 100%; border-radius: 3px; background: var(--confidence-high); transition: width 0.6s ease; }
        .confidence-item .item-value { font-size: 14px; font-weight: 600; color: #222; min-width: 42px; text-align: right; font-family: "Source Han Sans CN", "Microsoft YaHei UI", sans-serif; }
        .compliance-extra { display: flex; align-items: center; gap: var(--gap-lg); padding: var(--gap-sm) 0; margin-top: var(--gap-sm); border-top: 1px dashed var(--border); flex-wrap: wrap; }
        .compliance-extra .extra-item { display: flex; align-items: baseline; gap: 6px; font-size: 14px; color: #444; font-family: "Source Han Serif CN", SimSun, serif; }
        .compliance-extra .extra-item .extra-value { font-weight: 700; color: #222; }
        .compliance-extra .extra-item .extra-tag { background: #f0f2f5; padding: 0 8px; border-radius: 4px; font-size: 12px; color: #666; }
        .confidence-note { padding-top: var(--gap-md); border-top: 1px dashed var(--border); font-size: 13px; color: #666; font-family: "Source Han Serif CN", SimSun, serif; line-height: 1.7; }
        .confidence-note strong { color: #222; }
        .confidence-note .kb-ref { display: inline-block; background: #f0f4ff; padding: 0 6px; border-radius: 3px; font-size: 12px; color: var(--primary); border: 1px solid rgba(22, 93, 255, 0.1); }
        .confidence-placeholder { padding: 24px; color: #888; text-align: center; font-size: 14px; font-family: "Source Han Serif CN", SimSun, serif; }
        @media (max-width: 900px) { body { padding: 16px; } .two-col-container, .fix-three-col { grid-template-columns: 1fr; } .risk-bar-group { min-width: 100%; overflow-x: auto; } }
        @media (max-width: 768px) { .confidence-summary { flex-direction: column; align-items: flex-start; } .confidence-item { flex-wrap: wrap; } .confidence-item .item-label { min-width: 100px; font-size: 13px; } .compliance-extra { flex-direction: column; align-items: flex-start; gap: var(--gap-sm); } .score-num { font-size: 20px; } .confidence-number { font-size: 24px; } }
        @media (max-width: 560px) { body { padding: 10px; } .card, .report-header, .appendix-card { padding: 16px; } .meta-wrap { grid-template-columns: 1fr; } .risk-bar-group { display: grid; grid-template-columns: repeat(2, 1fr); } .confidence-item .item-label { min-width: 80px; } .confidence-level-badge { font-size: 12px; padding: 2px 10px; } .confidence-header .standard-badge { font-size: 11px; padding: 0 8px; } }
        @media print { @page { size: A4; margin: 12mm; } body { padding: 0; background: #fff; } .report-shell { width: 100%; } .card, .report-header, .appendix-card { break-inside: avoid; } .confidence-module { break-inside: avoid; } details { display: block; } details > .appendix-content { display: block; } }
        .md-content { line-height: 1.8; }
        .md-content h1, .md-content h2, .md-content h3, .md-content h4 { margin: 0.6em 0 0.3em; font-weight: 600; color: #1a1a1a; }
        .md-content h1 { font-size: 1.2em; }
        .md-content h2 { font-size: 1.1em; }
        .md-content h3 { font-size: 1em; }
        .md-content ul, .md-content ol { margin: 0.3em 0; padding-left: 1.5em; }
        .md-content li { margin: 0.2em 0; }
        .md-content code { background: rgba(0,0,0,0.06); padding: 0.1em 0.4em; border-radius: 3px; font-family: 'SF Mono', Consolas, monospace; font-size: 0.9em; }
        .md-content pre { background: rgba(0,0,0,0.04); padding: 0.8em; border-radius: 6px; overflow-x: auto; margin: 0.5em 0; }
        .md-content pre code { background: none; padding: 0; }
        .md-content strong { font-weight: 600; }
        .md-content em { font-style: italic; }
        .md-content blockquote { border-left: 3px solid #165dff; padding-left: 1em; color: #555; margin: 0.5em 0; }
        .md-content p { margin: 0.3em 0; }
        """

        icon = '<svg class="icon-svg" viewBox="0 0 24 24" aria-hidden="true"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-5 14h-4v-2h4v2zm2-4H8v-2h8v2zm0-4H8V7h8v2z"/></svg>'

        return f"""<!DOCTYPE html>
<html lang="{'zh-CN' if language == Language.ZH_CN else 'en'}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html_text(report_data.task_name or labels['title'])}</title>
    <style>{styles}</style>
</head>
<body>
    <main class="report-shell">
        <header class="report-header">
            <h1 class="header-top">{icon}{labels['title']}</h1>
            <div class="header-subtitle">{labels['subtitle']}</div>
            <div class="meta-wrap">
                <div class="meta-item"><span class="meta-label">{labels['report_no']}：</span><span class="text-body">{html_text(report_no)}</span></div>
                <div class="meta-item"><span class="meta-label">{labels['task']}：</span><span class="text-body">{html_text(report_data.task_name)}</span></div>
                <div class="meta-item"><span class="meta-label">{labels['target']}：</span><span class="text-body">{html_text(report_data.target)}</span></div>
                <div class="meta-item"><span class="meta-label">{labels['scan_time']}：</span><span class="text-body">{html_text(report_data.scan_time)}</span></div>
                <div class="meta-item"><span class="meta-label">{labels['generated_at']}：</span><span class="text-body">{html_text(report_data.generated_at)}</span></div>
                <div class="meta-item"><span class="meta-label">{labels['total']}：</span><span class="text-body">{summary.total_vulnerabilities} {'项' if is_zh else ''}</span></div>
                <div class="meta-item"><span class="meta-label">{labels['owner']}：</span><span class="text-body">{labels['owner_value']}</span></div>
            </div>
        </header>

        <section class="card risk-overview">
            <h2 class="module-title">{icon}{labels['risk_overview']}</h2>
            <div class="risk-head-row">
                <div class="risk-score-box"><span class="score-num" style="color:{risk_color}">{risk_score:g}</span><span class="score-desc" style="color:{risk_color}">{labels['risk_level']}：{html_text(risk.label)} ({html_text(risk_level.upper())})</span></div>
                <div class="risk-bar-group">{risk_bars}</div>
            </div>
            <div class="risk-desc-block text-body"><p>{escape(risk_summary)}</p></div>
        </section>

        {confidence_html}

        <div class="two-col-container">
            <section class="card left-col">
                <h2 class="module-title">{icon}{labels['details']}</h2>
                <div class="vuln-list-wrap">{vuln_items_html or f'<p class="empty-state">{"未发现漏洞" if is_zh else "No findings"}</p>'}</div>
            </section>
            <div class="right-col">
                <section class="card"><h2 class="module-title">{icon}{labels['attack_chain']}</h2><ul class="list-uniform">{list_html(attack_items)}</ul></section>
                <section class="card"><h2 class="module-title">{icon}{labels['compliance']}</h2><ul class="list-uniform">{list_html(compliance_items)}</ul></section>
            </div>
        </div>

        <section class="card fix-plan-container">
            <h2 class="module-title">{icon}{labels['fix_plan']}</h2>
            <div class="fix-three-col">
                <div class="fix-block fix-emergency"><h3 class="fix-block-title">{'紧急修复（7日内完成）' if is_zh else 'Urgent (within 7 days)'}</h3><ul class="list-uniform">{list_html(urgent[:6])}</ul></div>
                <div class="fix-block fix-deadline"><h3 class="fix-block-title">{'限期整改（30日内完成）' if is_zh else 'Scheduled (within 30 days)'}</h3><ul class="list-uniform">{list_html(deadline[:6])}</ul></div>
                <div class="fix-block fix-longterm"><h3 class="fix-block-title">{'常态化长效优化' if is_zh else 'Continuous improvement'}</h3><ul class="list-uniform">{list_html(long_term[:6])}</ul></div>
            </div>
        </section>

        {workflow_html}
        {ai_analysis_html}

        <section class="appendix-card">
            <details>
                <summary class="appendix-summary">{icon}{labels['appendix']}</summary>
                <div class="appendix-content">{''.join(appendix_rows)}</div>
            </details>
        </section>
        <div class="footer">
            <p>{'报告由 WebScan 自动生成' if is_zh else 'Generated by WebScan'} | {labels['generated_at']}: {html_text(report_data.generated_at)}</p>
        </div>
    </main>
</body>
</html>"""
    
    def _render_vulnerabilities_html(self, vulnerabilities: List[Dict[str, Any]], language: Language) -> str:
        """渲染漏洞列表 HTML"""
        if not vulnerabilities:
            return ""
        
        is_zh = language == Language.ZH_CN
        html = ""
        for vuln in vulnerabilities:
            severity = str(vuln.get("severity") or "info").lower()
            if severity not in SEVERITY_CONFIG:
                severity = "info"
            config = SEVERITY_CONFIG.get(severity, SEVERITY_CONFIG["info"])
            label = config["label"] if language == Language.ZH_CN else config["label_en"]
            title = escape(str(vuln.get('title', vuln.get('name', 'Unknown'))))
            url = escape(str(vuln.get('url') or 'N/A'))
            description = escape(str(vuln.get('description') or ('暂无描述' if is_zh else 'No description')))
            remediation = escape(str(vuln.get('remediation') or ('暂无修复建议' if is_zh else 'No remediation guidance')))

            html += f"""
            <details class="vuln-item">
                <summary>
                    <div class="vuln-title-row"><span class="risk-tag tag-{severity}">{label}</span>{title}</div>
                    <div class="vuln-tip-text">{'风险简述' if is_zh else 'Summary'}：{description}</div>
                </summary>
                <div class="vuln-detail text-body">
                    <p><strong>URL：</strong>{url}</p>
                    <p><strong>{'修复建议' if is_zh else 'Remediation'}：</strong>{remediation}</p>
                </div>
            </details>
            """
        
        return html

    @staticmethod
    def _md_to_html(text: str) -> str:
        """将Markdown文本转换为HTML，保留标题/列表/粗体等格式"""
        import markdown as md
        html = md.markdown(
            str(text),
            extensions=['sane_lists'],
            output_format='html'
        )
        # 移除外层<p>标签（模板已有容器包裹，避免双重嵌套）
        if html.startswith('<p>') and html.endswith('</p>'):
            html = html[3:-4]
        return html

    def _render_ai_analysis_html(self, ai_analysis: AIAnalysisData, language: Language) -> str:
        """渲染 AI 分析 HTML"""
        if not ai_analysis:
            return ""

        is_zh = language == Language.ZH_CN
        labels = {
            "ai_analysis": "AI 智能分析" if language == Language.ZH_CN else "AI Analysis",
            "summary": "风险总结" if language == Language.ZH_CN else "Summary",
            "causes": "漏洞成因" if language == Language.ZH_CN else "Causes",
            "risks": "利用风险" if language == Language.ZH_CN else "Risks",
            "priorities": "修复优先级" if language == Language.ZH_CN else "Priorities",
            "recommendations": "综合建议" if language == Language.ZH_CN else "Recommendations",
        }

        blocks = []
        if ai_analysis.summary:
            blocks.append(f'<div class="analysis-block"><h3>{labels["summary"]}</h3><div class="text-body md-content">{self._md_to_html(ai_analysis.summary)}</div></div>')

        if ai_analysis.causes:
            items = "".join(f"<li>{self._md_to_html(cause)}</li>" for cause in ai_analysis.causes)
            blocks.append(f'<div class="analysis-block"><h3>{labels["causes"]}</h3><ul class="list-uniform">{items}</ul></div>')

        if ai_analysis.risks:
            items = "".join(f"<li>{self._md_to_html(risk)}</li>" for risk in ai_analysis.risks)
            blocks.append(f'<div class="analysis-block"><h3>{labels["risks"]}</h3><ul class="list-uniform">{items}</ul></div>')

        if ai_analysis.priorities:
            priority_label = "优先级" if is_zh else "Priority"
            items = "".join(
                f'<li>{self._md_to_html(p.get("vulnerability", ""))}：{priority_label} {p.get("priority", 0)}'
                f'{("，" + self._md_to_html(p.get("reason"))) if p.get("reason") else ""}</li>'
                for p in ai_analysis.priorities
            )
            blocks.append(f'<div class="analysis-block"><h3>{labels["priorities"]}</h3><ul class="list-uniform">{items}</ul></div>')

        if ai_analysis.recommendations:
            items = "".join(f"<li>{self._md_to_html(item)}</li>" for item in ai_analysis.recommendations)
            blocks.append(f'<div class="analysis-block"><h3>{labels["recommendations"]}</h3><ul class="list-uniform">{items}</ul></div>')

        if not blocks:
            return ""

        icon = '<svg class="icon-svg" viewBox="0 0 24 24" aria-hidden="true"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-5 14h-4v-2h4v2zm2-4H8v-2h8v2zm0-4H8V7h8v2z"/></svg>'
        return f'<section class="card ai-section"><h2 class="module-title">{icon}{labels["ai_analysis"]}</h2><div class="ai-grid">{"".join(blocks)}</div></section>'

    def _render_confidence_html(self, confidence: Optional["ConfidenceData"], language: Language, labels: Dict[str, str]) -> str:
        """渲染 AI 等保评估置信度 HTML

        当 confidence 为 None 或尚未填充数据时，展示降级占位说明，
        便于在评判规则接入前保持模块可见。
        """
        is_zh = language == Language.ZH_CN
        icon = '<svg class="icon-svg" viewBox="0 0 24 24" aria-hidden="true"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-7 14c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.2-7.2c0 1.3-1.1 2.3-2.4 2.3H11c-.6 0-1-.4-1-1v-6c0-.6.4-1 1-1h1.8c1.3 0 2.4 1 2.4 2.3z"/></svg>'

        # 降级占位：评判规则尚未接入
        if not confidence or (confidence.overall_score <= 0 and not confidence.dimensions):
            placeholder = labels["confidence_placeholder"]
            return (
                f'<section class="card confidence-module">'
                f'<h2 class="module-title">{icon}{labels["confidence_title"]}</h2>'
                f'<p class="confidence-placeholder">{escape(placeholder)}</p>'
                f'</section>'
            )

        # 等级判定：>=80 高 / 60-79 中 / <60 低
        score = max(0.0, min(100.0, float(confidence.overall_score or 0)))
        level_key = str(confidence.level or "").lower()
        if level_key not in ("high", "mid", "low", "info"):
            if score >= 80:
                level_key = "high"
            elif score >= 60:
                level_key = "mid"
            elif score > 0:
                level_key = "low"
            else:
                level_key = "info"

        level_label_map = {
            "high": labels["confidence_level_high"],
            "mid": labels["confidence_level_mid"],
            "low": labels["confidence_level_low"],
            "info": labels["confidence_level_info"],
        }
        level_label = level_label_map.get(level_key, labels["confidence_level_info"])

        # 标准标识行
        standard_text = escape(str(confidence.standard_text or ""))
        kb_version = escape(str(confidence.kb_version or ""))
        standard_badge_html = (
            f'<span class="standard-badge">{labels["confidence_kb_version"]} {kb_version}</span>'
            if kb_version else ""
        )
        header_html = (
            f'<div class="confidence-header">'
            f'<span class="confidence-standard-text">{standard_text}</span>'
            f'{standard_badge_html}'
            f'</div>'
        )

        # 综合置信度
        score_display = f"{score:.0f}%" if score > 0 else "—"
        summary_html = (
            f'<div class="confidence-summary">'
            f'<div class="confidence-score-wrap">'
            f'<span class="confidence-number">{score_display}</span>'
            f'<span class="confidence-number-label">{labels["confidence_overall"]}</span>'
            f'</div>'
            f'<span class="confidence-level-badge level-{level_key}">{escape(level_label)}</span>'
            f'</div>'
        )

        # 分项置信度
        details_html = ""
        if confidence.dimensions:
            items_html = ""
            for dim in confidence.dimensions:
                dim_value = max(0.0, min(100.0, float(dim.value or 0)))
                dim_label = escape(str(dim.label or ""))
                items_html += (
                    f'<div class="confidence-item">'
                    f'<span class="item-label">{dim_label}</span>'
                    f'<div class="item-bar-track"><div class="item-bar-fill" style="width:{dim_value:.1f}%;"></div></div>'
                    f'<span class="item-value">{dim_value:.0f}%</span>'
                    f'</div>'
                )
            details_html = f'<div class="confidence-details">{items_html}</div>'

        # 等保符合度附加信息
        extra_html = ""
        extra_items = []
        if confidence.compliance_estimate > 0:
            margin = escape(str(confidence.compliance_margin or "")) if confidence.compliance_margin else ""
            margin_tag = f'<span class="extra-tag">{margin}</span>' if margin else ""
            extra_items.append(
                f'<span class="extra-item">'
                f'<span>📊 {labels["compliance_estimate"]}：</span>'
                f'<span class="extra-value">{confidence.compliance_estimate:.0f}%</span>'
                f'{margin_tag}'
                f'</span>'
            )
        if confidence.kb_refs:
            extra_items.append(
                f'<span class="extra-item">'
                f'<span>📌 {labels["kb_refs"]}：</span>'
                f'<span class="extra-value" style="font-weight:400; font-size:13px; color:#666;">{escape(str(confidence.kb_refs))}</span>'
                f'</span>'
            )
        if confidence.scan_mode:
            extra_items.append(
                f'<span class="extra-item">'
                f'<span>⚙️ {labels["scan_mode"]}：</span>'
                f'<span class="extra-value" style="font-weight:400; font-size:13px; color:#666;">{escape(str(confidence.scan_mode))}</span>'
                f'</span>'
            )
        if extra_items:
            extra_html = f'<div class="compliance-extra">{"".join(extra_items)}</div>'

        # 评估说明
        note_html = ""
        note_text = confidence.note or ""
        if not note_text:
            # 默认说明模板
            if is_zh:
                note_text = (
                    f'<strong>📋 {labels["confidence_note_title"]}：</strong>本置信度由AI综合漏洞扫描结果与'
                    f'<span class="kb-ref">{labels["confidence_kb_ref"]}</span> 进行多维匹配得出。'
                    f'整体置信度达到 <strong>{score_display}</strong>，'
                    f'建议安全专家结合业务实际，对低置信度项（＜70%）进行人工复核，确保等保合规整改的准确性。'
                )
            else:
                note_text = (
                    f'<strong>📋 {labels["confidence_note_title"]}:</strong> Confidence is computed by matching '
                    f'scan results against the <span class="kb-ref">{labels["confidence_kb_ref"]}</span>. '
                    f'Overall confidence is <strong>{score_display}</strong>. '
                    f'Review items below 70% manually to ensure compliance accuracy.'
                )
        note_html = f'<div class="confidence-note">{note_text}</div>'

        return (
            f'<section class="card confidence-module">'
            f'<h2 class="module-title">{icon}{labels["confidence_title"]}</h2>'
            f'{header_html}'
            f'{summary_html}'
            f'{details_html}'
            f'{extra_html}'
            f'{note_html}'
            f'</section>'
        )

    def _render_workflow_html(self, workflow: WorkflowData, language: Language) -> str:
        """渲染工作流数据 HTML"""
        if not workflow:
            return ""

        is_zh = language == Language.ZH_CN
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
                status_text = escape(str(status_labels.get(record.status, record.status)))
                duration_text = f"{record.execution_time:.2f}s" if record.execution_time else "-"
                record_name = escape(str(record.node_name or record.task or f'{"步骤" if is_zh else "Step"} {idx + 1}'))
                node_type = escape(str(record.node_type or 'N/A'))
                tool_name = escape(str(record.tool_name or 'N/A'))
                error_html = f'<div style="color:#d93025;margin-top:5px;font-size:12px;">{"错误" if is_zh else "Error"}: {escape(str(record.error))}</div>' if record.error else ''
                
                timeline_html += f"""
                <div class="timeline-item {status_class}">
                    <div class="timeline-step">{idx + 1}</div>
                    <div class="timeline-content">
                        <div class="timeline-title">{record_name}</div>
                        <div class="timeline-meta">
                            <span>{'类型' if is_zh else 'Type'}: {node_type}</span>
                            <span style="margin-left:15px;">{labels['status']}: {status_text}</span>
                            <span style="margin-left:15px;">{'工具' if is_zh else 'Tool'}: {tool_name}</span>
                        </div>
                        {f'<div class="timeline-duration">{labels["duration"]}: {duration_text}</div>' if record.execution_time else ''}
                        {error_html}
                    </div>
                </div>
                """
        else:
            timeline_html = f'<p style="color: #64748b; text-align: center; padding: 20px;">{labels["no_records"]}</p>'
        
        plans_html = ""
        if workflow.task_plans:
            for plan in sorted(workflow.task_plans, key=lambda x: x.priority, reverse=True):
                status_class = plan.status if plan.status in ["completed", "running", "pending", "failed"] else "pending"
                status_text = escape(str(status_labels.get(plan.status, plan.status)))
                
                plans_html += f"""
                <div class="plan-item">
                    <div class="plan-priority">{escape(str(plan.priority))}</div>
                    <div class="plan-info">
                        <div class="plan-name">{escape(str(plan.plan_name))}</div>
                        <div class="timeline-meta">
                            {'类型' if is_zh else 'Type'}: {escape(str(plan.plan_type))} | ID: {escape(str(plan.plan_id))}
                        </div>
                    </div>
                    <span class="plan-status status-{status_class}">{status_text}</span>
                </div>
                """
        else:
            plans_html = f'<p style="color: #64748b; text-align: center; padding: 20px;">{labels["no_plans"]}</p>'
        
        progress_html = ""
        if workflow.progress > 0:
            progress = max(0, min(100, workflow.progress))
            progress_html = f"""
            <div style="margin-top: 15px;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                    <span class="text-tip">{'执行进度' if is_zh else 'Progress'}</span>
                    <span style="font-size:12px;font-weight:500;">{progress}%</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width:{progress}%;"></div>
                </div>
            </div>
            """

        icon = '<svg class="icon-svg" viewBox="0 0 24 24" aria-hidden="true"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-5 14h-4v-2h4v2zm2-4H8v-2h8v2zm0-4H8V7h8v2z"/></svg>'
        return f"""
        <section class="card workflow-section">
            <h2 class="module-title">{icon}{labels['workflow_title']}</h2>
            
            {overview_html}
            
            {progress_html}
            
            <div class="execution-timeline">
                <h3>{labels['execution_history']}</h3>
                {timeline_html}
            </div>
            
            <div class="task-plans">
                <h3>{labels['task_plans']}</h3>
                {plans_html}
            </div>
        </section>
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
