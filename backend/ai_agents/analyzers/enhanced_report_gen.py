"""
增强版报告生成器

集成 AI 分析功能的扫描报告生成模块。
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class TargetInfo:
    url: str = ""


@dataclass
class TimingInfo:
    start_time: str = ""
    end_time: str = ""
    total_duration_ms: float = 0.0


@dataclass
class AIAnalysis:
    vulnerability_causes: List[str] = field(default_factory=list)
    exploitation_risks: List[str] = field(default_factory=list)
    remediation_priorities: List[str] = field(default_factory=list)
    business_impact: List[str] = field(default_factory=list)
    analysis_evidence: List[str] = field(default_factory=list)


@dataclass
class ToolStep:
    step_number: int = 0
    tool_name: str = ""
    timestamp: str = ""


@dataclass
class GraphNode:
    node_id: str = ""
    node_name: str = ""
    status: str = ""


@dataclass
class Subgraph:
    subgraph_id: str = ""
    subgraph_name: str = ""
    nodes: List[GraphNode] = field(default_factory=list)


@dataclass
class GraphFlow:
    subgraphs: List[Subgraph] = field(default_factory=list)


@dataclass
class ReportData:
    task_id: str = ""
    task_name: str = ""
    target: TargetInfo = field(default_factory=TargetInfo)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    timing: TimingInfo = field(default_factory=TimingInfo)
    ai_analysis: AIAnalysis = field(default_factory=AIAnalysis)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    tool_execution_flow: List[ToolStep] = field(default_factory=list)
    graph_flow: GraphFlow = field(default_factory=GraphFlow)


class EnhancedReportGenerator:

    def __init__(self, auto_ai_analysis: bool = True):
        self.auto_ai_analysis = auto_ai_analysis
        logger.info("📄 增强版报告生成器初始化完成（AI分析: %s）", auto_ai_analysis)

    async def generate_from_state(self, state: Any, task_name: str = "") -> ReportData:
        now = datetime.now().isoformat()

        timing = TimingInfo(
            start_time=now,
            end_time=now,
            total_duration_ms=0.0,
        )

        target_url = getattr(state, 'target', '')
        task_id = getattr(state, 'task_id', '')

        vulnerabilities = []
        if hasattr(state, 'vulnerabilities'):
            vulnerabilities = [
                {"id": v.get("id", ""), "name": v.get("name", ""), "severity": v.get("severity", "info")}
                for v in state.vulnerabilities
            ]

        completed_tasks = getattr(state, 'completed_tasks', [])
        tool_flow = []
        for i, task in enumerate(completed_tasks):
            tool_flow.append(ToolStep(
                step_number=i + 1,
                tool_name=task if isinstance(task, str) else str(task),
                timestamp=now,
            ))

        graph_nodes = []
        for i, task in enumerate(completed_tasks):
            graph_nodes.append(GraphNode(
                node_id=f"node_{i}",
                node_name=task if isinstance(task, str) else str(task),
                status="completed",
            ))

        subgraph = Subgraph(
            subgraph_id="main",
            subgraph_name="安全扫描流程",
            nodes=graph_nodes,
        )

        graph_flow = GraphFlow(subgraphs=[subgraph])

        ai_analysis = AIAnalysis(
            vulnerability_causes=["待AI分析填充"] if vulnerabilities else [],
            exploitation_risks=["待AI分析填充"] if vulnerabilities else [],
            remediation_priorities=["待AI分析填充"] if vulnerabilities else [],
            business_impact=["待AI分析填充"] if vulnerabilities else [],
            analysis_evidence=["待AI分析填充"] if vulnerabilities else [],
        )

        report_data = ReportData(
            task_id=task_id,
            task_name=task_name,
            target=TargetInfo(url=target_url),
            vulnerabilities=vulnerabilities,
            timing=timing,
            ai_analysis=ai_analysis,
            raw_data={"execution_history": [str(t) for t in completed_tasks]},
            tool_execution_flow=tool_flow,
            graph_flow=graph_flow,
        )

        logger.info("📊 报告数据生成完成 | 任务: %s | 漏洞数: %d", task_name, len(vulnerabilities))
        return report_data

    def generate_json_report(self, report_data: ReportData) -> str:
        report_dict = {
            "task_id": report_data.task_id,
            "task_name": report_data.task_name,
            "target": report_data.target.url,
            "vulnerabilities": report_data.vulnerabilities,
            "timing": {
                "start_time": report_data.timing.start_time,
                "end_time": report_data.timing.end_time,
                "total_duration_ms": report_data.timing.total_duration_ms,
            },
            "ai_analysis": {
                "vulnerability_causes": report_data.ai_analysis.vulnerability_causes,
                "exploitation_risks": report_data.ai_analysis.exploitation_risks,
                "remediation_priorities": report_data.ai_analysis.remediation_priorities,
                "business_impact": report_data.ai_analysis.business_impact,
                "analysis_evidence": report_data.ai_analysis.analysis_evidence,
            },
            "generated_at": datetime.now().isoformat(),
        }
        return json.dumps(report_dict, ensure_ascii=False, indent=2)

    def generate_html_report(self, report_data: ReportData) -> str:
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>{report_data.task_name} - 安全扫描报告</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 960px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #1a73e8; }}
        .vuln {{ border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 4px; }}
        .critical {{ border-left: 4px solid #d32f2f; }}
        .high {{ border-left: 4px solid #f57c00; }}
        .medium {{ border-left: 4px solid #fbc02d; }}
        .low {{ border-left: 4px solid #388e3c; }}
        .info {{ border-left: 4px solid #1976d2; }}
    </style>
</head>
<body>
    <h1>安全扫描报告</h1>
    <p><strong>任务名称:</strong> {report_data.task_name}</p>
    <p><strong>目标:</strong> {report_data.target.url}</p>
    <p><strong>扫描时间:</strong> {report_data.timing.start_time}</p>
    <p><strong>漏洞总数:</strong> {len(report_data.vulnerabilities)}</p>
    <h2>漏洞列表</h2>
"""
        for v in report_data.vulnerabilities:
            severity = v.get("severity", "info")
            html += f'    <div class="vuln {severity}"><strong>{severity.upper()}</strong>: {v.get("name", "未知漏洞")}</div>\n'

        html += """</body>
</html>"""
        return html
