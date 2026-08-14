# -*- coding:utf-8 -*-
from __future__ import annotations
"""
HTML报告生成器模块

生成专业的HTML格式安全分析报告
"""

import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from TOSKill.tools.report.scan_report_template import render_scan_report

logger = logging.getLogger(__name__)


@dataclass
class ConfidenceDimension:
    """兼容既有置信度转换测试的轻量数据结构。"""

    label: str = ""
    value: float = 0.0


@dataclass
class ConfidenceData:
    """新报告模板只读取原始 dict；此结构保留给历史诊断接口。"""

    overall_score: float = 0.0
    level: str = "info"
    standard_text: str = ""
    kb_version: str = ""
    dimensions: List[ConfidenceDimension] = field(default_factory=list)
    compliance_estimate: float = 0.0
    compliance_margin: str = ""
    kb_refs: str = ""
    scan_mode: str = ""
    note: str = ""


@dataclass
class AIAnalysisData:
    """兼容历史私有转换方法的数据结构。"""

    summary: str = ""
    risk_level: str = "info"
    causes: List[str] = field(default_factory=list)
    risks: List[str] = field(default_factory=list)
    priorities: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


@dataclass
class VulnerabilityData:
    vuln_type: str = ""
    severity: str = "info"
    title: str = ""
    description: str = ""
    url: str = ""
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    confidence: float = 0.0
    cwe_id: str = ""
    solution: str = ""


class HTMLReportGenerator:
    """专业HTML安全报告生成器"""
    
    SEVERITY_CONFIG = {
        "critical": {"score": 10.0, "color": "#c0392b", "label": "严重"},
        "high": {"score": 8.0, "color": "#e74c3c", "label": "高危"},
        "medium": {"score": 5.0, "color": "#f39c12", "label": "中危"},
        "low": {"score": 3.0, "color": "#3498db", "label": "低危"},
        "info": {"score": 1.0, "color": "#95a5a6", "label": "信息"}
    }

    def generate_report(
        self,
        target: str,
        scan_time: str,
        vulnerabilities: List[Dict[str, Any]],
        tool_results: Dict[str, Any],
        ai_analysis: Optional[Dict[str, Any]] = None,
        confidence: Optional[Dict[str, Any]] = None,
        session_id: str = "",
        report_type: str = "vuln_scan",
    ) -> str:
        """生成HTML报告

        Args:
            target: 扫描目标URL
            scan_time: 扫描时间
            vulnerabilities: 漏洞列表
            tool_results: 工具执行结果
            ai_analysis: AI分析结果（可选）
            confidence: AI等保评估置信度数据（可选，dict格式）
            session_id: 会话ID
            report_type: 用户选择的报告类型（信息收集/漏洞扫描/完整扫描）

        Returns:
            str: HTML报告内容
        """
        return render_scan_report(
            target=target,
            scan_time=scan_time,
            vulnerabilities=vulnerabilities or [],
            tool_results=tool_results or {},
            ai_analysis=ai_analysis,
            confidence=confidence,
            session_id=session_id,
            report_type=report_type,
        )

    @staticmethod
    def _convert_ai_analysis(ai_analysis: Dict[str, Any]) -> AIAnalysisData:
        """将 TOSKill AI 报告结构映射为统一报告模板数据。"""
        vulnerability_analysis = ai_analysis.get("vulnerability_analysis", []) or []
        attack_chain = ai_analysis.get("attack_chain_analysis", {}) or {}
        recommendations = ai_analysis.get("remediation_recommendations", []) or []
        hardening = ai_analysis.get("security_hardening", {}) or {}

        causes = []
        for item in vulnerability_analysis[:5]:
            name = item.get("vuln_name", "Unknown")
            technical = item.get("technical_analysis") or item.get("business_impact")
            if technical:
                causes.append(f"{name}：{technical}")

        risks = list(attack_chain.get("attack_paths", []) or [])[:3]
        if attack_chain.get("description"):
            risks.insert(0, attack_chain["description"])
        if attack_chain.get("lateral_movement_risk"):
            risks.append(f"横向移动风险：{attack_chain['lateral_movement_risk']}")

        priorities = []
        for item in recommendations[:5]:
            priorities.append({
                "vulnerability": item.get("vulnerability", "Unknown"),
                "priority": item.get("priority", 0),
                "reason": item.get("recommendation", ""),
            })

        hardening_items = []
        for key in ("short_term", "mid_term", "long_term"):
            hardening_items.extend(hardening.get(key, []) or [])

        risk = ai_analysis.get("risk_assessment", {}) or {}
        return AIAnalysisData(
            summary=ai_analysis.get("executive_summary", ""),
            risk_level=str(risk.get("overall_risk", "info")).lower(),
            causes=causes,
            risks=risks[:5],
            priorities=priorities,
            recommendations=hardening_items[:10],
        )

    @staticmethod
    def _convert_confidence(confidence: Dict[str, Any]) -> ConfidenceData:
        """将置信度dict转为ConfidenceData dataclass

        【修正Bug#6】所有字段使用.get()容错读取，防止LLM返回部分字段缺失时崩溃
        """
        raw_dims = confidence.get("dimensions", []) or []
        dimensions = []
        for dim in raw_dims[:4]:
            if isinstance(dim, dict):
                try:
                    value = float(dim.get("value", 0))
                except (TypeError, ValueError):
                    value = 0.0
                dimensions.append(ConfidenceDimension(
                    label=str(dim.get("label", "")),
                    value=max(0.0, min(100.0, value))
                ))

        try:
            overall = float(confidence.get("overall_score", 0))
        except (TypeError, ValueError):
            overall = 0.0

        try:
            compliance = float(confidence.get("compliance_estimate", 0))
        except (TypeError, ValueError):
            compliance = 0.0

        level = str(confidence.get("level", "")).lower()
        if level not in ("high", "mid", "low", "info"):
            if overall >= 80:
                level = "high"
            elif overall >= 60:
                level = "mid"
            elif overall > 0:
                level = "low"
            else:
                level = "info"

        return ConfidenceData(
            overall_score=max(0.0, min(100.0, overall)),
            level=level,
            standard_text=str(confidence.get("standard_text", "基于等保2.0（GB/T 22239-2019）三级标准")),
            kb_version=str(confidence.get("kb_version", "")),
            dimensions=dimensions,
            compliance_estimate=max(0.0, min(100.0, compliance)),
            compliance_margin=str(confidence.get("compliance_margin", "")),
            kb_refs=str(confidence.get("kb_refs", "")),
            scan_mode=str(confidence.get("scan_mode", "")),
            note=str(confidence.get("note", "")),
        )

    def _calculate_risk_score(self, severity_count: Dict[str, int]) -> int:
        """计算风险评分"""
        score = 0
        score += severity_count.get("critical", 0) * 25
        score += severity_count.get("high", 0) * 15
        score += severity_count.get("medium", 0) * 8
        score += severity_count.get("low", 0) * 3
        score += severity_count.get("info", 0) * 1
        return min(100, score)
    
    def _determine_risk_level(self, severity_count: Dict[str, int]) -> str:
        """确定风险等级"""
        if severity_count.get("critical", 0) > 0:
            return "critical"
        elif severity_count.get("high", 0) > 0:
            return "high"
        elif severity_count.get("medium", 0) > 0:
            return "medium"
        elif severity_count.get("low", 0) > 0:
            return "low"
        return "info"
    
    def _build_html(
        self,
        target: str,
        scan_time: str,
        session_id: str,
        severity_count: Dict[str, int],
        risk_score: int,
        risk_level: str,
        risk_color: str,
        vulns_html: str,
        ai_html: str,
        tools_html: str,
        vuln_count: int,
        ai_analysis: Optional[Dict[str, Any]] = None
    ) -> str:
        """构建完整HTML报告"""
        risk_label = self.SEVERITY_CONFIG.get(risk_level, self.SEVERITY_CONFIG["medium"])["label"]
        
        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>安全分析报告 - {target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Microsoft YaHei', sans-serif; 
            line-height: 1.8; 
            color: #1a1a2e; 
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 30px; }}
        
        .header {{ 
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); 
            color: white; 
            padding: 50px; 
            border-radius: 20px; 
            margin-bottom: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            position: relative;
            overflow: hidden;
        }}
        .header::before {{
            content: '';
            position: absolute;
            top: -50%;
            right: -50%;
            width: 100%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
        }}
        .header h1 {{ font-size: 36px; margin-bottom: 15px; position: relative; }}
        .header .subtitle {{ font-size: 18px; opacity: 0.9; margin-bottom: 20px; position: relative; }}
        .header .meta {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 15px;
            position: relative;
        }}
        .header .meta-item {{ 
            background: rgba(255,255,255,0.1); 
            padding: 15px 20px; 
            border-radius: 10px;
            backdrop-filter: blur(10px);
        }}
        .header .meta-item .label {{ font-size: 12px; opacity: 0.7; text-transform: uppercase; }}
        .header .meta-item .value {{ font-size: 16px; font-weight: 600; margin-top: 5px; }}
        
        .risk-dashboard {{
            background: white;
            border-radius: 20px;
            padding: 40px;
            margin-bottom: 40px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
            display: grid;
            grid-template-columns: 300px 1fr;
            gap: 40px;
            align-items: center;
        }}
        .gauge-container {{ text-align: center; }}
        .gauge {{ 
            width: 250px; 
            height: 250px; 
            position: relative; 
            margin: 0 auto;
        }}
        .gauge svg {{ width: 100%; height: 100%; }}
        .gauge-value {{ 
            position: absolute; 
            top: 50%; 
            left: 50%; 
            transform: translate(-50%, -50%); 
            font-size: 56px; 
            font-weight: 800;
        }}
        .gauge-label {{ 
            text-align: center; 
            margin-top: 15px; 
            font-size: 24px; 
            font-weight: 700;
        }}
        .risk-breakdown {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; }}
        .risk-item {{ 
            padding: 20px; 
            border-radius: 12px; 
            background: #f8f9fa;
            border-left: 4px solid;
        }}
        .risk-item .title {{ font-size: 14px; color: #666; margin-bottom: 8px; }}
        .risk-item .value {{ font-size: 28px; font-weight: 700; }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 20px;
            margin-bottom: 40px;
        }}
        .stat-card {{
            background: white;
            border-radius: 16px;
            padding: 25px;
            text-align: center;
            box-shadow: 0 5px 20px rgba(0,0,0,0.08);
            transition: transform 0.3s, box-shadow 0.3s;
        }}
        .stat-card:hover {{ transform: translateY(-5px); box-shadow: 0 10px 30px rgba(0,0,0,0.15); }}
        .stat-card .count {{ font-size: 48px; font-weight: 800; margin: 10px 0; }}
        .stat-card .label {{ font-size: 14px; color: #666; text-transform: uppercase; letter-spacing: 1px; }}
        
        .section {{
            background: white;
            border-radius: 20px;
            padding: 40px;
            margin-bottom: 40px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
        }}
        .section-header {{
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 3px solid #1a1a2e;
        }}
        .section-header .icon {{ font-size: 32px; }}
        .section-header h2 {{ font-size: 24px; color: #1a1a2e; }}
        
        .vuln-card {{
            background: #f8f9fa;
            border-radius: 16px;
            padding: 25px;
            margin-bottom: 20px;
            border-left: 5px solid;
            transition: all 0.3s;
        }}
        .vuln-card:hover {{ box-shadow: 0 5px 20px rgba(0,0,0,0.1); }}
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            flex-wrap: wrap;
            gap: 10px;
        }}
        .vuln-title {{ font-size: 20px; font-weight: 700; color: #1a1a2e; }}
        .vuln-badge {{
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 700;
            color: white;
            text-transform: uppercase;
        }}
        .vuln-detail {{ margin: 10px 0; color: #555; }}
        .vuln-detail strong {{ color: #1a1a2e; }}
        .vuln-solution {{
            background: linear-gradient(135deg, #e8f5e9 0%, #c8e6c9 100%);
            padding: 15px 20px;
            border-radius: 10px;
            margin-top: 15px;
        }}
        
        .ai-section {{
            background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%);
            border-radius: 20px;
            padding: 40px;
            margin-bottom: 40px;
            border: 2px solid #1976d2;
        }}
        .ai-section .section-header {{ border-bottom-color: #1976d2; }}
        .ai-section .section-header h2 {{ color: #1565c0; }}
        
        .ai-card {{
            background: white;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 15px;
        }}
        .ai-card h4 {{ color: #1565c0; margin-bottom: 10px; font-size: 16px; }}
        .ai-card p {{ color: #333; line-height: 1.8; }}
        .ai-card ul {{ margin-left: 20px; margin-top: 10px; }}
        .ai-card li {{ margin: 8px 0; color: #555; }}
        
        .priority-item {{
            display: flex;
            align-items: flex-start;
            gap: 15px;
            padding: 15px;
            background: white;
            border-radius: 10px;
            margin-bottom: 10px;
        }}
        .priority-num {{
            min-width: 35px;
            height: 35px;
            background: linear-gradient(135deg, #1a1a2e, #16213e);
            color: white;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
        }}
        .priority-content {{ flex: 1; }}
        .priority-content h5 {{ font-size: 16px; margin-bottom: 5px; }}
        .priority-content p {{ color: #666; font-size: 14px; }}
        
        .attack-chain {{
            background: linear-gradient(135deg, #fff3e0 0%, #ffe0b2 100%);
            border-radius: 12px;
            padding: 20px;
            margin: 20px 0;
        }}
        .attack-chain h4 {{ color: #e65100; margin-bottom: 15px; }}
        
        .compliance-box {{
            background: linear-gradient(135deg, #fce4ec 0%, #f8bbd0 100%);
            border-radius: 12px;
            padding: 20px;
            margin: 20px 0;
        }}
        .compliance-box h4 {{ color: #c2185b; margin-bottom: 15px; }}
        
        .hardening-grid {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin-top: 20px;
        }}
        .hardening-card {{
            background: white;
            border-radius: 12px;
            padding: 20px;
            border-top: 4px solid;
        }}
        .hardening-card h5 {{ margin-bottom: 15px; font-size: 16px; }}
        .hardening-card ul {{ list-style: none; }}
        .hardening-card li {{ padding: 8px 0; border-bottom: 1px solid #eee; }}
        .hardening-card li:last-child {{ border-bottom: none; }}
        
        .tool-result {{
            background: #f8f9fa;
            border-radius: 12px;
            padding: 15px;
            margin-bottom: 15px;
        }}
        .tool-result h4 {{ color: #1a1a2e; margin-bottom: 10px; }}
        .tool-result pre {{ 
            background: #2d2d2d; 
            color: #f8f8f2; 
            padding: 15px; 
            border-radius: 8px; 
            overflow-x: auto;
            font-size: 13px;
        }}
        
        .footer {{
            text-align: center;
            padding: 40px;
            color: #666;
        }}
        .footer .logo {{ font-size: 24px; font-weight: 700; color: #1a1a2e; margin-bottom: 10px; }}
        
        @media print {{
            body {{ background: white; }}
            .section, .stat-card, .vuln-card, .ai-section {{ box-shadow: none; break-inside: avoid; }}
            .risk-dashboard {{ break-inside: avoid; }}
        }}
        @media (max-width: 768px) {{
            .stats-grid {{ grid-template-columns: repeat(3, 1fr); }}
            .risk-dashboard {{ grid-template-columns: 1fr; }}
            .hardening-grid {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 安全分析报告</h1>
            <div class="subtitle">AI 驱动的专业安全分析</div>
            <div class="meta">
                <div class="meta-item">
                    <div class="label">扫描目标</div>
                    <div class="value">{target}</div>
                </div>
                <div class="meta-item">
                    <div class="label">扫描时间</div>
                    <div class="value">{scan_time}</div>
                </div>
                <div class="meta-item">
                    <div class="label">报告生成时间</div>
                    <div class="value">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
                </div>
                <div class="meta-item">
                    <div class="label">归并后待复核问题</div>
                    <div class="value">{vuln_count}</div>
                </div>
            </div>
        </div>
        
        <div class="risk-dashboard">
            <div class="gauge-container">
                <div class="gauge">
                    <svg viewBox="0 0 200 200">
                        <defs>
                            <linearGradient id="gaugeGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                                <stop offset="0%" style="stop-color:{risk_color};stop-opacity:1" />
                                <stop offset="100%" style="stop-color:{risk_color};stop-opacity:0.6" />
                            </linearGradient>
                        </defs>
                        <circle cx="100" cy="100" r="80" fill="none" stroke="#eee" stroke-width="15"/>
                        <circle cx="100" cy="100" r="80" fill="none" stroke="url(#gaugeGradient)" stroke-width="15"
                            stroke-dasharray="{risk_score * 5.03} 503"
                            stroke-linecap="round" transform="rotate(-90 100 100)"/>
                    </svg>
                    <div class="gauge-value" style="color: {risk_color};">{risk_score}</div>
                </div>
                <div class="gauge-label" style="color: {risk_color};">风险等级: {risk_label}</div>
            </div>
            <div class="risk-breakdown">
                <div class="risk-item" style="border-color: #c0392b;">
                    <div class="title">严重漏洞</div>
                    <div class="value" style="color: #c0392b;">{severity_count['critical']}</div>
                </div>
                <div class="risk-item" style="border-color: #e74c3c;">
                    <div class="title">高危漏洞</div>
                    <div class="value" style="color: #e74c3c;">{severity_count['high']}</div>
                </div>
                <div class="risk-item" style="border-color: #f39c12;">
                    <div class="title">中危漏洞</div>
                    <div class="value" style="color: #f39c12;">{severity_count['medium']}</div>
                </div>
                <div class="risk-item" style="border-color: #3498db;">
                    <div class="title">低危漏洞</div>
                    <div class="value" style="color: #3498db;">{severity_count['low']}</div>
                </div>
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card" style="border-top: 4px solid #c0392b;">
                <div class="label">严重</div>
                <div class="count" style="color: #c0392b;">{severity_count['critical']}</div>
            </div>
            <div class="stat-card" style="border-top: 4px solid #e74c3c;">
                <div class="label">高危</div>
                <div class="count" style="color: #e74c3c;">{severity_count['high']}</div>
            </div>
            <div class="stat-card" style="border-top: 4px solid #f39c12;">
                <div class="label">中危</div>
                <div class="count" style="color: #f39c12;">{severity_count['medium']}</div>
            </div>
            <div class="stat-card" style="border-top: 4px solid #3498db;">
                <div class="label">低危</div>
                <div class="count" style="color: #3498db;">{severity_count['low']}</div>
            </div>
            <div class="stat-card" style="border-top: 4px solid #95a5a6;">
                <div class="label">信息</div>
                <div class="count" style="color: #95a5a6;">{severity_count['info']}</div>
            </div>
        </div>
        
        {ai_html}
        
        <div class="section">
            <div class="section-header">
                <span class="icon">🔍</span>
                <h2>漏洞详情</h2>
            </div>
            {vulns_html if vulns_html else '<p style="color: #666; text-align: center; padding: 40px;">未发现漏洞</p>'}
        </div>
        
        <div class="section">
            <div class="section-header">
                <span class="icon">🛠️</span>
                <h2>工具执行结果</h2>
            </div>
            {tools_html if tools_html else '<p style="color: #666; text-align: center; padding: 20px;">无工具执行记录</p>'}
        </div>
        
        <div class="footer">
            <div class="logo">🛡️ TOSKill Security Scanner</div>
            <p>本报告由 AI 安全分析系统自动生成</p>
            <p>会话ID: {session_id} | 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>"""
    
    def _render_vulnerabilities_html(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """渲染漏洞列表"""
        if not vulnerabilities:
            return ""
        
        html = ""
        for i, vuln in enumerate(vulnerabilities):
            severity = vuln.get("severity", "info").lower()
            config = self.SEVERITY_CONFIG.get(severity, self.SEVERITY_CONFIG["info"])
            
            title = vuln.get("title") or vuln.get("name") or vuln.get("vuln_type") or "Unknown"
            url = vuln.get("url", "N/A")
            parameter = vuln.get("parameter", "N/A")
            description = vuln.get("description", "N/A")
            payload = vuln.get("payload", "N/A")
            solution = vuln.get("solution") or vuln.get("remediation") or "请参考安全最佳实践进行修复"
            
            html += f"""
            <div class="vuln-card" style="border-left-color: {config['color']};">
                <div class="vuln-header">
                    <span class="vuln-title">{title}</span>
                    <span class="vuln-badge" style="background: {config['color']};">{config['label']}</span>
                </div>
                <div class="vuln-detail"><strong>URL:</strong> {url}</div>
                <div class="vuln-detail"><strong>参数:</strong> {parameter}</div>
                <div class="vuln-detail"><strong>描述:</strong> {description}</div>
                <div class="vuln-detail"><strong>Payload:</strong> <code style="background: #eee; padding: 2px 8px; border-radius: 4px;">{payload}</code></div>
                <div class="vuln-solution">
                    <strong>💡 修复建议:</strong> {solution}
                </div>
            </div>
            """
        return html
    
    def _render_tool_results_html(self, tool_results: Dict[str, Any]) -> str:
        """渲染工具执行结果"""
        if not tool_results:
            return ""
        
        html = ""
        for tool_name, result in list(tool_results.items())[:10]:
            if isinstance(result, dict):
                result_str = json.dumps(result, ensure_ascii=False, indent=2)
            else:
                result_str = str(result)
            
            if len(result_str) > 2000:
                result_str = result_str[:2000] + "\n... (内容已截断)"
            
            html += f"""
            <div class="tool-result">
                <h4>🔧 {tool_name}</h4>
                <pre>{result_str}</pre>
            </div>
            """
        return html
    
    def _render_ai_analysis_html(self, ai_analysis: Dict[str, Any]) -> str:
        """渲染AI分析内容"""
        if not ai_analysis:
            return ""
        
        exec_summary = ai_analysis.get("executive_summary", "")
        risk = ai_analysis.get("risk_assessment", {})
        vuln_analysis = ai_analysis.get("vulnerability_analysis", [])
        attack_chain = ai_analysis.get("attack_chain_analysis", {})
        compliance = ai_analysis.get("compliance_impact", {})
        recommendations = ai_analysis.get("remediation_recommendations", [])
        hardening = ai_analysis.get("security_hardening", {})
        
        vuln_analysis_html = ""
        for va in vuln_analysis[:5]:
            vuln_analysis_html += f"""
            <div class="ai-card">
                <h4>🔎 {va.get('vuln_name', 'Unknown')}</h4>
                <p><strong>技术分析:</strong> {va.get('technical_analysis', 'N/A')}</p>
                <p><strong>业务影响:</strong> {va.get('business_impact', 'N/A')}</p>
                <p><strong>利用难度:</strong> {va.get('exploitation_difficulty', 'N/A')} | <strong>CVSS:</strong> {va.get('cvss_estimate', 'N/A')}</p>
                <p><strong>攻击场景:</strong> {va.get('attack_scenario', 'N/A')}</p>
            </div>
            """
        
        recommendations_html = ""
        for rec in recommendations[:5]:
            recommendations_html += f"""
            <div class="priority-item">
                <div class="priority-num">{rec.get('priority', 1)}</div>
                <div class="priority-content">
                    <h5>{rec.get('vulnerability', 'Unknown')}</h5>
                    <p>{rec.get('recommendation', 'N/A')}</p>
                    <p style="font-size: 12px; color: #888;">预估工作量: {rec.get('estimated_effort', 'N/A')}</p>
                </div>
            </div>
            """
        
        short_term = hardening.get("short_term", [])
        mid_term = hardening.get("mid_term", [])
        long_term = hardening.get("long_term", [])
        
        hardening_html = f"""
        <div class="hardening-grid">
            <div class="hardening-card" style="border-color: #e74c3c;">
                <h5>⚡ 短期措施</h5>
                <ul>{''.join(f'<li>• {item}</li>' for item in short_term[:5]) if short_term else '<li>• 无</li>'}</ul>
            </div>
            <div class="hardening-card" style="border-color: #f39c12;">
                <h5>📅 中期措施</h5>
                <ul>{''.join(f'<li>• {item}</li>' for item in mid_term[:5]) if mid_term else '<li>• 无</li>'}</ul>
            </div>
            <div class="hardening-card" style="border-color: #3498db;">
                <h5>🎯 长期措施</h5>
                <ul>{''.join(f'<li>• {item}</li>' for item in long_term[:5]) if long_term else '<li>• 无</li>'}</ul>
            </div>
        </div>
        """
        
        attack_paths_html = "".join(f"<li>• {path}</li>" for path in attack_chain.get("attack_paths", [])[:3])
        compliance_html = "".join(f"<li>• {std}</li>" for std in compliance.get("standards", [])[:3])
        compliance_html += "".join(f"<li>⚠️ {rp}</li>" for rp in compliance.get("risk_points", [])[:3])
        
        return f"""
        <div class="ai-section">
            <div class="section-header">
                <span class="icon">🧠</span>
                <h2>AI 智能分析</h2>
            </div>
            
            <div class="ai-card">
                <h4>📋 执行摘要</h4>
                <p>{exec_summary or '无'}</p>
            </div>
            
            <div class="ai-card">
                <h4>📊 风险评估</h4>
                <p><strong>综合风险等级:</strong> {risk.get('overall_risk', 'N/A').upper()}</p>
                <p><strong>风险评分:</strong> {risk.get('risk_score', 'N/A')}/100</p>
                <p><strong>评级依据:</strong> {risk.get('risk_justification', 'N/A')}</p>
            </div>
            
            {f'<h4 style="margin: 25px 0 15px; color: #1565c0;">🔬 漏洞深度分析</h4>{vuln_analysis_html}' if vuln_analysis_html else ''}
            
            {f'''<div class="attack-chain">
                <h4>⛓️ 攻击链分析</h4>
                <p>{attack_chain.get('description', 'N/A')}</p>
                <p style="margin-top: 10px;"><strong>可能的攻击路径:</strong></p>
                <ul>{attack_paths_html or '<li>• 无</li>'}</ul>
                <p style="margin-top: 10px;"><strong>横向移动风险:</strong> {attack_chain.get('lateral_movement_risk', 'N/A')}</p>
            </div>''' if attack_chain else ''}
            
            {f'''<div class="compliance-box">
                <h4>📋 合规性影响</h4>
                <ul>{compliance_html or '<li>• 无</li>'}</ul>
            </div>''' if compliance else ''}
            
            {f'<h4 style="margin: 25px 0 15px; color: #1565c0;">🔧 修复优先级建议</h4>{recommendations_html}' if recommendations_html else ''}
            
            <h4 style="margin: 25px 0 15px; color: #1565c0;">🛡️ 安全加固建议</h4>
            {hardening_html}
        </div>
        """


html_report_generator = HTMLReportGenerator()


def get_html_report_generator() -> HTMLReportGenerator:
    """获取HTML报告生成器实例"""
    return html_report_generator
