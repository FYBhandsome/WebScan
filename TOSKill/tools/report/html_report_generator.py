# -*- coding:utf-8 -*-
"""
HTML报告生成器模块

生成专业的HTML格式安全分析报告
"""

import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


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
        session_id: str = ""
    ) -> str:
        """生成HTML报告
        
        Args:
            target: 扫描目标URL
            scan_time: 扫描时间
            vulnerabilities: 漏洞列表
            tool_results: 工具执行结果
            ai_analysis: AI分析结果（可选）
            session_id: 会话ID
            
        Returns:
            str: HTML报告内容
        """
        severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in vulnerabilities:
            sev = (v.get("severity") or "info").lower()
            if sev in severity_count:
                severity_count[sev] += 1
        
        if ai_analysis:
            risk = ai_analysis.get("risk_assessment", {})
            risk_score = risk.get("risk_score", 50)
            risk_level = risk.get("overall_risk", "medium")
        else:
            risk_score = self._calculate_risk_score(severity_count)
            risk_level = self._determine_risk_level(severity_count)
        
        risk_color = self.SEVERITY_CONFIG.get(risk_level, self.SEVERITY_CONFIG["medium"])["color"]
        
        vulns_html = self._render_vulnerabilities_html(vulnerabilities)
        ai_html = self._render_ai_analysis_html(ai_analysis) if ai_analysis else ""
        tools_html = self._render_tool_results_html(tool_results)
        
        return self._build_html(
            target=target,
            scan_time=scan_time,
            session_id=session_id,
            severity_count=severity_count,
            risk_score=risk_score,
            risk_level=risk_level,
            risk_color=risk_color,
            vulns_html=vulns_html,
            ai_html=ai_html,
            tools_html=tools_html,
            vuln_count=len(vulnerabilities),
            ai_analysis=ai_analysis
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
                    <div class="label">漏洞总数</div>
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
            severity = (vuln.get("severity") or "info").lower()
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
            cwe_badge = f'<span class="badge" style="background:#7b1fa2;color:#fff;padding:2px 8px;border-radius:10px;font-size:11px;margin-left:8px;">{va.get("cwe_id", "")}</span>' if va.get("cwe_id") else ""
            cvss_val = va.get('cvss_estimate', 'N/A')
            cvss_color = "#e74c3c" if isinstance(cvss_val, (int, float)) and cvss_val >= 7.0 else "#f39c12" if isinstance(cvss_val, (int, float)) and cvss_val >= 4.0 else "#27ae60"
            cvss_vector_html = f'<p style="font-size:12px;color:#888;margin-top:4px;"><strong>CVSS向量:</strong> <code style="background:#f0f0f0;padding:2px 6px;border-radius:3px;font-size:11px;">{va.get("cvss_vector", "N/A")}</code></p>' if va.get("cvss_vector") else ""
            root_cause_html = f'<p><strong>根因分析:</strong> {va.get("root_cause", "N/A")}</p>' if va.get("root_cause") else ""
            poc_html = f'<p style="font-size:12px;color:#666;"><strong>验证思路:</strong> {va.get("proof_of_concept", "N/A")}</p>' if va.get("proof_of_concept") else ""
            vuln_analysis_html += f"""
            <div class="ai-card">
                <h4>🔎 {va.get('vuln_name', 'Unknown')} {cwe_badge}</h4>
                <p><strong>技术分析:</strong> {va.get('technical_analysis', 'N/A')}</p>
                {root_cause_html}
                <p><strong>业务影响:</strong> {va.get('business_impact', 'N/A')}</p>
                <p><strong>利用难度:</strong> {va.get('exploitation_difficulty', 'N/A')} | <strong>CVSS:</strong> <span style="color:{cvss_color};font-weight:bold;">{cvss_val}</span></p>
                {cvss_vector_html}
                <p><strong>攻击场景:</strong> {va.get('attack_scenario', 'N/A')}</p>
                {poc_html}
            </div>
            """
        
        recommendations_html = ""
        for rec in recommendations[:5]:
            verification_html = f'<p style="font-size:12px;color:#27ae60;">✅ <strong>验证方法:</strong> {rec.get("verification", "重新扫描验证")}</p>' if rec.get("verification") else ""
            recommendations_html += f"""
            <div class="priority-item">
                <div class="priority-num">{rec.get('priority', 1)}</div>
                <div class="priority-content">
                    <h5>{rec.get('vulnerability', 'Unknown')}</h5>
                    <p>{rec.get('recommendation', 'N/A')}</p>
                    {verification_html}
                    <p style="font-size: 12px; color: #888;">预估工作量: {rec.get('estimated_effort', 'N/A')} | 参考: {rec.get('references', 'N/A')}</p>
                </div>
            </div>
            """
        
        short_term = hardening.get("short_term", [])
        mid_term = hardening.get("mid_term", [])
        long_term = hardening.get("long_term", [])
        monitoring = hardening.get("monitoring", [])
        
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
        
        monitoring_html = ""
        if monitoring:
            monitoring_html = f"""
            <div class="ai-card" style="margin-top:15px;border-left:4px solid #00bcd4;">
                <h4>📡 安全监控建议</h4>
                <ul>{''.join(f'<li>• {item}</li>' for item in monitoring[:5])}</ul>
            </div>
            """
        
        attack_paths_html = "".join(f"<li>• {path}</li>" for path in attack_chain.get("attack_paths", [])[:3])
        
        kill_chain = attack_chain.get("kill_chain_mapping", {})
        kill_chain_html = ""
        if kill_chain:
            kc_stages = {
                "reconnaissance": ("🔍 侦察", "#9c27b0"),
                "weaponization": ("⚔️ 武器化", "#f44336"),
                "delivery": ("📦 投递", "#ff9800"),
                "exploitation": ("💥 利用", "#e74c3c"),
                "installation": ("🔧 安装", "#795548"),
                "command_and_control": ("📡 C2", "#607d8b"),
                "actions_on_objectives": ("🎯 目标行动", "#d32f2f")
            }
            kc_items = ""
            for stage_key, (stage_label, stage_color) in kc_stages.items():
                stage_items = kill_chain.get(stage_key, [])
                if stage_items:
                    kc_items += f'<div style="flex:1;min-width:120px;padding:8px;border-left:3px solid {stage_color};margin:4px;background:#fafafa;border-radius:4px;"><strong style="color:{stage_color};">{stage_label}</strong><br><span style="font-size:12px;">{", ".join(str(i) for i in stage_items[:3])}</span></div>'
            if kc_items:
                kill_chain_html = f"""
                <div style="margin-top:15px;">
                    <p><strong>网络杀伤链映射:</strong></p>
                    <div style="display:flex;flex-wrap:wrap;gap:8px;">{kc_items}</div>
                </div>
                """
        
        data_flow_risk_html = f'<p style="margin-top:10px;"><strong>数据流风险:</strong> {attack_chain.get("data_flow_risk", "N/A")}</p>' if attack_chain.get("data_flow_risk") else ""
        
        compliance_score = compliance.get("compliance_score")
        compliance_score_html = f'<p><strong>合规评分:</strong> <span style="font-weight:bold;color:{"#e74c3c" if isinstance(compliance_score, (int, float)) and compliance_score < 60 else "#f39c12" if isinstance(compliance_score, (int, float)) and compliance_score < 80 else "#27ae60"};">{compliance_score}/100</span></p>' if compliance_score is not None else ""
        
        risk_points_list = compliance.get("risk_points", [])
        compliance_risk_html = ""
        for rp in risk_points_list[:5]:
            if isinstance(rp, dict):
                compliance_risk_html += f'<li>⚠️ <strong>[{rp.get("standard", "")} {rp.get("clause", "")}]</strong> {rp.get("description", "")} — <em>整改: {rp.get("remediation", "")}</em></li>'
            else:
                compliance_risk_html += f'<li>⚠️ {rp}</li>'
        
        compliance_standards_html = "".join(f"<li>• {std}</li>" for std in compliance.get("standards", [])[:5])
        regulatory_html = f'<p style="margin-top:10px;color:#c62828;"><strong>监管处罚风险:</strong> {compliance.get("regulatory_penalties", "N/A")}</p>' if compliance.get("regulatory_penalties") else ""
        
        risk_matrix = risk.get("risk_matrix", {})
        risk_matrix_html = ""
        if risk_matrix:
            risk_matrix_html = f"""
            <div style="display:flex;gap:15px;margin-top:10px;">
                <div style="padding:8px 15px;background:#fff3e0;border-radius:6px;"><strong>可能性:</strong> {risk_matrix.get("likelihood", "N/A")}</div>
                <div style="padding:8px 15px;background:#ffebee;border-radius:6px;"><strong>影响程度:</strong> {risk_matrix.get("impact", "N/A")}</div>
                <div style="padding:8px 15px;background:#e8f5e9;border-radius:6px;"><strong>当前等级:</strong> {risk_matrix.get("current_level", "N/A").upper()}</div>
            </div>
            """
        
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
                {risk_matrix_html}
            </div>
            
            {f'<h4 style="margin: 25px 0 15px; color: #1565c0;">🔬 漏洞深度分析</h4>{vuln_analysis_html}' if vuln_analysis_html else ''}
            
            {f'''<div class="attack-chain">
                <h4>⛓️ 攻击链分析</h4>
                <p>{attack_chain.get('description', 'N/A')}</p>
                <p style="margin-top: 10px;"><strong>可能的攻击路径:</strong></p>
                <ul>{attack_paths_html or '<li>• 无</li>'}</ul>
                <p style="margin-top: 10px;"><strong>横向移动风险:</strong> {attack_chain.get('lateral_movement_risk', 'N/A')}</p>
                {data_flow_risk_html}
                {kill_chain_html}
            </div>''' if attack_chain else ''}
            
            {f'''<div class="compliance-box">
                <h4>📋 合规性影响</h4>
                <p><strong>相关标准:</strong></p>
                <ul>{compliance_standards_html or '<li>• 无</li>'}</ul>
                {compliance_score_html}
                <p style="margin-top:10px;"><strong>合规风险点:</strong></p>
                <ul>{compliance_risk_html or '<li>• 无</li>'}</ul>
                {regulatory_html}
            </div>''' if compliance else ''}
            
            {f'<h4 style="margin: 25px 0 15px; color: #1565c0;">🔧 修复优先级建议</h4>{recommendations_html}' if recommendations_html else ''}
            
            <h4 style="margin: 25px 0 15px; color: #1565c0;">🛡️ 安全加固建议</h4>
            {hardening_html}
            {monitoring_html}
        </div>
        """


html_report_generator = HTMLReportGenerator()


def get_html_report_generator() -> HTMLReportGenerator:
    """获取HTML报告生成器实例"""
    return html_report_generator
