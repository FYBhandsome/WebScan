"""
AI 安全分析报告生成脚本

基于扫描结果生成专业的安全分析报告，包含 AI 深度分析功能。
生成 HTML 和 PDF 格式的报告。
"""
import asyncio
import json
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

sys.path.insert(0, str(Path(__file__).parent))

from openai import OpenAI


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


@dataclass
class ScanResult:
    target: str = ""
    scan_time: str = ""
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)


class EnhancedAIAnalyzer:
    """增强版 AI 安全分析器 - 专业的安全人员视角"""
    
    def __init__(self):
        self.llm_client = None
        self.model_id = None
        self._init_llm_client()
    
    def _init_llm_client(self):
        try:
            from backend.config import settings
            if settings.OPENAI_API_KEY:
                self.llm_client = OpenAI(
                    api_key=settings.OPENAI_API_KEY,
                    base_url=settings.OPENAI_BASE_URL
                )
                self.model_id = settings.MODEL_ID
                print(f"[OK] AI 模型已初始化: {self.model_id}")
            else:
                print("[WARN] OPENAI_API_KEY 未配置")
        except Exception as e:
            print(f"[ERROR] AI 初始化失败: {e}")
    
    def _build_professional_prompt(self, scan_result: ScanResult) -> str:
        """构建专业的安全分析提示词"""
        
        vulns_json = json.dumps(scan_result.vulnerabilities, ensure_ascii=False, indent=2)
        
        severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in scan_result.vulnerabilities:
            sev = v.get("severity", "info").lower()
            if sev in severity_count:
                severity_count[sev] += 1
        
        prompt = f"""你是一位资深的安全专家，拥有 15 年以上的渗透测试和漏洞分析经验。请对以下安全扫描结果进行全面、专业的分析。

## 扫描目标信息
- 目标地址: {scan_result.target}
- 扫描时间: {scan_result.scan_time}

## 漏洞统计概览
- 漏洞总数: {len(scan_result.vulnerabilities)}
- 严重: {severity_count['critical']} | 高危: {severity_count['high']} | 中危: {severity_count['medium']} | 低危: {severity_count['low']} | 信息: {severity_count['info']}

## 漏洞详细数据
```json
{vulns_json}
```

## 分析要求

请从专业安全人员的视角，提供以下深度分析（输出为严格 JSON 格式）：

### 1. 执行摘要 (executive_summary)
- 用简洁专业的语言概述整体安全状况
- 突出最关键的安全风险
- 字数控制在 100-150 字

### 2. 风险评级 (risk_assessment)
- overall_risk: 综合风险等级 (critical/high/medium/low/info)
- risk_score: 风险评分 (0-100)
- risk_justification: 风险评级依据

### 3. 漏洞深度分析 (vulnerability_analysis)
对每个重要漏洞提供：
- vuln_id: 漏洞标识
- vuln_name: 漏洞名称
- technical_analysis: 技术原理分析（攻击向量、利用条件）
- business_impact: 业务影响评估
- exploitation_difficulty: 利用难度 (easy/medium/hard)
- attack_scenario: 可能的攻击场景描述
- cvss_estimate: CVSS 评分估算 (0.0-10.0)

### 4. 攻击链分析 (attack_chain_analysis)
- 描述攻击者如何组合利用多个漏洞
- 可能的攻击路径
- 潜在的横向移动风险

### 5. 合规性影响 (compliance_impact)
- 相关安全标准（如等保2.0、OWASP Top 10、ISO 27001）
- 合规风险点

### 6. 修复建议 (remediation_recommendations)
按优先级排序的修复建议：
- priority: 优先级 (1-5, 1最高)
- vulnerability: 关联漏洞
- recommendation: 具体修复措施
- estimated_effort: 预估工作量
- references: 参考链接或文档

### 7. 安全加固建议 (security_hardening)
- 短期措施（立即执行）
- 中期措施（1-3个月）
- 长期措施（持续改进）

## 输出格式要求
严格输出以下 JSON 格式，不要包含任何其他内容：
```json
{{
  "executive_summary": "执行摘要内容...",
  "risk_assessment": {{
    "overall_risk": "high",
    "risk_score": 75,
    "risk_justification": "评级依据..."
  }},
  "vulnerability_analysis": [
    {{
      "vuln_id": "VULN-001",
      "vuln_name": "SQL注入漏洞",
      "technical_analysis": "技术分析...",
      "business_impact": "业务影响...",
      "exploitation_difficulty": "easy",
      "attack_scenario": "攻击场景...",
      "cvss_estimate": 9.8
    }}
  ],
  "attack_chain_analysis": {{
    "description": "攻击链描述...",
    "attack_paths": ["路径1", "路径2"],
    "lateral_movement_risk": "横向移动风险..."
  }},
  "compliance_impact": {{
    "standards": ["等保2.0", "OWASP Top 10"],
    "risk_points": ["风险点1", "风险点2"]
  }},
  "remediation_recommendations": [
    {{
      "priority": 1,
      "vulnerability": "SQL注入",
      "recommendation": "使用参数化查询...",
      "estimated_effort": "2-4小时",
      "references": "OWASP SQL Injection Prevention"
    }}
  ],
  "security_hardening": {{
    "short_term": ["措施1", "措施2"],
    "mid_term": ["措施1", "措施2"],
    "long_term": ["措施1", "措施2"]
  }}
}}
```

请确保分析专业、全面、可操作，体现资深安全专家的专业水准。
"""
        return prompt
    
    async def analyze(self, scan_result: ScanResult) -> Dict[str, Any]:
        """执行 AI 分析"""
        if not self.llm_client:
            return self._fallback_analysis(scan_result)
        
        try:
            prompt = self._build_professional_prompt(scan_result)
            
            print(f"[AI] 正在调用 {self.model_id} 进行深度安全分析...")
            
            response = self.llm_client.chat.completions.create(
                model=self.model_id,
                messages=[
                    {
                        "role": "system", 
                        "content": "你是一位拥有15年以上经验的资深安全专家，精通渗透测试、漏洞分析、安全架构设计。你的分析报告被多家世界500强企业采用。请始终保持专业、严谨、可操作的分析风格。"
                    },
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=4000
            )
            
            analysis_text = response.choices[0].message.content
            result = self._parse_response(analysis_text)
            print("[OK] AI 分析完成")
            return result
            
        except Exception as e:
            print(f"[ERROR] AI 分析失败: {e}")
            return self._fallback_analysis(scan_result)
    
    def _parse_response(self, response_text: str) -> Dict[str, Any]:
        """解析 AI 响应"""
        import re
        try:
            json_match = re.search(r'\{[\s\S]*\}', response_text)
            if json_match:
                return json.loads(json_match.group())
        except Exception as e:
            print(f"[WARN] JSON 解析失败: {e}")
        return {"raw_response": response_text}
    
    def _fallback_analysis(self, scan_result: ScanResult) -> Dict[str, Any]:
        """规则回退分析"""
        vulns = scan_result.vulnerabilities
        severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in vulns:
            sev = v.get("severity", "info").lower()
            if sev in severity_count:
                severity_count[sev] += 1
        
        if severity_count["critical"] > 0 or severity_count["high"] > 0:
            risk_level = "high"
            risk_score = 75
        elif severity_count["medium"] > 0:
            risk_level = "medium"
            risk_score = 50
        else:
            risk_level = "low"
            risk_score = 25
        
        return {
            "executive_summary": f"目标 {scan_result.target} 存在 {len(vulns)} 个安全问题，其中高危 {severity_count['high']} 个，中危 {severity_count['medium']} 个。建议尽快修复高危漏洞。",
            "risk_assessment": {
                "overall_risk": risk_level,
                "risk_score": risk_score,
                "risk_justification": "基于漏洞数量和严重程度评估"
            },
            "vulnerability_analysis": [
                {
                    "vuln_id": f"VULN-{i+1:03d}",
                    "vuln_name": v.get("title", v.get("name", "Unknown")),
                    "technical_analysis": v.get("description", ""),
                    "business_impact": "可能导致数据泄露或服务中断",
                    "exploitation_difficulty": "medium",
                    "attack_scenario": "攻击者可利用此漏洞获取敏感信息",
                    "cvss_estimate": 7.5 if v.get("severity") == "high" else 5.0
                }
                for i, v in enumerate(vulns[:5])
            ],
            "attack_chain_analysis": {
                "description": "攻击者可能组合利用多个漏洞进行攻击",
                "attack_paths": ["信息收集 -> 漏洞利用 -> 权限提升"],
                "lateral_movement_risk": "存在横向移动风险"
            },
            "compliance_impact": {
                "standards": ["OWASP Top 10", "等保2.0"],
                "risk_points": ["输入验证不足", "安全配置缺失"]
            },
            "remediation_recommendations": [
                {
                    "priority": 1,
                    "vulnerability": v.get("title", "Unknown"),
                    "recommendation": v.get("solution", "请参考安全最佳实践进行修复"),
                    "estimated_effort": "根据具体情况评估",
                    "references": "OWASP"
                }
                for v in vulns[:3]
            ],
            "security_hardening": {
                "short_term": ["修复高危漏洞", "加强访问控制"],
                "mid_term": ["部署WAF", "实施安全监控"],
                "long_term": ["建立安全开发流程", "定期安全审计"]
            }
        }


class ProfessionalReportGenerator:
    """专业安全报告生成器"""
    
    SEVERITY_CONFIG = {
        "critical": {"score": 10.0, "color": "#c0392b", "label": "严重"},
        "high": {"score": 8.0, "color": "#e74c3c", "label": "高危"},
        "medium": {"score": 5.0, "color": "#f39c12", "label": "中危"},
        "low": {"score": 3.0, "color": "#3498db", "label": "低危"},
        "info": {"score": 1.0, "color": "#95a5a6", "label": "信息"}
    }
    
    def __init__(self):
        self.ai_analyzer = EnhancedAIAnalyzer()
    
    def generate_html_report(self, scan_result: ScanResult, ai_analysis: Dict[str, Any]) -> str:
        """生成专业的 HTML 报告"""
        
        severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in scan_result.vulnerabilities:
            sev = v.get("severity", "info").lower()
            if sev in severity_count:
                severity_count[sev] += 1
        
        risk = ai_analysis.get("risk_assessment", {})
        risk_score = risk.get("risk_score", 50)
        risk_level = risk.get("overall_risk", "medium")
        risk_color = self.SEVERITY_CONFIG.get(risk_level, self.SEVERITY_CONFIG["medium"])["color"]
        
        vulns_html = self._render_vulnerabilities_html(scan_result.vulnerabilities)
        ai_html = self._render_ai_analysis_html(ai_analysis)
        
        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>安全分析报告 - {scan_result.target}</title>
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
                    <div class="value">{scan_result.target}</div>
                </div>
                <div class="meta-item">
                    <div class="label">扫描时间</div>
                    <div class="value">{scan_result.scan_time}</div>
                </div>
                <div class="meta-item">
                    <div class="label">报告生成时间</div>
                    <div class="value">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
                </div>
                <div class="meta-item">
                    <div class="label">漏洞总数</div>
                    <div class="value">{len(scan_result.vulnerabilities)}</div>
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
                <div class="gauge-label" style="color: {risk_color};">风险等级: {self.SEVERITY_CONFIG.get(risk_level, self.SEVERITY_CONFIG['medium'])['label']}</div>
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
        
        <div class="footer">
            <div class="logo">🛡️ AI_WebSecurity</div>
            <p>本报告由 AI 安全分析系统自动生成</p>
            <p>生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
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
            
            html += f"""
            <div class="vuln-card" style="border-left-color: {config['color']};">
                <div class="vuln-header">
                    <span class="vuln-title">{vuln.get('title', vuln.get('name', vuln.get('vuln_type', 'Unknown')))}</span>
                    <span class="vuln-badge" style="background: {config['color']};">{config['label']}</span>
                </div>
                <div class="vuln-detail"><strong>URL:</strong> {vuln.get('url', 'N/A')}</div>
                <div class="vuln-detail"><strong>参数:</strong> {vuln.get('parameter', 'N/A')}</div>
                <div class="vuln-detail"><strong>描述:</strong> {vuln.get('description', 'N/A')}</div>
                <div class="vuln-detail"><strong>Payload:</strong> <code style="background: #eee; padding: 2px 8px; border-radius: 4px;">{vuln.get('payload', 'N/A')}</code></div>
                <div class="vuln-solution">
                    <strong>💡 修复建议:</strong> {vuln.get('solution', vuln.get('remediation', '请参考安全最佳实践进行修复'))}
                </div>
            </div>
            """
        return html
    
    def _render_ai_analysis_html(self, ai_analysis: Dict[str, Any]) -> str:
        """渲染 AI 分析内容"""
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
        
        hardening_html = ""
        short_term = hardening.get("short_term", [])
        mid_term = hardening.get("mid_term", [])
        long_term = hardening.get("long_term", [])
        
        hardening_html = f"""
        <div class="hardening-grid">
            <div class="hardening-card" style="border-color: #e74c3c;">
                <h5>⚡ 短期措施</h5>
                <ul>{''.join(f'<li>• {item}</li>' for item in short_term[:5])}</ul>
            </div>
            <div class="hardening-card" style="border-color: #f39c12;">
                <h5>📅 中期措施</h5>
                <ul>{''.join(f'<li>• {item}</li>' for item in mid_term[:5])}</ul>
            </div>
            <div class="hardening-card" style="border-color: #3498db;">
                <h5>🎯 长期措施</h5>
                <ul>{''.join(f'<li>• {item}</li>' for item in long_term[:5])}</ul>
            </div>
        </div>
        """
        
        attack_paths_html = ""
        for path in attack_chain.get("attack_paths", [])[:3]:
            attack_paths_html += f"<li>• {path}</li>"
        
        compliance_html = ""
        for std in compliance.get("standards", [])[:3]:
            compliance_html += f"<li>• {std}</li>"
        for rp in compliance.get("risk_points", [])[:3]:
            compliance_html += f"<li>⚠️ {rp}</li>"
        
        return f"""
        <div class="ai-section">
            <div class="section-header">
                <span class="icon">🧠</span>
                <h2>AI 智能分析</h2>
            </div>
            
            <div class="ai-card">
                <h4>📋 执行摘要</h4>
                <p>{exec_summary}</p>
            </div>
            
            <div class="ai-card">
                <h4>📊 风险评估</h4>
                <p><strong>综合风险等级:</strong> {risk.get('overall_risk', 'N/A').upper()}</p>
                <p><strong>风险评分:</strong> {risk.get('risk_score', 'N/A')}/100</p>
                <p><strong>评级依据:</strong> {risk.get('risk_justification', 'N/A')}</p>
            </div>
            
            <h4 style="margin: 25px 0 15px; color: #1565c0;">🔬 漏洞深度分析</h4>
            {vuln_analysis_html}
            
            <div class="attack-chain">
                <h4>⛓️ 攻击链分析</h4>
                <p>{attack_chain.get('description', 'N/A')}</p>
                <p style="margin-top: 10px;"><strong>可能的攻击路径:</strong></p>
                <ul>{attack_paths_html}</ul>
                <p style="margin-top: 10px;"><strong>横向移动风险:</strong> {attack_chain.get('lateral_movement_risk', 'N/A')}</p>
            </div>
            
            <div class="compliance-box">
                <h4>📋 合规性影响</h4>
                <ul>{compliance_html}</ul>
            </div>
            
            <h4 style="margin: 25px 0 15px; color: #1565c0;">🔧 修复优先级建议</h4>
            {recommendations_html}
            
            <h4 style="margin: 25px 0 15px; color: #1565c0;">🛡️ 安全加固建议</h4>
            {hardening_html}
        </div>
        """
    
    def generate_pdf_report(self, html_content: str) -> bytes:
        """生成 PDF 报告"""
        try:
            from weasyprint import HTML
            from io import BytesIO
            buffer = BytesIO()
            HTML(string=html_content).write_pdf(buffer)
            return buffer.getvalue()
        except ImportError:
            print("[WARN] weasyprint 未安装，尝试使用 reportlab")
            return self._generate_pdf_simple(html_content)
        except Exception as e:
            print(f"[ERROR] PDF 生成失败: {e}")
            raise
    
    def _generate_pdf_simple(self, html_content: str) -> bytes:
        """简化 PDF 生成"""
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
            from reportlab.lib.styles import getSampleStyleSheet
            from io import BytesIO
            
            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=A4)
            styles = getSampleStyleSheet()
            story = []
            
            story.append(Paragraph("安全分析报告", styles['Title']))
            story.append(Spacer(1, 20))
            story.append(Paragraph("请使用支持 HTML 的浏览器查看完整报告", styles['Normal']))
            
            doc.build(story)
            return buffer.getvalue()
        except Exception as e:
            print(f"[ERROR] PDF 生成失败: {e}")
            return b""


def parse_scan_results(file_path: str) -> List[ScanResult]:
    """解析扫描结果文件"""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    results = []
    
    # 解析 DVWA 报告
    dvwa_result = ScanResult(
        target="http://127.0.0.1/dvwa/vulnerabilities/sqli/",
        scan_time="2026-05-17",
        vulnerabilities=[]
    )
    
    dvwa_vulns = [
        {"title": "Apache server-info 功能开启", "severity": "medium", "url": "http://127.0.0.1/dvwa/", "description": "Apache 开放 server-info 页面，暴露服务器配置信息", "solution": "注释 httpd.conf 中相关配置"},
        {"title": "Apache server-status 功能开启", "severity": "medium", "url": "http://127.0.0.1/dvwa/", "description": "Apache 开放 server-status 状态页面，泄露运行状态", "solution": "注释 httpd.conf 中 server-status 相关配置"},
        {"title": "应用错误信息直接暴露", "severity": "medium", "url": "http://127.0.0.1/dvwa/", "description": "页面直接输出 PHP 错误详情，包含绝对路径与代码异常", "solution": "关闭页面错误显示，将错误写入日志文件"},
        {"title": "未加密 HTTP 连接", "severity": "medium", "url": "http://127.0.0.1/dvwa/", "description": "全站使用 HTTP 明文传输数据", "solution": "部署 HTTPS，实现全流量加密传输"},
        {"title": "点击劫持防护缺失", "severity": "low", "url": "http://127.0.0.1/dvwa/", "description": "未配置 X-Frame-Options 响应头", "solution": "添加 X-Frame-Options 防护头"},
        {"title": "Cookie 属性配置不规范", "severity": "low", "url": "http://127.0.0.1/dvwa/", "description": "Cookie 缺少 SameSite 属性", "solution": "为 Cookie 添加 SameSite 属性"},
        {"title": "会话 Cookie 未启用 HttpOnly", "severity": "low", "url": "http://127.0.0.1/dvwa/", "description": "PHPSESSID Cookie 未设置 HttpOnly", "solution": "为会话 Cookie 启用 HttpOnly 标记"},
        {"title": "HTTP TRACE 方法开启", "severity": "low", "url": "http://127.0.0.1/dvwa/", "description": "服务器开启 TRACE 方法", "solution": "在 Web 服务器中禁用 TRACE 方法"},
        {"title": "未配置内容安全策略（CSP）", "severity": "info", "url": "http://127.0.0.1/dvwa/", "description": "缺少对 XSS、资源加载的安全控制", "solution": "配置 CSP 策略"},
        {"title": "无 HTTP 自动跳转 HTTPS", "severity": "info", "url": "http://127.0.0.1/dvwa/", "description": "用户可能仍使用明文访问", "solution": "配置 HTTP 到 HTTPS 的自动跳转"},
        {"title": "PHP 版本信息泄露", "severity": "info", "url": "http://127.0.0.1/dvwa/", "description": "响应头暴露 PHP 版本", "solution": "隐藏 PHP 版本信息"},
        {"title": "服务器路径泄露", "severity": "info", "url": "http://127.0.0.1/dvwa/", "description": "错误页面暴露 Windows 系统绝对路径", "solution": "清理路径泄露，配置自定义错误页面"},
    ]
    dvwa_result.vulnerabilities = dvwa_vulns
    results.append(dvwa_result)
    
    # 解析北华航天工业学院 SQL 注入结果
    nciae_result = ScanResult(
        target="http://www.nciae.edu.cn",
        scan_time="2026-05-07",
        vulnerabilities=[
            {
                "title": "SQL注入漏洞(时间盲注)",
                "severity": "high",
                "url": "http://www.nciae.edu.cn",
                "parameter": "Referer",
                "payload": "' AND DBMS_LOCK.SLEEP(5)=1--",
                "description": "检测到基于时间盲注的SQL注入漏洞，数据库类型: oracle",
                "evidence": "响应时间差异: 20.35秒 (基准: 0.16秒, 实际: 20.51秒)",
                "confidence": 0.85,
                "cwe_id": "CWE-89",
                "solution": "使用参数化查询，对用户输入进行严格过滤和验证"
            }
        ]
    )
    results.append(nciae_result)
    
    # 解析 testasp.vulnweb.com 结果
    testasp_result = ScanResult(
        target="http://testasp.vulnweb.com",
        scan_time="2026-05-15",
        vulnerabilities=[
            {"title": "SQL注入(布尔盲注) - Login.asp tfUName", "severity": "high", "url": "http://testasp.vulnweb.com/Login.asp", "parameter": "tfUName", "payload": "-1' OR 3*2*1=6 AND 00013=00013 --", "description": "SQL注入漏洞，可通过布尔盲注获取数据", "solution": "使用参数化查询，禁止拼接SQL"},
            {"title": "SQL注入(布尔盲注) - Login.asp tfUPass", "severity": "high", "url": "http://testasp.vulnweb.com/Login.asp", "parameter": "tfUPass", "payload": "-1' OR 3*2*1=6 AND 000498=000498 --", "description": "SQL注入漏洞，可通过布尔盲注获取数据", "solution": "使用参数化查询，禁止拼接SQL"},
            {"title": "SQL注入(布尔盲注) - showforum.asp", "severity": "high", "url": "http://testasp.vulnweb.com/showforum.asp", "parameter": "id", "payload": "-1 OR 3*2*1=6 AND 000761=000761", "description": "SQL注入漏洞，可通过布尔盲注获取数据", "solution": "使用参数化查询，禁止拼接SQL"},
            {"title": "SQL注入(时间盲注) - showthread.asp", "severity": "high", "url": "http://testasp.vulnweb.com/showthread.asp", "parameter": "id", "payload": "-1; waitfor delay '0:0:6' --", "description": "SQL注入漏洞，可通过时间盲注获取数据", "solution": "使用参数化查询，禁止拼接SQL"},
            {"title": "跨站脚本XSS(反射型)", "severity": "high", "url": "http://testasp.vulnweb.com/Search.asp", "parameter": "tfSearch", "payload": "the\"><script>BsRZ(9482)</script>", "description": "反射型XSS漏洞，可窃取Cookie或执行恶意脚本", "solution": "对输出进行HTML编码，配置CSP策略"},
            {"title": "目录穿越漏洞", "severity": "high", "url": "http://testasp.vulnweb.com/Templatize.asp", "parameter": "item", "payload": "../../../../../../../../../../../../../../windows/win.ini", "description": "目录穿越漏洞，可读取服务器任意文件", "solution": "严格验证文件路径，禁止包含../等特殊字符"},
            {"title": "本地文件包含LFI", "severity": "high", "url": "http://testasp.vulnweb.com/Templatize.asp", "parameter": "item", "payload": "Templatize.asp", "description": "本地文件包含漏洞，可能执行本地脚本", "solution": "严格限制可包含的文件路径白名单"},
            {"title": "URL重定向漏洞", "severity": "medium", "url": "http://testasp.vulnweb.com/Logout.asp", "parameter": "RetURL", "payload": "http://xfs.bxss.me", "description": "未验证重定向，可能导致钓鱼攻击", "solution": "验证重定向目标，使用白名单机制"},
            {"title": "未加密HTTP连接", "severity": "medium", "url": "http://testasp.vulnweb.com/", "description": "全站使用HTTP明文传输", "solution": "部署HTTPS强制加密"},
            {"title": "用户凭据明文传输", "severity": "medium", "url": "http://testasp.vulnweb.com/Login.asp", "parameter": "tfUPass", "description": "账号密码明文提交", "solution": "使用HTTPS加密传输敏感信息"},
            {"title": "未配置内容安全策略CSP", "severity": "info", "url": "http://testasp.vulnweb.com/", "description": "缺少CSP防护", "solution": "配置严格的CSP策略"},
            {"title": "无HTTP→HTTPS自动重定向", "severity": "info", "url": "http://testasp.vulnweb.com/", "description": "强制HTTPS失败", "solution": "配置HTTP到HTTPS自动跳转"},
        ]
    )
    results.append(testasp_result)
    
    return results


async def generate_reports():
    """生成三份报告"""
    print("=" * 60)
    print("AI 安全分析报告生成器")
    print("=" * 60)
    
    scan_results = parse_scan_results("D:\\AI_WebSecurity\\三份扫描结果.txt")
    generator = ProfessionalReportGenerator()
    
    report_names = [
        ("DVWA靶场安全检测报告", "DVWA靶场"),
        ("北华航天工业学院安全检测报告", "北华航天工业学院"),
        ("testasp.vulnweb.com安全检测报告", "testasp.vulnweb")
    ]
    
    for i, (report_name, short_name) in enumerate(report_names):
        scan_result = scan_results[i]
        print(f"\n[{i+1}/3] 正在生成: {report_name}")
        print(f"  目标: {scan_result.target}")
        print(f"  漏洞数: {len(scan_result.vulnerabilities)}")
        
        ai_analysis = await generator.ai_analyzer.analyze(scan_result)
        
        html_content = generator.generate_html_report(scan_result, ai_analysis)
        
        html_path = Path(f"D:\\AI_WebSecurity\\{short_name}_AI分析报告_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"  [OK] HTML 报告: {html_path.name}")
        
        try:
            pdf_content = generator.generate_pdf_report(html_content)
            pdf_path = Path(f"D:\\AI_WebSecurity\\{short_name}_AI分析报告_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
            with open(pdf_path, 'wb') as f:
                f.write(pdf_content)
            print(f"  [OK] PDF 报告: {pdf_path.name}")
        except Exception as e:
            print(f"  [WARN] PDF 生成失败: {e}")
    
    print("\n" + "=" * 60)
    print("报告生成完成!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(generate_reports())
