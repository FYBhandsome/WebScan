# -*- coding:utf-8 -*-
"""
报告管理器模块

负责报告的保存、查询、映射管理等功能。
使用 AI 大模型服务分析扫描结果并生成报告。
"""

import json
import logging
import asyncio
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
import threading

logger = logging.getLogger(__name__)


def _get_llm():
    """获取 LLM 实例"""
    from langchain_openai import ChatOpenAI
    from TOSKill.config import settings
    
    return ChatOpenAI(
        model=settings.MODEL_ID,
        temperature=0.3,
        api_key=settings.OPENAI_API_KEY,
        base_url=settings.OPENAI_BASE_URL
    )


@dataclass
class ReportInfo:
    """报告信息"""
    report_id: str
    session_id: str
    report_file: str
    target: str
    created_at: str
    download_url: str
    tool_results: Dict[str, Any]
    vulnerabilities: List[Dict[str, Any]]
    scan_summary: Dict[str, Any]


class ReportManager:
    """报告管理器 - 单例模式"""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if hasattr(self, '_initialized') and self._initialized:
            return
        
        from TOSKill.config import settings
        self.reports_dir = settings.REPORTS_PATH
        self.mapping_file = self.reports_dir / "mapping.json"
        self._mapping: Dict[str, Dict] = {}
        self._ensure_dirs()
        self._load_mapping()
        self._initialized = True
        logger.info(f"报告管理器初始化完成，报告目录: {self.reports_dir}")
    
    def _ensure_dirs(self):
        """确保目录存在"""
        self.reports_dir.mkdir(parents=True, exist_ok=True)
    
    def _load_mapping(self):
        """加载映射文件"""
        if self.mapping_file.exists():
            try:
                with open(self.mapping_file, 'r', encoding='utf-8') as f:
                    self._mapping = json.load(f)
                logger.info(f"加载映射文件: {len(self._mapping)} 条记录")
            except Exception as e:
                logger.error(f"加载映射文件失败: {e}")
                self._mapping = {}
        else:
            self._mapping = {}
    
    def _save_mapping(self):
        """保存映射文件"""
        try:
            with open(self.mapping_file, 'w', encoding='utf-8') as f:
                json.dump(self._mapping, f, ensure_ascii=False, indent=2)
            logger.debug("映射文件已保存")
        except Exception as e:
            logger.error(f"保存映射文件失败: {e}")
    
    def generate_report_filename(self, session_id: str, format: str = "md") -> str:
        """生成报告文件名"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_safe = session_id.replace("/", "_").replace(":", "_")[:20]
        return f"scan_report_{target_safe}_{timestamp}.{format}"
    
    def save_html_report(
        self,
        session_id: str,
        target: str,
        scan_time: str,
        vulnerabilities: List[Dict[str, Any]],
        tool_results: Dict[str, Any],
        ai_analysis: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """生成并保存HTML报告
        
        Args:
            session_id: 会话ID
            target: 扫描目标URL
            scan_time: 扫描时间
            vulnerabilities: 漏洞列表
            tool_results: 工具执行结果
            ai_analysis: AI分析结果（可选）
            
        Returns:
            包含报告信息的字典
        """
        from TOSKill.tools.report.html_report_generator import get_html_report_generator
        
        self._ensure_dirs()
        
        generator = get_html_report_generator()
        html_content = generator.generate_report(
            target=target,
            scan_time=scan_time,
            vulnerabilities=vulnerabilities,
            tool_results=tool_results,
            ai_analysis=ai_analysis,
            session_id=session_id
        )
        
        report_file = self.generate_report_filename(session_id, "html")
        report_path = self.reports_dir / report_file
        report_id = report_path.stem
        download_url = f"/api/reports/download/{report_file}"
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            logger.info(f"HTML报告已保存: {report_path}")
        except Exception as e:
            logger.error(f"保存HTML报告失败: {e}")
            raise
        
        report_info = {
            "report_id": report_id,
            "session_id": session_id,
            "report_file": report_file,
            "target": target,
            "created_at": created_at,
            "download_url": download_url,
            "format": "html",
            "vulnerabilities_count": len(vulnerabilities),
            "tool_results": tool_results,
            "vulnerabilities": vulnerabilities
        }
        
        self._mapping[session_id] = report_info
        self._save_mapping()
        
        return report_info
    
    def save_report(
        self,
        session_id: str,
        content: str,
        metadata: Dict[str, Any],
        format: str = "md"
    ) -> Dict[str, Any]:
        """保存报告到文件
        
        Args:
            session_id: 会话ID
            content: 报告内容
            metadata: 元数据，包含 target, tool_results, vulnerabilities 等
            format: 报告格式，默认 md
            
        Returns:
            包含报告信息的字典
        """
        self._ensure_dirs()
        
        report_file = self.generate_report_filename(session_id, format)
        report_path = self.reports_dir / report_file
        report_id = report_path.stem
        download_url = f"/api/reports/download/{report_file}"
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        content_with_location = f"""{content}

---

## 📁 报告存放位置

- **文件名**: `{report_file}`
- **下载地址**: `{download_url}`
- **会话ID**: `{session_id}`
- **生成时间**: {created_at}

*报告由 TOSKill Security Scanner 自动生成*
"""
        
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(content_with_location)
            logger.info(f"报告已保存: {report_path}")
        except Exception as e:
            logger.error(f"保存报告失败: {e}")
            raise
        
        report_info = {
            "report_id": report_id,
            "session_id": session_id,
            "report_file": report_file,
            "target": metadata.get("target", ""),
            "created_at": datetime.now().isoformat(),
            "download_url": download_url,
            "tool_results": metadata.get("tool_results", {}),
            "vulnerabilities": metadata.get("vulnerabilities", []),
            "scan_summary": metadata.get("scan_summary", {})
        }
        
        self._mapping[session_id] = report_info
        self._save_mapping()
        
        logger.info(f"报告映射已更新: {session_id} -> {report_file}")
        
        return report_info
    
    def get_report_by_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """根据会话ID获取报告信息"""
        return self._mapping.get(session_id)
    
    def get_report_by_id(self, report_id: str) -> Optional[Dict[str, Any]]:
        """根据报告ID获取报告信息"""
        for info in self._mapping.values():
            if info.get("report_id") == report_id:
                return info
        return None
    
    def get_all_reports(self) -> List[Dict[str, Any]]:
        """获取所有报告信息"""
        return list(self._mapping.values())
    
    def delete_report(self, session_id: str) -> bool:
        """删除报告"""
        if session_id not in self._mapping:
            return False
        
        report_info = self._mapping[session_id]
        report_file = report_info.get("report_file")
        
        if report_file:
            report_path = self.reports_dir / report_file
            if report_path.exists():
                try:
                    report_path.unlink()
                    logger.info(f"报告文件已删除: {report_path}")
                except Exception as e:
                    logger.error(f"删除报告文件失败: {e}")
        
        del self._mapping[session_id]
        self._save_mapping()
        
        return True
    
    def generate_ai_report_content(
        self,
        tool_results: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        target: str,
        chat_history: List[Dict] = None,
        task_history: List[Dict] = None
    ) -> str:
        """使用 AI 大模型生成分析报告内容（同步版本）
        
        Args:
            tool_results: 工具执行结果
            vulnerabilities: 漏洞列表
            target: 扫描目标
            chat_history: 聊天历史记录
            task_history: 任务执行历史
            
        Returns:
            Markdown格式的报告内容
        """
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(
                        self._generate_ai_report_sync,
                        tool_results, vulnerabilities, target, chat_history, task_history
                    )
                    return future.result()
            else:
                return self._generate_ai_report_sync(
                    tool_results, vulnerabilities, target, chat_history, task_history
                )
        except Exception as e:
            logger.error(f"AI 生成报告失败: {e}")
            return self._generate_fallback_report(tool_results, vulnerabilities, target)
    
    async def generate_ai_report_content_async(
        self,
        tool_results: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        target: str,
        chat_history: List[Dict] = None,
        task_history: List[Dict] = None
    ) -> str:
        """使用 AI 大模型生成分析报告内容（异步版本）
        
        Args:
            tool_results: 工具执行结果
            vulnerabilities: 漏洞列表
            target: 扫描目标
            chat_history: 聊天历史记录
            task_history: 任务执行历史
            
        Returns:
            Markdown格式的报告内容
        """
        try:
            return await self._generate_ai_report_async(
                tool_results, vulnerabilities, target, chat_history, task_history
            )
        except Exception as e:
            logger.error(f"AI 生成报告失败: {e}")
            return self._generate_fallback_report(tool_results, vulnerabilities, target)
    
    def _generate_ai_report_sync(
        self,
        tool_results: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        target: str,
        chat_history: List[Dict] = None,
        task_history: List[Dict] = None
    ) -> str:
        """同步生成 AI 报告 - 专业安全分析格式"""
        llm = _get_llm()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        tool_summary = self._summarize_tool_results(tool_results)
        vuln_summary = self._format_vulnerabilities_detailed(vulnerabilities)
        
        rag_context = self._get_rag_context(target, vulnerabilities)
        
        severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in vulnerabilities:
            sev = v.get("severity", "info").lower()
            if sev in severity_count:
                severity_count[sev] += 1
        
        prompt = f"""你是一位拥有15年以上经验的资深安全专家，精通渗透测试、漏洞分析、安全架构设计。请对以下安全扫描结果进行全面、专业的分析。

## 扫描目标信息
- 目标地址: {target}
- 扫描时间: {now}

## 漏洞统计概览
- 漏洞总数: {len(vulnerabilities)}
- 严重: {severity_count['critical']} | 高危: {severity_count['high']} | 中危: {severity_count['medium']} | 低危: {severity_count['low']} | 信息: {severity_count['info']}

## 工具结果摘要
{tool_summary}

## 漏洞详细数据
{vuln_summary}

## 知识库参考
{rag_context}

请生成专业安全分析报告，输出为严格 JSON 格式，包含以下内容：

### 1. 执行摘要 (executive_summary)
- 用简洁专业的语言概述整体安全状况
- 突出最关键的安全风险
- 字数控制在 100-150 字

### 2. 风险评估 (risk_assessment)
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
- description: 攻击链描述
- attack_paths: 可能的攻击路径列表
- lateral_movement_risk: 横向移动风险

### 5. 合规性影响 (compliance_impact)
- standards: 相关安全标准列表（等保2.0、OWASP Top 10等）
- risk_points: 合规风险点列表

### 6. 修复建议 (remediation_recommendations)
按优先级排序的修复建议：
- priority: 优先级 (1-5, 1最高)
- vulnerability: 关联漏洞
- recommendation: 具体修复措施
- estimated_effort: 预估工作量
- references: 参考链接或文档

### 7. 安全加固建议 (security_hardening)
- short_term: 短期措施列表（立即执行）
- mid_term: 中期措施列表（1-3个月）
- long_term: 长期措施列表（持续改进）

## 输出格式要求
严格输出 JSON 格式，不要包含任何其他内容：
```json
{{
  "executive_summary": "执行摘要内容...",
  "risk_assessment": {{
    "overall_risk": "high",
    "risk_score": 75,
    "risk_justification": "评级依据..."
  }},
  "vulnerability_analysis": [...],
  "attack_chain_analysis": {{...}},
  "compliance_impact": {{...}},
  "remediation_recommendations": [...],
  "security_hardening": {{...}}
}}
```

请确保分析专业、全面、可操作，体现资深安全专家的专业水准。"""
        
        response = llm.invoke(prompt)
        return response.content
    
    def _get_rag_context(self, target: str, vulnerabilities: List[Dict]) -> str:
        """获取RAG知识库上下文"""
        try:
            from TOSKill.RAG.retriever import get_scan_strategy
            vuln_types = list(set(v.get("type") or v.get("vuln_type", "") for v in vulnerabilities if v.get("type") or v.get("vuln_type")))
            rag_result = get_scan_strategy(
                target=target,
                current_task="report_generation",
                completed_tasks=[],
                last_result={"vulnerabilities": vulnerabilities}
            )
            if rag_result and len(rag_result) > 100:
                return rag_result[:1500]
        except Exception as e:
            logger.debug(f"RAG检索失败: {e}")
        return "无"
    
    def _format_vulnerabilities_detailed(self, vulns: List) -> str:
        """格式化漏洞详细信息"""
        if not vulns:
            return "无漏洞发现"
        
        import json
        vuln_data = []
        for v in vulns[:10]:
            vuln_data.append({
                "id": v.get("id", "unknown"),
                "type": v.get("type") or v.get("vuln_type", "unknown"),
                "severity": v.get("severity", "unknown"),
                "url": str(v.get("url") or v.get("target", ""))[:100],
                "parameter": v.get("parameter", ""),
                "payload": str(v.get("payload", ""))[:100],
                "description": v.get("description", "")[:200]
            })
        return json.dumps(vuln_data, ensure_ascii=False, indent=2)
    
    def generate_professional_ai_analysis(
        self,
        tool_results: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        target: str
    ) -> Dict[str, Any]:
        """生成专业AI分析结果（用于HTML报告）"""
        try:
            import json
            import re
            
            md_report = self._generate_ai_report_sync(tool_results, vulnerabilities, target)
            
            json_match = re.search(r'\{[\s\S]*\}', md_report)
            if json_match:
                return json.loads(json_match.group())
            
            return self._generate_fallback_ai_analysis(vulnerabilities, target)
        except Exception as e:
            logger.error(f"生成专业AI分析失败: {e}")
            return self._generate_fallback_ai_analysis(vulnerabilities, target)
    
    def _generate_fallback_ai_analysis(
        self,
        vulnerabilities: List[Dict[str, Any]],
        target: str
    ) -> Dict[str, Any]:
        """生成备用AI分析结果"""
        severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in vulnerabilities:
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
        
        vuln_analysis = []
        for i, v in enumerate(vulnerabilities[:5]):
            vuln_analysis.append({
                "vuln_id": f"VULN-{i+1:03d}",
                "vuln_name": v.get("title") or v.get("type") or v.get("vuln_type", "Unknown"),
                "technical_analysis": v.get("description", "未提供详细技术分析"),
                "business_impact": "可能导致数据泄露或服务中断",
                "exploitation_difficulty": "medium",
                "attack_scenario": "攻击者可利用此漏洞获取敏感信息",
                "cvss_estimate": 9.8 if v.get("severity") == "critical" else 7.5 if v.get("severity") == "high" else 5.0
            })
        
        return {
            "executive_summary": f"目标 {target} 存在 {len(vulnerabilities)} 个安全问题，其中高危 {severity_count['high']} 个，中危 {severity_count['medium']} 个。建议尽快修复高危漏洞。",
            "risk_assessment": {
                "overall_risk": risk_level,
                "risk_score": risk_score,
                "risk_justification": "基于漏洞数量和严重程度评估"
            },
            "vulnerability_analysis": vuln_analysis,
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
                    "vulnerability": v.get("title") or v.get("type", "Unknown"),
                    "recommendation": v.get("solution") or "请参考安全最佳实践进行修复",
                    "estimated_effort": "2-4小时",
                    "references": "OWASP"
                }
                for v in vulnerabilities[:5]
            ],
            "security_hardening": {
                "short_term": ["修复高危漏洞", "加强访问控制"],
                "mid_term": ["部署WAF", "实施安全监控"],
                "long_term": ["建立安全开发流程", "定期安全审计"]
            }
        }
    
    async def _generate_ai_report_async(
        self,
        tool_results: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        target: str,
        chat_history: List[Dict] = None,
        task_history: List[Dict] = None
    ) -> str:
        """异步生成 AI 报告"""
        llm = _get_llm()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        tool_summary = self._summarize_tool_results(tool_results)
        vuln_summary = self._format_vulnerabilities(vulnerabilities)
        chat_summary = self._format_chat_history(chat_history)
        task_summary = self._format_task_history(task_history)
        
        prompt = f"""你是安全分析师，基于以下数据生成简洁的安全报告。

## 基本信息
- 目标: {target}
- 时间: {now}
- 工具数: {len(tool_results)}
- 漏洞数: {len(vulnerabilities)}

## 工具结果摘要
{tool_summary}

## 发现的漏洞
{vuln_summary}

## 用户交互记录
{chat_summary}

## 任务执行记录
{task_summary}

请生成简洁报告（控制在500字内），包含：
1. **风险等级**: 高/中/低
2. **关键发现**: 最多3条
3. **修复建议**: 具体可执行

要求：专业简洁，突出重点。"""
        
        response = await llm.ainvoke(prompt)
        return response.content
    
    def _summarize_tool_results(self, results: Dict) -> str:
        """精简工具结果摘要"""
        if not results:
            return "无"
        summary = []
        for tool, result in list(results.items())[:10]:
            if isinstance(result, dict):
                status = "⚠️ 发现问题" if result.get("vulnerable") else "✅ 正常"
                summary.append(f"- {tool}: {status}")
            else:
                summary.append(f"- {tool}: 已完成")
        return "\n".join(summary)
    
    def _format_vulnerabilities(self, vulns: List) -> str:
        """格式化漏洞信息"""
        if not vulns:
            return "无漏洞发现"
        lines = []
        for v in vulns[:5]:
            sev = v.get("severity", "unknown").upper()
            vtype = v.get("type") or v.get("vuln_type", "unknown")
            url = v.get("url") or v.get("target", "")
            lines.append(f"- [{sev}] {vtype}: {url[:50]}")
        return "\n".join(lines)
    
    def _format_chat_history(self, history: List) -> str:
        """格式化聊天历史"""
        if not history:
            return "无"
        lines = []
        for h in history[-5:]:
            role = h.get("role", "unknown")
            content = h.get("content", "")[:80]
            lines.append(f"- {role}: {content}")
        return "\n".join(lines)
    
    def _format_task_history(self, tasks: List) -> str:
        """格式化任务历史"""
        if not tasks:
            return "无"
        lines = []
        for t in tasks[:10]:
            tool = t.get("tool", "unknown")
            summary = t.get("result_summary", "")[:50]
            lines.append(f"- {tool}: {summary}")
        return "\n".join(lines)
    
    def _generate_fallback_report(
        self,
        tool_results: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        target: str
    ) -> str:
        """生成备用报告（当 AI 服务不可用时）"""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        report_lines = [
            f"# 安全扫描报告",
            f"",
            f"> 生成时间: {now}",
            f"> 扫描目标: {target}",
            f"",
            f"---",
            f"",
            f"## 1. 执行摘要",
            f"",
            f"本次扫描共执行 **{len(tool_results)}** 个工具，发现 **{len(vulnerabilities)}** 个安全问题。",
            f"",
        ]
        
        if vulnerabilities:
            severity_counts = {}
            for vuln in vulnerabilities:
                sev = vuln.get("severity", "unknown")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            report_lines.append("### 漏洞严重度分布")
            report_lines.append("")
            for sev in ["critical", "high", "medium", "low", "info"]:
                if sev in severity_counts:
                    report_lines.append(f"- **{sev.upper()}**: {severity_counts[sev]} 个")
            report_lines.append("")
        
        report_lines.extend([
            f"---",
            f"",
            f"## 2. 工具执行结果",
            f"",
        ])
        
        for tool_name, result in tool_results.items():
            report_lines.append(f"### {tool_name}")
            report_lines.append("")
            if isinstance(result, dict):
                result_str = json.dumps(result, ensure_ascii=False, indent=2)
            else:
                result_str = str(result)
            report_lines.append(f"```json")
            report_lines.append(result_str[:2000])
            report_lines.append(f"```")
            report_lines.append("")
        
        if vulnerabilities:
            report_lines.extend([
                f"---",
                f"",
                f"## 3. 漏洞详情",
                f"",
            ])
            
            for i, vuln in enumerate(vulnerabilities, 1):
                severity = vuln.get("severity", "unknown")
                vuln_type = vuln.get("type") or vuln.get("vuln_type", "Unknown")
                url = vuln.get("url", vuln.get("target", ""))
                
                report_lines.append(f"### {i}. {vuln_type}")
                report_lines.append("")
                report_lines.append(f"| 属性 | 值 |")
                report_lines.append(f"|------|-----|")
                report_lines.append(f"| 严重度 | **{severity.upper()}** |")
                if url:
                    report_lines.append(f"| URL | `{url}` |")
                if vuln.get("description"):
                    report_lines.append(f"| 描述 | {vuln.get('description')} |")
                report_lines.append("")
        
        report_lines.extend([
            f"---",
            f"",
            f"## 4. 修复建议",
            f"",
            f"- 建议对发现的问题进行深入分析",
            f"- 及时修复高危漏洞",
            f"- 定期进行安全扫描",
            f"",
            f"---",
            f"",
            f"*报告由 TOSKill Security Scanner 自动生成*",
        ])
        
        return "\n".join(report_lines)


report_manager = ReportManager()


def get_report_manager() -> ReportManager:
    """获取报告管理器实例"""
    return report_manager
