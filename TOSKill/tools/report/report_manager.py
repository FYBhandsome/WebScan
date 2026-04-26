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
        
        self.reports_dir = Path("reports")
        self.mapping_file = self.reports_dir / "mapping.json"
        self._mapping: Dict[str, Dict] = {}
        self._ensure_dirs()
        self._load_mapping()
        self._initialized = True
        logger.info("报告管理器初始化完成")
    
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
        return f"scan_report_{session_id}_{timestamp}.{format}"
    
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
        """同步生成 AI 报告"""
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
        
        response = llm.invoke(prompt)
        return response.content
    
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
