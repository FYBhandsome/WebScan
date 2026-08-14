"""新项目的扫描报告 HTML 模板。

模板按用户最初选择的扫描类型渲染，而不是按扫描执行过程中的临时阶段渲染。
"""

from __future__ import annotations

from datetime import datetime
from html import escape
from typing import Any, Dict, Iterable, List, Optional, Tuple

from TOSKill.tools.tool_categories import (
    information_items,
    is_information_tool,
    is_vulnerability_tool,
    tool_display_name,
)
from TOSKill.tools.report.vulnerability_normalizer import consolidate_vulnerabilities

SEVERITY = {
    "critical": ("严重", "critical"), "high": ("高危", "high"),
    "medium": ("中危", "medium"), "low": ("低危", "low"),
    "info": ("信息", "info"),
}


def normalize_report_type(report_type: Optional[str]) -> str:
    aliases = {
        "info": "info_collection", "information": "info_collection",
        "info_collection": "info_collection", "vuln": "vuln_scan",
        "vulnerability": "vuln_scan", "vuln_scan": "vuln_scan",
        "full": "full_scan", "full_scan": "full_scan",
    }
    return aliases.get(str(report_type or "").lower(), "vuln_scan")


def _plain(value: Any, limit: int = 240) -> str:
    if value is None or value == "":
        return ""
    if isinstance(value, bool):
        return "是" if value else "否"
    if isinstance(value, (list, tuple, set)):
        text = "、".join(_plain(item, 80) for item in value if _plain(item, 80))
    elif isinstance(value, dict):
        text = "；".join(
            f"{key}: {_plain(item, 80)}" for key, item in value.items()
            if _plain(item, 80)
        )
    else:
        text = str(value)
    return text[:limit] + ("…" if len(text) > limit else "")


def _safe(value: Any, default: str = "—") -> str:
    text = _plain(value)
    return escape(text or default)


def _result_data(result: Any) -> Dict[str, Any]:
    if not isinstance(result, dict):
        return {"result": result}
    data = result.get("data")
    if isinstance(data, dict) and data:
        return data
    return {
        key: value for key, value in result.items()
        if key not in {"success", "error", "timestamp", "metadata", "data"}
    }


def _is_success(result: Any) -> bool:
    return not isinstance(result, dict) or result.get("success") is not False


def _information_rows(tool_name: str, result: Any) -> List[Tuple[str, Any]]:
    return [(item["label"], item["value"]) for item in information_items(tool_name, result)]


def _information_cards(tool_results: Dict[str, Any]) -> List[Dict[str, Any]]:
    cards = []
    for tool_name, result in tool_results.items():
        if not is_information_tool(tool_name) or not _is_success(result):
            continue
        rows = _information_rows(tool_name, result)
        if rows:
            cards.append({"tool": tool_name, "title": tool_display_name(tool_name), "rows": rows})
    return cards


def _list_count(result: Any, *keys: str) -> int:
    data = _result_data(result)
    for key in keys:
        value = data.get(key)
        if isinstance(value, (list, tuple, set, dict)):
            return len(value)
        if isinstance(value, int):
            return value
    return 0


def _information_metrics(tool_results: Dict[str, Any], cards: List[Dict[str, Any]]) -> List[Tuple[str, str, str]]:
    info_results = {name: result for name, result in tool_results.items() if is_information_tool(name)}
    completed = sum(1 for result in info_results.values() if _is_success(result))
    ports = _list_count(info_results.get("port_scan", {}), "open_ports", "ports", "total_count")
    subdomains = _list_count(info_results.get("subdomain_scan", {}), "subdomains", "total_count")
    resources = _list_count(info_results.get("crawler_scan", {}), "pages", "urls", "crawled_urls", "page_count")
    return [
        (str(completed), "已完成信息收集工具", "仅统计信息收集类工具"),
        (str(ports), "已识别开放端口", "端口与服务暴露面"),
        (str(subdomains), "已发现子域名", "目标关联资产"),
        (str(resources), "已发现站点资源", "页面、目录与可访问路径"),
    ]


def _normalized_vulnerabilities(vulnerabilities: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    normalized = []
    for item in consolidate_vulnerabilities(vulnerabilities):
        if not isinstance(item, dict):
            continue
        vuln = dict(item)
        vuln["severity"] = str(vuln.get("severity") or "info").lower()
        if vuln["severity"] not in SEVERITY:
            vuln["severity"] = "info"
        vuln["title"] = vuln.get("title") or vuln.get("name") or vuln.get("vuln_type") or vuln.get("type") or "未命名问题"
        vuln["remediation"] = vuln.get("remediation") or vuln.get("solution") or "请结合验证证据完成修复。"
        normalized.append(vuln)
    return sorted(normalized, key=lambda item: order[item["severity"]])


def _severity_counts(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {key: 0 for key in SEVERITY}
    for vuln in vulnerabilities:
        counts[vuln["severity"]] += 1
    return counts


def _risk_data(vulnerabilities: List[Dict[str, Any]], ai_analysis: Optional[Dict[str, Any]]) -> Tuple[float, str]:
    risk = (ai_analysis or {}).get("risk_assessment") or {}
    try:
        score = float(risk.get("risk_score"))
    except (TypeError, ValueError):
        counts = _severity_counts(vulnerabilities)
        score = min(100.0, counts["critical"] * 25 + counts["high"] * 15 + counts["medium"] * 8 + counts["low"] * 3)
    level = str(risk.get("overall_risk") or "").lower()
    if level not in SEVERITY:
        counts = _severity_counts(vulnerabilities)
        level = next((item for item in ("critical", "high", "medium", "low") if counts[item]), "info")
    return max(0.0, min(100.0, score)), level


def _icon() -> str:
    return '<svg class="icon-svg" viewBox="0 0 24 24" aria-hidden="true"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-5 14h-4v-2h4v2zm2-4H8v-2h8v2zm0-4H8V7h8v2z"/></svg>'


def _header(target: str, scan_time: str, session_id: str, report_type: str) -> str:
    labels = {
        "info_collection": ("信息收集报告", "资产、服务与攻击面信息汇总", "信息收集"),
        "vuln_scan": ("安全分析研判报告", "标准化渗透扫描安全评估文书", "漏洞扫描"),
        "full_scan": ("完整扫描报告", "资产与攻击面信息收集、漏洞验证结果汇总", "完整扫描"),
    }
    title, subtitle, mode_label = labels[report_type]
    date_token = "".join(char for char in str(scan_time)[:10] if char.isdigit()) or datetime.now().strftime("%Y%m%d")
    safe_session = "".join(char for char in str(session_id) if char.isalnum() or char in "-_")[:24] or "NA"
    report_no = f"SEC-{date_token}-{safe_session}"
    return f'''<header class="report-header">
      <h1 class="header-top">{_icon()}{title}</h1>
      <div class="header-subtitle">{subtitle}</div>
      <div class="meta-wrap">
        <div class="meta-item"><span class="meta-label">报告编号：</span><span class="text-body">{_safe(report_no)}</span></div>
        <div class="meta-item"><span class="meta-label">扫描目标：</span><span class="text-body">{_safe(target)}</span></div>
        <div class="meta-item"><span class="meta-label">扫描执行时间：</span><span class="text-body">{_safe(scan_time)}</span></div>
        <div class="meta-item"><span class="meta-label">扫描模式：</span><span class="text-body">{mode_label}</span></div>
      </div>
    </header>'''


def _information_section(tool_results: Dict[str, Any], include_status: bool) -> str:
    cards = _information_cards(tool_results)
    metrics = _information_metrics(tool_results, cards)
    metrics_html = "".join(
        f'<div class="overview-item"><span class="overview-value">{_safe(value, "0")}</span><span class="overview-label">{label}</span><span class="overview-tip">{tip}</span></div>'
        for value, label, tip in metrics
    )
    cards_html = "".join(
        f'''<article class="collection-card"><div class="collection-head"><h3>{_safe(card["title"])}</h3><span class="tool-tag">{_safe(card["tool"])}</span></div>
          <ul class="data-list">{"".join(f"<li><span class='data-key'>{_safe(label)}</span><span>{_safe(value)}</span></li>" for label, value in card["rows"])}</ul></article>'''
        for card in cards
    ) or '<p class="empty-state">本次信息收集工具未返回可展示的信息。</p>'
    status_html = ""
    if include_status:
        status_items = []
        for tool_name, result in tool_results.items():
            if not is_information_tool(tool_name):
                continue
            state = "已完成" if _is_success(result) else "失败"
            state_class = "completed" if _is_success(result) else "failed"
            status_items.append(f'<div class="tool-row"><span class="tool-state {state_class}"></span><span class="tool-name">{_safe(tool_name)}</span><span class="tool-result {state_class}">{state}</span></div>')
        if status_items:
            status_html = f'<section class="card tool-module"><h2 class="module-title">{_icon()}信息收集工具执行状态</h2><div class="tool-grid">{"".join(status_items)}</div></section>'
    return f'''<section class="card info-module">
      <h2 class="module-title">{_icon()}信息收集结果</h2>
      <p class="section-note">仅展示信息收集工具实际返回的有效字段；这部分不使用漏洞结论。</p>
      <div class="overview-grid">{metrics_html}</div>
      <p class="notice">某项工具没有返回有效信息时，正式报告不生成空卡片，也不使用与信息收集无关的结果描述。</p>
      <div class="collection-grid">{cards_html}</div>
    </section>{status_html}'''


def _risk_section(vulnerabilities: List[Dict[str, Any]], ai_analysis: Optional[Dict[str, Any]]) -> str:
    counts = _severity_counts(vulnerabilities)
    score, level = _risk_data(vulnerabilities, ai_analysis)
    label, _ = SEVERITY[level]
    bars = []
    total = max(len(vulnerabilities), 1)
    for severity, title in (("critical", "严重漏洞"), ("high", "高危漏洞"), ("medium", "中危漏洞"), ("low", "低危漏洞"), ("info", "信息类配置缺陷")):
        bars.append(f'<div class="risk-bar-item"><div class="bar-label">{title}</div><div class="bar-outer"><div class="bar-inner bar-{severity}" style="width:{counts[severity] / total * 100:.1f}%"></div></div><div class="bar-count">{counts[severity]}</div></div>')
    top = vulnerabilities[0]["title"] if vulnerabilities else "—"
    summary = "本次漏洞扫描未确认漏洞。" if not vulnerabilities else f"本次漏洞扫描共确认 {len(vulnerabilities)} 个问题，当前最高优先级问题为“{_safe(top)}”。"
    return f'''<section class="card risk-overview"><h2 class="module-title">{_icon()}漏洞扫描风险概览</h2>
      <div class="risk-head-row"><div class="risk-score-box"><span class="score-num level-{level}">{score:g}</span><span class="score-desc level-{level}">综合风险等级：{label} ({level.upper()})</span></div><div class="risk-bar-group">{"".join(bars)}</div></div>
      <div class="text-body">{summary}</div></section>'''


def _confidence_section(confidence: Optional[Dict[str, Any]]) -> str:
    if not confidence:
        return f'<section class="card confidence-module"><h2 class="module-title">{_icon()}AI 等保评估置信度</h2><p class="confidence-placeholder">本次未生成置信度数据。</p></section>'
    try:
        score = max(0, min(100, float(confidence.get("overall_score", 0))))
    except (TypeError, ValueError):
        score = 0
    level = str(confidence.get("level") or "info").lower()
    labels = {"high": "高置信度", "mid": "中置信度", "low": "低置信度", "info": "待评估"}
    dimensions = [item for item in confidence.get("dimensions", []) if isinstance(item, dict)][:4]
    items = []
    for item in dimensions:
        try:
            value = max(0, min(100, float(item.get("value", 0))))
        except (TypeError, ValueError):
            value = 0
        items.append(f'<div class="confidence-item"><span class="item-label">{_safe(item.get("label"), "评估维度")}</span><span class="item-bar-track"><span class="item-bar-fill" style="width:{value:.1f}%"></span></span><span class="item-value">{value:.0f}%</span></div>')
    note = _safe(confidence.get("note"), "置信度基于本次扫描的结构化结果生成，建议结合业务实际进行人工复核。")
    return f'''<section class="card confidence-module"><h2 class="module-title">{_icon()}AI 等保评估置信度</h2>
      <div class="confidence-layout"><div class="confidence-summary"><p class="confidence-kicker">{_safe(confidence.get("standard_text"), "基于等保 2.0 三级标准")}</p><span class="confidence-number">{score:.0f}%</span><span class="confidence-label">综合评估置信度</span><br><span class="confidence-badge">{labels.get(level, labels["info"])}</span><p class="confidence-note">{note}</p></div><div class="confidence-details">{"".join(items) or '<p class="text-tip">暂无分项置信度数据。</p>'}</div></div>
    </section>'''


def _vulnerability_section(vulnerabilities: List[Dict[str, Any]]) -> str:
    cards = []
    for vuln in vulnerabilities:
        label, css = SEVERITY[vuln["severity"]]
        meta = []
        if vuln.get("cwe_id"):
            meta.append(str(vuln["cwe_id"]))
        if vuln.get("method"):
            meta.append(str(vuln["method"]))
        if vuln.get("confidence") not in (None, ""):
            try:
                meta.append(f"置信度 {float(vuln['confidence']) * 100:.0f}%")
            except (TypeError, ValueError):
                pass
        details = []
        for title, value in (("目标", vuln.get("url") or vuln.get("target")), ("证据", vuln.get("evidence")), ("描述", vuln.get("description"))):
            if _plain(value):
                details.append(f'<p><strong>{title}：</strong>{_safe(value)}</p>')
        parameter = vuln.get("parameter") or vuln.get("affected_parameter")
        location = f'<p class="vuln-location">输入位置：{_safe(parameter)}</p>' if _plain(parameter) else ""
        evidence_count = int(vuln.get("evidence_count") or 0)
        deduplicated_count = int(vuln.get("deduplicated_count") or 0)
        evidence_summary = ""
        if evidence_count > 1 or deduplicated_count > 0:
            summary_parts = [f"保留 {evidence_count} 条独立验证证据"]
            if deduplicated_count:
                summary_parts.append(f"已合并 {deduplicated_count} 条完全重复命中")
            evidence_summary = f'<p class="evidence-summary">{"；".join(summary_parts)}</p>'
        payloads = vuln.get("payloads") if isinstance(vuln.get("payloads"), list) else []
        payload_summary = ""
        if len(payloads) > 1:
            shown_payloads = "".join(f"<code>{_safe(payload)}</code>" for payload in payloads[:3])
            remaining = f"<span>另有 {len(payloads) - 3} 条</span>" if len(payloads) > 3 else ""
            payload_summary = f'<div class="payload-summary"><strong>验证 Payload：</strong>{shown_payloads}{remaining}</div>'
        cards.append(f'''<article class="vuln-item"><div class="vuln-title-row"><span class="risk-tag tag-{css}">{label}</span>{_safe(vuln["title"])}</div>
          <p class="vuln-tip-text">{_safe(vuln.get("description"), "已确认安全问题，请结合证据完成修复。")}</p>
          <div class="vuln-detail text-body">{evidence_summary}{"".join(details) or '<p>暂无补充证据。</p>'}{payload_summary}{location}</div></article>''')
    content = "".join(cards) or '<p class="empty-state">本次漏洞扫描未确认漏洞。</p>'
    return f'<section class="card vuln-section"><h2 class="module-title">{_icon()}确认的问题（按受影响位置展示）</h2><div class="vuln-list-wrap">{content}</div></section>'


def _unique(values: Iterable[str]) -> List[str]:
    result, seen = [], set()
    for value in values:
        key = value.strip()
        if key and key not in seen:
            seen.add(key)
            result.append(key)
    return result


def _remediation_section(vulnerabilities: List[Dict[str, Any]], ai_analysis: Optional[Dict[str, Any]]) -> str:
    urgent, deadline, long_term = [], [], []
    for vuln in vulnerabilities:
        text = f'{_plain(vuln["title"])}：{_plain(vuln["remediation"])}'
        if vuln["severity"] in {"critical", "high"}:
            urgent.append(text)
        elif vuln["severity"] == "medium":
            deadline.append(text)
        else:
            long_term.append(text)
    hardening = (ai_analysis or {}).get("security_hardening") or {}
    deadline.extend(_plain(item) for item in hardening.get("mid_term", []) or [])
    long_term.extend(_plain(item) for item in (hardening.get("short_term", []) or []) + (hardening.get("long_term", []) or []))
    columns = [
        ("紧急修复（7日内完成）", "fix-emergency", _unique(urgent) or ["暂无严重或高危问题，持续复核新增风险。"]),
        ("限期整改（30日内完成）", "fix-deadline", _unique(deadline) or ["结合业务影响复核已确认问题，并完成复测。"]),
        ("常态化长效优化", "fix-longterm", _unique(long_term) or ["建立周期性扫描、补丁更新与安全基线核查机制。"]),
    ]
    blocks = "".join(f'<div class="fix-block {css}"><h3 class="fix-block-title">{title}</h3><ul class="list-uniform">{"".join(f"<li>{_safe(item)}</li>" for item in items[:6])}</ul></div>' for title, css, items in columns)
    return f'<section class="card fix-plan-container"><h2 class="module-title">{_icon()}分层加固整改方案</h2><div class="fix-three-col">{blocks}</div></section>'


def _ai_section(vulnerabilities: List[Dict[str, Any]], ai_analysis: Optional[Dict[str, Any]]) -> str:
    if not vulnerabilities:
        return ""
    summary = _safe((ai_analysis or {}).get("executive_summary"), f"本次扫描确认 {len(vulnerabilities)} 个问题，应优先处理高风险项。")
    facts = []
    for vuln in vulnerabilities[:4]:
        fact = _plain(vuln["title"])
        if _plain(vuln.get("evidence")):
            fact += f"：{_plain(vuln.get('evidence'), 100)}"
        facts.append(fact)
    recommendations = (ai_analysis or {}).get("remediation_recommendations") or []
    next_steps = [
        _plain(item.get("recommendation")) for item in recommendations
        if isinstance(item, dict) and _plain(item.get("recommendation"))
    ]
    if not next_steps:
        next_steps = ["优先完成高风险问题的修复。", "修复后对已确认位置进行复测。", "结合应用代码确认输入数据处理路径。"]
    return f'''<section class="card ai-section"><h2 class="module-title">{_icon()}AI 智能分析</h2><div class="ai-grid">
      <div class="analysis-block"><h3>风险总结</h3><p class="text-body">{summary}</p></div>
      <div class="analysis-block"><h3>验证结论</h3><ul class="list-uniform">{"".join(f"<li>{_safe(item)}</li>" for item in _unique(facts)[:4])}</ul></div>
      <div class="analysis-block"><h3>下一步建议</h3><ul class="list-uniform">{"".join(f"<li>{_safe(item)}</li>" for item in _unique(next_steps)[:4])}</ul></div>
    </div></section>'''


def _appendix(report_type: str, cards: List[Dict[str, Any]], vulnerabilities: List[Dict[str, Any]]) -> str:
    items = []
    if report_type in {"info_collection", "full_scan"}:
        items.append(f'<div class="evidence-item"><strong>信息收集证据摘要</strong>已收集 {len(cards)} 类有效信息；仅保留端口、资产、技术指纹、路径等必要字段。</div>')
    if report_type in {"vuln_scan", "full_scan"}:
        evidence_count = sum(int(item.get("evidence_count") or 0) for item in vulnerabilities)
        raw_count = sum(int(item.get("occurrence_count") or 1) for item in vulnerabilities)
        duplicate_count = max(0, raw_count - evidence_count)
        duplicate_note = f"；已过滤 {duplicate_count} 条完全重复命中" if duplicate_count else ""
        items.append(f'<div class="evidence-item"><strong>漏洞验证证据摘要</strong>已确认 {len(vulnerabilities)} 个问题，保留 {evidence_count} 条独立验证证据{duplicate_note}。</div>')
    items.append('<div class="evidence-item"><strong>报告保留策略</strong>正文不输出完整工具 JSON、响应正文和重复 Payload。</div>')
    return f'<section class="appendix-card"><details><summary class="appendix-summary">{_icon()}查看必要验证与收集证据</summary><div class="appendix-content"><div class="evidence-grid">{"".join(items)}</div></div></details></section>'


def _styles() -> str:
    return """
* { margin: 0; padding: 0; box-sizing: border-box; }
:root { --gap-sm:10px; --gap-md:12px; --gap-lg:24px; --gap-xl:24px; --radius:4px; --border:#e5e7eb; --primary:#165dff; --critical:#d93025; --high:#e67e22; --medium:#d4a017; --low:#165dff; --info:#888; --success:#00a870; }
body { background:#f7f8fa; padding:32px; color:#222; line-height:1.8; font-family:"Source Han Sans CN","Microsoft YaHei UI","Microsoft YaHei",sans-serif; -webkit-font-smoothing:antialiased; }
.report-shell { width:min(1440px,100%); margin:0 auto; }.card,.report-header,.appendix-card { background:#fff; border:1px solid var(--border); border-radius:var(--radius); padding:var(--gap-lg); }.report-header,.info-module,.tool-module,.risk-overview,.confidence-module,.vuln-section,.fix-plan-container,.ai-section { margin-bottom:var(--gap-xl); }
.header-top,.module-title { display:flex; align-items:center; gap:var(--gap-sm); font-weight:700; }.header-top { font-size:22px; margin-bottom:var(--gap-sm); }.header-subtitle { font:13px "Source Han Serif CN",SimSun,serif; color:#666; margin-bottom:var(--gap-lg); }.icon-svg { width:20px; height:20px; fill:var(--primary); flex:0 0 20px; }.meta-wrap { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:var(--gap-md); }.meta-item { display:flex; flex-direction:column; gap:4px; min-width:0; }.meta-label { font-weight:500; color:#444; }.text-body,.text-tip { font-family:"Source Han Serif CN",SimSun,serif; color:#333; overflow-wrap:anywhere; }.text-body { font-size:14px; }.module-title { font-size:18px; padding-bottom:var(--gap-sm); border-bottom:1px solid var(--border); margin-bottom:var(--gap-lg); }.section-note { margin:-8px 0 var(--gap-lg); color:#666; font:13px "Source Han Serif CN",SimSun,serif; }
.overview-grid { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:var(--gap-md); }.overview-item { min-height:98px; padding:16px; background:#f9fafb; border:1px solid var(--border); border-radius:var(--radius); }.overview-value { display:block; color:var(--primary); font-size:25px; font-weight:700; line-height:1.25; }.overview-label { display:block; margin-top:4px; color:#555; font-size:13px; }.overview-tip { display:block; margin-top:6px; color:#888; font-size:12px; }.notice { margin:var(--gap-lg) 0; padding:11px 13px; border-left:3px solid var(--primary); background:#f9fafb; color:#555; font:13px/1.7 "Source Han Serif CN",SimSun,serif; }
.collection-grid { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:var(--gap-lg); }.collection-card { min-width:0; padding:18px; border:1px solid var(--border); border-radius:var(--radius); }.collection-head { display:flex; align-items:flex-start; justify-content:space-between; gap:var(--gap-md); margin-bottom:13px; }.collection-head h3 { font-size:15px; }.tool-tag { flex:0 0 auto; padding:2px 8px; border:1px solid rgba(22,93,255,.15); border-radius:2px; color:var(--primary); background:#e8f0fe; font:12px Consolas,monospace; }.data-list,.list-uniform { list-style:none; }.data-list li { display:grid; grid-template-columns:92px minmax(0,1fr); gap:var(--gap-sm); padding:7px 0; border-top:1px dashed var(--border); font:13px/1.7 "Source Han Serif CN",SimSun,serif; overflow-wrap:anywhere; }.data-list li:first-child { padding-top:0; border-top:0; }.data-key { color:#666; }.empty-state { padding:24px; text-align:center; color:#666; }
.tool-grid { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:var(--gap-md); }.tool-row { display:flex; align-items:center; gap:var(--gap-sm); padding:11px 12px; border:1px solid var(--border); border-radius:var(--radius); background:#f9fafb; }.tool-state { width:9px; height:9px; flex:0 0 9px; border-radius:50%; background:var(--success); }.tool-state.failed { background:var(--critical); }.tool-name { min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font:13px Consolas,monospace; }.tool-result { margin-left:auto; color:var(--success); font-size:12px; }.tool-result.failed { color:var(--critical); }
.risk-head-row { display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:var(--gap-lg); margin-bottom:var(--gap-md); }.risk-score-box { display:flex; align-items:baseline; gap:var(--gap-sm); }.score-num { font-size:24px; font-weight:700; }.score-desc { font-size:14px; font-weight:600; }.level-critical { color:var(--critical); }.level-high { color:var(--high); }.level-medium { color:var(--medium); }.level-low { color:var(--low); }.level-info { color:var(--info); }.risk-bar-group { display:flex; gap:var(--gap-md); flex:1; min-width:520px; }.risk-bar-item { flex:1; min-width:72px; text-align:center; }.bar-label { min-height:24px; color:#666; font-size:12px; }.bar-outer { height:6px; overflow:hidden; border-radius:3px; background:#eee; }.bar-inner { height:100%; }.bar-critical { background:var(--critical); }.bar-high { background:var(--high); }.bar-medium { background:var(--medium); }.bar-low { background:var(--low); }.bar-info { background:var(--info); }.bar-count { margin-top:4px; font-size:13px; font-weight:600; }
.confidence-layout { display:grid; grid-template-columns:280px minmax(0,1fr); gap:var(--gap-lg); align-items:center; }.confidence-summary { padding-right:var(--gap-lg); border-right:1px solid var(--border); }.confidence-kicker { margin-bottom:6px; color:#555; font:13px "Source Han Serif CN",SimSun,serif; }.confidence-number { color:var(--primary); font-size:28px; font-weight:700; }.confidence-label { margin-left:8px; color:#444; font-size:14px; font-weight:500; }.confidence-badge { display:inline-block; margin-top:10px; padding:3px 12px; border:1px solid rgba(22,93,255,.2); border-radius:12px; color:var(--primary); background:#e8f0fe; font-size:13px; font-weight:600; }.confidence-note { margin-top:12px; color:#666; font:13px/1.7 "Source Han Serif CN",SimSun,serif; }.confidence-details { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:14px 24px; }.confidence-item { display:grid; grid-template-columns:116px 1fr 38px; align-items:center; gap:var(--gap-sm); }.item-label { color:#444; font:13px "Source Han Serif CN",SimSun,serif; }.item-bar-track { height:6px; overflow:hidden; border-radius:3px; background:#eee; }.item-bar-fill { display:block; height:100%; border-radius:3px; background:var(--primary); }.item-value { text-align:right; font-size:13px; font-weight:600; }.confidence-placeholder { padding:24px; color:#888; text-align:center; }
.vuln-list-wrap { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:var(--gap-md); }.vuln-item { padding:16px; border:1px solid var(--border); border-radius:var(--radius); }.vuln-title-row { display:flex; align-items:center; gap:var(--gap-sm); font-size:15px; font-weight:600; }.risk-tag { flex:0 0 auto; min-width:46px; padding:2px 8px; border-radius:2px; color:#fff; text-align:center; font-size:12px; }.tag-critical { background:var(--critical); }.tag-high { background:var(--high); }.tag-medium { background:var(--medium); }.tag-low { background:var(--low); }.tag-info { background:var(--info); }.vuln-tip-text { margin-top:8px; color:#555; font:13px/1.7 "Source Han Serif CN",SimSun,serif; }.vuln-detail { margin-top:12px; padding-top:12px; border-top:1px dashed var(--border); }.vuln-detail p + p { margin-top:5px; }.vuln-location { margin-top:9px; color:var(--primary); font:12px Consolas,monospace; }
.evidence-summary { margin-bottom:8px; padding:6px 9px; border-left:3px solid var(--primary); background:#f3f7ff; color:#445; font-size:12px; }.payload-summary { display:flex; flex-wrap:wrap; align-items:center; gap:6px; margin-top:8px; }.payload-summary code { max-width:100%; padding:2px 6px; border:1px solid var(--border); border-radius:2px; background:#f7f8fa; color:#444; overflow-wrap:anywhere; white-space:normal; }
.fix-three-col,.ai-grid { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:var(--gap-lg); }.fix-block { padding:var(--gap-lg); border-radius:var(--radius); }.fix-emergency { background:#fef2f2; }.fix-deadline { background:#fffbeb; }.fix-longterm { background:#f9fafb; }.fix-block-title { margin-bottom:var(--gap-md); font-size:15px; font-weight:700; }.list-uniform li { display:flex; gap:var(--gap-sm); margin-bottom:var(--gap-sm); font:14px/1.7 "Source Han Serif CN",SimSun,serif; overflow-wrap:anywhere; }.list-uniform li:last-child { margin-bottom:0; }.list-uniform li::before { content:"-"; flex:0 0 auto; color:#666; }.analysis-block { min-height:164px; padding:18px; border:1px solid var(--border); border-radius:var(--radius); background:#f9fafb; }.analysis-block h3 { margin-bottom:9px; font-size:15px; }
.appendix-summary { display:flex; align-items:center; gap:var(--gap-sm); cursor:pointer; color:var(--primary); font-size:14px; }.appendix-content { margin-top:var(--gap-md); padding-top:var(--gap-md); border-top:1px dashed var(--border); font:13px "Source Han Serif CN",SimSun,serif; color:#555; }.evidence-grid { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:var(--gap-md); }.evidence-item { padding:12px; border:1px solid var(--border); border-radius:var(--radius); background:#f9fafb; }.evidence-item strong { display:block; margin-bottom:4px; color:#222; }.footer { padding:20px; color:#666; text-align:center; font-size:12px; }
@media (max-width:1000px) { .meta-wrap,.overview-grid,.collection-grid,.tool-grid,.vuln-list-wrap,.fix-three-col,.ai-grid,.evidence-grid { grid-template-columns:repeat(2,minmax(0,1fr)); }.confidence-layout { grid-template-columns:1fr; }.confidence-summary { padding:0 0 var(--gap-lg); border:0; border-bottom:1px solid var(--border); } }
@media (max-width:680px) { body { padding:12px; }.card,.report-header,.appendix-card { padding:16px; }.meta-wrap,.overview-grid,.collection-grid,.tool-grid,.vuln-list-wrap,.fix-three-col,.ai-grid,.evidence-grid,.confidence-details { grid-template-columns:1fr; }.risk-bar-group { display:grid; grid-template-columns:repeat(2,1fr); min-width:100%; } }
@media print { @page { size:A4; margin:12mm; } body { padding:0; background:#fff; }.report-shell { width:100%; }.card,.report-header,.appendix-card,.collection-card { break-inside:avoid; } details { display:block; } details > .appendix-content { display:block; } }
"""


def render_scan_report(
    *, target: str, scan_time: str, vulnerabilities: List[Dict[str, Any]],
    tool_results: Dict[str, Any], ai_analysis: Optional[Dict[str, Any]],
    confidence: Optional[Dict[str, Any]], session_id: str, report_type: str,
) -> str:
    """Render one of the three new-project scan reports."""
    report_type = normalize_report_type(report_type)
    tool_results = tool_results or {}
    normalized_vulns = _normalized_vulnerabilities(vulnerabilities)
    cards = _information_cards(tool_results)
    parts = [_header(target, scan_time, session_id, report_type)]
    if report_type == "info_collection":
        parts.append(_information_section(tool_results, include_status=True))
    elif report_type == "vuln_scan":
        parts.extend([_risk_section(normalized_vulns, ai_analysis), _confidence_section(confidence), _vulnerability_section(normalized_vulns), _remediation_section(normalized_vulns, ai_analysis), _ai_section(normalized_vulns, ai_analysis)])
    else:
        total_tools = len(tool_results)
        info_tools = sum(1 for name in tool_results if is_information_tool(name))
        vuln_tools = sum(1 for name in tool_results if is_vulnerability_tool(name))
        parts.append(f'''<section class="card info-module"><h2 class="module-title">{_icon()}扫描执行概览</h2><div class="overview-grid">
          <div class="overview-item"><span class="overview-value">{total_tools}</span><span class="overview-label">已执行扫描工具</span><span class="overview-tip">信息收集与漏洞验证</span></div>
          <div class="overview-item"><span class="overview-value">{info_tools}</span><span class="overview-label">信息收集工具</span><span class="overview-tip">资产、服务与应用攻击面</span></div>
          <div class="overview-item"><span class="overview-value">{vuln_tools}</span><span class="overview-label">漏洞扫描工具</span><span class="overview-tip">按漏洞类别验证</span></div>
          <div class="overview-item"><span class="overview-value">{len(normalized_vulns)}</span><span class="overview-label">确认问题位置</span><span class="overview-tip">以结构化验证结果为准</span></div>
        </div><p class="notice">完整扫描报告按工具类别分区：信息收集部分展示实际收集内容；漏洞扫描部分展示确认的问题和修复建议。两类结果不会互相替代或混合统计。</p></section>''')
        parts.extend([_information_section(tool_results, include_status=False), _risk_section(normalized_vulns, ai_analysis), _confidence_section(confidence), _vulnerability_section(normalized_vulns), _remediation_section(normalized_vulns, ai_analysis), _ai_section(normalized_vulns, ai_analysis)])
    parts.append(_appendix(report_type, cards, normalized_vulns))
    parts.append('<footer class="footer">报告由 TOSKill 自动生成；仅展示实际工具返回的有效信息与必要验证证据。</footer>')
    return f'''<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>{_safe(target)} 扫描报告</title><style>{_styles()}</style></head><body><main class="report-shell">{"".join(part for part in parts if part)}</main></body></html>'''
