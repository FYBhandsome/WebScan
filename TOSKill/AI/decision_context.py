"""Helpers for converting pause-chat messages into decision context.

The workflow needs both the original user wording and a small, stable set of
decision factors.  This module deliberately uses deterministic extraction so
that a malformed or unavailable LLM response cannot discard a user's scan
constraints.  The original message is always retained in ``messages``.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional
from uuid import uuid4


MAX_CONTEXT_MESSAGES = 12
MAX_CONTEXT_ITEMS = 24
MAX_TEXT_LENGTH = 1200


# Canonical task names are the names used by the scan graph.  The aliases are
# intentionally conservative: an unmatched phrase remains available in the
# raw message and will not cause an unsafe tool selection.
TASK_ALIASES = {
    "baseinfo_scan": ("baseinfo_scan", "baseinfo", "基础信息", "基本信息", "信息收集"),
    "port_scan": ("port_scan", "端口扫描", "端口探测", "开放端口", "port scan", "portscan"),
    "subdomain_scan": ("subdomain_scan", "子域名", "子域", "subdomain"),
    "dir_brute": ("dir_brute", "目录爆破", "目录扫描", "敏感目录", "目录枚举", "directory"),
    "waf_detect_scan": ("waf_detect_scan", "waf", "web 应用防火墙", "防火墙识别"),
    "cdn_detect_scan": ("cdn_detect_scan", "cdn", "内容分发网络"),
    "cms_detect_scan": ("cms_detect_scan", "cms", "cms 识别", "指纹识别"),
    "infoleak_scan": ("infoleak_scan", "信息泄露", "敏感信息", "信息泄漏", "info leak"),
    "ip_locate_scan": ("ip_locate_scan", "ip 定位", "ip归属", "ip 归属", "ip locate"),
    "webside_query_scan": ("webside_query_scan", "网站查询", "站点查询", "webside"),
    "web_weight_scan": ("web_weight_scan", "网站权重", "web weight"),
    "sqli_scan": ("sqli_scan", "sql 注入", "sql注入", "sqli", "注入测试"),
    "xss_scan": ("xss_scan", "xss", "跨站脚本", "跨站脚本攻击"),
    "csrf_scan": ("csrf_scan", "csrf", "跨站请求伪造"),
    "fileupload_scan": ("fileupload_scan", "文件上传", "文件上传漏洞", "file upload"),
    "cmdi_scan": ("cmdi_scan", "命令注入", "命令执行", "命令执行漏洞", "cmdi"),
    "ssrf_scan": ("ssrf_scan", "ssrf", "服务端请求伪造"),
    "lfi_scan": ("lfi_scan", "lfi", "本地文件包含", "文件包含"),
    "weakpass_scan": ("weakpass_scan", "弱口令", "弱密码", "默认口令", "weak password"),
}

_NEGATION_RE = re.compile(
    r"不要|不需要|无需|跳过|排除|禁用|停止|不做|别做|避免|skip|exclude|without|avoid",
    re.IGNORECASE,
)
_NON_NEGATING_RE = re.compile(r"不要只|不只是|不仅|不局限于|不要仅", re.IGNORECASE)
_PRIORITY_RE = re.compile(r"优先|重点|首先|先做|优先测试|重点测试|focus|priorit", re.IGNORECASE)
_CONSTRAINT_RE = re.compile(
    r"只读|被动|低风险|低影响|限速|低并发|并发|不要修改|不得修改|避免破坏|禁止|仅限|只允许|"
    r"不要|不需要|无需|跳过|排除|停止|在.+之前|在.+之后|先.+再",
    re.IGNORECASE,
)


def _text(value: Any, limit: int = MAX_TEXT_LENGTH) -> str:
    return str(value or "").strip()[:limit]


def _sentences(content: str) -> List[str]:
    chunks = re.split(r"[\r\n。！？!?；;，,]+", content)
    return [chunk.strip() for chunk in chunks if chunk.strip()]


def _task_pattern(alias: str) -> re.Pattern[str]:
    if re.fullmatch(r"[A-Za-z0-9_ ]+", alias):
        return re.compile(rf"(?<![A-Za-z0-9_]){re.escape(alias)}(?![A-Za-z0-9_])", re.IGNORECASE)
    return re.compile(re.escape(alias), re.IGNORECASE)


def _is_negated(sentence: str, start: int) -> bool:
    prefix = sentence[:start]
    if _NON_NEGATING_RE.search(prefix):
        return False
    return bool(_NEGATION_RE.search(prefix[-24:]))


def _task_items(content: str, message_id: str) -> Dict[str, List[Dict[str, Any]]]:
    requested: List[Dict[str, Any]] = []
    excluded: List[Dict[str, Any]] = []
    priorities: List[str] = []

    for task, aliases in TASK_ALIASES.items():
        matches = []
        for alias in aliases:
            matches.extend(_task_pattern(alias).finditer(content))
        if not matches:
            continue

        # One task should be emitted once even if the user writes both its
        # English tool name and a Chinese description.
        match = min(matches, key=lambda item: item.start())
        sentence_start = max(
            content.rfind("。", 0, match.start()),
            content.rfind("；", 0, match.start()),
            content.rfind("，", 0, match.start()),
            content.rfind(",", 0, match.start()),
            content.rfind("\n", 0, match.start()),
        ) + 1
        sentence_end_candidates = [
            index for index in (
                content.find("。", match.end()),
                content.find("；", match.end()),
                content.find("，", match.end()),
                content.find(",", match.end()),
                content.find("\n", match.end()),
            ) if index >= 0
        ]
        sentence_end = min(sentence_end_candidates) if sentence_end_candidates else len(content)
        sentence = _text(content[sentence_start:sentence_end], 300)
        negated = _is_negated(sentence, max(0, match.start() - sentence_start))
        priority = "high" if _PRIORITY_RE.search(sentence[: max(0, match.start() - sentence_start)]) else "normal"
        item = {
            "task": task,
            "priority": priority,
            "reason": sentence,
            "source": "user_chat",
            "source_message_id": message_id,
        }
        (excluded if negated else requested).append(item)
        if not negated and priority == "high":
            priorities.append(task)

    return {
        "requested_tasks": requested,
        "excluded_tasks": excluded,
        "priority_tasks": priorities,
    }


def _constraint_items(content: str, message_id: str) -> List[Dict[str, Any]]:
    constraints: List[Dict[str, Any]] = []
    for sentence in _sentences(content):
        if not _CONSTRAINT_RE.search(sentence):
            continue
        lower = sentence.lower()
        if any(token in lower for token in ("并发", "限速", "频率")):
            kind = "performance"
        elif any(token in lower for token in ("只读", "被动", "低风险", "低影响", "破坏", "修改", "禁止")):
            kind = "safety"
        elif any(token in lower for token in ("只", "仅限", "范围", "目标")):
            kind = "scope"
        elif _PRIORITY_RE.search(sentence):
            kind = "priority"
        else:
            kind = "execution"
        constraints.append({
            "text": _text(sentence, 400),
            "kind": kind,
            "source": "user_chat",
            "source_message_id": message_id,
        })
    return constraints


def _risk_tolerance(content: str) -> Optional[str]:
    if re.search(r"低风险|低影响|只读|被动|不要破坏|避免破坏", content, re.IGNORECASE):
        return "low_impact"
    if re.search(r"高风险|侵入性|攻击性|允许破坏性", content, re.IGNORECASE):
        return "aggressive"
    return None


def _item_key(item: Any, key: str = "text") -> str:
    if isinstance(item, dict):
        return _text(item.get(key) or item.get("task") or item.get("content"), 400).lower()
    return _text(item, 400).lower()


def _merge_items(existing: Iterable[Any], additions: Iterable[Dict[str, Any]], key: str) -> List[Any]:
    merged: List[Any] = []
    seen = set()
    for item in list(existing or []) + list(additions or []):
        identity = _item_key(item, key)
        if not identity or identity in seen:
            continue
        seen.add(identity)
        merged.append(item)
    return merged[-MAX_CONTEXT_ITEMS:]


def _normalize_task_items(items: Iterable[Any]) -> List[Dict[str, Any]]:
    normalized = []
    for item in items or []:
        if isinstance(item, dict):
            task = _text(item.get("task"))
            if task:
                normalized.append(dict(item, task=task))
        elif _text(item):
            normalized.append({"task": _text(item), "priority": "normal", "source": "legacy"})
    return normalized


def build_decision_context(
    previous: Optional[Dict[str, Any]],
    content: str,
    *,
    version: int,
    pause_id: str = "",
    timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    """Merge one user message into a normalized decision context.

    ``requested_tasks`` and ``excluded_tasks`` are mutually overriding: the
    latest explicit instruction wins for a task.  This prevents an old
    "skip X" instruction from permanently blocking a later "do X" request.
    """
    previous = dict(previous or {})
    now = timestamp or datetime.now().isoformat()
    message_id = f"decision-msg:{uuid4().hex}"
    clean_content = _text(content, MAX_TEXT_LENGTH)
    extracted_tasks = _task_items(clean_content, message_id)
    extracted_constraints = _constraint_items(clean_content, message_id)

    old_requested = _normalize_task_items(previous.get("requested_tasks", []))
    old_excluded = _normalize_task_items(previous.get("excluded_tasks", []))
    new_requested = _normalize_task_items(extracted_tasks["requested_tasks"])
    new_excluded = _normalize_task_items(extracted_tasks["excluded_tasks"])
    requested_names = {item["task"] for item in new_requested}
    excluded_names = {item["task"] for item in new_excluded}

    requested = [item for item in old_requested if item["task"] not in excluded_names]
    requested = [item for item in requested if item["task"] not in requested_names]
    requested.extend(new_requested)
    excluded = [item for item in old_excluded if item["task"] not in requested_names]
    excluded = [item for item in excluded if item["task"] not in excluded_names]
    excluded.extend(new_excluded)

    old_messages = [item for item in previous.get("messages", []) if isinstance(item, dict)]
    old_messages.append({
        "id": message_id,
        "role": "user",
        "content": clean_content,
        "pause_id": pause_id,
        "timestamp": now,
    })

    old_priorities = [item for item in previous.get("priority_tasks", []) if _text(item)]
    priority_tasks = list(dict.fromkeys(old_priorities + extracted_tasks["priority_tasks"]))
    priority_tasks = [task for task in priority_tasks if task not in excluded_names]

    context = {
        "version": int(version),
        "user_constraints": _merge_items(
            previous.get("user_constraints", []), extracted_constraints, "text"
        ),
        "requested_tasks": _merge_items(requested, [], "task"),
        "excluded_tasks": _merge_items(excluded, [], "task"),
        "priority_tasks": priority_tasks[-MAX_CONTEXT_ITEMS:],
        "risk_tolerance": _risk_tolerance(clean_content) or previous.get("risk_tolerance", ""),
        "latest_request": clean_content,
        "messages": old_messages[-MAX_CONTEXT_MESSAGES:],
        "updated_at": now,
    }
    return context
