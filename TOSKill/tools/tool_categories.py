"""扫描工具类别与信息收集结果摘要的统一定义。"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple


INFO_COLLECTION_TOOL_NAMES = frozenset({
    "baseinfo_scan", "port_scan", "subdomain_scan", "dir_brute",
    "waf_detect_scan", "cdn_detect_scan", "cms_detect_scan", "infoleak_scan",
    "ip_locate_scan", "webside_query_scan", "web_weight_scan", "crawler_scan",
    "tls_certificate_scan", "http_methods_scan", "public_metadata_scan",
})

VULN_SCAN_TOOL_NAMES = frozenset({
    "sqli_scan", "xss_scan", "csrf_scan", "fileupload_scan",
    "cmdi_scan", "ssrf_scan", "lfi_scan", "weakpass_scan",
    "http_security_headers_scan", "cookie_security_scan", "cors_misconfiguration_scan",
})

TOOL_LABELS = {
    "baseinfo_scan": "目标与服务", "port_scan": "网络暴露面",
    "subdomain_scan": "子域名资产", "dir_brute": "目录与路径",
    "waf_detect_scan": "边界防护", "cdn_detect_scan": "CDN 信息",
    "cms_detect_scan": "技术指纹", "infoleak_scan": "敏感信息线索",
    "ip_locate_scan": "网络归属", "webside_query_scan": "站点关联信息",
    "web_weight_scan": "站点权重", "crawler_scan": "站点结构",
    "tls_certificate_scan": "TLS 与证书", "http_methods_scan": "HTTP 方法与服务行为",
    "public_metadata_scan": "公开站点元数据",
}

FIELD_LABELS = {
    "server": "HTTP 服务", "title": "页面标题", "ip": "解析地址",
    "host": "主机名", "hostname": "主机名", "status_code": "响应状态",
    "open_ports": "开放端口", "ports": "开放端口", "total_count": "数量",
    "subdomains": "已发现子域", "directories": "已发现目录",
    "files": "已发现文件", "found_paths": "已发现路径",
    "waf_detected": "WAF 状态", "waf_type": "WAF 标识", "waf": "WAF 标识",
    "cdn_detected": "CDN 状态", "cdn_provider": "CDN 提供商",
    "cms_name": "CMS", "cms_version": "CMS 版本", "cms": "CMS",
    "pages": "已发现页面", "urls": "已发现页面", "crawled_urls": "已发现页面",
    "page_count": "页面数量", "forms": "表单", "form_count": "表单数量",
    "parameters": "请求参数", "params": "请求参数", "location": "地理位置",
    "isp": "运营商", "provider": "运营商", "domain": "域名",
    "weight": "站点权重", "website_name": "站点名称", "record": "备案信息",
    "leaks_found": "扫描结果", "leak_details": "线索详情",
    "tls_version": "TLS 版本", "cipher": "加密套件", "certificate_subject": "证书主体",
    "certificate_issuer": "证书签发者", "certificate_expires_at": "证书到期时间",
    "subject_alt_names": "证书备用名称", "allowed_methods": "允许的 HTTP 方法",
    "options_status_code": "OPTIONS 状态", "head_status_code": "HEAD 状态",
    "redirect_location": "重定向地址", "public_resources": "公开资源",
    "discovered_paths": "发现路径", "target_url": "目标地址",
}

PREFERRED_FIELDS = {
    "baseinfo_scan": ("ip", "host", "hostname", "server", "title", "status_code"),
    "port_scan": ("open_ports", "ports", "total_count"),
    "subdomain_scan": ("subdomains", "total_count"),
    "dir_brute": ("directories", "files", "found_paths", "total_count"),
    "waf_detect_scan": ("waf_detected", "waf_type", "waf", "detected", "name"),
    "cdn_detect_scan": ("cdn_detected", "cdn_provider", "detected", "provider"),
    "cms_detect_scan": ("cms_name", "cms_version", "cms", "version"),
    "crawler_scan": ("pages", "urls", "crawled_urls", "page_count", "forms", "form_count", "parameters", "params"),
    "ip_locate_scan": ("ip", "location", "isp", "provider"),
    "webside_query_scan": ("website_name", "record", "domain", "provider"),
    "web_weight_scan": ("weight", "domain"),
    "infoleak_scan": ("leaks_found", "leak_details"),
    "tls_certificate_scan": ("host", "port", "tls_version", "cipher", "certificate_subject", "certificate_issuer", "certificate_expires_at", "subject_alt_names"),
    "http_methods_scan": ("allowed_methods", "options_status_code", "head_status_code", "redirect_location", "server"),
    "public_metadata_scan": ("discovered_paths", "total_count", "public_resources"),
}


def tool_category(tool_name: str) -> str:
    """Return the category used by UI, workflow and report rendering."""
    if tool_name in INFO_COLLECTION_TOOL_NAMES:
        return "info_collection"
    if tool_name in VULN_SCAN_TOOL_NAMES:
        return "vuln_scan"
    return "other"


def is_information_tool(tool_name: str) -> bool:
    return tool_category(tool_name) == "info_collection"


def is_vulnerability_tool(tool_name: str) -> bool:
    return tool_category(tool_name) == "vuln_scan"


def tool_display_name(tool_name: str) -> str:
    return TOOL_LABELS.get(tool_name, tool_name)


def _plain(value: Any, limit: int = 240) -> str:
    if value is None or value == "":
        return ""
    if isinstance(value, bool):
        return "是" if value else "否"
    if isinstance(value, (list, tuple, set)):
        text = "、".join(item for item in (_plain(item, 80) for item in value) if item)
    elif isinstance(value, dict):
        text = "；".join(
            f"{key}: {item_text}" for key, item in value.items()
            if (item_text := _plain(item, 80))
        )
    else:
        text = str(value)
    return text[:limit] + ("…" if len(text) > limit else "")


def result_data(result: Any) -> Dict[str, Any]:
    """Unwrap the standard tool result while preserving direct-tool compatibility."""
    if not isinstance(result, dict):
        return {"result": result}
    data = result.get("data")
    if isinstance(data, dict) and data:
        return data
    return {
        key: value for key, value in result.items()
        if key not in {"success", "error", "timestamp", "metadata", "data"}
    }


def information_items(tool_name: str, result: Any, limit: int = 6) -> List[Dict[str, str]]:
    """Return UI-safe, structured information collected by one info tool."""
    if not is_information_tool(tool_name):
        return []
    data = result_data(result)
    items: List[Dict[str, str]] = []
    used = set()
    for key in PREFERRED_FIELDS.get(tool_name, ()):
        text = _plain(data.get(key))
        if text:
            items.append({"label": FIELD_LABELS.get(key, key), "value": text})
            used.add(key)
        if len(items) >= limit:
            return items
    for key, value in data.items():
        if key in used or key in {"headers", "raw", "request_response_log", "result", "vulnerabilities"}:
            continue
        text = _plain(value)
        if text:
            items.append({"label": FIELD_LABELS.get(key, str(key)), "value": text})
        if len(items) >= limit:
            break
    return items


def information_summary_text(tool_name: str, result: Any) -> str:
    items = information_items(tool_name, result, limit=3)
    if not items:
        return f"{tool_display_name(tool_name)}执行完成，未返回可展示的信息。"
    details = "；".join(f"{item['label']}：{item['value']}" for item in items)
    return f"{tool_display_name(tool_name)}执行完成，已收集 {details}。"


def collect_information_results(tool_results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build the stable information-result payload consumed by both UIs."""
    collected = []
    for tool_name, result in (tool_results or {}).items():
        if not is_information_tool(tool_name):
            continue
        if isinstance(result, dict) and result.get("success") is False:
            continue
        items = information_items(tool_name, result)
        if items:
            collected.append({
                "tool": tool_name,
                "title": tool_display_name(tool_name),
                "items": items,
            })
    return collected
