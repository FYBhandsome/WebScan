const pageMetadataSummaryScript = String.raw`from datetime import datetime
import re

import requests


def _result(success: bool, data: dict, error=None) -> dict:
    return {
        "success": success,
        "data": data,
        "error": error,
        "auth_info": None,
        "timestamp": datetime.now().isoformat()
    }


def _normalize_target(target: str) -> str:
    value = str(target or "").strip()
    if not value:
        return ""
    if value.startswith(("http://", "https://")):
        return value
    return f"http://{value}"


def run(target: str) -> dict:
    url = _normalize_target(target)
    if not url:
        return _result(False, {}, "目标不能为空")

    try:
        response = requests.get(
            url,
            headers={"User-Agent": "TOSKill/1.0"},
            timeout=4,
            allow_redirects=True
        )

        html = response.text
        title_match = re.search(
            r"<title[^>]*>(.*?)</title>",
            html,
            re.IGNORECASE | re.DOTALL
        )
        title = title_match.group(1).strip() if title_match else "未识别"

        return _result(True, {
            "target_url": response.url,
            "status_code": response.status_code,
            "title": title,
            "link_count": len(re.findall(r"<a\b", html, re.IGNORECASE)),
            "form_count": len(re.findall(r"<form\b", html, re.IGNORECASE)),
            "page_size_kb": round(len(response.content) / 1024, 1)
        })
    except requests.RequestException as error:
        return _result(False, {"target_url": url}, str(error))
`

const technologyFingerprintScript = String.raw`from datetime import datetime

import requests


def _result(success: bool, data: dict, error=None) -> dict:
    return {
        "success": success,
        "data": data,
        "error": error,
        "auth_info": None,
        "timestamp": datetime.now().isoformat()
    }


def _normalize_target(target: str) -> str:
    value = str(target or "").strip()
    if not value:
        return ""
    if value.startswith(("http://", "https://")):
        return value
    return f"http://{value}"


def run(target: str) -> dict:
    url = _normalize_target(target)
    if not url:
        return _result(False, {}, "目标不能为空")

    try:
        response = requests.get(
            url,
            headers={"User-Agent": "TOSKill/1.0"},
            timeout=4,
            allow_redirects=True
        )

        html = response.text[:200000].lower()
        technologies = []

        if "wp-content" in html:
            technologies.append("WordPress")
        if "data-v-" in html:
            technologies.append("Vue.js")
        if "bootstrap" in html:
            technologies.append("Bootstrap")
        if "jquery" in html:
            technologies.append("jQuery")

        if not technologies:
            technologies.append("未识别明显前端框架")

        return _result(True, {
            "target_url": response.url,
            "status_code": response.status_code,
            "server": response.headers.get("Server", "未披露"),
            "powered_by": response.headers.get("X-Powered-By", "未披露"),
            "technology_clues": technologies,
            "technology_count": len(technologies),
            "content_type": response.headers.get("Content-Type", "未披露")
        })
    except requests.RequestException as error:
        return _result(False, {"target_url": url}, str(error))
`

// Local generation is deliberately deterministic: one audited template per UI.
export const generateLocalScript = ({ placement, category = 'info_collection' }) => {
  if (placement === 'console') {
    return {
      toolName: 'technology_fingerprint',
      scriptCode: technologyFingerprintScript,
      description: '识别目标页面暴露的服务端与前端技术特征。',
      category
    }
  }

  return {
    toolName: 'page_metadata_summary',
    scriptCode: pageMetadataSummaryScript,
    description: '快速采集页面标题、描述、链接数量和表单数量。',
    category
  }
}
