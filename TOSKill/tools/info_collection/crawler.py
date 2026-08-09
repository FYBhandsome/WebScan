# -*- coding: utf-8 -*-
"""TOSKill wrapper for the backend web crawler plugin."""

from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Optional


def crawler(target: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Crawl a target website and return a normalized scanner result."""
    try:
        from backend.plugins.crawler.crawler import crawl

        # The backend entry point uses asyncio.run(). Execute it in a worker
        # thread so this synchronous wrapper also works in FastAPI's event loop.
        with ThreadPoolExecutor(max_workers=1) as executor:
            result = executor.submit(crawl, target, config).result()

        return {
            "success": True,
            "data": result if isinstance(result, dict) else {"result": result},
            "error": None,
            "metadata": {"tool": "crawler", "target": target},
        }
    except Exception as exc:
        return {
            "success": False,
            "data": {},
            "error": f"执行 crawler 工具异常: {exc}",
            "metadata": {"tool": "crawler", "target": target},
        }
