"""Crawler registration tests for TOSKill."""

from unittest.mock import patch


def test_crawler_is_registered_as_info_collection_tool():
    from TOSKill.AI.tools import (
        INFO_COLLECTION_TOOLS,
        get_tool_by_name,
        get_tool_sequence,
    )

    tool = get_tool_by_name("crawler_scan")

    assert tool is not None
    assert tool in INFO_COLLECTION_TOOLS
    assert "crawler_scan" in get_tool_sequence("info_collection")


def test_crawler_tool_wraps_backend_result():
    from TOSKill.AI.tools import crawler_scan, validate_tool_result

    backend_result = {
        "target": "https://example.com",
        "total_pages": 1,
        "total_links": 0,
        "total_forms": 0,
        "pages": [],
        "forms": [],
        "urls": ["https://example.com"],
        "site_map": {},
        "sensitive_info": [],
        "errors": [],
    }

    with patch("backend.plugins.crawler.crawler.crawl", return_value=backend_result) as crawl:
        result = crawler_scan.invoke({"target": "https://example.com"})

    crawl.assert_called_once_with("https://example.com", None)
    assert validate_tool_result(result)
    assert result["success"] is True
    assert result["data"]["total_pages"] == 1
