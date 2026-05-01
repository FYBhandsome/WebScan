"""测试任务-工具映射规则"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import pytest
from TOSKill.AI.graph import TOOL_MAPPING_MATRIX, get_tools_by_context, get_fallback_tools

class TestToolMappingMatrix:
    def test_fast_mode(self):
        assert "xss" in TOOL_MAPPING_MATRIX["fast"]
        assert "sqli" in TOOL_MAPPING_MATRIX["fast"]
        assert "cmdi" not in TOOL_MAPPING_MATRIX["fast"]

    def test_deep_mode(self):
        assert len(TOOL_MAPPING_MATRIX["deep"]) == 8

    def test_full_mode(self):
        assert len(TOOL_MAPPING_MATRIX["full"]) == 16

class TestGetToolsByContext:
    def test_port_3306_triggers_sqli(self):
        result = get_tools_by_context({"ports": [80, 3306], "open_ports": [80, 3306]})
        assert "sqli" in result

    def test_empty_ports_returns_empty(self):
        result = get_tools_by_context({})
        assert result == []

    def test_none_input(self):
        result = get_tools_by_context(None)
        assert result == []

    def test_deduplication(self):
        result = get_tools_by_context({"open_ports": [80, 443]})
        assert "xss" in result
        assert "sqli" in result
        assert result.count("xss") == 1

class TestGetFallbackTools:
    def test_sqli_fallback(self):
        result = get_fallback_tools("sqli")
        assert "xss" in result
        assert "cmdi" in result

    def test_unknown_tool_fallback(self):
        result = get_fallback_tools("nonexistent")
        assert "xss" in result

    def test_empty_input(self):
        result = get_fallback_tools("")
        assert "xss" in result
