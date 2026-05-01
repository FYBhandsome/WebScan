"""测试 ReACT 提示词构建和响应解析"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import pytest
from TOSKill.AI.graph import build_react_prompt, parse_react_response
from TOSKill.AI.state import create_initial_state, update_state

class TestBuildReactPrompt:
    def test_basic_prompt_structure(self):
        state = create_initial_state("https://test.com", task_id="t1", mode="deep")
        prompt = build_react_prompt(state, "test rag strategy")
        assert "Thought" in prompt
        assert "Action" in prompt
        assert "Reason" in prompt
        assert "https://test.com" in prompt
        assert "deep" in prompt
        assert "test rag strategy" in prompt

    def test_prompt_with_completed_tasks(self):
        state = create_initial_state("https://test.com", task_id="t1", mode="fast")
        state = update_state(state, tool_results={"xss": {"found": True}})
        prompt = build_react_prompt(state, "")
        assert "xss" in prompt

    def test_prompt_with_empty_rag(self):
        state = create_initial_state("https://test.com", task_id="t1", mode="deep")
        prompt = build_react_prompt(state, "")
        assert "\u6682\u65e0\u4e13\u4e1a\u77e5\u8bc6\u53c2\u8003" in prompt


class TestParseReactResponse:
    def test_parse_standard_format(self):
        response = "Thought: \u9700\u8981\u5148\u626b\u63cfSQL\u6ce8\u5165\nAction: sqli\nReason: \u76ee\u6807\u53ef\u80fd\u6709\u6570\u636e\u5e93"
        result = parse_react_response(response)
        assert result["thought"] == "\u9700\u8981\u5148\u626b\u63cfSQL\u6ce8\u5165"
        assert result["action"] == "sqli"
        assert result["reason"] == "\u76ee\u6807\u53ef\u80fd\u6709\u6570\u636e\u5e93"

    def test_parse_case_insensitive(self):
        response = "THOUGHT: test thought\nACTION: xss\nreason: test reason"
        result = parse_react_response(response)
        assert result["thought"] == "test thought"
        assert result["action"] == "xss"

    def test_parse_empty_response(self):
        result = parse_react_response("")
        assert result["thought"] == ""
        assert result["action"] == ""
        assert result["reason"] == ""

    def test_parse_partial_response(self):
        response = "Thought: only thought"
        result = parse_react_response(response)
        assert result["thought"] == "only thought"
        assert result["action"] == ""
