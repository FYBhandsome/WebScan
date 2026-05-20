import asyncio
from services.react_agent import (
    AgentState,
    reason_node,
    act_parse_node,
    act_scan_node,
    act_diff_node,
    agent
)


class TestReactAgent:
    def test_reason_node_async(self):
        state = AgentState(
            task_id=1,
            filename="test.py",
            code="print('hello')",
            standard_code="",
            vulns=[],
            diff_text="",
            diff_html="",
            thought=""
        )
        result = asyncio.run(reason_node(state))
        assert "开始审计文件" in result["thought"]
        assert result["filename"] == "test.py"

    def test_act_parse_node(self):
        state = AgentState(
            task_id=1,
            filename="test.py",
            code="\nprint( 'hello' )\n",
            standard_code="",
            vulns=[],
            diff_text="",
            diff_html="",
            thought=""
        )
        result = act_parse_node(state)
        assert result["standard_code"] != ""
        assert "AST代码标准化完成" in result["thought"]

    def test_act_scan_node_safe_code(self):
        code = "x = 1\ny = 2"
        state = AgentState(
            task_id=1,
            filename="test.py",
            code=code,
            standard_code="",
            vulns=[],
            diff_text="",
            diff_html="",
            thought=""
        )
        result = act_scan_node(state)
        assert isinstance(result["vulns"], list)

    def test_act_scan_node_danger_code(self):
        code = 'eval("1+1")'
        state = AgentState(
            task_id=1,
            filename="test.py",
            code=code,
            standard_code="",
            vulns=[],
            diff_text="",
            diff_html="",
            thought=""
        )
        result = act_scan_node(state)
        assert len(result["vulns"]) >= 1

    def test_act_diff_node(self):
        code = "x = 1"
        state = AgentState(
            task_id=1,
            filename="test.py",
            code=code,
            standard_code="x = 1",
            vulns=[],
            diff_text="",
            diff_html="",
            thought=""
        )
        result = act_diff_node(state)
        assert isinstance(result["diff_text"], str)
        assert isinstance(result["diff_html"], str)
        assert "代码差异生成完成" in result["thought"]

    def test_agent_graph_compiled(self):
        assert agent is not None

    def test_workflow_has_nodes(self):
        graph = agent.get_graph()
        assert graph is not None
