from typing import TypedDict, Dict
from langgraph.graph import StateGraph, END
from services.ast_service import ASTAuditor
from services.diff_service import generate_diff
from models.models import AuditTask, CodeStandard, Vulnerability, DiffRecord


class AgentState(TypedDict):
    task_id: int
    filename: str
    code: str
    standard_code: str
    vulns: list
    diff_text: str
    diff_html: str
    thought: str


async def reason_node(state: AgentState) -> Dict:
    state["thought"] = f"开始审计文件 {state['filename']}，计划执行：AST解析 → 漏洞扫描 → 生成差异"
    return state


def act_parse_node(state: AgentState) -> Dict:
    state["standard_code"] = ASTAuditor.standardize(state["code"])
    state["thought"] = "AST代码标准化完成"
    return state


def act_scan_node(state: AgentState) -> Dict:
    auditor = ASTAuditor(state["code"])
    state["vulns"] = auditor.scan()
    state["thought"] = f"漏洞扫描完成，发现 {len(state['vulns'])} 个问题"
    return state


def act_diff_node(state: AgentState) -> Dict:
    state["diff_text"], state["diff_html"] = generate_diff(state["code"], state["standard_code"])
    state["thought"] = "代码差异生成完成"
    return state


async def observe_save_node(state: AgentState) -> Dict:
    task = await AuditTask.get(id=state["task_id"])

    await CodeStandard.create(task=task, standard_code=state["standard_code"])

    await DiffRecord.create(task=task, diff_text=state["diff_text"], diff_html=state["diff_html"])

    for v in state["vulns"]:
        await Vulnerability.create(
            task=task,
            vuln_type=v["vuln_type"],
            level=v["level"],
            line_no=v["line_no"],
            code=v["code"],
            desc=v["desc"]
        )

    task.status = "SUCCESS"
    await task.save()

    state["thought"] = "审计结果保存完成"
    return state


workflow = StateGraph(AgentState)

workflow.add_node("reason", reason_node)
workflow.add_node("parse", act_parse_node)
workflow.add_node("scan", act_scan_node)
workflow.add_node("diff", act_diff_node)
workflow.add_node("save", observe_save_node)

workflow.set_entry_point("reason")
workflow.add_edge("reason", "parse")
workflow.add_edge("parse", "scan")
workflow.add_edge("scan", "diff")
workflow.add_edge("diff", "save")
workflow.add_edge("save", END)

agent = workflow.compile()
