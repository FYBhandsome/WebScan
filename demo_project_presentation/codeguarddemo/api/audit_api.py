from fastapi import APIRouter, UploadFile, File
from models.models import AuditTask, Vulnerability, DiffRecord
from services.react_agent import agent
from utils.tools import resp_success, resp_error

router = APIRouter(tags=["代码审计"])


@router.post("/upload")
async def upload_code(file: UploadFile = File(...)):
    try:
        content = await file.read()
        code = content.decode("utf-8")

        task = await AuditTask.create(
            filename=file.filename,
            original_code=code,
            status="RUNNING"
        )

        await agent.ainvoke({
            "task_id": task.id,
            "filename": file.filename,
            "code": code,
            "standard_code": "",
            "vulns": [],
            "diff_text": "",
            "diff_html": "",
            "thought": ""
        })

        return resp_success({"task_id": task.id}, "审计完成")
    except Exception as e:
        return resp_error(str(e))


@router.get("/result/{task_id}")
async def get_result(task_id: int):
    task = await AuditTask.get_or_none(id=task_id)
    if not task:
        return resp_error("任务不存在")

    vulns = await Vulnerability.filter(task=task).all()
    diff = await DiffRecord.get_or_none(task=task)

    return resp_success({
        "filename": task.filename,
        "status": task.status,
        "vulns": [
            {"type": v.vuln_type, "level": v.level, "line": v.line_no, "code": v.code, "desc": v.desc}
            for v in vulns
        ],
        "diff_html": diff.diff_html if diff else ""
    })
