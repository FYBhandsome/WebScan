"""扫描页使用的全自动、可取消扫描执行器。

该执行器与控制台的人机交互图分离，按固定工具队列执行，不触发
``user_interact``、高危确认等 interrupt 节点，但复用统一工具调用和报告生成逻辑。
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any, Awaitable, Callable, Dict, List, Optional

from TOSKill.AI.progress_events import scanner_progress_context
from TOSKill.AI.state import update_state
from TOSKill.AI.tools import (
    INFO_COLLECTION_TOOLS,
    VULN_SCAN_TOOLS,
    extract_auth_from_result,
    get_tool_by_name,
    invoke_tool_with_auth,
)
from TOSKill.tools.tool_categories import (
    information_items,
    information_summary_text,
    is_vulnerability_tool,
    tool_category,
)


EventCallback = Callable[[Dict[str, Any]], Awaitable[None]]


class AutoScanRunner:
    """按模式执行固定工具队列，并通过回调推送结构化进度事件。"""

    MODE_TO_TOOLS = {
        "info_collection": INFO_COLLECTION_TOOLS,
        "vuln_scan": VULN_SCAN_TOOLS,
        "full_scan": INFO_COLLECTION_TOOLS + VULN_SCAN_TOOLS,
    }

    def __init__(
        self,
        session_id: str,
        target: str,
        mode: str,
        emit: EventCallback,
    ) -> None:
        self.session_id = session_id
        self.target = target
        self.mode = mode if mode in self.MODE_TO_TOOLS else "info_collection"
        self.emit = emit

    @property
    def tool_names(self) -> List[str]:
        return [tool.name for tool in self.MODE_TO_TOOLS[self.mode]]

    async def _send(self, event_type: str, payload: Optional[Dict[str, Any]] = None) -> None:
        await self.emit({
            "type": event_type,
            "payload": {
                "session_id": self.session_id,
                "run_type": "automatic",
                **(payload or {}),
            },
        })

    @staticmethod
    def _as_tool_result(result: Any) -> Dict[str, Any]:
        if isinstance(result, dict):
            return result
        return {
            "success": True,
            "data": {"result": result},
            "timestamp": datetime.now().isoformat(),
        }

    @staticmethod
    def _extract_vulnerabilities(tool_name: str, result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not is_vulnerability_tool(tool_name):
            return []
        data = result.get("data") if isinstance(result.get("data"), dict) else {}
        raw_items = result.get("vulnerabilities")
        if not isinstance(raw_items, list):
            raw_items = data.get("vulnerabilities")

        vulnerabilities: List[Dict[str, Any]] = []
        if isinstance(raw_items, list):
            for item in raw_items:
                if isinstance(item, dict):
                    normalized = dict(item)
                    normalized.setdefault("source_tool", tool_name)
                    normalized.setdefault(
                        "title",
                        normalized.get("name")
                        or normalized.get("vuln_type")
                        or tool_name,
                    )
                    normalized.setdefault("severity", "medium")
                    vulnerabilities.append(normalized)

        if not vulnerabilities and (result.get("vulnerable") or data.get("vulnerable")):
            vulnerabilities.append({
                "source_tool": tool_name,
                "title": result.get("vuln_type") or data.get("vuln_type") or tool_name,
                "name": result.get("vuln_type") or data.get("vuln_type") or tool_name,
                "severity": result.get("severity") or data.get("severity") or "medium",
                "description": result.get("description") or data.get("description", ""),
            })

        return vulnerabilities

    async def _execute_tool(self, tool_name: str, state: Dict[str, Any]) -> Dict[str, Any]:
        tool = get_tool_by_name(tool_name)
        if not tool:
            raise RuntimeError(f"工具 {tool_name} 不存在")

        callback = self.emit
        with scanner_progress_context(self.session_id, tool_name, self.target, callback):
            result = await asyncio.to_thread(
                invoke_tool_with_auth,
                tool,
                self.target,
                state,
            )
        return self._as_tool_result(result)

    async def run(self, state: Dict[str, Any]) -> Dict[str, Any]:
        from TOSKill.AI.graph import memory_store, report_generation

        planned_tasks = self.tool_names
        completed_tasks = list(state.get("completed_tasks", []))
        failed_tasks = list(state.get("failed_tasks", []))
        errors = list(state.get("errors", []))
        tool_results = dict(state.get("tool_results", {}))
        vulnerabilities = list(state.get("vulnerabilities", []))

        state = update_state(
            state,
            mode=self.mode,
            scan_mode="全自动",
            run_type="automatic",
            planned_tasks=planned_tasks,
            completed_tasks=completed_tasks,
            failed_tasks=failed_tasks,
            errors=errors,
            tool_results=tool_results,
            vulnerabilities=vulnerabilities,
            is_complete=False,
            cancelled=False,
            scan_status="running",
            progress=0,
        )
        memory_store.save_session(self.session_id, state)

        await self._send("scan_flow_started", {
            "target": self.target,
            "mode": self.mode,
            "scan_mode": self.mode,
            "planned_tasks": planned_tasks,
            "total_tasks": len(planned_tasks),
        })

        for index, tool_name in enumerate(planned_tasks):
            # asyncio.CancelledError is deliberately not swallowed here. The manager
            # turns it into one scan_cancelled event and prevents report generation.
            await self._send("task_started", {
                "tool": tool_name,
                "target": self.target,
                "task_index": index,
                "total_tasks": len(planned_tasks),
            })
            state = update_state(
                state,
                current_tool=tool_name,
                current_task=tool_name,
                progress=round(index / max(len(planned_tasks), 1) * 100, 1),
            )
            memory_store.save_session(self.session_id, state)

            try:
                result = await self._execute_tool(tool_name, state)
                tool_results[tool_name] = result
                auth_info = extract_auth_from_result(result)
                if auth_info:
                    state = update_state(state, **auth_info)

                success = result.get("success", True) is not False
                current_vulnerabilities = self._extract_vulnerabilities(tool_name, result)
                vulnerabilities.extend(current_vulnerabilities)

                if success:
                    if tool_name not in completed_tasks:
                        completed_tasks.append(tool_name)
                else:
                    if tool_name not in failed_tasks:
                        failed_tasks.append(tool_name)
                    errors.append(f"{tool_name}: {result.get('error') or '工具执行失败'}")

                state = update_state(
                    state,
                    tool_results=dict(tool_results),
                    completed_tasks=list(completed_tasks),
                    failed_tasks=list(failed_tasks),
                    vulnerabilities=list(vulnerabilities),
                    errors=list(errors),
                    task_result={"tool": tool_name, "result": result},
                    task_history=list(state.get("task_history", [])) + [
                        f"{tool_name}: {str(result)[:200]}"
                    ],
                    progress=round((index + 1) / max(len(planned_tasks), 1) * 100, 1),
                    current_tool="",
                    current_task="",
                )
                memory_store.save_session(self.session_id, state)

                event_type = "task_completed" if success else "task_error"
                is_information_collection = tool_category(tool_name) == "info_collection"
                await self._send(event_type, {
                    "tool": tool_name,
                    "tool_category": tool_category(tool_name),
                    "target": self.target,
                    "success": success,
                    "raw_result": result,
                    "vulnerabilities": current_vulnerabilities,
                    "information_summary": information_items(tool_name, result),
                    # 信息收集结果是执行结果而非 AI 分析；使用独立字段，避免前端重复渲染。
                    "result_summary": information_summary_text(tool_name, result)
                    if is_information_collection else "",
                    "analysis": "",
                    "error": result.get("error") if not success else "",
                })
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                error_message = f"{tool_name}: {exc}"
                errors.append(error_message)
                if tool_name not in failed_tasks:
                    failed_tasks.append(tool_name)
                state = update_state(
                    state,
                    failed_tasks=list(failed_tasks),
                    errors=list(errors),
                    current_tool="",
                    current_task="",
                    progress=round((index + 1) / max(len(planned_tasks), 1) * 100, 1),
                )
                memory_store.save_session(self.session_id, state)
                await self._send("task_error", {
                    "tool": tool_name,
                    "target": self.target,
                    "error": str(exc),
                })

            await self._send("workflow_progress", {
                "stage": "tool_execution",
                "status": "running",
                "completed": index + 1,
                "total": len(planned_tasks),
                "progress_percent": round((index + 1) / max(len(planned_tasks), 1) * 80, 1),
            })

        state = update_state(
            state,
            tool_results=dict(tool_results),
            completed_tasks=list(completed_tasks),
            failed_tasks=list(failed_tasks),
            vulnerabilities=list(vulnerabilities),
            errors=list(errors),
            progress=80,
            scan_status="reporting",
        )
        memory_store.save_session(self.session_id, state)

        state = await report_generation(state)
        state = update_state(
            state,
            run_type="automatic",
            scan_mode="全自动",
            scan_status="completed",
            progress=100,
            current_tool="",
            current_task="",
            is_complete=True,
        )
        memory_store.save_session(self.session_id, state)
        return state
