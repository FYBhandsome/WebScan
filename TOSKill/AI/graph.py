"""
TOSKill AI 工作流图定义

类比 demo.py，使用 LangGraph 构建三个子图：
1. 信息收集子图 (InfoCollectionGraph)
2. 漏洞扫描子图 (VulnScanGraph)
3. 报告生成子图 (ReportGraph)

使用 LangGraph interrupt 机制实现用户交互暂停/恢复。
"""
import logging
import asyncio
from typing import Dict, Optional, Callable, List, Any
from datetime import datetime

from langgraph.graph import StateGraph, END
from langgraph.types import interrupt, Command
from langgraph.checkpoint.memory import MemorySaver
from langchain_openai import ChatOpenAI

from .state import ScanState, create_initial_state, append_chat, update_state
from .tools import get_tool_by_name, get_tool_sequence
from ..config import settings

logger = logging.getLogger(__name__)


def get_llm():
    """获取LLM实例"""
    return ChatOpenAI(
        model=settings.MODEL_ID,
        temperature=0.1,
        api_key=settings.OPENAI_API_KEY,
        base_url=settings.OPENAI_BASE_URL
    )


class MemoryStore:
    """记忆化存储 - 类比 demo.py 的 chat_history"""
    
    _instance = None
    _sessions: Dict[str, ScanState] = {}
    _chat_histories: Dict[str, List[Dict]] = {}
    _pending_interactions: Dict[str, Dict] = {}
    _websocket_callbacks: Dict[str, Callable] = {}
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    def save_session(self, session_id: str, state: ScanState):
        """保存会话状态"""
        self._sessions[session_id] = state
        logger.debug(f"保存会话状态: {session_id}")
    
    def get_session(self, session_id: str) -> Optional[ScanState]:
        """获取会话状态"""
        return self._sessions.get(session_id)
    
    def delete_session(self, session_id: str):
        """删除会话"""
        self._sessions.pop(session_id, None)
        self._chat_histories.pop(session_id, None)
        self._pending_interactions.pop(session_id, None)
        self._websocket_callbacks.pop(session_id, None)
    
    def append_chat(self, session_id: str, role: str, content: str):
        """追加聊天历史"""
        if session_id not in self._chat_histories:
            self._chat_histories[session_id] = []
        self._chat_histories[session_id].append({
            "role": role,
            "content": content,
            "timestamp": datetime.now().isoformat()
        })
    
    def get_chat_history(self, session_id: str) -> List[Dict]:
        """获取聊天历史"""
        return self._chat_histories.get(session_id, [])
    
    def set_pending_interaction(self, session_id: str, interaction_data: Dict):
        """设置待处理的交互请求"""
        self._pending_interactions[session_id] = interaction_data
    
    def get_pending_interaction(self, session_id: str) -> Optional[Dict]:
        """获取待处理的交互请求"""
        return self._pending_interactions.get(session_id)
    
    def clear_pending_interaction(self, session_id: str):
        """清除待处理的交互请求"""
        self._pending_interactions.pop(session_id, None)
    
    def set_websocket_callback(self, session_id: str, callback: Callable):
        """设置 WebSocket 回调函数"""
        self._websocket_callbacks[session_id] = callback
    
    def get_websocket_callback(self, session_id: str) -> Optional[Callable]:
        """获取 WebSocket 回调函数"""
        return self._websocket_callbacks.get(session_id)
    
    def has_pending_interaction(self, session_id: str) -> bool:
        """检查是否有待处理的交互"""
        return session_id in self._pending_interactions


memory_store = MemoryStore.get_instance()


async def ai_decision(state: ScanState) -> ScanState:
    """原子1: AI智能决策"""
    logger.info(f"[{state.get('task_id')}] AI决策节点开始执行")
    
    session_id = state.get("websocket_session_id") or state.get("task_id")
    done = list(state.get("tool_results", {}).keys())
    mode = state.get("mode", "full_scan")
    tool_sequence = get_tool_sequence(mode)
    
    for t in tool_sequence:
        if t not in done:
            logger.info(f"✅ 分配任务：{t}")
            
            ws_callback = memory_store.get_websocket_callback(session_id)
            if ws_callback:
                try:
                    await ws_callback({
                        "type": "ai_decision",
                        "payload": {
                            "next_task": t,
                            "completed_tasks": done,
                            "total_tasks": len(tool_sequence),
                            "progress": f"{len(done)}/{len(tool_sequence)}"
                        }
                    })
                except Exception as e:
                    logger.error(f"WebSocket推送失败: {e}")
            
            return update_state(state, next_task=t, need_generate_script=False)
    
    logger.info("✅ 所有扫描任务已完成！")
    
    ws_callback = memory_store.get_websocket_callback(session_id)
    if ws_callback:
        try:
            await ws_callback({
                "type": "ai_decision_complete",
                "payload": {
                    "completed_tasks": done,
                    "total_tasks": len(tool_sequence)
                }
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    return update_state(state, next_task="end", need_generate_script=False)


async def user_interact(state: ScanState) -> ScanState:
    """原子2: 用户交互 - 使用 interrupt 实现暂停等待"""
    logger.info(f"[{state.get('task_id')}] 用户交互节点")
    
    next_task = state.get("next_task", "")
    mode = state.get("mode", "full_scan")
    target = state.get("target", "")
    session_id = state.get("websocket_session_id") or state.get("task_id")
    
    if next_task == "end":
        return state
    
    interaction_data = {
        "type": "interaction_required",
        "session_id": session_id,
        "next_task": next_task,
        "target": target,
        "mode": mode,
        "completed_tasks": state.get("completed_tasks", []),
        "options": [
            {"key": "1", "label": "执行", "description": f"执行任务: {next_task}"},
            {"key": "2", "label": "停止", "description": "停止扫描并生成报告"},
            {"key": "3", "label": "聊天", "description": "与 AI 助手对话"}
        ]
    }
    
    logger.info(f"🎯 目标：{target} | 模式：{mode} | 下一个任务：{next_task}")
    logger.info("[1]执行 [2]停止 [3]聊天")
    
    memory_store.set_pending_interaction(session_id, interaction_data)
    
    ws_callback = memory_store.get_websocket_callback(session_id)
    if ws_callback:
        try:
            await ws_callback(interaction_data)
        except Exception as e:
            logger.error(f"WebSocket 回调失败: {e}")
    
    user_choice = interrupt(interaction_data)
    
    memory_store.clear_pending_interaction(session_id)
    
    logger.info(f"👤 用户选择: {user_choice}")
    
    return update_state(state, user_choice=user_choice)


async def execute_task(state: ScanState) -> ScanState:
    """原子3: 执行任务"""
    logger.info(f"[{state.get('task_id')}] 执行任务节点")
    
    task = state.get("next_task", "")
    if task == "end" or task == "":
        return state
    
    target = state.get("target", "")
    session_id = state.get("websocket_session_id") or state.get("task_id")
    ws_callback = memory_store.get_websocket_callback(session_id)
    
    tool = get_tool_by_name(task)
    
    if not tool:
        logger.warning(f"工具 {task} 不存在")
        if ws_callback:
            await ws_callback({
                "type": "task_error",
                "payload": {"tool": task, "error": f"工具 {task} 不存在"}
            })
        return update_state(state, errors=state.get("errors", []) + [f"工具 {task} 不存在"])
    
    if ws_callback:
        try:
            await ws_callback({
                "type": "task_started",
                "payload": {"tool": task, "target": target}
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    try:
        res = tool.invoke(target)
        logger.info(f"📊 【{task}】结果：{res}")
        
        llm = get_llm()
        analysis = llm.invoke(f"用1-2句话简要分析这个扫描结果的关键发现：{str(res)[:500]}").content
        logger.info(f"🧾 分析：{analysis}")
        
        if ws_callback:
            try:
                await ws_callback({
                    "type": "task_completed",
                    "payload": {
                        "tool": task,
                        "result_summary": str(res)[:300] if res else "无结果",
                        "analysis": analysis,
                        "vulnerable": isinstance(res, dict) and res.get("vulnerable", False)
                    }
                })
            except Exception as e:
                logger.error(f"WebSocket推送失败: {e}")
        
        new_state = append_chat(state, "system", f"任务：{task}\n结果：{res}\n分析：{analysis}")
        tool_results = state.get("tool_results", {}).copy()
        tool_results[task] = res
        
        completed_tasks = state.get("completed_tasks", []).copy()
        completed_tasks.append(task)
        
        return update_state(new_state, tool_results=tool_results, completed_tasks=completed_tasks)
        
    except Exception as e:
        logger.error(f"执行任务失败: {e}")
        if ws_callback:
            try:
                await ws_callback({
                    "type": "task_error",
                    "payload": {"tool": task, "error": str(e)}
                })
            except Exception as we:
                logger.error(f"WebSocket推送失败: {we}")
        return update_state(state, errors=state.get("errors", []) + [f"{task}: {str(e)}"])


async def chat(state: ScanState) -> ScanState:
    """原子4: 聊天"""
    logger.info(f"[{state.get('task_id')}] 聊天节点")
    
    session_id = state.get("websocket_session_id") or state.get("task_id")
    ws_callback = memory_store.get_websocket_callback(session_id)
    
    llm = get_llm()
    user_name = state.get("user_name", "用户")
    chat_summary = state.get("chat_summary", "无")
    task_history = state.get("completed_tasks", [])
    target = state.get("target", "")
    
    prompt = f"""你是安全助手，用户：{user_name}
聊天总结：{chat_summary}
任务历史：{task_history}
目标：{target}
自然简洁回复。"""
    
    ai_msg = llm.invoke(prompt).content
    logger.info(f"🤖 AI：{ai_msg}")
    
    if ws_callback:
        try:
            await ws_callback({
                "type": "ai_chat",
                "payload": {"content": ai_msg, "context": "scan_assistant"}
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    new_state = append_chat(state, "assistant", ai_msg)
    return update_state(new_state, chat_summary=ai_msg[:200])


async def script_manager(state: ScanState) -> ScanState:
    """原子5: 脚本管理"""
    logger.info(f"[{state.get('task_id')}] 脚本管理节点")
    
    user_choice = state.get("user_choice", "")
    
    if user_choice == "4":
        logger.info("📁 脚本上传功能")
    elif user_choice == "5":
        logger.info("🔧 脚本生成功能")
    
    return update_state(state, need_generate_script=False)


async def report_generation(state: ScanState) -> ScanState:
    """原子6: 报告生成 - 使用AI分析并保存报告到文件"""
    logger.info(f"[{state.get('task_id')}] 报告生成节点")
    
    tool_results = state.get("tool_results", {})
    vulnerabilities = state.get("vulnerabilities", [])
    target = state.get("target", "")
    session_id = state.get("websocket_session_id") or state.get("task_id", "unknown")
    ws_callback = memory_store.get_websocket_callback(session_id)
    
    if not tool_results:
        if ws_callback:
            await ws_callback({
                "type": "report_error",
                "payload": {"error": "无扫描结果"}
            })
        return update_state(state, is_complete=True, report="无扫描结果")
    
    scan_summary = {
        "timestamp": datetime.now().isoformat(),
        "tool_count": len(tool_results),
        "vulnerability_count": len(vulnerabilities)
    }
    
    if ws_callback:
        try:
            await ws_callback({
                "type": "report_generation_started",
                "payload": {
                    "session_id": session_id,
                    "tool_count": len(tool_results),
                    "vulnerability_count": len(vulnerabilities)
                }
            })
        except Exception as e:
            logger.error(f"WebSocket推送失败: {e}")
    
    try:
        from ..tools.report.report_manager import get_report_manager
        report_manager = get_report_manager()
        
        chat_history = memory_store.get_chat_history(session_id)
        task_history = [
            {
                "tool": task, 
                "result_summary": str(state.get("tool_results", {}).get(task, ""))[:200]
            }
            for task in state.get("completed_tasks", [])
        ]
        
        report = await report_manager.generate_ai_report_content_async(
            tool_results=tool_results,
            vulnerabilities=vulnerabilities,
            target=target,
            chat_history=chat_history,
            task_history=task_history
        )
        
        report_info = report_manager.save_report(
            session_id=session_id,
            content=report,
            metadata={
                "target": target,
                "tool_results": tool_results,
                "vulnerabilities": vulnerabilities,
                "scan_summary": scan_summary,
                "chat_history_count": len(chat_history),
                "task_history_count": len(task_history)
            }
        )
        
        logger.info(f"报告已保存: {report_info.get('download_url')}")
        
        if ws_callback:
            try:
                await ws_callback({
                    "type": "report_generated",
                    "payload": {
                        "report_url": report_info.get("download_url", ""),
                        "report_id": report_info.get("report_id", ""),
                        "report_preview": report[:500] if report else ""
                    }
                })
            except Exception as e:
                logger.error(f"WebSocket推送失败: {e}")
        
        return update_state(
            state, 
            is_complete=True, 
            report=report, 
            scan_summary=scan_summary,
            report_url=report_info.get("download_url", ""),
            report_id=report_info.get("report_id", "")
        )
    except Exception as e:
        logger.error(f"保存报告失败: {e}")
        if ws_callback:
            try:
                await ws_callback({
                    "type": "report_error",
                    "payload": {"error": str(e)}
                })
            except Exception as we:
                logger.error(f"WebSocket推送失败: {we}")
        return update_state(state, is_complete=True, report="报告生成失败", scan_summary=scan_summary)


def router(state: ScanState) -> str:
    """路由决策"""
    next_task = state.get("next_task", "")
    need_generate_script = state.get("need_generate_script", False)
    user_choice = state.get("user_choice", "")
    
    if next_task == "end":
        return "report_generation"
    
    if need_generate_script:
        return "script_manager"
    
    c = user_choice
    if c == "1":
        return "execute_task"
    if c == "2":
        return "report_generation"
    if c == "3":
        return "chat"
    if c in ["4", "5"]:
        return "script_manager"
    
    return "user_interact"


class InfoCollectionGraph:
    """信息收集子图"""
    
    @staticmethod
    def build() -> StateGraph:
        workflow = StateGraph(ScanState)
        
        workflow.add_node("ai_decision", ai_decision)
        workflow.add_node("user_interact", user_interact)
        workflow.add_node("execute_task", execute_task)
        workflow.add_node("chat", chat)
        workflow.add_node("script_manager", script_manager)
        workflow.add_node("report_generation", report_generation)
        
        workflow.set_entry_point("ai_decision")
        workflow.add_edge("ai_decision", "user_interact")
        workflow.add_conditional_edges("user_interact", router)
        workflow.add_edge("execute_task", "ai_decision")
        workflow.add_edge("chat", "ai_decision")
        workflow.add_edge("script_manager", "ai_decision")
        workflow.add_edge("report_generation", END)
        
        return workflow.compile(checkpointer=MemorySaver())


class VulnScanGraph:
    """漏洞扫描子图"""
    
    @staticmethod
    def build() -> StateGraph:
        workflow = StateGraph(ScanState)
        
        workflow.add_node("ai_decision", ai_decision)
        workflow.add_node("user_interact", user_interact)
        workflow.add_node("execute_task", execute_task)
        workflow.add_node("chat", chat)
        workflow.add_node("report_generation", report_generation)
        
        workflow.set_entry_point("ai_decision")
        workflow.add_edge("ai_decision", "user_interact")
        workflow.add_conditional_edges("user_interact", router)
        workflow.add_edge("execute_task", "ai_decision")
        workflow.add_edge("chat", "ai_decision")
        workflow.add_edge("report_generation", END)
        
        return workflow.compile(checkpointer=MemorySaver())


class ReportGraph:
    """报告生成子图"""
    
    @staticmethod
    def build() -> StateGraph:
        workflow = StateGraph(ScanState)
        
        workflow.add_node("report_generation", report_generation)
        
        workflow.set_entry_point("report_generation")
        workflow.add_edge("report_generation", END)
        
        return workflow.compile()


class AgentOrchestrator:
    """Agent编排器 - 管理多个子图的执行，支持暂停/恢复"""
    
    def __init__(self):
        self.info_graph = InfoCollectionGraph.build()
        self.vuln_graph = VulnScanGraph.build()
        self.report_graph = ReportGraph.build()
        self._running_tasks: Dict[str, asyncio.Task] = {}
        logger.info("Agent编排器初始化完成")
    
    def set_websocket_callback(self, session_id: str, callback: Callable):
        """设置 WebSocket 回调"""
        memory_store.set_websocket_callback(session_id, callback)
    
    def resume_workflow(self, session_id: str, user_choice: str) -> bool:
        """恢复暂停的工作流"""
        state = memory_store.get_session(session_id)
        if not state:
            logger.warning(f"会话 {session_id} 不存在")
            return False
        
        state = update_state(state, user_choice=user_choice)
        memory_store.save_session(session_id, state)
        
        logger.info(f"工作流 {session_id} 已恢复，用户选择: {user_choice}")
        return True
    
    def get_pending_interaction(self, session_id: str) -> Optional[Dict]:
        """获取待处理的交互请求"""
        return memory_store.get_pending_interaction(session_id)
    
    def has_pending_interaction(self, session_id: str) -> bool:
        """检查是否有待处理的交互"""
        return memory_store.has_pending_interaction(session_id)
    
    async def run_full_scan(self, state: ScanState, websocket_callback: Callable = None) -> ScanState:
        """运行完整扫描流程"""
        logger.info(f"[{state.get('task_id')}] 开始完整扫描流程")
        
        session_id = state.get("websocket_session_id") or state.get("task_id")
        memory_store.save_session(session_id, state)
        
        if websocket_callback:
            memory_store.set_websocket_callback(session_id, websocket_callback)
        
        try:
            state = update_state(state, mode="info_collection")
            state = await self.info_graph.ainvoke(
                state,
                config={"configurable": {"thread_id": session_id}}
            )
            memory_store.save_session(session_id, state)
            
            state = update_state(state, mode="vuln_scan")
            state = await self.vuln_graph.ainvoke(
                state,
                config={"configurable": {"thread_id": session_id}}
            )
            memory_store.save_session(session_id, state)
            
            state = await self.report_graph.ainvoke(state)
            memory_store.save_session(session_id, state)
            
            logger.info(f"[{state.get('task_id')}] 完整扫描流程完成")
            return state
            
        except Exception as e:
            logger.error(f"完整扫描流程失败: {e}")
            raise
    
    async def run_info_collection(self, state: ScanState, websocket_callback: Callable = None) -> ScanState:
        """仅运行信息收集"""
        session_id = state.get("websocket_session_id") or state.get("task_id")
        
        if websocket_callback:
            memory_store.set_websocket_callback(session_id, websocket_callback)
        
        state = update_state(state, mode="info_collection")
        return await self.info_graph.ainvoke(
            state,
            config={"configurable": {"thread_id": session_id}}
        )
    
    async def run_vuln_scan(self, state: ScanState, websocket_callback: Callable = None) -> ScanState:
        """仅运行漏洞扫描"""
        session_id = state.get("websocket_session_id") or state.get("task_id")
        
        if websocket_callback:
            memory_store.set_websocket_callback(session_id, websocket_callback)
        
        state = update_state(state, mode="vuln_scan")
        return await self.vuln_graph.ainvoke(
            state,
            config={"configurable": {"thread_id": session_id}}
        )
    
    async def run_report(self, state: ScanState) -> ScanState:
        """仅生成报告"""
        return await self.report_graph.ainvoke(state)


agent_orchestrator = AgentOrchestrator()


def get_agent_orchestrator() -> AgentOrchestrator:
    """获取Agent编排器实例"""
    return agent_orchestrator
