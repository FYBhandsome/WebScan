"""
TOSKill 主入口模块

提供API入口和CLI交互界面，支持多种扫描模式和记忆化会话管理。
"""
import asyncio
import logging
import sys
from datetime import datetime
from typing import Dict, Any, Optional, List
from uuid import uuid4

from .AI.state import AgentState
from .AI.graph import AgentOrchestrator, get_agent_orchestrator
from .AI.memory.session_memory import get_memory_manager, SessionMemoryManager

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ScanMode:
    INFO_COLLECTION = "info_collection"
    VULN_SCAN = "vuln_scan"
    FULL_SCAN = "full_scan"
    CHAT = "chat"


class ScanTask:
    def __init__(self, task_id: str, target: str, mode: str):
        self.task_id = task_id
        self.target = target
        self.mode = mode
        self.status = "pending"
        self.created_at = datetime.now().isoformat()
        self.started_at: Optional[str] = None
        self.completed_at: Optional[str] = None
        self.result: Optional[Dict[str, Any]] = None
        self.error: Optional[str] = None
        self.session_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "target": self.target,
            "mode": self.mode,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "result": self.result,
            "error": self.error,
            "session_id": self.session_id
        }


class TOSKillRunner:
    """
    TOSKill API入口类

    提供扫描任务创建、结果获取、会话管理等API接口。
    """

    def __init__(self):
        self._orchestrator: Optional[AgentOrchestrator] = None
        self._memory_manager: SessionMemoryManager = get_memory_manager()
        self._tasks: Dict[str, ScanTask] = {}
        self._active_tasks: Dict[str, asyncio.Task] = {}
        logger.info("TOSKillRunner 初始化完成")

    @property
    def orchestrator(self) -> AgentOrchestrator:
        if self._orchestrator is None:
            self._orchestrator = get_agent_orchestrator()
        return self._orchestrator

    async def create_scan_task(
        self,
        target: str,
        mode: str = ScanMode.FULL_SCAN,
        config: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        创建扫描任务

        Args:
            target: 扫描目标URL或IP
            mode: 扫描模式 (info_collection/vuln_scan/full_scan/chat)
            config: 额外配置参数

        Returns:
            str: 任务ID
        """
        task_id = str(uuid4())
        session_id = self._memory_manager.create_session()

        task = ScanTask(task_id, target, mode)
        task.session_id = session_id
        self._tasks[task_id] = task

        config = config or {}
        state = AgentState(
            target=target,
            task_id=task_id,
            websocket_session_id=session_id,
            target_context=config
        )

        self._memory_manager.save_session(session_id, state.to_dict())
        self._memory_manager.add_message(
            session_id, "system",
            f"创建扫描任务: {mode} -> {target}",
            {"task_id": task_id, "mode": mode}
        )

        async def run_scan():
            task.status = "running"
            task.started_at = datetime.now().isoformat()

            try:
                if mode == ScanMode.INFO_COLLECTION:
                    result_state = await self.orchestrator.run_info_collection(state)
                elif mode == ScanMode.VULN_SCAN:
                    result_state = await self.orchestrator.run_vuln_scan(state)
                elif mode == ScanMode.FULL_SCAN:
                    result_state = await self.orchestrator.run_full_scan(state)
                elif mode == ScanMode.CHAT:
                    result_state = await self.orchestrator.run_full_scan(state)
                else:
                    raise ValueError(f"未知的扫描模式: {mode}")

                task.status = "completed"
                task.completed_at = datetime.now().isoformat()
                task.result = result_state.to_dict()

                self._memory_manager.save_session(session_id, result_state.to_dict())
                self._memory_manager.add_message(
                    session_id, "system",
                    f"扫描任务完成: {task_id}",
                    {"status": "completed", "vulnerabilities": len(result_state.vulnerabilities)}
                )

                logger.info(f"扫描任务完成: {task_id}")

            except Exception as e:
                task.status = "failed"
                task.completed_at = datetime.now().isoformat()
                task.error = str(e)

                state.set_workflow_failed(str(e))
                self._memory_manager.save_session(session_id, state.to_dict())
                self._memory_manager.add_message(
                    session_id, "system",
                    f"扫描任务失败: {str(e)}",
                    {"status": "failed", "error": str(e)}
                )

                logger.error(f"扫描任务失败: {task_id}, 错误: {e}")

            finally:
                if task_id in self._active_tasks:
                    del self._active_tasks[task_id]

        scan_task = asyncio.create_task(run_scan())
        self._active_tasks[task_id] = scan_task

        logger.info(f"创建扫描任务: {task_id}, 目标: {target}, 模式: {mode}")
        return task_id

    def get_scan_result(self, task_id: str) -> Optional[Dict[str, Any]]:
        """
        获取扫描结果

        Args:
            task_id: 任务ID

        Returns:
            扫描结果字典，如果任务不存在返回None
        """
        task = self._tasks.get(task_id)
        if task:
            return task.to_dict()
        return None

    def get_session_history(self, session_id: str) -> List[Dict[str, Any]]:
        """
        获取会话历史

        Args:
            session_id: 会话ID

        Returns:
            消息历史列表
        """
        return self._memory_manager.get_message_history(session_id)

    def get_session_state(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        获取会话状态

        Args:
            session_id: 会话ID

        Returns:
            会话状态字典
        """
        return self._memory_manager._sessions.get(session_id)

    async def resume_session(self, session_id: str) -> str:
        """
        恢复会话

        Args:
            session_id: 会话ID

        Returns:
            str: 新任务ID
        """
        checkpoint = self._memory_manager._sessions.get(session_id)
        if not checkpoint:
            raise ValueError(f"会话不存在: {session_id}")

        state_data = checkpoint.channel_values
        if not state_data:
            raise ValueError(f"会话状态为空: {session_id}")

        state = AgentState.from_dict(state_data)

        checkpoint_info = state_data.get("_checkpoint", {})
        stage = checkpoint_info.get("stage", "initial")

        if stage in ["completed", "failed"]:
            logger.info(f"会话 {session_id} 已{stage}，无需恢复")
            return state.task_id

        new_task_id = str(uuid4())
        state.task_id = new_task_id

        task = ScanTask(new_task_id, state.target, ScanMode.FULL_SCAN)
        task.session_id = session_id
        task.status = "running"
        task.started_at = datetime.now().isoformat()
        self._tasks[new_task_id] = task

        async def resume_scan():
            try:
                result_state = await self.orchestrator.resume_from_memory(session_id)

                task.status = "completed"
                task.completed_at = datetime.now().isoformat()
                task.result = result_state.to_dict()

                logger.info(f"恢复会话完成: {session_id} -> {new_task_id}")

            except Exception as e:
                task.status = "failed"
                task.completed_at = datetime.now().isoformat()
                task.error = str(e)
                logger.error(f"恢复会话失败: {session_id}, 错误: {e}")

            finally:
                if new_task_id in self._active_tasks:
                    del self._active_tasks[new_task_id]

        resume_task = asyncio.create_task(resume_scan())
        self._active_tasks[new_task_id] = resume_task

        logger.info(f"恢复会话: {session_id} -> 新任务: {new_task_id}")
        return new_task_id

    def get_all_sessions(self) -> List[Dict[str, Any]]:
        """
        获取所有会话

        Returns:
            会话信息列表
        """
        return self.orchestrator.get_all_sessions()

    def get_active_sessions(self) -> List[Dict[str, Any]]:
        """
        获取所有活动会话

        Returns:
            活动会话信息列表
        """
        return self.orchestrator.get_active_sessions()

    def delete_session(self, session_id: str) -> bool:
        """
        删除会话

        Args:
            session_id: 会话ID

        Returns:
            是否删除成功
        """
        return self._memory_manager.delete_session(session_id)

    def get_all_tasks(self) -> List[Dict[str, Any]]:
        """
        获取所有任务

        Returns:
            任务信息列表
        """
        return [task.to_dict() for task in self._tasks.values()]

    def get_active_tasks(self) -> Dict[str, asyncio.Task]:
        """
        获取所有活动任务

        Returns:
            活动任务字典
        """
        return self._active_tasks.copy()

    async def cancel_task(self, task_id: str) -> bool:
        """
        取消任务

        Args:
            task_id: 任务ID

        Returns:
            是否取消成功
        """
        if task_id in self._active_tasks:
            task = self._active_tasks[task_id]
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

            if task_id in self._tasks:
                self._tasks[task_id].status = "cancelled"
                self._tasks[task_id].completed_at = datetime.now().isoformat()

            logger.info(f"任务已取消: {task_id}")
            return True
        return False


class TOSKillCLI:
    """
    TOSKill CLI交互界面

    提供命令行交互界面，支持扫描模式选择、目标输入和会话管理。
    """

    BANNER = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ████████╗ ██████╗  ██████╗ ██╗     ███████╗                 ║
║   ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔════╝                 ║
║      ██║   ██║   ██║██║   ██║██║     ███████╗                 ║
║      ██║   ██║   ██║██║   ██║██║     ╚════██║                 ║
║      ██║   ╚██████╔╝╚██████╔╝███████╗███████║                 ║
║      ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚══════╝                 ║
║                                                               ║
║           AI-Powered Web Security Scanner                     ║
║                    Version 1.0.0                              ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""

    MENU = """
┌─────────────────────────────────────────────────────────────┐
│                        主菜单                                │
├─────────────────────────────────────────────────────────────┤
│  [1] 新建扫描任务                                           │
│  [2] 查看任务状态                                           │
│  [3] 查看所有会话                                           │
│  [4] 恢复中断任务                                           │
│  [5] 删除会话                                               │
│  [6] 退出                                                   │
└─────────────────────────────────────────────────────────────┘
"""

    SCAN_MODE_MENU = """
┌─────────────────────────────────────────────────────────────┐
│                      选择扫描模式                            │
├─────────────────────────────────────────────────────────────┤
│  [1] 信息收集模式 (info_collection)                         │
│      - 端口扫描、子域名发现、目录扫描等                      │
│                                                              │
│  [2] 漏洞扫描模式 (vuln_scan)                               │
│      - SQL注入、XSS、SSRF等漏洞检测                         │
│                                                              │
│  [3] 完整扫描模式 (full_scan)                               │
│      - 信息收集 + 漏洞扫描 + 报告生成                       │
│                                                              │
│  [4] 聊天模式 (chat)                                        │
│      - 与AI助手交互式对话                                    │
│                                                              │
│  [0] 返回主菜单                                             │
└─────────────────────────────────────────────────────────────┘
"""

    MODE_MAP = {
        "1": ScanMode.INFO_COLLECTION,
        "2": ScanMode.VULN_SCAN,
        "3": ScanMode.FULL_SCAN,
        "4": ScanMode.CHAT
    }

    MODE_NAMES = {
        ScanMode.INFO_COLLECTION: "信息收集模式",
        ScanMode.VULN_SCAN: "漏洞扫描模式",
        ScanMode.FULL_SCAN: "完整扫描模式",
        ScanMode.CHAT: "聊天模式"
    }

    def __init__(self):
        self.runner = TOSKillRunner()
        self.running = True

    def print_banner(self):
        print(self.BANNER)

    def print_menu(self):
        print(self.MENU)

    def print_scan_mode_menu(self):
        print(self.SCAN_MODE_MENU)

    def clear_screen(self):
        print("\033[2J\033[H", end="")

    def print_separator(self, char: str = "─", length: int = 60):
        print(char * length)

    def print_header(self, title: str):
        self.print_separator()
        print(f"  {title}")
        self.print_separator()

    def print_success(self, message: str):
        print(f"\033[92m[✓] {message}\033[0m")

    def print_error(self, message: str):
        print(f"\033[91m[✗] {message}\033[0m")

    def print_info(self, message: str):
        print(f"\033[94m[i] {message}\033[0m")

    def print_warning(self, message: str):
        print(f"\033[93m[!] {message}\033[0m")

    def get_input(self, prompt: str, default: str = "") -> str:
        if default:
            prompt = f"{prompt} [{default}]: "
        else:
            prompt = f"{prompt}: "
        try:
            value = input(prompt).strip()
            return value if value else default
        except EOFError:
            return default

    def get_choice(self, prompt: str, choices: List[str]) -> str:
        while True:
            choice = self.get_input(prompt)
            if choice in choices:
                return choice
            self.print_error(f"无效选择，请输入: {', '.join(choices)}")

    async def new_scan_task(self):
        self.print_header("新建扫描任务")

        self.print_scan_mode_menu()
        mode_choice = self.get_choice("请选择扫描模式", ["0", "1", "2", "3", "4"])

        if mode_choice == "0":
            return

        mode = self.MODE_MAP.get(mode_choice, ScanMode.FULL_SCAN)
        print(f"\n已选择: {self.MODE_NAMES[mode]}")

        target = self.get_input("请输入目标地址 (URL/IP)")
        if not target:
            self.print_error("目标地址不能为空")
            return

        if not self._validate_target(target):
            self.print_warning("目标地址格式可能不正确，继续吗？(y/n)")
            confirm = self.get_choice("", ["y", "n", "Y", "N"]).lower()
            if confirm != "y":
                return

        self.print_info(f"正在创建扫描任务...")
        self.print_info(f"目标: {target}")
        self.print_info(f"模式: {self.MODE_NAMES[mode]}")

        try:
            task_id = await self.runner.create_scan_task(target, mode)
            self.print_success(f"任务创建成功!")
            self.print_info(f"任务ID: {task_id}")

            print("\n扫描任务已启动，按 Enter 返回主菜单...")
            input()

        except Exception as e:
            self.print_error(f"创建任务失败: {e}")

    def _validate_target(self, target: str) -> bool:
        if target.startswith(("http://", "https://")):
            return True
        import re
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(:\d+)?$'
        if re.match(ip_pattern, target):
            return True
        domain_pattern = r'^[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+(:\d+)?$'
        if re.match(domain_pattern, target):
            return True
        return False

    def view_task_status(self):
        self.print_header("任务状态")

        tasks = self.runner.get_all_tasks()
        if not tasks:
            self.print_info("暂无任务记录")
            print("\n按 Enter 返回主菜单...")
            input()
            return

        print(f"\n{'任务ID':<36} {'目标':<30} {'模式':<15} {'状态':<10}")
        self.print_separator()

        for task in tasks:
            task_id = task["task_id"][:36]
            target = task["target"][:28] + ".." if len(task["target"]) > 30 else task["target"]
            mode = self.MODE_NAMES.get(task["mode"], task["mode"])[:12]
            status = task["status"]

            status_icons = {
                "pending": "⏳",
                "running": "🔄",
                "completed": "✅",
                "failed": "❌",
                "cancelled": "🚫"
            }
            icon = status_icons.get(status, "❓")

            print(f"{task_id} {target:<30} {mode:<15} {icon} {status}")

        print("\n输入任务ID查看详情，或按 Enter 返回主菜单...")
        task_id = self.get_input("任务ID")
        if task_id:
            self._show_task_detail(task_id)

    def _show_task_detail(self, task_id: str):
        task = self.runner.get_scan_result(task_id)
        if not task:
            self.print_error(f"任务不存在: {task_id}")
            return

        print(f"\n{'='*60}")
        print(f"任务详情")
        print(f"{'='*60}")
        print(f"任务ID:     {task['task_id']}")
        print(f"目标:       {task['target']}")
        print(f"模式:       {self.MODE_NAMES.get(task['mode'], task['mode'])}")
        print(f"状态:       {task['status']}")
        print(f"创建时间:   {task['created_at']}")
        if task['started_at']:
            print(f"开始时间:   {task['started_at']}")
        if task['completed_at']:
            print(f"完成时间:   {task['completed_at']}")
        if task['error']:
            print(f"错误信息:   {task['error']}")

        if task['result']:
            result = task['result']
            print(f"\n{'─'*60}")
            print("扫描结果摘要:")
            print(f"  - 完成任务数: {len(result.get('completed_tasks', []))}")
            print(f"  - 发现漏洞数: {len(result.get('vulnerabilities', []))}")
            print(f"  - 执行步骤数: {len(result.get('execution_history', []))}")
            print(f"  - 错误数:     {len(result.get('errors', []))}")

            vulnerabilities = result.get('vulnerabilities', [])
            if vulnerabilities:
                print(f"\n{'─'*60}")
                print("发现的漏洞:")
                for i, vuln in enumerate(vulnerabilities[:10], 1):
                    vuln_type = vuln.get('type', vuln.get('vulnerability_type', '未知'))
                    severity = vuln.get('severity', '未知')
                    print(f"  [{i}] {vuln_type} (严重程度: {severity})")

        print(f"\n{'='*60}")
        print("按 Enter 返回...")
        input()

    def view_all_sessions(self):
        self.print_header("所有会话")

        sessions = self.runner.get_all_sessions()
        if not sessions:
            self.print_info("暂无会话记录")
            print("\n按 Enter 返回主菜单...")
            input()
            return

        print(f"\n{'会话ID':<36} {'目标':<25} {'阶段':<15} {'状态':<10}")
        self.print_separator()

        for session in sessions:
            session_id = session["session_id"][:36]
            target = session.get("target", "")[:23] + ".." if len(session.get("target", "")) > 25 else session.get("target", "")
            stage = session.get("stage", "unknown")[:13]
            is_complete = "已完成" if session.get("is_complete") else "进行中"

            print(f"{session_id} {target:<25} {stage:<15} {is_complete}")

        print(f"\n{'='*60}")
        print("按 Enter 返回主菜单...")
        input()

    async def resume_session(self):
        self.print_header("恢复中断任务")

        active_sessions = self.runner.get_active_sessions()
        if not active_sessions:
            self.print_info("没有可恢复的会话")
            print("\n按 Enter 返回主菜单...")
            input()
            return

        print("\n可恢复的会话:")
        print(f"\n{'序号':<6} {'会话ID':<36} {'目标':<25} {'阶段':<15}")
        self.print_separator()

        for i, session in enumerate(active_sessions, 1):
            session_id = session["session_id"][:36]
            target = session.get("target", "")[:23] + ".." if len(session.get("target", "")) > 25 else session.get("target", "")
            stage = session.get("stage", "unknown")[:13]
            print(f"[{i}]    {session_id} {target:<25} {stage}")

        print(f"\n{'='*60}")
        choice = self.get_input("选择要恢复的会话序号 (0 返回)")

        if choice == "0" or not choice:
            return

        try:
            index = int(choice) - 1
            if 0 <= index < len(active_sessions):
                session = active_sessions[index]
                session_id = session["session_id"]

                self.print_info(f"正在恢复会话: {session_id}")
                new_task_id = await self.runner.resume_session(session_id)

                self.print_success(f"会话恢复成功!")
                self.print_info(f"新任务ID: {new_task_id}")
                print("\n按 Enter 返回主菜单...")
                input()
            else:
                self.print_error("无效的序号")
        except ValueError:
            self.print_error("请输入有效的数字")

    def delete_session(self):
        self.print_header("删除会话")

        sessions = self.runner.get_all_sessions()
        if not sessions:
            self.print_info("暂无会话记录")
            print("\n按 Enter 返回主菜单...")
            input()
            return

        print("\n所有会话:")
        print(f"\n{'序号':<6} {'会话ID':<36} {'目标':<25} {'阶段':<15}")
        self.print_separator()

        for i, session in enumerate(sessions, 1):
            session_id = session["session_id"][:36]
            target = session.get("target", "")[:23] + ".." if len(session.get("target", "")) > 25 else session.get("target", "")
            stage = session.get("stage", "unknown")[:13]
            print(f"[{i}]    {session_id} {target:<25} {stage}")

        print(f"\n{'='*60}")
        choice = self.get_input("选择要删除的会话序号 (0 返回)")

        if choice == "0" or not choice:
            return

        try:
            index = int(choice) - 1
            if 0 <= index < len(sessions):
                session = sessions[index]
                session_id = session["session_id"]

                self.print_warning(f"确定要删除会话 {session_id} 吗？(y/n)")
                confirm = self.get_choice("", ["y", "n", "Y", "N"]).lower()

                if confirm == "y":
                    if self.runner.delete_session(session_id):
                        self.print_success("会话删除成功!")
                    else:
                        self.print_error("会话删除失败")
                else:
                    self.print_info("已取消删除")

                print("\n按 Enter 返回主菜单...")
                input()
            else:
                self.print_error("无效的序号")
        except ValueError:
            self.print_error("请输入有效的数字")

    async def run(self):
        self.clear_screen()
        self.print_banner()

        while self.running:
            self.print_menu()
            choice = self.get_choice("请选择操作", ["1", "2", "3", "4", "5", "6"])

            if choice == "1":
                await self.new_scan_task()
            elif choice == "2":
                self.view_task_status()
            elif choice == "3":
                self.view_all_sessions()
            elif choice == "4":
                await self.resume_session()
            elif choice == "5":
                self.delete_session()
            elif choice == "6":
                self.running = False
                self.print_info("感谢使用 TOSKill，再见!")
                break

            self.clear_screen()
            self.print_banner()


async def main():
    cli = TOSKillCLI()
    await cli.run()


def run_cli():
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n程序已退出")
        sys.exit(0)


if __name__ == "__main__":
    run_cli()
