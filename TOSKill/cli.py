"""
TOSKill CLI - 终端交互式安全扫描工具

提供类似前端静态页面的交互体验，支持：
- 信息收集扫描
- 漏洞扫描
- 完整扫描
- 单工具执行
- AI对话
- 工具列表查看
"""
import asyncio
import json
import sys
from typing import Optional, Dict, Any, List
from datetime import datetime

try:
    import httpx
except ImportError:
    print("请安装 httpx: pip install httpx")
    sys.exit(1)

try:
    import websockets
except ImportError:
    print("请安装 websockets: pip install websockets")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.prompt import Prompt, Confirm
    from rich.markdown import Markdown
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("提示: 安装 rich 库可获得更好的终端体验: pip install rich")


API_BASE_URL = "http://localhost:8081/api"
WS_URL = "ws://localhost:8081/api/ai-chat/ws"
REQUEST_TIMEOUT = 300.0


if RICH_AVAILABLE:
    console = Console()
else:
    class SimpleConsole:
        def print(self, *args, **kwargs):
            message = " ".join(str(arg) for arg in args)
            print(message)
        
        def clear(self):
            print("\033[2J\033[H", end="")
        
        def rule(self, title=""):
            print(f"\n{'='*50}")
            if title:
                print(f"  {title}")
            print('='*50 + "\n")
    
    console = SimpleConsole()


class APIClient:
    """REST API 客户端"""
    
    def __init__(self, base_url: str = API_BASE_URL):
        self.base_url = base_url
        self.client = httpx.AsyncClient(timeout=REQUEST_TIMEOUT)
    
    async def close(self):
        await self.client.aclose()
    
    async def health_check(self) -> Dict:
        try:
            resp = await self.client.get(f"{self.base_url}/toskill/health")
            return resp.json()
        except Exception as e:
            return {"code": 500, "message": str(e)}
    
    async def info_scan(self, target: str, tools: List[str] = None) -> Dict:
        payload = {"target": target}
        if tools:
            payload["tools"] = tools
        resp = await self.client.post(f"{self.base_url}/toskill/scan/info", json=payload)
        return resp.json()
    
    async def vuln_scan(self, target: str, tools: List[str] = None) -> Dict:
        payload = {"target": target}
        if tools:
            payload["tools"] = tools
        resp = await self.client.post(f"{self.base_url}/toskill/scan/vuln", json=payload)
        return resp.json()
    
    async def full_scan(self, target: str, tools: List[str] = None) -> Dict:
        payload = {"target": target, "generate_report": True}
        if tools:
            payload["tools"] = tools
        resp = await self.client.post(f"{self.base_url}/toskill/scan/full", json=payload)
        return resp.json()
    
    async def execute_tool(self, tool_name: str, target: str) -> Dict:
        payload = {"tool_name": tool_name, "target": target}
        resp = await self.client.post(f"{self.base_url}/toskill/tools/execute", json=payload)
        return resp.json()
    
    async def list_tools(self) -> Dict:
        resp = await self.client.get(f"{self.base_url}/toskill/tools")
        return resp.json()
    
    async def list_tools_by_category(self) -> Dict:
        resp = await self.client.get(f"{self.base_url}/toskill/tools/categories")
        return resp.json()


class AIChatClient:
    """AI对话 WebSocket 客户端"""
    
    def __init__(self, ws_url: str = WS_URL):
        self.ws_url = ws_url
        self.ws = None
        self.session_id = None
        self.connected = False
    
    async def connect(self):
        try:
            self.ws = await websockets.connect(self.ws_url)
            self.connected = True
            msg = await asyncio.wait_for(self.ws.recv(), timeout=10.0)
            data = json.loads(msg)
            self.session_id = data.get("payload", {}).get("session_id")
            return True, data
        except asyncio.TimeoutError:
            self.connected = False
            return False, "连接超时"
        except Exception as e:
            self.connected = False
            return False, str(e)
    
    async def disconnect(self):
        if self.ws:
            try:
                await self.ws.close()
            except:
                pass
        self.connected = False
    
    async def send_message(self, msg_type: str, payload: Dict):
        if not self.connected or not self.ws:
            return False
        try:
            msg = {"type": msg_type, "payload": payload}
            await self.ws.send(json.dumps(msg))
            return True
        except Exception:
            return False
    
    async def receive_message(self, timeout: float = 30.0) -> Optional[Dict]:
        if not self.connected or not self.ws:
            return None
        try:
            msg = await asyncio.wait_for(self.ws.recv(), timeout=timeout)
            return json.loads(msg)
        except asyncio.TimeoutError:
            return None
        except Exception:
            return None
    
    async def chat(self, content: str):
        await self.send_message("chat", {"content": content})


class TOSKillCLI:
    """TOSKill 命令行交互界面"""
    
    def __init__(self):
        self.api = APIClient()
        self.ai_client = AIChatClient()
        self.running = True
        self.tools_cache = None
        self.current_target = ""
    
    async def close(self):
        await self.api.close()
        if self.ai_client.connected:
            await self.ai_client.disconnect()
    
    def clear_screen(self):
        if RICH_AVAILABLE:
            console.clear()
        else:
            print("\033[2J\033[H", end="")
    
    def show_header(self):
        if RICH_AVAILABLE:
            header = Panel(
                "[bold cyan]TOSKill Security Scanner[/bold cyan]\n"
                "[dim]AI驱动的Web安全扫描系统 - 终端版[/dim]",
                style="bold blue",
                padding=(1, 2)
            )
            console.print(header)
            if self.current_target:
                console.print(f"[yellow]当前目标:[/yellow] [green]{self.current_target}[/green]")
        else:
            print("\n" + "="*50)
            print("  TOSKill Security Scanner")
            print("  AI驱动的Web安全扫描系统 - 终端版")
            print("="*50)
            if self.current_target:
                print(f"\n当前目标: {self.current_target}")
    
    def show_menu(self):
        if RICH_AVAILABLE:
            table = Table(show_header=False, box=None, padding=(0, 2))
            table.add_column("选项", style="cyan", width=6)
            table.add_column("功能", style="white")
            
            menu_items = [
                ("1", "信息收集扫描"),
                ("2", "漏洞扫描"),
                ("3", "完整扫描"),
                ("4", "执行单个工具"),
                ("5", "AI 对话"),
                ("6", "查看工具列表"),
                ("7", "设置目标"),
                ("0", "退出"),
            ]
            
            for num, desc in menu_items:
                table.add_row(f"[{num}]", desc)
            
            console.print(table)
        else:
            print("\n功能菜单:")
            print("  [1] 信息收集扫描")
            print("  [2] 漏洞扫描")
            print("  [3] 完整扫描")
            print("  [4] 执行单个工具")
            print("  [5] AI 对话")
            print("  [6] 查看工具列表")
            print("  [7] 设置目标")
            print("  [0] 退出")
    
    def get_input(self, prompt: str, default: str = "") -> str:
        if RICH_AVAILABLE:
            return Prompt.ask(f"[bold]{prompt}[/bold]", default=default)
        else:
            val = input(f"{prompt}: ").strip()
            return val if val else default
    
    def get_target(self) -> str:
        if self.current_target:
            use_current = self.confirm(f"使用当前目标 [{self.current_target}]?")
            if use_current:
                return self.current_target
        
        target = self.get_input("请输入扫描目标 (URL/域名/IP)")
        if target:
            self.current_target = target
        return target
    
    def confirm(self, prompt: str) -> bool:
        if RICH_AVAILABLE:
            return Confirm.ask(prompt, default=True)
        else:
            val = input(f"{prompt} [Y/n]: ").strip().lower()
            return val in ("", "y", "yes")
    
    def show_result(self, result: Dict, title: str = "扫描结果"):
        if RICH_AVAILABLE:
            console.print()
            console.rule(f"[bold green]{title}[/bold green]")
            
            if result.get("code") == 200:
                data = result.get("data", {})
                
                if "results" in data:
                    self._show_scan_results(data)
                elif "tools" in data:
                    self._show_tools_list(data)
                else:
                    console.print_json(json.dumps(data, ensure_ascii=False, indent=2))
            else:
                console.print(f"[red]错误: {result.get('message', '未知错误')}[/red]")
        else:
            print(f"\n{'='*50}")
            print(f"  {title}")
            print("="*50)
            if result.get("code") == 200:
                print(json.dumps(result.get("data", {}), ensure_ascii=False, indent=2))
            else:
                print(f"错误: {result.get('message', '未知错误')}")
    
    def _show_scan_results(self, data: Dict):
        results = data.get("results", [])
        
        if RICH_AVAILABLE:
            table = Table(title="扫描结果摘要")
            table.add_column("工具", style="cyan")
            table.add_column("状态", style="white")
            table.add_column("结果", style="green")
            
            for r in results:
                tool = r.get("tool", "unknown")
                success = "✓" if r.get("success") else "✗"
                status_style = "green" if r.get("success") else "red"
                
                result_data = r.get("result", r.get("error"))
                if isinstance(result_data, dict):
                    result_str = self._format_result_summary(result_data)
                else:
                    result_str = str(result_data)[:50] if result_data else "完成"
                
                table.add_row(tool, f"[{status_style}]{success}[/{status_style}]", result_str)
            
            console.print(table)
            
            success_count = sum(1 for r in results if r.get("success"))
            console.print(f"\n[bold]统计:[/bold] 成功 {success_count}/{len(results)}")
        else:
            print("\n扫描结果:")
            for r in results:
                tool = r.get("tool", "unknown")
                success = "成功" if r.get("success") else "失败"
                print(f"  - {tool}: {success}")
            
            success_count = sum(1 for r in results if r.get("success"))
            print(f"\n统计: 成功 {success_count}/{len(results)}")
    
    def _format_result_summary(self, data: Dict) -> str:
        if data.get("vulnerable"):
            return "[red]发现漏洞[/red]"
        if data.get("ports"):
            return f"端口: {len(data['ports'])}个"
        if data.get("subdomains"):
            return f"子域名: {len(data['subdomains'])}个"
        if data.get("directories"):
            return f"目录: {len(data['directories'])}个"
        if data.get("server"):
            return f"服务器: {data['server']}"
        return "完成"
    
    def _show_tools_list(self, data: Dict):
        tools = data.get("tools", [])
        
        if RICH_AVAILABLE:
            table = Table(title="可用工具列表")
            table.add_column("名称", style="cyan")
            table.add_column("描述", style="white")
            
            for tool in tools[:30]:
                name = tool.get("name", "")
                desc = tool.get("description", "")[:50]
                table.add_row(name, desc)
            
            console.print(table)
            if len(tools) > 30:
                console.print(f"[dim]... 共 {len(tools)} 个工具[/dim]")
        else:
            print("\n可用工具:")
            for tool in tools[:20]:
                print(f"  - {tool.get('name')}: {tool.get('description', '')[:40]}")
            if len(tools) > 20:
                print(f"  ... 共 {len(tools)} 个工具")
    
    async def do_info_scan(self):
        target = self.get_target()
        if not target:
            self._print_error("目标不能为空")
            return
        
        self._print_info("正在执行信息收集扫描...")
        result = await self.api.info_scan(target)
        self.show_result(result, "信息收集扫描结果")
    
    async def do_vuln_scan(self):
        target = self.get_target()
        if not target:
            self._print_error("目标不能为空")
            return
        
        self._print_info("正在执行漏洞扫描...")
        result = await self.api.vuln_scan(target)
        self.show_result(result, "漏洞扫描结果")
    
    async def do_full_scan(self):
        target = self.get_target()
        if not target:
            self._print_error("目标不能为空")
            return
        
        self._print_info("正在执行完整扫描...")
        result = await self.api.full_scan(target)
        self.show_result(result, "完整扫描结果")
    
    async def do_execute_tool(self):
        if not self.tools_cache:
            result = await self.api.list_tools()
            self.tools_cache = result.get("data", {}).get("tools", [])
        
        self._show_tools_list({"tools": self.tools_cache})
        
        tool_name = self.get_input("请输入工具名称")
        if not tool_name:
            return
        
        target = self.get_target()
        if not target:
            return
        
        self._print_info(f"正在执行 {tool_name}...")
        result = await self.api.execute_tool(tool_name, target)
        self.show_result(result, f"工具执行结果 - {tool_name}")
    
    async def do_ai_chat(self):
        if RICH_AVAILABLE:
            console.print(Panel(
                "[bold cyan]AI 对话模式[/bold cyan]\n"
                "[dim]输入消息与AI交互，输入 'exit' 或 'quit' 退出[/dim]",
                style="blue"
            ))
        else:
            print("\n" + "="*50)
            print("  AI 对话模式")
            print("  输入消息与AI交互，输入 'exit' 或 'quit' 退出")
            print("="*50)
        
        self._print_info("正在连接 AI 服务...")
        connected, result = await self.ai_client.connect()
        if not connected:
            self._print_error(f"连接失败: {result}")
            return
        
        self._print_success(f"已连接，会话ID: {self.ai_client.session_id}")
        
        try:
            while self.running:
                message = self.get_input("\n你")
                if message.lower() in ("exit", "quit", "q"):
                    break
                
                if message:
                    await self.ai_client.chat(message)
                    
                    while True:
                        response = await self.ai_client.receive_message(timeout=60.0)
                        if not response:
                            break
                        
                        msg_type = response.get("type", "")
                        payload = response.get("payload", {})
                        
                        if msg_type == "ai_message":
                            content = payload.get("content", "")
                            self._print_ai_message(content)
                            break
                        elif msg_type == "error":
                            self._print_error(payload.get("error", "未知错误"))
                            break
                        elif msg_type == "connected":
                            continue
                        else:
                            self._print_info(f"[{msg_type}] {payload}")
        
        except KeyboardInterrupt:
            self._print_info("用户中断对话")
        finally:
            await self.ai_client.disconnect()
            self._print_info("已断开连接")
    
    async def do_list_tools(self):
        result = await self.api.list_tools()
        self.tools_cache = result.get("data", {}).get("tools", [])
        self.show_result(result, "工具列表")
    
    def do_set_target(self):
        target = self.get_input("请输入目标地址 (URL/域名/IP)")
        if target:
            self.current_target = target
            self._print_success(f"目标已设置: {target}")
    
    def _print_error(self, message: str):
        if RICH_AVAILABLE:
            console.print(f"[red]错误: {message}[/red]")
        else:
            print(f"错误: {message}")
    
    def _print_info(self, message: str):
        if RICH_AVAILABLE:
            console.print(f"[cyan]{message}[/cyan]")
        else:
            print(message)
    
    def _print_success(self, message: str):
        if RICH_AVAILABLE:
            console.print(f"[green]{message}[/green]")
        else:
            print(message)
    
    def _print_ai_message(self, content: str):
        if RICH_AVAILABLE:
            console.print(f"\n[bold green]AI:[/bold green] {content}")
        else:
            print(f"\nAI: {content}")
    
    async def check_api_health(self) -> bool:
        result = await self.api.health_check()
        if result.get("code") == 200:
            self._print_success(f"API 服务正常 - 工具数量: {result.get('data', {}).get('tools_count', 0)}")
            return True
        else:
            self._print_error(f"API 服务不可用: {result.get('message', '未知错误')}")
            return False
    
    async def run(self):
        self.clear_screen()
        self.show_header()
        
        self._print_info("正在检查 API 服务...")
        healthy = await self.check_api_health()
        if not healthy:
            self._print_info("请确保 TOSKill 服务已启动 (python -m TOSKill.main)")
        
        while self.running:
            console.print()
            self.show_menu()
            
            choice = self.get_input("\n请选择功能")
            
            if choice == "1":
                await self.do_info_scan()
            elif choice == "2":
                await self.do_vuln_scan()
            elif choice == "3":
                await self.do_full_scan()
            elif choice == "4":
                await self.do_execute_tool()
            elif choice == "5":
                await self.do_ai_chat()
            elif choice == "6":
                await self.do_list_tools()
            elif choice == "7":
                self.do_set_target()
            elif choice == "0":
                self.running = False
                self._print_info("感谢使用 TOSKill，再见！")
            else:
                self._print_error("无效选项，请重新选择")
            
            if self.running and choice in ("1", "2", "3", "4", "5", "6"):
                input("\n按回车键继续...")
                self.clear_screen()
                self.show_header()


async def main():
    cli = TOSKillCLI()
    try:
        await cli.run()
    except KeyboardInterrupt:
        if RICH_AVAILABLE:
            console.print("\n[yellow]用户中断[/yellow]")
        else:
            print("\n用户中断")
    finally:
        await cli.close()


if __name__ == "__main__":
    asyncio.run(main())
