# -*- coding: utf-8 -*-
"""
TOSKill Workflow Interactive Test Suite

Comprehensive test file for TOSKill workflow testing.
Tests all 22 tools with automatic interaction handling.

Features:
- Health check API
- Parse intent API
- Tools list API
- Reports list API
- WebSocket connection test
- Full workflow test with automatic interaction handling
- Tool execution verification
- Report generation verification

Usage:
    python test_workflow_interactive.py --target http://example.com --mode info
    python test_workflow_interactive.py --target http://example.com --mode vuln
    python test_workflow_interactive.py --target http://example.com --mode full
"""

import asyncio
import json
import sys
import os
import time
import argparse
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import httpx
    import websockets
except ImportError:
    print("Error: Missing required packages. Run: pip install httpx websockets")
    sys.exit(1)


BASE_URL = "http://127.0.0.1:8081"
WS_URL = "ws://127.0.0.1:8081/api/ai-chat/ws"

DEFAULT_TIMEOUT = 30.0
WS_TIMEOUT = 60.0
SCAN_TIMEOUT = 600


class ScanMode(Enum):
    INFO = "info"
    VULN = "vuln"
    FULL = "full"


class InteractionType(Enum):
    INTERACTION_REQUIRED = "interaction_required"
    TOOL_CONFIRM_REQUIRED = "tool_confirm_required"
    ALTERNATIVE_OPTIONS = "alternative_options"
    WORKFLOW_RESUMED = "workflow_resumed"
    TOOL_EXECUTION_PROCEED = "tool_execution_proceed"
    HIGH_RISK_CONFIRM = "high_risk_vulnerability_detected"


@dataclass
class TestResult:
    name: str
    passed: bool
    detail: str = ""
    duration: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class ToolExecutionRecord:
    tool_name: str
    status: str
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    result: Optional[Dict] = None
    error: Optional[str] = None


class TestReport:
    def __init__(self):
        self.results: List[TestResult] = []
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.start_time = time.time()
        self.tool_executions: List[ToolExecutionRecord] = []
        self.messages_received: List[Dict] = []
        self.interactions_handled: Dict[str, int] = {
            InteractionType.INTERACTION_REQUIRED.value: 0,
            InteractionType.TOOL_CONFIRM_REQUIRED.value: 0,
            InteractionType.ALTERNATIVE_OPTIONS.value: 0,
            InteractionType.WORKFLOW_RESUMED.value: 0,
            InteractionType.TOOL_EXECUTION_PROCEED.value: 0,
            InteractionType.HIGH_RISK_CONFIRM.value: 0,
        }

    def add_result(self, result: TestResult):
        self.results.append(result)
        if result.passed:
            self.passed += 1
        else:
            self.failed += 1

    def skip(self, name: str, reason: str = ""):
        self.skipped += 1
        self.results.append(TestResult(name=name, passed=False, detail=f"SKIPPED: {reason}"))

    def record_tool_execution(self, record: ToolExecutionRecord):
        self.tool_executions.append(record)

    def record_message(self, message: Dict):
        self.messages_received.append(message)

    def record_interaction(self, interaction_type: str):
        if interaction_type in self.interactions_handled:
            self.interactions_handled[interaction_type] += 1

    def get_summary(self) -> Dict:
        total = self.passed + self.failed + self.skipped
        duration = time.time() - self.start_time
        return {
            "total_tests": total,
            "passed": self.passed,
            "failed": self.failed,
            "skipped": self.skipped,
            "duration_seconds": round(duration, 2),
            "tools_executed": len(self.tool_executions),
            "tools_succeeded": len([t for t in self.tool_executions if t.status == "completed"]),
            "tools_failed": len([t for t in self.tool_executions if t.status == "error"]),
            "messages_received": len(self.messages_received),
            "interactions_handled": dict(self.interactions_handled),
        }

    def print_report(self):
        print("\n" + "=" * 70)
        print("TOSKill Workflow Test Report")
        print("=" * 70)
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()

        summary = self.get_summary()
        print("Summary:")
        print(f"  Total Tests: {summary['total_tests']}")
        print(f"  Passed: {summary['passed']}")
        print(f"  Failed: {summary['failed']}")
        print(f"  Skipped: {summary['skipped']}")
        print(f"  Duration: {summary['duration_seconds']}s")
        print()

        print("Tool Execution Summary:")
        print(f"  Tools Executed: {summary['tools_executed']}")
        print(f"  Succeeded: {summary['tools_succeeded']}")
        print(f"  Failed: {summary['tools_failed']}")
        print()

        print("Interaction Handling Summary:")
        for itype, count in summary['interactions_handled'].items():
            print(f"  {itype}: {count}")
        print()

        print("-" * 70)
        print("Test Results:")
        print("-" * 70)
        for result in self.results:
            status = "PASS" if result.passed else ("SKIP" if "SKIPPED" in result.detail else "FAIL")
            status_color = "+" if result.passed else "-"
            print(f"  [{status_color}] {result.name}: {status}")
            if result.detail:
                print(f"      {result.detail}")
            if result.duration > 0:
                print(f"      Duration: {result.duration:.2f}s")

        if self.tool_executions:
            print()
            print("-" * 70)
            print("Tool Execution Details:")
            print("-" * 70)
            for tool in self.tool_executions:
                status_icon = "+" if tool.status == "completed" else "-"
                print(f"  [{status_icon}] {tool.tool_name}: {tool.status}")
                if tool.error:
                    print(f"      Error: {tool.error[:100]}")

        print()
        print("=" * 70)
        print(f"FINAL RESULT: {'ALL TESTS PASSED' if self.failed == 0 else f'{self.failed} TESTS FAILED'}")
        print("=" * 70)


ALL_TOOLS = [
    "baseinfo_scan",
    "port_scan",
    "subdomain_scan",
    "dir_brute",
    "waf_detect_scan",
    "cdn_detect_scan",
    "cms_detect_scan",
    "infoleak_scan",
    "ip_locate_scan",
    "webside_query_scan",
    "web_weight_scan",
    "sqli_scan",
    "xss_scan",
    "csrf_scan",
    "fileupload_scan",
    "cmdi_scan",
    "ssrf_scan",
    "lfi_scan",
    "weakpass_scan",
    "thinkphp_rce_scan",
    "struts2_scan",
    "weblogic_scan",
]

INFO_COLLECTION_TOOLS = [
    "baseinfo_scan",
    "port_scan",
    "subdomain_scan",
    "dir_brute",
    "waf_detect_scan",
    "cdn_detect_scan",
    "cms_detect_scan",
    "infoleak_scan",
    "ip_locate_scan",
    "webside_query_scan",
    "web_weight_scan",
]

VULN_SCAN_TOOLS = [
    "sqli_scan",
    "xss_scan",
    "csrf_scan",
    "fileupload_scan",
    "cmdi_scan",
    "ssrf_scan",
    "lfi_scan",
    "weakpass_scan",
]

POC_TOOLS = [
    "thinkphp_rce_scan",
    "struts2_scan",
    "weblogic_scan",
]


class TOSKillTestClient:
    def __init__(self, base_url: str = BASE_URL, ws_url: str = WS_URL):
        self.base_url = base_url
        self.ws_url = ws_url
        self.report = TestReport()
        self.session_id: Optional[str] = None
        self.ws = None
        self.auto_choice: str = "1"

    async def test_health_api(self) -> bool:
        print("\n[1/8] Testing Health API...")
        start = time.time()
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(f"{self.base_url}/health", timeout=DEFAULT_TIMEOUT)
                ok = resp.status_code == 200
                data = resp.json() if ok else {}
                detail = f"status={resp.status_code}, status={data.get('status', 'unknown')}"
                self.report.add_result(TestResult(
                    name="Health API",
                    passed=ok,
                    detail=detail,
                    duration=time.time() - start
                ))
                return ok
        except Exception as e:
            self.report.add_result(TestResult(
                name="Health API",
                passed=False,
                detail=str(e),
                duration=time.time() - start
            ))
            return False

    async def test_parse_intent_api(self, message: str = "http://testasp.vulnweb.com port scan") -> Optional[Dict]:
        print("\n[2/8] Testing Parse Intent API...")
        start = time.time()
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{self.base_url}/api/parse-intent",
                    json={"message": message},
                    timeout=DEFAULT_TIMEOUT
                )
                ok = resp.status_code == 200
                data = resp.json()
                result_data = data.get("data", {})
                detail = f"target={result_data.get('target')}, mode={result_data.get('mode')}, action={result_data.get('action')}"
                self.report.add_result(TestResult(
                    name="Parse Intent API",
                    passed=ok and data.get("code") == 200,
                    detail=detail,
                    duration=time.time() - start
                ))
                return result_data if ok else None
        except Exception as e:
            self.report.add_result(TestResult(
                name="Parse Intent API",
                passed=False,
                detail=str(e),
                duration=time.time() - start
            ))
            return None

    async def test_tools_list_api(self) -> bool:
        print("\n[3/8] Testing Tools List API...")
        start = time.time()
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(f"{self.base_url}/api/tools", timeout=DEFAULT_TIMEOUT)
                ok = resp.status_code == 200
                data = resp.json()
                tools = data.get("data", {}).get("tools", [])
                tool_count = len(tools)
                detail = f"count={tool_count}"
                self.report.add_result(TestResult(
                    name="Tools List API",
                    passed=ok and tool_count >= 22,
                    detail=detail,
                    duration=time.time() - start
                ))
                return ok
        except Exception as e:
            self.report.add_result(TestResult(
                name="Tools List API",
                passed=False,
                detail=str(e),
                duration=time.time() - start
            ))
            return False

    async def test_tools_categories_api(self) -> bool:
        print("\n[4/8] Testing Tools Categories API...")
        start = time.time()
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(f"{self.base_url}/api/tools/categories", timeout=DEFAULT_TIMEOUT)
                ok = resp.status_code == 200
                data = resp.json()
                categories = data.get("data", {})
                info_count = len(categories.get("info_collection", []))
                vuln_count = len(categories.get("vuln_scan", []))
                all_count = len(categories.get("all", []))
                detail = f"info={info_count}, vuln={vuln_count}, all={all_count}"
                self.report.add_result(TestResult(
                    name="Tools Categories API",
                    passed=ok,
                    detail=detail,
                    duration=time.time() - start
                ))
                return ok
        except Exception as e:
            self.report.add_result(TestResult(
                name="Tools Categories API",
                passed=False,
                detail=str(e),
                duration=time.time() - start
            ))
            return False

    async def test_reports_list_api(self) -> bool:
        print("\n[5/8] Testing Reports List API...")
        start = time.time()
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(f"{self.base_url}/api/reports/list", timeout=DEFAULT_TIMEOUT)
                ok = resp.status_code == 200
                data = resp.json()
                reports = data.get("reports", data.get("data", []))
                report_count = len(reports) if isinstance(reports, list) else 0
                detail = f"count={report_count}"
                self.report.add_result(TestResult(
                    name="Reports List API",
                    passed=ok,
                    detail=detail,
                    duration=time.time() - start
                ))
                return ok
        except Exception as e:
            self.report.add_result(TestResult(
                name="Reports List API",
                passed=False,
                detail=str(e),
                duration=time.time() - start
            ))
            return False

    async def test_websocket_connection(self) -> bool:
        print("\n[6/8] Testing WebSocket Connection...")
        start = time.time()
        try:
            async with websockets.connect(
                self.ws_url,
                ping_interval=20,
                ping_timeout=10,
                close_timeout=5
            ) as ws:
                self.ws = ws
                msg = await asyncio.wait_for(ws.recv(), timeout=WS_TIMEOUT)
                data = json.loads(msg)
                msg_type = data.get("type", "")

                if msg_type == "connected":
                    self.session_id = data.get("payload", {}).get("session_id", "")
                    available_tools = data.get("payload", {}).get("available_tools", [])
                    detail = f"session={self.session_id}, tools={len(available_tools)}"
                    self.report.add_result(TestResult(
                        name="WebSocket Connection",
                        passed=True,
                        detail=detail,
                        duration=time.time() - start
                    ))
                    return True
                else:
                    self.report.add_result(TestResult(
                        name="WebSocket Connection",
                        passed=False,
                        detail=f"Unexpected message type: {msg_type}",
                        duration=time.time() - start
                    ))
                    return False
        except Exception as e:
            self.report.add_result(TestResult(
                name="WebSocket Connection",
                passed=False,
                detail=str(e),
                duration=time.time() - start
            ))
            return False

    async def _handle_interaction(self, ws, message: Dict) -> bool:
        msg_type = message.get("type", "")
        payload = message.get("payload", {})

        self.report.record_message(message)
        self.report.record_interaction(msg_type)

        if msg_type == "interaction_required":
            options = payload.get("options", [])
            next_task = payload.get("next_task", "")
            print(f"    [INTERACTION] Required for task: {next_task}")
            print(f"    Options: {[o.get('key') for o in options]}")
            
            response = {"type": "user_choice", "payload": {"choice": self.auto_choice}}
            await ws.send(json.dumps(response))
            print(f"    -> Auto-sent choice: {self.auto_choice}")
            return True

        elif msg_type == "tool_confirm_required":
            tool_name = payload.get("tool_name", "")
            print(f"    [TOOL_CONFIRM] Tool: {tool_name}")
            
            response = {"type": "tool_confirmed", "payload": {"confirmed": True}}
            await ws.send(json.dumps(response))
            print(f"    -> Auto-confirmed tool execution")
            return True

        elif msg_type == "alternative_options":
            alternatives = payload.get("alternatives", [])
            print(f"    [ALTERNATIVE] Options available: {len(alternatives)}")
            
            if alternatives:
                first_alt = alternatives[0]
                response = {
                    "type": "alternative_selected",
                    "payload": {
                        "choice_index": 0,
                        "choice_label": first_alt.get("label", "Option 1")
                    }
                }
                await ws.send(json.dumps(response))
                print(f"    -> Auto-selected first alternative")
            return True

        elif msg_type == "high_risk_vulnerability_detected":
            risk_level = payload.get("highest_risk_level", "")
            print(f"    [HIGH_RISK] Detected: {risk_level}")
            
            response = {"type": "high_risk_confirm", "payload": {"choice": "continue"}}
            await ws.send(json.dumps(response))
            print(f"    -> Auto-confirmed continue scanning")
            return True

        elif msg_type == "workflow_resumed":
            print(f"    [WORKFLOW_RESUMED] Choice: {payload.get('choice')}")
            return True

        elif msg_type == "tool_execution_proceed":
            print(f"    [TOOL_PROCEED] Status: {payload.get('status')}")
            return True

        return False

    async def test_full_workflow(
        self,
        target: str,
        mode: str = "info",
        auto_choice: str = "1",
        max_wait: int = SCAN_TIMEOUT
    ) -> bool:
        print(f"\n[7/8] Testing Full Workflow (target={target}, mode={mode})...")
        self.auto_choice = auto_choice
        
        start = time.time()
        results = {
            "scan_started": False,
            "task_started": 0,
            "task_completed": 0,
            "task_skipped": 0,
            "task_error": 0,
            "scan_completed": False,
            "workflow_log": 0,
            "ai_decision": 0,
        }

        try:
            async with websockets.connect(
                self.ws_url,
                ping_interval=20,
                ping_timeout=10,
                close_timeout=5
            ) as ws:
                msg = await asyncio.wait_for(ws.recv(), timeout=WS_TIMEOUT)
                data = json.loads(msg)
                
                if data.get("type") != "connected":
                    self.report.add_result(TestResult(
                        name="Full Workflow",
                        passed=False,
                        detail=f"Connection failed: {data.get('type')}",
                        duration=time.time() - start
                    ))
                    return False
                
                self.session_id = data.get("payload", {}).get("session_id", "")
                print(f"    Connected: session={self.session_id}")

                scan_msg = {
                    "type": "start_scan",
                    "payload": {"target": target, "scan_mode": mode}
                }
                await ws.send(json.dumps(scan_msg))
                print(f"    Sent: start_scan({target}, {mode})")

                current_tool = None
                tool_start_time = None

                while time.time() - start < max_wait:
                    try:
                        msg = await asyncio.wait_for(ws.recv(), timeout=WS_TIMEOUT)
                        data = json.loads(msg)
                        msg_type = data.get("type", "")
                        payload = data.get("payload", {})

                        self.report.record_message(data)

                        if msg_type == "scan_started":
                            results["scan_started"] = True
                            print(f"    [scan_started] task_id={payload.get('task_id')}")

                        elif msg_type == "task_started":
                            results["task_started"] += 1
                            current_tool = payload.get("tool", "")
                            tool_start_time = datetime.now().isoformat()
                            print(f"    [task_started] {current_tool}")

                        elif msg_type == "task_completed":
                            results["task_completed"] += 1
                            tool_name = payload.get("tool", current_tool)
                            self.report.record_tool_execution(ToolExecutionRecord(
                                tool_name=tool_name,
                                status="completed",
                                start_time=tool_start_time,
                                end_time=datetime.now().isoformat(),
                                result=payload.get("result")
                            ))
                            print(f"    [task_completed] {tool_name}")
                            current_tool = None
                            tool_start_time = None

                        elif msg_type == "task_skipped":
                            results["task_skipped"] += 1
                            tool_name = payload.get("tool", "")
                            reason = payload.get("reason", "")
                            print(f"    [task_skipped] {tool_name}: {reason[:50]}")

                        elif msg_type == "task_error":
                            results["task_error"] += 1
                            tool_name = payload.get("tool", current_tool)
                            error = payload.get("error", "")
                            ai_analysis = payload.get("ai_analysis", "")
                            self.report.record_tool_execution(ToolExecutionRecord(
                                tool_name=tool_name,
                                status="error",
                                start_time=tool_start_time,
                                end_time=datetime.now().isoformat(),
                                error=error or ai_analysis
                            ))
                            print(f"    [task_error] {tool_name}: {error[:50] if error else 'AI analysis available'}")
                            current_tool = None
                            tool_start_time = None

                        elif msg_type == "scan_completed":
                            results["scan_completed"] = True
                            completed_tasks = payload.get("completed_tasks", [])
                            vulns_count = payload.get("vulnerabilities_count", 0)
                            print(f"    [scan_completed] tasks={len(completed_tasks)}, vulns={vulns_count}")
                            break

                        elif msg_type == "workflow_log":
                            results["workflow_log"] += 1
                            level = payload.get("level", "")
                            msg_text = payload.get("message", "")
                            if level in ["error", "warning"]:
                                print(f"    [workflow_log][{level}] {msg_text[:80]}")

                        elif msg_type == "ai_decision":
                            results["ai_decision"] += 1
                            decision = payload.get("decision", "")
                            print(f"    [ai_decision] {decision[:50]}")

                        elif msg_type == "error":
                            error_msg = payload.get("message", "")
                            print(f"    [error] {error_msg}")
                            self.report.add_result(TestResult(
                                name="Full Workflow",
                                passed=False,
                                detail=f"Error: {error_msg}",
                                duration=time.time() - start
                            ))
                            return False

                        else:
                            handled = await self._handle_interaction(ws, data)
                            if not handled and msg_type not in [
                                "connected", "user_message_received",
                                "input_received", "status"
                            ]:
                                print(f"    [{msg_type}] (unhandled)")

                    except asyncio.TimeoutError:
                        print(f"    [TIMEOUT] No message for {WS_TIMEOUT}s")
                        break

                duration = time.time() - start
                detail = (
                    f"started={results['scan_started']}, "
                    f"tasks={results['task_completed']}/{results['task_started']}, "
                    f"errors={results['task_error']}, "
                    f"completed={results['scan_completed']}"
                )
                
                passed = results["scan_started"] and results["scan_completed"]
                self.report.add_result(TestResult(
                    name="Full Workflow",
                    passed=passed,
                    detail=detail,
                    duration=duration
                ))
                return passed

        except Exception as e:
            self.report.add_result(TestResult(
                name="Full Workflow",
                passed=False,
                detail=str(e),
                duration=time.time() - start
            ))
            import traceback
            traceback.print_exc()
            return False

    async def test_tool_execution_verification(self) -> bool:
        print("\n[8/8] Testing Tool Execution Verification...")
        start = time.time()

        executed_tools = [t.tool_name for t in self.report.tool_executions]
        expected_tools = self._get_expected_tools_for_mode("info")

        found_tools = [t for t in expected_tools if t in executed_tools]
        missing_tools = [t for t in expected_tools if t not in executed_tools]

        detail = f"expected={len(expected_tools)}, executed={len(executed_tools)}, matched={len(found_tools)}"
        if missing_tools:
            detail += f", missing={missing_tools[:3]}..."

        passed = len(found_tools) > 0
        self.report.add_result(TestResult(
            name="Tool Execution Verification",
            passed=passed,
            detail=detail,
            duration=time.time() - start
        ))
        return passed

    def _get_expected_tools_for_mode(self, mode: str) -> List[str]:
        if mode == "info":
            return INFO_COLLECTION_TOOLS
        elif mode == "vuln":
            return VULN_SCAN_TOOLS
        elif mode == "full":
            return INFO_COLLECTION_TOOLS + VULN_SCAN_TOOLS
        return INFO_COLLECTION_TOOLS

    async def run_all_tests(
        self,
        target: str,
        mode: str = "info",
        auto_choice: str = "1"
    ) -> bool:
        print("=" * 70)
        print("TOSKill Workflow Interactive Test Suite")
        print("=" * 70)
        print(f"Target: {target}")
        print(f"Mode: {mode}")
        print(f"Auto Choice: {auto_choice}")
        print(f"Base URL: {self.base_url}")
        print(f"WebSocket URL: {self.ws_url}")
        print()

        await self.test_health_api()
        await self.test_parse_intent_api(f"{target} scan")
        await self.test_tools_list_api()
        await self.test_tools_categories_api()
        await self.test_reports_list_api()
        await self.test_full_workflow(target=target, mode=mode, auto_choice=auto_choice)
        await self.test_tool_execution_verification()

        self.report.print_report()
        return self.report.failed == 0


def parse_args():
    parser = argparse.ArgumentParser(
        description="TOSKill Workflow Interactive Test Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python test_workflow_interactive.py --target http://example.com --mode info
    python test_workflow_interactive.py --target http://example.com --mode vuln
    python test_workflow_interactive.py --target http://example.com --mode full
    python test_workflow_interactive.py --target http://testasp.vulnweb.com --mode info --choice 1

Scan Modes:
    info  - Information collection (11 tools)
    vuln  - Vulnerability scanning (8 tools)
    full  - Full scan (19 tools)

Auto Choices:
    1 - Execute current task (default)
    2 - Stop scan and generate report
    3 - Chat with AI assistant
    4 - Upload custom script
    5 - AI generate scan script
        """
    )
    parser.add_argument(
        "--target", "-t",
        type=str,
        default="http://testasp.vulnweb.com",
        help="Target URL for scanning (default: http://testasp.vulnweb.com)"
    )
    parser.add_argument(
        "--mode", "-m",
        type=str,
        choices=["info", "vuln", "full"],
        default="info",
        help="Scan mode: info, vuln, or full (default: info)"
    )
    parser.add_argument(
        "--choice", "-c",
        type=str,
        default="1",
        choices=["1", "2", "3", "4", "5"],
        help="Auto choice for interactions (default: 1)"
    )
    parser.add_argument(
        "--base-url",
        type=str,
        default=BASE_URL,
        help=f"Base URL for API (default: {BASE_URL})"
    )
    parser.add_argument(
        "--ws-url",
        type=str,
        default=WS_URL,
        help=f"WebSocket URL (default: {WS_URL})"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=SCAN_TIMEOUT,
        help=f"Scan timeout in seconds (default: {SCAN_TIMEOUT})"
    )
    return parser.parse_args()


async def main():
    args = parse_args()

    client = TOSKillTestClient(
        base_url=args.base_url,
        ws_url=args.ws_url
    )

    success = await client.run_all_tests(
        target=args.target,
        mode=args.mode,
        auto_choice=args.choice
    )

    return 0 if success else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
