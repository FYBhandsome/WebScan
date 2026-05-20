"""
TOSKill 模拟服务器

当真实 TOSKill 服务未运行时，提供模拟 HTTP 端点用于集成测试。
使用 Python 标准库 http.server 实现，无需额外依赖。
"""
import json
import threading
import time
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

MOCK_PORT = 8081
MOCK_HOST = "127.0.0.1"


def _now():
    return datetime.now().isoformat()


class MockTOSKillHandler(BaseHTTPRequestHandler):

    def _send_json(self, code, data):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _method_not_allowed(self):
        self._send_json(405, {"detail": "Method Not Allowed"})

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0].rstrip("/")

        if path == "" or path == "/":
            self._send_json(200, {
                "message": "Welcome to Mock TOSKill",
                "version": "1.0.0-test",
                "status": "running"
            })
        elif path == "/health":
            self._send_json(200, {"status": "healthy"})
        elif path == "/api/health":
            self._send_json(200, {
                "code": 200,
                "message": "TOSKill API 服务正常",
                "data": {
                    "status": "healthy",
                    "ai_model_status": "connected",
                    "tools_count": 21,
                    "timestamp": _now()
                },
                "timestamp": _now()
            })
        elif path == "/api/tools":
            self._send_json(200, {
                "code": 200,
                "message": "success",
                "data": {
                    "tools": [
                        {"name": "baseinfo_scan", "description": "基础信息扫描"},
                        {"name": "portscan", "description": "端口扫描"},
                        {"name": "cms_identify", "description": "CMS识别"},
                        {"name": "subdomain_scan", "description": "子域名扫描"},
                        {"name": "sqli_scan", "description": "SQL注入扫描"},
                        {"name": "xss_scan", "description": "跨站脚本扫描"},
                        {"name": "dirscan", "description": "目录扫描"},
                        {"name": "crawler", "description": "爬虫"},
                        {"name": "csrf_scan", "description": "CSRF扫描"},
                        {"name": "fileupload_scan", "description": "文件上传漏洞扫描"},
                        {"name": "cmdi_scan", "description": "命令注入扫描"},
                        {"name": "weakpass_scan", "description": "弱口令扫描"},
                        {"name": "lfi_scan", "description": "本地文件包含扫描"},
                        {"name": "ssrf_scan", "description": "SSRF扫描"},
                        {"name": "infoleak_scan", "description": "信息泄露扫描"},
                        {"name": "waf_detect", "description": "WAF检测"},
                        {"name": "cdn_detect", "description": "CDN检测"},
                        {"name": "iplocating", "description": "IP定位"},
                        {"name": "webside_scan", "description": "网站侧边扫描"},
                        {"name": "webweight_scan", "description": "Web权重扫描"},
                        {"name": "vuln_infoleak_scan", "description": "漏洞信息泄露扫描"},
                    ],
                    "count": 21
                },
                "timestamp": _now()
            })
        elif path == "/api/tools/categories":
            self._send_json(200, {
                "code": 200,
                "message": "success",
                "data": {
                    "info_collection": [
                        "baseinfo_scan", "portscan", "cms_identify",
                        "subdomain_scan", "waf_detect", "cdn_detect",
                        "iplocating", "webside_scan", "webweight_scan"
                    ],
                    "vuln_scan": [
                        "sqli_scan", "xss_scan", "csrf_scan",
                        "fileupload_scan", "cmdi_scan", "weakpass_scan",
                        "lfi_scan", "ssrf_scan", "infoleak_scan",
                        "vuln_infoleak_scan", "dirscan", "crawler"
                    ],
                    "all": [
                        "baseinfo_scan", "portscan", "cms_identify",
                        "subdomain_scan", "waf_detect", "cdn_detect",
                        "iplocating", "webside_scan", "webweight_scan",
                        "sqli_scan", "xss_scan", "csrf_scan",
                        "fileupload_scan", "cmdi_scan", "weakpass_scan",
                        "lfi_scan", "ssrf_scan", "infoleak_scan",
                        "vuln_infoleak_scan", "dirscan", "crawler"
                    ]
                },
                "timestamp": _now()
            })
        elif path == "/api/reports/list":
            self._send_json(200, {
                "code": 200,
                "message": "success",
                "data": {
                    "reports": [
                        {
                            "id": "mock-report-001",
                            "name": "mock_scan_report.md",
                            "size": 2048,
                            "created_at": _now(),
                            "modified_at": _now(),
                            "download_url": "/api/reports/download/mock_scan_report.md"
                        },
                        {
                            "id": "mock-report-002",
                            "name": "mock_scan_report.html",
                            "size": 4096,
                            "created_at": _now(),
                            "modified_at": _now(),
                            "download_url": "/api/reports/download/mock_scan_report.html"
                        }
                    ],
                    "total": 2
                },
                "timestamp": _now()
            })
        elif path == "/api/ai-chat/ws":
            self._send_json(404, {"detail": "WebSocket endpoint - use ws:// to connect"})
        elif path.startswith("/api/sessions/"):
            session_id = path.split("/")[-1]
            self._send_json(200, {
                "code": 200,
                "message": "success",
                "data": {
                    "session_id": session_id,
                    "target": "https://httpbin.org",
                    "mode": "info_collection",
                    "completed_tasks": ["baseinfo_scan", "portscan"],
                    "vulnerabilities": [],
                    "is_complete": False
                },
                "timestamp": _now()
            })
        elif path == "/api/chat/history":
            self._send_json(200, {
                "code": 200,
                "message": "success",
                "data": {"history": []},
                "timestamp": _now()
            })
        else:
            self._send_json(404, {"detail": f"Mock: 路径 {path} 不存在"})

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body_raw = self.rfile.read(content_length) if content_length else b"{}"
        try:
            body = json.loads(body_raw.decode("utf-8"))
        except json.JSONDecodeError:
            body = {}

        path = self.path.split("?")[0].rstrip("/")

        if path == "/api/scan/info":
            self._send_json(200, {
                "code": 200,
                "message": "信息收集完成: 3/3",
                "data": {
                    "session_id": "mock-session-001",
                    "target": body.get("target", "https://httpbin.org"),
                    "scan_type": "info_collection",
                    "tools_used": ["baseinfo_scan", "portscan", "cms_identify"],
                    "results": [
                        {
                            "tool": "baseinfo_scan",
                            "success": True,
                            "result": {"server": "nginx/1.18", "title": "Mock Site"},
                            "timestamp": _now()
                        },
                        {
                            "tool": "portscan",
                            "success": True,
                            "result": {"open_ports": [80, 443]},
                            "timestamp": _now()
                        },
                        {
                            "tool": "cms_identify",
                            "success": True,
                            "result": {"cms": "WordPress", "version": "6.0"},
                            "timestamp": _now()
                        }
                    ],
                    "completed_tasks": ["baseinfo_scan", "portscan", "cms_identify"],
                    "tool_results": {
                        "baseinfo_scan": {"server": "nginx/1.18", "title": "Mock Site"},
                        "portscan": {"open_ports": [80, 443]},
                        "cms_identify": {"cms": "WordPress", "version": "6.0"}
                    },
                    "errors": [],
                    "timestamp": _now()
                },
                "timestamp": _now()
            })
        elif path == "/api/scan/vuln":
            self._send_json(200, {
                "code": 200,
                "message": "漏洞扫描完成: 2/2",
                "data": {
                    "session_id": "mock-session-002",
                    "target": body.get("target", "https://httpbin.org"),
                    "scan_type": "vuln_scan",
                    "tools_used": ["sqli_scan", "xss_scan"],
                    "results": [
                        {
                            "tool": "sqli_scan",
                            "success": True,
                            "result": {"vulnerable": False},
                            "timestamp": _now()
                        },
                        {
                            "tool": "xss_scan",
                            "success": True,
                            "result": {"vulnerable": False},
                            "timestamp": _now()
                        }
                    ],
                    "completed_tasks": ["sqli_scan", "xss_scan"],
                    "tool_results": {},
                    "vulnerabilities": [],
                    "errors": [],
                    "timestamp": _now()
                },
                "timestamp": _now()
            })
        elif path == "/api/scan/full":
            self._send_json(200, {
                "code": 200,
                "message": "完整扫描完成: 5/5",
                "data": {
                    "session_id": "mock-session-003",
                    "target": body.get("target", "https://httpbin.org"),
                    "scan_type": "full_scan",
                    "tools_used": ["baseinfo_scan", "portscan", "cms_identify", "sqli_scan", "xss_scan"],
                    "results": [],
                    "completed_tasks": ["baseinfo_scan", "portscan", "cms_identify", "sqli_scan", "xss_scan"],
                    "tool_results": {},
                    "vulnerabilities": [],
                    "scan_summary": {"total_tools": 5, "completed_tools": 5, "vulnerabilities_found": 0, "errors_count": 0},
                    "errors": [],
                    "timestamp": _now()
                },
                "timestamp": _now()
            })
        elif path == "/api/sessions":
            self._send_json(200, {
                "code": 200,
                "message": "会话创建成功",
                "data": {"session_id": "mock-session-new"},
                "timestamp": _now()
            })
        elif path == "/api/chat/send":
            self._send_json(200, {
                "code": 200,
                "message": "消息已发送",
                "data": None,
                "timestamp": _now()
            })
        elif path == "/api/parse-intent":
            self._send_json(200, {
                "code": 200,
                "message": "意图解析完成",
                "data": {
                    "original_message": body.get("message", ""),
                    "target": "https://httpbin.org",
                    "mode": "full",
                    "action": "scan",
                    "confidence": 0.9,
                    "explanation": "用户请求安全扫描",
                    "should_start_scan": True,
                    "timestamp": _now()
                },
                "timestamp": _now()
            })
        else:
            self._send_json(404, {"detail": f"Mock: 路径 {path} 不存在"})

    def do_PUT(self):
        self._method_not_allowed()

    def do_DELETE(self):
        path = self.path.split("?")[0].rstrip("/")
        if path.startswith("/api/sessions/"):
            self._send_json(200, {
                "code": 200,
                "message": "会话删除成功",
                "data": None,
                "timestamp": _now()
            })
        else:
            self._send_json(404, {"detail": f"Mock: 路径 {path} 不存在"})

    def log_message(self, format, *args):
        pass


class MockTOSKillServer:
    """Mock TOSKill 服务器管理器"""

    def __init__(self, host=MOCK_HOST, port=MOCK_PORT):
        self.host = host
        self.port = port
        self._server = None
        self._thread = None

    @property
    def base_url(self):
        return f"http://{self.host}:{self.port}"

    def start(self):
        """启动 mock 服务器（非阻塞）"""
        self._server = HTTPServer((self.host, self.port), MockTOSKillHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        time.sleep(0.1)

    def stop(self):
        """停止 mock 服务器"""
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None

    def is_running(self):
        return self._server is not None


def create_mock_server():
    """创建并启动一个 mock 服务器实例"""
    server = MockTOSKillServer()
    server.start()
    return server