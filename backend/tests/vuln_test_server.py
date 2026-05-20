import sys
import json
import time
import base64
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

VULN_SERVER = None


class VulnTestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _send_response(self, code, content_type, body):
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.send_header('Access-Control-Allow-Methods', '*')
        self.end_headers()
        if isinstance(body, str):
            body = body.encode('utf-8')
        self.wfile.write(body)

    def do_OPTIONS(self):
        self._send_response(200, 'text/plain', '')

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == '/':
            self._send_response(200, 'text/html', '<html><body><h1>VulnTest Server</h1></body></html>')

        elif path == '/sqli':
            param = params.get('id', [''])[0]
            if "'" in param or '"' in param or 'OR' in param.upper() or 'UNION' in param.upper():
                self._send_response(200, 'text/html',
                    '<html><body>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version</body></html>')
            else:
                self._send_response(200, 'text/html',
                    '<html><body>Normal response for id=' + param + '</body></html>')

        elif path == '/xss':
            param = params.get('name', [''])[0]
            self._send_response(200, 'text/html',
                f'<html><body>Hello {param}</body></html>')

        elif path == '/lfi':
            param = params.get('file', [''])[0]
            if '../etc/passwd' in param or '/etc/passwd' in param or 'passwd' in param:
                self._send_response(200, 'text/html',
                    '<html><body>root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin</body></html>')
            elif 'php://' in param.lower():
                self._send_response(200, 'text/html',
                    base64.b64encode(b'<?php echo "test"; ?>').decode())
            else:
                self._send_response(200, 'text/html',
                    f'<html><body>File content for: {param}</body></html>')

        elif path == '/cmdi':
            param = params.get('cmd', [''])[0]
            if 'echo' in param and 'CMDI_ECHO' in param:
                marker = param.split('CMDI_ECHO_')[1].split()[0].split("'")[0].split('"')[0] if 'CMDI_ECHO_' in param else ''
                self._send_response(200, 'text/html',
                    f'<html><body>CMDI_ECHO_{marker}</body></html>')
            elif 'id' in param:
                self._send_response(200, 'text/html',
                    '<html><body>uid=0(root) gid=0(root) groups=0(root)</body></html>')
            else:
                self._send_response(200, 'text/html',
                    f'<html><body>Command output: {param}</body></html>')

        elif path == '/ssrf':
            param = params.get('url', [''])[0]
            if '169.254.169.254' in param:
                self._send_response(200, 'text/html',
                    '{"ami-id": "ami-12345678", "instance-id": "i-abcdef12", "local-ipv4": "10.0.0.1"}')
            elif '127.0.0.1' in param or 'localhost' in param:
                self._send_response(200, 'text/html',
                    '<html><body>Internal service response</body></html>')
            else:
                self._send_response(200, 'text/html',
                    f'<html><body>Fetched: {param}</body></html>')

        elif path == '/login':
            self._send_response(200, 'text/html', '''
                <html><body>
                <form method="POST" action="/login">
                    <input type="text" name="username" placeholder="Username">
                    <input type="password" name="password" placeholder="Password">
                    <input type="hidden" name="csrf_token" value="test_csrf_token_123">
                    <button type="submit">Login</button>
                </form>
                </body></html>
            ''')

        elif path == '/upload':
            self._send_response(200, 'text/html', '''
                <html><body>
                <form method="POST" action="/upload" enctype="multipart/form-data">
                    <input type="file" name="file" accept=".jpg,.png,.gif">
                    <input type="hidden" name="csrf_token" value="test_token">
                    <button type="submit">Upload</button>
                </form>
                </body></html>
            ''')

        elif path == '/csrf':
            self._send_response(200, 'text/html', '''
                <html><body>
                <form method="POST" action="/csrf/action">
                    <input type="text" name="amount" value="100">
                    <input type="text" name="to" value="user1">
                    <button type="submit">Transfer</button>
                </form>
                </body></html>
            ''')

        elif path == '/health':
            self._send_response(200, 'application/json', '{"status": "ok"}')

        else:
            self._send_response(404, 'text/html', '<html><body>Not Found</body></html>')

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == '/login':
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8') if content_length else ''
            params = parse_qs(body)

            username = params.get('username', [''])[0]
            password = params.get('password', [''])[0]

            if username == 'admin' and password == 'admin':
                self._send_response(200, 'text/html',
                    '<html><body>Welcome to dashboard! <a href="/logout">Logout</a></body></html>')
            else:
                self._send_response(200, 'text/html',
                    '<html><body>Login failed. Invalid username or password.</body></html>')

        elif path == '/upload':
            self._send_response(200, 'application/json',
                '{"success": true, "message": "File uploaded successfully", "url": "/uploads/test.php"}')

        elif path == '/csrf/action':
            self._send_response(200, 'text/html',
                '<html><body>Transfer completed successfully</body></html>')

        else:
            self._send_response(404, 'text/html', '<html><body>Not Found</body></html>')


def start_vuln_server(port=18888):
    global VULN_SERVER
    VULN_SERVER = HTTPServer(('127.0.0.1', port), VulnTestHandler)
    thread = threading.Thread(target=VULN_SERVER.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.5)
    return port


def stop_vuln_server():
    global VULN_SERVER
    if VULN_SERVER:
        VULN_SERVER.shutdown()
        VULN_SERVER = None


if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18888
    print(f"Starting vuln test server on port {port}...")
    start_vuln_server(port)
    print(f"Server running at http://127.0.0.1:{port}")
    print("Press Ctrl+C to stop")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_vuln_server()
        print("Server stopped")
