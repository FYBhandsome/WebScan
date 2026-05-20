import os
from fastapi.testclient import TestClient

os.environ.setdefault("CODE_GUARD_DB_URL", "sqlite://./test_codeguard.db")

from main import app


class TestAuditAPI:
    def test_upload_endpoint(self):
        test_code = 'x = 1\ny = 2\nprint("safe")'
        with TestClient(app) as client:
            response = client.post(
                "/upload",
                files={"file": ("test.py", test_code.encode("utf-8"), "text/x-python")}
            )
            assert response.status_code == 200
            data = response.json()
            assert data["code"] == 200
            assert "task_id" in data["data"]
            assert data["msg"] == "审计完成"

    def test_upload_with_vulnerabilities(self):
        test_code = """
password = "Admin@123456"
eval("print('danger')")
import os
os.system("ls")
cursor.execute("SELECT * FROM user WHERE name='admin'")
"""
        with TestClient(app) as client:
            response = client.post(
                "/upload",
                files={"file": ("vuln.py", test_code.encode("utf-8"), "text/x-python")}
            )
            assert response.status_code == 200
            data = response.json()
            assert data["code"] == 200

    def test_get_result(self):
        test_code = 'x = 1\ny = 2'
        with TestClient(app) as client:
            upload_resp = client.post(
                "/upload",
                files={"file": ("code.py", test_code.encode("utf-8"), "text/x-python")}
            )
            task_id = upload_resp.json()["data"]["task_id"]

            result_resp = client.get(f"/result/{task_id}")
            assert result_resp.status_code == 200
            data = result_resp.json()
            assert data["code"] == 200
            assert "filename" in data["data"]
            assert "vulns" in data["data"]
            assert "diff_html" in data["data"]

    def test_get_result_not_found(self):
        with TestClient(app) as client:
            response = client.get("/result/99999")
            assert response.status_code == 200
            data = response.json()
            assert data["code"] == 500

    def test_result_contains_vulnerabilities(self):
        test_code = 'password = "secret123"'
        with TestClient(app) as client:
            upload_resp = client.post(
                "/upload",
                files={"file": ("hardcode.py", test_code.encode("utf-8"), "text/x-python")}
            )
            task_id = upload_resp.json()["data"]["task_id"]

            result_resp = client.get(f"/result/{task_id}")
            vulns = result_resp.json()["data"]["vulns"]
            assert len(vulns) >= 1
            vuln = vulns[0]
            assert "type" in vuln
            assert "level" in vuln
            assert "line" in vuln
            assert "code" in vuln
            assert "desc" in vuln

    def test_home_page(self):
        with TestClient(app) as client:
            response = client.get("/")
            assert response.status_code == 200
