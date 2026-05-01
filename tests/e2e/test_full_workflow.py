"""端到端测试：模拟真实用户扫描场景"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import pytest
import requests
import json

BASE_URL = "http://localhost:8000"


def _service_available():
    try:
        response = requests.get(f"{BASE_URL}/toskill/health", timeout=2)
        return response.status_code == 200
    except Exception:
        return False


@pytest.mark.skipif(not _service_available(), reason="后端服务未运行")
class TestFullWorkflow:
    def test_create_session_to_scan_to_report(self):
        """端到端：创建会话 → 信息收集 → 漏洞扫描 → 生成报告"""

        resp = requests.post(f"{BASE_URL}/toskill/sessions", json={
            "target": "https://testasp.vulnweb.com",
            "mode": "full_scan"
        })
        assert resp.status_code == 200
        session_id = resp.json()["data"]["session_id"]
        print(f"\n创建会话: {session_id}")

        resp = requests.post(f"{BASE_URL}/toskill/scan/info", json={
            "target": "https://testasp.vulnweb.com",
            "session_id": session_id,
            "tools": ["baseinfo", "waf"]
        })
        assert resp.status_code == 200
        info_result = resp.json()
        print(f"信息收集完成: {info_result['data'].get('tools_used')}")

        resp = requests.post(f"{BASE_URL}/toskill/scan/vuln", json={
            "target": "https://testasp.vulnweb.com",
            "session_id": session_id,
            "tools": ["xss", "sqli"]
        })
        assert resp.status_code == 200
        vuln_result = resp.json()
        print(f"漏洞扫描完成: {vuln_result['message']}")

        resp = requests.post(f"{BASE_URL}/toskill/reports/generate/{session_id}")
        assert resp.status_code == 200
        report_result = resp.json()
        assert "report" in report_result["data"]
        print(f"报告生成完成: {len(report_result['data']['report'])} 字符")

        resp = requests.get(f"{BASE_URL}/toskill/sessions/{session_id}")
        assert resp.status_code == 200

        resp = requests.delete(f"{BASE_URL}/toskill/sessions/{session_id}")
        assert resp.status_code == 200

    def test_health_check_with_model_status(self):
        """验证健康检查返回 AI 模型状态"""
        resp = requests.get(f"{BASE_URL}/toskill/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["data"]["ai_model_status"] in ["connected", "disconnected"]
        print(f"\nAI模型状态: {data['data']['ai_model_status']}")
