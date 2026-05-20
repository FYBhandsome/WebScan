"""
报告导出功能测试脚本

此脚本需要后端服务运行在 127.0.0.1:8888 才能执行。
使用方法: python -m tests.scripts.export_test
"""
import pytest

pytestmark = pytest.mark.skip(reason="需要后端服务运行，手动执行: python -m tests.scripts.export_test")


def test_export_reports():
    """测试报告导出功能 - 需要后端服务运行"""
    import requests
    
    BASE = "http://127.0.0.1:8888/api"
    
    print("=== Create test report ===")
    r = requests.post(f"{BASE}/reports/", json={
        "task_id": 1,
        "name": "Fix Verification Report",
        "format": "json",
        "include_ai_analysis": True
    }, timeout=30)
    
    if r.status_code == 200:
        report_id = r.json()["data"]["id"]
        print(f"Report created: ID={report_id}")
        
        print(f"\n=== Export JSON ===")
        r = requests.get(f"{BASE}/reports/{report_id}/export", params={"format": "json"}, timeout=30)
        print(f"Export JSON: HTTP {r.status_code}")
        
        print(f"\n=== Export HTML ===")
        r = requests.get(f"{BASE}/reports/{report_id}/export", params={"format": "html"}, timeout=30)
        print(f"Export HTML: HTTP {r.status_code}")
    else:
        print(f"Report creation failed: HTTP {r.status_code} - {r.text[:200]}")
        print("Trying against :8888 instead...")
        r = requests.post("http://127.0.0.1:8888/api/reports/", json={
            "task_id": 1, "name": "Fix Verification", "format": "json", "include_ai_analysis": True
        }, timeout=30)
        if r.status_code == 200:
            rid = r.json()["data"]["id"]
            r2 = requests.get(f"http://127.0.0.1:8888/api/reports/{rid}/export", params={"format": "json"}, timeout=30)
            print(f"Export from :8888: HTTP {r2.status_code} - {'OK' if r2.status_code==200 else r2.text[:200]}")
        else:
            print(f"Both failed")


if __name__ == "__main__":
    test_export_reports()