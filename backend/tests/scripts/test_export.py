import requests

BASE = "http://127.0.0.1:8899/api"

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