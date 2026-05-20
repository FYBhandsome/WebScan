import requests

BASE = "http://127.0.0.1:8899/api"

print("=" * 60)
print("    FIX VERIFICATION TESTS (against :8899)")
print("=" * 60)

passed = 0
failed = 0

# Test 1: Report export (was failing with AIAnalysisData business_impact)
print("\n=== Test 1: Export Report JSON (AIAnalysisData fix) ===")
try:
    r = requests.get(f"{BASE}/reports/1/export", params={"format": "json"}, timeout=30)
    if r.status_code == 200:
        print(f"[PASS] Export OK")
        passed += 1
    else:
        print(f"[FAIL] HTTP {r.status_code}: {r.text[:200]}")
        failed += 1
except Exception as e:
    print(f"[ERROR] {e}")
    failed += 1

# Test 2: Export HTML
print("\n=== Test 2: Export Report HTML ===")
try:
    r = requests.get(f"{BASE}/reports/1/export", params={"format": "html"}, timeout=30)
    if r.status_code == 200:
        print(f"[PASS] Export HTML OK")
        passed += 1
    else:
        print(f"[FAIL] HTTP {r.status_code}: {r.text[:200]}")
        failed += 1
except Exception as e:
    print(f"[ERROR] {e}")
    failed += 1

# Test 3: Agent task detail (was failing with target_context undefined)
print("\n=== Test 3: Agent Task Detail (target_context fix) ===")
try:
    r = requests.get(f"{BASE}/ai_agents/tasks/1", timeout=30)
    if r.status_code == 200:
        data = r.json()
        task_data = data.get("data", {})
        if "target_context" in task_data:
            print(f"[PASS] Agent task detail OK - has target_context")
            passed += 1
        else:
            print(f"[WARN] Missing target_context in response")
            failed += 1
    else:
        print(f"[FAIL] HTTP {r.status_code}: {r.text[:200]}")
        failed += 1
except Exception as e:
    print(f"[ERROR] {e}")
    failed += 1

# Test 4: Vulnerability detail with cvss_score
print("\n=== Test 4: Vulnerability Detail (cvss_score field) ===")
try:
    r = requests.get(f"{BASE}/vulnerabilities/1", timeout=30)
    if r.status_code == 200:
        data = r.json()["data"]
        has_cvss = "cvss_score" in data
        has_affected = "affected_product" in data
        if has_cvss and has_affected:
            print(f"[PASS] Vulnerability has cvss_score and affected_product")
            passed += 1
        else:
            missing = []
            if not has_cvss: missing.append("cvss_score")
            if not has_affected: missing.append("affected_product")
            print(f"[FAIL] Missing fields: {missing}")
            failed += 1
    else:
        print(f"[FAIL] HTTP {r.status_code}")
        failed += 1
except Exception as e:
    print(f"[ERROR] {e}")
    failed += 1

# Test 5: AI Agent config
print("\n=== Test 5: AI Agent Config ===")
try:
    r = requests.get(f"{BASE}/ai_agents/config", timeout=30)
    if r.status_code == 200:
        print(f"[PASS] AI Agent config OK")
        passed += 1
    else:
        print(f"[FAIL] HTTP {r.status_code}")
        failed += 1
except Exception as e:
    print(f"[ERROR] {e}")
    failed += 1

# Test 6: AI Agent start scan
print("\n=== Test 6: AI Agent Start Scan ===")
try:
    r = requests.post(f"{BASE}/ai_agents/scan", json={
        "target": "https://httpbin.org",
        "strategy": "quick",
        "timeout": 60
    }, timeout=30)
    if r.status_code == 200:
        print(f"[PASS] Agent scan started: task_id={r.json().get('task_id')}")
        passed += 1
    else:
        print(f"[FAIL] HTTP {r.status_code}: {r.text[:200]}")
        failed += 1
except Exception as e:
    print(f"[ERROR] {e}")
    failed += 1

print()
print("=" * 60)
print(f"  RESULTS: {passed} PASSED / {passed + failed} TOTAL")
print("=" * 60)