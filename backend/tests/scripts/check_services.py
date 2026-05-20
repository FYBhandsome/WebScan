import requests

try:
    r = requests.get("http://127.0.0.1:8888/api/tasks/", timeout=5)
    print(f"[OK] Backend running on :8888 - HTTP {r.status_code}")
except Exception as e:
    print(f"[FAIL] Backend not accessible on :8888 - {e}")

try:
    r = requests.get("http://127.0.0.1:8899/api/tasks/", timeout=5)
    print(f"[OK] Backend running on :8899 - HTTP {r.status_code}")
except Exception as e:
    print(f"      Backend not running on :8899 - {e}")

try:
    r = requests.get("http://127.0.0.1:8081/health", timeout=5)
    print(f"[OK] TOSKill running on :8081 - HTTP {r.status_code}")
except Exception as e:
    print(f"      TOSKill not running on :8081")