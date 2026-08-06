import os
import sys

import pytest

pytest.importorskip("llama_index.core")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from TOSKill.AI.graph import detect_missing_required_params, _is_dvwa_target
from TOSKill.AI.state import create_initial_state
from TOSKill.AI.tools import extract_auth_from_result, get_tool_sequence


def test_setup_url_is_dvwa_and_requests_base_url():
    state = create_initial_state("http://127.0.0.1:8080/setup.php")
    assert _is_dvwa_target(state)
    fields = detect_missing_required_params(state, "dvwa_vuln_scanner")
    assert fields and fields[0]["name"] == "dvwa_base_url"


def test_cookie_extract_nested_cookies_are_saved():
    result = {"success": True, "data": {"cookies": ["PHPSESSID=abc"]}}
    auth = extract_auth_from_result(result)
    assert auth["session_cookies"] == ["PHPSESSID=abc"]
    assert auth["auth_cookies"] == ["PHPSESSID=abc"]
    assert auth["auth_info"]["cookies"] == {"0": "PHPSESSID=abc"}


def test_dvwa_sequence_and_findings_shape():
    assert get_tool_sequence("dvwa_scan") == ["cookie_extract", "dvwa_vuln_scanner"]

    state = create_initial_state("http://127.0.0.1:8080/setup.php", mode="dvwa_scan")
    result = {"success": True, "data": {"findings": [{
        "vuln_type": "sqli", "url": "http://target", "payload": "1'", "evidence": "error", "severity": "high"
    }]}}
    state["vulnerabilities"] = [{**result["data"]["findings"][0], "title": "sqli"}]
    state["vuln_scan_results"] = {"dvwa_vuln_scanner": result}
    assert state["vulnerabilities"][0]["severity"] == "high"
    assert state["vuln_scan_results"]["dvwa_vuln_scanner"] == result


def test_history_context_saves_input():
    state = create_initial_state("http://127.0.0.1:8080/setup.php")
    state["history_context"] = {"dvwa_base_url": "http://127.0.0.1:8080"}
    assert state["history_context"]["dvwa_base_url"].endswith(":8080")
