"""
SubTask 1.4 单元自测：模拟缺 dvwa_base_url 的 state，
调用 detect_missing_required_params 和构造 pending_input_request，
断言 fields 结构正确、task_status 为 waiting_user_input。
"""
import sys
import os

# 将项目根目录加入 sys.path
_project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from TOSKill.AI.state import ScanState, create_initial_state
from TOSKill.AI.graph import detect_missing_required_params, ai_decision_router


def test_detect_missing_params_dvwa_no_url():
    """DVWA 工具缺 dvwa_base_url 时应返回 fields 列表"""
    state = create_initial_state(target="example.com", task_id="test001")
    # target 不含 dvwa，user_directed_params 也无 dvwa_base_url
    result = detect_missing_required_params(state, "dvwa_vuln_scanner")

    assert result is not None, "应检测到缺失参数"
    assert len(result) == 1, "应返回 1 个缺失字段"
    field = result[0]
    assert field["name"] == "dvwa_base_url", f"字段名应为 dvwa_base_url，实际: {field['name']}"
    assert field["required"] is True, "dvwa_base_url 应为必填"
    assert "type" in field, "字段应包含 type"
    assert "description" in field, "字段应包含 description"
    assert "default" in field, "字段应包含 default"
    print("[PASS] test_detect_missing_params_dvwa_no_url")


def test_detect_missing_params_dvwa_with_url_in_target():
    """DVWA 工具但 target 含 dvwa 时不缺参"""
    state = create_initial_state(target="http://127.0.0.1:8080/dvwa/", task_id="test002")
    result = detect_missing_required_params(state, "dvwa_vuln_scanner")
    assert result is None, f"target 含 dvwa 不应缺参，实际返回: {result}"
    print("[PASS] test_detect_missing_params_dvwa_with_url_in_target")


def test_detect_missing_params_dvwa_with_directed_params():
    """DVWA 工具但 user_directed_params 含 dvwa_base_url 时不缺参"""
    state = create_initial_state(target="example.com", task_id="test003")
    state["user_directed_params"] = {"dvwa_base_url": "http://192.168.1.100:8080"}
    result = detect_missing_required_params(state, "dvwa_vuln_scanner")
    assert result is None, f"user_directed_params 含 dvwa_base_url 不应缺参，实际返回: {result}"
    print("[PASS] test_detect_missing_params_dvwa_with_directed_params")


def test_detect_missing_params_dvwa_with_extracted_params():
    """DVWA 工具但 extracted_params 含 dvwa_base_url 时不缺参"""
    state = create_initial_state(target="example.com", task_id="test004")
    state["extracted_params"] = {"dvwa_base_url": "http://10.0.0.1:8080"}
    result = detect_missing_required_params(state, "dvwa_vuln_scanner")
    assert result is None, f"extracted_params 含 dvwa_base_url 不应缺参，实际返回: {result}"
    print("[PASS] test_detect_missing_params_dvwa_with_extracted_params")


def test_detect_missing_params_non_dvwa():
    """非 DVWA 工具不触发缺参检测"""
    state = create_initial_state(target="example.com", task_id="test005")
    result = detect_missing_required_params(state, "port_scanner")
    assert result is None, f"非 DVWA 工具应返回 None，实际: {result}"
    print("[PASS] test_detect_missing_params_non_dvwa")


def test_detect_missing_params_empty_task():
    """空任务名不触发缺参检测"""
    state = create_initial_state(target="example.com", task_id="test006")
    result = detect_missing_required_params(state, "")
    assert result is None, f"空任务名应返回 None，实际: {result}"
    print("[PASS] test_detect_missing_params_empty_task")


def test_pending_input_request_structure():
    """缺参时构造的 pending_input_request 结构正确"""
    state = create_initial_state(target="example.com", task_id="test007")
    missing = detect_missing_required_params(state, "dvwa_vuln_scanner")
    assert missing is not None

    pending_input_request = {"fields": missing}
    # 模拟 ai_decision 返回的 state
    updated = dict(state)
    updated["pending_input_request"] = pending_input_request
    updated["task_status"] = "waiting_user_input"

    # 验证结构
    assert updated["task_status"] == "waiting_user_input"
    assert "fields" in updated["pending_input_request"]
    assert len(updated["pending_input_request"]["fields"]) == 1
    assert updated["pending_input_request"]["fields"][0]["name"] == "dvwa_base_url"
    print("[PASS] test_pending_input_request_structure")


def test_ai_decision_router_missing_params():
    """ai_decision_router 在 pending_input_request 有 fields 时路由到 wait_user_input"""
    state = create_initial_state(target="example.com", task_id="test008")
    state["pending_input_request"] = {"fields": [{"name": "dvwa_base_url"}]}
    result = ai_decision_router(state)
    assert result == "wait_user_input", f"应路由到 wait_user_input，实际: {result}"
    print("[PASS] test_ai_decision_router_missing_params")


def test_ai_decision_router_no_missing_params():
    """ai_decision_router 在无 pending_input_request 时路由到 user_interact"""
    state = create_initial_state(target="example.com", task_id="test009")
    state["pending_input_request"] = {}
    result = ai_decision_router(state)
    assert result == "user_interact", f"应路由到 user_interact，实际: {result}"
    print("[PASS] test_ai_decision_router_no_missing_params")


def test_initial_state_has_new_fields():
    """create_initial_state 应包含新增字段的默认值"""
    state = create_initial_state(target="example.com", task_id="test010")
    assert state.get("pending_input_request") == {}, f"pending_input_request 默认应为 {{}}，实际: {state.get('pending_input_request')}"
    assert state.get("task_status") == "queued", f"task_status 默认应为 queued，实际: {state.get('task_status')}"
    assert state.get("pending_script_request") == {}, f"pending_script_request 默认应为 {{}}，实际: {state.get('pending_script_request')}"
    print("[PASS] test_initial_state_has_new_fields")


if __name__ == "__main__":
    tests = [
        test_detect_missing_params_dvwa_no_url,
        test_detect_missing_params_dvwa_with_url_in_target,
        test_detect_missing_params_dvwa_with_directed_params,
        test_detect_missing_params_dvwa_with_extracted_params,
        test_detect_missing_params_non_dvwa,
        test_detect_missing_params_empty_task,
        test_pending_input_request_structure,
        test_ai_decision_router_missing_params,
        test_ai_decision_router_no_missing_params,
        test_initial_state_has_new_fields,
    ]

    passed = 0
    failed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            failed += 1
            print(f"[FAIL] {t.__name__}: {e}")

    print(f"\n===== 结果: {passed} passed, {failed} failed =====")
    sys.exit(0 if failed == 0 else 1)
