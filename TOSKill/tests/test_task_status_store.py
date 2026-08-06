"""
TaskStatusStore 自测脚本

测试内容：
1. set_status 各状态 -> get_status 返回正确
2. payload JSON 含 waiting_input.fields 正确序列化/反序列化
3. sqlite 持久化（重新 new 一个 instance 模拟重启，内存清空后 get_status 从 sqlite 恢复）
4. delete_status 删除后 get_status 返回 None
5. progress / stage 更新合并
6. 单例行为
"""
import json
import os
import sys

# 确保项目根目录在 sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
PARENT_ROOT = os.path.dirname(PROJECT_ROOT)
if PARENT_ROOT not in sys.path:
    sys.path.insert(0, PARENT_ROOT)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from TOSKill.AI.task_status_store import (
    TaskStatusStore,
    get_task_status_store,
    STATUS_QUEUED,
    STATUS_PLANNING,
    STATUS_WAITING_USER_INPUT,
    STATUS_WAITING_SCRIPT_UPLOAD,
    STATUS_RUNNING,
    STATUS_COMPLETED,
    STATUS_EXCEPTION,
)

passed = 0
failed = 0


def assert_eq(test_name, actual, expected):
    global passed, failed
    if actual == expected:
        passed += 1
        print(f"  [PASS] {test_name}")
    else:
        failed += 1
        print(f"  [FAIL] {test_name}: expected={expected!r}, actual={actual!r}")


def assert_true(test_name, condition):
    assert_eq(test_name, condition, True)


def assert_none(test_name, value):
    global passed, failed
    if value is None:
        passed += 1
        print(f"  [PASS] {test_name}")
    else:
        failed += 1
        print(f"  [FAIL] {test_name}: expected=None, actual={value!r}")


def test_all_statuses():
    """测试1: set_status 各状态 -> get_status 返回正确"""
    print("\n=== Test 1: 各状态设置与获取 ===")
    store = get_task_status_store()

    statuses = [
        (STATUS_QUEUED, "task-queued"),
        (STATUS_PLANNING, "task-planning"),
        (STATUS_WAITING_USER_INPUT, "task-waiting-input"),
        (STATUS_WAITING_SCRIPT_UPLOAD, "task-waiting-script"),
        (STATUS_RUNNING, "task-running"),
        (STATUS_COMPLETED, "task-completed"),
        (STATUS_EXCEPTION, "task-exception"),
    ]

    for status, task_id in statuses:
        store.set_status(task_id, status, progress=50, stage=f"stage-{status}")
        result = store.get_status(task_id)
        assert_eq(f"{status} status", result["status"], status)
        assert_eq(f"{status} progress", result["progress"], 50)
        assert_eq(f"{status} stage", result["stage"], f"stage-{status}")
        assert_eq(f"{status} task_id", result["task_id"], task_id)


def test_waiting_input_payload():
    """测试2: waiting_input.fields 正确序列化/反序列化"""
    print("\n=== Test 2: waiting_input.fields 序列化/反序列化 ===")
    store = get_task_status_store()

    fields = [
        {"name": "dvwa_base_url", "type": "string", "description": "DVWA 靶场地址", "required": True, "default": None},
        {"name": "scan_depth", "type": "integer", "description": "扫描深度", "required": False, "default": 1},
    ]

    store.set_status(
        "task-waiting-payload",
        STATUS_WAITING_USER_INPUT,
        progress=30,
        stage="wait_input",
        waiting_input={"fields": fields},
    )

    result = store.get_status("task-waiting-payload")
    assert_eq("status", result["status"], STATUS_WAITING_USER_INPUT)
    assert_true("has waiting_input", "waiting_input" in result)
    assert_eq("fields count", len(result["waiting_input"]["fields"]), 2)
    assert_eq("field[0] name", result["waiting_input"]["fields"][0]["name"], "dvwa_base_url")
    assert_eq("field[0] required", result["waiting_input"]["fields"][0]["required"], True)
    assert_eq("field[1] default", result["waiting_input"]["fields"][1]["default"], 1)


def test_waiting_script_payload():
    """测试2b: waiting_script.capability 正确序列化/反序列化"""
    print("\n=== Test 2b: waiting_script.capability 序列化/反序列化 ===")
    store = get_task_status_store()

    store.set_status(
        "task-waiting-script",
        STATUS_WAITING_SCRIPT_UPLOAD,
        progress=10,
        stage="wait_script",
        waiting_script={
            "capability": "dvwa_vuln_scanner",
            "params": [
                {"name": "target", "type": "string", "description": "目标 URL"},
                {"name": "cookie", "type": "string", "description": "会话 Cookie"},
            ],
        },
    )

    result = store.get_status("task-waiting-script")
    assert_eq("status", result["status"], STATUS_WAITING_SCRIPT_UPLOAD)
    assert_eq("capability", result["waiting_script"]["capability"], "dvwa_vuln_scanner")
    assert_eq("params count", len(result["waiting_script"]["params"]), 2)


def test_result_and_error_payload():
    """测试2c: result 和 error payload"""
    print("\n=== Test 2c: result / error payload ===")
    store = get_task_status_store()

    # completed with result
    store.set_status(
        "task-result",
        STATUS_COMPLETED,
        progress=100,
        stage="done",
        result={"vulns_found": 3, "scan_time": "12s"},
    )
    result = store.get_status("task-result")
    assert_eq("result vulns_found", result["result"]["vulns_found"], 3)

    # exception with error
    store.set_status(
        "task-error",
        STATUS_EXCEPTION,
        progress=60,
        stage="crashed",
        error="Connection refused: 127.0.0.1:8080",
    )
    result = store.get_status("task-error")
    assert_eq("error message", result["error"], "Connection refused: 127.0.0.1:8080")


def test_sqlite_persistence():
    """测试3: sqlite 持久化 —— 重置单例模拟重启，内存清空后从 sqlite 恢复"""
    print("\n=== Test 3: sqlite 持久化（模拟重启恢复） ===")

    # 先写入一条特殊数据
    store = get_task_status_store()
    store.set_status(
        "task-persist",
        STATUS_RUNNING,
        progress=75,
        stage="scanning",
        waiting_input={"fields": [{"name": "url", "type": "string", "description": "Target URL", "required": True}]},
    )

    # 验证当前能读到
    result = store.get_status("task-persist")
    assert_eq("before reset status", result["status"], STATUS_RUNNING)
    assert_eq("before reset progress", result["progress"], 75)

    # 重置单例，清空内存
    TaskStatusStore._reset_singleton()

    # 重新获取实例（模拟重启）
    store2 = get_task_status_store()
    result2 = store2.get_status("task-persist")

    assert_eq("after reset status", result2["status"], STATUS_RUNNING)
    assert_eq("after reset progress", result2["progress"], 75)
    assert_eq("after reset stage", result2["stage"], "scanning")
    assert_eq("after reset fields[0] name", result2["waiting_input"]["fields"][0]["name"], "url")


def test_delete_status():
    """测试4: delete_status 后 get_status 返回 None"""
    print("\n=== Test 4: delete_status ===")
    store = get_task_status_store()

    store.set_status("task-delete-me", STATUS_QUEUED, progress=0)
    result = store.get_status("task-delete-me")
    assert_eq("before delete", result["status"], STATUS_QUEUED)

    store.delete_status("task-delete-me")
    result = store.get_status("task-delete-me")
    assert_none("after delete", result)

    # 再重置单例确认 sqlite 也删了
    TaskStatusStore._reset_singleton()
    store2 = get_task_status_store()
    result2 = store2.get_status("task-delete-me")
    assert_none("after reset still None", result2)


def test_progress_stage_merge():
    """测试5: progress / stage 更新合并"""
    print("\n=== Test 5: progress / stage 更新合并 ===")
    store = get_task_status_store()

    store.set_status("task-merge", STATUS_QUEUED, progress=0, stage="init")
    store.set_status("task-merge", STATUS_RUNNING, progress=50)  # 不传 stage，保持原 stage
    result = store.get_status("task-merge")
    assert_eq("progress updated", result["progress"], 50)
    assert_eq("stage preserved", result["stage"], "init")

    store.set_status("task-merge", STATUS_RUNNING, stage="scanning")  # 不传 progress，保持原 progress
    result = store.get_status("task-merge")
    assert_eq("progress preserved", result["progress"], 50)
    assert_eq("stage updated", result["stage"], "scanning")


def test_singleton():
    """测试6: 单例行为"""
    print("\n=== Test 6: 单例行为 ===")
    # 重置
    TaskStatusStore._reset_singleton()

    s1 = get_task_status_store()
    s2 = get_task_status_store()
    assert_true("same instance", s1 is s2)

    # 写入后另一个引用也能读到
    s1.set_status("task-singleton", STATUS_PLANNING, progress=10)
    result = s2.get_status("task-singleton")
    assert_eq("cross-ref status", result["status"], STATUS_PLANNING)


def test_nonexistent_task():
    """测试7: 查询不存在的任务返回 None"""
    print("\n=== Test 7: 不存在的任务 ===")
    store = get_task_status_store()
    result = store.get_status("nonexistent-task-xyz")
    assert_none("nonexistent task", result)


def test_invalid_status():
    """测试8: 无效状态被忽略"""
    print("\n=== Test 8: 无效状态 ===")
    store = get_task_status_store()
    store.set_status("task-invalid", "invalid_status_xyz")
    result = store.get_status("task-invalid")
    assert_none("invalid status not stored", result)


def main():
    print("=" * 60)
    print("TaskStatusStore 自测")
    print("=" * 60)

    # 重置单例确保干净状态
    TaskStatusStore._reset_singleton()

    test_all_statuses()
    test_waiting_input_payload()
    test_waiting_script_payload()
    test_result_and_error_payload()
    test_sqlite_persistence()
    test_delete_status()
    test_progress_stage_merge()
    test_singleton()
    test_nonexistent_task()
    test_invalid_status()

    print("\n" + "=" * 60)
    total = passed + failed
    print(f"结果: {passed}/{total} 通过, {failed} 失败")
    print("=" * 60)

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
