"""
Task 5 自测：GET /api/scan/tasks/{task_id}/status 端点

验证：
1. waiting_user_input 状态 —— waiting_input.fields 正确透传
2. 不存在的 task_id —— 返回 200 + status:"unknown"
3. waiting_script_upload 状态 —— waiting_script.capability 正确透传（额外覆盖）

构造最小 FastAPI app，仅 include scan_router + prefix="/api"（与 main.py 注册方式一致），
不触发 main.py 的 lifespan（模型连通性检查等），保证测试轻量可独立运行。
"""
import sys
from pathlib import Path

# 确保项目根目录在 sys.path
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from fastapi import FastAPI
from fastapi.testclient import TestClient

from TOSKill.api.scan_api import router as scan_router
from TOSKill.AI.task_status_store import (
    get_task_status_store,
    TaskStatusStore,
    STATUS_WAITING_USER_INPUT,
    STATUS_WAITING_SCRIPT_UPLOAD,
    STATUS_RUNNING,
)

# 构造最小 app，复刻 main.py 的 scan_router 注册方式
app = FastAPI()
app.include_router(scan_router, prefix="/api")

client = TestClient(app)


def _fresh_store() -> TaskStatusStore:
    """重置单例，返回干净的 store 实例（不影响 db_path 配置）"""
    TaskStatusStore._reset_singleton()
    return get_task_status_store()


def test_waiting_user_input():
    """场景 1：waiting_user_input 状态，waiting_input.fields 透传"""
    store = _fresh_store()
    task_id = "test_t1_status_api"
    fields = [
        {"name": "dvwa_base_url", "type": "string", "required": True},
        {"name": "level", "type": "string", "required": False, "default": "low"},
    ]
    store.set_status(
        task_id,
        STATUS_WAITING_USER_INPUT,
        progress=30,
        stage="等待用户输入参数",
        waiting_input={"fields": fields},
    )

    resp = client.get(f"/api/scan/tasks/{task_id}/status")
    assert resp.status_code == 200, f"期望 200，实际 {resp.status_code}: {resp.text}"
    body = resp.json()

    assert body["task_id"] == task_id
    assert body["status"] == "waiting_user_input"
    assert body["progress"] == 30
    assert body["stage"] == "等待用户输入参数"
    # waiting_input 已展开到顶层
    assert "waiting_input" in body, f"waiting_input 未透传: {body}"
    assert body["waiting_input"]["fields"] == fields
    # 校验字段内容
    assert body["waiting_input"]["fields"][0]["name"] == "dvwa_base_url"
    assert body["waiting_input"]["fields"][0]["required"] is True

    # 清理测试数据
    store.delete_status(task_id)
    print(f"[PASS] test_waiting_user_input: status={body['status']}, fields={len(fields)}个")


def test_unknown_task():
    """场景 2：不存在的 task_id 返回 200 + status:'unknown'"""
    _fresh_store()
    task_id = "nonexistent_task_xyz_999"

    resp = client.get(f"/api/scan/tasks/{task_id}/status")
    assert resp.status_code == 200, f"期望 200，实际 {resp.status_code}: {resp.text}"
    body = resp.json()

    assert body["task_id"] == task_id
    assert body["status"] == "unknown"
    assert body["progress"] == 0
    assert body["stage"] == ""
    assert "message" in body
    print(f"[PASS] test_unknown_task: status={body['status']}, message={body['message']}")


def test_waiting_script_upload():
    """场景 3（额外覆盖）：waiting_script_upload 状态，waiting_script.capability 透传"""
    store = _fresh_store()
    task_id = "test_t2_status_api"
    store.set_status(
        task_id,
        STATUS_WAITING_SCRIPT_UPLOAD,
        progress=50,
        stage="等待用户上传脚本",
        waiting_script={
            "capability": "SQL注入检测",
            "required_params": [
                {"name": "target", "type": "string", "description": "扫描目标URL"},
            ],
        },
    )

    resp = client.get(f"/api/scan/tasks/{task_id}/status")
    assert resp.status_code == 200, f"期望 200，实际 {resp.status_code}: {resp.text}"
    body = resp.json()

    assert body["task_id"] == task_id
    assert body["status"] == "waiting_script_upload"
    assert "waiting_script" in body, f"waiting_script 未透传: {body}"
    assert body["waiting_script"]["capability"] == "SQL注入检测"
    assert len(body["waiting_script"]["required_params"]) == 1

    store.delete_status(task_id)
    print(f"[PASS] test_waiting_script_upload: status={body['status']}, capability={body['waiting_script']['capability']}")


def test_running_status():
    """场景 4（额外覆盖）：running 状态，progress 透传"""
    store = _fresh_store()
    task_id = "test_t3_status_api"
    store.set_status(task_id, STATUS_RUNNING, progress=75, stage="漏洞扫描中")

    resp = client.get(f"/api/scan/tasks/{task_id}/status")
    assert resp.status_code == 200
    body = resp.json()

    assert body["status"] == "running"
    assert body["progress"] == 75
    assert body["stage"] == "漏洞扫描中"

    store.delete_status(task_id)
    print(f"[PASS] test_running_status: status={body['status']}, progress={body['progress']}")


def test_endpoint_independent_of_ws():
    """场景 5：端点不依赖 WS session —— 直接通过 HTTP 访问，无 WS 连接"""
    store = _fresh_store()
    task_id = "test_t4_status_api"
    store.set_status(task_id, STATUS_RUNNING, progress=10)

    # 纯 HTTP GET，无任何 WS 连接建立
    resp = client.get(f"/api/scan/tasks/{task_id}/status")
    assert resp.status_code == 200
    assert resp.json()["status"] == "running"

    store.delete_status(task_id)
    print("[PASS] test_endpoint_independent_of_ws: 端点可独立 HTTP 访问")


if __name__ == "__main__":
    print("=" * 60)
    print("Task 5 自测：GET /api/scan/tasks/{task_id}/status")
    print("=" * 60)
    test_waiting_user_input()
    test_unknown_task()
    test_waiting_script_upload()
    test_running_status()
    test_endpoint_independent_of_ws()
    print("=" * 60)
    print("全部测试通过 ✓")
    print("=" * 60)
