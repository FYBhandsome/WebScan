import importlib.util
from pathlib import Path
from unittest.mock import Mock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


_module_path = Path(__file__).parents[1] / "api" / "rag_api.py"
_spec = importlib.util.spec_from_file_location("TOSKill.rag_api_test", _module_path)
rag_api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rag_api)


@pytest.fixture
def client(tmp_path, monkeypatch):
    knowledge_dir = tmp_path / "knowledge"
    knowledge_dir.mkdir()
    monkeypatch.setattr(rag_api, "_KNOWLEDGE_DIR", knowledge_dir)
    monkeypatch.setattr(rag_api, "_index_stale", False)
    monkeypatch.setattr(rag_api, "_rebuild_operations", {})
    monkeypatch.setattr(rag_api, "_active_rebuild_id", None)
    app = FastAPI()
    app.include_router(rag_api.router, prefix="/api")
    return TestClient(app), knowledge_dir


def test_list_and_get_documents_are_stable_and_safe(client):
    test_client, knowledge_dir = client
    (knowledge_dir / "b.txt").write_text("second", encoding="utf-8")
    (knowledge_dir / "A.md").write_text("first", encoding="utf-8")
    (knowledge_dir / "ignored.json").write_text("{}", encoding="utf-8")

    response = test_client.get("/api/rag/documents")

    assert response.status_code == 200
    documents = response.json()
    assert [item["filename"] for item in documents] == ["A.md", "b.txt"]
    assert set(documents[0]) == {"filename", "name", "size", "modified_at", "extension", "source"}
    assert documents[0]["source"] == "RAG/knowledge"

    response = test_client.get("/api/rag/documents/A.md")
    assert response.status_code == 200
    assert response.json() == {"filename": "A.md", "name": "A.md", "content": "first"}


def test_get_rejects_path_traversal_and_missing_document(client):
    test_client, _ = client

    traversal = test_client.get("/api/rag/documents/..%5Csecret.md")
    missing = test_client.get("/api/rag/documents/missing.md")

    assert traversal.status_code == 400
    assert missing.status_code == 404


def test_upload_rejects_invalid_extension_and_path_traversal(client, tmp_path):
    test_client, _ = client
    outside = tmp_path / "outside.md"

    invalid = test_client.post(
        "/api/rag/documents",
        files={"file": ("payload.exe", b"bad", "application/octet-stream")},
    )
    traversal = test_client.post(
        "/api/rag/documents",
        files={"file": ("../outside.md", b"bad", "text/markdown")},
    )

    assert invalid.status_code == 400
    assert traversal.status_code == 400
    assert not outside.exists()


def test_upload_writes_document_notifies_rag_refresh_and_marks_stale(client, monkeypatch):
    test_client, knowledge_dir = client
    notify = Mock()
    monkeypatch.setattr(rag_api, "_notify_rag_refresh", notify)

    response = test_client.post(
        "/api/rag/documents",
        files={"file": ("guide.md", "安全内容".encode("utf-8"), "text/markdown")},
    )

    assert response.status_code == 201
    assert response.json() == {
        "filename": "guide.md",
        "name": "guide.md",
        "size": len("安全内容".encode("utf-8")),
        "index_stale": True,
    }
    assert (knowledge_dir / "guide.md").read_text(encoding="utf-8") == "安全内容"
    assert not list(knowledge_dir.glob(".rag-*.tmp"))
    notify.assert_called_once_with()
    assert rag_api._index_stale is True


class MockEngine:
    def __init__(self, rebuild_result=True):
        self.mode = "mapping"
        self.index = object()
        self.retriever = object()
        self.rebuild_result = rebuild_result

    def get_status(self):
        return {
            "mode": self.mode,
            "model_loaded": self.mode == "vector",
            "index_ready": self.mode == "mapping" or self.rebuild_result,
            "index_stale": False,
            "last_error": None if self.rebuild_result else "mock rebuild failed",
        }

    def set_mode(self, mode):
        self.mode = mode
        return self.get_status()

    def rebuild_index(self):
        if isinstance(self.rebuild_result, Exception):
            raise self.rebuild_result
        return self.rebuild_result


def test_rag_config_get_and_put(client, monkeypatch):
    test_client, _ = client
    engine = MockEngine()
    monkeypatch.setattr(rag_api, "_get_rag_engine", lambda: engine)

    assert test_client.get("/api/rag/config").json()["mode"] == "mapping"
    response = test_client.put("/api/rag/config", json={"mode": "vector"})
    assert response.status_code == 200
    assert response.json()["mode"] == "vector"


def test_rag_config_rejects_invalid_mode(client, monkeypatch):
    test_client, _ = client
    monkeypatch.setattr(rag_api, "_get_rag_engine", lambda: MockEngine())
    response = test_client.put("/api/rag/config", json={"mode": "invalid"})
    assert response.status_code == 422


def test_rebuild_success_and_duplicate_trigger(client, monkeypatch):
    test_client, _ = client
    monkeypatch.setattr(rag_api, "_get_rag_engine", lambda: MockEngine())
    original_worker = rag_api._run_rebuild
    queued = []

    def enqueue(operation_id):
        queued.append(operation_id)

    monkeypatch.setattr(rag_api, "_run_rebuild", enqueue)
    first = test_client.post("/api/rag/index/rebuild")
    assert first.status_code == 202
    duplicate = test_client.post("/api/rag/index/rebuild")
    assert duplicate.status_code == 409
    monkeypatch.setattr(rag_api, "_run_rebuild", original_worker)
    original_worker(first.json()["operation_id"])
    status = test_client.get(f"/api/rag/index/rebuild/{first.json()['operation_id']}")
    assert status.status_code == 200
    assert status.json()["status"] == "completed"


def test_rebuild_failure_reports_exception_and_preserves_index(client, monkeypatch):
    test_client, _ = client
    engine = MockEngine(rebuild_result=RuntimeError("boom"))
    old_index = engine.index
    monkeypatch.setattr(rag_api, "_get_rag_engine", lambda: engine)
    monkeypatch.setattr(rag_api, "_rebuild_knowledge_base", engine.rebuild_index)
    response = test_client.post("/api/rag/index/rebuild")
    operation_id = response.json()["operation_id"]
    status = test_client.get(f"/api/rag/index/rebuild/{operation_id}").json()
    assert status["status"] == "exception"
    assert "boom" in status["error"]
    assert engine.index is old_index
