"""RAG 管理 REST 接口的单元测试。"""
import asyncio
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from TOSKill.api import rag_api


def _engine(*, ready=True, rebuilt=True):
    engine = MagicMock()
    engine.get_stats.return_value = {
        "initialized": ready,
        "ready": ready,
        "document_count": 17,
        "embed_model": "BAAI/bge-small-zh-v1.5",
        "embed_model_loaded": ready,
        "model_load_error": None,
        "keyword_fallback_enabled": True,
    }
    engine.get_kb_version.return_value = "v2.17.20260809"
    engine.rebuild_index.return_value = rebuilt
    return engine


def test_get_rag_status_returns_public_status_without_paths():
    engine = _engine()
    with patch.object(rag_api, "get_rag_engine", return_value=engine):
        response = asyncio.run(rag_api.get_rag_status())

    assert response.code == 200
    assert response.data == {
        "enabled": True,
        "index_status": "ready",
        "initialized": True,
        "ready": True,
        "document_count": 17,
        "knowledge_base_version": "v2.17.20260809",
        "embed_model": "BAAI/bge-small-zh-v1.5",
        "embed_model_loaded": True,
        "model_load_error": None,
        "keyword_fallback_enabled": True,
    }


def test_rebuild_rag_index_returns_latest_status():
    engine = _engine(rebuilt=True)
    with patch.object(rag_api, "get_rag_engine", return_value=engine):
        response = asyncio.run(rag_api.rebuild_rag_index())

    engine.rebuild_index.assert_called_once_with()
    assert response.code == 200
    assert response.message == "RAG 向量索引重建成功"
    assert response.data["index_status"] == "ready"


def test_rebuild_rejects_concurrent_request():
    assert rag_api._rebuild_lock.acquire(blocking=False)
    try:
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(rag_api.rebuild_rag_index())
    finally:
        rag_api._rebuild_lock.release()

    assert exc_info.value.status_code == 409


def test_rag_router_is_registered_on_application():
    from TOSKill.main import app

    paths = {route.path for route in app.routes}
    assert "/api/rag/status" in paths
    assert "/api/rag/rebuild" in paths
