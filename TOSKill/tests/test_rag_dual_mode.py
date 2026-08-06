import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path


@pytest.fixture
def engine():
    from TOSKill.RAG import rag_engine
    rag_engine.TOSKillRAGEngine._instance = None
    rag_engine._rag_engine = None
    with patch.object(rag_engine.TOSKillRAGEngine, "_try_load_embed_model") as load_model:
        instance = rag_engine.TOSKillRAGEngine()
        yield instance, load_model
    rag_engine.TOSKillRAGEngine._instance = None
    rag_engine._rag_engine = None


def test_default_mapping_does_not_load_embedding_model(engine):
    instance, load_model = engine
    assert instance.get_status()["mode"] == "mapping"
    assert instance.get_status()["model_loaded"] is False
    load_model.assert_not_called()


def test_set_mode_rejects_invalid_mode(engine):
    instance, _ = engine
    with pytest.raises(ValueError, match="非法"):
        instance.set_mode("invalid")


def test_status_contains_dual_mode_fields(engine):
    status = engine[0].get_status()
    assert set(("mode", "model_loaded", "index_ready", "index_stale",
                "index_version", "indexed_at", "last_error")).issubset(status)


def test_rebuild_failure_keeps_existing_storage_and_memory(engine, tmp_path):
    instance, _ = engine
    from TOSKill.RAG import rag_engine
    storage_dir = tmp_path / "storage"
    storage_dir.mkdir()
    old_file = storage_dir / "docstore.json"
    old_file.write_text("old", encoding="utf-8")
    old_index = object()
    old_retriever = object()
    instance.index = old_index
    instance.retriever = old_retriever
    with patch.object(rag_engine, "_STORAGE_DIR", storage_dir), \
            patch.object(instance, "_try_load_embed_model", return_value=object()), \
            patch.object(instance, "_build_index", side_effect=RuntimeError("build failed")):
        assert instance.rebuild_index() is False
    assert old_file.read_text(encoding="utf-8") == "old"
    assert instance.index is old_index
    assert instance.retriever is old_retriever


def test_rebuild_success_updates_metadata_and_retrieval(engine, tmp_path):
    instance, _ = engine
    from TOSKill.RAG import rag_engine
    storage_dir = tmp_path / "storage"
    storage_dir.mkdir()
    (storage_dir / "old.json").write_text("old", encoding="utf-8")
    old_version = "old-version"
    old_time = "old-time"
    instance._index_version = old_version
    instance._indexed_at = old_time
    instance._mode = "vector"
    new_index = MagicMock()
    new_index.storage_context = MagicMock()

    def build_success(persist_dir):
        persist_dir.mkdir(parents=True, exist_ok=True)
        (persist_dir / "new.json").write_text("new", encoding="utf-8")
        return new_index

    with patch.object(rag_engine, "_STORAGE_DIR", storage_dir), \
            patch.object(rag_engine, "_LLAMA_INDEX_IMPORT_ERROR", None), \
            patch.object(instance, "_try_load_embed_model", return_value=object()), \
            patch.object(instance, "_build_index", side_effect=build_success), \
            patch.object(rag_engine, "VectorIndexRetriever", return_value=MagicMock()):
        assert instance.rebuild_index() is True, instance.get_status()["last_error"]
    assert (storage_dir / "new.json").exists()
    assert not (storage_dir / "old.json").exists()
    assert instance._index_version != old_version
    assert instance._indexed_at != old_time
    assert instance.retrieve_scan_strategy("target", "", [], {}) == ""


