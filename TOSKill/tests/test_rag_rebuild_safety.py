"""RAG 索引安全重建的回归测试。"""
import json
import threading
from pathlib import Path
from unittest.mock import MagicMock

from TOSKill.RAG import rag_engine as rag_module
from TOSKill.RAG.rag_engine import TOSKillRAGEngine


def _bare_engine() -> TOSKillRAGEngine:
    """创建不加载模型的引擎实例，用于验证重建事务。"""
    engine = object.__new__(TOSKillRAGEngine)
    engine.index = object()
    engine.retriever = object()
    engine._initialized = True
    engine._query_cache = {"old": "cached"}
    engine._cache_hits = 0
    engine._total_queries = 0
    engine._document_count = 3
    engine._embed_model = MagicMock()
    engine._model_load_error = None
    engine._index_generation = 4
    engine._index_lock = threading.RLock()
    return engine


def test_promote_staged_storage_replaces_complete_directory(monkeypatch, tmp_path):
    storage_dir = tmp_path / "storage"
    storage_dir.mkdir()
    (storage_dir / "old.json").write_text("old", encoding="utf-8")
    staged_dir = tmp_path / "storage-rebuild-test"
    staged_dir.mkdir()
    (staged_dir / "docstore.json").write_text("new", encoding="utf-8")

    monkeypatch.setattr(rag_module, "_STORAGE_DIR", storage_dir)
    engine = _bare_engine()
    engine._promote_staged_storage(staged_dir)

    assert (storage_dir / "docstore.json").read_text(encoding="utf-8") == "new"
    assert not (storage_dir / "old.json").exists()
    assert not list(staged_dir.iterdir())
    assert not list(tmp_path.glob("storage-backup-*"))


def test_promote_staged_storage_restores_staged_acl_inheritance(monkeypatch, tmp_path):
    storage_dir = tmp_path / "storage"
    storage_dir.mkdir()
    staged_dir = tmp_path / "storage-rebuild-test"
    staged_dir.mkdir()
    (staged_dir / "docstore.json").write_text("new", encoding="utf-8")
    monkeypatch.setattr(rag_module, "_STORAGE_DIR", storage_dir)
    engine = _bare_engine()
    enable_acl = MagicMock()
    engine._enable_windows_acl_inheritance = enable_acl

    engine._promote_staged_storage(staged_dir)

    enable_acl.assert_called_once_with(staged_dir)


def test_promote_recovers_when_existing_index_cannot_be_read(monkeypatch, tmp_path):
    storage_dir = tmp_path / "storage"
    storage_dir.mkdir()
    old_file = storage_dir / "docstore.json"
    old_file.write_text("old", encoding="utf-8")
    staged_dir = tmp_path / "storage-rebuild-test"
    staged_dir.mkdir()
    (staged_dir / "docstore.json").write_text("new", encoding="utf-8")
    monkeypatch.setattr(rag_module, "_STORAGE_DIR", storage_dir)
    engine = _bare_engine()

    real_copy2 = rag_module.shutil.copy2

    def deny_old_index_read(source, target, *args, **kwargs):
        if Path(source) == old_file:
            raise PermissionError("old index ACL denies reads")
        return real_copy2(source, target, *args, **kwargs)

    monkeypatch.setattr(rag_module.shutil, "copy2", deny_old_index_read)

    engine._promote_staged_storage(staged_dir)

    assert old_file.read_text(encoding="utf-8") == "new"
    assert not list(tmp_path.glob("storage-backup-*"))


def test_unreadable_index_backup_is_rolled_back_on_publish_failure(monkeypatch, tmp_path):
    storage_dir = tmp_path / "storage"
    storage_dir.mkdir()
    old_file = storage_dir / "docstore.json"
    old_file.write_text("old", encoding="utf-8")
    staged_dir = tmp_path / "storage-rebuild-test"
    staged_dir.mkdir()
    staged_file = staged_dir / "docstore.json"
    staged_file.write_text("new", encoding="utf-8")
    monkeypatch.setattr(rag_module, "_STORAGE_DIR", storage_dir)
    engine = _bare_engine()

    monkeypatch.setattr(
        rag_module.shutil,
        "copy2",
        MagicMock(side_effect=PermissionError("old index ACL denies reads")),
    )
    real_replace = rag_module.os.replace

    def fail_staged_publish(source, target):
        if Path(source) == staged_file:
            raise PermissionError("new index is locked")
        return real_replace(source, target)

    monkeypatch.setattr(rag_module.os, "replace", fail_staged_publish)

    try:
        engine._promote_staged_storage(staged_dir)
        raise AssertionError("Expected staged publish to fail")
    except RuntimeError as exc:
        assert "发布 RAG 索引文件失败" in str(exc)

    assert old_file.read_text(encoding="utf-8") == "old"
    assert not list(tmp_path.glob("storage-backup-*"))


def test_promote_staged_storage_rolls_back_replaced_files(monkeypatch, tmp_path):
    storage_dir = tmp_path / "storage"
    storage_dir.mkdir()
    (storage_dir / "docstore.json").write_text("old-docstore", encoding="utf-8")
    (storage_dir / "index_manifest.json").write_text("old-manifest", encoding="utf-8")
    staged_dir = tmp_path / "storage-rebuild-test"
    staged_dir.mkdir()
    (staged_dir / "docstore.json").write_text("new-docstore", encoding="utf-8")
    (staged_dir / "index_manifest.json").write_text("new-manifest", encoding="utf-8")
    monkeypatch.setattr(rag_module, "_STORAGE_DIR", storage_dir)
    engine = _bare_engine()

    real_replace = rag_module.os.replace

    def fail_manifest_publish(source, target):
        if Path(source) == staged_dir / "index_manifest.json":
            raise PermissionError("manifest is locked")
        return real_replace(source, target)

    monkeypatch.setattr(rag_module.os, "replace", fail_manifest_publish)

    try:
        engine._promote_staged_storage(staged_dir)
        raise AssertionError("Expected staged publish to fail")
    except RuntimeError as exc:
        assert "发布 RAG 索引文件失败" in str(exc)

    assert (storage_dir / "docstore.json").read_text(encoding="utf-8") == "old-docstore"
    assert (storage_dir / "index_manifest.json").read_text(encoding="utf-8") == "old-manifest"
    assert not list(tmp_path.glob("storage-backup-*"))


def test_rebuild_failure_keeps_existing_memory_index_and_cache(monkeypatch):
    engine = _bare_engine()
    old_index = engine.index
    old_retriever = engine.retriever
    engine._build_staged_index = MagicMock(side_effect=RuntimeError("staged build failed"))

    assert engine.rebuild_index() is False

    assert engine.index is old_index
    assert engine.retriever is old_retriever
    assert engine._document_count == 3
    assert engine._query_cache == {"old": "cached"}
    assert engine._index_generation == 4


def test_staged_build_validates_before_publishing(monkeypatch, tmp_path):
    storage_dir = tmp_path / "storage"
    storage_dir.mkdir()
    (storage_dir / "old.json").write_text("old", encoding="utf-8")
    monkeypatch.setattr(rag_module, "_STORAGE_DIR", storage_dir)

    engine = _bare_engine()
    fake_index = MagicMock()

    def persist(*, persist_dir):
        Path(persist_dir, "docstore.json").write_text("new", encoding="utf-8")

    fake_index.storage_context.persist.side_effect = persist
    engine._create_index = MagicMock(return_value=(fake_index, 9))
    engine._validate_staged_index = MagicMock()

    index, document_count = engine._build_staged_index()

    assert index is fake_index
    assert document_count == 9
    engine._validate_staged_index.assert_called_once()
    assert (storage_dir / "docstore.json").read_text(encoding="utf-8") == "new"
    assert not (storage_dir / "old.json").exists()


def test_knowledge_documents_use_portable_ids_and_metadata(monkeypatch, tmp_path):
    knowledge_dir = tmp_path / "RAG" / "knowledge"
    knowledge_dir.mkdir(parents=True)
    source_file = knowledge_dir / "portable.md"
    source_file.write_text("# Portable knowledge\n\ncontent", encoding="utf-8")
    monkeypatch.setattr(rag_module, "_KNOWLEDGE_DIR", knowledge_dir)

    documents = _bare_engine()._load_knowledge_documents()

    assert len(documents) == 1
    assert documents[0].id_ == "knowledge/portable.md"
    assert documents[0].metadata == {
        "file_name": "portable.md",
        "source": "knowledge/portable.md",
    }
    assert str(knowledge_dir) not in str(documents[0].metadata)


def test_legacy_manifest_requires_rebuild_for_portable_storage(monkeypatch, tmp_path):
    storage_dir = tmp_path / "storage"
    knowledge_dir = tmp_path / "RAG" / "knowledge"
    storage_dir.mkdir()
    knowledge_dir.mkdir(parents=True)
    (knowledge_dir / "portable.md").write_text("content", encoding="utf-8")
    manifest_path = storage_dir / "index_manifest.json"
    monkeypatch.setattr(rag_module, "_STORAGE_DIR", storage_dir)
    monkeypatch.setattr(rag_module, "_KNOWLEDGE_DIR", knowledge_dir)
    monkeypatch.setattr(rag_module, "_MANIFEST_PATH", manifest_path)
    engine = _bare_engine()

    engine._write_manifest(storage_dir, document_count=1)
    assert engine._manifest_matches() is True

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.pop("storage_schema")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    assert engine._manifest_matches() is False


def test_initialization_builds_index_when_generated_storage_is_absent(monkeypatch, tmp_path):
    storage_dir = tmp_path / "storage"
    knowledge_dir = tmp_path / "knowledge"
    knowledge_dir.mkdir()
    monkeypatch.setattr(rag_module, "_STORAGE_DIR", storage_dir)
    monkeypatch.setattr(rag_module, "_KNOWLEDGE_DIR", knowledge_dir)
    monkeypatch.setattr(rag_module, "_MANIFEST_PATH", storage_dir / "index_manifest.json")
    monkeypatch.setattr(rag_module, "Settings", MagicMock())

    engine = _bare_engine()
    engine.index = None
    engine.retriever = None
    engine._initialized = False
    engine._embed_model = None
    engine._try_load_embed_model = MagicMock(return_value=MagicMock())

    def build_index():
        engine.index = MagicMock()
        engine._document_count = 0

    engine._build_index = MagicMock(side_effect=build_index)
    monkeypatch.setattr(rag_module, "VectorIndexRetriever", MagicMock())

    engine._initialize_rag()

    engine._build_index.assert_called_once_with()
    assert engine.is_ready is True
