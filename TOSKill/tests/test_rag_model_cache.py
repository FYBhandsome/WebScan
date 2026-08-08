"""RAG 本地 HuggingFace 模型缓存布局测试。"""

from pathlib import Path

from TOSKill.RAG.rag_engine import TOSKillRAGEngine


def _write_snapshot(cache_root: Path, model_name: str, *, use_hub_dir: bool = False) -> Path:
    model_dir = f"models--{model_name.replace('/', '--')}"
    repository = cache_root / "hub" / model_dir if use_hub_dir else cache_root / model_dir
    snapshot = repository / "snapshots" / "revision-1"
    snapshot.mkdir(parents=True)
    (snapshot / "config.json").write_text("{}", encoding="utf-8")
    (snapshot / "model.safetensors").write_bytes(b"model")
    (repository / "refs").mkdir()
    (repository / "refs" / "main").write_text("revision-1", encoding="utf-8")
    return snapshot


def test_find_cached_snapshot_without_hub_directory(tmp_path):
    expected = _write_snapshot(tmp_path, "BAAI/bge-small-zh-v1.5")

    actual = TOSKillRAGEngine._find_cached_model_snapshot(
        "BAAI/bge-small-zh-v1.5",
        str(tmp_path),
    )

    assert actual == expected
    assert TOSKillRAGEngine._check_model_cached(
        "BAAI/bge-small-zh-v1.5",
        str(tmp_path),
    )


def test_find_cached_snapshot_with_hub_directory(tmp_path):
    expected = _write_snapshot(
        tmp_path,
        "sentence-transformers/all-MiniLM-L6-v2",
        use_hub_dir=True,
    )

    actual = TOSKillRAGEngine._find_cached_model_snapshot(
        "sentence-transformers/all-MiniLM-L6-v2",
        str(tmp_path),
    )

    assert actual == expected


def test_incomplete_snapshot_is_not_treated_as_cached(tmp_path):
    repository = tmp_path / "models--BAAI--bge-small-zh-v1.5" / "snapshots" / "revision-1"
    repository.mkdir(parents=True)
    (repository / "config.json").write_text("{}", encoding="utf-8")

    assert TOSKillRAGEngine._find_cached_model_snapshot(
        "BAAI/bge-small-zh-v1.5",
        str(tmp_path),
    ) is None
